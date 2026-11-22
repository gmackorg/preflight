package main

// The exec layer for store builds and uploads (PREFLT-66).
//
// Everything store.build/store.upload runs — expo, pod, xcodebuild, security,
// codesign, gradle, keytool, altool — goes through storeCommandRunner so tests
// substitute a fake and never touch the real keychain, provisioning profile
// directories or Apple/Google tooling on the machine running them.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type storeCommand struct {
	Name    string
	Args    []string
	Dir     string
	Env     []string
	Timeout time.Duration
	// Quiet keeps the command's output out of the job log (it is still
	// returned). Used for security(1) queries whose output is noise.
	Quiet bool
}

func (command storeCommand) String() string {
	return strings.TrimSpace(command.Name + " " + strings.Join(command.Args, " "))
}

type storeCommandRunner interface {
	// Run executes the command and returns its combined output. A cancelled
	// job returns errCommandCancelled; a timeout wraps errCommandTimedOut.
	Run(command storeCommand) ([]byte, error)
}

// newStoreCommandRunner is a seam for tests of the job handlers.
var newStoreCommandRunner = func(log io.Writer, cancellationCheck func() (bool, error)) storeCommandRunner {
	return &execStoreCommandRunner{log: log, cancellationCheck: cancellationCheck}
}

type execStoreCommandRunner struct {
	log               io.Writer
	cancellationCheck func() (bool, error)
}

const defaultStoreCommandTimeout = 60 * time.Minute

func (runner *execStoreCommandRunner) Run(spec storeCommand) ([]byte, error) {
	log := runner.log
	if log == nil {
		log = io.Discard
	}
	_, _ = fmt.Fprintf(log, "$ %s\n", redactSetupTranscriptText(spec.String()))
	command := exec.Command(spec.Name, spec.Args...)
	command.Dir = spec.Dir
	if spec.Env != nil {
		command.Env = spec.Env
	}
	var output bytes.Buffer
	flush := func() {}
	if spec.Quiet {
		command.Stdout = &output
		command.Stderr = &output
	} else {
		flush = attachRedactedCommandLog(command, log)
		command.Stdout = io.MultiWriter(&output, command.Stdout)
		command.Stderr = command.Stdout
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = defaultStoreCommandTimeout
	}
	err := runCommandWithTimeoutAndCancellation(command, timeout, runner.cancellationCheck, runnerPollInterval())
	flush()
	if err != nil {
		return output.Bytes(), fmt.Errorf("%s: %w", spec.Name, err)
	}
	return output.Bytes(), nil
}

// storeEnvReference matches ${NAME} references in build-profile values.
var storeEnvReference = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandStorePlanEnvironment resolves ${NAME} references in the plan's
// environment against the revealed secret environment, the way eas.json
// interpolated EAS environment variables (e.g. SENTRY_DSN:
// "${EXPO_PUBLIC_SENTRY_DSN_PROD}"). A reference with no revealed secret is
// an error: building with the literal "${NAME}" would ship a broken value.
func expandStorePlanEnvironment(planEnv map[string]string, secretEnv map[string]string) (map[string]string, error) {
	expanded := make(map[string]string, len(planEnv))
	missing := map[string]bool{}
	for key, value := range planEnv {
		expanded[key] = storeEnvReference.ReplaceAllStringFunc(value, func(match string) string {
			name := storeEnvReference.FindStringSubmatch(match)[1]
			if secret, ok := secretEnv[name]; ok {
				return secret
			}
			missing[name] = true
			return match
		})
	}
	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for name := range missing {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, storeFailuref(
			"build_environment_unresolved",
			"build profile references %s, which no secret in this build provides; add them to the profile's secretEnvironmentKeys",
			strings.Join(names, ", "),
		)
	}
	return expanded, nil
}

// storeCommandEnv is the environment for prebuild/pod/xcodebuild/gradle: the
// runner's environment, the non-interactive and locale fixes the other build
// paths apply (see expoCommandEnv), then the plan's environment (with ${NAME}
// references expanded from secrets) and the revealed secret environment,
// which win.
func storeCommandEnv(planEnv map[string]string, secretEnv map[string]string) ([]string, error) {
	resolved, err := expandStorePlanEnvironment(planEnv, secretEnv)
	if err != nil {
		return nil, err
	}
	env := append([]string{}, os.Environ()...)
	env = upsertEnv(env, "EXPO_NO_INTERACTIVE", "1")
	env = upsertEnv(env, "CI", "1")
	if os.Getenv("LANG") == "" && os.Getenv("LC_ALL") == "" && os.Getenv("LC_CTYPE") == "" {
		env = upsertEnv(env, "LANG", "en_US.UTF-8")
	}
	for key, value := range resolved {
		if isSafeEnvironmentKey(key) {
			env = upsertEnv(env, key, value)
		}
	}
	for key, value := range secretEnv {
		env = upsertEnv(env, key, value)
	}
	return env, nil
}

// storeCleanup runs registered cleanups in reverse order exactly once. It is
// deferred by the handlers so success, failure and cancellation all unwind
// the keychain, the installed profiles and the temporary key files.
type storeCleanup struct {
	steps []storeCleanupStep
	log   io.Writer
	done  bool
}

type storeCleanupStep struct {
	label string
	run   func() error
}

func (cleanup *storeCleanup) add(label string, run func() error) {
	cleanup.steps = append(cleanup.steps, storeCleanupStep{label: label, run: run})
}

func (cleanup *storeCleanup) removeFile(path string) {
	cleanup.add("remove "+path, func() error {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
}

func (cleanup *storeCleanup) removeAll(path string) {
	cleanup.add("remove "+path, func() error { return os.RemoveAll(path) })
}

func (cleanup *storeCleanup) Run() []error {
	if cleanup.done {
		return nil
	}
	cleanup.done = true
	var errs []error
	for index := len(cleanup.steps) - 1; index >= 0; index-- {
		step := cleanup.steps[index]
		if err := step.run(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", step.label, err))
			if cleanup.log != nil {
				_, _ = fmt.Fprintf(cleanup.log, "cleanup warning: %s: %v\n", step.label, err)
			}
		}
	}
	return errs
}
