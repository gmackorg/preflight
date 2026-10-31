package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type devSessionProcessOwner struct {
	PID         int      `json:"pid"`
	StartedAt   string   `json:"startedAt"`
	WorkflowID  string   `json:"workflowId"`
	RunnerJobID string   `json:"runnerJobId"`
	BorrowedBy  []string `json:"borrowedBy,omitempty"`
}

func lockDevSessionProcessOwner(appDir string) (func(), error) {
	dir := filepath.Join(appDir, ".preflight", "dev-session-owner")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return acquireCheckoutLock(dir, time.Second)
}

func recordDevSessionBorrower(appDir string, job apiRunnerJob) error {
	path := filepath.Join(appDir, ".preflight", "expo-dev-session-owner.json")
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var owner devSessionProcessOwner
	if err := json.Unmarshal(content, &owner); err != nil {
		return err
	}
	if job.WorkflowID == "" || owner.WorkflowID == job.WorkflowID {
		return nil
	}
	for _, borrower := range owner.BorrowedBy {
		if borrower == job.WorkflowID {
			return nil
		}
	}
	owner.BorrowedBy = append(owner.BorrowedBy, job.WorkflowID)
	content, err = json.Marshal(owner)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", content, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func devSessionProcessStart(pid int) (string, error) {
	out, err := metroProcessOutput("ps", "-p", strconv.Itoa(pid), "-o", "lstart=")
	if err != nil {
		return "", err
	}
	started := strings.TrimSpace(string(out))
	if started == "" {
		return "", fmt.Errorf("process start identity unavailable")
	}
	return started, nil
}

func writeDevSessionProcessOwner(appDir string, pid int, job apiRunnerJob) error {
	started, err := devSessionProcessStart(pid)
	if err != nil {
		return err
	}
	owner := devSessionProcessOwner{PID: pid, StartedAt: started, WorkflowID: job.WorkflowID, RunnerJobID: job.ID}
	content, err := json.Marshal(owner)
	if err != nil {
		return err
	}
	path := filepath.Join(appDir, ".preflight", "expo-dev-session-owner.json")
	if err := os.WriteFile(path+".tmp", content, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// A stale PID file must never authorize killing a new process or a server
// started by another workflow in the same checkout. Verify both the durable
// start identity and the current listener's process tree and directory.
func stopVerifiedDevSession(appDir string, job apiRunnerJob) (string, error) {
	release, err := lockDevSessionProcessOwner(appDir)
	if err != nil {
		return "owner_unverified", err
	}
	defer release()
	session := job.Payload.DevSession
	if session.PID <= 0 {
		return "owner_unverified", fmt.Errorf("development session has no verified process")
	}
	if err := syscall.Kill(session.PID, 0); err != nil {
		if err != syscall.ESRCH {
			return "owner_unverified", err
		}
		if err := syscall.Kill(-session.PID, 0); err != syscall.ESRCH {
			return "owner_unverified", fmt.Errorf("session leader exited but process group ownership is unresolved")
		}
		return stopPreflightOwnedDevSession(appDir, session.PID)
	}
	group, err := syscall.Getpgid(session.PID)
	cwd, cwdErr := metroProcessCwd(session.PID)
	appPath, appErr := filepath.EvalSymlinks(appDir)
	cwdPath, realErr := filepath.EvalSymlinks(cwd)
	if err != nil || group != session.PID || cwdErr != nil || appErr != nil || realErr != nil || cwdPath != appPath {
		return "owner_unverified", fmt.Errorf("development session listener or process group ownership could not be verified")
	}
	path := filepath.Join(appDir, ".preflight", "expo-dev-session-owner.json")
	content, err := os.ReadFile(path)
	if err == nil {
		var owner devSessionProcessOwner
		started, startErr := devSessionProcessStart(session.PID)
		if json.Unmarshal(content, &owner) != nil || startErr != nil || owner.PID != session.PID ||
			owner.StartedAt != started || (job.WorkflowID != "" && owner.WorkflowID != job.WorkflowID) ||
			(session.RunnerJobID != "" && owner.RunnerJobID != session.RunnerJobID) || len(owner.BorrowedBy) > 0 {
			return "owner_unverified", fmt.Errorf("development session process birth or workflow owner changed")
		}
	} else if !os.IsNotExist(err) || session.RunnerJobID != "" {
		return "owner_unverified", fmt.Errorf("development session owner receipt unavailable")
	} else if !metroListenerOwnedByApp(appDir, session.PID, session.StatusURL) {
		return "owner_unverified", fmt.Errorf("legacy development session listener ownership is unverified")
	}
	outcome, err := stopPreflightOwnedDevSession(appDir, session.PID)
	if err != nil {
		return outcome, err
	}
	deadline := time.Now().Add(2 * time.Second)
	for devSessionProcessGroupLive(session.PID) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if devSessionProcessGroupLive(session.PID) || metroListenerOwnedByApp(appDir, session.PID, session.StatusURL) {
		return "failed", fmt.Errorf("owned development session still has a live listener")
	}
	_ = os.Remove(path)
	return outcome, nil
}

func devSessionProcessGroupLive(group int) bool {
	out, err := metroProcessOutput("ps", "-axo", "pgid=,stat=")
	if err != nil {
		return true
	}
	for _, row := range strings.Split(string(out), "\n") {
		fields := strings.Fields(row)
		if len(fields) != 2 {
			continue
		}
		pidGroup, err := strconv.Atoi(fields[0])
		if err == nil && pidGroup == group && !strings.HasPrefix(fields[1], "Z") {
			return true
		}
	}
	return false
}

func completeCancelledJobAndCleanup(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, result map[string]any, stdout io.Writer) error {
	if err := completeRunnerJob(client, options, registration, job, result); err != nil {
		return err
	}
	// Older API fixtures/servers do not bind workflows. Never widen an unscoped
	// claim just to look for cleanup, nor apply the build-space admission floor
	// to a teardown that can release resources.
	if job.WorkflowID == "" {
		return nil
	}
	options.workflowID = job.WorkflowID
	for remaining := 16; remaining > 0; remaining-- {
		claim, err := claimRunnerJob(client, options, registration)
		if err != nil || claim == nil {
			return err
		}
		if claim.Job.Kind != "dev_session.stop" {
			return fmt.Errorf("cancelled workflow returned non-cleanup job %s", claim.Job.ID)
		}
		if err := handleRunnerClaim(client, options, registration, claim.Job, stdout, nil); err != nil {
			return err
		}
	}
	return fmt.Errorf("cancelled workflow exceeded the bounded session cleanup limit")
}
