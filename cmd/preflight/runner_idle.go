package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// PREFLT-51: idle polling.
//
// Runner hosts supervise `preflight runner once` with a shell loop that sleeps
// five seconds between invocations. With nothing queued, every invocation
// re-registered, re-fetched the signing identity, heartbeated, reconciled,
// opened the job stream and claimed: six requests about every nine seconds per
// runner, with the stream and claim each costing 130-180 ms of Worker CPU. The
// stream answer was never even used (see claimRunnerJob).
//
// Now an idle `runner once` stays registered and keeps polling the claim
// endpoint itself, backing off from runnerIdlePollMin to runnerIdlePollMax,
// while the liveness heartbeat goroutine keeps the runner row fresh. It exits
// after runnerIdleWait without work so the supervisor loop still re-registers
// (picking up new capabilities and binaries) on a slow cadence, and it exits
// as before as soon as it has handled a job, so the next invocation claims
// immediately: work resets the backoff.
//
// Worst-case pickup latency for a job queued while a runner is idle is one
// maximum poll interval (60 s by default) plus a claim round trip.

const defaultRunnerIdlePollMin = 10 * time.Second
const defaultRunnerIdlePollMax = 60 * time.Second

// defaultRunnerIdleWait is a variable so the package tests, which drive
// `runner once` against fakes that answer one empty claim, can keep the
// single-claim behaviour; see TestMain.
var defaultRunnerIdleWait = 10 * time.Minute

// runnerIdleSleep and runnerIdleNow are replaced by tests.
var runnerIdleSleep = time.Sleep
var runnerIdleNow = time.Now

type runnerIdlePolicy struct {
	wait    time.Duration
	pollMin time.Duration
	pollMax time.Duration
}

func defaultRunnerIdlePolicy() runnerIdlePolicy {
	return runnerIdlePolicy{
		wait:    nonNegativeDurationFromEnv("PREFLIGHT_RUNNER_IDLE_WAIT", defaultRunnerIdleWait),
		pollMin: durationFromEnv("PREFLIGHT_RUNNER_IDLE_POLL_MIN", defaultRunnerIdlePollMin),
		pollMax: durationFromEnv("PREFLIGHT_RUNNER_IDLE_POLL_MAX", defaultRunnerIdlePollMax),
	}
}

// nonNegativeDurationFromEnv is durationFromEnv that also accepts zero, which
// for PREFLIGHT_RUNNER_IDLE_WAIT means "claim once and exit" (the old
// behaviour).
func nonNegativeDurationFromEnv(name string, fallback time.Duration) time.Duration {
	configured := strings.TrimSpace(os.Getenv(name))
	if configured == "" {
		return fallback
	}
	duration, err := time.ParseDuration(configured)
	if err != nil || duration < 0 {
		return fallback
	}
	return duration
}

// parseRunnerIdleFlag handles the three idle flags for parseRunnerOnceOptions.
// It reports whether the flag was one of them.
func parseRunnerIdleFlag(args []string, index *int, policy *runnerIdlePolicy) (bool, error) {
	flag := args[*index]
	var target *time.Duration
	allowZero := false
	switch flag {
	case "--idle-wait":
		target = &policy.wait
		allowZero = true
	case "--idle-poll-min":
		target = &policy.pollMin
	case "--idle-poll-max":
		target = &policy.pollMax
	default:
		return false, nil
	}
	value, ok := nextFlagValue(args, index)
	if !ok {
		return true, fmt.Errorf("%s requires a value", flag)
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 || (duration == 0 && !allowZero) {
		if allowZero {
			return true, fmt.Errorf("%s must be a non-negative duration", flag)
		}
		return true, fmt.Errorf("%s must be a positive duration", flag)
	}
	*target = duration
	return true, nil
}

// normalized keeps the schedule usable whatever was configured.
func (policy runnerIdlePolicy) normalized() runnerIdlePolicy {
	if policy.pollMin <= 0 {
		policy.pollMin = defaultRunnerIdlePollMin
	}
	if policy.pollMax < policy.pollMin {
		policy.pollMax = policy.pollMin
	}
	return policy
}

// nextRunnerIdleDelay doubles the previous delay up to the maximum. A zero
// previous delay starts the schedule.
func nextRunnerIdleDelay(previous time.Duration, policy runnerIdlePolicy) time.Duration {
	if previous <= 0 {
		return policy.pollMin
	}
	next := previous * 2
	if next > policy.pollMax {
		return policy.pollMax
	}
	return next
}

// waitForIdleRunnerJob polls the claim endpoint with backoff after an empty
// claim. It returns nil without error when the idle window ends or the host
// starts declining work, and the caller exits so the supervisor re-registers.
func waitForIdleRunnerJob(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	stdout io.Writer,
) (*runnerClaimData, error) {
	if options.idle.wait <= 0 {
		return nil, nil
	}
	policy := options.idle.normalized()
	deadline := runnerIdleNow().Add(policy.wait)
	delay := time.Duration(0)
	for {
		delay = nextRunnerIdleDelay(delay, policy)
		if runnerIdleNow().Add(delay).After(deadline) {
			return nil, nil
		}
		runnerIdleSleep(delay)
		if err := ensureBuildDiskHeadroom(options.workspaceRoot, stdout); err != nil {
			fmt.Fprintf(stdout, "declining claims: %v\n", err)
			return nil, nil
		}
		claim, err := claimRunnerJob(client, options, registration)
		if err != nil || claim != nil {
			return claim, err
		}
	}
}
