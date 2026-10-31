package main

import (
	"errors"
	"net/http"
	"time"
)

// Match the server's stale-heartbeat recovery window. A long native job's lease
// can be forty minutes, but it stops being owned after five minutes of silence.
const runnerJobHeartbeatStaleAfter = 5 * time.Minute

func lostRunnerJobClaim(reason string) error {
	return &preflightAPIError{status: http.StatusConflict, code: "runner_job_lease_denied", message: reason}
}

func runnerJobOwnershipRejected(err error) bool {
	var apiErr *preflightAPIError
	return errors.As(err, &apiErr) && (jobLeaseLost(err) || apiErr.code == "target_busy")
}

func runnerJobClaimDeadline(job apiRunnerJob, fallback time.Time) time.Time {
	deadline := fallback
	if heartbeat, err := time.Parse(time.RFC3339Nano, job.LastHeartbeatAt); err == nil {
		deadline = heartbeat.Add(runnerJobHeartbeatStaleAfter)
	}
	if lease, err := time.Parse(time.RFC3339Nano, job.LeaseExpiresAt); err == nil && lease.Before(deadline) {
		deadline = lease
	}
	return deadline
}

func runnerJobCancellationCheckWithClock(client *http.Client, options runnerOnceOptions, registration runnerRegistrationData, job apiRunnerJob, now func() time.Time) func() (bool, error) {
	deadline := runnerJobClaimDeadline(job, now().Add(runnerJobHeartbeatStaleAfter))
	return func() (bool, error) {
		var read apiRunnerJob
		var err error
		heartbeat := runnerJobHeartbeatEnabled(registration)
		if heartbeat {
			read, err = heartbeatRunnerJob(client, options, registration, job)
			if runnerJobOwnershipRejected(err) {
				return false, lostRunnerJobClaim("Job or device ownership was revoked; stopped this runner's work.")
			}
			if err != nil {
				heartbeat = false
				read, err = readRunnerJob(client, options, registration, job)
			}
		} else {
			read, err = readRunnerJob(client, options, registration, job)
		}
		if err != nil {
			var apiErr *preflightAPIError
			if runnerJobOwnershipRejected(err) || (errors.As(err, &apiErr) && apiErr.code == "runner_job_not_running") {
				return false, lostRunnerJobClaim("Job is no longer owned or running; stopped this runner's work.")
			}
			// Transport failures do not prove cancellation. They may only be
			// tolerated while the last confirmed claim is still live.
			if !now().Before(deadline) {
				return false, lostRunnerJobClaim("Could not confirm job ownership before its lease or heartbeat deadline.")
			}
			return false, nil
		}
		if read.ID != job.ID ||
			(read.RunnerID != "" && read.RunnerID != registration.Runner.ID) ||
			(job.LeaseOwner != "" && read.LeaseOwner != job.LeaseOwner) ||
			(job.ClaimedAt != "" && read.ClaimedAt != job.ClaimedAt) ||
			(job.Attempt != 0 && read.Attempt != job.Attempt) {
			return false, lostRunnerJobClaim("Job claim identity changed; stopped this runner's work.")
		}
		if read.Status == "cancelled" {
			return true, nil
		}
		if read.Status != "running" {
			return false, lostRunnerJobClaim("Job is no longer running; stopped this runner's work.")
		}
		fallback := deadline
		if heartbeat {
			fallback = now().Add(runnerJobHeartbeatStaleAfter)
		}
		deadline = runnerJobClaimDeadline(read, fallback)
		if !now().Before(deadline) {
			return false, lostRunnerJobClaim("Job lease or heartbeat deadline elapsed; stopped this runner's work.")
		}
		return false, nil
	}
}
