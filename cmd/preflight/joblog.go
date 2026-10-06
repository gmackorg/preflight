package main

// Ships command output to the server while a job runs.
//
// The server has had the whole receiving half of this for a long time — an
// endpoint, redaction, a byte budget, truncation accounting, and a paginated
// read API at /api/preflight/v1/logs — and the runner never called it. Across
// 6,788 jobs the fleet had stored exactly zero bytes, so "why did this build
// fail?" could only be answered by sshing to the Mac that ran it. This is the
// missing producer.
//
// It hangs off the active-job lifecycle rather than being threaded through the
// fifteen places that run a command: `attachRedactedCommandLog` already funnels
// every one of them through a single writer, so teeing there covers all of them
// at once and cannot miss one that gets added later.
//
// Everything here is best-effort by construction. Log shipping must never fail
// a build: a server that is down, a lease that expired, or a budget that is
// exhausted costs visibility, not the job.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// How often buffered output is flushed upstream. Frequent enough that a live
// build reads as live, sparse enough that a chatty build (xcodebuild emits
// thousands of lines) does not turn into thousands of requests.
const jobLogFlushInterval = 3 * time.Second

// Flush early once this much output has accumulated, so a burst does not wait
// out the timer. Comfortably under any sane request-size limit.
const jobLogFlushBytes = 16 * 1024

// Stop shipping after this much. The server enforces its own budget and starts
// rejecting; this keeps a runaway build from spending the whole time posting
// chunks that will be refused.
const jobLogMaxBytes = 4 * 1024 * 1024

const jobLogTruncationMarker = "\n[preflight] log truncated: job exceeded the runner's upload budget\n"

// The upload worker owns HTTP; command writers only append to a bounded buffer.
// Requests and terminal drain are bounded independently of native-build timeouts.
type jobLogShipper struct {
	mu       sync.Mutex
	pending  bytes.Buffer
	accepted int
	stopped  bool
	overflow bool
	post     func(context.Context, string) error
	ctx      context.Context
	cancel   context.CancelFunc
	wake     chan struct{}
	done     chan struct{}
	finished chan struct{}
	stopOnce sync.Once
}

func newJobLogShipper(post func(context.Context, string) error) *jobLogShipper {
	ctx, cancel := context.WithCancel(context.Background())
	s := &jobLogShipper{post: post, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{}), finished: make(chan struct{})}
	go s.run()
	return s
}

func (s *jobLogShipper) run() {
	defer close(s.finished)
	ticker := time.NewTicker(jobLogFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.done:
			s.flush()
			return
		case <-s.wake:
			s.flush()
		case <-ticker.C:
			s.flush()
		}
	}
}

func (s *jobLogShipper) stop() {
	s.stopOnce.Do(func() {
		// Fence appends before taking the terminal snapshot. An append that already
		// acquired the mutex belongs to this job and is included in the drain.
		s.mu.Lock()
		s.stopped = true
		s.mu.Unlock()
		close(s.done)
		timer := time.NewTimer(durationFromEnv("PREFLIGHT_JOB_LOG_STOP_TIMEOUT", 5*time.Second))
		defer timer.Stop()
		select {
		case <-s.finished:
		case <-timer.C:
			s.cancel()
			<-s.finished
		}
		s.cancel()
	})
}

func (s *jobLogShipper) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

var activeJobLog struct {
	mu      sync.Mutex
	shipper *jobLogShipper
}

// startJobLogShipping begins streaming this job's command output upstream.
// Returns a stop function that flushes what is left; safe to call twice.
func startJobLogShipping(
	client *http.Client,
	options runnerOnceOptions,
	registration runnerRegistrationData,
	job apiRunnerJob,
) func() {
	shipper := newJobLogShipper(func(ctx context.Context, chunk string) error {
		body, err := json.Marshal(struct {
			Chunk string `json:"chunk"`
		}{Chunk: chunk})
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost,
			runnerEndpoint(options.apiURL, fmt.Sprintf("/api/preflight/v1/runners/%s/jobs/%s/logs", registration.Runner.ID, job.ID)), bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		if registration.Token != "" {
			request.Header.Set("Authorization", "Bearer "+registration.Token)
		}
		// Log chunks are not idempotent. Avoid the general API helper's retry/backoff
		// loop, which duplicates chunks and can extend shutdown after cancellation.
		_, _, err = doPreflightJSONOnce(client, request)
		return err
	})
	activeJobLog.mu.Lock()
	activeJobLog.shipper = shipper
	activeJobLog.mu.Unlock()
	return func() {
		activeJobLog.mu.Lock()
		if activeJobLog.shipper == shipper {
			activeJobLog.shipper = nil
		}
		activeJobLog.mu.Unlock()
		shipper.stop()
	}
}

// writeActiveJobLog tees a line of command output to the in-flight job, if any.
// Called from the shared redacting writer, so every logged command feeds it.
func writeActiveJobLog(line string) {
	activeJobLog.mu.Lock()
	shipper := activeJobLog.shipper
	activeJobLog.mu.Unlock()
	if shipper == nil {
		return
	}
	shipper.append(line)
}

func (s *jobLogShipper) append(line string) {
	s.mu.Lock()
	if s.stopped || s.overflow {
		s.mu.Unlock()
		return
	}
	// Reserve the marker inside the budget, including already in-flight chunks.
	remaining := jobLogMaxBytes - len(jobLogTruncationMarker) - s.accepted
	if len(line) > remaining {
		count := jobLogPrefixBytes([]byte(line), remaining)
		s.pending.WriteString(line[:count])
		s.pending.WriteString(jobLogTruncationMarker)
		s.accepted += count + len(jobLogTruncationMarker)
		s.overflow = true
	} else {
		s.pending.WriteString(line)
		s.accepted += len(line)
	}
	full := s.pending.Len() >= jobLogFlushBytes || s.overflow
	s.mu.Unlock()
	if full {
		s.signal()
	}
}

// Only the worker calls flush, so requests cannot race or reorder chunks.
func (s *jobLogShipper) flush() {
	for s.ctx.Err() == nil {
		s.mu.Lock()
		count := min(s.pending.Len(), jobLogFlushBytes)
		if count == 0 {
			s.mu.Unlock()
			return
		}
		// Keep UTF-8 code points intact when a chunk boundary crosses a log line.
		count = jobLogPrefixBytes(s.pending.Bytes(), count)
		chunk := string(s.pending.Next(count))
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(s.ctx, durationFromEnv("PREFLIGHT_JOB_LOG_UPLOAD_TIMEOUT", 5*time.Second))
		_ = s.post(ctx, chunk)
		cancel()
		// Failed uploads remain best-effort; complete redacted output stays in the
		// command's local log. Never retry a chunk the server may have accepted.
	}
}

// Do not split valid UTF-8, but do not stall forever on invalid tool output.
func jobLogPrefixBytes(data []byte, count int) int {
	if count >= len(data) {
		return count
	}
	for cut := count; cut >= 0 && cut >= count-utf8.UTFMax+1; cut-- {
		if utf8.RuneStart(data[cut]) {
			return cut
		}
	}
	return count
}

// jobLogUploadEnabled reports whether the server advertised the log-ingest
// capability for this runner. Gated the same way the per-job heartbeat is, so
// an older server does not get posted to.
func jobLogUploadEnabled(registration runnerRegistrationData) bool {
	enabled, ok := registration.Runner.Capabilities["runnerJobLogs"].(bool)
	// Absent means on, matching runnerJobHeartbeatEnabled: the runner advertises
	// the capability, and a server that wants it off says so explicitly.
	return !ok || enabled
}

// redactedLogLine is what the shared writer hands us: already newline-split and
// already run through the transcript redactor. Kept as its own function so the
// tee point is obvious at the call site.
func teeRedactedLogLine(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	writeActiveJobLog(line)
}
