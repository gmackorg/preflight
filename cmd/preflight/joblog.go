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
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
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

type jobLogShipper struct {
	mu       sync.Mutex
	pending  bytes.Buffer
	sent     int
	stopped  bool
	overflow bool

	// Injected so tests exercise batching and budgets rather than HTTP.
	post func(chunk string) error

	done chan struct{}
	wg   sync.WaitGroup
}

func newJobLogShipper(post func(chunk string) error) *jobLogShipper {
	return &jobLogShipper{post: post, done: make(chan struct{})}
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
	shipper := newJobLogShipper(func(chunk string) error {
		_, err := postPreflightJSON(
			client,
			runnerEndpoint(options.apiURL, fmt.Sprintf(
				"/api/preflight/v1/runners/%s/jobs/%s/logs",
				registration.Runner.ID, job.ID,
			)),
			registration.Token,
			map[string]any{"chunk": chunk},
		)
		return err
	})

	activeJobLog.mu.Lock()
	activeJobLog.shipper = shipper
	activeJobLog.mu.Unlock()

	shipper.wg.Add(1)
	go func() {
		defer shipper.wg.Done()
		ticker := time.NewTicker(jobLogFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-shipper.done:
				return
			case <-ticker.C:
				shipper.flush()
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			close(shipper.done)
			shipper.wg.Wait()
			// One last flush after the goroutine is gone, so the tail of a
			// failing command — the part anyone actually wants — is not the
			// part that gets dropped.
			shipper.flush()

			activeJobLog.mu.Lock()
			if activeJobLog.shipper == shipper {
				activeJobLog.shipper = nil
			}
			activeJobLog.mu.Unlock()

			shipper.mu.Lock()
			shipper.stopped = true
			shipper.mu.Unlock()
		})
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
	if s.sent+s.pending.Len()+len(line) > jobLogMaxBytes {
		s.overflow = true
		s.pending.WriteString("\n[preflight] log truncated: job exceeded the runner's upload budget\n")
		s.mu.Unlock()
		s.flush()
		return
	}
	s.pending.WriteString(line)
	full := s.pending.Len() >= jobLogFlushBytes
	s.mu.Unlock()

	if full {
		s.flush()
	}
}

func (s *jobLogShipper) flush() {
	s.mu.Lock()
	if s.pending.Len() == 0 {
		s.mu.Unlock()
		return
	}
	chunk := s.pending.String()
	s.pending.Reset()
	s.sent += len(chunk)
	s.mu.Unlock()

	if err := s.post(chunk); err != nil {
		// Deliberately not retried and not surfaced. The lease may simply have
		// ended, or the budget been hit server-side; either way the build is
		// the thing that matters and it is still running.
		return
	}
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
