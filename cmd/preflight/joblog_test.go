package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// recorder captures the chunks a shipper posts, safely across the flush
// goroutine.
type recorder struct {
	mu     sync.Mutex
	chunks []string
	err    error
}

func (r *recorder) post(chunk string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chunks = append(r.chunks, chunk)
	return r.err
}

func (r *recorder) all() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.chunks, "")
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.chunks)
}

func TestJobLogShipperBatchesInsteadOfPostingPerLine(t *testing.T) {
	// xcodebuild emits thousands of lines; one request each would be its own
	// outage. Nothing goes out until a flush.
	rec := &recorder{}
	shipper := newJobLogShipper(rec.post)

	for i := 0; i < 50; i++ {
		shipper.append("building...\n")
	}
	if rec.count() != 0 {
		t.Fatalf("want nothing posted before a flush, got %d chunks", rec.count())
	}

	shipper.flush()
	if rec.count() != 1 {
		t.Fatalf("want one batched chunk, got %d", rec.count())
	}
	if strings.Count(rec.all(), "building...") != 50 {
		t.Fatalf("want all 50 lines in the batch, got %q", rec.all())
	}
}

func TestJobLogShipperFlushesOnceBufferIsFull(t *testing.T) {
	// A burst must not wait out the timer, or the tail of a fast failure lands
	// after anyone has stopped looking.
	rec := &recorder{}
	shipper := newJobLogShipper(rec.post)

	line := strings.Repeat("x", 1024) + "\n"
	for i := 0; i < (jobLogFlushBytes/len(line))+2; i++ {
		shipper.append(line)
	}
	if rec.count() == 0 {
		t.Fatal("want an early flush once the buffer filled, got none")
	}
}

func TestJobLogShipperStopsAtItsBudgetAndSaysSo(t *testing.T) {
	rec := &recorder{}
	shipper := newJobLogShipper(rec.post)

	// One line past the budget.
	shipper.append(strings.Repeat("y", jobLogMaxBytes+1))
	shipper.flush()

	if !strings.Contains(rec.all(), "log truncated") {
		t.Fatalf("want a truncation marker so the gap is explained, got %q", truncate(rec.all(), 120))
	}

	// Everything after the budget is dropped rather than retried forever.
	before := rec.count()
	shipper.append("this should be dropped\n")
	shipper.flush()
	if rec.count() != before {
		t.Fatal("want nothing more posted after the budget was hit")
	}
}

func TestJobLogShipperFlushIsANoOpWhenEmpty(t *testing.T) {
	// The ticker fires on a quiet build too; it must not post empty chunks.
	rec := &recorder{}
	shipper := newJobLogShipper(rec.post)
	shipper.flush()
	shipper.flush()
	if rec.count() != 0 {
		t.Fatalf("want no empty posts, got %d", rec.count())
	}
}

func TestJobLogShipperSurvivesAFailingServer(t *testing.T) {
	// Log shipping must never fail a build. A server that is down costs
	// visibility, not the job.
	rec := &recorder{err: errors.New("503")}
	shipper := newJobLogShipper(rec.post)

	shipper.append("still building\n")
	shipper.flush()
	shipper.append("still building\n")
	shipper.flush()

	if rec.count() != 2 {
		t.Fatalf("want the shipper to keep trying subsequent chunks, got %d", rec.count())
	}
}

func TestTeeIgnoresBlankLinesAndUnclaimedOutput(t *testing.T) {
	// Output produced while no job is in flight has nowhere to go and must not
	// panic; blank lines are not worth a request.
	activeJobLog.mu.Lock()
	activeJobLog.shipper = nil
	activeJobLog.mu.Unlock()
	teeRedactedLogLine("orphan output\n")

	rec := &recorder{}
	shipper := newJobLogShipper(rec.post)
	activeJobLog.mu.Lock()
	activeJobLog.shipper = shipper
	activeJobLog.mu.Unlock()
	defer func() {
		activeJobLog.mu.Lock()
		activeJobLog.shipper = nil
		activeJobLog.mu.Unlock()
	}()

	teeRedactedLogLine("   \n")
	teeRedactedLogLine("real line\n")
	shipper.flush()

	if got := rec.all(); got != "real line\n" {
		t.Fatalf("want only the real line shipped, got %q", got)
	}
}
