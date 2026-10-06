package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

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
func (r *recorder) upload(_ context.Context, chunk string) error { return r.post(chunk) }
func (r *recorder) all() string                                  { r.mu.Lock(); defer r.mu.Unlock(); return strings.Join(r.chunks, "") }
func (r *recorder) count() int                                   { r.mu.Lock(); defer r.mu.Unlock(); return len(r.chunks) }

func TestJobLogShipperBatchesInsteadOfPostingPerLine(t *testing.T) {
	rec := &recorder{}
	s := newJobLogShipper(rec.upload)
	defer s.stop()
	for i := 0; i < 50; i++ {
		s.append("building...\n")
	}
	if rec.count() != 0 {
		t.Fatal("posted before threshold/timer")
	}
	s.stop()
	if rec.count() != 1 || strings.Count(rec.all(), "building...") != 50 {
		t.Fatal("batched lines lost")
	}
}

func TestJobLogShipperFlushesOnceBufferIsFull(t *testing.T) {
	posted := make(chan struct{}, 1)
	s := newJobLogShipper(func(_ context.Context, chunk string) error { posted <- struct{}{}; return nil })
	defer s.stop()
	s.append(strings.Repeat("x", jobLogFlushBytes))
	select {
	case <-posted:
	case <-time.After(time.Second):
		t.Fatal("threshold did not wake uploader")
	}
}

func TestJobLogShipperBudgetIncludesInflightAndTruncation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	rec := &recorder{}
	var once sync.Once
	s := newJobLogShipper(func(_ context.Context, chunk string) error {
		once.Do(func() { close(entered); <-release })
		return rec.post(chunk)
	})
	defer s.stop()
	s.append(strings.Repeat("first", jobLogFlushBytes/5+1))
	<-entered
	s.append(strings.Repeat("y", jobLogMaxBytes+1))
	s.append("must be dropped")
	close(release)
	s.stop()
	got := rec.all()
	if len(got) > jobLogMaxBytes || !strings.HasSuffix(got, jobLogTruncationMarker) || strings.Count(got, jobLogTruncationMarker) != 1 || strings.Contains(got, "must be dropped") {
		t.Fatalf("incorrect budget/truncation: bytes=%d", len(got))
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, chunk := range rec.chunks {
		if len(chunk) > jobLogFlushBytes {
			t.Fatal("oversized request")
		}
	}
}

func TestJobLogShipperFlushIsANoOpWhenEmpty(t *testing.T) {
	rec := &recorder{}
	s := newJobLogShipper(rec.upload)
	s.stop()
	s.stop()
	if rec.count() != 0 {
		t.Fatal("empty posts")
	}
}

func TestJobLogShipperSurvivesAFailingServer(t *testing.T) {
	rec := &recorder{err: errors.New("503")}
	s := newJobLogShipper(rec.upload)
	s.append(strings.Repeat("x", jobLogFlushBytes*2))
	s.stop()
	if rec.count() != 2 {
		t.Fatalf("subsequent chunks skipped or retried: %d", rec.count())
	}
}

func TestTeeIgnoresBlankLinesAndUnclaimedOutput(t *testing.T) {
	activeJobLog.mu.Lock()
	activeJobLog.shipper = nil
	activeJobLog.mu.Unlock()
	teeRedactedLogLine("orphan\n")
	rec := &recorder{}
	s := newJobLogShipper(rec.upload)
	activeJobLog.mu.Lock()
	activeJobLog.shipper = s
	activeJobLog.mu.Unlock()
	defer func() { activeJobLog.mu.Lock(); activeJobLog.shipper = nil; activeJobLog.mu.Unlock(); s.stop() }()
	teeRedactedLogLine("  \n")
	teeRedactedLogLine("real line\n")
	s.stop()
	if rec.all() != "real line\n" {
		t.Fatal("unexpected tee output")
	}
}

func TestJobLogChunksPreserveUTF8AndOrder(t *testing.T) {
	rec := &recorder{}
	s := newJobLogShipper(rec.upload)
	expected := strings.Repeat("a", jobLogFlushBytes-1) + strings.Repeat("🐱 line\n", 4000)
	s.append(expected)
	s.stop()
	if rec.all() != expected {
		t.Fatal("output reordered or lost")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, chunk := range rec.chunks {
		if !utf8.ValidString(chunk) {
			t.Fatal("split UTF8 rune")
		}
	}
}

func TestJobLogInvalidToolOutputDoesNotStallDrain(t *testing.T) {
	rec := &recorder{}
	s := newJobLogShipper(rec.upload)
	expected := strings.Repeat("\x80", jobLogFlushBytes*2)
	s.append(expected)
	s.stop()
	if rec.all() != expected {
		t.Fatal("invalid tool bytes blocked or vanished in queue")
	}
}
