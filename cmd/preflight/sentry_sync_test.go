package main

import (
	"encoding/json"
	"testing"
)

func TestMapSentryLevel(t *testing.T) {
	cases := map[string]string{
		"fatal": "fatal", "error": "error", "warning": "warning",
		"info": "info", "debug": "info", "sample": "info", "weird": "error",
	}
	for in, want := range cases {
		if got := mapSentryLevel(in); got != want {
			t.Errorf("mapSentryLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSentryRuntimeAndPlatform(t *testing.T) {
	runtime := map[string]string{
		"unity":        "unity",
		"csharp":       "unity",
		"node":         "node",
		"javascript":   "expo",
		"react-native": "expo",
		"cocoa":        "expo",
		"java-android": "expo",
		"python":       "",
	}
	for in, want := range runtime {
		if got := sentryRuntime(in); got != want {
			t.Errorf("sentryRuntime(%q) = %q, want %q", in, got, want)
		}
	}
	platform := map[string]string{
		"cocoa": "ios", "apple-ios": "ios", "java-android": "android",
		"android": "android", "javascript": "",
	}
	for in, want := range platform {
		if got := sentryPlatform(in); got != want {
			t.Errorf("sentryPlatform(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSentryFramesToStackReversesOrder(t *testing.T) {
	// Sentry frames are bottom-to-top; we want most-recent-first.
	frames := []sentryAPIFrame{
		{Function: "main", Filename: "index.js", InApp: true},
		{Function: "render", AbsPath: "/abs/Screen.tsx", LineNo: 42, InApp: true},
	}
	stack := sentryFramesToStack(frames)
	if len(stack) != 2 {
		t.Fatalf("want 2 frames, got %d", len(stack))
	}
	if stack[0].Function != "render" {
		t.Errorf("top frame = %q, want render", stack[0].Function)
	}
	if stack[0].Filename != "/abs/Screen.tsx" {
		t.Errorf("absPath fallback failed: %q", stack[0].Filename)
	}
	if stack[1].Function != "main" {
		t.Errorf("bottom frame = %q, want main", stack[1].Function)
	}
}

func TestExtractSentryException(t *testing.T) {
	data, _ := json.Marshal(sentryExceptionData{
		Values: []struct {
			Type       string `json:"type"`
			Value      string `json:"value"`
			Stacktrace struct {
				Frames []sentryAPIFrame `json:"frames"`
			} `json:"stacktrace"`
		}{
			{
				Type:  "TypeError",
				Value: "undefined is not an object",
				Stacktrace: struct {
					Frames []sentryAPIFrame `json:"frames"`
				}{Frames: []sentryAPIFrame{{Function: "boom", InApp: true}}},
			},
		},
	})
	event := &sentryEvent{
		Entries: []struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}{
			{Type: "breadcrumbs", Data: json.RawMessage(`{}`)},
			{Type: "exception", Data: data},
		},
	}
	typ, val, stack := extractSentryException(event)
	if typ != "TypeError" || val != "undefined is not an object" {
		t.Fatalf("got type=%q value=%q", typ, val)
	}
	if len(stack) != 1 || stack[0].Function != "boom" {
		t.Fatalf("stack = %+v", stack)
	}
	// Nil event yields nothing rather than panicking.
	if _, _, s := extractSentryException(nil); s != nil {
		t.Errorf("nil event should give nil stack")
	}
}

func TestNormalizeSentryIssue(t *testing.T) {
	issue := sentryIssue{
		ID:        "556677",
		Title:     "TypeError: boom",
		Culprit:   "ProfileScreen",
		Level:     "fatal",
		Permalink: "https://sentry.io/org/proj/issues/556677/",
		Count:     "1200",
		UserCount: 47,
		LastSeen:  "2026-08-09T10:00:00Z",
		FirstSeen: "2026-08-01T10:00:00Z",
		Platform:  "javascript",
	}
	issue.Metadata.Type = "TypeError"
	issue.Metadata.Value = "boom from metadata"

	// No latest event: falls back to issue metadata.
	p := normalizeSentryIssue(issue, nil)
	if p.Provider != "sentry" || p.ProviderIssueID != "556677" {
		t.Fatalf("provider/issueId wrong: %+v", p)
	}
	if p.Level != "fatal" || !p.IsFatal {
		t.Errorf("level/isFatal wrong: %+v", p)
	}
	if p.Runtime != "expo" {
		t.Errorf("runtime = %q, want expo", p.Runtime)
	}
	if p.Type != "TypeError" || p.Message != "boom from metadata" {
		t.Errorf("type/message wrong: %q / %q", p.Type, p.Message)
	}
	if p.IssueURL != issue.Permalink || p.OccurredAt != issue.LastSeen {
		t.Errorf("permalink/occurredAt wrong: %+v", p)
	}
	if p.Context["sentryEventCount"] != 1200 || p.Context["sentryUserCount"] != 47 {
		t.Errorf("context counts wrong: %+v", p.Context)
	}

	// With a latest event: prefers event exception + release + eventID.
	excData, _ := json.Marshal(map[string]any{
		"values": []map[string]any{{
			"type":  "TypeError",
			"value": "real value from event",
			"stacktrace": map[string]any{
				"frames": []map[string]any{{"function": "render", "inApp": true}},
			},
		}},
	})
	event := &sentryEvent{EventID: "deadbeef", Platform: "cocoa", Release: "1.4.0 (231)"}
	event.Entries = []struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}{{Type: "exception", Data: excData}}
	p2 := normalizeSentryIssue(issue, event)
	if p2.ProviderEventID != "deadbeef" {
		t.Errorf("eventId = %q, want deadbeef", p2.ProviderEventID)
	}
	if p2.Message != "real value from event" {
		t.Errorf("message = %q, want event value", p2.Message)
	}
	if p2.Release != "1.4.0 (231)" {
		t.Errorf("release = %q", p2.Release)
	}
	if p2.Platform != "ios" {
		t.Errorf("platform = %q, want ios (cocoa)", p2.Platform)
	}
	if len(p2.Stack) != 1 || p2.Stack[0].Function != "render" {
		t.Errorf("stack from event wrong: %+v", p2.Stack)
	}
}

func TestMatchSentryProject(t *testing.T) {
	aliases := map[string]string{"classcheck": "pfapp_seed_classcheck"}
	bySlug := map[string]string{"crucible": "pfapp_crucible"}
	byName := map[string]string{"class check": "pfapp_classcheck"}
	if id := matchSentryProject(sentryProject{Slug: "Crucible"}, aliases, bySlug, byName); id != "pfapp_crucible" {
		t.Errorf("slug match failed: %q", id)
	}
	if id := matchSentryProject(sentryProject{Slug: "x", Name: "Class Check"}, aliases, bySlug, byName); id != "pfapp_classcheck" {
		t.Errorf("name match failed: %q", id)
	}
	if id := matchSentryProject(sentryProject{Slug: "unknown", Name: "nope"}, aliases, bySlug, byName); id != "" {
		t.Errorf("expected no match, got %q", id)
	}
	// The mobile Sentry project resolves to the base app via suffix stripping.
	if id := matchSentryProject(sentryProject{Slug: "crucible-mobile"}, aliases, bySlug, byName); id != "pfapp_crucible" {
		t.Errorf("suffix-stripped match failed: %q", id)
	}
	if id := matchSentryProject(sentryProject{Slug: "crucible-backend"}, aliases, bySlug, byName); id != "" {
		t.Errorf("non-app suffix should not match base: %q", id)
	}
	// Alias wins, including via suffix-stripped base (classcheck-mobile).
	if id := matchSentryProject(sentryProject{Slug: "classcheck"}, aliases, bySlug, byName); id != "pfapp_seed_classcheck" {
		t.Errorf("alias match failed: %q", id)
	}
	if id := matchSentryProject(sentryProject{Slug: "classcheck-mobile"}, aliases, bySlug, byName); id != "pfapp_seed_classcheck" {
		t.Errorf("alias via suffix-strip failed: %q", id)
	}
}
