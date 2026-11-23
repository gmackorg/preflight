package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The control plane now rolls a workflow's outcome up to its work order, so
// `build --wait` sees succeeded/failed instead of every order ending cancelled.
func TestWaitForWorkOrderReportsOutcome(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantCode int
		wantOut  []string
	}{
		{
			name:     "succeeded exits zero",
			body:     `{"workOrder":{"id":"pfwo_1","status":"succeeded"}}`,
			wantCode: 0,
			wantOut:  []string{"succeeded"},
		},
		{
			name:     "failed prints the rolled-up failure",
			body:     `{"workOrder":{"id":"pfwo_1","status":"failed","failure":{"code":"maestro_failed","message":"01-app-launches.yaml failed","workflowId":"pfw_9"}}}`,
			wantCode: 1,
			wantOut:  []string{"FAILED: maestro_failed: 01-app-launches.yaml failed", "workflow: pfw_9"},
		},
		{
			name:     "cancelled prints its reason",
			body:     `{"workOrder":{"id":"pfwo_1","status":"cancelled","blockedReason":"abandoned"}}`,
			wantCode: 1,
			wantOut:  []string{"CANCELLED: abandoned"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/preflight/v1/work-orders/pfwo_1" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":true,"data":` + tc.body + `}`))
			}))
			defer server.Close()

			var stdout, stderr bytes.Buffer
			ctx := buildOpsContext{apiURL: server.URL, token: "t", workspaceID: "ws"}
			code := waitForWorkOrder(ctx, server.Client(), "pfwo_1", &stdout, &stderr)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d (stderr %q)", code, tc.wantCode, stderr.String())
			}
			for _, want := range tc.wantOut {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout %q missing %q", stdout.String(), want)
				}
			}
		})
	}
}

// Kinds the farm cannot dispatch fail before any request, with the command to
// use instead.
func TestBuildRejectsUndispatchableKinds(t *testing.T) {
	for kind := range undispatchableKindAdvice {
		var stdout, stderr bytes.Buffer
		code := runBuild([]string{"--app", "pfapp_x", "--kind", kind}, &stdout, &stderr, http.DefaultClient)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2", kind, code)
		}
		if !strings.Contains(stderr.String(), "cannot run on the build farm") {
			t.Errorf("%s: stderr %q lacks guidance", kind, stderr.String())
		}
		if contains(workOrderKinds, kind) {
			t.Errorf("%s is still listed as a dispatchable kind", kind)
		}
	}
}

func TestFetchNodesFilteredRequestsRetiredOnlyWhenAsked(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"data":{"nodes":[],"summary":{}}}`))
	}))
	defer server.Close()
	ctx := buildOpsContext{apiURL: server.URL, token: "t", workspaceID: "ws"}

	if _, _, err := fetchNodes(ctx, server.Client()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fetchNodesFiltered(ctx, server.Client(), true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(queries[0], "includeRetired") {
		t.Errorf("default listing asked for retired nodes: %s", queries[0])
	}
	if !strings.Contains(queries[1], "includeRetired=1") {
		t.Errorf("--all listing did not ask for retired nodes: %s", queries[1])
	}
}
