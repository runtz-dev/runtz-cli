package cloudclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const workspace = "111111111111111111111111"

func testResult() Result {
	now := time.Now().UTC()
	return Result{Provider: "gcp", ProjectID: "my-project", CatalogVersion: "new-private-catalog", StartedAt: now, FinishedAt: now, Checks: []Check{{RuleID: "NEW-CHECK-NO-CLI-RELEASE", Status: "fail"}}, Findings: []Finding{{RuleID: "NEW-CHECK-NO-CLI-RELEASE", Severity: "high"}}}
}
func TestRemoteValidationAndScan(t *testing.T) {
	result := testResult()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer workspace-token" || r.Header.Get("X-Runtz-Tenant-ID") != "" || r.Method != "POST" {
			t.Error("invalid public authentication")
		}
		var body struct {
			Scope       string          `json:"scope"`
			Credentials json.RawMessage `json:"credentials"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Scope != "my-project" || string(body.Credentials) != `{"test":true}` {
			t.Error("invalid scan request")
		}
		encoder := json.NewEncoder(w)
		if strings.HasSuffix(r.URL.Path, "/validate") {
			encoder.Encode(map[string]any{"valid": true, "workspaceId": workspace})
			return
		}
		if r.URL.Path != "/v1/cli/gcp/scan" {
			t.Error("wrong scan URL")
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprintf(w, "{\"type\":\"started\",\"workspaceId\":%q}\n{\"type\":\"heartbeat\",\"futureField\":true}\n", workspace)
		encoder.Encode(map[string]any{"type": "result", "workspaceId": workspace, "result": result})
	}))
	defer server.Close()
	client, err := New(server.URL, "workspace-token", workspace)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Validate(context.Background(), "gcp", "my-project", []byte(`{"test":true}`)); err != nil {
		t.Fatal(err)
	}
	got, err := client.Scan(context.Background(), "gcp", "my-project", []byte(`{"test":true}`))
	if err != nil || got.CatalogVersion != result.CatalogVersion || got.Checks[0].RuleID != result.Checks[0].RuleID {
		t.Fatal("new server checks did not reach CLI", err)
	}
}
func TestInvalidOrIncompleteStreamsFail(t *testing.T) {
	result, _ := json.Marshal(testResult())
	started := `{"type":"started","workspaceId":"` + workspace + `"}` + "\n"
	for _, body := range []string{"", started, `{"type":"heartbeat"}`, `{"type":"started","workspaceId":"other-workspace"}`, started + `{"type":"error","error":"must-not-echo-secret"}`, started + `{"type":"result","workspaceId":"other-workspace","result":` + string(result) + `}`, started + `{"type":"result","workspaceId":"` + workspace + `","result":{}}`, started + `{"type":"result","workspaceId":"` + workspace + `","result":` + strings.Replace(string(result), "my-project", "wrong-project", 1) + `}`} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer server.Close()
			client, _ := New(server.URL, "token", workspace)
			_, err := client.Scan(context.Background(), "gcp", "my-project", []byte(`{}`))
			if err == nil || strings.Contains(err.Error(), "must-not-echo-secret") {
				t.Fatal("accepted invalid stream or leaked error")
			}
		})
	}
}
func TestSecurityEndpointSafetyAndEnvironment(t *testing.T) {
	for _, endpoint := range []string{"http://security.example.com", "https://user:pass@security.example.com", "https://security.example.com?token=secret", "https://security.example.com#fragment", "//security.example.com", ""} {
		if _, err := New(endpoint, "token", workspace); err == nil {
			t.Fatal("accepted unsafe endpoint")
		}
	}
	for _, tc := range []struct{ engine, want string }{{"https://engine.runtz.dev", DefaultEndpoint}, {"https://engine-dev.runtz.dev/", "https://security-dev.runtz.dev"}} {
		got, err := Endpoint("", tc.engine)
		if err != nil || got != tc.want {
			t.Fatal(got, err)
		}
	}
	if _, err := Endpoint("", "https://self-host.example"); err == nil {
		t.Fatal("self-hosted credentials would go to SaaS")
	}
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	client, _ := New(redirect.URL, "token", workspace)
	if err := client.Validate(context.Background(), "azure", "subscription", []byte(`{}`)); err == nil || leaked.Load() {
		t.Fatal("redirect leaked credentials")
	}
}
func TestCancellationStopsStream(t *testing.T) {
	stopped := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "{\"type\":\"started\",\"workspaceId\":%q}\n", workspace)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(stopped)
	}))
	defer server.Close()
	client, _ := New(server.URL, "token", workspace)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.Scan(ctx, "gcp", "my-project", []byte(`{}`)); err == nil {
		t.Fatal("canceled scan succeeded")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("server not canceled")
	}
}
