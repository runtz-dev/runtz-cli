package runtzclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/runtz-dev/runtz-cli/internal/cloudclient"
)

func TestCloudUploadWireContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ingest/cloud" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("incorrect cloud route or authentication")
		}
		var request struct {
			Name   string             `json:"name"`
			Result cloudclient.Result `json:"result"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			t.Error(err)
		}
		if request.Name != "Production" || request.Result.Provider != "gcp" || request.Result.ProjectID != "test-project" {
			t.Error("incorrect cloud result")
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"connection-id"}`))
	}))
	defer server.Close()
	id, err := New(server.URL, "test-token").SendCloud(context.Background(), "Production", cloudclient.Result{Provider: "gcp", ProjectID: "test-project"})
	if err != nil || id != "connection-id" {
		t.Fatalf("upload: %s %v", id, err)
	}
}
