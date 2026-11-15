package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/runtz-dev/runtz-cli/internal/cloudclient"
	"github.com/runtz-dev/runtz-cli/internal/config"
)

func TestCloudKeyPathWithSpacesAndSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key with spaces.json")
	if err := os.WriteFile(path, []byte(`{"type":"service_account"}`), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := cloudCredentials("gcp", config.Cloud{CredentialsFile: path})
	if err != nil || string(raw) != `{"type":"service_account"}` {
		t.Fatal("could not read key with spaces")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 32769)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = cloudCredentials("gcp", config.Cloud{CredentialsFile: path}); err == nil {
		t.Fatal("accepted oversized key")
	}
}

func TestCloudConfigurationRejectsMissingFieldsWithoutPromptingInCI(t *testing.T) {
	for _, provider := range []string{"gcp", "aws", "azure"} {
		t.Run(provider, func(t *testing.T) {
			t.Setenv("RUNTZ_CONFIG_DIR", t.TempDir())
			for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS"} {
				t.Setenv(name, "")
			}
			if _, err := configureCloud(provider, config.Cloud{}, nil); err == nil {
				t.Fatal("accepted missing cloud configuration")
			}
			cfg, err := config.Load()
			if err != nil || len(cfg.Clouds) != 0 {
				t.Fatal("saved incomplete configuration")
			}
		})
	}
}

// This exercises command configuration, the private API protocol, upload and
// severity gates together. No provider SDK or real cloud account is involved.
func TestCloudCommandRemoteScanUploadAndGate(t *testing.T) {
	t.Setenv("RUNTZ_CONFIG_DIR", t.TempDir())
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString(nonce)
	for key, value := range map[string]string{"RUNTZ_TOKEN": "test-workspace-token", "AZURE_TENANT_ID": "22222222-2222-4222-8222-222222222222", "AZURE_CLIENT_ID": "33333333-3333-4333-8333-333333333333", "AZURE_CLIENT_SECRET": secret} {
		t.Setenv(key, value)
	}
	scope := "11111111-1111-4111-8111-111111111111"
	workspace := "111111111111111111111111"
	var uploads, scans, validations atomic.Int32
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-workspace-token" {
			t.Error("wrong engine authentication")
		}
		if r.URL.Path == "/api/v1/keys/verify" {
			fmtBody := map[string]any{"workspace": map[string]string{"id": workspace}}
			json.NewEncoder(w).Encode(fmtBody)
			return
		}
		if r.URL.Path != "/api/v1/ingest/cloud" {
			t.Error("unexpected engine route")
			w.WriteHeader(404)
			return
		}
		var body struct {
			Name   string             `json:"name"`
			Result cloudclient.Result `json:"result"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			t.Error("engine received extra data or credentials", err)
		}
		if body.Result.Provider != "azure" || len(body.Result.Checks) != 1 || body.Result.Checks[0].RuleID != "NEW-SERVER-CHECK" {
			t.Error("private check result lost")
		}
		uploads.Add(1)
		json.NewEncoder(w).Encode(map[string]string{"id": "connection-id"})
	}))
	defer engine.Close()
	t.Setenv("RUNTZ_ENDPOINT", engine.URL)
	security := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Scope       string `json:"scope"`
			Credentials struct {
				ClientSecret string `json:"clientSecret"`
			} `json:"credentials"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Scope != scope || body.Credentials.ClientSecret != secret || r.Header.Get("Authorization") != "Bearer test-workspace-token" {
			t.Error("Security did not receive runtime authorization")
		}
		if strings.HasSuffix(r.URL.Path, "/validate") {
			validations.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"valid": true, "workspaceId": workspace})
			return
		}
		scans.Add(1)
		encoder := json.NewEncoder(w)
		encoder.Encode(map[string]string{"type": "started", "workspaceId": workspace})
		encoder.Encode(map[string]string{"type": "heartbeat"})
		now := time.Now().UTC()
		result := cloudclient.Result{Provider: "azure", SubscriptionID: scope, CatalogVersion: "future-private-catalog", StartedAt: now, FinishedAt: now, Summary: cloudclient.Summary{Failed: 1, High: 1}, Checks: []cloudclient.Check{{RuleID: "NEW-SERVER-CHECK", Status: "fail", Severity: "high"}}, Findings: []cloudclient.Finding{{RuleID: "NEW-SERVER-CHECK", Severity: "high"}}}
		encoder.Encode(map[string]any{"type": "result", "workspaceId": workspace, "result": result})
	}))
	defer security.Close()
	if err := runCloud("azure", []string{"config", "--subscription-id", scope, "--security-endpoint", security.URL}); err != nil {
		t.Fatal(err)
	}
	if scans.Load() != 0 || uploads.Load() != 0 || validations.Load() != 1 {
		t.Fatal("config unexpectedly scanned or uploaded")
	}
	cfg, err := config.Load()
	if err != nil || cfg.SecurityEndpoint != security.URL || cfg.Clouds["azure"].Scope != scope {
		t.Fatal("configuration was not saved")
	}
	// The saved endpoint is used without a flag, and a new private check triggers
	// the shared gate only after its result has reached the workspace.
	err = runCloud("azure", []string{"--high-threshold", "1"})
	if !errors.Is(err, errThresholdBreached) || scans.Load() != 1 || uploads.Load() != 1 {
		t.Fatal("remote scan/gate/upload sequence failed", err)
	}
	// A mismatched Security environment never produces a workspace upload.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"type": "started", "workspaceId": "222222222222222222222222"})
	}))
	defer other.Close()
	if err := runCloud("azure", []string{"--security-endpoint", other.URL}); err == nil || uploads.Load() != 1 {
		t.Fatal("published a result from a mismatched workspace")
	}
}
