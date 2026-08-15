package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/runtz-dev/runtz-cli/internal/config"
	"github.com/runtz-dev/runtz-cli/internal/gate"
	"github.com/runtz-dev/runtz-cli/internal/report"
	"github.com/runtz-dev/runtz-cli/internal/sca"
)

func TestEnforceThresholds(t *testing.T) {
	sevs := []string{"critical", "high", "high"}

	// No gate configured: never fails, even with findings.
	if err := enforceThresholds(gate.Thresholds{}, sevs); err != nil {
		t.Fatalf("inactive thresholds returned %v, want nil", err)
	}

	// Gate tripped: returns the sentinel main maps to exit 3.
	if err := enforceThresholds(gate.Thresholds{Critical: 1}, sevs); !errors.Is(err, errThresholdBreached) {
		t.Fatalf("critical gate returned %v, want errThresholdBreached", err)
	}

	// Gate configured but not reached: passes.
	if err := enforceThresholds(gate.Thresholds{Critical: 2}, sevs); err != nil {
		t.Fatalf("unmet critical gate returned %v, want nil", err)
	}

	// No findings at all: passes even with a strict gate.
	if err := enforceThresholds(gate.Thresholds{Critical: 1}, nil); err != nil {
		t.Fatalf("gate with no findings returned %v, want nil", err)
	}
}

func TestWindowsHostScanningError(t *testing.T) {
	if got := errHostScanningUnsupported.Error(); got != "Host scanning is not supported on Windows" {
		t.Fatalf("Windows host scanning error = %q", got)
	}
}

// clearAuthEnv detaches the test from any token/endpoint in the caller's
// environment and points the config file at an empty temp dir.
func clearAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv("RUNTZ_TOKEN", "")
	t.Setenv("RUNTZ_API_KEY", "")
	t.Setenv("RUNTZ_ENDPOINT", "")
	t.Setenv("RUNTZ_CONFIG_DIR", t.TempDir())
}

func TestResolveAuthPrecedence(t *testing.T) {
	clearAuthEnv(t)
	if _, err := config.Save(config.Config{Endpoint: "http://stored:8080", Token: "stored-token"}); err != nil {
		t.Fatalf("Save returned %v", err)
	}

	// Flag beats environment and config.
	t.Setenv("RUNTZ_TOKEN", "env-token")
	auth := authOptions{Token: "flag-token", Endpoint: "http://flag:8080"}
	source, err := resolveAuth(&auth)
	if err != nil {
		t.Fatalf("resolveAuth returned %v", err)
	}
	if auth.Token != "flag-token" || auth.Endpoint != "http://flag:8080" || source != "--token flag" {
		t.Fatalf("flag precedence: got token=%q endpoint=%q source=%q", auth.Token, auth.Endpoint, source)
	}

	// Environment beats config.
	auth = authOptions{}
	source, err = resolveAuth(&auth)
	if err != nil {
		t.Fatalf("resolveAuth returned %v", err)
	}
	if auth.Token != "env-token" || source != "RUNTZ_TOKEN environment variable" {
		t.Fatalf("env precedence: got token=%q source=%q", auth.Token, source)
	}
	// Endpoint falls through to the stored one even when the token came from
	// the environment.
	if auth.Endpoint != "http://stored:8080" {
		t.Fatalf("env precedence: endpoint = %q, want stored endpoint", auth.Endpoint)
	}

	// Config is used when flag and environment are empty.
	t.Setenv("RUNTZ_TOKEN", "")
	auth = authOptions{}
	source, err = resolveAuth(&auth)
	if err != nil {
		t.Fatalf("resolveAuth returned %v", err)
	}
	if auth.Token != "stored-token" || auth.Endpoint != "http://stored:8080" {
		t.Fatalf("config fallback: got token=%q endpoint=%q", auth.Token, auth.Endpoint)
	}
	if !strings.HasPrefix(source, "stored login (") {
		t.Fatalf("config fallback: source = %q, want stored login", source)
	}
}

func TestResolveAuthDefaultsEndpointToSaaS(t *testing.T) {
	clearAuthEnv(t)
	auth := authOptions{Token: "flag-token"}
	if _, err := resolveAuth(&auth); err != nil {
		t.Fatalf("resolveAuth returned %v", err)
	}
	if auth.Endpoint != saasEndpoint {
		t.Fatalf("endpoint = %q, want SaaS default %q", auth.Endpoint, saasEndpoint)
	}
}

func TestRequireAuthPointsToLogin(t *testing.T) {
	clearAuthEnv(t)
	auth := authOptions{}
	err := requireAuth(&auth)
	if err == nil {
		t.Fatal("requireAuth with no token returned nil, want error")
	}
	if !strings.Contains(err.Error(), "runtz login") {
		t.Fatalf("requireAuth error = %q, want a pointer to runtz login", err)
	}

	// RUNTZ_API_KEY still works as the deprecated alias.
	t.Setenv("RUNTZ_API_KEY", "legacy-token")
	auth = authOptions{}
	if err := requireAuth(&auth); err != nil {
		t.Fatalf("requireAuth with RUNTZ_API_KEY returned %v", err)
	}
	if auth.Token != "legacy-token" {
		t.Fatalf("token = %q, want legacy-token", auth.Token)
	}
}

func TestSeverityExtractors(t *testing.T) {
	scaVulns := []sca.Vulnerability{{Severity: "CRITICAL"}, {Severity: "high"}}
	if got := scaSeverities(scaVulns); len(got) != 2 || got[0] != "CRITICAL" {
		t.Fatalf("scaSeverities = %v", got)
	}
	findings := []report.Finding{{Severity: "medium"}, {Severity: "low"}, {Severity: "low"}}
	if got := findingSeverities(findings); len(got) != 3 {
		t.Fatalf("findingSeverities = %v", got)
	}
	// End-to-end through the gate: two lows trip --low-threshold 2.
	if err := enforceThresholds(gate.Thresholds{Low: 2}, findingSeverities(findings)); !errors.Is(err, errThresholdBreached) {
		t.Fatalf("low gate returned %v, want errThresholdBreached", err)
	}
}
