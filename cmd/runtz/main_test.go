package main

import (
	"errors"
	"testing"

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
