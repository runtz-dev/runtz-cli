package gate

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"CRITICAL":   Critical,
		"critical":   Critical,
		"High":       High,
		"important":  High,
		"MODERATE":   Medium,
		"moderate":   Medium,
		"medium":     Medium,
		"Low":        Low,
		"negligible": Low,
		"":           Unknown,
		"bogus":      Unknown,
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCount(t *testing.T) {
	c := Count([]string{"CRITICAL", "high", "High", "MODERATE", "low", "low", "low", "weird"})
	if c.Critical != 1 || c.High != 2 || c.Medium != 1 || c.Low != 3 || c.Unknown != 1 {
		t.Fatalf("unexpected counts: %+v", c)
	}
	if c.Total != 8 {
		t.Fatalf("total = %d, want 8", c.Total)
	}
}

func TestThresholdsEvaluate(t *testing.T) {
	counts := Count([]string{"critical", "high", "high", "medium"})

	// Off by default: no thresholds means no breaches.
	if br := (Thresholds{}).Evaluate(counts); len(br) != 0 {
		t.Fatalf("empty thresholds should not breach, got %v", br)
	}
	if (Thresholds{}).Active() {
		t.Fatal("empty thresholds must be inactive")
	}

	// One critical fails --critical-threshold 1.
	br := Thresholds{Critical: 1}.Evaluate(counts)
	if len(br) != 1 || br[0].Severity != Critical {
		t.Fatalf("critical gate: got %v", br)
	}

	// Threshold above the count does not fire.
	if br := (Thresholds{High: 3}).Evaluate(counts); len(br) != 0 {
		t.Fatalf("high threshold 3 with 2 highs should not breach, got %v", br)
	}

	// Exactly meeting the threshold fires (>=).
	if br := (Thresholds{High: 2}).Evaluate(counts); len(br) != 1 {
		t.Fatalf("high threshold 2 with 2 highs should breach, got %v", br)
	}

	// Multiple gates report most-severe first.
	br = Thresholds{Critical: 1, High: 1, Medium: 1}.Evaluate(counts)
	if len(br) != 3 || br[0].Severity != Critical || br[2].Severity != Medium {
		t.Fatalf("multi-gate order wrong: %v", br)
	}
}
