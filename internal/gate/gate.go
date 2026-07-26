// Package gate implements the CI/CD severity gates shared by every scan
// command. A scan can be told to fail (non-zero exit) when the number of
// findings at a given severity reaches a threshold, which is how a runtz scan
// breaks a pipeline on, say, "any critical vulnerability".
package gate

import (
	"fmt"
	"sort"
	"strings"
)

// Severity buckets, lower-case, as normalized by Normalize.
const (
	Critical = "critical"
	High     = "high"
	Medium   = "medium"
	Low      = "low"
	Unknown  = "unknown"
)

// Thresholds is the minimum count of findings at each severity that fails the
// scan. Zero means the gate is off for that severity.
type Thresholds struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// Active reports whether at least one gate is enabled.
func (t Thresholds) Active() bool {
	return t.Critical > 0 || t.High > 0 || t.Medium > 0 || t.Low > 0
}

// Counts is the tally of findings per normalized severity.
type Counts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
	Total    int
}

// Normalize maps the various severity spellings the scanners and upstream
// advisories use (e.g. GitHub's "MODERATE", upper-case values) onto the fixed
// buckets. Anything unrecognized becomes Unknown.
func Normalize(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return Critical
	case "high", "important":
		return High
	case "medium", "moderate":
		return Medium
	case "low", "minor", "negligible":
		return Low
	default:
		return Unknown
	}
}

// Count tallies a list of raw severity strings.
func Count(severities []string) Counts {
	var c Counts
	for _, s := range severities {
		c.Total++
		switch Normalize(s) {
		case Critical:
			c.Critical++
		case High:
			c.High++
		case Medium:
			c.Medium++
		case Low:
			c.Low++
		default:
			c.Unknown++
		}
	}
	return c
}

// For returns the count for a normalized severity bucket.
func (c Counts) For(severity string) int {
	switch severity {
	case Critical:
		return c.Critical
	case High:
		return c.High
	case Medium:
		return c.Medium
	case Low:
		return c.Low
	default:
		return c.Unknown
	}
}

// Breach records a single gate that was met or exceeded.
type Breach struct {
	Severity  string
	Count     int
	Threshold int
}

func (b Breach) String() string {
	return fmt.Sprintf("%s: %d (threshold %d)", b.Severity, b.Count, b.Threshold)
}

// Evaluate returns every gate that the counts meet or exceed, most severe
// first. An empty slice means the scan passes.
func (t Thresholds) Evaluate(c Counts) []Breach {
	var breaches []Breach
	check := func(severity string, threshold, count int) {
		if threshold > 0 && count >= threshold {
			breaches = append(breaches, Breach{Severity: severity, Count: count, Threshold: threshold})
		}
	}
	check(Critical, t.Critical, c.Critical)
	check(High, t.High, c.High)
	check(Medium, t.Medium, c.Medium)
	check(Low, t.Low, c.Low)
	return breaches
}

// Summary renders a one-line count of findings by severity for logs.
func (c Counts) Summary() string {
	parts := []string{
		fmt.Sprintf("critical=%d", c.Critical),
		fmt.Sprintf("high=%d", c.High),
		fmt.Sprintf("medium=%d", c.Medium),
		fmt.Sprintf("low=%d", c.Low),
	}
	if c.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("unknown=%d", c.Unknown))
	}
	return strings.Join(parts, " ")
}

// BreachMessage renders the human-readable reason a scan failed its gates.
func BreachMessage(breaches []Breach) string {
	labels := make([]string, 0, len(breaches))
	for _, b := range breaches {
		labels = append(labels, b.String())
	}
	sort.SliceStable(labels, func(i, j int) bool { return i < j })
	return "severity threshold exceeded — " + strings.Join(labels, ", ")
}
