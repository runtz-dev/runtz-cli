package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/runtz-dev/runtz-cli/internal/report"
)

func TestRunFindsHighSignalSourceIssues(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "app.js")
	if err := os.WriteFile(source, []byte(`const token = "1234567890abcdef1234567890abcdef";
eval(userInput);
`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "ignored.js"), []byte(`eval(ignored);`), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := Run(context.Background(), Options{Path: root, ProjectName: "demo"})
	if err != nil {
		t.Fatal(err)
	}

	if result.ProjectName != "demo" {
		t.Fatalf("ProjectName = %q, want demo", result.ProjectName)
	}
	if result.FilesScanned != 1 {
		t.Fatalf("FilesScanned = %d, want 1", result.FilesScanned)
	}
	if !hasFinding(result.Findings, "SAST003") {
		t.Fatalf("expected SAST003 finding, got %#v", result.Findings)
	}
	if !hasFinding(result.Findings, "SAST004") {
		t.Fatalf("expected SAST004 finding, got %#v", result.Findings)
	}
}

func hasFinding(findings []report.Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}
