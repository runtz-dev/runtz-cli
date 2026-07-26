package k8s

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/runtz-dev/runtz-cli/internal/report"
)

func TestRunFindsManifestPostureIssues(t *testing.T) {
	root := t.TempDir()
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    spec:
      containers:
        - name: api
          image: nginx:latest
          securityContext:
            privileged: true
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: LoadBalancer
`
	if err := os.WriteFile(filepath.Join(root, "deploy.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := Run(context.Background(), Options{Path: root, Target: "prod"})
	if err != nil {
		t.Fatal(err)
	}

	if result.TargetName != "prod" {
		t.Fatalf("TargetName = %q, want prod", result.TargetName)
	}
	if result.FilesScanned != 1 {
		t.Fatalf("FilesScanned = %d, want 1", result.FilesScanned)
	}
	if result.ResourcesScanned != 2 {
		t.Fatalf("ResourcesScanned = %d, want 2", result.ResourcesScanned)
	}
	if !hasFinding(result.Findings, "K8S005") {
		t.Fatalf("expected K8S005 finding, got %#v", result.Findings)
	}
	if !hasFinding(result.Findings, "K8S010") {
		t.Fatalf("expected K8S010 finding, got %#v", result.Findings)
	}
}

func TestRunUsesKubectlWhenPathIsNotProvided(t *testing.T) {
	root := t.TempDir()
	kubectl := filepath.Join(root, "kubectl")
	script := `#!/bin/sh
if [ "$1" = "config" ] && [ "$2" = "current-context" ]; then
  echo kind-test
  exit 0
fi
if [ "$1" = "get" ]; then
  case "$2" in
    pods)
      cat <<'EOF'
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: api
      namespace: prod
    spec:
      containers:
        - name: api
          image: nginx:latest
          securityContext:
            privileged: true
EOF
      ;;
    services)
      cat <<'EOF'
kind: List
items:
  - apiVersion: v1
    kind: Service
    metadata:
      name: api
      namespace: prod
    spec:
      type: NodePort
EOF
      ;;
    *)
      cat <<'EOF'
kind: List
items: []
EOF
      ;;
  esac
  exit 0
fi
exit 1
`
	if err := os.WriteFile(kubectl, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	result, err := Run(context.Background(), Options{
		Kubectl:       kubectl,
		AllNamespaces: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.TargetName != "kind-test" {
		t.Fatalf("TargetName = %q, want kind-test", result.TargetName)
	}
	if result.ResourcesScanned != 2 {
		t.Fatalf("ResourcesScanned = %d, want 2", result.ResourcesScanned)
	}
	if !hasFinding(result.Findings, "K8S005") {
		t.Fatalf("expected K8S005 finding, got %#v", result.Findings)
	}
	if !hasFinding(result.Findings, "K8S010") {
		t.Fatalf("expected K8S010 finding, got %#v", result.Findings)
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
