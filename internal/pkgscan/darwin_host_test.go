package pkgscan

import (
	"strings"
	"testing"
)

func TestParseBrewListOutput(t *testing.T) {
	output := `wget 1.21.4
jq 1.7.1
openssl@3 3.2.1 3.2.2
`
	packages, err := parseBrewListOutput(strings.NewReader(output), "brew")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(packages))
	}
	if packages[0].Name != "wget" || packages[0].Version != "1.21.4" || packages[0].Manager != "brew" {
		t.Fatalf("unexpected package: %+v", packages[0])
	}
	if packages[2].Name != "openssl@3" || packages[2].Version != "3.2.2" {
		t.Fatalf("expected the last cellar version to win: %+v", packages[2])
	}
}

func TestParseBrewListOutputCasks(t *testing.T) {
	output := "docker 4.29.0\n"
	packages, err := parseBrewListOutput(strings.NewReader(output), "brew-cask")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 || packages[0].Manager != "brew-cask" {
		t.Fatalf("unexpected packages: %+v", packages)
	}
}

func TestParseBrewListOutputIgnoresBlankLines(t *testing.T) {
	output := "\nwget 1.21.4\n\n"
	packages, err := parseBrewListOutput(strings.NewReader(output), "brew")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
}
