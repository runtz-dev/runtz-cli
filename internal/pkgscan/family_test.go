package pkgscan

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFamilyForOS(t *testing.T) {
	cases := []struct {
		id     string
		idLike string
		family packageFamily
	}{
		{"ubuntu", "debian", familyDpkg},
		{"debian", "", familyDpkg},
		{"linuxmint", "ubuntu debian", familyDpkg},
		{"alpine", "", familyAPK},
		{"arch", "", familyPacman},
		{"manjaro", "arch", familyPacman},
		{"rocky", "rhel centos fedora", familyRPM},
		{"almalinux", "rhel centos fedora", familyRPM},
		{"rhel", "fedora", familyRPM},
		{"opensuse-leap", "suse opensuse", familyRPM},
		{"fedora", "", familyRPM},
	}
	for _, testCase := range cases {
		family, err := familyForOS(OSRelease{ID: testCase.id, IDLike: testCase.idLike})
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", testCase.id, err)
		}
		if family != testCase.family {
			t.Fatalf("%s: expected %s, got %s", testCase.id, testCase.family, family)
		}
	}

	if _, err := familyForOS(OSRelease{ID: "haiku"}); err == nil {
		t.Fatal("expected error for unsupported distribution")
	}
}

func TestEcosystemForOS(t *testing.T) {
	cases := []struct {
		osRelease OSRelease
		ecosystem string
	}{
		{OSRelease{ID: "ubuntu", VersionID: "22.04", Version: "22.04.4 LTS (Jammy Jellyfish)"}, "Ubuntu:22.04:LTS"},
		{OSRelease{ID: "debian", VersionID: "12"}, "Debian:12"},
		{OSRelease{ID: "alpine", VersionID: "3.19.1"}, "Alpine:v3.19"},
		{OSRelease{ID: "rocky", VersionID: "9.3"}, "Rocky Linux"},
		{OSRelease{ID: "almalinux", VersionID: "9.3"}, "AlmaLinux"},
		{OSRelease{ID: "rhel", VersionID: "9.3"}, "Red Hat"},
		{OSRelease{ID: "arch"}, ""},
		{OSRelease{ID: "fedora", VersionID: "40"}, ""},
	}
	for _, testCase := range cases {
		if ecosystem := ecosystemForOS(testCase.osRelease); ecosystem != testCase.ecosystem {
			t.Fatalf("%s: expected %q, got %q", testCase.osRelease.ID, testCase.ecosystem, ecosystem)
		}
	}
}

func TestParseApkInstalled(t *testing.T) {
	database := `C:Q1pKAgUXqFPJTGtM4CT4sqHkOnZVc=
P:musl
V:1.2.4_git20230717-r4
A:x86_64
o:musl
t:1715254011

C:Q1pyGVoqzNs28li8DFLLcU1DsNq8c=
P:ssl_client
V:1.36.1-r15
A:x86_64
o:busybox
`
	packages, err := parseApkInstalled(strings.NewReader(database))
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}
	if packages[0].Name != "musl" || packages[0].Version != "1.2.4_git20230717-r4" || packages[0].Manager != "apk" {
		t.Fatalf("unexpected package: %+v", packages[0])
	}
	if packages[1].Name != "ssl_client" || packages[1].SourceName != "busybox" {
		t.Fatalf("expected origin busybox: %+v", packages[1])
	}
}

func TestParsePacmanLocal(t *testing.T) {
	root := t.TempDir()
	descDir := filepath.Join(root, "openssl-3.2.1-1")
	if err := os.MkdirAll(descDir, 0o755); err != nil {
		t.Fatal(err)
	}
	desc := `%NAME%
openssl

%VERSION%
3.2.1-1

%BASE%
openssl

%ARCH%
x86_64
`
	if err := os.WriteFile(filepath.Join(descDir, "desc"), []byte(desc), 0o600); err != nil {
		t.Fatal(err)
	}

	packages, err := parsePacmanLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "openssl" || packages[0].Version != "3.2.1-1" || packages[0].Manager != "pacman" {
		t.Fatalf("unexpected package: %+v", packages[0])
	}
}

func TestParseRPMQueryOutput(t *testing.T) {
	output := "openssl-libs\t1\t3.0.7\t27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\n" +
		"bash\t0\t5.1.8\t9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm\n" +
		"gpg-pubkey\t0\tfd431d51\t4ae0493b\t(none)\t(none)\n"

	packages, err := parseRPMQueryOutput(bytes.NewBufferString(output))
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 {
		t.Fatalf("expected 2 packages (gpg-pubkey skipped), got %d", len(packages))
	}
	if packages[1].Name != "openssl-libs" || packages[1].Version != "1:3.0.7-27.el9" {
		t.Fatalf("unexpected epoch handling: %+v", packages[1])
	}
	if packages[1].SourceName != "openssl" {
		t.Fatalf("expected source rpm name openssl: %+v", packages[1])
	}
}

func TestCvssBaseScore(t *testing.T) {
	cases := []struct {
		vector string
		score  float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5},
		{"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
	}
	for _, testCase := range cases {
		score, ok := cvssBaseScore(testCase.vector)
		if !ok {
			t.Fatalf("%s: expected parseable vector", testCase.vector)
		}
		if score != testCase.score {
			t.Fatalf("%s: expected %.1f, got %.1f", testCase.vector, testCase.score, score)
		}
	}

	if _, ok := cvssBaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"); ok {
		t.Fatal("CVSS 4 vectors should not be parsed by the 3.x calculator")
	}
	if severity := severityFromScore(9.8); severity != "critical" {
		t.Fatalf("expected critical, got %s", severity)
	}
}
