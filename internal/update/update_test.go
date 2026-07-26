package update

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeVersion(t *testing.T) {
	cases := map[string]string{
		"v1.0.0-rc1": "1.0.0-rc1",
		"1.0.0-rc1":  "1.0.0-rc1",
		"dev":        "",
		"":           "",
		"  v2.0.0 ":  "2.0.0",
	}
	for in, want := range cases {
		if got := normalizeVersion(in); got != want {
			t.Errorf("normalizeVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChecksumFor(t *testing.T) {
	sums := "abc123  runtz_linux_amd64\ndef456  runtz_darwin_arm64\n"
	if got, ok := checksumFor(sums, "runtz_darwin_arm64"); !ok || got != "def456" {
		t.Fatalf("checksumFor = %q, %v", got, ok)
	}
	if _, ok := checksumFor(sums, "runtz_windows_amd64"); ok {
		t.Fatal("unexpected match for missing asset")
	}
}

func TestConfirm(t *testing.T) {
	for _, in := range []string{"y\n", "Y\n", "yes\n"} {
		if ok, _ := confirm(&bytes.Buffer{}, strings.NewReader(in), "?"); !ok {
			t.Errorf("confirm(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"n\n", "\n", "no\n", ""} {
		if ok, _ := confirm(&bytes.Buffer{}, strings.NewReader(in), "?"); ok {
			t.Errorf("confirm(%q) = true, want false", in)
		}
	}
}

func newReleasesServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/releases") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func TestLatestTagSkipsDrafts(t *testing.T) {
	srv := newReleasesServer(t, `[{"tag_name":"v1.0.0-rc2","draft":true},{"tag_name":"v1.0.0-rc1","draft":false}]`)
	defer srv.Close()

	// Point the API host at the test server by overriding the repo path is not
	// possible; instead exercise the parser directly via a custom client + URL.
	tag, err := latestTagFromURL(context.Background(), srv.Client(), srv.URL+"/repos/x/y/releases")
	if err != nil {
		t.Fatalf("latestTag error: %v", err)
	}
	if tag != "v1.0.0-rc1" {
		t.Fatalf("tag = %q, want v1.0.0-rc1 (draft skipped)", tag)
	}
}

func TestRunCheckOnly(t *testing.T) {
	srv := newReleasesServer(t, `[{"tag_name":"v1.0.0-rc1","draft":false}]`)
	defer srv.Close()
	client := srv.Client()

	// Up to date: no error.
	var out bytes.Buffer
	err := runWithBaseURL(context.Background(), Options{
		CurrentVersion: "1.0.0-rc1", CheckOnly: true, HTTPClient: client,
		Stdout: &out, Stderr: &out, Stdin: strings.NewReader(""),
	}, srv.URL+"/repos/x/y/releases")
	if err != nil {
		t.Fatalf("up-to-date check returned %v", err)
	}

	// Outdated: ErrUpdateAvailable.
	out.Reset()
	err = runWithBaseURL(context.Background(), Options{
		CurrentVersion: "1.0.0-rc0", CheckOnly: true, HTTPClient: client,
		Stdout: &out, Stderr: &out, Stdin: strings.NewReader(""),
	}, srv.URL+"/repos/x/y/releases")
	if !errors.Is(err, ErrUpdateAvailable) {
		t.Fatalf("outdated check returned %v, want ErrUpdateAvailable", err)
	}
}
