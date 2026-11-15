package config

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestLoadMissingFile(t *testing.T) {
	t.Setenv("RUNTZ_CONFIG_DIR", t.TempDir())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with no file returned %v, want nil", err)
	}
	if !reflect.DeepEqual(cfg, Config{}) {
		t.Fatalf("Load with no file returned %+v, want zero Config", cfg)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("RUNTZ_CONFIG_DIR", t.TempDir())

	want := Config{Endpoint: "http://localhost:8080", Token: "rtz_live_test"}
	path, err := Save(want)
	if err != nil {
		t.Fatalf("Save returned %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load returned %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load = %+v, want %+v", got, want)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat config: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("config file mode = %o, want 600", perm)
		}
	}
}

func TestClearTokenKeepsSelfHostedEndpoint(t *testing.T) {
	t.Setenv("RUNTZ_CONFIG_DIR", t.TempDir())

	if _, err := Save(Config{Endpoint: "http://localhost:8080", Token: "rtz_live_test"}); err != nil {
		t.Fatalf("Save returned %v", err)
	}
	hadToken, err := ClearToken()
	if err != nil {
		t.Fatalf("ClearToken returned %v", err)
	}
	if !hadToken {
		t.Fatal("ClearToken reported no token, want true")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned %v", err)
	}
	if cfg.Token != "" || cfg.Endpoint != "http://localhost:8080" {
		t.Fatalf("after ClearToken config = %+v, want endpoint kept and token empty", cfg)
	}
}

func TestClearTokenRemovesFileWithoutEndpoint(t *testing.T) {
	t.Setenv("RUNTZ_CONFIG_DIR", t.TempDir())

	if _, err := Save(Config{Token: "rtz_live_test"}); err != nil {
		t.Fatalf("Save returned %v", err)
	}
	if _, err := ClearToken(); err != nil {
		t.Fatalf("ClearToken returned %v", err)
	}
	path, err := Path()
	if err != nil {
		t.Fatalf("Path returned %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("config file still exists after ClearToken (stat err: %v)", err)
	}

	// Idempotent: clearing again reports no token and no error.
	hadToken, err := ClearToken()
	if err != nil || hadToken {
		t.Fatalf("second ClearToken = (%v, %v), want (false, nil)", hadToken, err)
	}
}

func TestPathHonorsOverrideDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RUNTZ_CONFIG_DIR", dir)

	path, err := Path()
	if err != nil {
		t.Fatalf("Path returned %v", err)
	}
	if want := filepath.Join(dir, "config.json"); path != want {
		t.Fatalf("Path = %q, want %q", path, want)
	}
}

func TestLogoutPreservesCloudConfigurations(t *testing.T) {
	t.Setenv("RUNTZ_CONFIG_DIR", t.TempDir())
	clouds := map[string]Cloud{"gcp": {Scope: "test-project", CredentialsFile: "/keys/key.json"}, "azure": {Scope: "subscription", TenantID: "tenant"}}
	if _, err := Save(Config{Token: "test-token", Clouds: clouds}); err != nil {
		t.Fatal(err)
	}
	if existed, err := ClearToken(); err != nil || !existed {
		t.Fatal("could not clear login")
	}
	cfg, err := Load()
	if err != nil || cfg.Token != "" || !reflect.DeepEqual(cfg.Clouds, clouds) {
		t.Fatal("logout modified cloud configurations")
	}
	cfg.Token = "replacement-token"
	if _, err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load()
	if err != nil || !reflect.DeepEqual(cfg.Clouds, clouds) {
		t.Fatal("login replacement modified cloud configurations")
	}
}
