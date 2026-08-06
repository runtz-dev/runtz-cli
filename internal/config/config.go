// Package config stores the credentials `runtz login` saves so scan commands
// can run without --token. The file lives at os.UserConfigDir()/runtz/config.json
// (~/.config/runtz/config.json on Linux) with 0600 permissions, and is the
// lowest-precedence token source: --token and RUNTZ_TOKEN always win over it.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

type Config struct {
	// Endpoint is only stored for self-hosted deployments; empty means the
	// Runtz SaaS default.
	Endpoint string `json:"endpoint,omitempty"`
	Token    string `json:"token,omitempty"`
}

// Path returns the config file location without touching the filesystem.
// RUNTZ_CONFIG_DIR overrides the directory (useful for tests and shared CI
// caches); otherwise it is os.UserConfigDir()/runtz.
func Path() (string, error) {
	if dir := os.Getenv("RUNTZ_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "config.json"), nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(base, "runtz", "config.json"), nil
}

// Load reads the stored credentials. A missing file is not an error: it
// returns a zero Config so callers fall through to their defaults.
func Load() (Config, error) {
	path, err := Path()
	if err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// Save writes the credentials with owner-only permissions, creating the
// directory when needed. The write goes through a temp file + rename so a
// crash never leaves a half-written token behind.
func Save(cfg Config) (string, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "config-*.json")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

// ClearToken removes the stored token but keeps a self-hosted endpoint, so
// logging out doesn't force self-hosted users to re-discover their URL. When
// nothing else remains the file is deleted. Returns whether a token existed.
func ClearToken() (bool, error) {
	cfg, err := Load()
	if err != nil {
		return false, err
	}
	hadToken := cfg.Token != ""
	cfg.Token = ""
	path, err := Path()
	if err != nil {
		return hadToken, err
	}
	if cfg.Endpoint == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return hadToken, err
		}
		return hadToken, nil
	}
	_, err = Save(cfg)
	return hadToken, err
}
