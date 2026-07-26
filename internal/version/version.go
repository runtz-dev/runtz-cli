// Package version holds the single source of truth for the CLI version.
package version

// Version is stamped at release time with:
// go build -ldflags "-X github.com/runtz-dev/runtz-cli/internal/version.Version=1.0.0-rc1"
var Version = "dev"

// Scanner identifies the CLI scanners in ingest payloads.
func Scanner() string {
	return "runtz-cli/" + Version
}
