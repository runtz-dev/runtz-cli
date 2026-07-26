// Package update implements the `runtz update` self-updater. It resolves the
// newest release of the CLI on GitHub, and (with confirmation) downloads the
// matching binary, verifies its SHA-256 against the release checksums file and
// atomically replaces the running executable.
package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultRepo is the GitHub repository the CLI updates from.
const DefaultRepo = "runtz-dev/runtz-cli"

// ErrUpdateAvailable is returned by Check when a newer release exists. Callers
// map it to a distinct exit code so `runtz update --check` is scriptable in CI.
var ErrUpdateAvailable = errors.New("update available")

// Options configures an update run.
type Options struct {
	Repo           string // GitHub owner/name; defaults to DefaultRepo.
	CurrentVersion string // Running CLI version (version.Version).
	CheckOnly      bool   // Only compare versions, never write.
	AssumeYes      bool   // Skip the confirmation prompt.
	HTTPClient     *http.Client
	Stdout         io.Writer
	Stderr         io.Writer
	Stdin          io.Reader
}

func (o *Options) defaults() {
	if o.Repo == "" {
		o.Repo = DefaultRepo
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
}

// Run performs the update flow. In CheckOnly mode it returns ErrUpdateAvailable
// when a newer release exists (and nil when up to date). Otherwise it prompts
// (unless AssumeYes), downloads, verifies and replaces the binary.
func Run(ctx context.Context, opts Options) error {
	opts.defaults()
	return runWithBaseURL(ctx, opts, releasesURL(opts.Repo))
}

func runWithBaseURL(ctx context.Context, opts Options, releasesURL string) error {
	opts.defaults()

	latest, err := latestTagFromURL(ctx, opts.HTTPClient, releasesURL)
	if err != nil {
		return err
	}
	current := normalizeVersion(opts.CurrentVersion)
	latestNorm := normalizeVersion(latest)

	if current != "" && current == latestNorm {
		fmt.Fprintf(opts.Stdout, "runtz is already up to date (%s).\n", displayVersion(opts.CurrentVersion))
		return nil
	}

	fmt.Fprintf(opts.Stdout, "Update available: %s -> %s\n", displayVersion(opts.CurrentVersion), latest)

	if opts.CheckOnly {
		return ErrUpdateAvailable
	}

	if !opts.AssumeYes {
		ok, err := confirm(opts.Stdout, opts.Stdin, fmt.Sprintf("Update to %s? [y/N] ", latest))
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(opts.Stdout, "Update cancelled.")
			return nil
		}
	}

	return download(ctx, opts, latest)
}

func download(ctx context.Context, opts Options, tag string) error {
	asset := fmt.Sprintf("runtz_%s_%s", runtime.GOOS, runtime.GOARCH)
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", opts.Repo, tag)

	fmt.Fprintf(opts.Stdout, "Downloading %s (%s)...\n", asset, tag)
	binaryData, err := fetch(ctx, opts.HTTPClient, base+"/"+asset)
	if err != nil {
		return fmt.Errorf("download %s: %w", asset, err)
	}

	// Verify against the published checksums.txt (goreleaser output).
	sums, err := fetch(ctx, opts.HTTPClient, base+"/checksums.txt")
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	want, ok := checksumFor(string(sums), asset)
	if !ok {
		return fmt.Errorf("checksum for %s not found in checksums.txt", asset)
	}
	got := fmt.Sprintf("%x", sha256.Sum256(binaryData))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", asset, got, want)
	}

	return replaceExecutable(binaryData, opts.Stdout)
}

// replaceExecutable atomically swaps the running binary for newData by writing
// a sibling temp file and renaming it over the original.
func replaceExecutable(newData []byte, stdout io.Writer) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".runtz-update-*")
	if err != nil {
		return permissionHint(dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(newData); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmpName, exe); err != nil {
		return permissionHint(dir, err)
	}

	fmt.Fprintf(stdout, "Updated runtz at %s\n", exe)
	return nil
}

func permissionHint(dir string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w\nno write access to %s; re-run with sudo or set RUNTZ_INSTALL_DIR and reinstall via https://get.runtz.dev", err, dir)
	}
	return err
}

// ghRelease is the subset of the GitHub releases API we read.
type ghRelease struct {
	TagName string `json:"tag_name"`
	Draft   bool   `json:"draft"`
}

func releasesURL(repo string) string {
	return fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=10", repo)
}

// latestTagFromURL returns the newest non-draft release tag, prereleases
// included (GitHub returns releases newest-first). This mirrors install.sh,
// which cannot use the stable-only "latest" endpoint while runtz ships -rc
// versions. The URL is a parameter so tests can point at a local server.
func latestTagFromURL(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github releases API returned %d", resp.StatusCode)
	}
	var releases []ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", err
	}
	for _, r := range releases {
		if !r.Draft && strings.TrimSpace(r.TagName) != "" {
			return r.TagName, nil
		}
	}
	return "", errors.New("no releases found")
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// checksumFor finds the hex digest for asset in a `<sha256>  <name>` file.
func checksumFor(sums, asset string) (string, bool) {
	scanner := bufio.NewScanner(strings.NewReader(sums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[1] == asset {
			return fields[0], true
		}
	}
	return "", false
}

func confirm(stdout io.Writer, stdin io.Reader, prompt string) (bool, error) {
	fmt.Fprint(stdout, prompt)
	reader := bufio.NewReader(stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// normalizeVersion strips a leading v and surrounding space so "v1.0.0-rc1" and
// "1.0.0-rc1" compare equal. "dev"/"" normalize to empty (always outdated).
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "dev" {
		return ""
	}
	return strings.TrimPrefix(v, "v")
}

func displayVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "dev"
	}
	return v
}
