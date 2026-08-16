package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/runtz-dev/runtz-cli/internal/config"
	"github.com/runtz-dev/runtz-cli/internal/runtzclient"
)

type whoamiStatus struct {
	Authenticated bool             `json:"authenticated"`
	Verified      bool             `json:"verified"`
	Workspace     *whoamiWorkspace `json:"workspace,omitempty"`
	APIKey        *whoamiAPIKey    `json:"apiKey,omitempty"`
	Endpoint      string           `json:"endpoint"`
	TokenSource   string           `json:"tokenSource,omitempty"`
}

type whoamiWorkspace struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

type whoamiAPIKey struct {
	Name      string `json:"name,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

type keyVerifier func(context.Context, string, string) (runtzclient.VerifyKeyResult, error)

// runLogin stores a platform token (and, for self-hosted, the endpoint) in
// the user config file so scan commands no longer need --token. The token is
// verified against the platform before anything is written.
func runLogin(args []string) error {
	flags := commandFlagSet("login", loginHelp)
	endpoint := flags.String("endpoint", os.Getenv("RUNTZ_ENDPOINT"), "Runtz backend endpoint (self-hosted only)")
	token := flags.String("token", "", "Token to store; omit to paste it at a hidden prompt")
	if help, err := parseFlags(flags, args); help || err != nil {
		return err
	}

	stored, err := config.Load()
	if err != nil {
		return err
	}

	// Keep a previously stored self-hosted endpoint when the user just
	// refreshes the token without repeating --endpoint.
	effectiveEndpoint := firstNonEmpty(*endpoint, stored.Endpoint, saasEndpoint)

	value := strings.TrimSpace(*token)
	if value == "" {
		value, err = readTokenInteractively()
		if err != nil {
			return err
		}
	}
	if value == "" {
		return fmt.Errorf("no token provided: pass --token or paste one at the prompt")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := runtzclient.New(effectiveEndpoint, value)
	result, err := client.VerifyKey(ctx)
	verified := err == nil
	if err != nil {
		if !errors.Is(err, runtzclient.ErrVerifyUnsupported) {
			return err
		}
		fmt.Fprintf(os.Stderr, "warning: %s does not support token verification (older engine); storing the token unverified.\n", effectiveEndpoint)
	}

	next := stored
	next.Token = value
	if effectiveEndpoint == saasEndpoint {
		next.Endpoint = ""
	} else {
		next.Endpoint = effectiveEndpoint
	}
	path, err := config.Save(next)
	if err != nil {
		return err
	}

	if verified {
		fmt.Printf("Logged in to workspace %q.\n", result.Workspace.Name)
		if detail := keyDetail(result.APIKey.Name, result.APIKey.Prefix, result.APIKey.ExpiresAt); detail != "" {
			fmt.Printf("Key: %s\n", detail)
		}
	}
	fmt.Printf("Token saved to %s — scan commands no longer need --token.\n", path)
	return nil
}

func runLogout(args []string) error {
	flags := commandFlagSet("logout", logoutHelp)
	if help, err := parseFlags(flags, args); help || err != nil {
		return err
	}

	hadToken, err := config.ClearToken()
	if err != nil {
		return err
	}
	path, pathErr := config.Path()
	if pathErr != nil {
		path = "the runtz config file"
	}
	if hadToken {
		fmt.Printf("Logged out: removed the token stored at %s.\n", path)
	} else {
		fmt.Printf("No stored token at %s; nothing to do.\n", path)
	}
	if envOrDefault("RUNTZ_TOKEN", os.Getenv("RUNTZ_API_KEY")) != "" {
		fmt.Fprintln(os.Stderr, "note: RUNTZ_TOKEN is still set in this environment and will keep authenticating scans.")
	}
	return nil
}

func runWhoami(args []string) error {
	return runWhoamiWithVerifier(args, func(ctx context.Context, endpoint, token string) (runtzclient.VerifyKeyResult, error) {
		return runtzclient.New(endpoint, token).VerifyKey(ctx)
	})
}

func runWhoamiWithVerifier(args []string, verify keyVerifier) error {
	var auth authOptions
	flags := commandFlagSet("whoami", whoamiHelp)
	jsonOutput := flags.Bool("json", false, "Print machine-readable JSON")
	addAuthFlags(flags, &auth)
	if help, err := parseFlags(flags, args); help || err != nil {
		return err
	}

	source, err := resolveAuth(&auth)
	if err != nil {
		return err
	}
	if auth.Token == "" {
		if *jsonOutput {
			return writeWhoamiJSON(whoamiStatus{Endpoint: auth.Endpoint})
		}
		return fmt.Errorf("not logged in: run `runtz login`, pass --token, or set RUNTZ_TOKEN")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := verify(ctx, auth.Endpoint, auth.Token)
	status := whoamiStatus{
		Authenticated: true,
		Endpoint:      auth.Endpoint,
		TokenSource:   source,
	}
	switch {
	case err == nil:
		status.Verified = true
		status.Workspace = &whoamiWorkspace{ID: result.Workspace.ID, Name: result.Workspace.Name}
		status.APIKey = &whoamiAPIKey{
			Name:      result.APIKey.Name,
			Prefix:    result.APIKey.Prefix,
			ExpiresAt: result.APIKey.ExpiresAt,
		}
		if *jsonOutput {
			return writeWhoamiJSON(status)
		}
		fmt.Printf("Workspace:  %s\n", result.Workspace.Name)
		if detail := keyDetail(result.APIKey.Name, result.APIKey.Prefix, result.APIKey.ExpiresAt); detail != "" {
			fmt.Printf("Key:        %s\n", detail)
		}
	case errors.Is(err, runtzclient.ErrVerifyUnsupported):
		if *jsonOutput {
			return writeWhoamiJSON(status)
		}
		fmt.Fprintf(os.Stderr, "warning: %s does not support token verification (older engine); showing local configuration only.\n", auth.Endpoint)
	default:
		return err
	}
	fmt.Printf("Endpoint:   %s\n", auth.Endpoint)
	fmt.Printf("Token from: %s\n", source)
	return nil
}

func writeWhoamiJSON(status whoamiStatus) error {
	if err := json.NewEncoder(os.Stdout).Encode(status); err != nil {
		return fmt.Errorf("encode login status: %w", err)
	}
	return nil
}

// readTokenInteractively asks for the token without echoing it on a TTY, and
// falls back to reading one line from stdin when piped.
func readTokenInteractively() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Paste your token (rtz_live_...): ")
		raw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read token: %w", err)
		}
		return strings.TrimSpace(string(raw)), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read token from stdin: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// keyDetail renders `name (prefix…, expires in N days)` from whatever verify
// returned, leaving out the parts the platform did not send.
func keyDetail(name, prefix, expiresAt string) string {
	parts := make([]string, 0, 2)
	if prefix != "" {
		parts = append(parts, prefix+"…")
	}
	if expiresAt != "" {
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			days := int(time.Until(t).Hours() / 24)
			parts = append(parts, fmt.Sprintf("expires in %d days, %s", days, t.Format("2006-01-02")))
		} else {
			parts = append(parts, "expires "+expiresAt)
		}
	} else if name != "" {
		parts = append(parts, "no expiration")
	}
	if name == "" && len(parts) == 0 {
		return ""
	}
	if len(parts) == 0 {
		return name
	}
	if name == "" {
		return strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%s (%s)", name, strings.Join(parts, ", "))
}

func loginHelp() {
	fmt.Fprintf(os.Stderr, `Usage:
  runtz login [flags]

Verifies a platform token and stores it in %s
so scan commands no longer need --token. The token still loses to an explicit
--token flag or RUNTZ_TOKEN environment variable when either is set.

Examples:
  runtz login                                  # paste the token at a hidden prompt
  runtz login --token rtz_live_...             # non-interactive
  runtz login --endpoint http://localhost:8080 # self-hosted: endpoint is stored too

Flags:
  --token      Token generated in the Runtz platform; omit to be prompted
  --endpoint   Runtz backend endpoint (only needed for self-hosted deployments;
               stored alongside the token, defaults to Runtz SaaS: %s)

Environment:
  RUNTZ_ENDPOINT      Default for --endpoint
  RUNTZ_CONFIG_DIR    Overrides the config directory
`, configPathForHelp(), saasEndpoint)
}

func logoutHelp() {
	fmt.Fprintf(os.Stderr, `Usage:
  runtz logout

Removes the token stored by runtz login from %s.
A self-hosted endpoint saved there is kept, so the next login does not need
--endpoint again.
`, configPathForHelp())
}

func whoamiHelp() {
	fmt.Fprintf(os.Stderr, `Usage:
  runtz whoami [flags]

Shows which workspace the current token belongs to and where the token comes
from (--token flag, environment variable or stored login).

Flags:
  --json       Print machine-readable JSON for integrations
  --token      Check a specific token instead of the configured one
  --endpoint   Runtz backend endpoint (optional, defaults to Runtz SaaS: %s)
`, saasEndpoint)
}

func configPathForHelp() string {
	if path, err := config.Path(); err == nil {
		return path
	}
	return "~/.config/runtz/config.json"
}
