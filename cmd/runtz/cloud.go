package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/runtz-dev/runtz-cli/internal/cloudclient"
	"github.com/runtz-dev/runtz-cli/internal/config"
	"github.com/runtz-dev/runtz-cli/internal/gate"
	"github.com/runtz-dev/runtz-cli/internal/runtzclient"
	"golang.org/x/term"
)

var errCloudUsage = errors.New("invalid cloud command usage")

func cloudHelp(provider string) {
	fmt.Fprintf(os.Stderr, `Usage:
  runtz %[1]s [--name NAME] [authentication and severity gate flags]
  runtz %[1]s config [flags]

Runs private read-only checks on Runtz Security and sends results to your workspace.
Cloud credentials are transmitted to Security over HTTPS for validation and scanning.
The first interactive scan opens setup if this cloud is not configured.
Configuration is saved with owner-only permissions in the Runtz config file.

Config flags:
  --project-id ID --credentials-file PATH    GCP project and service account JSON
  --account-id ID --regions REGION,...       AWS account and regional scope
  --subscription-id ID                      Azure subscription
  --name NAME                               Display name in the platform
  --security-endpoint URL                   Public Runtz Security URL (self-hosted)

Credentials can be supplied through AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
or AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET in noninteractive setup.
GCP also accepts GOOGLE_APPLICATION_CREDENTIALS. Secrets are hidden at prompts.
Setup: https://runtz.dev/docs/scans/%[2]s
`, provider, cloudDocSlug(provider))
}

func cloudDocSlug(provider string) string {
	if provider == "gcp" {
		return "google-cloud"
	}
	return provider
}

func cloudReady(provider string, c config.Cloud) bool {
	if c.Scope == "" {
		return false
	}
	switch provider {
	case "gcp":
		return c.CredentialsFile != ""
	case "aws":
		return c.AccessKeyID != "" && c.SecretAccessKey != "" && len(c.Regions) > 0
	case "azure":
		return c.TenantID != "" && c.ClientID != "" && c.ClientSecret != ""
	}
	return false
}

func cloudCredentials(provider string, c config.Cloud) ([]byte, error) {
	if provider == "gcp" {
		f, err := os.Open(c.CredentialsFile)
		if err != nil {
			return nil, errors.New("cannot open GCP key; run runtz gcp config to update its path")
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, 32769))
		if err != nil || len(raw) > 32768 {
			return nil, errors.New("GCP key must be a readable JSON file of at most 32 KB")
		}
		return raw, nil
	}
	if provider == "aws" {
		return json.Marshal(struct {
			AuthMethod      string   `json:"authMethod"`
			AccessKeyID     string   `json:"accessKeyId"`
			SecretAccessKey string   `json:"secretAccessKey"`
			Regions         []string `json:"regions"`
		}{"access_key", c.AccessKeyID, c.SecretAccessKey, c.Regions})
	}
	return json.Marshal(struct {
		TenantID     string `json:"tenantId"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}{c.TenantID, c.ClientID, c.ClientSecret})
}

func runCloud(provider string, args []string) error {
	configure := len(args) > 0 && args[0] == "config"
	if configure {
		args = args[1:]
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	c := cfg.Clouds[provider]
	flags := commandFlagSet(provider, func() { cloudHelp(provider) })
	flags.StringVar(&c.Name, "name", c.Name, "Connection name")
	switch provider {
	case "gcp":
		flags.StringVar(&c.Scope, "project-id", c.Scope, "GCP project ID")
		flags.StringVar(&c.CredentialsFile, "credentials-file", firstNonEmpty(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"), c.CredentialsFile), "Local service account JSON path")
	case "aws":
		flags.StringVar(&c.Scope, "account-id", c.Scope, "12-digit AWS account ID")
	case "azure":
		flags.StringVar(&c.Scope, "subscription-id", c.Scope, "Azure subscription ID")
	}
	regions := flags.String("regions", strings.Join(c.Regions, ","), "AWS regions separated by commas")
	securityEndpoint := flags.String("security-endpoint", "", "Public Runtz Security URL")
	var auth authOptions
	addAuthFlags(flags, &auth)
	var thresholds gate.Thresholds
	addThresholdFlags(flags, &thresholds)
	if help, err := parseFlags(flags, args); help || err != nil {
		if err != nil {
			return fmt.Errorf("%w: %v", errCloudUsage, err)
		}
		return nil
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%w: unexpected arguments; use runtz %s --help", errCloudUsage, provider)
	}
	if provider == "aws" {
		c.Regions = strings.FieldsFunc(*regions, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' })
		c.AccessKeyID = firstNonEmpty(os.Getenv("AWS_ACCESS_KEY_ID"), c.AccessKeyID)
		c.SecretAccessKey = firstNonEmpty(os.Getenv("AWS_SECRET_ACCESS_KEY"), c.SecretAccessKey)
	}
	if provider == "azure" {
		c.TenantID = firstNonEmpty(os.Getenv("AZURE_TENANT_ID"), c.TenantID)
		c.ClientID = firstNonEmpty(os.Getenv("AZURE_CLIENT_ID"), c.ClientID)
		c.ClientSecret = firstNonEmpty(os.Getenv("AZURE_CLIENT_SECRET"), c.ClientSecret)
	}
	if err := requireAuth(&auth); err != nil {
		return err
	}
	endpoint, err := cloudclient.Endpoint(firstNonEmpty(*securityEndpoint, os.Getenv("RUNTZ_SECURITY_ENDPOINT"), cfg.SecurityEndpoint), auth.Endpoint)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	client := runtzclient.New(auth.Endpoint, auth.Token)
	verified, err := client.VerifyKey(ctx)
	if err != nil {
		return err
	}
	security, err := cloudclient.New(endpoint, auth.Token, verified.Workspace.ID)
	if err != nil {
		return err
	}
	if configure || !cloudReady(provider, c) {
		c, err = configureCloud(provider, c, security)
		if err != nil {
			return err
		}
		if cfg.Clouds == nil {
			cfg.Clouds = map[string]config.Cloud{}
		}
		cfg.Clouds[provider] = c
		if *securityEndpoint != "" {
			cfg.SecurityEndpoint = *securityEndpoint
		}
		path, err := config.Save(cfg)
		if err != nil {
			return err
		}
		fmt.Printf("%s configuration saved to %s.\n", strings.ToUpper(provider), path)
		if configure {
			fmt.Printf("Run runtz %s to scan and send results.\n", provider)
			return nil
		}
	}
	raw, err := cloudCredentials(provider, c)
	if err != nil {
		return err
	}
	defer clear(raw)
	printProgress("Running private " + strings.ToUpper(provider) + " checks on Runtz Security...")
	result, err := security.Scan(ctx, provider, c.Scope, raw)
	if err != nil {
		return err
	}
	printProgress("Sending cloud findings and coverage to Runtz...")
	connectionID, err := client.SendCloud(ctx, firstNonEmpty(c.Name, c.Scope), result)
	if err != nil {
		return err
	}
	fmt.Printf("%s scan completed and sent.\nScope: %s\nChecks: %d\nFindings: %d\n", strings.ToUpper(provider), c.Scope, len(result.Checks), len(result.Findings))
	if result.Summary.Errors+result.Summary.Skipped > 0 {
		fmt.Printf("Coverage incomplete: %d errors, %d skipped checks. Review Checks in the platform.\n", result.Summary.Errors, result.Summary.Skipped)
	}
	fmt.Printf("Cloud connection ID: %s\n", connectionID)
	if auth.Endpoint == saasEndpoint {
		fmt.Printf("Results: https://runtz.dev/cloud/%s/%s\n", provider, connectionID)
	} else {
		fmt.Printf("Open /cloud/%s/%s in your self-hosted platform.\n", provider, connectionID)
	}
	severities := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		severities = append(severities, finding.Severity)
	}
	return enforceThresholds(thresholds, severities)
}

func configureCloud(provider string, c config.Cloud, security *cloudclient.Client) (config.Cloud, error) {
	fmt.Fprintf(os.Stderr, "\nConfigure %s · read-only scanning\nGuide: https://runtz.dev/docs/scans/%s\nConfiguration is saved locally. Credentials are sent over HTTPS to Runtz Security for validation and scanning; they are not saved by this scan API.\n\n", strings.ToUpper(provider), cloudDocSlug(provider))
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	reader := bufio.NewReader(os.Stdin)
	prompt := func(label, current string, secret bool) (string, error) {
		if !interactive {
			return current, nil
		}
		hint := current
		if secret && hint != "" {
			hint = "saved; Enter to keep"
		}
		if hint != "" {
			fmt.Fprintf(os.Stderr, "%s [%s]: ", label, hint)
		} else {
			fmt.Fprintf(os.Stderr, "%s: ", label)
		}
		var value string
		if secret {
			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			value = string(raw)
			clear(raw)
		} else {
			line, err := reader.ReadString('\n')
			if err != nil {
				return "", errors.New("setup cancelled before all fields were entered")
			}
			value = line
		}
		return firstNonEmpty(strings.TrimSpace(value), current), nil
	}
	var err error
	scopeLabel := map[string]string{"gcp": "Project ID", "aws": "AWS account ID", "azure": "Subscription ID"}[provider]
	if c.Scope, err = prompt(scopeLabel, c.Scope, false); err != nil {
		return c, err
	}
	switch provider {
	case "gcp":
		c.CredentialsFile, err = prompt("Service account JSON file path", c.CredentialsFile, false)
		if err == nil && strings.HasPrefix(c.CredentialsFile, "~/") {
			var home string
			home, err = os.UserHomeDir()
			c.CredentialsFile = filepath.Join(home, c.CredentialsFile[2:])
		}
		if err == nil && c.CredentialsFile != "" {
			c.CredentialsFile, err = filepath.Abs(c.CredentialsFile)
		}
	case "aws":
		if c.AccessKeyID, err = prompt("Access key ID", c.AccessKeyID, false); err != nil {
			return c, err
		}
		if c.SecretAccessKey, err = prompt("Secret access key (hidden)", c.SecretAccessKey, true); err != nil {
			return c, err
		}
		var value string
		value, err = prompt("Regions, separated by commas", strings.Join(c.Regions, ","), false)
		c.Regions = strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' })
	case "azure":
		if c.TenantID, err = prompt("Directory (tenant) ID", c.TenantID, false); err != nil {
			return c, err
		}
		if c.ClientID, err = prompt("Application (client) ID", c.ClientID, false); err != nil {
			return c, err
		}
		c.ClientSecret, err = prompt("Client secret VALUE (hidden)", c.ClientSecret, true)
	}
	if err != nil {
		return c, err
	}
	if !cloudReady(provider, c) {
		return c, fmt.Errorf("incomplete %s configuration; run runtz %s config interactively or supply the documented flags and environment variables", provider, provider)
	}
	if c.Name, err = prompt("Connection name", firstNonEmpty(c.Name, c.Scope), false); err != nil {
		return c, err
	}
	if len(c.Name) > 80 {
		return c, errors.New("connection name must be at most 80 characters")
	}
	raw, err := cloudCredentials(provider, c)
	if err != nil {
		return c, err
	}
	defer clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	printProgress("Verifying read access...")
	if err := security.Validate(ctx, provider, c.Scope, raw); err != nil {
		return c, err
	}
	return c, nil
}
