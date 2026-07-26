package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/runtz-dev/runtz-cli/internal/gate"
	"github.com/runtz-dev/runtz-cli/internal/k8s"
	"github.com/runtz-dev/runtz-cli/internal/pkgscan"
	"github.com/runtz-dev/runtz-cli/internal/report"
	"github.com/runtz-dev/runtz-cli/internal/runtzclient"
	"github.com/runtz-dev/runtz-cli/internal/sast"
	"github.com/runtz-dev/runtz-cli/internal/sca"
	"github.com/runtz-dev/runtz-cli/internal/update"
	"github.com/runtz-dev/runtz-cli/internal/version"
)

// errThresholdBreached is returned by a scan when a severity gate fires. main
// maps it to exit code 3 so CI pipelines can break on it.
var errThresholdBreached = errors.New("severity threshold exceeded")

const saasEndpoint = "https://engine.runtz.dev"

type authOptions struct {
	Endpoint string
	Token    string
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "sca":
		printBanner()
		err = runSCA(os.Args[2:])
	case "sast":
		printBanner()
		err = runSAST(os.Args[2:])
	case "host":
		printBanner()
		err = runHost(os.Args[2:])
	case "container":
		printBanner()
		err = runContainer(os.Args[2:])
	case "k8s", "kubernetes":
		printBanner()
		err = runKubernetes(os.Args[2:])
	case "update", "upgrade", "self-update":
		err = runUpdate(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("runtz %s (%s/%s)\n", version.Version, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		if len(os.Args) > 2 {
			err = showCommandHelp(os.Args[2])
		} else {
			usage()
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		switch {
		case errors.Is(err, errThresholdBreached), errors.Is(err, update.ErrUpdateAvailable):
			// The command already explained itself; exit 3 to break CI without
			// the generic "failed" prefix.
			os.Exit(3)
		default:
			fmt.Fprintf(os.Stderr, "runtz %s failed: %v\n", os.Args[1], err)
			os.Exit(1)
		}
	}
}

func runSCA(args []string) error {
	positional, args := splitPositionalPath(args)

	var auth authOptions
	flags := commandFlagSet("sca", scaHelp)
	project := flags.String("project", os.Getenv("RUNTZ_PROJECT"), "Project name override")
	source := flags.String("source", os.Getenv("RUNTZ_SOURCE"), "Project source path or URL")
	githubToken := flags.String("github-token", os.Getenv("GITHUB_TOKEN"), "Optional GitHub token for higher API limits")
	addAuthFlags(flags, &auth)
	var thresholds gate.Thresholds
	addThresholdFlags(flags, &thresholds)
	if help, err := parseFlags(flags, args); help || err != nil {
		return err
	}
	if err := requireAuth(auth); err != nil {
		return err
	}

	path := firstNonEmpty(positional, flags.Arg(0), ".")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := sca.Run(ctx, sca.Options{
		Path:        path,
		ProjectName: *project,
		Source:      *source,
		GitHubToken: *githubToken,
		Progress:    printProgress,
	})
	if err != nil {
		return err
	}

	client := runtzclient.New(auth.Endpoint, auth.Token)
	printProgress("Sending SCA scan to Runtz...")
	scanID, err := client.SendSCA(ctx, "", "", result)
	if err != nil {
		return err
	}

	fmt.Printf("SCA scan completed and sent to Runtz Platform.\n")
	fmt.Printf("Project: %s\nManifests: %d\nDependencies: %d\nVulnerabilities: %d\n", result.ProjectName, len(result.TargetFiles), len(result.Dependencies), len(result.Vulnerabilities))
	printScanID(scanID)
	return enforceThresholds(thresholds, scaSeverities(result.Vulnerabilities))
}

func runSAST(args []string) error {
	positional, args := splitPositionalPath(args)

	var auth authOptions
	flags := commandFlagSet("sast", sastHelp)
	project := flags.String("project", os.Getenv("RUNTZ_PROJECT"), "Project name override")
	source := flags.String("source", os.Getenv("RUNTZ_SOURCE"), "Project source path or URL")
	addAuthFlags(flags, &auth)
	var thresholds gate.Thresholds
	addThresholdFlags(flags, &thresholds)
	if help, err := parseFlags(flags, args); help || err != nil {
		return err
	}
	if err := requireAuth(auth); err != nil {
		return err
	}

	path := firstNonEmpty(positional, flags.Arg(0), ".")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := sast.Run(ctx, sast.Options{
		Path:        path,
		ProjectName: *project,
		Source:      *source,
		Progress:    printProgress,
	})
	if err != nil {
		return err
	}

	client := runtzclient.New(auth.Endpoint, auth.Token)
	printProgress("Sending SAST scan to Runtz...")
	scanID, err := client.SendFindingsScan(ctx, result)
	if err != nil {
		return err
	}

	fmt.Printf("SAST scan completed and sent to Runtz Platform.\n")
	fmt.Printf("Project: %s\nFiles: %d\nFindings: %d\n", result.ProjectName, result.FilesScanned, len(result.Findings))
	printScanID(scanID)
	return enforceThresholds(thresholds, findingSeverities(result.Findings))
}

func runHost(args []string) error {
	var auth authOptions
	flags := commandFlagSet("host", hostHelp)
	rootfs := flags.String("rootfs", envOrDefault("RUNTZ_HOST_ROOTFS", "/"), "Root filesystem whose dpkg package database will be scanned")
	hostname := flags.String("hostname", os.Getenv("RUNTZ_HOSTNAME"), "Hostname override")
	osvURL := flags.String("osv-url", os.Getenv("RUNTZ_OSV_URL"), "Optional OSV API base URL")
	addAuthFlags(flags, &auth)
	var thresholds gate.Thresholds
	addThresholdFlags(flags, &thresholds)
	if help, err := parseFlags(flags, args); help || err != nil {
		return err
	}
	if err := requireAuth(auth); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	result, err := pkgscan.RunHost(ctx, pkgscan.HostOptions{
		TargetRoot: *rootfs,
		Hostname:   *hostname,
		OSVBaseURL: *osvURL,
		Progress:   printProgress,
	})
	if err != nil {
		return err
	}

	client := runtzclient.New(auth.Endpoint, auth.Token)
	printProgress("Sending host scan to Runtz...")
	scanID, err := client.SendPackageScan(ctx, "", "", result)
	if err != nil {
		return err
	}

	fmt.Printf("Host package scan completed and sent to Runtz Platform.\n")
	fmt.Printf("Hostname: %s\nOS: %s\nPackages: %d\nVulnerabilities: %d\n", result.Hostname, result.OSName, len(result.Packages), len(result.Vulnerabilities))
	printScanID(scanID)
	return enforceThresholds(thresholds, pkgSeverities(result.Vulnerabilities))
}

func runContainer(args []string) error {
	positional, args := splitPositionalPath(args)

	var auth authOptions
	flags := commandFlagSet("container", containerHelp)
	local := flags.Bool("local", envBool("RUNTZ_CONTAINER_LOCAL"), "Read image from the local Docker daemon instead of a registry")
	osvURL := flags.String("osv-url", os.Getenv("RUNTZ_OSV_URL"), "Optional OSV API base URL")
	addAuthFlags(flags, &auth)
	var thresholds gate.Thresholds
	addThresholdFlags(flags, &thresholds)
	if help, err := parseFlags(flags, args); help || err != nil {
		return err
	}
	if err := requireAuth(auth); err != nil {
		return err
	}

	image := firstNonEmpty(positional, flags.Arg(0), os.Getenv("RUNTZ_CONTAINER_IMAGE"))
	if image == "" {
		return fmt.Errorf("image reference is required: runtz container IMAGE")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	result, err := pkgscan.RunContainer(ctx, pkgscan.ContainerOptions{
		Image:      image,
		Local:      *local,
		OSVBaseURL: *osvURL,
		Progress:   printProgress,
	})
	if err != nil {
		return err
	}

	client := runtzclient.New(auth.Endpoint, auth.Token)
	printProgress("Sending container scan to Runtz...")
	scanID, err := client.SendPackageScan(ctx, "", "", result)
	if err != nil {
		return err
	}

	fmt.Printf("Container package scan completed and sent to Runtz Platform.\n")
	fmt.Printf("Image: %s\nOS: %s\nPackages: %d\nVulnerabilities: %d\n", result.ImageName, result.OSName, len(result.Packages), len(result.Vulnerabilities))
	printScanID(scanID)
	return enforceThresholds(thresholds, pkgSeverities(result.Vulnerabilities))
}

func runKubernetes(args []string) error {
	positional, args := splitPositionalPath(args)

	var auth authOptions
	flags := commandFlagSet("k8s", k8sHelp)
	target := flags.String("target", os.Getenv("RUNTZ_K8S_TARGET"), "Target name shown in the platform")
	source := flags.String("source", os.Getenv("RUNTZ_SOURCE"), "Scan source label, repository or URL")
	kubectl := flags.String("kubectl", envOrDefault("RUNTZ_KUBECTL", "kubectl"), "kubectl binary path")
	kubeconfig := flags.String("kubeconfig", os.Getenv("KUBECONFIG"), "Kubeconfig path")
	kubeContext := flags.String("context", os.Getenv("RUNTZ_K8S_CONTEXT"), "Kubernetes context override")
	namespace := flags.String("namespace", os.Getenv("RUNTZ_K8S_NAMESPACE"), "Namespace to scan instead of all namespaces")
	allNamespaces := flags.Bool("all-namespaces", envBoolDefault("RUNTZ_K8S_ALL_NAMESPACES", true), "Scan all namespaces when --namespace is not set")
	addAuthFlags(flags, &auth)
	var thresholds gate.Thresholds
	addThresholdFlags(flags, &thresholds)
	if help, err := parseFlags(flags, args); help || err != nil {
		return err
	}
	if err := requireAuth(auth); err != nil {
		return err
	}

	path := firstNonEmpty(positional, flags.Arg(0), os.Getenv("RUNTZ_K8S_PATH"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := k8s.Run(ctx, k8s.Options{
		Path:          path,
		Target:        *target,
		Source:        *source,
		Kubectl:       *kubectl,
		Kubeconfig:    *kubeconfig,
		Context:       *kubeContext,
		Namespace:     *namespace,
		AllNamespaces: *allNamespaces,
		Progress:      printProgress,
	})
	if err != nil {
		return err
	}

	client := runtzclient.New(auth.Endpoint, auth.Token)
	printProgress("Sending Kubernetes scan to Runtz...")
	scanID, err := client.SendFindingsScan(ctx, result)
	if err != nil {
		return err
	}

	fmt.Printf("Kubernetes scan completed and sent to Runtz Platform.\n")
	if result.FilesScanned > 0 {
		fmt.Printf("Target: %s\nFiles: %d\nResources: %d\nFindings: %d\n", result.TargetName, result.FilesScanned, result.ResourcesScanned, len(result.Findings))
	} else {
		fmt.Printf("Target: %s\nResources: %d\nFindings: %d\n", result.TargetName, result.ResourcesScanned, len(result.Findings))
	}
	printScanID(scanID)
	return enforceThresholds(thresholds, findingSeverities(result.Findings))
}

// splitPositionalPath pulls a leading non-flag argument (the scan path) so
// commands accept `runtz sca ./repo --endpoint ...`.
func splitPositionalPath(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func commandFlagSet(name string, help func()) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = help
	return flags
}

func parseFlags(flags *flag.FlagSet, args []string) (bool, error) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func addAuthFlags(flags *flag.FlagSet, auth *authOptions) {
	flags.StringVar(&auth.Endpoint, "endpoint", os.Getenv("RUNTZ_ENDPOINT"), "Runtz backend endpoint")
	flags.StringVar(&auth.Token, "token", envOrDefault("RUNTZ_TOKEN", os.Getenv("RUNTZ_API_KEY")), "Runtz token generated in the platform")
}

func requireAuth(auth authOptions) error {
	if auth.Endpoint == "" {
		return fmt.Errorf("--endpoint is required (use %s for Runtz SaaS)", saasEndpoint)
	}
	if auth.Token == "" {
		return fmt.Errorf("--token is required")
	}
	return nil
}

// addThresholdFlags registers the CI/CD severity gates shared by every scan
// command. Each flag defaults to its RUNTZ_*_THRESHOLD env var (0 = off).
func addThresholdFlags(flags *flag.FlagSet, th *gate.Thresholds) {
	flags.IntVar(&th.Critical, "critical-threshold", envInt("RUNTZ_CRITICAL_THRESHOLD"), "Fail (exit 3) when critical findings reach N (0 = off)")
	flags.IntVar(&th.High, "high-threshold", envInt("RUNTZ_HIGH_THRESHOLD"), "Fail (exit 3) when high findings reach N (0 = off)")
	flags.IntVar(&th.Medium, "medium-threshold", envInt("RUNTZ_MEDIUM_THRESHOLD"), "Fail (exit 3) when medium findings reach N (0 = off)")
	flags.IntVar(&th.Low, "low-threshold", envInt("RUNTZ_LOW_THRESHOLD"), "Fail (exit 3) when low findings reach N (0 = off)")
}

// enforceThresholds prints a per-severity summary and, when a gate is active and
// met, returns errThresholdBreached (which main maps to exit 3). It runs after
// the scan has been sent, so results always reach the platform first.
func enforceThresholds(th gate.Thresholds, severities []string) error {
	if !th.Active() {
		return nil
	}
	counts := gate.Count(severities)
	fmt.Printf("Severity gate: %s\n", counts.Summary())
	if breaches := th.Evaluate(counts); len(breaches) > 0 {
		fmt.Fprintln(os.Stderr, gate.BreachMessage(breaches))
		return errThresholdBreached
	}
	return nil
}

func scaSeverities(vulns []sca.Vulnerability) []string {
	out := make([]string, 0, len(vulns))
	for _, v := range vulns {
		out = append(out, v.Severity)
	}
	return out
}

func pkgSeverities(vulns []pkgscan.Vulnerability) []string {
	out := make([]string, 0, len(vulns))
	for _, v := range vulns {
		out = append(out, v.Severity)
	}
	return out
}

func findingSeverities(findings []report.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Severity)
	}
	return out
}

func envInt(key string) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return 0
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func runUpdate(args []string) error {
	flags := commandFlagSet("update", updateHelp)
	check := flags.Bool("check", false, "Only report whether a newer version exists (exit 3 if so)")
	var assumeYes bool
	flags.BoolVar(&assumeYes, "yes", false, "Update without the confirmation prompt")
	flags.BoolVar(&assumeYes, "y", false, "Update without the confirmation prompt (shorthand)")
	repo := flags.String("repo", envOrDefault("RUNTZ_REPO", update.DefaultRepo), "GitHub repository to update from")
	if help, err := parseFlags(flags, args); help || err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	return update.Run(ctx, update.Options{
		Repo:           *repo,
		CurrentVersion: version.Version,
		CheckOnly:      *check,
		AssumeYes:      assumeYes,
	})
}

func showCommandHelp(command string) error {
	switch command {
	case "sca":
		scaHelp()
	case "sast":
		sastHelp()
	case "host":
		hostHelp()
	case "container":
		containerHelp()
	case "k8s", "kubernetes":
		k8sHelp()
	case "update", "upgrade", "self-update":
		updateHelp()
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "yes", "YES":
		return true
	default:
		return false
	}
}

func envBoolDefault(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "TRUE", "yes", "YES":
		return true
	default:
		return false
	}
}

// printBanner renders the runtz wordmark with the terminal block cursor at
// the start of every scan. Skipped when stderr is not a terminal so CI logs
// and redirected output stay clean.
func printBanner() {
	if !isTerminal(os.Stderr) {
		return
	}
	fmt.Fprintf(os.Stderr, "\x1b[1mruntz\x1b[0m \x1b[38;5;75m█\x1b[0m \x1b[2m%s\x1b[0m\n\n", version.Version)
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func printProgress(message string) {
	fmt.Fprintf(os.Stderr, "%s\n", message)
}

func printScanID(scanID string) {
	if scanID != "" {
		fmt.Printf("Scan ID: %s\n", scanID)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `runtz scans DevSecOps targets and sends reports to the Runtz Platform.

Usage:
  runtz <command> [flags]
  runtz --help
  runtz help <command>

Commands:
  sca          Scan dependency manifests in a repository or a single manifest file
  sast         Scan source code with initial static rules
  container    Scan packages inside a container image
  host         Scan packages installed on a Linux host/rootfs
  k8s          Scan a Kubernetes cluster or manifests
  kubernetes   Alias for k8s
  update       Update the CLI to the latest release
  version      Print the CLI version

Required on every scan command:
  --endpoint   Runtz backend endpoint, for SaaS use %s
  --token      Token generated in the Runtz platform

Severity gates (optional, on every scan command) — fail with exit code 3 when
the number of findings at a severity reaches N, to break a CI/CD pipeline:
  --critical-threshold N   --high-threshold N
  --medium-threshold N     --low-threshold N

Exit codes:
  0  success            2  usage error
  1  execution error    3  severity gate tripped / update available

Environment:
  RUNTZ_ENDPOINT       Backend endpoint
  RUNTZ_TOKEN          Platform token generated for the workspace
  RUNTZ_API_KEY        Deprecated alias for RUNTZ_TOKEN
  RUNTZ_CRITICAL_THRESHOLD, RUNTZ_HIGH_THRESHOLD,
  RUNTZ_MEDIUM_THRESHOLD, RUNTZ_LOW_THRESHOLD
`, saasEndpoint)
}

func updateHelp() {
	fmt.Fprintf(os.Stderr, `Usage:
  runtz update [flags]

Updates the runtz CLI in place to the newest release. Downloads the binary for
your OS/arch, verifies its SHA-256 against the release checksums and atomically
replaces the running executable.

Examples:
  runtz update              # prompt, then update
  runtz update --yes        # update without prompting
  runtz update --check      # only report if a newer version exists (exit 3 if so)

Flags:
  --check      Only check for a newer version; do not modify anything
  --yes, -y    Update without the confirmation prompt
  --repo       GitHub repository to update from (default %s)

Environment:
  RUNTZ_REPO   Overrides --repo
`, update.DefaultRepo)
}

func scaHelp() {
	fmt.Fprintf(os.Stderr, `Usage:
  runtz sca (REPO_PATH | FILE_PATH) [flags]

Examples:
  runtz sca ./ --endpoint %s --token rtz_live_...
  runtz sca ./package.json --endpoint %s --token rtz_live_...

Scanning a repository path discovers every supported dependency manifest:
  %s

Supported languages: JavaScript/TypeScript, Python, Go, Java/Kotlin, Ruby,
PHP, Rust and C#/.NET.

Flags:
  --project        Project name override
  --source         Project source path, repository or URL
  --github-token   Optional GitHub token for higher advisory API limits
  --endpoint       Runtz backend endpoint (required)
  --token          Token generated in the Runtz platform (required)
  --*-threshold N  Severity gates: fail (exit 3) at N critical/high/medium/low findings

Environment:
  RUNTZ_PROJECT, RUNTZ_SOURCE, GITHUB_TOKEN, RUNTZ_ENDPOINT, RUNTZ_TOKEN
`, saasEndpoint, saasEndpoint, strings.Join(sca.SupportedManifests, ", "))
}

func sastHelp() {
	fmt.Fprintf(os.Stderr, `Usage:
  runtz sast (REPO_PATH | FILE_PATH) [flags]

Examples:
  runtz sast ./ --endpoint %s --token rtz_live_...
  runtz sast ./src/server.ts --endpoint %s --token rtz_live_...

Initial SAST rules detect common high-signal issues such as committed secrets,
dynamic code execution, disabled TLS verification and weak hash usage in
JavaScript/TypeScript, Python, Go, Java/Kotlin, Ruby, PHP, Rust and C#/.NET
source files.

Flags:
  --project    Project name override
  --source     Project source path, repository or URL
  --endpoint   Runtz backend endpoint (required)
  --token      Token generated in the Runtz platform (required)
  --*-threshold N  Severity gates: fail (exit 3) at N critical/high/medium/low findings

Environment:
  RUNTZ_PROJECT, RUNTZ_SOURCE, RUNTZ_ENDPOINT, RUNTZ_TOKEN
`, saasEndpoint, saasEndpoint)
}

func hostHelp() {
	fmt.Fprintf(os.Stderr, `Usage:
  runtz host --endpoint %s --token rtz_live_...

The host scanner always inventories the current host: it reads /etc/os-release,
detects the distribution family and lists installed packages from the matching
package database, then queries OSV for package CVEs.

Supported families:
  Debian/Ubuntu based   dpkg    (Debian, Ubuntu, Mint, ...)
  RPM based             rpm     (RHEL, CentOS, Rocky, Alma, openSUSE, SLES, ...)
  Alpine based          apk     (Alpine, ...)
  Arch based            pacman  (Arch, Manjaro, ...; inventory only for now)

Flags:
  --hostname   Hostname shown in the Hosts dashboard (default: local hostname)
  --rootfs     Root filesystem to scan when not / (advanced)
  --osv-url    Optional OSV API base URL
  --endpoint   Runtz backend endpoint (required)
  --token      Token generated in the Runtz platform (required)
  --*-threshold N  Severity gates: fail (exit 3) at N critical/high/medium/low findings

Environment:
  RUNTZ_HOST_ROOTFS, RUNTZ_HOSTNAME, RUNTZ_OSV_URL, RUNTZ_ENDPOINT, RUNTZ_TOKEN
`, saasEndpoint)
}

func containerHelp() {
	fmt.Fprintf(os.Stderr, `Usage:
  runtz container IMAGE [flags]

Examples:
  runtz container ubuntu:22.04 --endpoint %s --token rtz_live_...
  runtz container alpine:3.19 --endpoint %s --token rtz_live_...
  runtz container my-app:latest --local --endpoint %s --token rtz_live_...

The container scanner pulls the image from a registry by default (no Docker
needed), reads its layers directly and inventories the OS package database.
Use --local to scan an image from the local Docker daemon instead.

Supported image families:
  Debian/Ubuntu based   dpkg    (debian, ubuntu, node:*-slim, python:*-slim, ...)
  RPM based             rpm     (rockylinux, almalinux, ubi, opensuse, ...)
  Alpine based          apk     (alpine, node:*-alpine, nginx:*-alpine, ...)
  Arch based            pacman  (archlinux; inventory only for now)

Flags:
  --local      Read image from the local Docker daemon
  --osv-url    Optional OSV API base URL
  --endpoint   Runtz backend endpoint (required)
  --token      Token generated in the Runtz platform (required)
  --*-threshold N  Severity gates: fail (exit 3) at N critical/high/medium/low findings

Environment:
  RUNTZ_CONTAINER_IMAGE, RUNTZ_CONTAINER_LOCAL, RUNTZ_OSV_URL, RUNTZ_ENDPOINT, RUNTZ_TOKEN
`, saasEndpoint, saasEndpoint, saasEndpoint)
}

func k8sHelp() {
	fmt.Fprintf(os.Stderr, `Usage:
  runtz k8s [MANIFEST_PATH] [flags]

Examples:
  runtz k8s --endpoint %s --token rtz_live_...
  runtz k8s --kubeconfig ~/.kube/config2 --endpoint %s --token rtz_live_...
  runtz k8s --context production --namespace payments --endpoint %s --token rtz_live_...
  runtz k8s ./deploy --endpoint %s --token rtz_live_...

By default the Kubernetes scanner reads the currently connected cluster through
kubectl (the active kubeconfig context). Pass a manifest file or directory as
the positional argument to scan YAML/JSON manifests from a repo or chart render
instead of a live cluster.

Checks cover pod security, container security, RBAC, network exposure,
supply chain and resilience.

Flags:
  --kubeconfig       Kubeconfig path (default: active kubeconfig)
  --context          Kubernetes context override (default: current context)
  --namespace        Namespace to scan instead of all namespaces
  --all-namespaces   Scan all namespaces when --namespace is not set (default: true)
  --kubectl          kubectl binary path (default: kubectl)
  --target           Target name shown in the platform
  --source           Scan source label, repository or URL
  --endpoint         Runtz backend endpoint (required)
  --token            Token generated in the Runtz platform (required)
  --*-threshold N  Severity gates: fail (exit 3) at N critical/high/medium/low findings

Environment:
  RUNTZ_KUBECTL, KUBECONFIG, RUNTZ_K8S_CONTEXT, RUNTZ_K8S_NAMESPACE,
  RUNTZ_K8S_ALL_NAMESPACES, RUNTZ_K8S_TARGET,
  RUNTZ_SOURCE, RUNTZ_ENDPOINT, RUNTZ_TOKEN
`, saasEndpoint, saasEndpoint, saasEndpoint, saasEndpoint)
}
