package pkgscan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// runHostDarwin inventories a macOS host: OS version via sw_vers, and
// installed packages via Homebrew (formulae + casks). OSV has no advisory
// feed for Homebrew formulae, so the scan sends the inventory without CVE
// matching, the same way RunHost already handles any OS with no ecosystem.
func runHostDarwin(ctx context.Context, options HostOptions) (Result, error) {
	osVersion := macOSProductVersion(ctx)

	packages, err := listBrewPackages(ctx, options.Progress)
	if err != nil {
		return Result{}, err
	}
	reportProgress(options.Progress, "Found %d installed Homebrew packages on macOS %s.", len(packages), osVersion)
	reportProgress(options.Progress, "OSV has no advisory feed for Homebrew yet; sending the package inventory without CVE matching.")

	hostname := options.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if hostname == "" {
		hostname = "localhost"
	}

	return Result{
		Type:           "host",
		TargetName:     hostname,
		Hostname:       hostname,
		Source:         "/",
		OSID:           "macos",
		OSName:         "macOS",
		OSVersion:      osVersion,
		PackageManager: string(familyBrew),
		ScannerVersion: ScannerVersion,
		Packages:       packages,
	}, nil
}

func macOSProductVersion(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "sw_vers", "-productVersion").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// listBrewPackages inventories Homebrew formulae and casks via `brew list
// --versions`. Homebrew is the closest thing macOS has to a system package
// manager; when it isn't installed the scan still sends OS info with an
// empty package list instead of failing outright.
func listBrewPackages(ctx context.Context, progress func(string)) ([]Package, error) {
	brewPath, err := exec.LookPath("brew")
	if err != nil {
		reportProgress(progress, "Homebrew not found; sending OS info without a package inventory.")
		return nil, nil
	}

	formulae, err := runBrewList(ctx, brewPath, "--formula", string(familyBrew))
	if err != nil {
		return nil, err
	}
	casks, err := runBrewList(ctx, brewPath, "--cask", "brew-cask")
	if err != nil {
		return nil, err
	}

	packages := append(formulae, casks...)
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})
	return packages, nil
}

func runBrewList(ctx context.Context, brewPath, kind, manager string) ([]Package, error) {
	command := exec.CommandContext(ctx, brewPath, "list", kind, "--versions")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("run brew list %s --versions: %w: %s", kind, err, strings.TrimSpace(stderr.String()))
	}

	return parseBrewListOutput(&stdout, manager)
}

// parseBrewListOutput parses `brew list --versions` output. Each line is
// "name version [version...]" — multiple installed versions (side-by-side
// Homebrew cellars) are listed on one line; the last one is the newest.
func parseBrewListOutput(reader io.Reader, manager string) ([]Package, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var packages []Package
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		packages = append(packages, Package{
			Name:    fields[0],
			Version: fields[len(fields)-1],
			Manager: manager,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return packages, nil
}
