package pkgscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func RunHost(ctx context.Context, options HostOptions) (Result, error) {
	if runtime.GOOS == "darwin" {
		return runHostDarwin(ctx, options)
	}

	root := options.TargetRoot
	if root == "" {
		root = "/"
	}

	osReleaseFile, err := os.Open(filepath.Join(root, "etc/os-release"))
	if err != nil {
		return Result{}, fmt.Errorf("read os-release: %w", err)
	}
	defer osReleaseFile.Close()

	osRelease, err := parseOSRelease(osReleaseFile)
	if err != nil {
		return Result{}, fmt.Errorf("parse os-release: %w", err)
	}

	family, err := familyForOS(osRelease)
	if err != nil {
		return Result{}, err
	}

	packages, err := listHostPackages(ctx, root, family)
	if err != nil {
		return Result{}, err
	}
	reportProgress(options.Progress, "Found %d installed %s packages on %s.", len(packages), family, osDisplayName(osRelease))

	var vulnerabilities []Vulnerability
	if ecosystemForOS(osRelease) == "" {
		reportProgress(options.Progress, "OSV has no advisory feed for %s yet; sending the package inventory without CVE matching.", osDisplayName(osRelease))
	} else {
		vulnerabilities, err = findVulnerabilities(ctx, packages, osRelease, options.OSVBaseURL, options.Progress)
		if err != nil {
			return Result{}, fmt.Errorf("scan package vulnerabilities: %w", err)
		}
		reportProgress(options.Progress, "Found %d package vulnerabilities.", len(vulnerabilities))
	}

	hostname := options.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if hostname == "" {
		hostname = "localhost"
	}

	return Result{
		Type:            "host",
		TargetName:      hostname,
		Hostname:        hostname,
		Source:          root,
		OSID:            osRelease.ID,
		OSName:          osDisplayName(osRelease),
		OSVersion:       osRelease.VersionID,
		OSCodename:      osRelease.VersionCodename,
		PackageManager:  string(family),
		ScannerVersion:  ScannerVersion,
		Packages:        packages,
		Vulnerabilities: vulnerabilities,
	}, nil
}

func listHostPackages(ctx context.Context, root string, family packageFamily) ([]Package, error) {
	switch family {
	case familyDpkg:
		statusFile, err := os.Open(filepath.Join(root, "var/lib/dpkg/status"))
		if err != nil {
			return nil, fmt.Errorf("read dpkg status: %w", err)
		}
		defer statusFile.Close()

		packages, err := parseDpkgStatus(statusFile)
		if err != nil {
			return nil, fmt.Errorf("parse dpkg status: %w", err)
		}
		return packages, nil
	case familyAPK:
		installedFile, err := os.Open(filepath.Join(root, "lib/apk/db/installed"))
		if err != nil {
			return nil, fmt.Errorf("read apk database: %w", err)
		}
		defer installedFile.Close()

		packages, err := parseApkInstalled(installedFile)
		if err != nil {
			return nil, fmt.Errorf("parse apk database: %w", err)
		}
		return packages, nil
	case familyPacman:
		return parsePacmanLocal(filepath.Join(root, "var/lib/pacman/local"))
	case familyRPM:
		return listRPMPackages(ctx, root)
	default:
		return nil, fmt.Errorf("unsupported package family: %s", family)
	}
}
