package pkgscan

import (
	"time"

	"github.com/runtz-dev/runtz-cli/internal/version"
)

var ScannerVersion = version.Scanner()

type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Architecture  string `json:"architecture,omitempty"`
	SourceName    string `json:"sourceName,omitempty"`
	SourceVersion string `json:"sourceVersion,omitempty"`
	Manager       string `json:"manager"`
}

type Vulnerability struct {
	ID                  string    `json:"id"`
	GHSAID              string    `json:"ghsaId,omitempty"`
	CVEID               string    `json:"cveId,omitempty"`
	PackageName         string    `json:"packageName"`
	InstalledPackage    string    `json:"installedPackage,omitempty"`
	SourcePackage       string    `json:"sourcePackage,omitempty"`
	Ecosystem           string    `json:"ecosystem"`
	InstalledVersion    string    `json:"installedVersion"`
	VulnerableRange     string    `json:"vulnerableRange"`
	FirstPatchedVersion string    `json:"firstPatchedVersion,omitempty"`
	Severity            string    `json:"severity"`
	Summary             string    `json:"summary"`
	AdvisoryURL         string    `json:"advisoryUrl"`
	CVSSScore           float64   `json:"cvssScore,omitempty"`
	References          []string  `json:"references,omitempty"`
	PublishedAt         time.Time `json:"publishedAt,omitempty"`
	UpdatedAt           time.Time `json:"updatedAt,omitempty"`
}

type OSRelease struct {
	ID              string
	IDLike          string
	Name            string
	PrettyName      string
	VersionID       string
	Version         string
	VersionCodename string
}

type Result struct {
	Type            string          `json:"type"`
	TargetName      string          `json:"targetName"`
	Hostname        string          `json:"hostname,omitempty"`
	ImageName       string          `json:"imageName,omitempty"`
	ImageRef        string          `json:"imageRef,omitempty"`
	ImageDigest     string          `json:"imageDigest,omitempty"`
	Source          string          `json:"source,omitempty"`
	OSID            string          `json:"osId"`
	OSName          string          `json:"osName"`
	OSVersion       string          `json:"osVersion"`
	OSCodename      string          `json:"osCodename,omitempty"`
	PackageManager  string          `json:"packageManager"`
	ScannerVersion  string          `json:"scannerVersion"`
	Packages        []Package       `json:"packages"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type HostOptions struct {
	TargetRoot string
	Hostname   string
	OSVBaseURL string
	Progress   func(string)
}

type ContainerOptions struct {
	Image      string
	Local      bool
	OSVBaseURL string
	Progress   func(string)
}
