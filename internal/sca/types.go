package sca

import "time"

type Dependency struct {
	Name            string `json:"name"`
	RequestedRange  string `json:"requestedRange"`
	ResolvedVersion string `json:"resolvedVersion"`
	Scope           string `json:"scope"`
	Ecosystem       string `json:"ecosystem"`
	File            string `json:"file,omitempty"`
}

type Vulnerability struct {
	ID                  string    `json:"id"`
	GHSAID              string    `json:"ghsaId"`
	CVEID               string    `json:"cveId,omitempty"`
	PackageName         string    `json:"packageName"`
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

type Result struct {
	ProjectName     string          `json:"projectName"`
	Source          string          `json:"source"`
	TargetFile      string          `json:"targetFile"`
	TargetFiles     []string        `json:"targetFiles,omitempty"`
	ScannerVersion  string          `json:"scannerVersion"`
	Dependencies    []Dependency    `json:"dependencies"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
