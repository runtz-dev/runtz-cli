package report

type Finding struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Description  string `json:"description,omitempty"`
	Severity     string `json:"severity"`
	Category     string `json:"category,omitempty"`
	File         string `json:"file,omitempty"`
	Line         int    `json:"line,omitempty"`
	Column       int    `json:"column,omitempty"`
	ResourceKind string `json:"resourceKind,omitempty"`
	ResourceName string `json:"resourceName,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	Remediation  string `json:"remediation,omitempty"`
}

type Result struct {
	Type             string    `json:"type"`
	ProjectName      string    `json:"projectName,omitempty"`
	TargetName       string    `json:"targetName"`
	Source           string    `json:"source,omitempty"`
	ScannerVersion   string    `json:"scannerVersion"`
	FilesScanned     int       `json:"filesScanned,omitempty"`
	ResourcesScanned int       `json:"resourcesScanned,omitempty"`
	Findings         []Finding `json:"findings"`
}
