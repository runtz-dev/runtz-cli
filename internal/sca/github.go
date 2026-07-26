package sca

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const githubAdvisoriesURL = "https://api.github.com/advisories"

type GitHubClient struct {
	httpClient *http.Client
	token      string
	userAgent  string
}

type githubAdvisory struct {
	GHSAID          string                `json:"ghsa_id"`
	CVEID           string                `json:"cve_id"`
	HTMLURL         string                `json:"html_url"`
	Summary         string                `json:"summary"`
	Severity        string                `json:"severity"`
	Identifiers     []githubIdentifier    `json:"identifiers"`
	References      []string              `json:"references"`
	Vulnerabilities []githubVulnerability `json:"vulnerabilities"`
	CVSS            struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
	PublishedAt time.Time `json:"published_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type githubIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type githubVulnerability struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	FirstPatchedVersion    any    `json:"first_patched_version"`
}

func NewGitHubClient(token string) *GitHubClient {
	return &GitHubClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		token:      strings.TrimSpace(token),
		userAgent:  "runtz-cli",
	}
}

// advisoryEcosystems lists the GitHub Advisory Database ecosystem identifiers
// the SCA scan queries. Dependency.Ecosystem values match these directly.
var advisoryEcosystems = []string{"npm", "pip", "go", "maven", "rubygems", "composer", "rust", "nuget"}

func (c *GitHubClient) FindVulnerabilities(ctx context.Context, dependencies []Dependency) ([]Vulnerability, error) {
	affectsByEcosystem := make(map[string][]string)
	versionsByEcosystem := make(map[string]map[string]string)
	for _, dependency := range dependencies {
		if dependency.ResolvedVersion == "" || !supportedEcosystem(dependency.Ecosystem) {
			continue
		}

		key := strings.ToLower(dependency.Name)
		if versionsByEcosystem[dependency.Ecosystem] == nil {
			versionsByEcosystem[dependency.Ecosystem] = make(map[string]string)
		}
		if _, exists := versionsByEcosystem[dependency.Ecosystem][key]; exists {
			continue
		}

		versionsByEcosystem[dependency.Ecosystem][key] = dependency.ResolvedVersion
		affectsByEcosystem[dependency.Ecosystem] = append(affectsByEcosystem[dependency.Ecosystem], fmt.Sprintf("%s@%s", dependency.Name, dependency.ResolvedVersion))
	}

	var vulnerabilities []Vulnerability
	for _, ecosystem := range advisoryEcosystems {
		versionByPackage := versionsByEcosystem[ecosystem]
		for _, chunk := range chunks(affectsByEcosystem[ecosystem], 50) {
			advisories, err := c.fetchAdvisories(ctx, ecosystem, chunk)
			if err != nil {
				return nil, err
			}

			for _, advisory := range advisories {
				for _, affected := range advisory.Vulnerabilities {
					if !strings.EqualFold(affected.Package.Ecosystem, ecosystem) {
						continue
					}

					installedVersion, ok := versionByPackage[strings.ToLower(affected.Package.Name)]
					if !ok {
						continue
					}

					vulnerability := Vulnerability{
						ID:                  advisoryID(advisory),
						GHSAID:              advisory.GHSAID,
						CVEID:               firstCVE(advisory),
						PackageName:         affected.Package.Name,
						Ecosystem:           ecosystem,
						InstalledVersion:    installedVersion,
						VulnerableRange:     affected.VulnerableVersionRange,
						FirstPatchedVersion: patchedVersion(affected.FirstPatchedVersion),
						Severity:            advisory.Severity,
						Summary:             advisory.Summary,
						AdvisoryURL:         advisory.HTMLURL,
						CVSSScore:           advisory.CVSS.Score,
						References:          advisory.References,
						PublishedAt:         advisory.PublishedAt,
						UpdatedAt:           advisory.UpdatedAt,
					}
					vulnerabilities = append(vulnerabilities, vulnerability)
				}
			}
		}
	}

	return dedupeVulnerabilities(vulnerabilities), nil
}

func supportedEcosystem(ecosystem string) bool {
	for _, value := range advisoryEcosystems {
		if value == ecosystem {
			return true
		}
	}
	return false
}

func (c *GitHubClient) fetchAdvisories(ctx context.Context, ecosystem string, affects []string) ([]githubAdvisory, error) {
	if len(affects) == 0 {
		return nil, nil
	}

	query := url.Values{}
	query.Set("ecosystem", ecosystem)
	query.Set("affects", strings.Join(affects, ","))
	query.Set("per_page", "100")

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAdvisoriesURL+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", c.userAgent)
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query github advisories: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		var body map[string]any
		_ = json.NewDecoder(response.Body).Decode(&body)
		return nil, fmt.Errorf("github advisories returned %s: %v", response.Status, body["message"])
	}

	var advisories []githubAdvisory
	if err := json.NewDecoder(response.Body).Decode(&advisories); err != nil {
		return nil, fmt.Errorf("decode github advisories: %w", err)
	}

	return advisories, nil
}

func advisoryID(advisory githubAdvisory) string {
	if cve := firstCVE(advisory); cve != "" {
		return cve
	}
	return advisory.GHSAID
}

func firstCVE(advisory githubAdvisory) string {
	if advisory.CVEID != "" {
		return advisory.CVEID
	}

	for _, identifier := range advisory.Identifiers {
		if strings.EqualFold(identifier.Type, "CVE") {
			return identifier.Value
		}
	}

	return ""
}

func patchedVersion(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case map[string]any:
		if identifier, ok := typed["identifier"].(string); ok {
			return identifier
		}
	}

	return ""
}

func chunks(values []string, size int) [][]string {
	if size <= 0 {
		return [][]string{values}
	}

	chunks := make([][]string, 0, (len(values)+size-1)/size)
	for start := 0; start < len(values); start += size {
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		chunks = append(chunks, values[start:end])
	}

	return chunks
}

func dedupeVulnerabilities(values []Vulnerability) []Vulnerability {
	seen := make(map[string]bool, len(values))
	result := make([]Vulnerability, 0, len(values))
	for _, value := range values {
		key := value.PackageName + "|" + value.ID + "|" + value.InstalledVersion
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
	}

	return result
}
