package pkgscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const defaultOSVBaseURL = "https://api.osv.dev"

type osvClient struct {
	baseURL    string
	httpClient *http.Client
	vulnCache  map[string]osvVulnerability
	cacheMu    sync.Mutex
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvVulnerability struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Aliases    []string       `json:"aliases"`
	Upstream   []string       `json:"upstream"`
	Severity   []osvSeverity  `json:"severity"`
	Affected   []osvAffected  `json:"affected"`
	References []osvReference `json:"references"`
	Published  time.Time      `json:"published"`
	Modified   time.Time      `json:"modified"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package  osvPackage    `json:"package"`
	Ranges   []osvRange    `json:"ranges"`
	Severity []osvSeverity `json:"severity"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type sourcePackage struct {
	Name             string
	Version          string
	InstalledPackage string
	InstalledVersion string
}

type osvMatch struct {
	sourcePackage sourcePackage
	vulnID        string
}

func findVulnerabilities(ctx context.Context, packages []Package, osRelease OSRelease, baseURL string, progress func(string)) ([]Vulnerability, error) {
	ecosystem := ecosystemForOS(osRelease)
	if ecosystem == "" {
		return nil, fmt.Errorf("unsupported OS for vulnerability matching: %s %s", osRelease.ID, osRelease.VersionID)
	}

	sourcePackages := uniqueSourcePackages(packages)
	if len(sourcePackages) == 0 {
		return nil, nil
	}

	client := newOSVClient(baseURL)
	chunks := sourcePackageChunks(sourcePackages, 500)
	reportProgress(progress, "Querying OSV for %d source packages in %d batch(es).", len(sourcePackages), len(chunks))

	matches, err := client.queryBatchMatchesConcurrently(ctx, ecosystem, chunks)
	if err != nil {
		return nil, err
	}

	uniqueIDs := make(map[string]bool)
	for _, match := range matches {
		uniqueIDs[match.vulnID] = true
	}
	reportProgress(progress, "Fetching details for %d OSV advisories.", len(uniqueIDs))

	details, err := client.fetchVulnerabilityDetails(ctx, mapKeys(uniqueIDs))
	if err != nil {
		return nil, err
	}

	vulnerabilities := make([]Vulnerability, 0, len(matches))
	for _, match := range matches {
		vuln, ok := details[match.vulnID]
		if !ok {
			continue
		}
		if firstCVE(vuln) == "" {
			continue
		}
		vulnerabilities = append(vulnerabilities, normalizeOSVVulnerability(vuln, match.sourcePackage, ecosystem))
	}

	return dedupeVulnerabilities(vulnerabilities), nil
}

func newOSVClient(baseURL string) *osvClient {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = defaultOSVBaseURL
	}

	return &osvClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 60 * time.Second},
		vulnCache:  make(map[string]osvVulnerability),
	}
}

func (c *osvClient) queryBatchMatchesConcurrently(ctx context.Context, ecosystem string, chunks [][]sourcePackage) ([]osvMatch, error) {
	const workerLimit = 4
	workerCount := min(workerLimit, len(chunks))
	jobs := make(chan []sourcePackage)
	var matches []osvMatch
	var matchesMu sync.Mutex
	var firstErr error
	var errMu sync.Mutex

	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for chunk := range jobs {
				errMu.Lock()
				hasErr := firstErr != nil
				errMu.Unlock()
				if hasErr {
					continue
				}

				result, err := c.queryBatchMatches(ctx, ecosystem, chunk)
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					continue
				}

				matchesMu.Lock()
				matches = append(matches, result...)
				matchesMu.Unlock()
			}
		}()
	}

	for _, chunk := range chunks {
		jobs <- chunk
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}

	return matches, nil
}

func (c *osvClient) queryBatchMatches(ctx context.Context, ecosystem string, sourcePackages []sourcePackage) ([]osvMatch, error) {
	requestPayload := osvBatchRequest{Queries: make([]osvQuery, 0, len(sourcePackages))}
	for _, pkg := range sourcePackages {
		requestPayload.Queries = append(requestPayload.Queries, osvQuery{
			Version: pkg.Version,
			Package: osvPackage{
				Name:      pkg.Name,
				Ecosystem: ecosystem,
			},
		})
	}

	body, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("encode osv request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "runtz-cli")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query osv: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		var errorBody map[string]any
		_ = json.NewDecoder(response.Body).Decode(&errorBody)
		return nil, fmt.Errorf("osv returned %s: %v", response.Status, errorBody["message"])
	}

	var responsePayload osvBatchResponse
	if err := json.NewDecoder(response.Body).Decode(&responsePayload); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}

	matches := make([]osvMatch, 0)
	for index, queryResult := range responsePayload.Results {
		if index >= len(sourcePackages) {
			break
		}
		pkg := sourcePackages[index]
		for _, vulnSummary := range queryResult.Vulns {
			matches = append(matches, osvMatch{sourcePackage: pkg, vulnID: vulnSummary.ID})
		}
	}

	return matches, nil
}

func (c *osvClient) fetchVulnerabilityDetails(ctx context.Context, ids []string) (map[string]osvVulnerability, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	const workerLimit = 48
	workerCount := min(workerLimit, len(ids))
	jobs := make(chan string)
	results := make(map[string]osvVulnerability, len(ids))
	var resultsMu sync.Mutex
	var firstErr error
	var errMu sync.Mutex

	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				errMu.Lock()
				hasErr := firstErr != nil
				errMu.Unlock()
				if hasErr {
					continue
				}

				vuln, err := c.fetchVulnerability(ctx, id)
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					continue
				}

				resultsMu.Lock()
				results[id] = vuln
				resultsMu.Unlock()
			}
		}()
	}

	for _, id := range ids {
		jobs <- id
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}

	return results, nil
}

func mapKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (c *osvClient) fetchVulnerability(ctx context.Context, id string) (osvVulnerability, error) {
	c.cacheMu.Lock()
	cached, ok := c.vulnCache[id]
	c.cacheMu.Unlock()
	if ok {
		return cached, nil
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return osvVulnerability{}, err
	}
	request.Header.Set("User-Agent", "runtz-cli")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return osvVulnerability{}, fmt.Errorf("fetch osv vulnerability %s: %w", id, err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		var errorBody map[string]any
		_ = json.NewDecoder(response.Body).Decode(&errorBody)
		return osvVulnerability{}, fmt.Errorf("osv vulnerability %s returned %s: %v", id, response.Status, errorBody["message"])
	}

	var vuln osvVulnerability
	if err := json.NewDecoder(response.Body).Decode(&vuln); err != nil {
		return osvVulnerability{}, fmt.Errorf("decode osv vulnerability %s: %w", id, err)
	}

	c.cacheMu.Lock()
	c.vulnCache[id] = vuln
	c.cacheMu.Unlock()

	return vuln, nil
}

func normalizeOSVVulnerability(vuln osvVulnerability, pkg sourcePackage, ecosystem string) Vulnerability {
	fixedVersion := fixedVersionFor(vuln, pkg.Name, ecosystem)
	cvssScore := cvssScoreFor(vuln, pkg.Name, ecosystem)
	severity := severityFor(vuln, pkg.Name, ecosystem, cvssScore)
	references := referenceURLs(vuln.References)
	advisoryURL := advisoryURLFor(vuln, references)

	vulnerableRange := "affected"
	if fixedVersion != "" {
		vulnerableRange = "< " + fixedVersion
	}

	return Vulnerability{
		ID:                  vuln.ID,
		CVEID:               firstCVE(vuln),
		PackageName:         pkg.Name,
		InstalledPackage:    pkg.InstalledPackage,
		SourcePackage:       pkg.Name,
		Ecosystem:           ecosystem,
		InstalledVersion:    pkg.Version,
		VulnerableRange:     vulnerableRange,
		FirstPatchedVersion: fixedVersion,
		Severity:            severity,
		Summary:             summaryFor(vuln),
		AdvisoryURL:         advisoryURL,
		CVSSScore:           cvssScore,
		References:          references,
		PublishedAt:         vuln.Published,
		UpdatedAt:           vuln.Modified,
	}
}

func uniqueSourcePackages(packages []Package) []sourcePackage {
	seen := make(map[string]sourcePackage)
	for _, pkg := range packages {
		name := firstNonEmpty(pkg.SourceName, pkg.Name)
		version := firstNonEmpty(pkg.SourceVersion, pkg.Version)
		if name == "" || version == "" {
			continue
		}

		key := name + "\x00" + version
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = sourcePackage{
			Name:             name,
			Version:          version,
			InstalledPackage: pkg.Name,
			InstalledVersion: pkg.Version,
		}
	}

	result := make([]sourcePackage, 0, len(seen))
	for _, pkg := range seen {
		result = append(result, pkg)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name == result[j].Name {
			return result[i].Version < result[j].Version
		}
		return result[i].Name < result[j].Name
	})

	return result
}

func sourcePackageChunks(packages []sourcePackage, size int) [][]sourcePackage {
	if size <= 0 {
		return [][]sourcePackage{packages}
	}

	chunks := make([][]sourcePackage, 0, (len(packages)+size-1)/size)
	for start := 0; start < len(packages); start += size {
		end := start + size
		if end > len(packages) {
			end = len(packages)
		}
		chunks = append(chunks, packages[start:end])
	}
	return chunks
}

// sameEcosystem matches OSV ecosystem identifiers that may carry a release
// suffix, e.g. "Rocky Linux:9" against the queried "Rocky Linux".
func sameEcosystem(candidate, ecosystem string) bool {
	return strings.EqualFold(candidate, ecosystem) ||
		strings.HasPrefix(strings.ToLower(candidate), strings.ToLower(ecosystem)+":")
}

func fixedVersionFor(vuln osvVulnerability, packageName, ecosystem string) string {
	for _, affected := range vuln.Affected {
		if affected.Package.Name != packageName || !sameEcosystem(affected.Package.Ecosystem, ecosystem) {
			continue
		}
		for _, versionRange := range affected.Ranges {
			for _, event := range versionRange.Events {
				if event.Fixed != "" {
					return event.Fixed
				}
			}
		}
	}
	return ""
}

func severityFor(vuln osvVulnerability, packageName, ecosystem string, cvssScore float64) string {
	if severity := ubuntuSeverity(vuln.Severity); severity != "" {
		return severity
	}

	for _, affected := range vuln.Affected {
		if affected.Package.Name != packageName || !sameEcosystem(affected.Package.Ecosystem, ecosystem) {
			continue
		}
		if severity := ubuntuSeverity(affected.Severity); severity != "" {
			return severity
		}
	}

	if severity := severityFromScore(cvssScore); severity != "" {
		return severity
	}

	if severity := severityFromSummary(vuln.Summary); severity != "" {
		return severity
	}

	return "unknown"
}

// severityFromSummary reads the severity prefix used by Red Hat style
// advisories, e.g. "Important: openssl security update".
func severityFromSummary(summary string) string {
	prefix, _, ok := strings.Cut(summary, ":")
	if !ok {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(prefix)) {
	case "critical":
		return "critical"
	case "important":
		return "high"
	case "moderate":
		return "medium"
	case "low":
		return "low"
	}
	return ""
}

// cvssScoreFor extracts a CVSS 3.x base score from the advisory, preferring
// entries scoped to the matched package.
func cvssScoreFor(vuln osvVulnerability, packageName, ecosystem string) float64 {
	for _, affected := range vuln.Affected {
		if affected.Package.Name != packageName || !sameEcosystem(affected.Package.Ecosystem, ecosystem) {
			continue
		}
		if score, ok := firstCVSSScore(affected.Severity); ok {
			return score
		}
	}

	if score, ok := firstCVSSScore(vuln.Severity); ok {
		return score
	}
	return 0
}

func firstCVSSScore(severities []osvSeverity) (float64, bool) {
	for _, severity := range severities {
		if !strings.HasPrefix(strings.ToUpper(severity.Type), "CVSS_V3") {
			continue
		}
		if score, ok := cvssBaseScore(severity.Score); ok {
			return score, true
		}
	}
	return 0, false
}

func ubuntuSeverity(severities []osvSeverity) string {
	for _, severity := range severities {
		if !strings.EqualFold(severity.Type, "Ubuntu") {
			continue
		}
		switch strings.ToLower(severity.Score) {
		case "critical", "high", "medium", "low":
			return strings.ToLower(severity.Score)
		case "negligible":
			return "low"
		}
	}
	return ""
}

func referenceURLs(references []osvReference) []string {
	urls := make([]string, 0, len(references))
	seen := make(map[string]bool, len(references))
	for _, reference := range references {
		if reference.URL == "" || seen[reference.URL] {
			continue
		}
		seen[reference.URL] = true
		urls = append(urls, reference.URL)
	}
	return urls
}

func advisoryURLFor(vuln osvVulnerability, references []string) string {
	for _, reference := range vuln.References {
		if strings.EqualFold(reference.Type, "ADVISORY") && reference.URL != "" {
			return reference.URL
		}
	}
	if len(references) > 0 {
		return references[0]
	}
	if vuln.ID != "" {
		return "https://osv.dev/vulnerability/" + vuln.ID
	}
	return ""
}

func summaryFor(vuln osvVulnerability) string {
	summary := strings.TrimSpace(vuln.Summary)
	if summary == "" {
		summary = strings.TrimSpace(vuln.Details)
	}
	if summary == "" {
		return vuln.ID
	}

	summary = strings.ReplaceAll(summary, "\n", " ")
	if len(summary) <= 260 {
		return summary
	}
	return strings.TrimSpace(summary[:260]) + "..."
}

func firstCVE(vuln osvVulnerability) string {
	for _, value := range append(vuln.Upstream, vuln.Aliases...) {
		if cve := extractCVE(value); cve != "" {
			return cve
		}
	}
	return extractCVE(vuln.ID)
}

func extractCVE(value string) string {
	start := strings.Index(value, "CVE-")
	if start < 0 {
		return ""
	}

	value = value[start:]
	end := len(value)
	for index, char := range value {
		if index == 0 {
			continue
		}
		if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' {
			continue
		}
		end = index
		break
	}

	return value[:end]
}

func dedupeVulnerabilities(vulnerabilities []Vulnerability) []Vulnerability {
	// The same CVE can come back under several OSV records (e.g. USN-... and
	// UBUNTU-CVE-... or RLSA-...), so entries collapse on the CVE when one
	// exists. On collision the entry with a patched version wins.
	seen := make(map[string]int, len(vulnerabilities))
	result := make([]Vulnerability, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		key := strings.Join([]string{
			firstNonEmpty(vulnerability.CVEID, vulnerability.ID),
			vulnerability.PackageName,
			vulnerability.InstalledVersion,
		}, "\x00")
		if index, exists := seen[key]; exists {
			if result[index].FirstPatchedVersion == "" && vulnerability.FirstPatchedVersion != "" {
				result[index] = vulnerability
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, vulnerability)
	}

	sort.Slice(result, func(i, j int) bool {
		leftRank := severityRank(result[i].Severity)
		rightRank := severityRank(result[j].Severity)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if result[i].PackageName == result[j].PackageName {
			return result[i].ID < result[j].ID
		}
		return result[i].PackageName < result[j].PackageName
	})

	return result
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
