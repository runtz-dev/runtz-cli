package runtzclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/runtz-dev/runtz-cli/internal/pkgscan"
	"github.com/runtz-dev/runtz-cli/internal/report"
	"github.com/runtz-dev/runtz-cli/internal/sca"
)

type Client struct {
	endpoint   string
	token      string
	httpClient *http.Client
}

type IngestSCARequest struct {
	Workspace       string              `json:"workspace,omitempty"`
	WorkspaceID     string              `json:"workspaceId,omitempty"`
	ProjectName     string              `json:"projectName"`
	Source          string              `json:"source"`
	TargetFile      string              `json:"targetFile"`
	ScannerVersion  string              `json:"scannerVersion"`
	Dependencies    []sca.Dependency    `json:"dependencies"`
	Vulnerabilities []sca.Vulnerability `json:"vulnerabilities"`
}

type IngestPackageScanRequest struct {
	Workspace       string                  `json:"workspace,omitempty"`
	WorkspaceID     string                  `json:"workspaceId,omitempty"`
	TargetName      string                  `json:"targetName"`
	Hostname        string                  `json:"hostname,omitempty"`
	ImageName       string                  `json:"imageName,omitempty"`
	ImageRef        string                  `json:"imageRef,omitempty"`
	ImageDigest     string                  `json:"imageDigest,omitempty"`
	Source          string                  `json:"source,omitempty"`
	OSID            string                  `json:"osId"`
	OSName          string                  `json:"osName"`
	OSVersion       string                  `json:"osVersion"`
	OSCodename      string                  `json:"osCodename,omitempty"`
	PackageManager  string                  `json:"packageManager"`
	ScannerVersion  string                  `json:"scannerVersion"`
	Packages        []pkgscan.Package       `json:"packages"`
	Vulnerabilities []pkgscan.Vulnerability `json:"vulnerabilities"`
}

type IngestFindingsScanRequest struct {
	ProjectName      string           `json:"projectName,omitempty"`
	TargetName       string           `json:"targetName"`
	Source           string           `json:"source,omitempty"`
	ScannerVersion   string           `json:"scannerVersion"`
	FilesScanned     int              `json:"filesScanned,omitempty"`
	ResourcesScanned int              `json:"resourcesScanned,omitempty"`
	Findings         []report.Finding `json:"findings"`
}

func New(endpoint, token string) *Client {
	return NewWithAPIKey(endpoint, token, "")
}

func NewWithAPIKey(endpoint, token, apiKey string) *Client {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" {
		endpoint = "https://engine.runtz.dev"
	}
	token = strings.TrimSpace(token)
	apiKey = strings.TrimSpace(apiKey)
	if apiKey != "" {
		token = apiKey
	}

	return &Client{
		endpoint:   endpoint,
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) SendSCA(ctx context.Context, workspace, workspaceID string, result sca.Result) (string, error) {
	payload := IngestSCARequest{
		Workspace:       workspace,
		WorkspaceID:     workspaceID,
		ProjectName:     result.ProjectName,
		Source:          result.Source,
		TargetFile:      result.TargetFile,
		ScannerVersion:  result.ScannerVersion,
		Dependencies:    result.Dependencies,
		Vulnerabilities: result.Vulnerabilities,
	}

	return c.send(ctx, "/api/v1/ingest/sca", payload)
}

func (c *Client) SendPackageScan(ctx context.Context, workspace, workspaceID string, result pkgscan.Result) (string, error) {
	payload := IngestPackageScanRequest{
		Workspace:       workspace,
		WorkspaceID:     workspaceID,
		TargetName:      result.TargetName,
		Hostname:        result.Hostname,
		ImageName:       result.ImageName,
		ImageRef:        result.ImageRef,
		ImageDigest:     result.ImageDigest,
		Source:          result.Source,
		OSID:            result.OSID,
		OSName:          result.OSName,
		OSVersion:       result.OSVersion,
		OSCodename:      result.OSCodename,
		PackageManager:  result.PackageManager,
		ScannerVersion:  result.ScannerVersion,
		Packages:        result.Packages,
		Vulnerabilities: result.Vulnerabilities,
	}

	return c.send(ctx, "/api/v1/ingest/"+result.Type, payload)
}

func (c *Client) SendFindingsScan(ctx context.Context, result report.Result) (string, error) {
	payload := IngestFindingsScanRequest{
		ProjectName:      result.ProjectName,
		TargetName:       result.TargetName,
		Source:           result.Source,
		ScannerVersion:   result.ScannerVersion,
		FilesScanned:     result.FilesScanned,
		ResourcesScanned: result.ResourcesScanned,
		Findings:         result.Findings,
	}

	return c.send(ctx, "/api/v1/ingest/"+result.Type, payload)
}

// ErrVerifyUnsupported means the endpoint answered but has no
// /api/v1/keys/verify route — a self-hosted engine older than the login
// feature. Callers may store the token anyway and let the first scan check it.
var ErrVerifyUnsupported = errors.New("endpoint does not support token verification")

type VerifyKeyResult struct {
	Workspace struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"workspace"`
	APIKey struct {
		Name      string `json:"name"`
		Prefix    string `json:"prefix"`
		ExpiresAt string `json:"expiresAt"`
	} `json:"apiKey"`
}

// VerifyKey checks the client token against the platform and reports the
// workspace it belongs to.
func (c *Client) VerifyKey(ctx context.Context) (VerifyKeyResult, error) {
	var result VerifyKeyResult

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/api/v1/keys/verify", nil)
	if err != nil {
		return result, err
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return result, fmt.Errorf("reach runtz endpoint: %w", err)
	}
	defer response.Body.Close()

	switch {
	case response.StatusCode == http.StatusOK:
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			return result, fmt.Errorf("decode verify response: %w", err)
		}
		return result, nil
	case response.StatusCode == http.StatusUnauthorized, response.StatusCode == http.StatusForbidden:
		var body map[string]any
		_ = json.NewDecoder(response.Body).Decode(&body)
		if message, ok := body["error"].(string); ok && message != "" {
			return result, fmt.Errorf("token rejected: %s", message)
		}
		return result, fmt.Errorf("token rejected by %s", c.endpoint)
	case response.StatusCode == http.StatusNotFound, response.StatusCode == http.StatusMethodNotAllowed:
		return result, ErrVerifyUnsupported
	default:
		return result, fmt.Errorf("runtz returned %s while verifying the token", response.Status)
	}
}

func (c *Client) send(ctx context.Context, path string, payload any) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode ingest payload: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("send scan to runtz: %w", err)
	}
	defer response.Body.Close()

	var resultBody map[string]any
	_ = json.NewDecoder(response.Body).Decode(&resultBody)
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("runtz returned %s: %v", response.Status, resultBody["error"])
	}

	if id, ok := resultBody["id"].(string); ok {
		return id, nil
	}

	return "", nil
}
