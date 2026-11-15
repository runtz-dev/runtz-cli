package cloudclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const DefaultEndpoint = "https://security.runtz.dev"

var workspacePattern = regexp.MustCompile(`^[a-f0-9]{24}$`)

// Endpoint keeps hosted dev/prod separate. Self-hosted engines must explicitly
// choose their Security service instead of sending cloud credentials to SaaS.
func Endpoint(explicit, engine string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	switch strings.TrimRight(engine, "/") {
	case "https://engine.runtz.dev":
		return DefaultEndpoint, nil
	case "https://engine-dev.runtz.dev":
		return "https://security-dev.runtz.dev", nil
	default:
		return "", errors.New("self-hosted cloud scans require --security-endpoint or RUNTZ_SECURITY_ENDPOINT")
	}
}

type Client struct {
	endpoint, token, workspaceID string
	http                         *http.Client
}

func New(endpoint, token, workspaceID string) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) {
		return nil, errors.New("Security endpoint must use HTTPS (HTTP is allowed only on loopback)")
	}
	if token == "" || !workspacePattern.MatchString(workspaceID) {
		return nil, errors.New("a verified Runtz workspace token is required")
	}
	return &Client{strings.TrimRight(endpoint, "/"), token, workspaceID, &http.Client{Timeout: 16 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) request(ctx context.Context, provider, action, scope string, credentials []byte) (*http.Response, error) {
	if provider != "gcp" && provider != "aws" && provider != "azure" {
		return nil, errors.New("unsupported cloud provider")
	}
	body, err := json.Marshal(struct {
		Scope       string          `json:"scope"`
		Credentials json.RawMessage `json:"credentials"`
	}{scope, credentials})
	if err != nil {
		return nil, errors.New("cloud credential must be valid JSON")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/cli/"+provider+"/"+action, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid Security request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/x-ndjson, application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach Runtz Security: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		switch res.StatusCode {
		case 401, 403:
			return nil, errors.New("Security rejected the workspace token; check your login and Security/engine environment")
		case 400, 422:
			return nil, errors.New("Security could not verify the cloud credential, scope or read permissions; review the provider setup guide")
		default:
			return nil, fmt.Errorf("Runtz Security returned HTTP %d; retry the command", res.StatusCode)
		}
	}
	return res, nil
}

func (c *Client) Validate(ctx context.Context, provider, scope string, credentials []byte) error {
	res, err := c.request(ctx, provider, "validate", scope, credentials)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var body struct {
		Valid       bool   `json:"valid"`
		WorkspaceID string `json:"workspaceId"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 16384)).Decode(&body) != nil || !body.Valid {
		return errors.New("Security returned an invalid validation response")
	}
	if body.WorkspaceID != c.workspaceID {
		return errors.New("Security belongs to a different workspace or engine environment")
	}
	return nil
}

// Scan consumes the live response, including heartbeats. A truncated stream is
// an error, never a successful empty scan. Errors are deliberately not echoed
// from arbitrary response bodies, which could contain credential material.
func (c *Client) Scan(ctx context.Context, provider, scope string, credentials []byte) (Result, error) {
	res, err := c.request(ctx, provider, "scan", scope, credentials)
	if err != nil {
		return Result{}, err
	}
	defer res.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(res.Body, 8<<20))
	started := false
	for {
		var event struct {
			Type        string  `json:"type"`
			WorkspaceID string  `json:"workspaceId"`
			Result      *Result `json:"result"`
		}
		if err := decoder.Decode(&event); err != nil {
			return Result{}, errors.New("Security scan response was interrupted or invalid; retry the command")
		}
		switch event.Type {
		case "started":
			if started || event.WorkspaceID != c.workspaceID {
				return Result{}, errors.New("Security belongs to a different workspace or engine environment")
			}
			started = true
		case "heartbeat":
			if !started {
				return Result{}, errors.New("Security returned an invalid scan stream")
			}
		case "error":
			return Result{}, errors.New("Security could not complete the scan; verify cloud access and retry")
		case "result":
			if !started || event.WorkspaceID != c.workspaceID || event.Result == nil {
				return Result{}, errors.New("Security returned an invalid scan result")
			}
			result := *event.Result
			actual := result.ProjectID
			if provider == "aws" {
				actual = result.AccountID
			}
			if provider == "azure" {
				actual = result.SubscriptionID
			}
			if result.Provider != provider || !strings.EqualFold(actual, scope) || result.CatalogVersion == "" || result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) || len(result.Checks) == 0 {
				return Result{}, errors.New("Security returned an incomplete or mismatched scan result")
			}
			return result, nil
		default:
			return Result{}, errors.New("Security returned an unsupported scan event; update Runtz CLI")
		}
	}
}
