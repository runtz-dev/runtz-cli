// Package cloudclient calls the public Runtz Security API. It contains only
// transport types; cloud collection and check implementations remain private.
package cloudclient

import "time"

type Check struct {
	Region   string `json:"region,omitempty"`
	RuleID   string `json:"ruleId"`
	Title    string `json:"title"`
	Status   string `json:"status"` // pass, fail, error, skipped, not_applicable
	Severity string `json:"severity"`
	Resource string `json:"resource"`
	Evidence string `json:"evidence"`
}

type Finding struct {
	AccountID      string `json:"accountId,omitempty"`
	Region         string `json:"region,omitempty"`
	ID             string `json:"id"`
	RuleID         string `json:"ruleId"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	ResourceName   string `json:"resourceName"`
	ProjectID      string `json:"projectId,omitempty"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	Source         string `json:"source"`
	Evidence       string `json:"evidence"`
	Remediation    string `json:"remediation"`
	Documentation  string `json:"documentation"`
}

type Summary struct {
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Errors        int `json:"errors"`
	Skipped       int `json:"skipped"`
	NotApplicable int `json:"notApplicable"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
}

type Result struct {
	AccountID      string    `json:"accountId,omitempty"`
	Regions        []string  `json:"regions,omitempty"`
	Provider       string    `json:"provider"`
	ProjectID      string    `json:"projectId,omitempty"`
	SubscriptionID string    `json:"subscriptionId,omitempty"`
	CatalogVersion string    `json:"catalogVersion"`
	StartedAt      time.Time `json:"startedAt"`
	FinishedAt     time.Time `json:"finishedAt"`
	Summary        Summary   `json:"summary"`
	Checks         []Check   `json:"checks"`
	Findings       []Finding `json:"findings"`
}
