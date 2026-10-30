package pkgscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestQueryBatchMatchesFollowsPageTokens(t *testing.T) {
	var requests [][]osvQuery
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		requests = append(requests, request.Queries)

		// "linux" spans three pages; "bash" fits in the first one.
		var response osvBatchResponse
		for _, query := range request.Queries {
			switch {
			case query.Package.Name == "bash":
				response.Results = append(response.Results, osvQueryResult{Vulns: []osvVulnerability{{ID: "BASH-1"}}})
			case query.PageToken == "":
				response.Results = append(response.Results, osvQueryResult{Vulns: []osvVulnerability{{ID: "LINUX-1"}}, NextPageToken: "page-2"})
			case query.PageToken == "page-2":
				response.Results = append(response.Results, osvQueryResult{Vulns: []osvVulnerability{{ID: "LINUX-2"}}, NextPageToken: "page-3"})
			default:
				response.Results = append(response.Results, osvQueryResult{Vulns: []osvVulnerability{{ID: "LINUX-3"}}})
			}
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	matches, err := newOSVClient(server.URL).queryBatchMatches(context.Background(), "Ubuntu:26.04:LTS", []sourcePackage{
		{Name: "bash", Version: "5.2"},
		{Name: "linux", Version: "7.0.0-42.42"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for _, match := range matches {
		got = append(got, match.sourcePackage.Name+":"+match.vulnID)
	}
	if want := []string{"bash:BASH-1", "linux:LINUX-1", "linux:LINUX-2", "linux:LINUX-3"}; !slices.Equal(got, want) {
		t.Fatalf("matches:\n got %v\nwant %v", got, want)
	}

	if len(requests) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(requests))
	}
	for _, followUp := range requests[1:] {
		if len(followUp) != 1 || followUp[0].Package.Name != "linux" {
			t.Fatalf("expected follow-up pages to re-query only linux, got %+v", followUp)
		}
	}
}

func TestQueryBatchMatchesStopsEndlessPagination(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		_ = json.NewEncoder(w).Encode(osvBatchResponse{Results: []osvQueryResult{{NextPageToken: fmt.Sprint(page)}}})
	}))
	defer server.Close()

	_, err := newOSVClient(server.URL).queryBatchMatches(context.Background(), "Ubuntu:26.04:LTS", []sourcePackage{{Name: "linux", Version: "7.0.0-42.42"}})
	if err == nil {
		t.Fatal("expected an error when OSV never stops paginating")
	}
	if page != maxOSVQueryPages {
		t.Fatalf("expected %d requests, got %d", maxOSVQueryPages, page)
	}
}
