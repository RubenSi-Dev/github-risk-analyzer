package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
)

const osvAPIURL = "https://api.osv.dev/v1/query"
const osvAPIURLBatch = "https://api.osv.dev/v1/querybatch"

type packageRequest struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Version   string `json:"version,omitempty"`
}

type osvQueryRequest struct {
	Package packageRequest `json:"package"`
}

type osvQueryBatchRequest struct {
	Queries []struct {
		Package packageRequest `json:"package"`
	} `json:"queries"`
}

type osvQueryResponse struct {
	Vulns []models.Vulnerability `json:"vulns"`
}

type osvQueryBatchResponse struct {
	Results []struct {
		Vulns []models.Vulnerability `json:"vulns"`
	} `json:"results"`
}

func QueryVulnerabilitiesBatch(ctx context.Context, deps []models.Dependency) ([]models.Vulnerability, error) {
	reqBody := osvQueryBatchRequest{}
	for _, dep := range deps {
		reqBody.Queries = append(reqBody.Queries, struct {
			Package packageRequest `json:"package"`
		}{Package: packageRequest{Name: dep.Name, Ecosystem: dep.Ecosystem}})
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV query request: %w", err)
	}

	// build the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvAPIURLBatch, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create OSV API request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json") // set header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send the OSV API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK { // check for status code 200 (OK)
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned non-OK status: %d, body: %s", resp.StatusCode, &bodyBytes)
	}

	var osvResp osvQueryBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode OSV API response: %w", err)
	}

	var vulns []models.Vulnerability
	for _, res := range osvResp.Results {
		vulns = append(vulns, res.Vulns...)
	}

	return vulns, nil

}

func QueryVulnerabilities(ctx context.Context, dep models.Dependency) ([]models.Vulnerability, error) {
	//build json for the request
	reqBody := osvQueryRequest{}
	reqBody.Package.Name = dep.Name
	reqBody.Package.Ecosystem = dep.Ecosystem

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV query request: %w", err)
	}

	// build the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvAPIURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create OSV API request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json") // set header

	// do the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send the OSV API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK { // check for status code 200 (OK)
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned non-OK status: %d, body: %s", resp.StatusCode, &bodyBytes)
	}

	var osvResp osvQueryResponse // unpack response into response struct
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode OSV API response: %w", err)
	}

	return osvResp.Vulns, nil
}
