package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OSVBatchQuery struct {
	Package OSVPackage `json:"package"`
	Version string     `json:"version"`
}

type OSVBatchPayload struct {
	Queries []OSVBatchQuery `json:"queries"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVVulnerability struct {
	ID         string        `json:"id"`
	Summary    string        `json:"summary"`
	Details    string        `json:"details"`
	Severities []OSVSeverity `json:"severity,omitempty"`
}

type OSVResultItem struct {
	Vulns []OSVVulnerability `json:"vulns,omitempty"`
}

type OSVBatchResponse struct {
	Results []OSVResultItem `json:"results"`
}

type OSVClient struct {
	httpClient *http.Client
	baseURL    string
}

func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://api.osv.dev/v1/querybatch",
	}
}

func (c *OSVClient) BatchQuery(queries []OSVBatchQuery) (*OSVBatchResponse, error) {
	if len(queries) == 0 {
		return &OSVBatchResponse{}, nil
	}

	payload := OSVBatchPayload{Queries: queries}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed encoding OSV request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL, bytes.NewBuffer(buf))
	if err != nil {
		return nil, fmt.Errorf("failed preparing OSV request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GitShield-CLI/1.0")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed communicating with OSV API: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API responded with HTTP %d", res.StatusCode)
	}

	var response OSVBatchResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed decoding OSV response: %w", err)
	}

	return &response, nil
}