// Package posture defines device posture signals and the client used by
// the reverse proxy to query the local posture agent before granting
// access. The posture agent itself (cmd/posture-agent) runs on the user's
// device and exposes these signals over a small local HTTP API; the proxy
// calls out to it (or, in a real deployment, to a fleet-wide posture
// service that aggregates agent check-ins) as part of the access decision.
package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Report is what a posture agent produces on each check-in.
type Report struct {
	DeviceID      string    `json:"device_id"`
	DiskEncrypted bool      `json:"disk_encrypted"`
	EDRRunning    bool      `json:"edr_running"`
	EDRProcess    string    `json:"edr_process,omitempty"`
	OS            string    `json:"os"`
	PatchLevel    string    `json:"patch_level"` // ISO date of last OS update, best-effort
	CheckedAt     time.Time `json:"checked_at"`
}

// Checker is implemented per-OS (see checks_linux.go / checks_darwin.go /
// checks_windows.go, selected via build tags) and produces a fresh Report.
type Checker interface {
	Check(ctx context.Context) (Report, error)
}

// Client is used by the IAP proxy to fetch the most recent posture report
// for a device, either from the agent directly (local dev / same-host
// demo) or from a fleet posture API in front of many agents.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{BaseURL: baseURL, HTTPClient: &http.Client{Timeout: 3 * time.Second}}
}

// Fetch retrieves the latest posture report for deviceID.
func (c *Client) Fetch(ctx context.Context, deviceID string) (*Report, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/posture/"+deviceID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("posture: fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("posture: agent returned status %d", resp.StatusCode)
	}
	var report Report
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, fmt.Errorf("posture: decode report: %w", err)
	}
	return &report, nil
}

// Stale reports whether a posture report is too old to trust — a stale
// report (agent offline, network partition) should fail closed, not open.
func (r Report) Stale(maxAge time.Duration) bool {
	return time.Since(r.CheckedAt) > maxAge
}
