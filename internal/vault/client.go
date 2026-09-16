// Package vault is a minimal client for the subset of HashiCorp Vault's
// HTTP API this project needs: reading KV secrets and issuing/renewing
// short-lived certificates from the PKI secrets engine. It talks to Vault
// over plain net/http rather than pulling in the official Go SDK, which
// keeps the whole proxy dependency-free (see internal/identity for the
// same rationale re: SPIFFE).
//
// This is what "secret rotation without hardcoded credentials" means in
// practice: the proxy never stores a long-lived TLS cert or API key on
// disk. It authenticates to Vault once (AppRole or a token injected by the
// platform), then periodically calls IssueCertificate to mint a new
// short-TTL leaf cert and swaps it into the running TLS config before the
// old one expires. See internal/proxy/rotation.go for the scheduler.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	Addr       string // e.g. https://127.0.0.1:8200
	Token      string
	HTTPClient *http.Client
}

func NewClient(addr, token string) *Client {
	return &Client{
		Addr:  addr,
		Token: token,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Addr+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault: request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("vault: %s %s returned %d: %s", method, path, resp.StatusCode, string(raw))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("vault: decode response from %s: %w", path, err)
		}
	}
	return nil
}

// --- KV v2 secrets ---

type kvReadResponse struct {
	Data struct {
		Data     map[string]any `json:"data"`
		Metadata struct {
			Version int `json:"version"`
		} `json:"metadata"`
	} `json:"data"`
}

// ReadSecret reads a KV-v2 secret at the given mount+path, e.g.
// mount="secret", path="iap/admin-ui" -> GET /v1/secret/data/iap/admin-ui
func (c *Client) ReadSecret(ctx context.Context, mount, path string) (map[string]any, int, error) {
	var resp kvReadResponse
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/%s/data/%s", mount, path), nil, &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.Data, resp.Data.Metadata.Version, nil
}

// WriteSecret writes/updates a KV-v2 secret.
func (c *Client) WriteSecret(ctx context.Context, mount, path string, data map[string]any) error {
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/%s/data/%s", mount, path), map[string]any{"data": data}, nil)
}

// --- PKI secrets engine ---

// CertificateBundle is a Vault-issued leaf certificate plus its private
// key and the CA chain needed to validate it.
type CertificateBundle struct {
	Certificate    string   `json:"certificate"`
	IssuingCA      string   `json:"issuing_ca"`
	CAChain        []string `json:"ca_chain"`
	PrivateKey     string   `json:"private_key"`
	PrivateKeyType string   `json:"private_key_type"`
	SerialNumber   string   `json:"serial_number"`
	ExpirationUnix int64    `json:"expiration"`
}

type issueRequest struct {
	CommonName string `json:"common_name"`
	AltNames   string `json:"alt_names,omitempty"`
	URISans    string `json:"uri_sans,omitempty"` // used to embed the spiffe:// URI SAN
	TTL        string `json:"ttl,omitempty"`
}

type issueResponse struct {
	Data CertificateBundle `json:"data"`
}

// IssueCertificate requests a new short-lived leaf certificate from Vault's
// PKI engine, embedding a SPIFFE URI SAN so the issued cert plugs directly
// into internal/identity's verification logic.
//
// mount: PKI mount path, e.g. "pki_int"
// role: pre-configured PKI role name, e.g. "iap-workload"
func (c *Client) IssueCertificate(ctx context.Context, mount, role, commonName, spiffeURI, ttl string) (*CertificateBundle, error) {
	var resp issueResponse
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/%s/issue/%s", mount, role), issueRequest{
		CommonName: commonName,
		URISans:    spiffeURI,
		TTL:        ttl,
	}, &resp)
	if err != nil {
		return nil, fmt.Errorf("vault: issue certificate: %w", err)
	}
	return &resp.Data, nil
}

// RevokeCertificate revokes a previously issued cert by serial number —
// used when a workload's posture goes bad or it's decommissioned.
func (c *Client) RevokeCertificate(ctx context.Context, mount, serial string) error {
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/%s/revoke", mount), map[string]string{
		"serial_number": serial,
	}, nil)
}

// Health checks Vault's seal/health status — used by the admin UI's
// "cert rotation status" panel to show whether Vault itself is reachable.
type HealthStatus struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	Standby     bool `json:"standby"`
}

func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	var h HealthStatus
	if err := c.do(ctx, http.MethodGet, "/v1/sys/health", nil, &h); err != nil {
		return nil, err
	}
	return &h, nil
}
