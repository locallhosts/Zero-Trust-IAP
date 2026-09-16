package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config is the top-level proxy configuration, loaded from a JSON file
// (see configs/proxy.example.json) with environment variable overrides for
// secrets (see envOverrides in main.go).
type Config struct {
	ListenAddr string `json:"listen_addr"`

	// TLS / mTLS
	ServerCertFile string `json:"server_cert_file"`
	ServerKeyFile  string `json:"server_key_file"`
	ClientCAFile   string `json:"client_ca_file"` // CA that signs client SVIDs

	// SPIFFE
	TrustDomains  []string      `json:"trust_domains"`
	MaxSVIDAgeStr string        `json:"max_svid_age"` // e.g. "1h"
	MaxSVIDAge    time.Duration `json:"-"`

	// JWT fallback auth
	JWTEnabled    bool   `json:"jwt_enabled"`
	JWTHMACSecret string `json:"jwt_hmac_secret"` // overridden by IAP_JWT_SECRET env var
	JWTIssuer     string `json:"jwt_issuer"`
	JWTAudience   string `json:"jwt_audience"`

	// Backend to forward allowed requests to (internal app, or an
	// Envoy/Nginx sidecar in front of it).
	BackendURL string `json:"backend_url"`

	// Policy engine
	PolicyFile string `json:"policy_file"`

	// Vault
	VaultAddr        string        `json:"vault_addr"`
	VaultToken       string        `json:"vault_token"` // overridden by VAULT_TOKEN env var
	VaultPKIMount    string        `json:"vault_pki_mount"`
	VaultPKIRole     string        `json:"vault_pki_role"`
	CertTTL          string        `json:"cert_ttl"`
	RotationEnabled  bool          `json:"rotation_enabled"`
	RotationCheckStr string        `json:"rotation_check_interval"` // e.g. "5m"
	RotationCheck    time.Duration `json:"-"`

	// Device posture
	PostureEnabled   bool          `json:"posture_enabled"`
	PostureAgentURL  string        `json:"posture_agent_url"`
	PostureMaxAgeStr string        `json:"posture_max_age"` // e.g. "10m"
	PostureMaxAge    time.Duration `json:"-"`

	// Access log
	AccessLogFile string `json:"access_log_file"`

	// Admin API / UI
	AdminListenAddr string `json:"admin_listen_addr"`
	AdminStaticDir  string `json:"admin_static_dir"`
	AdminAPIToken   string `json:"admin_api_token"` // overridden by IAP_ADMIN_TOKEN env var
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	if c.MaxSVIDAgeStr != "" {
		d, err := time.ParseDuration(c.MaxSVIDAgeStr)
		if err != nil {
			return nil, fmt.Errorf("config: invalid max_svid_age: %w", err)
		}
		c.MaxSVIDAge = d
	} else {
		c.MaxSVIDAge = time.Hour
	}

	if c.RotationCheckStr != "" {
		d, err := time.ParseDuration(c.RotationCheckStr)
		if err != nil {
			return nil, fmt.Errorf("config: invalid rotation_check_interval: %w", err)
		}
		c.RotationCheck = d
	} else {
		c.RotationCheck = 5 * time.Minute
	}

	if c.PostureMaxAgeStr != "" {
		d, err := time.ParseDuration(c.PostureMaxAgeStr)
		if err != nil {
			return nil, fmt.Errorf("config: invalid posture_max_age: %w", err)
		}
		c.PostureMaxAge = d
	} else {
		c.PostureMaxAge = 10 * time.Minute
	}

	if c.CertTTL == "" {
		c.CertTTL = "1h"
	}

	// Environment overrides for anything secret-shaped — never require
	// secrets to live in the JSON config file on disk.
	if v := os.Getenv("VAULT_TOKEN"); v != "" {
		c.VaultToken = v
	}
	if v := os.Getenv("IAP_JWT_SECRET"); v != "" {
		c.JWTHMACSecret = v
	}
	if v := os.Getenv("IAP_ADMIN_TOKEN"); v != "" {
		c.AdminAPIToken = v
	}

	return &c, nil
}
