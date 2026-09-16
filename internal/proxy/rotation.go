package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"zero-trust-iap/internal/vault"
)

// RotationStatus is exposed to the admin UI so operators can see rotation
// health at a glance without digging through logs.
type RotationStatus struct {
	LastRotatedAt time.Time `json:"last_rotated_at"`
	NotAfter      time.Time `json:"not_after"`
	SerialNumber  string    `json:"serial_number"`
	LastError     string    `json:"last_error,omitempty"`
	Source        string    `json:"source"` // "vault" | "static-file"
}

// Rotator holds the currently active TLS certificate and, if configured,
// periodically replaces it with a freshly Vault-issued one before it
// expires — this is the "secret rotation without hardcoded credentials"
// requirement from the project brief.
type Rotator struct {
	mu      sync.RWMutex
	current *tls.Certificate
	status  RotationStatus

	vaultClient *vault.Client
	cfg         *Config
	commonName  string
	spiffeURI   string

	stop chan struct{}
	// generation lets callers detect that a rotation happened, useful in tests.
	generation int64
}

// NewStaticRotator wraps a fixed cert/key pair with no rotation — used
// when Vault rotation is disabled (e.g. local dev with openssl-generated
// certs from scripts/generate-certs.sh).
func NewStaticRotator(certFile, keyFile string) (*Rotator, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &Rotator{
		current: &cert,
		status:  RotationStatus{Source: "static-file", LastRotatedAt: time.Now()},
	}, nil
}

// NewVaultRotator builds a Rotator that mints its first cert from Vault
// immediately and then re-issues on cfg.RotationCheck interval, replacing
// the cert whenever less than 20% of its TTL remains.
func NewVaultRotator(cfg *Config, vc *vault.Client, commonName, spiffeURI string) (*Rotator, error) {
	r := &Rotator{
		vaultClient: vc,
		cfg:         cfg,
		commonName:  commonName,
		spiffeURI:   spiffeURI,
		stop:        make(chan struct{}),
		status:      RotationStatus{Source: "vault"},
	}
	if err := r.rotateOnce(context.Background()); err != nil {
		return nil, fmt.Errorf("rotation: initial cert issuance failed: %w", err)
	}
	return r, nil
}

// Current returns the currently active certificate for use in
// tls.Config.GetCertificate.
func (r *Rotator) Current() *tls.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// Status returns a snapshot of rotation health for the admin API.
func (r *Rotator) Status() RotationStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

func (r *Rotator) rotateOnce(ctx context.Context) error {
	bundle, err := r.vaultClient.IssueCertificate(ctx, r.cfg.VaultPKIMount, r.cfg.VaultPKIRole, r.commonName, r.spiffeURI, r.cfg.CertTTL)
	if err != nil {
		r.mu.Lock()
		r.status.LastError = err.Error()
		r.mu.Unlock()
		return err
	}
	cert, err := tls.X509KeyPair([]byte(bundle.Certificate), []byte(bundle.PrivateKey))
	if err != nil {
		return fmt.Errorf("rotation: failed to load issued keypair: %w", err)
	}
	r.mu.Lock()
	r.current = &cert
	r.status = RotationStatus{
		LastRotatedAt: time.Now(),
		NotAfter:      time.Unix(bundle.ExpirationUnix, 0),
		SerialNumber:  bundle.SerialNumber,
		Source:        "vault",
	}
	atomic.AddInt64(&r.generation, 1)
	r.mu.Unlock()
	log.Printf("rotation: issued new certificate serial=%s expires=%s", bundle.SerialNumber, time.Unix(bundle.ExpirationUnix, 0))
	return nil
}

// Run starts the background rotation loop. Call in a goroutine; stop via
// Close(). No-op for static (non-Vault) rotators.
func (r *Rotator) Run(ctx context.Context) {
	if r.vaultClient == nil {
		return
	}
	ticker := time.NewTicker(r.cfg.RotationCheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		case <-ticker.C:
			status := r.Status()
			remaining := time.Until(status.NotAfter)
			ttl, err := time.ParseDuration(r.cfg.CertTTL)
			if err != nil {
				ttl = time.Hour
			}
			if remaining < ttl/5 {
				if err := r.rotateOnce(ctx); err != nil {
					log.Printf("rotation: failed to rotate certificate: %v", err)
				}
			}
		}
	}
}

func (r *Rotator) Close() {
	if r.stop != nil {
		close(r.stop)
	}
}
