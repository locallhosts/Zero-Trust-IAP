// Command proxy is the zero-trust Identity-Aware Proxy's entrypoint. It
// starts two listeners:
//
//  1. The data-plane listener (cfg.ListenAddr) — TLS-terminating reverse
//     proxy that end users/services hit. Requires mTLS (or JWT, if
//     enabled) on every request.
//  2. The admin/control-plane listener (cfg.AdminListenAddr) — serves the
//     JSON API + static TypeScript admin UI for policy management, access
//     logs, and cert rotation status. Bind this to localhost or an
//     internal-only interface in production; it is a separate listener
//     specifically so it can be firewalled off from the internet
//     independently of the data plane.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"zero-trust-iap/internal/admin"
	"zero-trust-iap/internal/logging"
	"zero-trust-iap/internal/policy"
	"zero-trust-iap/internal/proxy"
	"zero-trust-iap/internal/vault"
)

func main() {
	configPath := flag.String("config", "configs/proxy.example.json", "path to proxy config JSON")
	flag.Parse()

	cfg, err := proxy.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if cfg.AdminAPIToken == "" {
		log.Println("WARNING: no admin API token configured (IAP_ADMIN_TOKEN unset) — admin API is unauthenticated. Fine for local dev, unsafe for anything else.")
	}

	policyEngine, err := policy.LoadFromFile(cfg.PolicyFile)
	if err != nil {
		log.Fatalf("policy: %v", err)
	}

	accessLog, err := logging.NewLogger(cfg.AccessLogFile, 2000)
	if err != nil {
		log.Fatalf("logging: %v", err)
	}
	defer accessLog.Close()

	// --- Certificate source: Vault-issued + rotating, or static files ---
	var rotator *proxy.Rotator
	if cfg.VaultAddr != "" && cfg.VaultToken != "" {
		vc := vault.NewClient(cfg.VaultAddr, cfg.VaultToken)
		hostname, _ := os.Hostname()
		spiffeURI := "spiffe://" + firstOr(cfg.TrustDomains, "example.internal") + "/iap-proxy/" + hostname
		rotator, err = proxy.NewVaultRotator(cfg, vc, hostname, spiffeURI)
		if err != nil {
			log.Printf("vault rotation unavailable (%v) — falling back to static cert files", err)
		}
	}
	if rotator == nil {
		rotator, err = proxy.NewStaticRotator(cfg.ServerCertFile, cfg.ServerKeyFile)
		if err != nil {
			log.Fatalf("tls: no usable certificate source (vault or static files): %v", err)
		}
	}

	srv, err := proxy.NewServer(cfg, policyEngine, accessLog, rotator)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}

	tlsConfig, err := proxy.BuildTLSConfig(cfg)
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}
	tlsConfig.GetCertificate = rotator.GetCertificate

	dataPlane := &http.Server{
		Addr:      cfg.ListenAddr,
		Handler:   srv,
		TLSConfig: tlsConfig,
	}

	adminAPI := admin.NewAPI(policyEngine, accessLog, rotator, cfg.AdminAPIToken)
	adminMux := http.NewServeMux()
	adminMux.Handle("/api/", adminAPI)
	adminMux.HandleFunc("/healthz", adminAPI.ServeHTTP)
	if cfg.AdminStaticDir != "" {
		adminMux.Handle("/", http.FileServer(http.Dir(cfg.AdminStaticDir)))
	}
	adminPlane := &http.Server{
		Addr:    cfg.AdminListenAddr,
		Handler: adminMux,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rotator.Run(ctx)

	go func() {
		log.Printf("data-plane IAP listening on %s (mTLS required, forwarding to %s)", cfg.ListenAddr, cfg.BackendURL)
		if err := dataPlane.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("data-plane server: %v", err)
		}
	}()
	go func() {
		log.Printf("admin API + UI listening on %s", cfg.AdminListenAddr)
		if err := adminPlane.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("admin server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = dataPlane.Shutdown(shutdownCtx)
	_ = adminPlane.Shutdown(shutdownCtx)
	rotator.Close()
}

func firstOr(vals []string, fallback string) string {
	if len(vals) > 0 {
		return vals[0]
	}
	return fallback
}

var _ = tls.VersionTLS12
