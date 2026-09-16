// Command posture-agent is the small local agent that runs on a user's
// device and reports basic posture signals (disk encryption, EDR presence,
// OS patch level) over a local HTTP API that the IAP proxy (or a
// fleet-wide posture aggregator sitting in front of many agents) queries
// before granting access.
//
// This mirrors the "device posture check API" box in the architecture
// diagram. In production you would (a) run this as a signed, auto-updating
// background service, (b) have it push reports to a central posture
// service over mTLS rather than serving a plaintext local API, and (c)
// sign each report with the device's own SVID so the proxy can verify
// the report wasn't tampered with in transit. This implementation keeps
// it simple — local-only HTTP on 127.0.0.1 — which is enough to
// demonstrate the end-to-end policy flow.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"zero-trust-iap/internal/posture"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:9443", "address for the posture agent's local HTTP API")
	deviceID := flag.String("device-id", "", "stable device identifier (defaults to hostname)")
	interval := flag.Duration("interval", 60*time.Second, "how often to refresh the local posture report")
	flag.Parse()

	id := *deviceID
	if id == "" {
		h, err := os.Hostname()
		if err != nil {
			h = "unknown-device"
		}
		id = h
	}

	checker := posture.NewLocalChecker(id)

	var (
		mu     sync.RWMutex
		latest posture.Report
	)

	refresh := func() {
		r, err := checker.Check(context.Background())
		if err != nil {
			log.Printf("posture: check failed: %v", err)
			return
		}
		mu.Lock()
		latest = r
		mu.Unlock()
	}
	refresh()

	go func() {
		ticker := time.NewTicker(*interval)
		defer ticker.Stop()
		for range ticker.C {
			refresh()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/posture/", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(latest)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	log.Printf("posture agent for device %q listening on %s (refresh every %s)", id, *listenAddr, *interval)
	if err := http.ListenAndServe(*listenAddr, mux); err != nil {
		log.Fatalf("posture agent: %v", err)
	}
}
