package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zero-Trust IAP — Protected Dashboard</title>
<style>
:root{color-scheme:light;--bg:#f4f7fa;--panel:#fff;--text:#17202a;--muted:#667585;--border:#d9e1e8;--accent:#2563eb;--soft:#eaf1ff}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#0f141a;--panel:#171e26;--text:#e6edf3;--muted:#91a0af;--border:#2b3642;--accent:#6ea8fe;--soft:#18253a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{max-width:920px;margin:0 auto;padding:48px 24px}.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:var(--accent);font-weight:700}.hero{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:32px}.hero h1{margin:8px 0;font-size:32px}.hero p{color:var(--muted);max-width:720px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px;margin-top:18px}.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:20px}.card h2{font-size:17px;margin:0 0 8px}.badge{display:inline-block;background:var(--soft);color:var(--accent);border-radius:999px;padding:3px 9px;font-size:12px;font-weight:700}.steps{margin:8px 0 0;padding-left:20px}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;background:var(--soft);padding:2px 5px;border-radius:4px}.note{margin-top:18px;color:var(--muted);font-size:13px}
</style>
</head>
<body><main class="wrap">
<section class="hero"><span class="eyebrow">Protected application</span><h1>Zero-Trust IAP Demo Dashboard</h1><p>This placeholder application sits behind the Zero-Trust Identity-Aware Proxy. Authentication, device posture, policy evaluation and adaptive risk decisions happen at the IAP before an allowed request reaches this service.</p><span class="badge">Upstream: 127.0.0.1:8081</span></section>
<section class="grid">
<div class="card"><h2>What this demonstrates</h2><p>Per-request access control using mTLS/SPIFFE identity, device posture, policy rules and risk evaluation.</p></div>
<div class="card"><h2>How to use</h2><ol class="steps"><li>Start the local stack with <span class="mono">make dev-up</span>.</li><li>Present a valid client certificate to <span class="mono">:8443</span>.</li><li>Open <span class="mono">/dashboard</span>.</li><li>Inspect the resulting LIVE event in the Admin Console.</li></ol></div>
<div class="card"><h2>Admin Console</h2><p>Use <span class="mono">:8444</span> for policies, access logs, Security Lab simulations and certificate rotation status.</p></div>
</section>
<p class="note">This is a demo upstream placeholder. It intentionally does not make authorization decisions; the IAP remains the security boundary.</p>
</main></body></html>`

func main() {
	tmpl := template.Must(template.New("dashboard").Parse(page))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/dashboard" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, nil); err != nil {
			log.Printf("demo dashboard: %v", err)
		}
	})

	addr := "127.0.0.1:8081"
	fmt.Printf("demo dashboard listening on http://%s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
