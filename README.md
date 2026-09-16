# Zero-Trust Identity-Aware Proxy (IAP)

**A security-focused Identity-Aware Proxy built from scratch in Go that enforces Zero Trust access at the application layer — authenticating identity, validating device posture, evaluating policy, and authorizing every request before it reaches an internal service.**

This project explores what happens when you remove the assumption that **network location equals trust**.

Instead of treating a user as trusted simply because they are connected to a VPN or inside a corporate network, the proxy evaluates:

- **Who** is making the request
- **What cryptographic identity** they present
- **What device** they are using
- **Whether the device satisfies security posture requirements**
- **What resource and HTTP method** they are requesting
- **Which policy** permits or denies the request
- **Whether credentials and certificates are still valid**

```text
                         ZERO-TRUST REQUEST FLOW

 [User / Workload]
        │
        │  mTLS / JWT
        ▼
 ┌──────────────────────────────┐
 │     Go Identity-Aware Proxy  │
 │                              │
 │  1. Authenticate identity    │
 │  2. Validate credentials     │
 │  3. Check device posture     │
 │  4. Evaluate security policy │
 │  5. Authorize request        │
 └──────────────┬───────────────┘
                │
        ┌───────┴────────┐
        │                │
        ▼                ▼
 [SPIFFE/SPIRE]     [Posture Agent]
  Workload ID       Device Security
        │                │
        └───────┬────────┘
                │
                ▼
        [HashiCorp Vault]
        Secrets / PKI / Certs
                │
                ▼
        ┌─────────────────┐
        │ Policy Decision │
        │                 │
        │ ALLOW / DENY    │
        └────────┬────────┘
                 │
        ┌────────┴─────────┐
        │                  │
      ALLOW               DENY
        │                  │
        ▼                  ▼
 [Internal Service]   [Access Blocked]

                 │
                 ▼
        [Audit / Access Logs]
                 │
                 ▼
          [Admin Console]
```

## Why this exists

Traditional network-based access models often establish trust from where a request originates: authenticate to a VPN, receive an internal network identity, and rely on downstream services to trust that network boundary.

This project moves the trust decision to the application access layer and addresses two core problems:

1. **Network location is not identity.** A compromised device connected to an internal network can otherwise look similar to a legitimate device. This proxy requires cryptographic workload identity instead of relying on IP-based trust.
2. **Authentication is not the same as authorization.** A valid login does not automatically mean a device should access sensitive resources. The proxy evaluates device posture and policy before forwarding a request, using fail-closed behavior when required security information is unavailable or stale.

The result is a small, auditable reference implementation demonstrating identity-aware access control, certificate-based authentication, device posture, policy enforcement, secrets management, certificate rotation, and security-focused audit logging.

See [`docs/vpn-comparison.md`](docs/vpn-comparison.md) for a detailed before/after comparison.

## What's actually implemented

Everything in the architecture diagram above is real, working code — not stubs. Specifically:

| Component | Where | Notes |
|---|---|---|
| Go reverse proxy, mTLS termination | `internal/proxy/`, `cmd/proxy/` | stdlib `net/http` + `crypto/tls` only |
| SPIFFE-style identity verification | `internal/identity/spiffe.go` | parses/validates `spiffe://` URI SANs, trust domain + SVID freshness checks |
| JWT fallback auth | `internal/identity/jwt.go` | hand-rolled HS256/RS256 (no `alg: none`, no dependency) |
| Policy engine | `internal/policy/` | subject/path/method/posture rules, deny-by-default, hot-reloadable via admin API |
| Vault integration | `internal/vault/`, `internal/proxy/rotation.go` | KV secrets + PKI cert issuance, automatic rotation before expiry, zero-downtime hot-swap |
| Device posture agent | `cmd/posture-agent/`, `internal/posture/` | disk-encryption, EDR-presence, patch-level checks; Linux/macOS/Windows via build tags |
| Admin UI | `admin-ui/` | vanilla TypeScript, compiled with `tsc`, no framework or bundler |
| Access logging | `internal/logging/` | structured JSON, append-only file + queryable ring buffer |

**One honest caveat:** the SPIFFE/SPIRE piece implements the *verification* side of the SPIFFE spec (parsing and validating X.509-SVIDs) against certs that are structurally identical to what a real SPIRE Agent issues. For the fast local demo, those certs come from `certs/generate-certs.sh` (`openssl`) rather than a running SPIRE server, so you can exercise the whole access-control flow in under a minute without standing up infrastructure. `deploy/` has a full Docker Compose reference setup with an actual SPIRE server + agent + Vault + Envoy for when you want the real thing — see `deploy/README.md`. Swapping the cert *source* from openssl to a live SPIRE Workload API is a small, clearly-scoped change (see the comment in `deploy/spire/agent.conf`); nothing in the verification or policy logic needs to change either way.

## Why zero external Go dependencies

Every package — SPIFFE parsing, JWT verification, the Vault client — is built on the Go standard library alone (`crypto/x509`, `crypto/tls`, `net/http`, `crypto/hmac`/`crypto/rsa`). This was a deliberate constraint, not an accident:

- It's a stronger demonstration of understanding than importing `go-spiffe` or the Vault SDK and calling their methods — writing your own JWT verifier means actually knowing why `alg: none` is a vulnerability, not just knowing which library option disables it.
- The whole module builds offline, with no `go.sum` supply-chain surface at all. `go build ./...` works with zero network access.
- It cross-compiles cleanly for Linux, macOS, and Windows (verified — see Testing below), which matters for the posture agent shipping to heterogeneous fleets.

## Quick start (local demo, ~1 minute)

Requires Go 1.22+, OpenSSL, and Node.js (for the admin UI build only).

```bash
git clone <this-repo>
cd zero-trust-iap
./scripts/dev-up.sh
```

This builds the proxy, posture agent, and admin UI; generates a local CA and demo client certs (`alice` on the engineering team, `bob` on contractors) with `spiffe://iap.local/...` identities baked into the URI SAN; and starts everything against `configs/policy.example.json`.

Then, in another terminal:

```bash
# alice (engineering) — denied, because the demo posture agent reports
# disk_encrypted=false and the engineers policy requires it:
curl -k --cacert certs/out/ca.crt --cert certs/out/alice.crt --key certs/out/alice.key \
  https://localhost:8443/

# check the admin UI to see exactly why, with the policy ID and reason:
open http://127.0.0.1:8444/    # token: devtoken (or $IAP_ADMIN_TOKEN)
```

Watch `internal/policy/policy.go`'s decision reasons come through in real time in the admin UI's Access Logs tab — every allow and deny is logged with the specific policy that matched (or why none did).

## Repository layout

```text
cmd/
  proxy/            entrypoint: data-plane + admin-plane listeners
  posture-agent/    entrypoint: runs on the user's device
  mint-jwt/         dev tool: mints demo JWTs for the fallback auth path
internal/
  identity/         SPIFFE SVID verification + JWT verification
  policy/           the access-control decision engine
  vault/            minimal Vault REST client (KV + PKI)
  posture/          posture report types + OS-specific checks
  proxy/            the reverse proxy handler, TLS config, cert rotation
  logging/          structured access logging
  admin/            JSON REST API behind the admin UI
admin-ui/            TypeScript admin console (policies, logs, rotation)
certs/               openssl-based local cert generation
configs/             example proxy config + example policy set
deploy/              Docker Compose reference deployment (SPIRE/Vault/Envoy)
docs/                VPN comparison, threat model notes
scripts/dev-up.sh    one-command local demo
```

## Testing

```bash
go test ./...          # unit tests: policy engine, SPIFFE verification, JWT
go vet ./...
gofmt -l .              # should print nothing
GOOS=darwin  go build ./...   # cross-compile check
GOOS=windows go build ./...
```

Unit tests cover the security-critical decision points specifically: posture-based deny, trust-domain rejection, expired/stale SVID rejection, JWT signature/audience/expiry validation, and deny-by-default when no policy matches. The proxy's request path was also validated end-to-end manually against real mTLS handshakes (see commit history / dev notes) — including confirming that a client-supplied `X-Forwarded-Identity` header is stripped and can't spoof the trusted identity the backend receives.

## Milestones (as built)

| Week | Planned | Status |
|---|---|---|
| 1 | Basic Go reverse proxy, manual mTLS working end-to-end | done — `internal/proxy/proxy.go`, `BuildTLSConfig` |
| 2 | SPIRE integration for identity issuance/verification | verification done against SPIRE-shaped SVIDs; live SPIRE server wiring documented in `deploy/` |
| 3 | Vault integration for cert/secret management + rotation | done — `internal/vault/`, `internal/proxy/rotation.go`, zero-downtime hot-swap via `tls.Config.GetCertificate` |
| 4 | Device posture check agent + policy enforcement | done — `cmd/posture-agent/`, fail-closed posture checks in the policy engine |
| 5 | Admin UI, access logging, README with VPN comparison | done — `admin-ui/`, `internal/logging/`, `docs/vpn-comparison.md` |

## What I'd harden next

Being upfront about the gap between "portfolio demo" and "production," since that distinction is itself part of demonstrating security judgment:

- **Posture agent trust**: right now the proxy fetches posture reports over plain local HTTP. Production needs the agent to sign each report with its own device SVID so the proxy can verify it wasn't tampered with in transit (noted in `internal/posture/posture.go`).
- **SPIRE node attestation**: the reference deployment uses `join_token` attestation, which is fine for a demo and wrong for a real fleet — see the comment in `deploy/spire/agent.conf` for what to use instead (cloud IID, k8s PSAT, TPM).
- **Vault**: single-node, file-storage, no auto-unseal. A real deployment needs Vault's HA/Raft storage and auto-unseal via a cloud KMS.
- **Revocation**: `internal/vault/client.go` has `RevokeCertificate` wired up but nothing calls it yet on a posture-goes-bad event — that's the natural next integration point.
