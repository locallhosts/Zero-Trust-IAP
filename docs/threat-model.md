# Threat Model Notes

Short and specific, covering what this design defends against, what it
explicitly doesn't, and the trust assumptions baked into each component.

## Assets being protected

- The internal application(s) behind the proxy.
- The identity material itself (private keys, Vault tokens, JWT secrets).
- The audit trail (access logs) — its integrity matters for incident response.

## Trust boundaries

```
[Untrusted: public internet / user devices]
        │  mTLS or JWT, TLS-terminated at the proxy
        v
[Semi-trusted: the IAP proxy process]
        │  policy-gated forwarding, trusted identity headers injected
        v
[Trusted: internal app network]
```

The proxy is the trust boundary. Everything before it (the client device,
the network path to the proxy) is untrusted. Everything after it (the
backend app, reading `X-Forwarded-Identity`) trusts the proxy completely —
which is exactly why `internal/proxy/proxy.go` strips any
client-supplied `X-Forwarded-Identity`/`X-Forwarded-Policy` headers
*before* authentication runs, so a client can never inject a header that
survives to spoof the backend's trust in the proxy.

## What's defended against

- **Network-location spoofing** (the VPN failure mode): identity is
  cryptographic (mTLS/SVID or signed JWT), not IP-based.
- **Header injection / identity spoofing**: client-supplied
  `X-Forwarded-*` headers are stripped before the trusted ones are set.
  See the regression test note in `README.md`'s Testing section.
- **JWT `alg` confusion**: the verifier is constructed for one specific
  algorithm and rejects any token whose header claims a different one —
  there's no code path that accepts `alg: none` or lets the token pick
  its own verification algorithm.
- **Stale/replayed short-lived certs**: `Verifier.MaxCertAge` rejects an
  SVID whose `NotBefore` is older than the configured max age, even if
  it's technically still before `NotAfter` — this catches a leaked cert
  being replayed well after the window it was meant to be used in.
- **Posture-check unavailability being treated as "pass"**: a missing or
  stale posture report fails closed (`postureOK = false`), not open. An
  attacker taking down the posture agent doesn't grant access — it *blocks*
  policies that require posture checks.
- **Deny-by-default**: no matching policy is an explicit deny, not a
  fallthrough allow. See `policy.Engine.Evaluate`'s final return.
- **Admin-plane exposure**: the admin API/UI is a *separate listener*
  from the data plane specifically so it can be firewalled independently;
  mixing control-plane and data-plane traffic on one listener is a common
  real-world IAP/VPN-concentrator compromise pattern.

## What's explicitly out of scope / not defended against

Being direct about this rather than implying full coverage:

- **A fully compromised proxy process itself.** If an attacker gets code
  execution on the proxy host, they can see plaintext traffic post-TLS-
  termination and mint their own decisions. Standard host-hardening
  (least-privilege service account, no unnecessary local access) applies
  and isn't reimplemented here.
- **Posture agent tampering on a compromised device.** The demo agent
  self-reports over local HTTP with no code-integrity guarantee — a
  sufficiently privileged attacker on the device could patch the agent's
  binary to always report "healthy." Production mitigation (signed
  reports, attestation) is noted as a follow-up in the main README.
- **DDoS / volumetric attacks** against the data-plane listener — this is
  an application-layer access-control proxy, not a network-layer DDoS
  mitigation product.
- **Compromise of the Vault or SPIRE server itself.** Both are treated as
  trusted infrastructure; hardening *them* (unseal process, HA storage,
  node attestation strength) is a different, well-documented problem
  (see `deploy/README.md` for what's simplified in the reference setup).

## Key management summary

| Key/secret | Where it lives | Rotation |
|---|---|---|
| Proxy's TLS serving cert | Vault PKI (or static file in local-dev mode) | Auto-rotated by `internal/proxy/rotation.go` when <20% of TTL remains |
| Client SVIDs | Issued by SPIRE (or openssl script in local-dev mode) | Short TTL (~1h in prod config, 30d in the demo script for convenience) |
| JWT HMAC secret | `IAP_JWT_SECRET` env var, never in the config file on disk | Manual rotation; verifier supports accepting old+new during a rotation window by running two verifiers (not yet wired up — noted as a follow-up) |
| Admin API token | `IAP_ADMIN_TOKEN` env var | Manual rotation |
| Vault token | `VAULT_TOKEN` env var | Should be a short-lived AppRole token in production, not a static root/dev token |
