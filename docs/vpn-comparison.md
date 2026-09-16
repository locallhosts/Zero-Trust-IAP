# Before/After: Traditional VPN vs. This Identity-Aware Proxy

This is the comparison the project brief asked for, written as a genuine
technical analysis rather than a marketing pitch — including where a VPN
is still the right tool.

## The core architectural difference

A traditional remote-access VPN (IPsec or OpenVPN-style) does authorization
**once, at connection time**, and then trusts network location for
everything after that:

```
User authenticates --> VPN assigns an internal IP --> that IP can reach
                                                        anything on the
                                                        internal network
                                                        the VPN routes to
```

This IAP does authorization **on every single request**, using
cryptographic identity instead of network location:

```
Every request --> mTLS/SPIFFE identity verified --> device posture
               --> checked --> policy evaluated for THIS specific
               --> path/method --> forward only if all pass, log
               --> the decision either way
```

## Side-by-side

| | Traditional VPN | This IAP |
|---|---|---|
| **What's trusted** | The network (your IP is "inside") | The request (identity + device posture, every time) |
| **Granularity** | Usually all-or-nothing to a subnet, or coarse VLAN segmentation | Per-path, per-method policy (`contractors-read-only-dashboard` can GET `/dashboard` and nothing else) |
| **Identity** | Often a shared PSK or a single user/password at connect time | Short-lived cryptographic SVID per workload/user, re-verified per request |
| **Device health** | Not checked at all, or checked only at connect time via a NAC agent that's easy to bypass | Checked per-request; a stale/missing posture report **fails closed** |
| **Lateral movement if a device is compromised** | High — attacker inherits whatever network access the VPN grants | Limited to whatever policies explicitly allow that specific identity, and posture checks can catch a compromised device (EDR down, disk unencrypted) |
| **Audit trail** | Connection-level logs (who connected, when) — rarely which internal resource was touched | Every single request logged with subject, path, decision, reason, and matched policy ID |
| **Credential lifetime** | Often long-lived (PSKs rotated rarely; user creds valid for weeks) | SVIDs default to ~1h TTL, auto-rotated from Vault before expiry |
| **Revocation** | Usually means rotating a shared secret for everyone, or waiting for a session to expire | Revoke one identity's cert; policy changes take effect on the next request, no reconnection needed |
| **What happens if the client is stolen but still has valid VPN creds** | Full network access until someone notices and revokes | Requires the device's actual private key (not exportable, generated on-device) *and* a passing posture check; contractor-tier identities are scoped to a handful of paths regardless |

## A concrete walkthrough

Take the actual demo policy set in `configs/policy.example.json`:

- **A VPN world**: once "bob" (a contractor) is on the VPN, he's on the
  same internal network as the finance dashboard, the admin panel, and
  the engineering deploy tooling — segmented only by whatever VLAN/subnet
  rules someone remembered to configure, if any.
- **This IAP's world**: `bob`'s SVID is `spiffe://iap.local/team/contractors/bob`.
  The only policy that matches his subject pattern is
  `contractors-read-only-dashboard`, which only allows `GET /dashboard`
  with disk encryption on. He can present a perfectly valid, unexpired
  mTLS certificate and still get a 403 the instant he tries
  `GET /admin-panel` — there's no policy that authorizes it, and
  "deny by default" means that's a hard stop, logged with the reason
  `no policy matched subject/path/method (deny by default)`.

## Where a VPN (or VPN + this) still makes sense

Being accurate here rather than one-sided:

- **Network-layer protocols that aren't HTTP**: this IAP proxies HTTP(S)
  traffic. A VPN (or a SPIFFE-aware service mesh) is still the right tool
  for arbitrary TCP/UDP — database connections, SSH, RDP — unless those
  are also fronted by protocol-aware proxies.
- **Bootstrapping problem**: something has to get the device its first
  SVID or JWT. In practice that's usually still an SSO/IdP login, which a
  VPN's initial auth step and this IAP's JWT fallback path both ultimately
  depend on.
- **Full network segmentation is sometimes actually what you want** — e.g.
  a factory floor's OT network genuinely should be reachable only from a
  jump host, and a coarse-grained VPN boundary is simpler to reason about
  there than a fine-grained policy set would be.

The honest framing: this project replaces VPN-style implicit network trust
with per-request identity and posture checks for the specific case of
"employees/contractors reaching an internal HTTP application" — which is
most of what a typical corporate VPN is actually used for day to day, but
not the whole of what a VPN does.
