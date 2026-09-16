# Reference Deployment (SPIRE + Vault + Envoy)

This directory is the "real infrastructure" version of the architecture
diagram — SPIRE issuing actual workload identities, Vault managing the
PKI, and Envoy fronting the internal app. It's deliberately kept separate
from the fast local-dev path (`scripts/dev-up.sh`), which uses plain
`openssl`-generated certs and no Vault/SPIRE at all so you can run and
demo the whole access-control flow in under a minute.

## Bring it up

```bash
docker compose -f deploy/docker-compose.yml up -d spire-server vault backend-app
```

### 1. Bootstrap SPIRE

```bash
# Register the IAP proxy itself as a SPIRE workload:
docker exec spire-server /opt/spire/bin/spire-server entry create \
  -parentID "spiffe://iap.local/spire/agent/join_token/<token>" \
  -spiffeID "spiffe://iap.local/iap-proxy" \
  -selector "unix:uid:0"
```

(Replace `<token>` with a join token minted via `spire-server token generate`
— see the [SPIRE quickstart](https://spiffe.io/docs/latest/try/getting-started-linux-macos-x/)
for the full node-registration flow, which is a few more steps than fits
here and is genuinely worth doing by hand once to understand what SPIRE is
actually doing.)

### 2. Bootstrap Vault's PKI engine

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root   # dev-mode root token; never do this in prod
./deploy/vault/bootstrap-pki.sh
```

### 3. Start the IAP proxy + Envoy

```bash
docker compose -f deploy/docker-compose.yml up -d iap-proxy envoy
```

### 4. Verify

```bash
curl -k --cacert certs/out/ca.crt --cert certs/out/alice.crt --key certs/out/alice.key \
  https://localhost:8443/
```

## What's real here vs. simplified

- **Real**: SPIRE server/agent config, Vault PKI mount + role structure,
  Envoy's routing/access-log setup, the Docker Compose topology.
- **Simplified for a portfolio project**: SPIRE's node attestation uses
  `join_token` (fine for a demo, not for a real fleet — see the comment in
  `spire/agent.conf`); Vault runs in a single-node file-storage config with
  no auto-unseal; there's no root/intermediate CA separation for Vault's
  PKI engine. Each simplification is called out in a comment at the point
  it's made, so it's clear what a production hardening pass would change.
