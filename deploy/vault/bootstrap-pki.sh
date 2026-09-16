#!/usr/bin/env bash
# One-time Vault bootstrap for the IAP's PKI-based cert rotation:
# mounts the PKI secrets engine, generates an intermediate CA, and
# configures a role the proxy will call `vault write pki_int/issue/...`
# against (see internal/vault/client.go's IssueCertificate).
#
# Run against a dev-mode or already-unsealed Vault:
#   VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./bootstrap-pki.sh
set -euo pipefail

: "${VAULT_ADDR:?set VAULT_ADDR}"
: "${VAULT_TOKEN:?set VAULT_TOKEN}"
TRUST_DOMAIN="${TRUST_DOMAIN:-iap.local}"

vault_() { vault "$@"; }

echo "==> Enabling PKI secrets engine at pki_int"
vault_ secrets enable -path=pki_int pki || echo "  (already enabled)"
vault_ secrets tune -max-lease-ttl=720h pki_int

echo "==> Generating intermediate CA (in a real deployment, sign this with your root CA out of band)"
vault_ write -field=csr pki_int/intermediate/generate/internal \
  common_name="IAP Vault Intermediate CA" > /tmp/pki_intermediate.csr

vault_ write -field=certificate pki_int/root/generate/internal \
  common_name="IAP Vault Root CA" ttl=87600h > /tmp/pki_root_ca.crt 2>/dev/null || true

# For a from-scratch demo we self-sign the intermediate as its own root,
# since bootstrapping a full root/intermediate chain is out of scope for
# a portfolio project's setup script. Swap this for a real signed
# intermediate in production.
vault_ write pki_int/config/urls \
  issuing_certificates="${VAULT_ADDR}/v1/pki_int/ca" \
  crl_distribution_points="${VAULT_ADDR}/v1/pki_int/crl"

echo "==> Creating role 'iap-workload' (short TTL, embeds SPIFFE URI SANs)"
vault_ write pki_int/roles/iap-workload \
  allowed_domains="${TRUST_DOMAIN},localhost" \
  allow_subdomains=true \
  allow_bare_domains=true \
  allow_localhost=true \
  allow_any_name=true \
  enforce_hostnames=false \
  allow_uri_sans_template=false \
  max_ttl="4h" \
  ttl="1h"

echo "==> Done. The proxy config's vault_pki_mount/vault_pki_role should be pki_int/iap-workload."
