#!/usr/bin/env bash
# Generates a local CA plus server and client certificates for developing
# and demoing the IAP without a real SPIRE deployment.
#
# The client certs get a spiffe://<trust-domain>/... URI SAN, which is
# exactly what internal/identity/spiffe.go looks for — so these
# openssl-minted certs are structurally identical to what a real SPIRE
# Agent would hand a workload via the Workload API. Swapping this script
# out for real SPIRE is a drop-in replacement; nothing in the proxy code
# needs to change.
#
# Usage: ./generate-certs.sh [trust-domain] [output-dir]
set -euo pipefail

TRUST_DOMAIN="${1:-iap.local}"
OUT_DIR="${2:-$(dirname "$0")/out}"
DAYS_CA=3650
DAYS_LEAF=30   # deliberately short — real SVIDs are minutes/hours; this is a demo default

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

echo "==> Generating root CA (trust domain: ${TRUST_DOMAIN})"
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS_CA" \
  -subj "/O=Zero-Trust IAP Demo/CN=IAP Root CA" \
  -out ca.crt

echo "==> Generating IAP proxy server certificate"
openssl genrsa -out proxy.key 2048 2>/dev/null
openssl req -new -key proxy.key -subj "/O=Zero-Trust IAP Demo/CN=iap-proxy" -out proxy.csr
cat > proxy.ext <<EOF
subjectAltName = DNS:localhost, DNS:iap-proxy, IP:127.0.0.1, URI:spiffe://${TRUST_DOMAIN}/iap-proxy
extendedKeyUsage = serverAuth
EOF
openssl x509 -req -in proxy.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out proxy.crt -days "$DAYS_LEAF" -sha256 -extfile proxy.ext
rm -f proxy.csr proxy.ext

# Generates one client SVID: generate_client.sh alice engineering
generate_client() {
  local name="$1" team="$2"
  echo "==> Generating client SVID for ${name} (team: ${team})"
  openssl genrsa -out "${name}.key" 2048 2>/dev/null
  openssl req -new -key "${name}.key" -subj "/O=Zero-Trust IAP Demo/CN=${name}" -out "${name}.csr"
  cat > "${name}.ext" <<EOF
subjectAltName = URI:spiffe://${TRUST_DOMAIN}/team/${team}/${name}
extendedKeyUsage = clientAuth
EOF
  openssl x509 -req -in "${name}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "${name}.crt" -days "$DAYS_LEAF" -sha256 -extfile "${name}.ext"
  rm -f "${name}.csr" "${name}.ext"
}

generate_client "alice" "engineering"
generate_client "bob" "contractors"

echo ""
echo "==> Done. Certificates written to ${OUT_DIR}/"
echo "    CA:              ca.crt / ca.key"
echo "    Proxy server:    proxy.crt / proxy.key"
echo "    Client (engineer, spiffe://${TRUST_DOMAIN}/team/engineering/alice): alice.crt / alice.key"
echo "    Client (contractor, spiffe://${TRUST_DOMAIN}/team/contractors/bob): bob.crt / bob.key"
echo ""
echo "Test the proxy once it's running with, e.g.:"
echo "  curl --cacert ${OUT_DIR}/ca.crt --cert ${OUT_DIR}/alice.crt --key ${OUT_DIR}/alice.key https://localhost:8443/"
