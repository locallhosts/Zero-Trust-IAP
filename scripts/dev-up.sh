#!/usr/bin/env bash
# Fast local demo path: builds all binaries, generates demo certs if
# missing, and starts the posture agent + protected demo app + IAP proxy.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Building binaries"
mkdir -p bin logs
go build -o bin/proxy ./cmd/proxy
go build -o bin/posture-agent ./cmd/posture-agent
go build -o bin/mint-jwt ./cmd/mint-jwt
go build -o bin/demo-app ./cmd/demo-app

if [ ! -f certs/out/ca.crt ]; then
  echo "==> Generating demo certificates (trust domain: iap.local)"
  ./certs/generate-certs.sh iap.local certs/out
else
  echo "==> Reusing existing certs/out/ (delete the directory to regenerate)"
fi

if [ ! -f admin-ui/dist/index.html ]; then
  echo "==> Building admin UI"
  (cd admin-ui && npm install --no-audit --no-fund && npm run build)
else
  echo "==> Reusing existing admin-ui/dist/ (run 'npm run build' in admin-ui/ to rebuild)"
fi

echo "==> Starting protected demo app on 127.0.0.1:8081"
./bin/demo-app > logs/demo-app.out 2>&1 &
DEMO_APP_PID=$!

echo "==> Starting posture agent on 127.0.0.1:9443"
./bin/posture-agent -listen 127.0.0.1:9443 -device-id alice > logs/posture.out 2>&1 &
POSTURE_PID=$!

echo "==> Starting IAP proxy (data plane :8443, admin :8444)"
export IAP_ADMIN_TOKEN="${IAP_ADMIN_TOKEN:-devtoken}"
export IAP_JWT_SECRET="${IAP_JWT_SECRET:-dev-only-change-me-set-via-IAP_JWT_SECRET-env-var}"
./bin/proxy -config configs/proxy.example.json > logs/proxy.out 2>&1 &
PROXY_PID=$!

trap 'echo ""; echo "==> Shutting down"; kill "$DEMO_APP_PID" "$POSTURE_PID" "$PROXY_PID" 2>/dev/null || true' EXIT INT TERM

sleep 1
echo ""
echo "Ready. Try:"
echo "  curl -k --cacert certs/out/ca.crt --cert certs/out/alice.crt --key certs/out/alice.key https://localhost:8443/dashboard"
echo "  open http://127.0.0.1:8444/  (admin UI — token: ${IAP_ADMIN_TOKEN})"
echo ""
echo "Press Ctrl+C to stop."
wait
