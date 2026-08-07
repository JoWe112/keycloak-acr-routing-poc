#!/usr/bin/env bash
# One-command bring-up: build the provider (if missing), start Keycloak, wait
# until healthy. The realm is auto-imported from realm/poc-realm.json.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || cp .env.example .env
[ -f providers/keycloak-poc-providers.jar ] || ./scripts/build-provider.sh
[ -f certs/server.crt ] || ./scripts/gen-certs.sh   # demo PKI for the X.509 login option
docker compose up -d
echo "Waiting for Keycloak to become healthy..."
for _ in $(seq 1 40); do
  s=$(docker inspect --format='{{.State.Health.Status}}' kc-acr-poc 2>/dev/null || true)
  [ "$s" = "healthy" ] && { echo "Keycloak healthy: http://localhost:8080  (admin/admin)"; exit 0; }
  sleep 5
done
echo "Timed out waiting for Keycloak health" >&2
exit 1
