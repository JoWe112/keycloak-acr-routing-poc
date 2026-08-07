#!/usr/bin/env bash
# Run the provider integration test (JUnit + Testcontainers real Keycloak).
# Requires a local JDK 21 + Maven and a running Docker/Rancher/colima daemon.
# Auto-detects the Docker endpoint so Testcontainers works on non-standard sockets.
set -euo pipefail
cd "$(dirname "$0")/../providers-src"

endpoint=$(docker context inspect -f '{{.Endpoints.docker.Host}}' 2>/dev/null || true)
if [ -n "${endpoint:-}" ] && [ "$endpoint" != "unix:///var/run/docker.sock" ]; then
  export DOCKER_HOST="$endpoint"
  sock="${endpoint#unix://}"
  [ -S "$sock" ] && export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE="$sock"
fi
export TESTCONTAINERS_RYUK_DISABLED="${TESTCONTAINERS_RYUK_DISABLED:-true}"

exec mvn -B verify "$@"
