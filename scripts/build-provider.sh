#!/usr/bin/env bash
# Build the custom Keycloak SPI (Condition - ACR value exact) into providers/.
# Uses a Maven container so no local JDK/Maven is required.
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm \
  -v "$PWD/providers-src":/build \
  -v "$HOME/.m2":/root/.m2 \
  -w /build maven:3.9-eclipse-temurin-21 mvn -q -B -Dmaven.test.skip=true package
mkdir -p providers
cp providers-src/target/keycloak-poc-providers.jar providers/
echo "Built providers/keycloak-poc-providers.jar"
