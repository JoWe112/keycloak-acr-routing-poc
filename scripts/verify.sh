#!/usr/bin/env bash
# Smoke-test both clients across every ACR path, including X.509 (the default).
# Passkey ceremonies require a browser + virtual authenticator, so the passkey
# path is shown reaching its page rather than completing headlessly.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "===== EXACT client (postman) ====="
echo "--- acr=loa/low  -> expect password only, acr=low, amr=[pwd]"
CLIENT=postman python3 scripts/test_flow.py low
echo "--- acr=loa/high -> identity-first: username -> (no passkey) password verify -> create-a-passkey page"
CLIENT=postman python3 scripts/test_flow.py high
echo "--- acr_values='loa/low loa/high' (space-separated) -> HIGHEST wins = passkey (min would give password)"
CLIENT=postman ACR="http://example.com/loa/low http://example.com/loa/high" python3 scripts/test_flow.py
echo "--- default (no acr_values) is now X.509 — see the X.509 section below"
echo
echo "===== CUMULATIVE client (postman-cumulative) ====="
echo "--- acr=loa/low  -> expect password only, acr=low, amr=[pwd]"
CLIENT=postman-cumulative python3 scripts/test_flow.py low
echo "--- default      -> expect password THEN passkey step-up (needs a passkey)"
CLIENT=postman-cumulative python3 scripts/test_flow.py

echo
echo "===== X.509 client-certificate login — the DEFAULT method, loa/x509 (mutual TLS, :8443) ====="
echo "--- default (no acr_values) + cert -> expect x509 login as alice, acr=loa/x509, amr=[x509]"
python3 scripts/test_x509.py --default
echo "--- explicit acr=loa/x509 + cert   -> same"
python3 scripts/test_x509.py
echo "--- no client cert                 -> expect the login to be refused (X.509 required)"
python3 scripts/test_x509.py --no-cert
