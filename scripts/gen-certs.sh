#!/usr/bin/env bash
# Generate a demo PKI for the X.509 login option:
#   - ca.crt/key         a throwaway CA
#   - server.crt/key     Keycloak's HTTPS server cert (SAN: localhost, kc-acr-poc)
#   - alice.crt/key      a client cert for alice, with SubjectAltName email
#   - alice.p12          PKCS#12 bundle for importing into Postman / a browser
#
# DEMO ONLY — self-signed, no passphrase on keys. Never use these for anything real.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p certs
cd certs

P12_PASS="${P12_PASS:-changeit}"
DAYS=3650

if [ -f server.crt ] && [ -f alice.crt ] && [ "${FORCE:-}" != "1" ]; then
  echo "certs already exist (set FORCE=1 to regenerate)"; exit 0
fi

# CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days "$DAYS" \
  -subj "/CN=poc-demo-ca" >/dev/null 2>&1

# Server cert (Keycloak HTTPS)
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost" >/dev/null 2>&1
printf "subjectAltName=DNS:localhost,DNS:kc-acr-poc,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -extfile server.ext >/dev/null 2>&1

# Client cert for alice (SubjectAltName email -> mapped to the user's email)
openssl req -newkey rsa:2048 -nodes -keyout alice.key -out alice.csr \
  -subj "/CN=Alice Example/O=poc" >/dev/null 2>&1
printf "subjectAltName=email:alice@example.com\nextendedKeyUsage=clientAuth\n" > alice.ext
openssl x509 -req -in alice.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out alice.crt -days "$DAYS" -extfile alice.ext >/dev/null 2>&1

# PKCS#12 for Postman / browser import
openssl pkcs12 -export -inkey alice.key -in alice.crt -certfile ca.crt \
  -out alice.p12 -passout "pass:${P12_PASS}" >/dev/null 2>&1

rm -f server.csr server.ext alice.csr alice.ext
echo "Generated certs/ (CA, server, alice client cert, alice.p12 pass='${P12_PASS}')"
