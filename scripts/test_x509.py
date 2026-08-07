#!/usr/bin/env python3
"""
Smoke-test the X.509 client-certificate login option over mutual TLS (:8443).

  python3 scripts/test_x509.py           # low path, presenting alice's client cert
  python3 scripts/test_x509.py --no-cert # same, WITHOUT a cert -> falls back to password form

Presents certs/alice.crt (SubjectAltName email alice@example.com), which Keycloak
maps to the alice account, and prints the resulting acr/amr (expect amr=['x509']).
Requires `./scripts/gen-certs.sh` and Keycloak running with HTTPS (docker compose up).
"""
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("KC_HTTPS", "https://localhost:8443")
REALM, CLIENT = "poc", "postman"
REDIRECT = "https://oauth.pstmn.io/v1/callback"
ACR_X509 = "http://example.com/loa/x509"   # X.509 is its own (highest) LoA level
CERTS = os.path.join(os.path.dirname(__file__), "..", "certs")


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class _Stop(Exception):
    def __init__(self, url):
        self.url = url


class _Capture(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith(REDIRECT):
            raise _Stop(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def main(with_cert, use_default_acr):
    ctx = ssl.create_default_context(cafile=os.path.join(CERTS, "ca.crt"))
    if with_cert:
        ctx.load_cert_chain(os.path.join(CERTS, "alice.crt"), os.path.join(CERTS, "alice.key"))
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        _Capture())

    verifier = b64(os.urandom(40))
    challenge = b64(hashlib.sha256(verifier.encode()).digest())
    params = {"client_id": CLIENT, "response_type": "code", "scope": "openid",
              "redirect_uri": REDIRECT, "state": "x",
              "code_challenge": challenge, "code_challenge_method": "S256"}
    if not use_default_acr:
        params["acr_values"] = ACR_X509   # otherwise rely on the client's default.acr.values

    url = f"{BASE}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(params)

    print(f"[1] GET authorize (client cert: {'yes' if with_cert else 'no'}, "
          f"acr: {'default' if use_default_acr else 'loa/x509'})")
    try:
        body = opener.open(url).read().decode()
        title = (re.search(r"<title>(.*?)</title>", body) or ["", "?"])[1]
        print(f"    Landed on '{title}' — no token.")
        if not with_cert:
            print("    -> X.509 is required at this LoA, so with no certificate the login is refused.")
        return
    except urllib.error.HTTPError as e:
        # X.509 is REQUIRED at loa/x509; with no cert the authenticator fails (4xx).
        print(f"    HTTP {e.code}: login refused (no client certificate; X.509 is required here).")
        return
    except _Stop as s:
        code = urllib.parse.parse_qs(urllib.parse.urlparse(s.url).query)["code"][0]

    tok = json.loads(opener.open(
        f"{BASE}/realms/{REALM}/protocol/openid-connect/token",
        data=urllib.parse.urlencode({
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "client_id": CLIENT, "code_verifier": verifier,
        }).encode()).read())

    def claims(jwt):
        p = jwt.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))

    idc = claims(tok["id_token"])
    print(f"[2] X.509 login -> user={idc.get('preferred_username')!r}  "
          f"acr={idc.get('acr')!r}  amr={idc.get('amr')!r}")


if __name__ == "__main__":
    main(with_cert="--no-cert" not in sys.argv,
         use_default_acr="--default" in sys.argv)
