#!/usr/bin/env python3
"""
End-to-end smoke test of the step-up flow WITHOUT a browser: drives the
authorization-code + PKCE flow over HTTP, logs in with username/password, and
prints the acr/amr claims from the returned tokens.

  python3 scripts/test_flow.py            # default path (no acr_values)
  python3 scripts/test_flow.py low        # acr_values=http://example.com/loa/low

Passkey ceremonies need a real/virtual authenticator, so this script only
exercises the password paths. For the default path with a passwordless user it
shows that Keycloak lands on the "create a passkey" registration step.
"""
import base64
import hashlib
import html
import http.cookiejar
import json
import os
import re
import sys
import urllib.parse
import urllib.request

KC = os.environ.get("KC_URL", "http://localhost:8080").rstrip("/")
REALM = "poc"
CLIENT = os.environ.get("CLIENT", "postman")
REDIRECT = "https://oauth.pstmn.io/v1/callback"
USER, PW = "alice", "alice"
ACR_LOW = "http://example.com/loa/low"
ACR_HIGH = "http://example.com/loa/high"


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Stop(Exception):
    def __init__(self, location):
        self.location = location


class CaptureRedirect(urllib.request.HTTPRedirectHandler):
    """Stop before following a redirect to the external callback host."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith(REDIRECT):
            raise Stop(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def main(mode):
    verifier = b64url(os.urandom(40))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())

    params = {
        "client_id": CLIENT, "response_type": "code", "scope": "openid",
        "redirect_uri": REDIRECT, "state": "xyz",
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if mode == "low":
        params["acr_values"] = ACR_LOW
    if mode == "high":
        params["acr_values"] = ACR_HIGH
    # Raw override, e.g. ACR="http://example.com/loa/low http://example.com/loa/high"
    # to test a space-separated acr_values list (highest wins).
    if os.environ.get("ACR"):
        params["acr_values"] = os.environ["ACR"]
    if mode == "enroll":
        # App-initiated action: offer passkey creation, skip if the user has one.
        params["kc_action"] = "webauthn-register-passwordless"
        params["skip_if_exists"] = "true"

    # Keycloak marks session cookies Secure; browsers treat localhost as a
    # secure context and send them over http, but Python's jar won't unless we
    # relax the policy. (Test-only; never do this against a real endpoint.)
    class LocalhostPolicy(http.cookiejar.DefaultCookiePolicy):
        def return_ok_secure(self, cookie, request):
            return True

    cj = http.cookiejar.CookieJar(policy=LocalhostPolicy())
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj), CaptureRedirect())

    auth_url = f"{KC}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(params)
    print(f"[1] GET authorize (mode={mode or 'default'})")
    page = opener.open(auth_url).read().decode()

    # Drive whatever credential forms appear (username, then password, ...),
    # step by step, until we get an authorization code or hit a page that needs
    # a real authenticator (passkey login / passkey registration).
    code = None
    try:
        for step in range(6):
            m = re.search(r'action="([^"]+)"', page)
            names = re.findall(r'<input[^>]*name="([^"]+)"', page)
            title = (re.search(r"<title>(.*?)</title>", page) or ["", "?"])[1]
            fields = {}
            if "username" in names:
                fields["username"] = USER
            if "password" in names:
                fields["password"] = PW
            if not m or not fields:
                # No submittable credential form: a passkey/register/webauthn page.
                hints = [k for k in ("passkey", "webauthn", "security key", "register")
                         if k in page.lower()]
                print(f"    Landed on '{title}' — inputs={names or 'none'} hints={hints}")
                print("    (Needs a real/virtual authenticator to continue.)")
                return
            fields["credentialId"] = ""
            print(f"[2.{step}] submit {sorted(fields)} on '{title}'")
            try:
                page = opener.open(html.unescape(m.group(1)),
                                   data=urllib.parse.urlencode(fields).encode()).read().decode()
            except urllib.error.HTTPError as he:
                page = he.read().decode()
                t = (re.search(r"<title>(.*?)</title>", page) or ["", "?"])[1]
                print(f"    HTTP {he.code} -> '{t}'")
                return
        print("    Gave up after too many steps.")
        return
    except Stop as s:
        code = urllib.parse.parse_qs(urllib.parse.urlparse(s.location).query)["code"][0]
        print(f"[3] Got authorization code: {code[:12]}...")

    tok = opener.open(
        f"{KC}/realms/{REALM}/protocol/openid-connect/token",
        data=urllib.parse.urlencode({
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "client_id": CLIENT,
            "code_verifier": verifier,
        }).encode()).read()
    tokens = json.loads(tok)

    def claims(jwt):
        p = jwt.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))

    idc = claims(tokens["id_token"])
    print(f"[4] id_token: acr={idc.get('acr')!r}  amr={idc.get('amr')!r}")
    ac = claims(tokens["access_token"])
    print(f"    access_token: acr={ac.get('acr')!r}  amr={ac.get('amr')!r}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "")
