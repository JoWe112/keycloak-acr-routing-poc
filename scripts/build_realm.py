#!/usr/bin/env python3
"""
Build the `poc` realm for the Keycloak passkey/password step-up POC.

Source of truth for the realm. Talks to the Keycloak Admin REST API using only
the Python standard library. Deletes and recreates the `poc` realm each run, so
the result is deterministic.

Prereqs: `docker compose up -d` (Keycloak healthy on http://localhost:8080) with
the custom provider JAR mounted (see providers/ and docker-compose.yml).
Usage:   python3 scripts/build_realm.py
Env:     KC_URL (default http://localhost:8080), KC_ADMIN, KC_ADMIN_PASSWORD

Two browser flows are built to compare approaches to ACR-driven step-up:

  1. browser-acr-exact  (client `postman`)
     Uses the custom `conditional-acr-highest` condition (highest of the requested
     acr_values == level, RFC 9470). Disjoint selection: loa/low -> password;
     loa/high -> passkey; loa/x509 (default) -> client certificate.

  2. browser-stepup-cumulative  (client `postman-cumulative`)
     Uses the built-in `conditional-level-of-authentication` (cumulative).
     loa/low -> password only;  default -> password THEN passkey (step-up).

Both clients carry the ACR->LoA map, default.acr.values = high, and the built-in
AMR protocol mapper so tokens include `amr` (pwd / hwk).
"""
import json
import os
import sys
import urllib.request
import urllib.error
import urllib.parse

KC_URL = os.environ.get("KC_URL", "http://localhost:8080").rstrip("/")
ADMIN = os.environ.get("KC_ADMIN", "admin")
ADMIN_PW = os.environ.get("KC_ADMIN_PASSWORD", "admin")

REALM = "poc"
REDIRECT_URI = "https://oauth.pstmn.io/v1/callback"
TEST_USER = "alice"
TEST_PW = "alice"

ACR_LOW = "http://example.com/loa/low"
ACR_HIGH = "http://example.com/loa/high"
ACR_X509 = "http://example.com/loa/x509"

AMR_PWD = "pwd"
AMR_PASSKEY = "hwk"
AMR_X509 = "x509"
X509_PROVIDER = "auth-x509-client-username-form"
LOA_MAX_AGE = "0"     # 0 => re-evaluate every request (clean demo of both paths)
AMR_MAX_AGE = "36000"

# Native ACR routing: one flow per method, selected by client-policy (acr-condition +
# auth-flow-enforcer). No custom ACR SPI is used for routing.
FLOW_PASSWORD = "flow-password"
FLOW_PASSKEY = "flow-passkey"
FLOW_X509 = "flow-x509"
ROUTING_ATTR = "acr.flow.routing"   # client attribute that scopes the ACR routing policies

FLOW_CUMULATIVE = "browser-stepup-cumulative"
COND_CUMULATIVE = "conditional-level-of-authentication"  # built-in (used only by the cumulative demo)

TOKEN = None
TOP = None  # alias of the flow currently being built (used by helpers)


def _req(method, path, body=None, base_admin=True):
    url = (f"{KC_URL}/admin/realms/{path}" if base_admin else f"{KC_URL}/{path}")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            payload = json.loads(raw)
        except Exception:
            payload = raw.decode(errors="replace")
        return e.code, payload


def api(method, path, body=None):
    status, payload = _req(method, path, body)
    if status >= 400:
        raise RuntimeError(f"{method} {path} -> {status}: {payload}")
    return payload


def login():
    global TOKEN
    data = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "admin-cli",
        "username": ADMIN, "password": ADMIN_PW,
    }).encode()
    req = urllib.request.Request(
        f"{KC_URL}/realms/master/protocol/openid-connect/token",
        data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req) as r:
        TOKEN = json.loads(r.read())["access_token"]


# --- flow-building helpers (operate on the flow named by global TOP) --------

def _all_exec_ids():
    execs = api("GET", f"{REALM}/authentication/flows/{TOP}/executions")
    return {e["id"] for e in execs}


def add_execution(parent_alias, provider):
    before = _all_exec_ids()
    api("POST", f"{REALM}/authentication/flows/{parent_alias}/executions/execution",
        {"provider": provider})
    return (_all_exec_ids() - before).pop()


def add_subflow(parent_alias, alias, description=""):
    before = _all_exec_ids()
    api("POST", f"{REALM}/authentication/flows/{parent_alias}/executions/flow",
        {"alias": alias, "type": "basic-flow", "description": description})
    return (_all_exec_ids() - before).pop()


def set_requirement(exec_id, requirement):
    execs = api("GET", f"{REALM}/authentication/flows/{TOP}/executions")
    obj = next(e for e in execs if e["id"] == exec_id)
    obj["requirement"] = requirement
    api("PUT", f"{REALM}/authentication/flows/{TOP}/executions", obj)


def set_config(exec_id, alias, config):
    api("POST", f"{REALM}/authentication/executions/{exec_id}/config",
        {"alias": alias, "config": config})


def amr_config(exec_id, alias, value):
    set_config(exec_id, alias, {
        "default.reference.value": value, "default.reference.maxAge": AMR_MAX_AGE})


def loa_config(exec_id, alias, level):
    set_config(exec_id, alias, {
        "loa-condition-level": str(level), "loa-max-age": LOA_MAX_AGE})


def x509_config(exec_id, alias):
    # Map the client cert's SubjectAltName e-mail to the user's e-mail, skip the
    # confirmation page (log in directly), and emit amr=x509 via the same config.
    set_config(exec_id, alias, {
        "x509-cert-auth.mapping-source-selection": "Subject's Alternative Name E-mail",
        "x509-cert-auth.mapper-selection": "Username or Email",
        "x509-cert-auth.confirmation-page-disallowed": "true",
        "x509-cert-auth.timestamp-validation-enabled": "true",
        "default.reference.value": AMR_X509,
        "default.reference.maxAge": AMR_MAX_AGE,
    })


def new_top_flow(alias, description):
    global TOP
    TOP = alias
    api("POST", f"{REALM}/authentication/flows", {
        "alias": alias, "providerId": "basic-flow", "topLevel": True,
        "builtIn": False, "description": description})
    cookie = add_execution(alias, "auth-cookie")
    set_requirement(cookie, "ALTERNATIVE")
    forms = add_subflow(alias, f"{alias}-forms", "Forms")
    set_requirement(forms, "ALTERNATIVE")
    return f"{alias}-forms"


# --- build steps -----------------------------------------------------------

def reset_realm():
    status, _ = _req("GET", f"{REALM}")
    if status == 200:
        api("DELETE", f"{REALM}")
    api("POST", "", {"realm": REALM, "enabled": True, "displayName": "Passkey Step-up POC"})


def configure_webauthn():
    api("PUT", f"{REALM}", {
        "realm": REALM,
        "webAuthnPolicyPasswordlessRpEntityName": "poc",
        "webAuthnPolicyPasswordlessSignatureAlgorithms": ["ES256", "RS256"],
        "webAuthnPolicyPasswordlessAttestationConveyancePreference": "none",
        "webAuthnPolicyPasswordlessAuthenticatorAttachment": "not specified",
        "webAuthnPolicyPasswordlessRequireResidentKey": "Yes",
        "webAuthnPolicyPasswordlessUserVerificationRequirement": "required",
        "webAuthnPolicyPasswordlessCreateTimeout": 0,
        # ACR -> LoA mapping at the REALM level (single source of truth for all clients);
        # the flow-enforcer's auth-flow-loa maps back to the acr claim through this.
        # x509 is the highest level (3), above passkey (2) and password (1).
        "attributes": {"acr.loa.map": json.dumps({ACR_LOW: 1, ACR_HIGH: 2, ACR_X509: 3})},
    })
    # Passwordless-register stays enabled (Account Console + application-initiated
    # action) but NOT a default action: a *default* action is mandatory and would
    # fire on every login (incl. the password path). The passkey path offers
    # creation via a skippable AIA: kc_action=webauthn-register-passwordless.
    ra = api("GET", f"{REALM}/authentication/required-actions/webauthn-register-passwordless")
    ra["enabled"] = True
    ra["defaultAction"] = False
    api("PUT", f"{REALM}/authentication/required-actions/webauthn-register-passwordless", ra)


# --- ACR routing-target flows (one method each; the LoA is set by the flow-enforcer) ---

def build_password_flow():
    """flow-password: username + password."""
    forms = new_top_flow(FLOW_PASSWORD, "ACR routing target: username + password")
    pw = add_execution(forms, "auth-username-password-form")
    set_requirement(pw, "REQUIRED")
    amr_config(pw, "fp-amr-pwd", AMR_PWD)


def build_passkey_flow():
    """flow-passkey: identity-first passkey; passkey-less users verify with password + enrol."""
    forms = new_top_flow(FLOW_PASSKEY, "ACR routing target: identity-first passkey")
    uname = add_execution(forms, "auth-username-form")
    set_requirement(uname, "REQUIRED")
    # Has a passkey -> passkey login only.
    has_pk = add_subflow(forms, "pk-has", "user has a passkey -> passkey login")
    set_requirement(has_pk, "CONDITIONAL")
    uc = add_execution("pk-has", "conditional-user-configured")
    set_requirement(uc, "REQUIRED")
    wa = add_execution("pk-has", "webauthn-authenticator-passwordless")
    set_requirement(wa, "REQUIRED")
    amr_config(wa, "pk-amr-hwk", AMR_PASSKEY)
    # No passkey -> verify with password, then offer to create one.
    no_pk = add_subflow(forms, "pk-no", "no passkey -> password + create passkey")
    set_requirement(no_pk, "CONDITIONAL")
    sfe = add_execution("pk-no", "conditional-sub-flow-executed")
    set_requirement(sfe, "REQUIRED")
    set_config(sfe, "pk-no-cond", {"flow_to_check": "pk-has", "check_result": "not-executed"})
    pwv = add_execution("pk-no", "auth-password-form")
    set_requirement(pwv, "REQUIRED")
    amr_config(pwv, "pk-amr-pwd", AMR_PWD)
    enrol = add_execution("pk-no", "require-passkey-enrolment")
    set_requirement(enrol, "REQUIRED")


def build_x509_flow():
    """flow-x509: client certificate only."""
    forms = new_top_flow(FLOW_X509, "ACR routing target: X.509 client certificate")
    x = add_execution(forms, X509_PROVIDER)
    set_requirement(x, "REQUIRED")
    x509_config(x, "fx-x509-cfg")


def setup_client_policies():
    """Native ACR routing: acr-condition selects a flow via auth-flow-enforcer (sets the LoA too).

    Policies are ordered low -> high -> x509; for a multi-valued acr_values every matching policy
    runs and the LAST one wins, so the highest requested method is selected. Scoped to clients tagged
    with the ROUTING_ATTR attribute so the cumulative demo client is unaffected.
    """
    api("PUT", f"{REALM}/client-policies/profiles", {"profiles": [
        {"name": "acr-flow-low", "description": "route loa/low -> password",
         "executors": [{"executor": "auth-flow-enforcer",
                        "configuration": {"auth-flow-alias": FLOW_PASSWORD, "auth-flow-loa": 1}}]},
        {"name": "acr-flow-high", "description": "route loa/high -> passkey",
         "executors": [{"executor": "auth-flow-enforcer",
                        "configuration": {"auth-flow-alias": FLOW_PASSKEY, "auth-flow-loa": 2}}]},
        {"name": "acr-flow-x509", "description": "route loa/x509 -> certificate",
         "executors": [{"executor": "auth-flow-enforcer",
                        "configuration": {"auth-flow-alias": FLOW_X509, "auth-flow-loa": 3}}]},
    ]})

    scope_attr = json.dumps([{"key": ROUTING_ATTR, "value": "enabled"}])  # MapperTypeSerializer format

    def policy(name, acr, profile):
        return {"name": name, "description": "", "enabled": True,
                "conditions": [
                    {"condition": "acr-condition", "configuration": {"acr-property": acr}},
                    {"condition": "client-attributes",
                     "configuration": {"is-negative-logic": False, "attributes": scope_attr}},
                ],
                "profiles": [profile]}

    api("PUT", f"{REALM}/client-policies/policies", {"policies": [
        policy("acr-low", ACR_LOW, "acr-flow-low"),
        policy("acr-high", ACR_HIGH, "acr-flow-high"),
        policy("acr-x509", ACR_X509, "acr-flow-x509"),
    ]})


def build_cumulative_flow():
    """loa/low -> password; default -> password THEN passkey (classic step-up)."""
    forms = new_top_flow(FLOW_CUMULATIVE, "Cumulative step-up: password (LoA1) then passkey (LoA2)")

    # Password subflow (cumulative LoA 1) -- MUST come first (ascending).
    pwflow = add_subflow(forms, "cu-password", "LoA 1: username + password")
    set_requirement(pwflow, "CONDITIONAL")
    c1 = add_execution("cu-password", COND_CUMULATIVE)
    set_requirement(c1, "REQUIRED")
    loa_config(c1, "cu-loa-1", 1)
    pw = add_execution("cu-password", "auth-username-password-form")
    set_requirement(pw, "REQUIRED")
    amr_config(pw, "cu-amr-pwd", AMR_PWD)

    # Passkey subflow (cumulative LoA 2) -- added on top for the high request.
    passkey = add_subflow(forms, "cu-passkey", "LoA 2: passkey (added on top)")
    set_requirement(passkey, "CONDITIONAL")
    c2 = add_execution("cu-passkey", COND_CUMULATIVE)
    set_requirement(c2, "REQUIRED")
    loa_config(c2, "cu-loa-2", 2)
    wa = add_execution("cu-passkey", "webauthn-authenticator-passwordless")
    set_requirement(wa, "REQUIRED")
    amr_config(wa, "cu-amr-hwk", AMR_PASSKEY)


def create_client(client_id, name, default_acr=None, browser_flow_alias=None, routing=False):
    attributes = {"pkce.code.challenge.method": "S256"}
    # default.acr.values sets the LoA requested when the app sends no acr_values.
    if default_acr is not None:
        attributes["default.acr.values"] = default_acr
    # Tag the client so the ACR routing client-policies apply to it (and not to others).
    if routing:
        attributes[ROUTING_ATTR] = "enabled"
    body = {
        "clientId": client_id, "name": name, "enabled": True,
        "publicClient": True, "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "redirectUris": [REDIRECT_URI], "webOrigins": ["+"],
        "attributes": attributes,
    }
    # Only the cumulative demo client pins a browser flow; the routed client's flow is chosen
    # per request by the auth-flow-enforcer client-policy.
    if browser_flow_alias is not None:
        flows = api("GET", f"{REALM}/authentication/flows")
        fid = next(f["id"] for f in flows if f["alias"] == browser_flow_alias)
        body["authenticationFlowBindingOverrides"] = {"browser": fid}
    api("POST", f"{REALM}/clients", body)
    cid = api("GET", f"{REALM}/clients?clientId={client_id}")[0]["id"]
    api("POST", f"{REALM}/clients/{cid}/protocol-mappers/models", {
        "name": "amr", "protocol": "openid-connect",
        "protocolMapper": "oidc-amr-mapper",
        "config": {"id.token.claim": "true", "access.token.claim": "true",
                   "userinfo.token.claim": "true"},
    })


def create_user():
    api("POST", f"{REALM}/users", {
        "username": TEST_USER, "enabled": True,
        "email": f"{TEST_USER}@example.com", "emailVerified": True,
        "firstName": "Alice", "lastName": "Example",
        "credentials": [{"type": "password", "value": TEST_PW, "temporary": False}],
    })


def main():
    login()
    print(">> reset realm"); reset_realm()
    print(">> webauthn / passkeys"); configure_webauthn()
    print(">> build routing-target flows"); build_password_flow(); build_passkey_flow(); build_x509_flow()
    print(">> build cumulative flow"); build_cumulative_flow()
    print(">> client-policies (native ACR routing)"); setup_client_policies()
    # Routed client: no flow override; the flow is chosen per request by the acr-condition policy.
    # default.acr.values = x509 so a request with no acr_values matches the x509 policy (cert login).
    print(">> client 'postman' (native ACR routing)")
    create_client("postman", "Postman (native ACR routing)", default_acr=ACR_X509, routing=True)
    # Cumulative demo: pins the built-in cumulative flow; NOT tagged, so routing policies skip it.
    print(">> client 'postman-cumulative'")
    create_client("postman-cumulative", "Postman (cumulative step-up)",
                  default_acr=ACR_HIGH, browser_flow_alias=FLOW_CUMULATIVE)
    print(">> test user"); create_user()
    print(f"\nDone. Realm '{REALM}' ready at {KC_URL}/realms/{REALM}")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
