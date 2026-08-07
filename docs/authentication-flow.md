# Authentication flow deep dive

This document explains how each ACR selects a login method (natively, via client policies), the
routing-target flows, and how the `amr` claim is wired.

## The goal

- **Default** (client sends no `acr_values`): **X.509 client certificate** — the client's
  `default.acr.values` is `…/loa/x509`, so a certificate is required (see *X.509 client-certificate
  option* below).
- **`acr_values=http://example.com/loa/high`**: **identity-first passkey** — enter a username, then a
  passkey holder logs in with their passkey (no password), while a passkey-less user verifies with a
  password and is offered to create a passkey. (See *Passkey enrolment* below.)
- **`acr_values=http://example.com/loa/low`**: log in with **username + password only**.
- Tokens carry an **`amr`** claim: `hwk` for passkey, `pwd` for password, `x509` for the certificate.

The ACR values are mapped to numeric Levels of Authentication (LoA) **at the realm level** (the realm
attribute `acr.loa.map`), so the mapping is a single source of truth shared by every client. A client
may still override it via its own `acr.loa.map` under *Clients → Advanced → ACR to LoA*.

| ACR value | LoA |
|---|---|
| `http://example.com/loa/low` | 1 |
| `http://example.com/loa/high` | 2 |
| `http://example.com/loa/x509` | 3 |

**Default ACR when the app sends no `acr_values`.** Keycloak's **Default ACR Values** is a *client*
attribute (there is no native realm-level equivalent). The `postman` client sets
`default.acr.values = …/loa/x509`, so a request with no `acr_values` resolves to the certificate — the
`acr-condition` for `…/loa/x509` matches (because `AcrUtils.getAcrValues` returns the client default) and
the `acr-x509` policy routes to `flow-x509`.

Precedence (highest priority first): request `acr_values` / essential `claims` acr → client
`default.acr.values` → none.

**Client Minimum ACR Value (a floor).** The client *Minimum ACR Value* (Clients → Advanced) is honoured
automatically. The `acr-condition` resolves the requested ACR list via `AcrUtils.getAcrValues(...)`, which
ends in `enforceMinimumAcr(...)`: it drops any requested ACR *below* the client minimum and, if that
empties the list, injects the minimum. The mapping uses `getAcrLoaMap(client)`, which falls back to the
realm-level `acr.loa.map`. So a client with Minimum ACR `…/loa/high` requesting `acr_values=…/loa/low` is
bumped to `…/loa/high` (the `acr-high` policy matches → passkey). An essential `claims` acr *below* the
minimum is rejected by the authorization endpoint before the flow runs.

## How ACR selects the authentication method (native client policies)

Keycloak **26.2+** can select the authentication method disjointly by ACR **natively** — no custom code —
using **client policies**: the built-in **`acr-condition`** matches the requested ACR and the
**`auth-flow-enforcer`** executor routes the request to a whole **authentication flow** (and sets the
achieved LoA). This PoC uses that mechanism.

> **History:** earlier revisions claimed vanilla Keycloak couldn't do this and shipped custom SPIs
> (`conditional-acr-exact` / `conditional-acr-highest`). That was **wrong for 26.2+**; those SPIs were
> removed. The cumulative limitation is real only for the **`Condition - Level of Authentication`**
> authenticator (see the contrast flow below) — flow selection sidesteps it.

### Routing-target flows (one method each)

Three standalone top-level flows, each doing exactly one method. They contain **no** ACR condition — the
level is set by the policy:

```
flow-password : Cookie(ALT) + Username Password Form                                    amr=pwd
flow-passkey  : Cookie(ALT) + Username Form
                              ├─ pk-has (CONDITIONAL)  Condition - user configured
                              │                        + WebAuthn Passwordless           amr=hwk
                              └─ pk-no  (CONDITIONAL)  <pk-has not executed> + Password Form (amr=pwd)
                                                       + Require passkey enrolment (custom SPI)
flow-x509     : Cookie(ALT) + X509 Validate Username Form                                amr=x509
```

### Client policies (the routing)

*Realm → Client policies.* Each **profile** points `auth-flow-enforcer` at a flow + LoA; each **policy**
matches one ACR (and is scoped to the `postman` client with a `client-attributes` condition so it does
not affect `postman-cumulative`):

| policy | `acr-condition` (`acr-property`) | → flow (`auth-flow-loa`) |
|---|---|---|
| `acr-low`  | `…/loa/low`  | `flow-password` (1) |
| `acr-high` | `…/loa/high` | `flow-passkey` (2) |
| `acr-x509` | `…/loa/x509` | `flow-x509` (3) |

- `AcrCondition.containsAcr()` = `AcrUtils.getAcrValues(...).contains(<acr-property>)` — **exact membership**.
- `auth-flow-enforcer` sets `REQUESTED_AUTHENTICATION_FLOW` (overriding any client browser-flow) and the
  achieved LoA; the token `acr` comes from `auth-flow-loa` through the realm ACR-to-LoA map.
- **No `acr_values`** → the client's `default.acr.values` (`…/loa/x509`) is what `getAcrValues` returns →
  `acr-x509` matches → certificate.
- **Multiple `acr_values`** → *every* matching policy runs and the **last-evaluated wins**; policies are
  ordered low → high → x509, so the **highest** requested method is selected (e.g. `"low high"` → passkey).
  This is how the native routing avoids the LoA *condition*'s `.min()` collapse (it selects a whole flow,
  never the collapsed level).

### Contrast: the cumulative flow (client `postman-cumulative`)

For comparison, `postman-cumulative` uses the built-in **cumulative** `Condition - Level of Authentication`
(the client is not tagged for routing, so the policies skip it):

```
Cookie(ALT) + forms(ALT)
├─ cu-password (CONDITIONAL)  Condition - LoA level=1 + Username Password Form (amr=pwd)
└─ cu-passkey  (CONDITIONAL)  Condition - LoA level=2 + WebAuthn Passwordless   (amr=hwk)
```

- `acr_values=loa/low` (LoA 1): only `cu-password` → **password**.
- default (LoA 2): `cu-password` **then** `cu-passkey` → **password + passkey** (textbook additive step-up).

`ConditionalLoaAuthenticator.matchCondition` is cumulative (`requestedLoa >= configuredLoa`, and always
on a fresh session), so it always runs the lower method too — which is exactly why flow selection is the
better fit for disjoint ACR→method routing.

## X.509 client-certificate option

X.509 is the **default** login method and its own highest LoA level (`loa/x509` → 3). The `postman`
client's `default.acr.values=…/loa/x509` (and the `acr-x509` policy) route no-`acr_values` requests to
`flow-x509`, which contains only `auth-x509-client-username-form` as **REQUIRED** — so a request with no
`acr_values` (or an explicit `…/loa/x509`) requires a trusted client certificate, with no password
fallback (and no certificate prompt on the password/passkey paths).

This needs **HTTPS with client-certificate auth**, so the compose file adds an `:8443` listener with
`KC_HTTPS_CLIENT_AUTH=request` and trusts the demo CA via `KC_TRUSTSTORE_PATHS`. The authenticator is
configured to:

- **map the identity** from the certificate's *SubjectAltName e-mail*
  (`x509-cert-auth.mapping-source-selection = "Subject's Alternative Name E-mail"`) using the
  *Username or Email* mapper — so `alice@example.com` in the cert resolves to the `alice` account;
- **skip the confirmation page** (`x509-cert-auth.confirmation-page-disallowed = true`) so a valid cert
  logs in directly.

The **`amr=x509`** value is carried in the *same* authenticator-config object as the X.509 settings —
the AMR mapper reads `default.reference.value` from it, so one config both drives the X.509 mapping and
labels the method.

## Passkey enrolment ("offer to create one")

Passwordless login needs an existing passkey, so a passkey-less user is bootstrapped on the default
path itself: they identify with a username, verify with a password (because "no verification →
register" would let anyone enrol a passkey onto any username), and are then sent to create a passkey.

Keycloak has no in-flow passkey *registration* authenticator — enrolment runs as the
`webauthn-register-passwordless` **required action**. The custom `require-passkey-enrolment`
authenticator triggers it, but adds it to the **authentication session**
(`AuthenticationSessionModel.addRequiredAction`) rather than the user account. That scoping is the key
detail: a user-level required action would persist and re-prompt on *every* subsequent login (including
the password-only `loa/low` path); a session-scoped one applies to this login only.

The `webauthn-register-passwordless` required action is left **enabled but not default**, so it is also
available for the Account Console and for application-initiated enrolment
(`kc_action=webauthn-register-passwordless&skip_if_exists=true`) if an app wants to offer it elsewhere.

## The `amr` claim

Keycloak 26 ships a built-in **Authentication Method Reference (AMR)** protocol mapper
(`oidc-amr-mapper`), added to both clients. It reads a **reference value** configured on each
authentication execution and emits it in `amr`.

The reference value is stored in the execution's **authenticator config** under
`default.reference.value` (with `default.reference.maxAge`). This POC sets:

| Execution | `default.reference.value` |
|---|---|
| Username Password Form / Password Form | `pwd` |
| WebAuthn Passwordless Authenticator | `hwk` |
| X509 Validate Username Form | `x509` |

So a password login yields `amr: ["pwd"]`, a passkey login `amr: ["hwk"]`, a certificate login
`amr: ["x509"]`, and the cumulative default path (password + passkey) would yield both.

## Verified behaviour

`scripts/verify.sh` (authorization-code + PKCE) confirms:

| Client | Request | Result |
|---|---|---|
| `postman` (routed) | `acr_values=loa/low` | token, `acr=…/loa/low`, `amr=["pwd"]` |
| `postman` (routed) | `acr_values=loa/high` | identity-first: username → (passkey-less alice) password verify → **create-a-passkey** page |
| `postman` (routed) | `acr_values="loa/low loa/high"` | **highest wins** → identity-first passkey page |
| `postman-cumulative` | `acr_values=loa/low` | token, `acr=…/loa/low`, `amr=["pwd"]` |
| `postman-cumulative` | default | password succeeds, then requires the passkey step (LoA 2) |
| `postman` (routed, `:8443` + cert) | **default** (no `acr_values`) | X.509 login as `alice`, `acr=…/loa/x509`, `amr=["x509"]` |
| `postman` (routed, `:8443` + cert) | `acr_values=loa/x509` | same (explicit) |
| `postman` (routed, `:8443`, no cert) | default / `loa/x509` | login refused (X.509 required) |

Passkey login (`amr: ["hwk"]`) is verified manually with a Chrome DevTools virtual authenticator — see
the README.

## Automated integration test

`providers-src` ships a JUnit 5 + Testcontainers integration test
(`AcrRoutingIT`) that boots a real Keycloak 26.4 container with the compiled provider mounted
and the actual `realm/poc-realm.json` imported, then drives authorization-code + PKCE logins and
asserts:

- `postman` + `acr_values=loa/low` → token with `acr = …/loa/low`, `amr` contains `pwd`
- `postman` + `acr_values=loa/high` → the first page asks for a **username** and has **no password**
  field (identity-first passkey); a passkey-less alice then verifies with a password and reaches the
  **passkey registration** page
- `postman` + `loa/high` *then* `loa/low` → the password path still returns a token — proving the
  enrolment step is session-scoped and leaves **no lingering passkey nag**
- `postman` + default (no `acr_values`) → routed to **X.509** (no password/passkey page; can't complete
  headlessly without a cert)
- `postman` + `acr_values="loa/low loa/high"` → the **highest** wins → the identity-first passkey page
- `postman-cumulative` + `acr_values=loa/low` → token with `acr = …/loa/low` (policies don't touch it)

This exercises the whole native routing end-to-end: if a client policy or `require-passkey-enrolment`
were missing or wrong, the flow would route incorrectly and the tests would fail. Run it with
`./scripts/it.sh` (needs local JDK 21 + Maven + a container engine).

## Further reading — Keycloak documentation

Each concept this PoC relies on is documented upstream (Keycloak *Server Administration Guide*, `latest`):

| Concept in this doc | Keycloak documentation |
|---|---|
| ACR → Level of Authentication (LoA) realm mapping (`acr.loa.map`) | [Mapping ACR to LoA at the realm](https://www.keycloak.org/docs/latest/server_admin/index.html#_mapping-acr-to-loa-realm) |
| **ACR selects a whole flow** (`acr-condition` + `auth-flow-enforcer`) — the core of this PoC | [Using client policies to select an authentication flow](https://www.keycloak.org/docs/latest/server_admin/index.html#_client-policy-auth-flow) |
| Client policies (profiles, conditions, executors) | [Client policies](https://www.keycloak.org/docs/latest/server_admin/index.html#_client_policies) |
| The routing-target flows and conditional sub-flows | [Authentication flows](https://www.keycloak.org/docs/latest/server_admin/index.html#_authentication-flows) |
| Passkey / passwordless WebAuthn login | [Passkeys](https://www.keycloak.org/docs/latest/server_admin/index.html#passkeys_server_administration_guide) · [Passwordless WebAuthn](https://www.keycloak.org/docs/latest/server_admin/index.html#_webauthn_passwordless) |
| `webauthn-register-passwordless` as a required action (what `require-passkey-enrolment` triggers) | [Required actions](https://www.keycloak.org/docs/latest/server_admin/index.html#con-required-actions_server_administration_guide) |
| X.509 client-certificate authentication | [X.509 client certificate user authentication](https://www.keycloak.org/docs/latest/server_admin/index.html#_x509) |

The custom `require-passkey-enrolment` authenticator is built against the
[Authentication SPI](https://www.keycloak.org/docs/latest/server_development/index.html#_auth_spi)
(*Server Development Guide*).
