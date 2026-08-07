<!--
Ready to paste into a GitHub Discussion (Show and tell / Q&A / Ideas).
Suggested title (plain text): Selecting the login method by ACR (password / passkey / X.509) natively with client policies
-->

# Selecting the login method by ACR natively (password / passkey / X.509)

A common ask: "make `acr=low` do password, `acr=high` do a passkey, `acr=cert` do an X.509 client
certificate — each **instead of** the others, not stacked on top." Keycloak's `Condition - Level of
Authentication` is *cumulative* (a higher level also runs the lower method), so it can't express that on
its own. But since **Keycloak 26.2** there's a native way: **client policies** route each ACR to a
**separate authentication flow** — no custom SPI. Here's a complete, working setup (verified on 26.7.1).

The pieces: the built-in **`acr-condition`** (client-policy condition) matches the requested ACR, and the
**`auth-flow-enforcer`** (client-policy executor) selects a whole flow *and* sets the achieved LoA. Both
are behind the `STEP_UP_AUTHENTICATION` feature (on by default).

## 1. Map ACR values to LoA numbers (realm)

Realm Settings → set the realm `acr.loa.map` attribute (or per client under *Clients → Advanced → ACR to
LoA*). The numbers are just labels for the token `acr` claim:

```json
{ "http://example.com/loa/low": 1,
  "http://example.com/loa/high": 2,
  "http://example.com/loa/x509": 3 }
```

## 2. Create one authentication flow per method

Three standalone top-level browser flows (Authentication → Flows → Create flow). Each does exactly one
method — **no ACR condition inside**; the level is set by the policy in step 3:

- **`flow-password`** — Cookie (Alternative) + Username Password Form (Required).
- **`flow-passkey`** — Cookie (Alternative) + your passkey flow (e.g. Username Form, then WebAuthn
  Passwordless; optionally offer registration for users without a passkey).
- **`flow-x509`** — Cookie (Alternative) + X509/Validate Username Form (Required). Requires the server to
  run HTTPS with `KC_HTTPS_CLIENT_AUTH=request` and a truststore for the client-cert CA.

## 3. Client policies: route each ACR to a flow

*Realm Settings → Client policies.* Create one **profile** per method (the executor picks the flow + LoA)
and one **policy** per ACR (the condition matches the requested ACR and applies the profile).

**Profiles** (`auth-flow-enforcer`):

```json
{ "profiles": [
  { "name": "acr-flow-low",  "executors": [ { "executor": "auth-flow-enforcer",
      "configuration": { "auth-flow-alias": "flow-password", "auth-flow-loa": 1 } } ] },
  { "name": "acr-flow-high", "executors": [ { "executor": "auth-flow-enforcer",
      "configuration": { "auth-flow-alias": "flow-passkey",  "auth-flow-loa": 2 } } ] },
  { "name": "acr-flow-x509", "executors": [ { "executor": "auth-flow-enforcer",
      "configuration": { "auth-flow-alias": "flow-x509",     "auth-flow-loa": 3 } } ] }
] }
```

**Policies** (`acr-condition`) — order them **low → high → x509** (see multi-value note below):

```json
{ "policies": [
  { "name": "acr-low",  "enabled": true, "profiles": ["acr-flow-low"],
    "conditions": [ { "condition": "acr-condition",
      "configuration": { "acr-property": "http://example.com/loa/low" } } ] },
  { "name": "acr-high", "enabled": true, "profiles": ["acr-flow-high"],
    "conditions": [ { "condition": "acr-condition",
      "configuration": { "acr-property": "http://example.com/loa/high" } } ] },
  { "name": "acr-x509", "enabled": true, "profiles": ["acr-flow-x509"],
    "conditions": [ { "condition": "acr-condition",
      "configuration": { "acr-property": "http://example.com/loa/x509" } } ] }
] }
```

## 4. The client

- Set the client's **Default ACR Values** to whatever should happen when the app sends no `acr_values`
  (e.g. `http://example.com/loa/x509` → certificate). `acr-condition` reads the requested list *including*
  the client default, so the matching policy fires.
- The client needs **no** authentication-flow override — the policy selects the flow per request
  (`auth-flow-enforcer` sets `REQUESTED_AUTHENTICATION_FLOW`, which wins over any client/realm default).
- **Scope, if needed:** the policies above apply to every client in the realm requesting those ACRs. To
  limit them to specific clients, add a second condition to each policy — e.g. `client-attributes`
  matching a tag you set on the client:

  ```json
  { "condition": "client-attributes",
    "configuration": { "is-negative-logic": false,
                       "attributes": "[{\"key\":\"acr.flow.routing\",\"value\":\"enabled\"}]" } }
  ```

## How it behaves

| Request | Selected flow | Token `acr` |
|---|---|---|
| `acr_values=…/loa/low`  | `flow-password` | `…/loa/low` |
| `acr_values=…/loa/high` | `flow-passkey`  | `…/loa/high` |
| `acr_values=…/loa/x509` | `flow-x509`     | `…/loa/x509` |
| *(none)* → client Default ACR | that flow  | that level |

- **Token `acr`** comes from the executor's `auth-flow-loa`, mapped back through the ACR-to-LoA map.
- **Multiple `acr_values`** (a space-separated list): *every* matching policy runs and the **last one
  evaluated wins**, so with policies ordered low → high → x509 the **highest** requested method is
  selected (e.g. `acr_values="low high"` → passkey). This sidesteps the fact that the LoA *condition*
  otherwise collapses a multi-valued `acr_values` to its minimum.
- **Client `Minimum ACR Value`** still applies as a floor (`AcrUtils.enforceMinimumAcr`), so a request
  below the minimum is bumped up before the policies match.

## Gotchas

- `auth-flow-enforcer` id is `auth-flow-enforcer`; `acr-condition` id is `acr-condition` (26.7.1).
- The `client-attributes` condition's `attributes` is a serialized **string** of
  `[{"key":"…","value":"…"}]` (single string value per entry), not a JSON object.
- X.509 needs mutual TLS (HTTPS + `KC_HTTPS_CLIENT_AUTH=request` + a CA truststore); it can't work over
  plain HTTP.
- Docs: Server Admin Guide → *Using Client Policies to Select an Authentication Flow*; released in the
  26.2 notes as "Dynamic Authentication Flow selection using Client Policies".

## A working reference

A full runnable PoC (docker-compose, realm import, `build_realm.py` that creates exactly the flows +
profiles + policies above, plus password/passkey/X.509 flows and an `amr` mapper, with scripted tests)
is here: <link-to-your-repo>.

---

### Still missing natively (possible enhancements)

- **Realm-level Default ACR Values** — `default.acr.values` is client-only today; a realm-wide default
  (inherited by clients without their own) would avoid repeating it. (`AcrUtils.getDefaultAcrValues` reads
  only the client, whereas the ACR-to-LoA map already falls back to the realm.)
- **`unmet_authentication_requirements`** OAuth error (RFC 9470) when a requested ACR can't be met — see
  keycloak/keycloak#23531.
