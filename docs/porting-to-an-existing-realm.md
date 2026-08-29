# Porting the ACR routing to another Keycloak — admin console only

This is a step-by-step runbook for reproducing this PoC's behaviour on a **different** Keycloak
installation, configured **entirely in the admin console** (no REST calls, no scripts), full scope
(**password + passkey + X.509**), added **into an existing realm** without wiping it.

For *why* each piece exists, see the [authentication-flow deep dive](authentication-flow.md); this page is
purely the "how to click it" guide. Native ACR→flow routing needs **Keycloak 26.2+**; passkeys need the
`passkeys` feature (26.4+).

Everything below is clickable in the console. Two substitutions make that possible:

- The realm **ACR→LoA map** and per-execution **AMR reference values** *are* console fields.
- Clients have **no generic attributes UI**, so instead of the PoC's `acr.flow.routing` client-attribute
  we scope the routing policies with a **client scope** + a `client-scopes` policy condition (same effect,
  fully clickable).

ACR values used throughout: `low = http://example.com/loa/low`, `high = http://example.com/loa/high`,
`x509 = http://example.com/loa/x509`. Rename them consistently if you prefer your own URIs.

> **How this differs from the PoC realm.** The PoC scopes routing with a custom **client attribute**
> (`acr.flow.routing=enabled`, matched by a `client-attributes` policy condition), set over the REST API.
> There is **no `acr-routing` scope in the PoC** — that scope is introduced here purely as the
> console-clickable substitute (matched by a `client-scopes` condition), since custom client attributes
> can't be set in the console. The built-in **`acr`** scope you'll see on every client is Keycloak's own
> (it holds the `acr loa level` mapper) and is unrelated to routing selection — don't reuse it as the
> selector (see step 3).

---

## 0. Server prerequisites (host-level, before the console work)

These are the only non-console items — server startup / file operations, not realm config:

1. **Version ≥ 26.2** (26.4+ recommended).
2. Start with the **`passkeys` feature**: `--features=passkeys` (or `KC_FEATURES=passkeys`).
3. **Deploy the custom SPI** `require-passkey-enrolment`: copy `keycloak-poc-providers.jar` into
   `/opt/keycloak/providers/`, run `kc.sh build`, restart. **Rebuild the jar from `providers-src/`
   against the target's Keycloak version** if it isn't 26.4 (align the `keycloak-*` versions in
   `providers-src/pom.xml`). Verify: it shows up as the authenticator **"Require passkey enrolment"**
   when you add a step to a flow (step 2).
4. **X.509 / mTLS** (needed for the X.509 method): serve HTTPS and set `KC_HTTPS_CLIENT_AUTH=request` and
   `KC_TRUSTSTORE_PATHS=<CA that issued the client certs>`. Each X.509 user needs a client certificate
   whose **SubjectAltName e-mail = their account e-mail**.

> If mTLS (0.4) isn't possible on this server, drop X.509: skip `flow-x509` and the `acr-x509` policy,
> and set the client's Default ACR to `…/loa/high`. Password+passkey still needs the SPI (0.3) for
> enrolment.

---

## 1. Realm settings (select your existing realm first — all additive)

**A. ACR → LoA mapping.** Realm settings → **Login** tab → **ACR to LoA Mapping** → add three rows:
`http://example.com/loa/low → 1`, `…/loa/high → 2`, `…/loa/x509 → 3`. Save.

**B. WebAuthn Passwordless policy.** Authentication → **Policies** → **WebAuthn Passwordless Policy**
(may be shown as **Passkeys** on 26.4+): set an RP entity name, Signature algorithms `ES256`, `RS256`,
**Require resident key = Yes**, **User verification requirement = required**, Attestation conveyance
`none`. Save.

**C. Required action.** Authentication → **Required actions** → find **Webauthn Register Passwordless** →
toggle **Enabled = On**, **Default action = Off**. (Default-on would prompt enrolment on *every* login,
including the password path; the flow triggers it per-session instead.)

---

## 2. Build the three routing-target flows

Authentication → **Flows** → **Create flow** (each is a top-level "Basic flow"). For each: **Add step →
Cookie** (set to *Alternative*), then **Add sub-flow** named `…-forms` (*Alternative*) and add the method
steps inside it. Set each requirement with the dropdown. Set the **Reference value** (and the X509 config)
via each step's **⚙ / kebab → Settings** dialog.

**`flow-password`**

| Step | Requirement | ⚙ Settings |
|---|---|---|
| Cookie | Alternative | — |
| Username Password Form | **Required** | Reference value = `pwd` |

**`flow-passkey`** (identity-first; passkey-less → password verify → enrol)

| Step | Requirement | ⚙ Settings |
|---|---|---|
| Cookie | Alternative | — |
| Username Form | **Required** | — |
| sub-flow **pk-has** | **Conditional** | — |
| — Condition - user configured | **Required** | — |
| — WebAuthn Passwordless Authenticator | **Required** | Reference value = `hwk` |
| sub-flow **pk-no** | **Conditional** | — |
| — Condition - sub-flow executed | **Required** | Flow to check = `pk-has`, Check result = `not executed` |
| — Password Form | **Required** | Reference value = `pwd` |
| — Require passkey enrolment | **Required** | — |

**`flow-x509`**

| Step | Requirement | ⚙ Settings |
|---|---|---|
| Cookie | Alternative | — |
| X509/Validate Username Form | **Required** | User identity source = **Subject's Alternative Name E-mail**; User mapping method = **Username or Email**; **Bypass identity confirmation = On**; Reference value = `x509` |

> The **Reference value** field is the generic per-execution AMR setting (some versions show it alongside
> "Max age"). It appears in the same ⚙ Settings dialog as any authenticator-specific config (so on the
> X509 step you set both the mapping fields *and* the reference value together).

---

## 3. Client scope for routing (the console substitute for the client-attribute)

Because there's no console field for a custom client attribute, use a client scope to mark which clients
get ACR routing:

1. **Client scopes → Create client scope** → Name `acr-routing`, Type **Default**, Protocol
   `openid-connect`, **Include in token scope = Off** (it's only a marker; add no mappers).
2. You'll attach it to your app client in step 5.

> **Don't reuse the built-in `acr` scope for this.** Keycloak ships an `acr` client scope (it carries the
> `acr loa level` mapper) that is assigned as a **Default** scope to *every* client — so a `client-scopes`
> condition on `acr` would match all clients and route the whole realm. The point of `acr-routing` is that
> it's a *sparse* marker present only on the clients you deliberately assign it to. (If you genuinely want
> every client routed, skip this scope and use an `any-client` condition in step 4 instead.)

---

## 4. Client policies — the actual ACR→flow routing (Realm settings → Client policies)

**Profiles** tab → create three profiles, each with one executor **`auth-flow-enforcer`**:

| Profile | Executor config: Authentication flow | Executor config: LoA |
|---|---|---|
| `acr-flow-low` | `flow-password` | 1 |
| `acr-flow-high` | `flow-passkey` | 2 |
| `acr-flow-x509` | `flow-x509` | 3 |

**Policies** tab → create three policies **in this order** (low → high → x509 — for a multi-valued
`acr_values`, the last matching policy wins, so the highest is selected). Each policy: **Enabled = On**,
add **two conditions**, and attach the matching profile.

| Policy | Condition `acr-condition` (ACR) | Condition `client-scopes` | Profile |
|---|---|---|---|
| `acr-low`  | `http://example.com/loa/low`  | Scopes = `acr-routing`, Type = Default | `acr-flow-low` |
| `acr-high` | `http://example.com/loa/high` | Scopes = `acr-routing`, Type = Default | `acr-flow-high` |
| `acr-x509` | `http://example.com/loa/x509` | Scopes = `acr-routing`, Type = Default | `acr-flow-x509` |

> The `client-scopes` condition restricts routing to clients that carry the `acr-routing` scope (step 5),
> so other clients in the realm are untouched. If you actually want routing to apply to *every* client,
> use an `any-client` condition instead of `client-scopes` — but then any client sending `acr_values` (or
> with a Default ACR) gets routed.

---

## 5. Your application client (Clients → your client)

- **Settings:** Client type public, **Standard flow = On**; add your redirect URI; PKCE (Advanced → Proof
  Key… = `S256`) recommended.
- **Client scopes** tab → **Add client scope** → pick `acr-routing` → add as **Default**. (This is what
  makes the routing policies apply to this client.)
- **Advanced** tab → **Default ACR Values** → add `http://example.com/loa/x509` (this makes "no
  `acr_values`" default to the certificate). Use `…/loa/low` or `…/loa/high` to default to
  password/passkey instead — no flow changes needed.
- **DO NOT** set an *Authentication flow override → Browser* on this client. Routing works by the enforcer
  overriding the browser flow per request; an override here would fight it.
- **AMR mapper:** Client scopes → the client's **-dedicated** scope → **Add mapper → By configuration →
  Authentication Method Reference (AMR)** → tick **Add to ID token / Access token / Userinfo**. Save.

---

## 6. Users & credentials

- Each user: set an **e-mail** (X.509 maps the cert's SAN e-mail to it) and a **password** credential.
- **Passkey:** enrolled by logging in via the `high` path (password verify → create-a-passkey), or by the
  user in the Account Console.
- **X.509 user:** issue a client cert (SAN e-mail = account e-mail) from the CA in `KC_TRUSTSTORE_PATHS`.

---

## Verification (end-to-end, from a client / Postman)

Run Authorization-Code + PKCE and inspect the token `acr` / `amr`:

| Request | Expected |
|---|---|
| `acr_values=…/loa/low` | username+password → `acr=…/loa/low`, `amr=["pwd"]` |
| `acr_values=…/loa/high` | identity-first: username → (passkey-less) password → **create-passkey**; `amr=["hwk"]` once enrolled |
| `acr_values="…/loa/low …/loa/high"` | **highest wins** → passkey page |
| **no** `acr_values` (HTTPS + client cert) | X.509 login → `acr=…/loa/x509`, `amr=["x509"]` |
| no `acr_values`, **no** cert | login refused (cert required) |
| a client **without** the `acr-routing` scope | unaffected — runs its normal browser flow |

If a case misbehaves, check in order: SPI loaded (0.3) → ACR-to-LoA rows present (1.A) → each method step
has its Reference value (2) → the client has the `acr-routing` **Default** scope (5) and each policy's
`client-scopes` condition names it (4) → the client's **Default ACR Values** is set (5).

---

## Debugging the authentication flow

Work from the outside in — the token tells you *what* happened, the logs tell you *why*.

**1. Read the token first — it shows which flow actually ran.** Decode the ID/access token (any JWT
decoder) and look at:
- **`acr`** — the LoA that was achieved, which maps back (through the realm ACR→LoA map) to the flow that
  ran. A wrong `acr` means wrong routing → a policy/condition problem (§4) or the wrong Default ACR (§5).
- **`amr`** — missing/empty means the AMR mapper isn't on the client (§5) or a step's **Reference value**
  is unset (§2).

**2. Turn on login events (console).** Enable saving **User events** (Realm settings → the events/**User
events** config), reproduce the login, then read the **Events** list. A `LOGIN_ERROR` row's **error** and
details (e.g. `invalid_user_credentials`, certificate errors) pinpoint the failing step; a successful
`LOGIN` row shows the client and identity that resolved.

**3. Targeted server debug logging (the most detailed view).** Start Keycloak with these categories
(env `KC_LOG_LEVEL`, or `--log-level`):

```
INFO,org.keycloak.authentication:debug,org.keycloak.services.clientpolicy:trace,org.keycloak.events:debug
```

- `org.keycloak.authentication` (debug) — every executor and requirement decision as the flow runs; you
  see exactly which steps executed vs skipped (e.g. the `pk-has` / `pk-no` conditionals).
- `org.keycloak.services.clientpolicy` (trace) — client-policy evaluation: whether `acr-condition`
  matched the requested ACR and whether `auth-flow-enforcer` set the flow. **This is where you confirm
  routing fired** (or why it didn't).
- `org.keycloak.events` (debug) — writes each event inline in the server log.

**4. Drive the authorization endpoint directly — no app needed.** Open this in a browser and watch the
pages, varying (or dropping) `acr_values`:

```
https://KC/realms/REALM/protocol/openid-connect/auth?client_id=CLIENT&response_type=code&scope=openid&redirect_uri=REDIRECT&acr_values=http://example.com/loa/high
```

Confirm the first page is the expected method. The Network tab shows the final redirect carrying `code=`
(success) or `error=` (failure).

**5. Method-specific**
- **Passkey:** Chrome DevTools → **WebAuthn** tab → enable a *virtual authenticator* to enrol / log in
  without hardware. No enrolment page → recheck the WebAuthn Passwordless policy (§1.B) and that
  **Require passkey enrolment** is REQUIRED inside `pk-no` (§2).
- **X.509:** confirm the browser actually presented a certificate (you got the cert picker / TLS
  handshake succeeded). No prompt → `KC_HTTPS_CLIENT_AUTH` / server-cert issue (§0.4); *unknown user* →
  the SAN-email→account mapping (§0.4, §2); *untrusted cert* → the issuing CA isn't in
  `KC_TRUSTSTORE_PATHS` (§0.4).

**Symptom → likely cause**

| Symptom | Look at |
|---|---|
| Always the same method regardless of `acr_values` | policy disabled / wrong `acr-condition` value / client missing the `acr-routing` scope (§4, §5) |
| *Every* client gets routed | condition uses `any-client` or the built-in `acr` scope instead of `acr-routing` (§3, §4) |
| Multi-value picks the **lowest** | policy order — must be low → high → x509 (§4) |
| No `amr` in the token | AMR mapper missing on the client (§5) or Reference value unset on the step (§2) |
| `acr` present but numeric/unexpected | realm ACR→LoA map missing or mismatched (§1.A) |
| Routing ignored, the client's browser flow runs | the client has a **Browser flow override** set — remove it (§5) |
| Server log shows `POLICY UNSATISFIED` + `client-attributes` **NEGATIVE** on every policy | the policies still use the PoC's `client-attributes` scoping (`acr.flow.routing`), which **can't be set from the console** — switch each policy to a `client-scopes` condition on `acr-routing` (§3, §4) |
| `acr` always comes back `…/loa/low` even though the right method ran | the enforcer never ran, so no LoA was stamped (see the row above) — routing must actually fire; also confirm the realm map has the `…/loa/x509 → 3` row (§1.A) |
