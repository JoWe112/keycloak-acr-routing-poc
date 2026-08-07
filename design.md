# PR-scoped design — native ACR matching/selection in `STEP_UP_AUTHENTICATION` (Keycloak 26.7.1)

Companion technical design for the split issue set — [`issue.md`](issue.md) (#1+#2, OIDC ↔ SAML
`Comparison` parity), [`issue-realm-default-acr.md`](issue-realm-default-acr.md) (#3), and upstream
**#23531** (#4, use [`comment-23531.md`](comment-23531.md)). This is the implementation design for a
Keycloak fork at tag **`26.7.1`**: it maps all four gaps onto concrete, backwards-compatible changes,
all behind the existing `Profile.Feature.STEP_UP_AUTHENTICATION` flag. Line references are from tag
`26.7.1`.

Guiding principles:
- **Backwards compatible** — every new option defaults to today's behaviour.
- **Reuse existing utilities** — `AcrUtils`, `AcrStore`, `LoAUtil`, `AcrProtocolMapper`.
- **Small, reviewable PRs** — suggested split at the end.

---

> **Prior art:** SAML step-up already implements this comparison model
> (`SamlProtocolUtils.checkLoAExact/checkLoAMinimum/checkLoAMaximum`, dispatched by
> `AuthnContextComparisonType`, feature `STEP_UP_AUTHENTICATION_SAML`). #1+#2 bring the same semantics to
> the OIDC `acr_values` side, so the design should mirror the SAML enum/dispatch where practical.
> Gap #4 is already tracked by **keycloak/keycloak#23531** — contribute there rather than re-filing.

## #1 — Exact / comparison mode on *Condition - Level of Authentication*

**Goal:** let a subflow require the requested LoA to match the configured level **exactly**, enabling
disjoint ACR→method selection (our `conditional-acr-exact`). This is the OIDC analogue of SAML
`Comparison="exact"` (`SamlProtocolUtils.checkLoAExact`).

**Files**
- `services/.../authenticators/conditional/ConditionalLoaAuthenticator.java`
- `services/.../authenticators/conditional/ConditionalLoaAuthenticatorFactory.java`

**Changes**
- Add constant `public static final String COMPARISON = "loa-comparison";` and values `minimum` (default)
  / `exact`.
- Factory `CONFIG`: add a `ProviderConfigProperty` of `LIST_TYPE` named `COMPARISON` with options
  `[minimum, exact]`, default `minimum` (next to the existing `LEVEL` / `MAX_AGE`).
- `matchCondition` (`ConditionalLoaAuthenticator.java:54`): read the mode; when `exact`, short-circuit to

  ```java
  return requestedLoa == configuredLoa;   // no cumulative / fresh-login / previouslyAuthenticated branch
  ```

  `minimum` keeps the current body verbatim. `onParentFlowSuccess` (records the achieved level via
  `AcrStore.setLevelAuthenticatedToCurrentRequest`) is unchanged, so the token `acr` stays correct.

**Compatibility:** existing configs have no `loa-comparison` → treated as `minimum` → no behaviour change.

---

## #2 — Configurable multi-value `acr_values` reduction

**Goal:** stop silently collapsing a multi-valued `acr_values` to its minimum; let the deployment choose
`minimum` (today) or `maximum`. `#1 exact` + `#2 maximum` = our `conditional-acr-highest`.

**Files**
- `services/.../protocol/oidc/utils/AcrUtils.java` (new helper)
- `services/.../protocol/oidc/endpoints/AuthorizationEndpoint.java` (`:371-388`)

**Changes**
- Extract the acr→loa stream + reduction into
  `AcrUtils.reduceToRequestedLoa(List<String> acrValues, Map<String,Integer> acrLoaMap, ReductionPolicy policy)`
  returning `OptionalInt`. Keep the existing per-acr mapping (map lookup, `Integer.parseInt`, essential
  vs. voluntary handling) intact — only the terminal `.min()` becomes `min`/`max` by policy.
- Read the policy from a client attribute `acr.reduction.policy` (fallback realm, mirroring
  `getAcrLoaMap(client)`→realm); enum `ReductionPolicy { MINIMUM (default), MAXIMUM }`.
- `AuthorizationEndpoint`: replace the inline `acrValues.stream()…min().ifPresent(...)`
  (`AuthorizationEndpoint.java:388`) with the helper.

**Notes**
- The raw `acr_values` param is already stored as a client note (via `performActionOnParameters`), so the
  full preference list remains available to authenticators — no change needed there.
- RFC 9470 frames the list as *preference-ordered*; `MAXIMUM` is a security-max policy (compliant, since
  selection is implementation-defined). A future `PREFERENCE_ORDER` policy could be added the same way.

**Compatibility:** default `MINIMUM` reproduces today's `.min()`.

---

## #3 — Realm-level Default ACR Values

**Goal:** clients without their own `default.acr.values` inherit a realm default (our realm-attribute
fallback), symmetric with the realm-level ACR-to-LoA map.

**Files**
- Behaviour: `services/.../protocol/oidc/utils/AcrUtils.java` (`getDefaultAcrValues`, `:247`)
- Model/representation/UI: `RealmModel` (+ `jpa`/`infinispan` adapters), `RealmRepresentation`,
  `RealmManager` import/export, and the admin console Realm Settings form.

**Changes**
- Core one-liner (makes it work for *all* flows, endpoint + condition):

  ```java
  public static List<String> getDefaultAcrValues(ClientModel client) {
      List<String> v = OIDCAdvancedConfigWrapper.fromClientModel(client)
              .getAttributeMultivalued(Constants.DEFAULT_ACR_VALUES);
      if (v.isEmpty()) {                                   // NEW: fall back to the realm default
          String realmDefault = client.getRealm().getAttribute(Constants.DEFAULT_ACR_VALUES);
          if (realmDefault != null && !realmDefault.isBlank())
              v = Arrays.asList(realmDefault.trim().split("\\s+"));
      }
      return v;
  }
  ```
- Surface `defaultAcrValues` on `RealmRepresentation` + a **Realm Settings** field (the model/UI is the
  bulk of the work; the behaviour is the fallback above). Interacts correctly with the existing
  `enforceMinimumAcr` floor and with #2.

**Compatibility:** no realm attribute set → unchanged.

---

## #4 — RFC 9470 `unmet_authentication_requirements` error  — *tracked in keycloak/keycloak#23531*

> This gap already has an open upstream issue (**#23531**), which notes it should be raisable via
> `AuthenticationFlowContext#failure(AuthenticationFlowError)`. Contribute the fix there; the design
> below is the concrete shape.

**Goal:** when a requested ACR cannot be met, return the RFC 9470 OAuth error instead of a generic one.
(Most invasive of the four.)

**Files**
- `core/.../OAuthErrorException.java` — add
  `public static final String UNMET_AUTHENTICATION_REQUIREMENTS = "unmet_authentication_requirements";`
- `server-spi/.../authentication/AuthenticationFlowError.java` — add `ACR_NOT_FULFILLED`.
- `services/.../authentication/AuthenticationProcessor.java` (`:896`) — map the new flow error, and the
  OIDC `LoginProtocol.sendError` path, to `error=unmet_authentication_requirements` in the redirect
  (today the LoA condition throws `GENERIC_AUTHENTICATION_ERROR` + `Messages.ACR_NOT_FULFILLED`, which
  becomes a generic error).

**Scope note:** the resource-server `insufficient_user_authentication` `WWW-Authenticate` challenge
(RFC 9470 §4) is the RS's responsibility and is **out of scope** for the AS change.

---

## Cross-cutting

- **Feature flag:** everything stays behind `STEP_UP_AUTHENTICATION` (the LoA condition already gates on
  it via `isSupported`).
- **Backwards compatibility:** new config keys (`loa-comparison`, `acr.reduction.policy`, realm
  `default.acr.values`) all default to current behaviour; #4 only changes an error string on an
  already-failing path.
- **Suggested PR split:**
  1. **#1 + #2** together (small, high value; the exact-match condition is inert without a sane requested
     level, and vice-versa).
  2. **#3** (self-contained: one behaviour line + model/representation/UI).
  3. **#4** (touches an enum + processor + protocol error mapping; discuss the error contract first).
- **Testsuite:** extend the existing ACR/step-up OIDC tests (e.g. under
  `testsuite/integration-arquillian/tests/base/.../oidc` alongside the current LoA/step-up tests) with:
  - exact-mode routing (`acr=low` → password only; `acr=high` → passkey only);
  - `MAXIMUM` reduction (`acr_values="low high"` → high);
  - realm-default inheritance (client with no `default.acr.values` → realm default);
  - unmet request returns `error=unmet_authentication_requirements`.
  These mirror the end-to-end checks already proven in this PoC (`scripts/verify.sh`,
  `providers-src/.../AcrExactConditionIT.java`).

## Provenance

This design is a direct generalisation of the PoC's `conditional-acr-highest` /
`conditional-acr-exact` SPIs (see [`docs/authentication-flow.md`](docs/authentication-flow.md)), which
already implement #1+#2+#3 against internal SPIs and are verified end-to-end.
