<!--
GitHub Discussion opener for keycloak/keycloak → Discussions → Ideas.
Suggested title (plain text — GitHub titles don't render Markdown):
OIDC step-up: bring SAML's Comparison (exact/minimum/maximum) semantics to acr_values
Keep it conversational; the formal Enhancement issue (issue.md) can follow once there's some agreement.
-->

## OIDC step-up: bring SAML's `Comparison` (exact/minimum/maximum) semantics to `acr_values`?

While building an OIDC step-up setup — where the first-factor **method is chosen from the requested ACR**
(password / passkey / X.509 client cert) — I hit two OIDC limitations that SAML step-up doesn't have.
Floating it here in Ideas before proposing a formal enhancement.

### The gap

SAML step-up already honours `RequestedAuthnContext Comparison` with **exact / minimum / maximum**
semantics (`SamlProtocolUtils.checkLoAExact/checkLoAMinimum/checkLoAMaximum`, behind
`STEP_UP_AUTHENTICATION_SAML`). The **OIDC side has no equivalent**:

1. **`Condition - Level of Authentication` is cumulative only** (`requestedLoa >= configuredLoa`). There's
   no "exact" mode, so you can't express "`acr=X` ⇒ *exactly* method A" — a higher level always also runs
   the lower method.
2. **Multi-valued `acr_values` is always collapsed to its minimum.** `acr_values` is a space-separated
   preference list (RFC 9470 §3), but `AuthorizationEndpoint` reduces it with `.min()`, so
   `acr_values="silver gold"` silently becomes `silver`. There's no way to pick the highest acceptable
   level or honour preference order.

Net effect: the same client intent behaves differently depending on whether the client speaks OIDC or
SAML.

### The idea

Two small, backwards-compatible additions behind the existing `STEP_UP_AUTHENTICATION` feature:

- a **comparison mode** on the LoA condition — `minimum` (today's default) vs `exact`;
- a **configurable reduction** for multi-valued `acr_values` — `minimum` (default) vs `maximum` (and maybe
  later `exact-any` / preference-order).

Together, `exact` + `maximum` means "authenticate at exactly the highest requested level", which is what
makes disjoint ACR→method selection possible over OIDC.

### Concrete example

Realm map `low→1, high→2`:

- **Today:** `acr_values="low high"` → collapses to `1` → password.
- **With `maximum`:** `acr_values="low high"` → `2` → passkey.
- **With `exact` on the level-2 subflow:** it runs *only* for level-2 requests, not as a step on top of
  level 1.

### Open questions

- Mirror the SAML `Comparison` model directly (share the enum/semantics), or an OIDC-specific config?
- Where should the reduction policy live — **client**, **realm**, or both? And the comparison mode:
  per-execution on the condition (like `loa-condition-level`)?
- Is `maximum` enough to start, or should `exact-any` / preference-order come in from the beginning?
- Any concerns about the interplay with **Minimum ACR Value** (the floor) and the `acr` claim mapping?

I have a working reference implementation (as external `ConditionalAuthenticator` SPIs) plus a PR-scoped
design, and I'm happy to do the PR if there's appetite. Curious what the maintainers and community think.
