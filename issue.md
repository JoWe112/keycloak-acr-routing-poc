<!--
Keycloak "Enhancement Request" template (enhancement.yml): Description, Value Proposition, Goals,
Non-Goals (all required), then Discussion (link — non-small enhancements should be raised in
GitHub Discussions → Ideas first) and Notes. Labels kind/enhancement + status/triage are auto-applied.
Issue title (plain text — GitHub titles don't render Markdown):
OIDC: support ACR Comparison (exact/minimum/maximum) for acr_values — parity with SAML step-up
-->

## Description

SAML step-up in Keycloak already honours `RequestedAuthnContext Comparison` with **exact / minimum /
maximum** semantics (`SamlProtocolUtils.checkLoAExact/checkLoAMinimum/checkLoAMaximum`, feature
`STEP_UP_AUTHENTICATION_SAML`). The **OIDC side has no equivalent**: a multi-valued `acr_values` is always
reduced to its **minimum**, and the `Condition - Level of Authentication` authenticator only supports
cumulative (`>=`) matching. This enhancement brings the same `Comparison` model to the OIDC `acr_values`
path, so ACR-driven authentication behaves the same over OIDC as it already does over SAML. (Behaviour
confirmed against tag `26.7.1`.)

## Value Proposition

- **Disjoint ACR → method selection over OIDC** — e.g. "`acr=loa/low` ⇒ password only; `acr=loa/high` ⇒
  passkey only". Impossible today, because the LoA condition is cumulative (the higher level also runs the
  lower method).
- **Honour multi-valued `acr_values`** (RFC 9470 §3 — a space-separated preference list) instead of
  silently collapsing it to the minimum, so a client can request "any of these, prefer the strongest".
- **Remove an OIDC/SAML asymmetry** — the same client intent should yield the same result regardless of
  protocol; SAML already supports this.
- **Fewer internal-API workarounds** — adopters currently need custom authenticator SPIs that reach into
  internal APIs (`AcrStore`, `LoAUtil`, `AcrUtils`) to get this behaviour.

## Goals

- Add a **comparison mode** to `Condition - Level of Authentication`: `minimum` (current, cumulative,
  default) vs `exact` (`requestedLoa == configuredLoa`).
- Make the **multi-valued `acr_values` reduction configurable**: `minimum` (default) vs `maximum`
  (extensible later to `exact-any` / `preference-order`).
- Together, `exact` + `maximum` selects exactly the **highest** requested level → OIDC parity with SAML
  `Comparison`, enabling disjoint ACR→method routing with stock authenticators.
- **Backwards compatible** — defaults reproduce today's behaviour; everything stays behind the existing
  `STEP_UP_AUTHENTICATION` feature.

## Non-Goals

- The `unmet_authentication_requirements` OAuth error — **already tracked in #23531**.
- **Realm-level Default ACR Values** (the "no `acr_values`" side) — filed as a separate enhancement.
- Any change to **SAML** step-up (it already has `Comparison`) or to the resource-server
  `insufficient_user_authentication` `WWW-Authenticate` challenge (a resource-server concern, RFC 9470 §4).
- A fully **pluggable requested-LoA SPI** (see #24556) — this is the config-driven common case, not a
  replacement for that.

## Discussion

<!-- Per the template, non-small enhancements should be raised in GitHub Discussions (Ideas) first, then
     linked here. Replace with the Discussion URL before submitting. -->
_TODO: link to a `keycloak/keycloak` Discussion (Ideas category)._

## Notes

**Current behaviour (26.7.1)**
- `ConditionalLoaAuthenticator.matchCondition` (`ConditionalLoaAuthenticator.java:54`) fires when
  `requestedLoa >= configuredLoa` (and unconditionally on a fresh session) — no exact-match mode.
- `AuthorizationEndpoint` reduces the requested ACRs with `.min()` (`AuthorizationEndpoint.java:388`) into
  the `REQUESTED_LEVEL_OF_AUTHENTICATION` note, so downstream only ever sees the minimum.

**Prior art**
- SAML: `SamlProtocolUtils.checkLoAExact/checkLoAMinimum/checkLoAMaximum` dispatched by
  `AuthnContextComparisonType` (`SamlProtocolUtils.java:356-410`), feature `STEP_UP_AUTHENTICATION_SAML`;
  recent refinements #50464 / #50465 / #50466.
- #24556 — *Custom ACR-to-LoA mapping* (SPI) — related flexibility request.

**Implementation sketch**
- Comparison mode: add a `loa-comparison` config (`minimum` | `exact`) to `ConditionalLoaAuthenticator`
  (+ its factory); in `exact`, `return requestedLoa == configuredLoa` (skip the cumulative branch);
  `onParentFlowSuccess` unchanged.
- Reduction policy: extract the acr→loa reduction into `AcrUtils.reduceToRequestedLoa(acrValues,
  acrLoaMap, policy)` with `policy` from a client (fallback realm) attribute `acr.reduction.policy`
  (`minimum` default | `maximum`); replace the inline `.min()` at `AuthorizationEndpoint.java:388`.
- Testsuite: extend the existing OIDC step-up tests with exact-mode routing and `maximum` reduction.

**Alternatives considered:** external `ConditionalAuthenticator` SPIs (`conditional-acr-exact` /
`conditional-acr-highest`) — verified end-to-end, but depend on internal SPIs flagged "may change without
notice".

**Willing to contribute:** yes — I have a PR-scoped design and a working reference implementation and am
happy to open the PR. Guidance welcome on the config surface (per-execution config vs aligning with the
SAML `Comparison` model) and whether the two goals land as one PR or two.
