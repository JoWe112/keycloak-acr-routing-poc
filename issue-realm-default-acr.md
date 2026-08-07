<!--
Keycloak "Enhancement Request" template (enhancement.yml): Description, Value Proposition, Goals,
Non-Goals (required), then Discussion (link — Ideas first) and Notes.
Issue title (plain text — GitHub titles don't render Markdown):
OIDC: realm-level Default ACR Values (inherited by clients without their own)
-->

## Description

`default.acr.values` is a **client-only** attribute — `AcrUtils.getDefaultAcrValues(ClientModel)`
(`AcrUtils.java:247`) reads only the client. There is no realm-wide default and no Realm Settings field,
so the same default must be repeated on every client. By contrast the ACR-to-LoA map already falls back to
the realm (`AcrUtils.getAcrLoaMap(client)` → `getAcrLoaMap(realm)`, `AcrUtils.java:141`). This enhancement
adds the symmetric realm-level fallback for **Default ACR Values**. (Confirmed against tag `26.7.1`.)

## Value Proposition

- Set a sensible **realm-wide default ACR once**, instead of duplicating `default.acr.values` across every
  client — less repetition and drift.
- Keep **client-level as an override** for clients that need a different default.
- Consistent with the existing realm-level ACR-to-LoA map, which already has this fallback.

## Goals

- When a client has no `default.acr.values` and the request carries no `acr_values`, fall back to a
  **realm-level default**, applied uniformly by the authorization endpoint and the LoA condition.
- Expose it as a **Realm Settings** field, mirroring the client-level "Default ACR Values".
- Interact correctly with the client **Minimum ACR Value** floor and any multi-value reduction policy.
- **Backwards compatible** — no realm default set ⇒ unchanged; behind `STEP_UP_AUTHENTICATION`.

## Non-Goals

- Changing how the *requested* ACR is compared/selected (that is the companion "OIDC ACR `Comparison`"
  enhancement).
- Broker/IdP forwarding of Default/Minimum ACR (see #42625).
- SAML.

## Discussion

<!-- Raise in GitHub Discussions → Ideas first, then link here. -->
_TODO: link to a `keycloak/keycloak` Discussion (Ideas category)._

## Notes

**Implementation sketch**
- Behaviour (one-liner): in `AcrUtils.getDefaultAcrValues(client)`, when the client list is empty, fall
  back to `client.getRealm().getAttribute(Constants.DEFAULT_ACR_VALUES)` — mirroring the existing realm
  fallback for the ACR-to-LoA map. This makes it apply to all flows.
- Model/UI: add `defaultAcrValues` to `RealmRepresentation` (+ `RealmModel` getter/setter, import/export)
  and a Realm Settings field.

**Related**
- #42625 — inconsistent handling of `acr_values` / Default & Minimum ACR when brokering (adjacent).

**Alternatives considered:** in a PoC we stored the realm default as a realm attribute and read it in a
custom conditional authenticator's fallback — but that only works for flows using that SPI; a native
change to `getDefaultAcrValues` makes it apply everywhere.

**Willing to contribute:** yes — happy to open the PR (small behaviour change + `RealmRepresentation` /
Realm Settings field). Guidance welcome on whether the realm default should be a first-class
`RealmRepresentation` field or a realm attribute.
