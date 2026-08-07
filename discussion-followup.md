<!-- Paste as a follow-up comment in the discussion you already opened. -->

**Update / correction to myself.** The premise above — that Keycloak can't select the login method
disjointly by ACR and that you'd need a custom authenticator — is **not right for Keycloak 26.2+**. It's
already possible **natively**, no custom code:

Since 26.2 there's *"Dynamic Authentication Flow selection using Client Policies"*. You combine two
built-ins:

- **`acr-condition`** (client-policy condition) — matches the requested ACR (`AcrUtils.getAcrValues(...)
  .contains(<acr>)`, i.e. exact membership), and
- **`auth-flow-enforcer`** (client-policy executor) — routes the request to a whole **authentication
  flow** and sets the achieved LoA (`auth-flow-loa`).

So you make one flow per method (`flow-password`, `flow-passkey`, `flow-x509`) and one policy per ACR
(`acr=low → flow-password`, `acr=high → flow-passkey`, `acr=x509 → flow-x509`). No `acr_values` → the
client's Default ACR Values decides. Multiple `acr_values` → order the policies and the last match wins
(so you can make the highest requested method win). The token `acr` comes from `auth-flow-loa` via the
ACR-to-LoA map. Docs: Server Admin Guide → *Using Client Policies to Select an Authentication Flow*.

I verified this end-to-end (password / passkey / X.509 cert, single and multi-valued `acr_values`) — a
full runnable how-to + PoC is here: <link>. I've since removed the custom SPIs from my setup.

**So what's actually still missing natively** (the parts that motivated this thread, minus what 26.2
already solved):

1. **Realm-level Default ACR Values.** `default.acr.values` is client-only
   (`AcrUtils.getDefaultAcrValues` reads only the client), so a realm-wide default that clients without
   their own inherit would avoid repeating it — symmetric with the ACR-to-LoA map, which already falls
   back to the realm.
2. **`unmet_authentication_requirements`** OAuth error (RFC 9470) when a requested ACR can't be met —
   already tracked in #23531.

(Minor: the `Condition - Level of Authentication` authenticator still collapses a multi-valued
`acr_values` to its *minimum*; the flow-selection approach avoids that by picking a whole flow, so it's
only an issue if you rely on the LoA conditions directly.)

Happy to help turn (1) into a PR if there's interest.
