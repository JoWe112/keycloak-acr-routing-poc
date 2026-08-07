<!-- Ready-to-paste comment for keycloak/keycloak#23531
     "Add unmet_authentication_requirements as OAuth-Error" -->

+1 — we hit this building an OIDC step-up PoC. When a requested ACR can't be met, the client currently
gets a generic error rather than the RFC 9470 `unmet_authentication_requirements`.

Concretely, today the LoA condition fails an unmet/forced step-up as
`AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR` + `Messages.ACR_NOT_FULFILLED`, handled in
`AuthenticationProcessor` (~`AuthenticationProcessor.java:896`), which surfaces to the client as a
generic redirect error. A minimal shape (matching the `AuthenticationFlowContext#failure(...)` idea in
the description):

- add `OAuthErrorException.UNMET_AUTHENTICATION_REQUIREMENTS = "unmet_authentication_requirements"`;
- add a typed `AuthenticationFlowError.ACR_NOT_FULFILLED` that authenticators can raise via
  `AuthenticationFlowContext#failure(AuthenticationFlowError.ACR_NOT_FULFILLED)`;
- map it in the OIDC error path (`AuthenticationProcessor` → `LoginProtocol.sendError`) to
  `error=unmet_authentication_requirements` in the authorization-response redirect.

This is the **error side** of ACR-based step-up. Selecting a method by ACR is already possible natively
(client policies: `acr-condition` + `auth-flow-enforcer`, since 26.2), so an authorization request can
legitimately require, say, a certificate; when that requirement can't be met,
`unmet_authentication_requirements` is exactly the error that request should return instead of a generic
one. Happy to help with a PR here.
