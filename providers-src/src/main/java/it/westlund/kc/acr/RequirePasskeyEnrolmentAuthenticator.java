/*
 * Licensed under the Apache License, Version 2.0.
 */
package it.westlund.kc.acr;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;

/**
 * If the (already identified + verified) user has no passwordless WebAuthn
 * credential (passkey), adds the {@code webauthn-register-passwordless} required
 * action so the user is prompted to create one after the flow completes.
 *
 * Keycloak has no in-flow passkey *registration* authenticator — enrolment is a
 * required action — so this bridges "user just verified with a password but has
 * no passkey" to "offer them a passkey".
 */
public class RequirePasskeyEnrolmentAuthenticator implements Authenticator {

    static final String REGISTER_PASSWORDLESS = "webauthn-register-passwordless";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user != null) {
            boolean hasPasskey = user.credentialManager()
                    .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS)
                    .findAny().isPresent();
            if (!hasPasskey) {
                // Scope enrolment to THIS authentication only (auth session), not
                // the user account -- otherwise the action persists and would nag
                // the user on every later login, including the password-only path.
                context.getAuthenticationSession().addRequiredAction(REGISTER_PASSWORDLESS);
            }
        }
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // no-op
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }
}
