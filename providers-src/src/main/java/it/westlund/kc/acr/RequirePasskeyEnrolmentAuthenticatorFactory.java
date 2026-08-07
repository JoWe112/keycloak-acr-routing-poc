/*
 * Licensed under the Apache License, Version 2.0.
 */
package it.westlund.kc.acr;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class RequirePasskeyEnrolmentAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "require-passkey-enrolment";
    private static final RequirePasskeyEnrolmentAuthenticator INSTANCE =
            new RequirePasskeyEnrolmentAuthenticator();
    private static final Requirement[] REQUIREMENT_CHOICES =
            new Requirement[]{Requirement.REQUIRED, Requirement.DISABLED};

    @Override
    public Authenticator create(KeycloakSession session) {
        return INSTANCE;
    }

    @Override
    public void init(Config.Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void close() { }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Require passkey enrolment (if none)";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "If the authenticated user has no passwordless WebAuthn (passkey) credential, adds the "
                + "webauthn-register-passwordless required action so they are prompted to create one.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}
