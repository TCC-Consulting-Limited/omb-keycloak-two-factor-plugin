package com.tcc.consulting.opensourced.rhbk.auth.email;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

public class TccRhbkEmailTwoFactorAuthFormFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "email-authenticator";
    public static final TccRhbkEmailTwoFactorAuthForm SINGLETON = new TccRhbkEmailTwoFactorAuthForm();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "TCC OMB Email OTP";
    }

    @Override
    public String getReferenceCategory() {
        return OTPCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "OMB Email 2fa Authenticator powered by TCC.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                new ProviderConfigProperty(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE_LENGTH,
                        "Code length",
                        "The number of digits of the generated code.",
                        ProviderConfigProperty.STRING_TYPE,
                        String.valueOf(
                                TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_DEFAULT_LENGTH)),
                new ProviderConfigProperty(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE_TTL,
                        "Time-to-live",
                        "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE,
                        String.valueOf(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_DEFAULT_TTL)));
    }

    @Override
    public void close() {
        // DO NOTHING
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // DO NOTHING
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // DO NOTHINGs
    }
}
