package com.tcc.consulting.opensourced.rhbk.auth.email;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.common.util.SecretGenerator;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TccRhbkEmailTwoFactorAuthForm extends AbstractUsernameFormAuthenticator {
    private static final Logger log = Logger.getLogger(TccRhbkEmailTwoFactorAuthForm.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        challenge(context, null);
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        sendCodeByEmail(context);

        LoginFormsProvider loginForm = context.form().setExecution(context.getExecution().getId());
        if (error != null) {
            if (field != null) {
                loginForm.addError(new FormMessage(field, error));
            } else {
                loginForm.setError(error);
            }
        }
        Response response = loginForm.createForm("email-2fa-form.ftl");
        context.challenge(response);
        return response;
    }

    private void sendCodeByEmail(AuthenticationFlowContext context) {
        AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        if (authSession.getAuthNote(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE) != null) {
            // skip sending email code when the session has already got the auth code
            return;
        }

        int length = TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_DEFAULT_LENGTH;
        int ttl = TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_DEFAULT_TTL;
        if (authConfig != null) {
            // obtain config values from settings
            length = Integer.parseInt(authConfig.getConfig()
                    .get(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE_LENGTH));
            ttl = Integer.parseInt(authConfig.getConfig()
                    .get(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE_TTL));
        }

        String codeGenerated = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
        sendEmailWithGeneratedCode(context.getSession(), context.getRealm(), context.getUser(), codeGenerated, ttl);
        authSession.setAuthNote(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE, codeGenerated);
        authSession.setAuthNote(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE_TTL,
                Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        UserModel userModel = context.getUser();
        if (!enabledUser(context, userModel)) {
            // Skip when use is not enabled
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("EMAIL_CODE_RESEND")) {
            resetEmailCode(context);
            challenge(context, null);
            return;
        }

        if (formData.containsKey("EMAIL_CODE_CANCEL")) {
            resetEmailCode(context);
            context.resetFlow();
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String code = authSession.getAuthNote(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE);
        String ttl = authSession.getAuthNote(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE_TTL);
        String enteredCode = formData.getFirst(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE);

        if (enteredCode.equals(code)) {
            if (Long.parseLong(ttl) < System.currentTimeMillis()) {
                // check if the token expired
                context.getEvent().user(userModel).error(Errors.EXPIRED_CODE);
                Response challengeResponse = challenge(context, Messages.EXPIRED_ACTION_TOKEN_SESSION_EXISTS,
                        TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE);
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challengeResponse);
            } else {
                // Token is not expired
                resetEmailCode(context);
                context.success();
            }
        } else {
            // Code enterred is not correct
            AuthenticationExecutionModel execution = context.getExecution();
            if (execution.isRequired()) {
                context.getEvent().user(userModel).error(Errors.INVALID_USER_CREDENTIALS);
                Response challengeResponse = challenge(context, Messages.INVALID_ACCESS_CODE,
                        TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            } else if (execution.isConditional() || execution.isAlternative()) {
                context.attempted();
            }
        }
    }

    @Override
    protected String disabledByBruteForceError() {
        return Messages.INVALID_ACCESS_CODE;
    }

    private void resetEmailCode(AuthenticationFlowContext context) {
        context.getAuthenticationSession()
                .removeAuthNote(TccRhbkEmailTwoFactorAuthConstants.TCC_RHBK_EMAIL_TWOFACTOR_AUTH_CODE);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getEmail() != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    private void sendEmailWithGeneratedCode(KeycloakSession session, RealmModel realm, UserModel user, String code,
            int ttl) {
        if (user.getEmail() == null) {
            log.warnf("No email defined in the user account. realm=%s user=%s", realm.getId(), user.getUsername());
            throw new AuthenticationFlowException(AuthenticationFlowError.INVALID_USER);
        }

        Map<String, Object> emailBodyAttributes = new HashMap<>();
        emailBodyAttributes.put("username", user.getUsername());
        emailBodyAttributes.put("code", code);
        emailBodyAttributes.put("ttl", ttl);

        String realmName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
        List<Object> subjectParams = List.of(realmName);
        try {
            EmailTemplateProvider emailProvider = session.getProvider(EmailTemplateProvider.class);
            emailProvider.setRealm(realm);
            emailProvider.setUser(user);
            emailProvider.send("emailCodeSubject", subjectParams, "email-2f2-emailbody.ftl", emailBodyAttributes);
        } catch (EmailException eex) {
            log.errorf(eex, "Cannot send verification code via email for realm %s from user %s", realm.getId(),
                    user.getUsername());
        }
    }
}
