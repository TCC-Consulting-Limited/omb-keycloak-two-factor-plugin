<#import "template.ftl" as layout>
    <@layout.registrationLayout displayMessage=!messagesPerField.existsError('TccRhbkEmailTwoFactorAuthCode'); section>
        <#if section="header">
            ${msg("doLogIn")}
            <#elseif section="form">
                <form id="kc-otp-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}"
                    method="post">
                    <div class="${properties.kcFormGroupClass!}">
                        <div class="${properties.kcLabelWrapperClass!}">
                            <label for="TccRhbkEmailTwoFactorAuthCode" class="${properties.kcLabelClass!}">
                                ${msg("loginOtpOneTime")}
                            </label>
                        </div>
                        <div class="${properties.kcInputWrapperClass!}">
                            <input id="TccRhbkEmailTwoFactorAuthCode" name="TccRhbkEmailTwoFactorAuthCode" autocomplete="off" type="text" class="${properties.kcInputClass!}"
                                autofocus aria-invalid="<#if messagesPerField.existsError('TccRhbkEmailTwoFactorAuthCode')>true</#if>" />
                            <#if messagesPerField.existsError('TccRhbkEmailTwoFactorAuthCode')>
                                <span id="input-error-otp-code" class="${properties.kcInputErrorMessageClass!}"
                                    aria-live="polite">
                                    ${kcSanitize(messagesPerField.get('TccRhbkEmailTwoFactorAuthCode'))?no_esc}
                                </span>
                            </#if>
                        </div>
                    </div>
                    <div class="${properties.kcFormGroupClass!}">
                        <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                            <div class="${properties.kcFormOptionsWrapperClass!}">
                            </div>
                        </div>
                        <div id="kc-form-buttons">
                            <div class="${properties.kcFormButtonsWrapperClass!}">
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="login" type="submit" value="${msg("doLogIn")}" />
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="resendToken" type="submit" value="${msg("resendToken")}" />
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="cancel" type="submit" value="${msg("doCancel")}" />
                            </div>
                        </div>
                    </div>
                </form>
        </#if>
    </@layout.registrationLayout>