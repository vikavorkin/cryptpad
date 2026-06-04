// SPDX-FileCopyrightText: 2023 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

define([
    'jquery',
    '/customize/messages.js',
    '/common/hyperscript.js',
    '/common/common-interface.js',
    '/components/nthen/index.js',
    '/customize.dist/login.js',
    '/common/common-icons.js',
    '/components/simplewebauthn-browser/dist/bundle/index.umd.min.js',
], function ($, Messages, h, UI, nThen, Login, Icons, SimpleWebAuthn) {

    var WebAuthn = {};

    WebAuthn.isSupported = function () {
        return !!(window.PublicKeyCredential &&
                  typeof window.PublicKeyCredential === 'function' &&
                  SimpleWebAuthn &&
                  typeof SimpleWebAuthn.startRegistration === 'function');
    };

    // Main entry point called from settings/inner.js.
    // Mirrors the signature of MFA.totpSetup:
    //   common       - the common API object (provides getSframeChannel)
    //   config       - { accountName, origin }
    //   content      - DOM node to render into
    //   enabled      - boolean, whether WebAuthn is currently active
    //   cb(newState) - called with true on enable, false on disable
    WebAuthn.setup = function (common, config, content, enabled, cb) {
        var sframeChan = common.getSframeChannel();
        var accountName = config.accountName;

        var $content = $(content).empty();

        $content.append(h('div.cp-settings-mfa-hint.cp-settings-mfa-status' + (enabled ? '.mfa-enabled' : '.mfa-disabled'), [
            (enabled ? Icons.get('check') : Icons.get('close')),
            h('span', enabled ? Messages.mfa_status_on : Messages.mfa_status_off)
        ]));

        if (!WebAuthn.isSupported()) {
            $content.append(h('div.alert.alert-warning',
                Messages.webauthn_unsupported || 'Your browser does not support security keys (WebAuthn).'));
            return;
        }

        // Both setup and revoke need block keys, which require the user's password.
        var pwInput;
        var actionButton = h('button.btn' + (enabled ? '' : '.btn-primary'), [
            enabled ? Icons.get('unlocked') : Icons.get('lock'),
            h('span', enabled
                ? (Messages.mfa_disable || 'Disable')
                : (Messages.webauthn_register_button || 'Register security key'))
        ]);
        var $actionButton = $(actionButton);
        var ssoSeed;

        $content.append(h('div.cp-password-container', [
            h('label.cp-settings-mfa-hint', { for: 'cp-webauthn-password' },
                enabled
                    ? (Messages.mfa_revoke_label || 'Enter your password to disable WebAuthn')
                    : (Messages.mfa_setup_label || 'Enter your password to register a security key')),
            pwInput = h('input#cp-webauthn-password', {
                type: 'password',
                placeholder: Messages.login_password,
            }),
            actionButton,
        ]));

        $(pwInput).on('keyup', function (e) {
            if (e.which === 13) { $actionButton.click(); }
        });

        var spinner = UI.makeSpinner($actionButton);

        $actionButton.click(function () {
            var password = $(pwInput).val();
            if (!password) { return void UI.warn(Messages.login_noSuchUser); }

            spinner.spin();
            $(pwInput).prop('disabled', 'disabled');
            $actionButton.prop('disabled', 'disabled');

            var blockKeys;

            nThen(function (waitFor) {
                sframeChan.query('Q_SETTINGS_GET_SSO_SEED', {}, waitFor(function (err, obj) {
                    if (!obj || !obj.seed) { return; }
                    ssoSeed = obj.seed;
                }));
            }).nThen(function (waitFor) {
                var next = waitFor();
                setTimeout(function () {
                    var salt = ssoSeed || accountName;
                    Login.Cred.deriveFromPassphrase(salt, password, Login.requiredBytes, function (bytes) {
                        var result = Login.allocateBytes(bytes);
                        sframeChan.query('Q_SETTINGS_CHECK_PASSWORD', {
                            blockHash: result.blockHash,
                        }, function (err, obj) {
                            if (!obj || !obj.correct) {
                                spinner.hide();
                                UI.warn(Messages.login_noSuchUser);
                                $actionButton.removeAttr('disabled');
                                $(pwInput).removeAttr('disabled');
                                waitFor.abort();
                                return;
                            }
                            spinner.done();
                            blockKeys = result.blockKeys;
                            next();
                        });
                    });
                }, 100);
            }).nThen(function () {
                $(pwInput).closest('.cp-password-container').remove();
                if (enabled) {
                    _doRevoke(sframeChan, blockKeys, $content, cb);
                } else {
                    _doSetup(sframeChan, blockKeys, $content, cb);
                }
            });
        });
    };

    // ── Setup (register a new security key) ──────────────────────────────────

    var _doSetup = function (sframeChan, blockKeys, $content, cb) {
        var button = h('button.btn.btn-primary', [
            Icons.get('lock'),
            h('span', Messages.webauthn_register_button || 'Register security key')
        ]);
        var $btn = $(button);
        $content.append(h('div.cp-password-container', [
            h('p.cp-settings-mfa-hint',
                Messages.webauthn_register_hint || 'Click the button and touch your security key when prompted.'),
            button
        ]));

        var spinner = UI.makeSpinner($btn);

        $btn.click(function () {
            spinner.spin();
            $btn.prop('disabled', 'disabled');

            sframeChan.query('Q_SETTINGS_WEBAUTHN_SETUP', {
                key: blockKeys.sign,
            }, function (err, result) {
                spinner.hide();
                $btn.removeAttr('disabled');
                if (err || !result || !result.success) {
                    console.error(err);
                    return void UI.warn(Messages.error);
                }
                cb(true);
            }, { raw: true });
        });

        $btn.click();
    };

    // ── Revoke (remove WebAuthn) ──────────────────────────────────────────────

    var _doRevoke = function (sframeChan, blockKeys, $content, cb) {
        var button = h('button.btn.disable-button', Messages.mfa_revoke_button || 'Disable WebAuthn');
        var $btn = $(button);
        $content.append(h('div.cp-password-container', [
            h('p.cp-settings-mfa-hint',
                Messages.webauthn_revoke_hint || 'Click the button and touch your security key to remove WebAuthn 2FA.'),
            button
        ]));

        var spinner = UI.makeSpinner($btn);

        $btn.click(function () {
            spinner.spin();
            $btn.prop('disabled', 'disabled');

            sframeChan.query('Q_SETTINGS_WEBAUTHN_REVOKE', {
                key: blockKeys.sign,
                data: { command: 'WEBAUTHN_REVOKE' },
            }, function (err, result) {
                spinner.hide();
                $btn.removeAttr('disabled');
                if (err || !result || !result.success) {
                    console.error(err);
                    return void UI.warn(Messages.error);
                }
                cb(false);
            }, { raw: true });
        });

        $btn.click();
    };

    return WebAuthn;
});
