// SPDX-FileCopyrightText: 2023 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

define([
    'jquery',
    '/customize/messages.js',
    '/common/hyperscript.js',
    '/common/common-interface.js',
    '/components/nthen/index.js',
    '/common/common-icons.js',
    '/components/simplewebauthn-browser/dist/bundle/index.umd.min.js',
], function ($, Messages, h, UI, nThen, Icons) {
    // SimpleWebAuthnBrowser is loaded as a side-effect UMD global.
    var SimpleWebAuthn = window.SimpleWebAuthnBrowser;

    var WebAuthn = {};

    // Returns true if this browser supports WebAuthn.
    WebAuthn.isSupported = function () {
        return !!(window.PublicKeyCredential &&
                  typeof window.PublicKeyCredential === 'function' &&
                  SimpleWebAuthn &&
                  typeof SimpleWebAuthn.startRegistration === 'function');
    };

    // Render the WebAuthn section inside `content`.
    // `enabled` — boolean, whether WebAuthn is currently active for this account.
    // `config.blockKeys` — the account's block signing keypair.
    // `cb(newState)` — called with true when registration succeeds, false when revoke succeeds.
    WebAuthn.setup = function (common, config, content, enabled, cb) {
        var sframeChan = common.getSframeChannel();
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

        if (enabled) {
            _renderRevoke(sframeChan, config, $content, cb);
        } else {
            _renderSetup(sframeChan, config, $content, cb);
        }
    };

    // ── Setup (register a new security key) ──────────────────────────────────

    var _renderSetup = function (sframeChan, config, $content, cb) {
        var button = h('button.btn.btn-primary', [Icons.get('lock'), h('span',
            Messages.webauthn_register_button || 'Register security key')]);
        var $btn = $(button);
        $content.append(h('div.cp-password-container', [
            h('p.cp-settings-mfa-hint',
                Messages.webauthn_register_hint || 'Connect your security key and click the button to register it.'),
            button
        ]));

        var spinner = UI.makeSpinner($btn);

        $btn.click(function () {
            if (!config.blockKeys) { return void UI.warn(Messages.error); }
            spinner.spin();
            $btn.prop('disabled', 'disabled');

            sframeChan.query('Q_SETTINGS_WEBAUTHN_SETUP', {
                key: config.blockKeys.sign,
            }, function (err, result) {
                spinner.hide();
                $btn.removeAttr('disabled');
                if (err || !result || !result.success) {
                    return void UI.warn((err && String(err)) || Messages.error);
                }
                cb(true);
            }, { raw: true });
        });
    };

    // ── Revoke (remove all security keys) ────────────────────────────────────

    var _renderRevoke = function (sframeChan, config, $content, cb) {
        var button = h('button.btn.disable-button', Messages.mfa_disable || 'Disable');
        var $btn = $(button);
        $content.append(h('div.cp-password-container', [
            h('p.cp-settings-mfa-hint',
                Messages.webauthn_revoke_hint || 'Connect your security key and click the button to remove WebAuthn 2FA from your account.'),
            button
        ]));

        var spinner = UI.makeSpinner($btn);

        $btn.click(function () {
            if (!config.blockKeys) { return void UI.warn(Messages.error); }
            spinner.spin();
            $btn.prop('disabled', 'disabled');

            sframeChan.query('Q_SETTINGS_WEBAUTHN_REVOKE', {
                key: config.blockKeys.sign,
                data: { command: 'WEBAUTHN_REVOKE' },
            }, function (err, result) {
                spinner.hide();
                $btn.removeAttr('disabled');
                if (err || !result || !result.success) {
                    return void UI.warn((err && String(err)) || Messages.error);
                }
                cb(false);
            }, { raw: true });
        });
    };

    return WebAuthn;
});
