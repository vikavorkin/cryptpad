// SPDX-FileCopyrightText: 2023 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const Nacl = require('tweetnacl/nacl-fast');
const nThen = require('nthen');
const Util = require('../common-util');

const MFA = require('../storage/mfa');
const Sessions = require('../storage/sessions');
const BlockStore = require('../storage/block');
const Block = require('../commands/block');
const config = require('../load-config');

const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const Commands = module.exports;

var isValidBlockId = Block.isValidBlockId;

var EXPIRATION = (config.otpSessionExpiration || 7 * 24) * 3600 * 1000;

// WebAuthn relying party settings. Must match the domain serving CryptPad.
// rpId must be the effective domain (no port, no scheme).
var getRpConfig = function () {
    var httpUnsafeOrigin = config.httpUnsafeOrigin || '';
    var defaultOrigin = httpUnsafeOrigin || 'http://localhost:3000';
    var webauthnCfg = config.webauthn || {};
    var origin = webauthnCfg.origin || defaultOrigin;
    var rpId = webauthnCfg.rpId || (function () {
        try { return new URL(origin).hostname; } catch (e) { return 'localhost'; }
    }());
    var rpName = webauthnCfg.rpName || 'CryptPad';
    return { rpId, rpName, origin };
};

// Generates a random base64url challenge string for WebAuthn operations.
var generateChallenge = function () {
    return Buffer.from(Nacl.randomBytes(32)).toString('base64url');
};

// Create an authenticated session for publicKey, mirroring the pattern in totp.js.
const makeSession = (Env, publicKey, oldKey, ssoSession, cb) => {
    const sessionId = ssoSession || Sessions.randomId();
    let SSOUtils = Env.plugins && Env.plugins.SSO && Env.plugins.SSO.utils;
    oldKey = oldKey || publicKey;

    let isUpdate = false;
    nThen(function (w) {
        if (!ssoSession || !SSOUtils) { return; }
        SSOUtils.readBlock(Env, oldKey, w((err) => {
            if (err === 'ENOENT') { return; }
            if (err) {
                w.abort();
                return void cb('WEBAUTHN_VALIDATE_READ_SSO');
            }
            isUpdate = true;
        }));
    }).nThen(function (w) {
        let sessionData = {
            mfa: {
                type: 'webauthn',
                exp: (+new Date()) + EXPIRATION
            }
        };
        var then = w(function (err) {
            if (err) {
                Env.Log.error('WEBAUTHN_VALIDATE_SESSION_WRITE', {
                    error: Util.serializeError(err),
                    publicKey,
                    sessionId,
                });
                w.abort();
                return void cb('SESSION_WRITE_ERROR');
            }
        });
        if (isUpdate) {
            Sessions.update(Env, publicKey, oldKey, sessionId, JSON.stringify(sessionData), then);
        } else {
            Sessions.write(Env, publicKey, sessionId, JSON.stringify(sessionData), then);
        }
    }).nThen(function () {
        cb(void 0, { bearer: sessionId });
    });
};

const readMFA = (Env, publicKey, cb) => {
    MFA.read(Env, publicKey, function (err, content) {
        if (err) {
            Env.Log.error('WEBAUTHN_MFA_READ', { error: err, publicKey });
            return void cb('NO_MFA_CONFIGURED');
        }
        var parsed = Util.tryParse(content);
        if (!parsed) { return void cb('INVALID_CONFIGURATION'); }
        cb(void 0, parsed);
    });
};

var findCredential = function (credentials, credentialId) {
    return credentials.find(c => c.credentialId === credentialId);
};

// Verify a WebAuthn assertion using the stored mfaData credentials.
// Updates signCount in-place and calls cb(err, mfaData).
var verifyAssertion = function (assertionResponse, webauthnChallenge, webauthnRpId, mfaData, Env, publicKey, cb) {
    var rp = getRpConfig();
    var rpId = webauthnRpId || rp.rpId;
    var credentials = mfaData.credentials || [];

    var credentialIdStr = Buffer.from(
        assertionResponse.rawId || assertionResponse.id || '',
        'base64url'
    ).toString('base64url');
    var stored = findCredential(credentials, credentialIdStr);
    if (!stored) { return void cb('UNKNOWN_CREDENTIAL'); }

    verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: webauthnChallenge,
        expectedOrigin: rp.origin,
        expectedRPID: rpId,
        credential: {
            id: Buffer.from(stored.credentialId, 'base64url'),
            publicKey: Buffer.from(stored.publicKey, 'base64url'),
            counter: stored.signCount,
            transports: stored.transports,
        },
    }).then(function (verification) {
        if (!verification.verified) { return void cb('WEBAUTHN_VERIFICATION_FAILED'); }
        stored.signCount = verification.authenticationInfo.newCounter;
        cb(void 0, mfaData);
    }).catch(function (err) {
        Env.Log.error('WEBAUTHN_ASSERTION_VERIFY_ERROR', {
            error: Util.serializeError(err),
            publicKey,
        });
        cb('WEBAUTHN_VERIFICATION_FAILED');
    });
};

// ─── SETUP ───────────────────────────────────────────────────────────────────

// Stage 1: validate the request and return a WebAuthn registration challenge.
// The challenge is injected into body (which Challenge.write will persist) so that
// .complete() can retrieve it when verifying the attestation response.
const WEBAUTHN_SETUP = Commands.WEBAUTHN_SETUP = function (Env, body, cb) {
    const { publicKey } = body;

    if (!isValidBlockId(publicKey)) { return void cb('INVALID_KEY'); }

    MFA.read(Env, publicKey, function (err, existing) {
        if (!err) {
            // MFA already exists — only allowed if it is WebAuthn (adding a second key)
            var parsed = Util.tryParse(existing);
            if (!parsed || parsed.method !== 'WebAuthn') {
                return void cb('EEXISTS');
            }
            var creds = parsed.credentials || [];
            var maxKeys = (config.webauthn && config.webauthn.maxKeys) || 5;
            if (creds.length >= maxKeys) { return void cb('TOO_MANY_KEYS'); }
        } else if (err.code !== 'ENOENT') {
            return void cb(err);
        }

        var rp = getRpConfig();
        var challenge = generateChallenge();
        // Inject into body so Challenge.write stores the challenge for .complete() to use.
        body.webauthnChallenge = challenge;
        body.webauthnRpId = rp.rpId;

        generateRegistrationOptions({
            rpName: rp.rpName,
            rpID: rp.rpId,
            userID: Buffer.from(publicKey),
            userName: publicKey,
            challenge: Buffer.from(challenge, 'base64url'),
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'discouraged',
                userVerification: 'preferred',
            },
        }).then(function (options) {
            cb(void 0, { registrationOptions: options });
        }).catch(function (err) {
            Env.Log.error('WEBAUTHN_SETUP_OPTIONS_ERROR', { error: Util.serializeError(err) });
            cb('WEBAUTHN_OPTIONS_FAILED');
        });
    });
};

// stage1ServerExtensions lists fields this command injects into body during Stage 1.
// These are NOT part of the client-signed payload (the client never sees them);
// handleResponse strips them before signature verification and keeps them for .complete().
WEBAUTHN_SETUP.stage1ServerExtensions = ['webauthnChallenge', 'webauthnRpId'];
WEBAUTHN_SETUP.stage2Extensions = ['attestationResponse'];

WEBAUTHN_SETUP.complete = function (Env, body, cb) {
    var { publicKey, webauthnChallenge, webauthnRpId, attestationResponse, session } = body;

    if (!attestationResponse) { return void cb('MISSING_ATTESTATION'); }

    var rp = getRpConfig();
    var rpId = webauthnRpId || rp.rpId;

    nThen(function (w) {
        BlockStore.check(Env, publicKey, w(function (err) {
            if (err) {
                Env.Log.error('WEBAUTHN_SETUP_NO_BLOCK', { publicKey });
                w.abort();
                return void cb('NO_BLOCK');
            }
        }));
    }).nThen(function (w) {
        verifyRegistrationResponse({
            response: attestationResponse,
            expectedChallenge: webauthnChallenge,
            expectedOrigin: rp.origin,
            expectedRPID: rpId,
        }).then(function (verification) {
            if (!verification.verified) {
                w.abort();
                return void cb('WEBAUTHN_VERIFICATION_FAILED');
            }

            var info = verification.registrationInfo;
            var newCredential = {
                credentialId: Buffer.from(info.credential.id).toString('base64url'),
                publicKey: Buffer.from(info.credential.publicKey).toString('base64url'),
                signCount: info.credential.counter,
                transports: (attestationResponse.response && attestationResponse.response.transports) || [],
                aaguid: info.aaguid || '',
                created: new Date().toISOString(),
            };

            MFA.read(Env, publicKey, w(function (err, existing) {
                var credentials = [];
                if (!err) {
                    var parsed = Util.tryParse(existing);
                    if (parsed && parsed.method === 'WebAuthn' && Array.isArray(parsed.credentials)) {
                        credentials = parsed.credentials;
                    }
                }
                credentials.push(newCredential);

                var data = {
                    method: 'WebAuthn',
                    credentials: credentials,
                    creation: new Date().toISOString(),
                };

                MFA.write(Env, publicKey, JSON.stringify(data), w(function (err) {
                    if (err) {
                        w.abort();
                        Env.Log.error('WEBAUTHN_SETUP_STORAGE_FAILURE', { publicKey, error: err });
                        return void cb('STORAGE_FAILURE');
                    }
                    makeSession(Env, publicKey, null, session, cb);
                }));
            }));
        }).catch(function (err) {
            Env.Log.error('WEBAUTHN_SETUP_VERIFY_ERROR', { error: Util.serializeError(err) });
            w.abort();
            cb('WEBAUTHN_VERIFICATION_FAILED');
        });
    });
};

// ─── VALIDATE ────────────────────────────────────────────────────────────────

// Stage 1: read existing credentials and return a WebAuthn authentication challenge.
const WEBAUTHN_VALIDATE = Commands.WEBAUTHN_VALIDATE = function (Env, body, cb) {
    var { publicKey } = body;

    if (!isValidBlockId(publicKey)) { return void cb('INVALID_KEY'); }

    readMFA(Env, publicKey, function (err, mfaData) {
        if (err) { return void cb(err); }
        if (mfaData.method !== 'WebAuthn') { return void cb('WRONG_METHOD'); }

        var credentials = mfaData.credentials || [];
        if (!credentials.length) { return void cb('NO_CREDENTIALS'); }

        var rp = getRpConfig();
        var challenge = generateChallenge();
        body.webauthnChallenge = challenge;
        body.webauthnRpId = rp.rpId;

        var allowCredentials = credentials.map(c => ({
            id: c.credentialId,
            transports: c.transports || [],
        }));

        generateAuthenticationOptions({
            rpID: rp.rpId,
            challenge: Buffer.from(challenge, 'base64url'),
            allowCredentials,
            userVerification: 'preferred',
        }).then(function (options) {
            cb(void 0, { authenticationOptions: options });
        }).catch(function (err) {
            Env.Log.error('WEBAUTHN_VALIDATE_OPTIONS_ERROR', { error: Util.serializeError(err) });
            cb('WEBAUTHN_OPTIONS_FAILED');
        });
    });
};

WEBAUTHN_VALIDATE.stage1ServerExtensions = ['webauthnChallenge', 'webauthnRpId'];
WEBAUTHN_VALIDATE.stage2Extensions = ['assertionResponse'];

WEBAUTHN_VALIDATE.complete = function (Env, body, cb) {
    var { publicKey, webauthnChallenge, webauthnRpId, assertionResponse, session } = body;

    if (!assertionResponse) { return void cb('MISSING_ASSERTION'); }

    readMFA(Env, publicKey, function (err, mfaData) {
        if (err) { return void cb(err); }
        if (mfaData.method !== 'WebAuthn') { return void cb('WRONG_METHOD'); }

        verifyAssertion(assertionResponse, webauthnChallenge, webauthnRpId, mfaData, Env, publicKey,
            function (err, updatedMfaData) {
                if (err) { return void cb(err); }
                MFA.write(Env, publicKey, JSON.stringify(updatedMfaData), function (writeErr) {
                    if (writeErr) {
                        Env.Log.error('WEBAUTHN_SIGNCOUNT_UPDATE_FAILED', { publicKey, error: writeErr });
                    }
                    makeSession(Env, publicKey, null, session, cb);
                });
            }
        );
    });
};

// ─── MFA CHECK (verify without creating a session) ───────────────────────────

// Used before sensitive operations (password change, etc.) to confirm the user
// has their security key, without establishing a full login session.
const WEBAUTHN_MFA_CHECK = Commands.WEBAUTHN_MFA_CHECK = function (Env, body, cb) {
    var { publicKey } = body;

    if (!isValidBlockId(publicKey)) { return void cb('INVALID_KEY'); }

    readMFA(Env, publicKey, function (err, mfaData) {
        if (err) { return void cb(err); }
        if (mfaData.method !== 'WebAuthn') { return void cb('WRONG_METHOD'); }

        var credentials = mfaData.credentials || [];
        if (!credentials.length) { return void cb('NO_CREDENTIALS'); }

        var rp = getRpConfig();
        var challenge = generateChallenge();
        body.webauthnChallenge = challenge;
        body.webauthnRpId = rp.rpId;

        var allowCredentials = credentials.map(c => ({
            id: c.credentialId,
            transports: c.transports || [],
        }));

        generateAuthenticationOptions({
            rpID: rp.rpId,
            challenge: Buffer.from(challenge, 'base64url'),
            allowCredentials,
            userVerification: 'preferred',
        }).then(function (options) {
            cb(void 0, { authenticationOptions: options });
        }).catch(function (err) {
            Env.Log.error('WEBAUTHN_MFA_CHECK_OPTIONS_ERROR', { error: Util.serializeError(err) });
            cb('WEBAUTHN_OPTIONS_FAILED');
        });
    });
};

WEBAUTHN_MFA_CHECK.stage1ServerExtensions = ['webauthnChallenge', 'webauthnRpId'];
WEBAUTHN_MFA_CHECK.stage2Extensions = ['assertionResponse'];

WEBAUTHN_MFA_CHECK.complete = function (Env, body, cb) {
    var { publicKey, webauthnChallenge, webauthnRpId, assertionResponse } = body;

    if (!assertionResponse) { return void cb('MISSING_ASSERTION'); }

    readMFA(Env, publicKey, function (err, mfaData) {
        if (err) { return void cb(err); }
        if (mfaData.method !== 'WebAuthn') { return void cb('WRONG_METHOD'); }

        verifyAssertion(assertionResponse, webauthnChallenge, webauthnRpId, mfaData, Env, publicKey,
            function (err, updatedMfaData) {
                if (err) { return void cb(err); }
                MFA.write(Env, publicKey, JSON.stringify(updatedMfaData), function (writeErr) {
                    if (writeErr) {
                        Env.Log.error('WEBAUTHN_SIGNCOUNT_UPDATE_FAILED', { publicKey, error: writeErr });
                    }
                    cb();
                });
            }
        );
    });
};

// ─── REVOKE ───────────────────────────────────────────────────────────────────

// Stage 1: issue a challenge the client must satisfy to revoke WebAuthn registration.
// body.credentialId (optional): if provided, only that key is removed; otherwise all are removed.
const WEBAUTHN_REVOKE = Commands.WEBAUTHN_REVOKE = function (Env, body, cb) {
    var { publicKey } = body;

    if (!isValidBlockId(publicKey)) { return void cb('INVALID_KEY'); }

    readMFA(Env, publicKey, function (err, mfaData) {
        if (err) { return void cb(err); }
        if (mfaData.method !== 'WebAuthn') { return void cb('WRONG_METHOD'); }

        var credentials = mfaData.credentials || [];
        if (!credentials.length) { return void cb('NO_CREDENTIALS'); }

        var rp = getRpConfig();
        var challenge = generateChallenge();
        body.webauthnChallenge = challenge;
        body.webauthnRpId = rp.rpId;

        var allowCredentials = credentials.map(c => ({
            id: c.credentialId,
            transports: c.transports || [],
        }));

        generateAuthenticationOptions({
            rpID: rp.rpId,
            challenge: Buffer.from(challenge, 'base64url'),
            allowCredentials,
            userVerification: 'preferred',
        }).then(function (options) {
            cb(void 0, { authenticationOptions: options });
        }).catch(function (err) {
            Env.Log.error('WEBAUTHN_REVOKE_OPTIONS_ERROR', { error: Util.serializeError(err) });
            cb('WEBAUTHN_OPTIONS_FAILED');
        });
    });
};

WEBAUTHN_REVOKE.stage1ServerExtensions = ['webauthnChallenge', 'webauthnRpId'];
WEBAUTHN_REVOKE.stage2Extensions = ['assertionResponse'];

WEBAUTHN_REVOKE.complete = function (Env, body, cb) {
    var { publicKey, webauthnChallenge, webauthnRpId, assertionResponse, credentialId } = body;

    if (!assertionResponse) { return void cb('MISSING_ASSERTION'); }

    readMFA(Env, publicKey, function (err, mfaData) {
        if (err) { return void cb(err); }
        if (mfaData.method !== 'WebAuthn') { return void cb('WRONG_METHOD'); }

        verifyAssertion(assertionResponse, webauthnChallenge, webauthnRpId, mfaData, Env, publicKey,
            function (err, updatedMfaData) {
                if (err) { return void cb(err); }

                var credentials = updatedMfaData.credentials || [];
                var credentialIdStr = Buffer.from(
                    assertionResponse.rawId || assertionResponse.id || '',
                    'base64url'
                ).toString('base64url');
                var targetId = credentialId || credentialIdStr;
                var remaining = credentials.filter(c => c.credentialId !== targetId);

                if (remaining.length === 0) {
                    // No credentials left — fully revoke MFA.
                    return void MFA.revoke(Env, publicKey, cb);
                }

                updatedMfaData.credentials = remaining;
                MFA.write(Env, publicKey, JSON.stringify(updatedMfaData), function (err) {
                    if (err) {
                        Env.Log.error('WEBAUTHN_REVOKE_WRITE_FAILED', { publicKey, error: err });
                        return void cb('STORAGE_FAILURE');
                    }
                    cb(void 0, { success: true });
                });
            }
        );
    });
};

// ─── WRITE BLOCK (password change) ───────────────────────────────────────────

// Stage 1: validate the ancestor proof and return an authentication challenge.
const WEBAUTHN_WRITE_BLOCK = Commands.WEBAUTHN_WRITE_BLOCK = function (Env, body, cb) {
    const { publicKey, content } = body;
    const registrationProof = content && content.registrationProof;

    if (!isValidBlockId(publicKey)) { return void cb('INVALID_KEY'); }
    if (publicKey !== content.publicKey) { return void cb('INVALID_KEY'); }
    if (!registrationProof) { return void cb('MISSING_ANCESTOR'); }

    let oldKey;
    nThen(function (w) {
        Block.validateAncestorProof(Env, registrationProof, w((err, provenKey) => {
            if (err || !provenKey) {
                w.abort();
                return void cb('INVALID_ANCESTOR');
            }
            oldKey = provenKey;
        }));
    }).nThen(function (w) {
        readMFA(Env, oldKey, w(function (err, mfaData) {
            if (err) {
                w.abort();
                return void cb(err);
            }
            if (mfaData.method !== 'WebAuthn') {
                w.abort();
                return void cb('WRONG_METHOD');
            }

            var credentials = mfaData.credentials || [];
            if (!credentials.length) {
                w.abort();
                return void cb('NO_CREDENTIALS');
            }

            var rp = getRpConfig();
            var challenge = generateChallenge();
            body.webauthnChallenge = challenge;
            body.webauthnRpId = rp.rpId;
            body.webauthnOldKey = oldKey;

            var allowCredentials = credentials.map(c => ({
                id: Buffer.from(c.credentialId, 'base64url'),
                type: 'public-key',
                transports: c.transports || [],
            }));

            generateAuthenticationOptions({
                rpID: rp.rpId,
                challenge: Buffer.from(challenge, 'base64url'),
                allowCredentials,
                userVerification: 'preferred',
            }).then(function (options) {
                w.abort();
                cb(void 0, { authenticationOptions: options });
            }).catch(function (err) {
                Env.Log.error('WEBAUTHN_WRITE_BLOCK_OPTIONS_ERROR', { error: Util.serializeError(err) });
                w.abort();
                cb('WEBAUTHN_OPTIONS_FAILED');
            });
        }));
    });
};

WEBAUTHN_WRITE_BLOCK.stage1ServerExtensions = ['webauthnChallenge', 'webauthnRpId', 'webauthnOldKey'];
WEBAUTHN_WRITE_BLOCK.stage2Extensions = ['assertionResponse'];

WEBAUTHN_WRITE_BLOCK.complete = function (Env, body, cb) {
    const { publicKey, content, session, webauthnChallenge, webauthnRpId, webauthnOldKey, assertionResponse } = body;

    if (!assertionResponse) { return void cb('MISSING_ASSERTION'); }

    var oldKey = webauthnOldKey;

    readMFA(Env, oldKey, function (err, mfaData) {
        if (err) { return void cb(err); }
        if (mfaData.method !== 'WebAuthn') { return void cb('WRONG_METHOD'); }

        verifyAssertion(assertionResponse, webauthnChallenge, webauthnRpId, mfaData, Env, oldKey,
            function (err, updatedMfaData) {
                if (err) { return void cb(err); }

                nThen(function (w) {
                    Block.writeLoginBlock(Env, content, w((err) => {
                        if (err) {
                            w.abort();
                            return void cb('BLOCK_WRITE_ERROR');
                        }
                    }));
                }).nThen(function (w) {
                    MFA.copy(Env, oldKey, publicKey, w());
                }).nThen(function (w) {
                    MFA.write(Env, oldKey, JSON.stringify(updatedMfaData), w(function (writeErr) {
                        if (writeErr) {
                            Env.Log.error('WEBAUTHN_SIGNCOUNT_UPDATE_FAILED', { publicKey: oldKey, error: writeErr });
                        }
                    }));
                }).nThen(function () {
                    makeSession(Env, publicKey, oldKey, session, cb);
                });
            }
        );
    });
};

// ─── REMOVE BLOCK (account deletion) ─────────────────────────────────────────

// Stage 1: issue an authentication challenge that must be satisfied to delete the block.
const WEBAUTHN_REMOVE_BLOCK = Commands.WEBAUTHN_REMOVE_BLOCK = function (Env, body, cb) {
    const { publicKey } = body;

    if (!isValidBlockId(publicKey)) { return void cb('INVALID_KEY'); }

    readMFA(Env, publicKey, function (err, mfaData) {
        if (err) { return void cb(err); }
        if (mfaData.method !== 'WebAuthn') { return void cb('WRONG_METHOD'); }

        var credentials = mfaData.credentials || [];
        if (!credentials.length) { return void cb('NO_CREDENTIALS'); }

        var rp = getRpConfig();
        var challenge = generateChallenge();
        body.webauthnChallenge = challenge;
        body.webauthnRpId = rp.rpId;

        var allowCredentials = credentials.map(c => ({
            id: c.credentialId,
            transports: c.transports || [],
        }));

        generateAuthenticationOptions({
            rpID: rp.rpId,
            challenge: Buffer.from(challenge, 'base64url'),
            allowCredentials,
            userVerification: 'preferred',
        }).then(function (options) {
            cb(void 0, { authenticationOptions: options });
        }).catch(function (err) {
            Env.Log.error('WEBAUTHN_REMOVE_BLOCK_OPTIONS_ERROR', { error: Util.serializeError(err) });
            cb('WEBAUTHN_OPTIONS_FAILED');
        });
    });
};

WEBAUTHN_REMOVE_BLOCK.stage1ServerExtensions = ['webauthnChallenge', 'webauthnRpId'];
WEBAUTHN_REMOVE_BLOCK.stage2Extensions = ['assertionResponse'];

WEBAUTHN_REMOVE_BLOCK.complete = function (Env, body, cb) {
    const { publicKey, edPublic, reason, webauthnChallenge, webauthnRpId, assertionResponse } = body;

    if (!assertionResponse) { return void cb('MISSING_ASSERTION'); }

    readMFA(Env, publicKey, function (err, mfaData) {
        if (err) { return void cb(err); }
        if (mfaData.method !== 'WebAuthn') { return void cb('WRONG_METHOD'); }

        verifyAssertion(assertionResponse, webauthnChallenge, webauthnRpId, mfaData, Env, publicKey,
            function (err) {
                if (err) { return void cb(err); }

                nThen(function (w) {
                    Block.removeLoginBlock(Env, publicKey, reason, edPublic, w((err) => {
                        if (err) {
                            w.abort();
                            return void cb(err);
                        }
                    }));
                }).nThen(() => {
                    MFA.revoke(Env, publicKey, cb);
                });
            }
        );
    });
};
