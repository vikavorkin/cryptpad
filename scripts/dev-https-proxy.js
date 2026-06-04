#!/usr/bin/env node
// SPDX-FileCopyrightText: 2023 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/*
 * dev-https-proxy.js — lightweight HTTPS reverse-proxy for local WebAuthn testing.
 *
 * Usage:
 *   npm run dev:https
 *
 * What it does:
 *   1. Generates a self-signed TLS certificate under data/dev-certs/ (once, then reuses it).
 *   2. Starts an HTTPS server on the port given by DEV_HTTPS_PORT (default 3443).
 *   3. Forwards every request to the existing HTTP dev server (default http://localhost:3000).
 *
 * WebAuthn requires a secure context (HTTPS or plain http://localhost).
 * This proxy lets you access CryptPad over https://localhost:3443 when you need HTTPS,
 * for example to test from a different device on the LAN via https://<your-ip>:3443.
 *
 * Your browser will show a self-signed certificate warning the first time.
 * In Chrome: click "Advanced" → "Proceed to localhost (unsafe)".
 * In Firefox: click "Advanced" → "Accept the Risk and Continue".
 *
 * The underlying CryptPad server must already be running (npm run dev).
 *
 * Environment variables:
 *   DEV_HTTPS_PORT   Port for this HTTPS proxy  (default: 3443)
 *   DEV_HTTP_TARGET  HTTP server to proxy to     (default: http://localhost:3000)
 *   DEV_CERT_DIR     Directory for cert/key PEM  (default: data/dev-certs)
 */

'use strict';

const Https = require('https');
const Http  = require('http');
const Fs    = require('fs');
const Path  = require('path');
const Cp    = require('child_process');
const Url   = require('url');

const HTTPS_PORT  = parseInt(process.env.DEV_HTTPS_PORT  || '3443', 10);
const HTTP_TARGET = process.env.DEV_HTTP_TARGET || 'http://localhost:3000';
const CERT_DIR    = process.env.DEV_CERT_DIR    || Path.join(__dirname, '..', 'data', 'dev-certs');

const CERT_PATH = Path.join(CERT_DIR, 'cert.pem');
const KEY_PATH  = Path.join(CERT_DIR, 'key.pem');

// ── Certificate generation ────────────────────────────────────────────────────

function ensureCert() {
    if (Fs.existsSync(CERT_PATH) && Fs.existsSync(KEY_PATH)) {
        console.log('[dev-https] Using existing certificate from', CERT_DIR);
        return;
    }

    Fs.mkdirSync(CERT_DIR, { recursive: true });

    console.log('[dev-https] Generating self-signed certificate in', CERT_DIR, '...');

    // subjectAltName is required by Chrome/Firefox for localhost to be accepted
    // (even though we're using a self-signed cert that the browser will still warn about).
    const san = 'subjectAltName=DNS:localhost,IP:127.0.0.1';

    try {
        Cp.execSync(
            `openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes` +
            ` -keyout "${KEY_PATH}"` +
            ` -out "${CERT_PATH}"` +
            ` -subj "/CN=localhost"` +
            ` -addext "${san}"`,
            { stdio: ['ignore', 'ignore', 'pipe'] }
        );
        console.log('[dev-https] Certificate generated.');
    } catch (err) {
        console.error('[dev-https] openssl failed:', err.stderr && err.stderr.toString());
        process.exit(1);
    }
}

// ── Request proxying ──────────────────────────────────────────────────────────

const target = new Url.URL(HTTP_TARGET);

function proxy(req, res) {
    const options = {
        hostname: target.hostname,
        port:     target.port || 80,
        path:     req.url,
        method:   req.method,
        headers:  Object.assign({}, req.headers, {
            // Tell the upstream server the real protocol so that any
            // absolute redirects it generates use https://.
            'x-forwarded-proto': 'https',
            'x-forwarded-host':  req.headers.host || `localhost:${HTTPS_PORT}`,
            host:                `${target.hostname}:${target.port}`,
        }),
    };

    const upstream = Http.request(options, (upRes) => {
        res.writeHead(upRes.statusCode, upRes.headers);
        upRes.pipe(res, { end: true });
    });

    upstream.on('error', (err) => {
        console.error('[dev-https] upstream error:', err.message);
        if (!res.headersSent) {
            res.writeHead(502);
        }
        res.end('Bad Gateway — is the CryptPad dev server running on ' + HTTP_TARGET + '?');
    });

    req.pipe(upstream, { end: true });
}

// WebSocket upgrade passthrough (needed for cryptpad_websocket).
function proxyUpgrade(req, socket, head) {
    const wsTarget = HTTP_TARGET.replace(/^https?/, 'ws');
    const wsUrl = new Url.URL(req.url, wsTarget);

    const upstream = require('net').connect({
        host: target.hostname,
        port: parseInt(target.port, 10) || 80,
    }, () => {
        upstream.write(
            `GET ${req.url} HTTP/1.1\r\n` +
            `Host: ${target.hostname}:${target.port}\r\n` +
            `Upgrade: websocket\r\n` +
            `Connection: Upgrade\r\n` +
            Object.entries(req.headers)
                .filter(([k]) => !['host'].includes(k))
                .map(([k, v]) => `${k}: ${v}`)
                .join('\r\n') +
            '\r\n\r\n'
        );
        upstream.write(head);
    });

    upstream.on('data', (chunk) => { socket.write(chunk); });
    upstream.on('end', ()  => { socket.end(); });
    upstream.on('error', () => { socket.end(); });
    socket.on('data', (chunk) => { upstream.write(chunk); });
    socket.on('end', ()  => { upstream.end(); });
    socket.on('error', () => { upstream.end(); });

    void wsUrl; // suppress unused-variable lint warning
}

// ── Startup ───────────────────────────────────────────────────────────────────

ensureCert();

const tlsOptions = {
    key:  Fs.readFileSync(KEY_PATH),
    cert: Fs.readFileSync(CERT_PATH),
};

const server = Https.createServer(tlsOptions, proxy);
server.on('upgrade', proxyUpgrade);

server.listen(HTTPS_PORT, () => {
    console.log('');
    console.log('  ┌─────────────────────────────────────────────────────┐');
    console.log('  │  CryptPad HTTPS dev proxy                           │');
    console.log('  │                                                     │');
    console.log(`  │  https://localhost:${HTTPS_PORT}  →  ${HTTP_TARGET.padEnd(20)} │`);
    console.log('  │                                                     │');
    console.log('  │  Self-signed cert: browser will warn on first visit │');
    console.log('  │  Chrome:  Advanced → Proceed to localhost (unsafe)  │');
    console.log('  │  Firefox: Advanced → Accept the Risk and Continue   │');
    console.log('  │                                                     │');
    console.log('  │  WebAuthn config — add to config/config.js:         │');
    console.log(`  │    httpUnsafeOrigin: 'https://localhost:${HTTPS_PORT}',   │`);
    console.log(`  │    webauthn: { rpId: 'localhost',                   │`);
    console.log(`  │               origin: 'https://localhost:${HTTPS_PORT}' } │`);
    console.log('  └─────────────────────────────────────────────────────┘');
    console.log('');
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`[dev-https] Port ${HTTPS_PORT} is already in use.`);
        console.error(`[dev-https] Set DEV_HTTPS_PORT=<other> to use a different port.`);
    } else {
        console.error('[dev-https] Server error:', err);
    }
    process.exit(1);
});
