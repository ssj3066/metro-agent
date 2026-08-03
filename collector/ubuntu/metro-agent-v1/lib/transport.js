const fs = require('fs');
const http = require('http');
const https = require('https');

function isEnabled(value) {
    return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

function buildHttpsAgent(env) {
    const options = {
        rejectUnauthorized: !isEnabled(env.NMS_INSECURE_TLS)
    };
    const caPath = String(env.NMS_CA_CERT_PATH || '').trim();
    if (caPath) options.ca = fs.readFileSync(caPath);
    return new https.Agent(options);
}

function requestJson(targetUrl, { method = 'GET', token, payload = null, timeoutMs = 15000, env = {} } = {}) {
    const parsedUrl = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new Error('metro agent server URL must use HTTP or HTTPS');
    }
    const body = payload === null ? null : Buffer.from(JSON.stringify(payload), 'utf8');
    const transport = parsedUrl.protocol === 'https:' ? https : http;
    const headers = {
        Accept: 'application/json',
        'User-Agent': 'Metro-Agent-V1'
    };
    if (token) headers['X-Collector-Token'] = token;
    if (body) {
        headers['Content-Type'] = 'application/json; charset=utf-8';
        headers['Content-Length'] = String(body.length);
    }

    return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (callback, value) => {
            if (settled) return;
            settled = true;
            clearTimeout(deadline);
            callback(value);
        };
        const request = transport.request(parsedUrl, {
            method,
            headers,
            agent: parsedUrl.protocol === 'https:' ? buildHttpsAgent(env) : undefined
        }, (response) => {
            const chunks = [];
            let bytes = 0;
            response.on('data', (chunk) => {
                bytes += chunk.length;
                if (bytes > 2 * 1024 * 1024) {
                    request.destroy(new Error('metro agent response exceeds 2 MiB'));
                    return;
                }
                chunks.push(chunk);
            });
            response.on('end', () => {
                const text = Buffer.concat(chunks).toString('utf8');
                let parsed = {};
                try {
                    parsed = text ? JSON.parse(text) : {};
                } catch {
                    finish(reject, new Error(`metro agent server returned invalid JSON (${response.statusCode})`));
                    return;
                }
                if (response.statusCode < 200 || response.statusCode >= 300) {
                    finish(reject, new Error(`metro agent server returned ${response.statusCode}: ${parsed.detail || parsed.error || 'request failed'}`));
                    return;
                }
                finish(resolve, parsed);
            });
        });
        const deadline = setTimeout(
            () => request.destroy(new Error('metro agent server request deadline exceeded')),
            timeoutMs
        );
        request.setTimeout(timeoutMs, () => request.destroy(new Error('metro agent server request timed out')));
        request.on('error', (error) => finish(reject, error));
        if (body) request.write(body);
        request.end();
    });
}

module.exports = {
    isEnabled,
    requestJson
};
