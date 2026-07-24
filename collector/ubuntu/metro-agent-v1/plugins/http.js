const http = require('http');
const https = require('https');

function run(check, context = {}) {
    const parsedUrl = new URL(check.target);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new Error('HTTP check target must use http or https');
    }
    const transport = context.transport || (parsedUrl.protocol === 'https:' ? https : http);
    const startedAt = Date.now();
    return new Promise((resolve) => {
        let settled = false;
        const finish = (status, errorCode, statusCode = null) => {
            if (settled) return;
            settled = true;
            const durationMs = Date.now() - startedAt;
            resolve([{
                result_id: `${check.key}:response`,
                check_key: check.key,
                check_type: 'http',
                target: parsedUrl.toString(),
                status,
                value: statusCode,
                unit: 'http_status',
                observed_at: new Date().toISOString(),
                duration_ms: durationMs,
                source: 'http_request',
                error_code: errorCode,
                details: { status_code: statusCode, response_time_ms: durationMs }
            }]);
        };
        const request = transport.request(parsedUrl, {
            method: String(check.options?.method || 'GET').toUpperCase(),
            headers: { 'User-Agent': 'Metro-Agent-V1' }
        }, (response) => {
            response.resume();
            response.once('end', () => {
                const ok = response.statusCode >= 200 && response.statusCode < 400;
                finish(ok ? 'success' : 'failure', ok ? null : 'http_status', response.statusCode);
            });
        });
        request.setTimeout(check.timeout_ms, () => request.destroy(new Error('timeout')));
        request.once('error', (error) => finish('failure', error.message === 'timeout' ? 'timeout' : String(error.code || 'http_failed').slice(0, 100)));
        request.end();
    });
}

module.exports = {
    run
};
