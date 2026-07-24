const net = require('net');

function parseTarget(check) {
    const raw = String(check.target || '').trim();
    const bracketMatch = raw.match(/^\[([^\]]+)\]:(\d+)$/);
    if (bracketMatch) return { host: bracketMatch[1], port: Number(bracketMatch[2]) };
    const separator = raw.lastIndexOf(':');
    const optionPort = Number(check.options?.port);
    if (separator > 0 && /^\d+$/.test(raw.slice(separator + 1))) {
        return { host: raw.slice(0, separator), port: Number(raw.slice(separator + 1)) };
    }
    if (Number.isInteger(optionPort) && optionPort >= 1 && optionPort <= 65535) {
        return { host: raw, port: optionPort };
    }
    throw new Error('TCP check requires host:port or options.port');
}

function run(check, context = {}) {
    const connect = context.connect || net.createConnection;
    const target = parseTarget(check);
    const startedAt = Date.now();
    return new Promise((resolve) => {
        let settled = false;
        const finish = (status, errorCode = null) => {
            if (settled) return;
            settled = true;
            socket.destroy();
            const durationMs = Date.now() - startedAt;
            resolve([{
                result_id: `${check.key}:connect`,
                check_key: check.key,
                check_type: 'tcp',
                target: `${target.host}:${target.port}`,
                status,
                value: status === 'success' ? durationMs : null,
                unit: 'ms',
                observed_at: new Date().toISOString(),
                duration_ms: durationMs,
                source: 'tcp_connect',
                error_code: errorCode,
                details: { host: target.host, port: target.port }
            }]);
        };
        const socket = connect({ host: target.host, port: target.port });
        socket.setTimeout(check.timeout_ms);
        socket.once('connect', () => finish('success'));
        socket.once('timeout', () => finish('failure', 'timeout'));
        socket.once('error', (error) => finish('failure', String(error.code || 'connect_failed').slice(0, 100)));
    });
}

module.exports = {
    parseTarget,
    run
};
