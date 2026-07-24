const { execFile } = require('child_process');

function execute(command, args, timeoutMs) {
    return new Promise((resolve, reject) => {
        execFile(command, args, { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 256 * 1024 }, (error, stdout, stderr) => {
            if (error) {
                error.stdout = stdout;
                error.stderr = stderr;
                reject(error);
                return;
            }
            resolve(stdout);
        });
    });
}

async function resolveGateway(exec = execute) {
    const output = await exec('ip', ['route', 'show', 'default'], 3000);
    const match = output.match(/\bdefault\s+via\s+(\S+)/);
    if (!match) throw new Error('default gateway is unavailable');
    return match[1];
}

function parsePingOutput(output) {
    const lossMatch = String(output).match(/([\d.]+)%\s+packet loss/i);
    const timingMatch = String(output).match(/=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)\s*ms/);
    return {
        packet_loss_pct: lossMatch ? Number(lossMatch[1]) : null,
        latency_min_ms: timingMatch ? Number(timingMatch[1]) : null,
        latency_avg_ms: timingMatch ? Number(timingMatch[2]) : null,
        latency_max_ms: timingMatch ? Number(timingMatch[3]) : null,
        jitter_ms: timingMatch ? Number(timingMatch[4]) : null
    };
}

async function run(check, context = {}) {
    const exec = context.exec || execute;
    const target = check.target === 'gateway' ? await resolveGateway(exec) : check.target;
    const count = Math.min(10, Math.max(1, Number(check.options?.count) || 4));
    const waitSeconds = Math.max(1, Math.ceil(check.timeout_ms / 1000));
    const startedAt = Date.now();
    try {
        const output = await exec('ping', ['-n', '-c', String(count), '-W', String(waitSeconds), target], check.timeout_ms + 2000);
        const parsed = parsePingOutput(output);
        const maximumPacketLossPct = Math.min(100, Math.max(0, Number(check.options?.max_packet_loss_pct) || 0));
        return [{
            result_id: `${check.key}:latency`,
            check_key: check.key,
            check_type: 'ping',
            target,
            status: parsed.packet_loss_pct === null || parsed.packet_loss_pct > maximumPacketLossPct
                ? 'failure' : 'success',
            value: parsed.latency_avg_ms,
            unit: 'ms',
            observed_at: new Date().toISOString(),
            duration_ms: Date.now() - startedAt,
            source: 'icmp_ping',
            error_code: null,
            details: { ...parsed, maximum_packet_loss_pct: maximumPacketLossPct }
        }];
    } catch (error) {
        const parsed = parsePingOutput(`${error.stdout || ''}\n${error.stderr || ''}`);
        return [{
            result_id: `${check.key}:latency`,
            check_key: check.key,
            check_type: 'ping',
            target,
            status: error.code === 'ENOENT' ? 'unavailable' : 'failure',
            value: parsed.latency_avg_ms,
            unit: 'ms',
            observed_at: new Date().toISOString(),
            duration_ms: Date.now() - startedAt,
            source: 'icmp_ping',
            error_code: String(error.code || 'ping_failed').slice(0, 100),
            details: parsed
        }];
    }
}

module.exports = {
    parsePingOutput,
    resolveGateway,
    run
};
