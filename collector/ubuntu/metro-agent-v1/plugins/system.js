const fs = require('fs');
const os = require('os');

function sleep(milliseconds) {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function readCpuCounters() {
    const line = fs.readFileSync('/proc/stat', 'utf8').split('\n')[0].trim().split(/\s+/).slice(1).map(Number);
    const idle = (line[3] || 0) + (line[4] || 0);
    return { idle, total: line.reduce((sum, value) => sum + value, 0) };
}

function cpuUsedPct(before, after) {
    const totalDelta = after.total - before.total;
    const idleDelta = after.idle - before.idle;
    if (totalDelta <= 0) return null;
    return Number((((totalDelta - idleDelta) / totalDelta) * 100).toFixed(2));
}

function parseMeminfo(text) {
    const values = {};
    for (const line of String(text || '').split('\n')) {
        const match = line.match(/^([A-Za-z_()]+):\s+(\d+)\s+kB$/);
        if (match) values[match[1]] = Number(match[2]);
    }
    if (!values.MemTotal || values.MemAvailable === undefined) return null;
    return Number((((values.MemTotal - values.MemAvailable) / values.MemTotal) * 100).toFixed(2));
}

function memoryUsedPct() {
    try {
        const value = parseMeminfo(fs.readFileSync('/proc/meminfo', 'utf8'));
        if (value !== null) return { value, source: 'procfs_memavailable' };
    } catch {
        // Fall back for non-Linux development hosts.
    }
    const total = os.totalmem();
    if (!total) return { value: null, source: 'os_memory' };
    return {
        value: Number((((total - os.freemem()) / total) * 100).toFixed(2)),
        source: 'os_memory'
    };
}

function rootDiskUsedPct() {
    if (typeof fs.statfsSync !== 'function') return null;
    const stat = fs.statfsSync('/');
    const total = Number(stat.blocks) * Number(stat.bsize);
    const available = Number(stat.bavail) * Number(stat.bsize);
    if (!total) return null;
    return Number((((total - available) / total) * 100).toFixed(2));
}

function result(check, suffix, value, unit, source, observedAt) {
    return {
        result_id: `${check.key}:${suffix}`,
        check_key: `${check.key}.${suffix}`,
        check_type: 'system',
        target: os.hostname(),
        status: value === null ? 'unavailable' : 'success',
        value,
        unit,
        observed_at: observedAt,
        duration_ms: null,
        source,
        error_code: value === null ? 'metric_unavailable' : null,
        details: {}
    };
}

async function run(check, context = {}) {
    const wait = context.sleep || sleep;
    let cpu = null;
    try {
        const before = readCpuCounters();
        await wait(100);
        cpu = cpuUsedPct(before, readCpuCounters());
    } catch {
        cpu = null;
    }
    const observedAt = new Date().toISOString();
    const memory = memoryUsedPct();
    return [
        result(check, 'cpu_used_pct', cpu, 'percent', 'procfs_cpu_delta', observedAt),
        result(check, 'memory_used_pct', memory.value, 'percent', memory.source, observedAt),
        result(check, 'root_disk_used_pct', rootDiskUsedPct(), 'percent', 'statfs', observedAt),
        result(check, 'uptime_seconds', Number(os.uptime().toFixed(0)), 'seconds', 'os_uptime', observedAt)
    ];
}

module.exports = {
    cpuUsedPct,
    parseMeminfo,
    run
};
