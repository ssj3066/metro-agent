#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const {
    buildTimeSeriesContext,
    readActiveDeployment
} = require('./time-series-context');

const DEFAULT_ENV_FILE = '/etc/nms-collector/collector.env';
const DEFAULT_STATE_DIR = '/var/lib/nms-collector/wifi-analysis';
const DEFAULT_MEASUREMENT_SESSION_STATE_FILE = '/var/lib/nms-collector/measurement-sessions/active.json';
const SCHEMA_VERSION = 'metro-wifi-analysis-v1';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
let preferredNmsBaseUrl = '';

class NmsRequestError extends Error {
    constructor(statusCode, responseBody) {
        let detail = '';
        try {
            const payload = JSON.parse(responseBody);
            detail = String(payload.detail || payload.error || '').trim();
        } catch {
            detail = String(responseBody || '').trim().slice(0, 300);
        }
        super(`NMS returned HTTP ${statusCode}${detail ? `: ${detail}` : ''}`);
        this.name = 'NmsRequestError';
        this.statusCode = statusCode;
        this.responseBody = String(responseBody || '').slice(0, 1000);
    }
}

function parseBoolean(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    const normalized = String(value).trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
    if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
    return fallback;
}

function parsePositiveInteger(value, fallback, minimum = 1, maximum = Number.MAX_SAFE_INTEGER) {
    const parsed = Number.parseInt(String(value ?? ''), 10);
    return Number.isInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : fallback;
}

function resolveNmsBaseUrl(env) {
    const explicitUrl = String(env.NMS_URL || env.NMS_BASE_URL || '').trim().replace(/\/+$/, '');
    if (explicitUrl) return explicitUrl;

    const scheme = String(env.NMS_SCHEME || 'http').trim();
    const host = String(env.NMS_HOST || '').trim();
    const port = parsePositiveInteger(env.NMS_PORT, 7443, 1, 65535);
    const rawPath = String(env.NMS_PATH || '').trim().replace(/^\/+|\/+$/g, '');
    return host ? `${scheme}://${host}:${port}${rawPath ? `/${rawPath}` : ''}` : '';
}

function resolveNmsBaseUrls(env) {
    const urls = [
        resolveNmsBaseUrl(env),
        String(env.NMS_FALLBACK_URL || '').trim().replace(/\/+$/, '')
    ].filter(Boolean);
    const unique = [...new Set(urls)];
    if (preferredNmsBaseUrl && unique.includes(preferredNmsBaseUrl)) {
        return [preferredNmsBaseUrl, ...unique.filter((url) => url !== preferredNmsBaseUrl)];
    }
    return unique;
}

function isRetryableNmsError(error) {
    return !(error instanceof NmsRequestError && error.statusCode < 500);
}

async function requestWithNmsFallback(env, operation) {
    const urls = resolveNmsBaseUrls(env);
    let lastError = null;
    for (const baseUrl of urls) {
        try {
            const result = await operation(baseUrl);
            preferredNmsBaseUrl = baseUrl;
            return result;
        } catch (error) {
            lastError = error;
            if (!isRetryableNmsError(error)) throw error;
        }
    }
    throw lastError || new Error('no NMS endpoint is configured');
}

function parseEnvFile(filePath = DEFAULT_ENV_FILE, baseEnv = process.env) {
    const env = { ...baseEnv };
    if (!fs.existsSync(filePath)) return env;
    for (const rawLine of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;
        const separator = line.indexOf('=');
        if (separator < 1) continue;
        const key = line.slice(0, separator).trim();
        if (env[key] !== undefined) continue;
        let value = line.slice(separator + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
            value = value.slice(1, -1);
        }
        env[key] = value;
    }
    return env;
}

function normalSampleKey(record) {
    if (record.kind === 'connectivity') {
        return `connectivity:${record.interface_role}:${record.target_kind}`;
    }
    if (record.kind === 'wifi') {
        return `wifi:${record.interface_name}`;
    }
    return null;
}

function execFileAsync(command, args, options = {}) {
    return new Promise((resolve) => {
        execFile(command, args, {
            timeout: options.timeoutMs || 5000,
            maxBuffer: options.maxBuffer || 1024 * 1024,
            encoding: 'utf8'
        }, (error, stdout, stderr) => resolve({
            ok: !error,
            stdout: String(stdout || ''),
            stderr: String(stderr || ''),
            error: error ? String(error.message || error) : null
        }));
    });
}

function parsePingOutput(output) {
    const text = String(output || '');
    const latencyMatch = text.match(/time[=<]([0-9.]+)\s*ms/i);
    const lossMatch = text.match(/([0-9.]+)%\s+packet loss/i);
    return {
        success: Boolean(latencyMatch) && (!lossMatch || Number(lossMatch[1]) < 100),
        latency_ms: latencyMatch ? Number(latencyMatch[1]) : null,
        packet_loss_pct: lossMatch ? Number(lossMatch[1]) : (latencyMatch ? 0 : 100)
    };
}

function frequencyToChannel(frequencyMhz) {
    const frequency = Number(frequencyMhz);
    if (!Number.isFinite(frequency)) return null;
    if (frequency === 2484) return 14;
    if (frequency >= 2412 && frequency <= 2472) return Math.round((frequency - 2407) / 5);
    if (frequency >= 5000 && frequency <= 5895) return Math.round((frequency - 5000) / 5);
    if (frequency >= 5955 && frequency <= 7115) return Math.round((frequency - 5950) / 5);
    return null;
}

function escapePattern(value) {
    return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function parseIwLink(output, interfaceName, observedAt = new Date().toISOString()) {
    const text = String(output || '');
    if (!text.trim() || /Not connected/i.test(text)) {
        return { observed_at: observedAt, interface_name: interfaceName, connected: false, source: 'iw_link' };
    }
    const value = (pattern) => text.match(pattern)?.[1] || null;
    const frequencyMhz = Number(value(/\bfreq:\s*([0-9.]+)/i));
    const signalDbm = Number(value(/\bsignal:\s*(-?[0-9.]+)\s*dBm/i));
    const rxMbps = Number(value(/\brx bitrate:\s*([0-9.]+)\s*MBit\/s/i));
    const txMbps = Number(value(/\btx bitrate:\s*([0-9.]+)\s*MBit\/s/i));
    return {
        observed_at: observedAt,
        interface_name: interfaceName,
        connected: true,
        ssid: value(/\bSSID:\s*(.+)/i)?.trim() || null,
        bssid: value(/Connected to\s+([0-9a-f:]{17})/i)?.toLowerCase() || null,
        frequency_mhz: Number.isFinite(frequencyMhz) ? frequencyMhz : null,
        channel: frequencyToChannel(frequencyMhz),
        signal_dbm: Number.isFinite(signalDbm) ? signalDbm : null,
        snr_db: null,
        rx_link_mbps: Number.isFinite(rxMbps) ? rxMbps : null,
        tx_link_mbps: Number.isFinite(txMbps) ? txMbps : null,
        source: 'iw_link'
    };
}

function parseIwChannelWidth(output, interfaceName) {
    const lines = String(output || '').split(/\r?\n/);
    let inInterface = false;
    for (const line of lines) {
        const interfaceMatch = line.match(/^\s*Interface\s+(\S+)/);
        if (interfaceMatch) inInterface = interfaceMatch[1] === interfaceName;
        if (!inInterface) continue;
        const widthMatch = line.match(/channel\s+\d+\s+\([^)]+\),\s*width:\s*([0-9]+)\s*MHz/i);
        if (widthMatch) return Number(widthMatch[1]);
    }
    return null;
}

function parseDefaultGateway(output) {
    try {
        const rows = JSON.parse(String(output || '[]'));
        return rows.find((row) => row.gateway)?.gateway || null;
    } catch {
        return null;
    }
}

function parseRouteVerification(output, interfaceName) {
    return new RegExp(`\\bdev\\s+${escapePattern(interfaceName)}\\b`).test(String(output || ''));
}

class TimeRingBuffer {
    constructor(retentionMs) {
        this.retentionMs = retentionMs;
        this.records = [];
    }

    add(record, nowMs = Date.parse(record.observed_at || '') || Date.now()) {
        this.records.push(record);
        const cutoff = nowMs - this.retentionMs;
        while (this.records.length && Date.parse(this.records[0].observed_at) < cutoff) this.records.shift();
    }

    between(startMs, endMs) {
        return this.records.filter((record) => {
            const timestamp = Date.parse(record.observed_at);
            return timestamp >= startMs && timestamp <= endMs;
        });
    }
}

class IncidentWindowManager {
    constructor({ preMs = 300000, postMs = 300000, cooldownMs = 60000 } = {}) {
        this.preMs = preMs;
        this.postMs = postMs;
        this.cooldownMs = cooldownMs;
        this.active = new Map();
        this.lastTriggeredAt = new Map();
    }

    trigger(triggerType, evidence, observedAt = new Date().toISOString()) {
        const nowMs = Date.parse(observedAt);
        if (nowMs - (this.lastTriggeredAt.get(triggerType) || 0) < this.cooldownMs) return null;
        const incident = {
            incident_id: crypto.randomUUID(),
            trigger_type: triggerType,
            detected_at: observedAt,
            window_start: new Date(nowMs - this.preMs).toISOString(),
            window_end: new Date(nowMs + this.postMs).toISOString(),
            evidence
        };
        this.active.set(incident.incident_id, incident);
        this.lastTriggeredAt.set(triggerType, nowMs);
        return incident;
    }

    collectCompleted(ring, nowMs = Date.now()) {
        const completed = [];
        for (const [incidentId, incident] of this.active.entries()) {
            if (Date.parse(incident.window_end) > nowMs) continue;
            completed.push({
                ...incident,
                records: ring.between(Date.parse(incident.window_start), Date.parse(incident.window_end))
            });
            this.active.delete(incidentId);
        }
        return completed;
    }
}

function classifyIncident(records, triggerType) {
    const latestBy = (samples, keySelector) => {
        const latest = new Map();
        for (const sample of samples) {
            const key = keySelector(sample);
            const previous = latest.get(key);
            if (!previous || Date.parse(sample.observed_at || '') >= Date.parse(previous.observed_at || '')) {
                latest.set(key, sample);
            }
        }
        return latest;
    };
    const external = records.filter((record) => record.kind === 'connectivity'
        && ['kt_dns', 'google_dns'].includes(record.target_kind));
    const recent = latestBy(external, (sample) => sample.interface_role);
    const gateways = latestBy(
        records.filter((record) => record.kind === 'connectivity' && record.target_kind === 'gateway'),
        (sample) => sample.interface_role
    );
    const latestWifi = [...records]
        .filter((record) => record.kind === 'wifi')
        .sort((left, right) => Date.parse(right.observed_at || '') - Date.parse(left.observed_at || ''))[0];
    const wired = recent.get('wired');
    const wireless = latestWifi?.connected === false ? null : recent.get('wireless');
    const wiredGateway = gateways.get('wired');
    if (wired && !wired.success && wiredGateway && !wiredGateway.success) {
        return { classification: 'gateway_or_wired_path', confidence: 'high' };
    }
    if (wired && wireless && !wired.success && !wireless.success) {
        return { classification: 'upstream_or_common_path', confidence: 'medium' };
    }
    if (wired && !wired.success && wiredGateway?.success) {
        return { classification: 'upstream_or_common_path', confidence: 'medium' };
    }
    if (wired?.success && wireless && !wireless.success) {
        return { classification: 'wireless_or_ap_path', confidence: 'medium' };
    }
    if (triggerType === 'bssid_change') return { classification: 'roaming_or_authentication', confidence: 'low' };
    if (triggerType === 'rssi_drop') return { classification: 'coverage_or_wireless_change', confidence: 'low' };
    if (triggerType === 'rf_energy_spike') return { classification: 'rf_interference_possible', confidence: 'low' };
    if (triggerType === 'gateway_latency_degraded') return { classification: 'gateway_or_wired_path', confidence: 'high' };
    return { classification: 'unknown', confidence: 'low' };
}

function safeWriteJson(filePath, value) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const temporary = `${filePath}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(value)}\n`, { mode: 0o600 });
    fs.renameSync(temporary, filePath);
}

function readActiveMeasurementSession(filePath = DEFAULT_MEASUREMENT_SESSION_STATE_FILE) {
    try {
        const payload = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const sessionId = String(payload?.measurement_session_id || '').trim().toLowerCase();
        if (!UUID_PATTERN.test(sessionId) || payload.status !== 'running') return null;
        if (payload.ends_at && Date.parse(payload.ends_at) < Date.now()) return null;
        const moduleRunIds = {};
        for (const [measurementType, moduleRun] of Object.entries(payload.module_runs || {})) {
            const moduleRunId = String(moduleRun?.module_run_id || '').trim().toLowerCase();
            if (UUID_PATTERN.test(moduleRunId)) moduleRunIds[measurementType] = moduleRunId;
        }
        return {
            measurement_session_id: sessionId,
            status: payload.status,
            started_at: payload.started_at || null,
            ends_at: payload.ends_at || null,
            timezone: String(payload.timezone || 'Asia/Seoul'),
            module_run_ids: moduleRunIds
        };
    } catch {
        return null;
    }
}

function enteredMeasurementSession(previousSessionId, activeSession) {
    const currentSessionId = activeSession?.measurement_session_id || null;
    return Boolean(currentSessionId && currentSessionId !== previousSessionId);
}

function measurementTypeForRecord(record) {
    if (record.kind === 'connectivity') return record.interface_role;
    if (record.kind === 'wifi') return 'wireless';
    if (record.kind === 'rf') return 'rf';
    return null;
}

function attachMeasurementContext(record, activeSession, now = new Date()) {
    const sampledAt = Date.parse(record.observed_at || '');
    record.timezone = activeSession?.timezone || 'Asia/Seoul';
    record.source_delay_ms = Number.isFinite(sampledAt)
        ? Number(Math.max(0, now.getTime() - sampledAt).toFixed(3))
        : null;
    record.sample_status = record.kind === 'connectivity' && record.success === false
        ? 'failure'
        : 'success';
    record.error_message = record.error_message || null;
    const measurementType = measurementTypeForRecord(record);
    const moduleRunId = activeSession?.module_run_ids?.[measurementType] || null;
    if (activeSession && moduleRunId) {
        record.measurement_session_id = activeSession.measurement_session_id;
        record.module_run_id = moduleRunId;
    } else {
        record.measurement_session_id = null;
        record.module_run_id = null;
    }
    return record;
}

function updateMeasurementSessionStats(stateFile, activeSession, records) {
    if (!activeSession) return null;
    const sessionDir = path.join(
        path.dirname(stateFile),
        'sessions',
        activeSession.measurement_session_id
    );
    const statsPath = path.join(sessionDir, 'wifi-analysis.json');
    let previous = {};
    try {
        previous = JSON.parse(fs.readFileSync(statsPath, 'utf8'));
    } catch {
        previous = {};
    }
    const wifiCount = records.filter((record) => (
        record.kind === 'wifi'
        || (record.kind === 'connectivity' && record.interface_role === 'wireless')
    )).length;
    const rfCount = records.filter((record) => record.kind === 'rf').length;
    const rfBands = [
        ...new Set([
            ...(Array.isArray(previous.rf_bands) ? previous.rf_bands : []),
            ...records
                .filter((record) => record.kind === 'rf' && record.band)
                .map((record) => String(record.band))
        ])
    ];
    const stats = {
        schema_version: 'metro-measurement-module-stats-v1',
        measurement_session_id: activeSession.measurement_session_id,
        updated_at: new Date().toISOString(),
        wireless_sample_count: Number(previous.wireless_sample_count || 0) + wifiCount,
        rf_sample_count: Number(previous.rf_sample_count || 0) + rfCount,
        rf_bands: rfBands,
        latest_wireless_at: records.filter((record) => (
            record.kind === 'wifi'
            || (record.kind === 'connectivity' && record.interface_role === 'wireless')
        )).at(-1)?.observed_at || previous.latest_wireless_at || null,
        latest_rf_at: records.filter((record) => record.kind === 'rf').at(-1)?.observed_at
            || previous.latest_rf_at
            || null
    };
    safeWriteJson(statsPath, stats);
    return stats;
}

function queueBatch(stateDir, payload) {
    const queueDir = path.join(stateDir, 'queue');
    fs.mkdirSync(queueDir, { recursive: true });
    const filePath = path.join(queueDir, `${payload.batch_id}.json`);
    safeWriteJson(filePath, payload);
    return filePath;
}

function listQueuedBatches(stateDir) {
    const queueDir = path.join(stateDir, 'queue');
    if (!fs.existsSync(queueDir)) return [];
    return fs.readdirSync(queueDir).filter((name) => name.endsWith('.json')).sort().slice(0, 100)
        .map((name) => path.join(queueDir, name));
}

function requestJson(urlValue, payload, env) {
    const target = new URL(urlValue);
    const body = Buffer.from(JSON.stringify(payload));
    const transport = target.protocol === 'https:' ? https : http;
    const options = {
        method: 'POST',
        hostname: target.hostname,
        port: target.port || (target.protocol === 'https:' ? 443 : 80),
        path: `${target.pathname}${target.search}`,
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': body.length,
            'X-Collector-Token': String(env.COLLECTOR_TOKEN || '')
        },
        timeout: parsePositiveInteger(env.NMS_REQUEST_TIMEOUT_MS, 5000, 1000, 30000)
    };
    if (target.protocol === 'https:') {
        if (parseBoolean(env.NMS_INSECURE_TLS, false)) {
            options.rejectUnauthorized = false;
        } else {
            const caPath = String(env.NMS_CA_CERT_PATH || '').trim();
            if (caPath) options.ca = fs.readFileSync(caPath);
        }
    }
    return new Promise((resolve, reject) => {
        const request = transport.request(options, (response) => {
            let responseBody = '';
            response.setEncoding('utf8');
            response.on('data', (chunk) => {
                if (responseBody.length < 65536) responseBody += chunk;
            });
            response.on('end', () => {
                if (response.statusCode >= 200 && response.statusCode < 300) {
                    resolve({ status_code: response.statusCode, body: responseBody });
                } else {
                    reject(new NmsRequestError(response.statusCode, responseBody));
                }
            });
        });
        request.on('timeout', () => request.destroy(new Error('NMS request timeout')));
        request.on('error', reject);
        request.end(body);
    });
}

function buildBatch(records, event = null, measurementSessionId = null) {
    const observedSessionIds = [...new Set(records
        .map((record) => record.measurement_session_id)
        .filter(Boolean))];
    if (observedSessionIds.length > 1) {
        throw new Error('Wi-Fi analysis batch cannot mix measurement sessions');
    }
    const resolvedSessionId = measurementSessionId || observedSessionIds[0] || null;
    const generatedAt = new Date();
    const deployment = readActiveDeployment(
        process.env.DEPLOYMENT_MONITORING_STATE_FILE
        || '/var/lib/nms-collector/deployment-monitoring/active.json'
    );
    const timeseries = buildTimeSeriesContext(
        generatedAt,
        deployment,
        process.env.DEPLOYMENT_MONITORING_INTERVAL_SECONDS
    );
    const withoutContext = ({ kind, measurement_session_id: _sessionId, ...record }) => record;
    return {
        schema_version: SCHEMA_VERSION,
        batch_id: crypto.randomUUID(),
        measurement_session_id: resolvedSessionId,
        generated_at: generatedAt.toISOString(),
        timeseries,
        hostname: os.hostname(),
        event,
        connectivity_samples: records.filter((record) => record.kind === 'connectivity').map(withoutContext),
        wifi_samples: records.filter((record) => record.kind === 'wifi').map(withoutContext),
        rf_sweeps: records.filter((record) => record.kind === 'rf').map(withoutContext)
    };
}

function splitRecordsIntoBatches(records) {
    const families = {
        connectivity: records.filter((record) => record.kind === 'connectivity'),
        wifi: records.filter((record) => record.kind === 'wifi'),
        rf: records.filter((record) => record.kind === 'rf')
    };
    const partCount = Math.max(
        1,
        Math.ceil(families.connectivity.length / 800),
        Math.ceil(families.wifi.length / 200),
        Math.ceil(families.rf.length / 20)
    );
    return Array.from({ length: partCount }, (_, index) => [
        ...families.connectivity.slice(index * 800, (index + 1) * 800),
        ...families.wifi.slice(index * 200, (index + 1) * 200),
        ...families.rf.slice(index * 20, (index + 1) * 20)
    ]).filter((part) => part.length);
}

function queueRecordBatches(stateDir, records, event = null) {
    const grouped = new Map();
    for (const record of records) {
        const sessionId = record.measurement_session_id || '';
        if (!grouped.has(sessionId)) grouped.set(sessionId, []);
        grouped.get(sessionId).push(record);
    }
    const queued = [];
    for (const [sessionId, groupedRecords] of grouped.entries()) {
        const parts = splitRecordsIntoBatches(groupedRecords);
        for (const [index, part] of parts.entries()) {
            queued.push(queueBatch(stateDir, buildBatch(part, event ? {
                ...event,
                part_index: index + 1,
                part_count: parts.length
            } : null, sessionId || null)));
        }
    }
    return queued;
}

async function discoverInterfaces(env) {
    const configuredWired = String(env.WIFI_ANALYSIS_WIRED_INTERFACE || '').trim();
    const configuredWireless = String(env.WIFI_ANALYSIS_WIRELESS_INTERFACE || '').trim();
    const rows = fs.existsSync('/sys/class/net') ? fs.readdirSync('/sys/class/net').filter((name) => name !== 'lo') : [];
    const wireless = configuredWireless || rows.find((name) => fs.existsSync(`/sys/class/net/${name}/wireless`)) || '';
    const wired = configuredWired || rows.find((name) => name !== wireless
        && !fs.existsSync(`/sys/class/net/${name}/wireless`)
        && !/^(wg|tun|docker|br-|veth)/.test(name)) || '';
    return { wired, wireless };
}

async function getGateway(interfaceName) {
    if (!interfaceName) return null;
    const result = await execFileAsync('ip', ['-j', '-4', 'route', 'show', 'default', 'dev', interfaceName], { timeoutMs: 3000 });
    return result.ok ? parseDefaultGateway(result.stdout) : null;
}

async function collectConnectivitySample(interfaceRole, interfaceName, targetKind, target) {
    const observedAt = new Date().toISOString();
    const route = await execFileAsync('ip', ['-4', 'route', 'get', target, 'oif', interfaceName], { timeoutMs: 2500 });
    const routeVerified = route.ok && parseRouteVerification(route.stdout, interfaceName);
    if (!routeVerified) {
        return {
            kind: 'connectivity', observed_at: observedAt, interface_role: interfaceRole,
            interface_name: interfaceName, target_kind: targetKind, target, route_verified: false,
            success: false, latency_ms: null, packet_loss_pct: null,
            error_code: 'route_unverified', source: 'icmp_ping'
        };
    }
    const ping = await execFileAsync('ping', ['-n', '-I', interfaceName, '-c', '1', '-W', '1', target], { timeoutMs: 2500 });
    const parsed = parsePingOutput(`${ping.stdout}\n${ping.stderr}`);
    return {
        kind: 'connectivity', observed_at: observedAt, interface_role: interfaceRole,
        interface_name: interfaceName, target_kind: targetKind, target, route_verified: true,
        ...parsed, error_code: parsed.success ? null : 'ping_failed', source: 'icmp_ping'
    };
}

async function collectWifiSample(interfaceName) {
    const observedAt = new Date().toISOString();
    const [link, dev] = await Promise.all([
        execFileAsync('iw', ['dev', interfaceName, 'link'], { timeoutMs: 3000 }),
        execFileAsync('iw', ['dev'], { timeoutMs: 3000 })
    ]);
    return {
        kind: 'wifi',
        ...parseIwLink(link.stdout || link.stderr, interfaceName, observedAt),
        channel_width_mhz: parseIwChannelWidth(dev.stdout, interfaceName),
        retry_count: null,
        deauth_count: null,
        disassoc_count: null
    };
}

const NETWORK_DIAGNOSTIC_RF_PROFILES = Object.freeze([
    Object.freeze({
        band: 'wifi_2_4ghz',
        start_hz: 2400000000,
        stop_hz: 2500000000,
        points: 290
    }),
    Object.freeze({
        band: 'wifi_5ghz',
        start_hz: 5150000000,
        stop_hz: 5850000000,
        points: 450
    }),
    Object.freeze({
        band: 'wifi_6ghz',
        start_hz: 5925000000,
        stop_hz: 7125000000,
        points: 450
    })
]);

function measurementRfProfiles(env = {}) {
    const requested = String(
        env.TINYSA_SESSION_BANDS || 'wifi_2_4ghz,wifi_5ghz,wifi_6ghz'
    ).split(',').map((value) => value.trim()).filter(Boolean);
    const selected = NETWORK_DIAGNOSTIC_RF_PROFILES.filter(
        (profile) => requested.includes(profile.band)
    );
    return selected.length ? selected.map((profile) => ({ ...profile })) : [];
}

async function collectRfSweep(env, profile = null) {
    if (!parseBoolean(env.TINYSA_ENABLED, false)) return null;
    const helper = String(env.TINYSA_HELPER_PATH || '/opt/nms-collector/nms-tinysa-sweep.py').trim();
    const band = String(profile?.band || env.TINYSA_BAND || '2.4GHz');
    const isWifiBand = band.startsWith('wifi_') || band === '2.4GHz' || band === '5GHz' || band === '6GHz';
    const sessionProfile = Boolean(profile);
    const defaultAggregation = isWifiBand ? 'max_hold' : 'single_sweep';
    const aggregation = String(
        sessionProfile ? 'max_hold' : (env.TINYSA_AGGREGATION || defaultAggregation)
    );
    const defaultRepetitions = aggregation === 'single_sweep' ? 1 : (sessionProfile ? 2 : (isWifiBand ? 8 : 4));
    const repetitions = sessionProfile
        ? parsePositiveInteger(env.TINYSA_SESSION_SWEEP_REPETITIONS, defaultRepetitions, 1, 8)
        : parsePositiveInteger(env.TINYSA_SWEEP_REPETITIONS, defaultRepetitions, 1, 32);
    const args = [
        '--json',
        '--start-hz', String(profile?.start_hz || parsePositiveInteger(env.TINYSA_START_HZ, 2400000000)),
        '--stop-hz', String(profile?.stop_hz || parsePositiveInteger(env.TINYSA_STOP_HZ, 2500000000)),
        '--points', String(profile?.points || parsePositiveInteger(env.TINYSA_POINTS, 290, 51, 450)),
        '--sweep-repetitions', String(repetitions),
        '--aggregation', aggregation,
        '--band', band,
        '--sensor-id', String(env.TINYSA_SENSOR_ID || 'tinysa-1'),
        '--device-model', String(env.TINYSA_DEVICE_MODEL || 'tinySA Ultra+ ZS407'),
        '--antenna-profile', String(env.TINYSA_ANTENNA_PROFILE || 'unknown'),
        '--calibration-state', String(env.TINYSA_CALIBRATION_STATE || 'uncalibrated')
    ];
    if (String(env.TINYSA_DEVICE || '').trim()) args.push('--device', String(env.TINYSA_DEVICE).trim());
    const result = await execFileAsync('python3', [helper, ...args], {
        timeoutMs: parsePositiveInteger(env.TINYSA_TIMEOUT_MS, 15000, 3000, 120000),
        maxBuffer: 4 * 1024 * 1024
    });
    if (!result.ok) return null;
    try {
        return { kind: 'rf', ...JSON.parse(result.stdout) };
    } catch {
        return null;
    }
}

function createTriggerState() {
    return { failures: new Map(), highLatency: new Map(), previousWifi: null, previousRfAverage: null };
}

function detectTriggers(records, state, incidents, env) {
    state.highLatency ||= new Map();
    const latencyThreshold = parsePositiveInteger(env.WIFI_ANALYSIS_LATENCY_THRESHOLD_MS, 200, 10, 60000);
    const gatewayLatencyThreshold = parsePositiveInteger(env.WIFI_ANALYSIS_GATEWAY_LATENCY_THRESHOLD_MS, 20, 5, 60000);
    const gatewayLatencyBurstCount = parsePositiveInteger(env.WIFI_ANALYSIS_GATEWAY_LATENCY_BURST_COUNT, 3, 2, 20);
    const failureThreshold = parsePositiveInteger(env.WIFI_ANALYSIS_FAILURE_BURST_COUNT, 3, 2, 20);
    const rssiDropThreshold = parsePositiveInteger(env.WIFI_ANALYSIS_RSSI_DROP_DB, 10, 3, 50);
    const rfSpikeThreshold = parsePositiveInteger(env.WIFI_ANALYSIS_RF_SPIKE_DB, 10, 3, 50);
    for (const record of records) {
        if (record.kind === 'connectivity') {
            const key = `${record.interface_role}:${record.target_kind}`;
            const failures = record.success ? 0 : (state.failures.get(key) || 0) + 1;
            state.failures.set(key, failures);
            const isWiredGateway = record.interface_role === 'wired' && record.target_kind === 'gateway';
            const threshold = isWiredGateway ? gatewayLatencyThreshold : latencyThreshold;
            const highLatencyCount = record.route_verified && Number.isFinite(record.latency_ms)
                && record.latency_ms >= threshold
                ? (state.highLatency.get(key) || 0) + 1
                : 0;
            state.highLatency.set(key, highLatencyCount);
            if (isWiredGateway && highLatencyCount === gatewayLatencyBurstCount) {
                incidents.trigger('gateway_latency_degraded', {
                    ...record,
                    threshold_ms: gatewayLatencyThreshold,
                    consecutive_samples: highLatencyCount
                }, record.observed_at);
            } else if (!isWiredGateway && record.route_verified && record.latency_ms >= threshold) {
                incidents.trigger('latency_threshold', record, record.observed_at);
            }
            if (record.route_verified && failures === failureThreshold) {
                incidents.trigger('packet_loss_burst', record, record.observed_at);
            }
        } else if (record.kind === 'wifi') {
            const previous = state.previousWifi;
            if (!record.connected) {
                for (const key of state.failures.keys()) {
                    if (key.startsWith('wireless:')) state.failures.delete(key);
                }
            }
            if (previous?.connected && record.connected && previous.bssid && record.bssid && previous.bssid !== record.bssid) {
                incidents.trigger('bssid_change', { previous_bssid: previous.bssid, current_bssid: record.bssid }, record.observed_at);
            }
            if (Number.isFinite(previous?.signal_dbm) && Number.isFinite(record.signal_dbm)
                && previous.signal_dbm - record.signal_dbm >= rssiDropThreshold) {
                incidents.trigger('rssi_drop', { previous_dbm: previous.signal_dbm, current_dbm: record.signal_dbm }, record.observed_at);
            }
            state.previousWifi = record;
        } else if (record.kind === 'rf' && Number.isFinite(record.average_dbm)) {
            if (Number.isFinite(state.previousRfAverage) && record.average_dbm - state.previousRfAverage >= rfSpikeThreshold) {
                incidents.trigger('rf_energy_spike', {
                    previous_average_dbm: state.previousRfAverage,
                    current_average_dbm: record.average_dbm
                }, record.observed_at);
            }
            state.previousRfAverage = record.average_dbm;
        }
    }
}

async function flushQueue(stateDir, env, dependencies = {}) {
    const collectorId = parsePositiveInteger(env.COLLECTOR_ID, 0);
    const baseUrls = resolveNmsBaseUrls(env);
    if (!collectorId || !baseUrls.length || !String(env.COLLECTOR_TOKEN || '').trim()) {
        return { sent: 0, pending: listQueuedBatches(stateDir).length };
    }
    let sent = 0;
    let invalid = 0;
    const request = dependencies.requestJson || requestJson;
    for (const filePath of listQueuedBatches(stateDir)) {
        const payload = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        try {
            await requestWithNmsFallback(env, (baseUrl) => request(
                `${baseUrl}/api/collectors/${collectorId}/wifi-analysis/batches`,
                payload,
                env
            ));
            fs.unlinkSync(filePath);
            sent += 1;
        } catch (error) {
            if (![400, 413].includes(error?.statusCode)) throw error;
            const invalidDir = path.join(stateDir, 'invalid');
            fs.mkdirSync(invalidDir, { recursive: true, mode: 0o700 });
            const invalidPath = path.join(invalidDir, path.basename(filePath));
            fs.renameSync(filePath, invalidPath);
            safeWriteJson(`${invalidPath}.error.json`, {
                quarantined_at: new Date().toISOString(),
                status_code: error.statusCode,
                error: String(error.message || error).slice(0, 500)
            });
            invalid += 1;
        }
    }
    return { sent, pending: listQueuedBatches(stateDir).length, invalid };
}

async function runAgent(env) {
    if (!parseBoolean(env.WIFI_ANALYSIS_ENABLED, false)) {
        console.log('Wi-Fi analysis is disabled');
        return;
    }
    const interfaces = await discoverInterfaces(env);
    if (!interfaces.wired || !interfaces.wireless) {
        throw new Error(`wired/wireless interfaces are required (wired=${interfaces.wired || 'missing'}, wireless=${interfaces.wireless || 'missing'})`);
    }
    const stateDir = String(env.WIFI_ANALYSIS_STATE_DIR || DEFAULT_STATE_DIR).trim();
    fs.mkdirSync(path.join(stateDir, 'queue'), { recursive: true, mode: 0o700 });
    const ring = new TimeRingBuffer(parsePositiveInteger(env.WIFI_ANALYSIS_RING_MINUTES, 15, 10, 60) * 60000);
    const incidents = new IncidentWindowManager({
        preMs: 300000,
        postMs: parsePositiveInteger(env.WIFI_ANALYSIS_POST_EVENT_SECONDS, 300, 30, 1800) * 1000
    });
    const triggerState = createTriggerState();
    const normalPending = [];
    const gateways = {
        wired: await getGateway(interfaces.wired),
        wireless: await getGateway(interfaces.wireless)
    };
    const normalLast = new Map();
    let lastWifiAt = 0;
    let lastRfAt = 0;
    let lastUploadAt = 0;
    let activeMeasurementSessionId = null;
    let rfProfileIndex = 0;
    let latestWifiSample = null;

    while (true) {
        const loopStartedAt = Date.now();
        const measurementStateFile = String(
            env.MEASUREMENT_SESSION_STATE_FILE || DEFAULT_MEASUREMENT_SESSION_STATE_FILE
        );
        const activeSession = readActiveMeasurementSession(measurementStateFile);
        if (enteredMeasurementSession(activeMeasurementSessionId, activeSession)) {
            lastWifiAt = 0;
            lastRfAt = 0;
            rfProfileIndex = 0;
        }
        activeMeasurementSessionId = activeSession?.measurement_session_id || null;
        const commonTargets = [
            ['internal', String(env.WIFI_ANALYSIS_INTERNAL_TARGET || '').trim()],
            ['kt_dns', String(env.DIAGNOSTIC_KT_PING_TARGET || '168.126.63.1').trim()],
            ['google_dns', String(env.DIAGNOSTIC_GOOGLE_PING_TARGET || '8.8.8.8').trim()]
        ];
        const records = [];
        const nowMs = Date.now();
        if (nowMs - lastWifiAt >= parsePositiveInteger(env.WIFI_ANALYSIS_WIFI_INTERVAL_SECONDS, 5, 2, 60) * 1000) {
            latestWifiSample = await collectWifiSample(interfaces.wireless);
            records.push(latestWifiSample);
            lastWifiAt = nowMs;
        }
        const pingPromises = [];
        const activeInterfaces = [['wired', interfaces.wired]];
        if (latestWifiSample?.connected) {
            activeInterfaces.push(['wireless', interfaces.wireless]);
        }
        for (const [role, interfaceName] of activeInterfaces) {
            const targets = [['gateway', gateways[role]], ...commonTargets];
            for (const [targetKind, target] of targets) {
                if (target) pingPromises.push(collectConnectivitySample(role, interfaceName, targetKind, target));
            }
        }
        records.push(...await Promise.all(pingPromises));
        if (parseBoolean(env.TINYSA_ENABLED, false)
            && nowMs - lastRfAt >= parsePositiveInteger(env.TINYSA_INTERVAL_SECONDS, 3, 1, 300) * 1000) {
            const sessionProfiles = activeSession?.module_run_ids?.rf
                ? measurementRfProfiles(env)
                : [];
            const profile = sessionProfiles.length
                ? sessionProfiles[rfProfileIndex % sessionProfiles.length]
                : null;
            const sweep = await collectRfSweep(env, profile);
            if (sweep) records.push(sweep);
            if (sessionProfiles.length) rfProfileIndex = (rfProfileIndex + 1) % sessionProfiles.length;
            lastRfAt = nowMs;
        }
        for (const record of records) attachMeasurementContext(record, activeSession);
        updateMeasurementSessionStats(measurementStateFile, activeSession, records);
        for (const record of records) ring.add(record);
        detectTriggers(records, triggerState, incidents, env);

        const normalStrideMs = parsePositiveInteger(env.WIFI_ANALYSIS_NORMAL_SAMPLE_SECONDS, 10, 5, 300) * 1000;
        for (const record of records) {
            if (record.kind === 'rf') {
                normalPending.push(record);
                continue;
            }
            const key = normalSampleKey(record);
            if (nowMs - (normalLast.get(key) || 0) >= normalStrideMs) {
                normalPending.push(record);
                normalLast.set(key, nowMs);
            }
        }
        for (const incident of incidents.collectCompleted(ring, nowMs)) {
            const event = {
                incident_id: incident.incident_id,
                trigger_type: incident.trigger_type,
                detected_at: incident.detected_at,
                window_start: incident.window_start,
                window_end: incident.window_end,
                evidence: incident.evidence,
                ...classifyIncident(incident.records, incident.trigger_type)
            };
            queueRecordBatches(stateDir, incident.records, event);
        }
        if (normalPending.length
            && nowMs - lastUploadAt >= parsePositiveInteger(env.WIFI_ANALYSIS_UPLOAD_INTERVAL_SECONDS, 10, 5, 300) * 1000) {
            queueRecordBatches(stateDir, normalPending.splice(0));
            lastUploadAt = nowMs;
        }
        safeWriteJson(path.join(stateDir, 'status.json'), {
            schema_version: SCHEMA_VERSION,
            updated_at: new Date().toISOString(),
            interfaces,
            gateways,
            ring_record_count: ring.records.length,
            active_incident_count: incidents.active.size,
            pending_batch_count: listQueuedBatches(stateDir).length,
            measurement_session_id: activeSession?.measurement_session_id || null
        });
        try {
            await flushQueue(stateDir, env);
        } catch (error) {
            console.error(`central delivery pending: ${error.message}`);
        }
        await new Promise((resolve) => setTimeout(resolve, Math.max(0, 1000 - (Date.now() - loopStartedAt))));
    }
}

async function doctor(env) {
    const interfaces = await discoverInterfaces(env);
    const helper = String(env.TINYSA_HELPER_PATH || '/opt/nms-collector/nms-tinysa-sweep.py');
    const result = {
        enabled: parseBoolean(env.WIFI_ANALYSIS_ENABLED, false),
        wired_interface: interfaces.wired || null,
        wireless_interface: interfaces.wireless || null,
        tiny_sa_enabled: parseBoolean(env.TINYSA_ENABLED, false),
        tiny_sa_helper_present: fs.existsSync(helper),
        nms_configured: Boolean(resolveNmsBaseUrl(env)
            && parsePositiveInteger(env.COLLECTOR_ID, 0)
            && String(env.COLLECTOR_TOKEN || '').trim()
            && env.COLLECTOR_TOKEN !== 'replace-with-agent-token')
    };
    result.ok = Boolean(result.wired_interface && result.wireless_interface && result.nms_configured
        && (!result.tiny_sa_enabled || result.tiny_sa_helper_present));
    return result;
}

async function main(argv = process.argv.slice(2)) {
    const command = argv[0] || 'run';
    const envFileIndex = argv.indexOf('--env-file');
    const env = parseEnvFile(envFileIndex >= 0 ? argv[envFileIndex + 1] : DEFAULT_ENV_FILE);
    if (command === 'doctor') {
        const result = await doctor(env);
        console.log(JSON.stringify(result, null, 2));
        return result.ok ? 0 : 1;
    }
    if (command === 'flush') {
        console.log(JSON.stringify(await flushQueue(String(env.WIFI_ANALYSIS_STATE_DIR || DEFAULT_STATE_DIR), env), null, 2));
        return 0;
    }
    if (command !== 'run') throw new Error('usage: nms-wifi-analysis.js [run|doctor|flush] [--env-file PATH]');
    await runAgent(env);
    return 0;
}

if (require.main === module) {
    main().then((code) => {
        process.exitCode = code;
    }).catch((error) => {
        console.error(error.message);
        process.exitCode = 1;
    });
}

module.exports = {
    IncidentWindowManager,
    NmsRequestError,
    TimeRingBuffer,
    attachMeasurementContext,
    buildBatch,
    classifyIncident,
    collectConnectivitySample,
    collectRfSweep,
    measurementRfProfiles,
    collectWifiSample,
    detectTriggers,
    discoverInterfaces,
    enteredMeasurementSession,
    frequencyToChannel,
    flushQueue,
    measurementTypeForRecord,
    normalSampleKey,
    parseDefaultGateway,
    parseEnvFile,
    parseIwChannelWidth,
    parseIwLink,
    parsePingOutput,
    parseRouteVerification,
    queueRecordBatches,
    readActiveMeasurementSession,
    updateMeasurementSessionStats,
    resolveNmsBaseUrl,
    resolveNmsBaseUrls,
    requestWithNmsFallback,
    splitRecordsIntoBatches
};
