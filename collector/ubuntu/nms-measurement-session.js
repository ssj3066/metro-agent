#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');
const { execFileSync, spawn } = require('child_process');

const {
    loadCollectorEnv,
    normalizeFieldMeasurementProfile,
    resolveNmsUrls,
    runLocalMeasurementSession
} = require('./nms-collector');
const { discoverInterfaces } = require('./nms-wifi-analysis');

const DEFAULT_ENV_FILE = '/etc/nms-collector/collector.env';
const DEFAULT_STATE_ROOT = '/var/lib/nms-collector/measurement-sessions';
const SESSION_SCHEMA_VERSION = 'metro-measurement-session-v1';
const MODULE_TYPES = ['wired', 'wireless', 'rf', 'packet_capture', 'system'];
const TERMINAL_SESSION_STATUSES = new Set(['completed', 'partial', 'failed', 'cancelled']);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

class MeasurementSessionRequestError extends Error {
    constructor(statusCode, body) {
        let message = '';
        try {
            const parsed = JSON.parse(String(body || '{}'));
            message = parsed.error?.message || parsed.detail || parsed.error || '';
        } catch {
            message = String(body || '').slice(0, 300);
        }
        super(`NMS HTTP ${statusCode}${message ? `: ${message}` : ''}`);
        this.statusCode = statusCode;
    }
}

function parseBoolean(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

function positiveInteger(value, fallback, minimum, maximum) {
    const parsed = Number.parseInt(String(value ?? ''), 10);
    return Number.isInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : fallback;
}

function statePaths(env = process.env) {
    const root = String(env.MEASUREMENT_SESSION_STATE_DIR || DEFAULT_STATE_ROOT).trim()
        || DEFAULT_STATE_ROOT;
    return {
        root,
        active: path.join(root, 'active.json'),
        last: path.join(root, 'last.json'),
        sessions: path.join(root, 'sessions')
    };
}

function writeJsonAtomically(filePath, value) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o750 });
    const temporary = path.join(
        path.dirname(filePath),
        `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`
    );
    fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
        encoding: 'utf8',
        mode: 0o640
    });
    fs.renameSync(temporary, filePath);
    fs.chmodSync(filePath, 0o640);
}

function readJson(filePath) {
    try {
        const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
    } catch {
        return null;
    }
}

function processAlive(pid) {
    if (!Number.isInteger(Number(pid)) || Number(pid) < 1) return false;
    try {
        process.kill(Number(pid), 0);
        return true;
    } catch {
        return false;
    }
}

function commandOutput(command, args) {
    try {
        return String(execFileSync(command, args, {
            encoding: 'utf8',
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'ignore']
        }) || '').trim();
    } catch {
        return '';
    }
}

function parseChronyTracking(output) {
    const text = String(output || '');
    const offset = text.match(/Last offset\s*:\s*([+-]?[0-9.]+)\s+seconds/i);
    return offset ? Number(offset[1]) * 1000 : null;
}

function classifyClockState(synchronized, offsetMs) {
    if (synchronized === 'no') return 'unsynced';
    if (offsetMs !== null && Number.isFinite(offsetMs)) {
        const absoluteOffset = Math.abs(offsetMs);
        if (absoluteOffset <= 1000) return 'synced';
        if (absoluteOffset <= 5000) return 'degraded';
        return 'unsynced';
    }
    return synchronized === 'yes' ? 'synced' : 'unknown';
}

function inspectClock() {
    const synchronized = commandOutput('timedatectl', ['show', '-p', 'NTPSynchronized', '--value']);
    const chrony = commandOutput('chronyc', ['tracking']);
    const offsetMs = parseChronyTracking(chrony);
    return {
        ntp_state: classifyClockState(synchronized, offsetMs),
        offset_ms: offsetMs,
        server_clock_delta_ms: null,
        source: chrony ? 'chronyc_tracking' : (synchronized ? 'timedatectl' : 'unavailable')
    };
}

function normalizeModuleSelection(value, env = {}) {
    const requested = String(value || 'wired,wireless,rf,system')
        .split(',')
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean);
    const unknown = requested.filter((item) => !MODULE_TYPES.includes(item));
    if (unknown.length) throw new Error(`unknown measurement modules: ${unknown.join(', ')}`);
    const selected = new Set(requested);
    if (parseBoolean(env.MEASUREMENT_PACKET_CAPTURE_DEFAULT, false)) selected.add('packet_capture');
    const modules = Object.fromEntries(MODULE_TYPES.map((name) => [name, selected.has(name)]));
    if (!Object.values(modules).some(Boolean)) throw new Error('at least one measurement module is required');
    return modules;
}

function rfDevicePath(env) {
    const configured = String(env.TINYSA_DEVICE || '/dev/tinysa4').trim();
    return configured || '/dev/tinysa4';
}

async function buildPreflight(env, serverClockDeltaMs = null) {
    const interfaces = await discoverInterfaces(env);
    const rfPath = rfDevicePath(env);
    const rfHelper = String(env.TINYSA_HELPER_PATH || '/opt/nms-collector/nms-tinysa-sweep.py').trim();
    const clock = inspectClock();
    clock.server_clock_delta_ms = serverClockDeltaMs;
    return {
        checked_at: new Date().toISOString(),
        clock,
        interfaces,
        devices: [
            {
                local_device_id: interfaces.wired || 'wired-interface-missing',
                measurement_type: 'wired',
                device_kind: 'network_interface',
                model: null,
                serial_number: null,
                firmware_version: null,
                interface_name: interfaces.wired || null,
                device_path: interfaces.wired ? `/sys/class/net/${interfaces.wired}` : null,
                status: interfaces.wired ? 'ready' : 'unavailable',
                settings: {}
            },
            {
                local_device_id: interfaces.wireless || 'wireless-interface-missing',
                measurement_type: 'wireless',
                device_kind: 'wireless_interface',
                model: null,
                serial_number: null,
                firmware_version: null,
                interface_name: interfaces.wireless || null,
                device_path: interfaces.wireless ? `/sys/class/net/${interfaces.wireless}` : null,
                status: interfaces.wireless ? 'ready' : 'unavailable',
                settings: {}
            },
            {
                local_device_id: String(env.TINYSA_SENSOR_ID || 'tinysa-zs407-400'),
                measurement_type: 'rf',
                device_kind: 'spectrum_analyzer',
                model: String(env.TINYSA_DEVICE_MODEL || 'tinySA Ultra+ ZS407'),
                serial_number: String(env.TINYSA_SERIAL_NUMBER || '').trim() || null,
                firmware_version: null,
                interface_name: null,
                device_path: rfPath,
                status: fs.existsSync(rfPath) && fs.existsSync(rfHelper) ? 'ready' : 'unavailable',
                settings: {
                    antenna_profile: String(env.TINYSA_ANTENNA_PROFILE || 'unknown'),
                    calibration_state: String(env.TINYSA_CALIBRATION_STATE || 'uncalibrated'),
                    helper_present: fs.existsSync(rfHelper)
                }
            },
            {
                local_device_id: os.hostname(),
                measurement_type: 'system',
                device_kind: 'collector_host',
                model: null,
                serial_number: null,
                firmware_version: os.release(),
                interface_name: null,
                device_path: null,
                status: 'ready',
                settings: { platform: os.platform(), architecture: os.arch() }
            }
        ]
    };
}

function assessServerClock(deltaMs, roundTripMs, correlationWindowMs) {
    const delta = Number(deltaMs);
    const roundTrip = Math.max(0, Number(roundTripMs) || 0);
    const window = Math.max(100, Number(correlationWindowMs) || 1000);
    if (!Number.isFinite(delta)) {
        return { state: 'unknown', reliable_delta_ms: null, uncertainty_ms: null };
    }
    const uncertainty = roundTrip / 2;
    const reliableDelta = Math.max(0, Math.abs(delta) - uncertainty);
    return {
        state: reliableDelta <= window ? 'synced' : 'unsynced',
        reliable_delta_ms: Number(reliableDelta.toFixed(3)),
        uncertainty_ms: Number(uncertainty.toFixed(3))
    };
}

function requestJson(urlValue, method, payload, env) {
    const target = new URL(urlValue);
    const body = payload === null || payload === undefined
        ? Buffer.alloc(0)
        : Buffer.from(JSON.stringify(payload));
    const transport = target.protocol === 'https:' ? https : http;
    const options = {
        method,
        hostname: target.hostname,
        port: target.port || (target.protocol === 'https:' ? 443 : 80),
        path: `${target.pathname}${target.search}`,
        headers: {
            Accept: 'application/json',
            'X-Collector-Token': String(env.COLLECTOR_TOKEN || '')
        },
        timeout: 15000
    };
    if (body.length) {
        options.headers['Content-Type'] = 'application/json';
        options.headers['Content-Length'] = body.length;
    }
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
                if (responseBody.length < 1024 * 1024) responseBody += chunk;
            });
            response.on('end', () => {
                if (response.statusCode >= 200 && response.statusCode < 300) {
                    try {
                        resolve(responseBody.trim() ? JSON.parse(responseBody) : {});
                    } catch {
                        reject(new Error('NMS returned invalid JSON'));
                    }
                } else {
                    reject(new MeasurementSessionRequestError(response.statusCode, responseBody));
                }
            });
        });
        request.on('timeout', () => request.destroy(new Error('NMS request timeout')));
        request.on('error', reject);
        request.end(body);
    });
}

async function nmsRequest(env, method, apiPath, payload = null) {
    const urls = resolveNmsUrls(env);
    if (!urls.length) throw new Error('NMS URL is not configured');
    let lastError = null;
    for (const baseUrl of urls) {
        try {
            return await requestJson(`${baseUrl}${apiPath}`, method, payload, env);
        } catch (error) {
            lastError = error;
            if (error.statusCode && error.statusCode < 500) throw error;
        }
    }
    throw lastError || new Error('NMS request failed');
}

function collectorId(env) {
    const value = positiveInteger(env.COLLECTOR_ID, 0, 1, Number.MAX_SAFE_INTEGER);
    if (!value) throw new Error('COLLECTOR_ID is not configured');
    if (!String(env.COLLECTOR_TOKEN || '').trim()) throw new Error('COLLECTOR_TOKEN is not configured');
    return value;
}

function sessionApiPath(env, sessionId = null, suffix = '') {
    const root = `/api/collectors/${collectorId(env)}/measurement-sessions`;
    return `${root}${sessionId ? `/${sessionId}` : ''}${suffix}`;
}

async function readStdinJson(maxBytes = 65536) {
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
        size += Buffer.byteLength(chunk);
        if (size > maxBytes) throw new Error('field profile input is too large');
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const text = Buffer.concat(chunks).toString('utf8').trim();
    if (!text) throw new Error('field profile JSON is required on standard input');
    const value = JSON.parse(text);
    normalizeFieldMeasurementProfile(value);
    return value;
}

function parseOptions(argv) {
    const options = {};
    for (let index = 0; index < argv.length; index += 1) {
        const key = argv[index];
        if (!key.startsWith('--')) continue;
        const name = key.slice(2).replaceAll('-', '_');
        const next = argv[index + 1];
        if (!next || next.startsWith('--')) {
            options[name] = true;
        } else {
            options[name] = next;
            index += 1;
        }
    }
    return options;
}

function sessionFile(paths, sessionId) {
    return path.join(paths.sessions, sessionId, 'session.json');
}

function writeSessionState(paths, state) {
    const stateFile = sessionFile(paths, state.measurement_session_id);
    writeJsonAtomically(stateFile, state);
    if (!['completed', 'partial', 'failed', 'cancelled'].includes(state.status)) {
        writeJsonAtomically(paths.active, state);
    } else {
        writeJsonAtomically(paths.last, state);
        const active = readJson(paths.active);
        if (active?.measurement_session_id === state.measurement_session_id) {
            fs.unlinkSync(paths.active);
        }
    }
    return stateFile;
}

function readActiveState(paths) {
    const active = readJson(paths.active);
    if (!active) return null;
    if (['completed', 'partial', 'failed', 'cancelled'].includes(active.status)) return null;
    return active;
}

async function postModuleRun(env, state, measurementType, status, detail = {}) {
    const module = state.module_runs[measurementType];
    if (!module) return null;
    const now = new Date().toISOString();
    const payload = {
        module_run_id: module.module_run_id,
        measurement_type: measurementType,
        status,
        started_at: module.started_at || (status === 'running' ? now : null),
        ended_at: ['completed', 'failed', 'unsupported', 'skipped', 'stopped'].includes(status)
            ? (detail.ended_at || now)
            : null,
        sample_count: Number(detail.sample_count ?? module.sample_count ?? 0),
        source_delay_ms: detail.source_delay_ms ?? null,
        ingest_delay_ms: detail.ingest_delay_ms ?? null,
        error_code: detail.error_code || null,
        error_message: detail.error_message || null,
        settings: module.settings || {}
    };
    const result = await nmsRequest(
        env,
        'POST',
        sessionApiPath(env, state.measurement_session_id, '/module-runs'),
        payload
    );
    Object.assign(module, payload);
    return result;
}

async function startSession(env, options, fieldProfile) {
    const paths = statePaths(env);
    const active = readActiveState(paths);
    if (active && processAlive(active.worker_pid)) {
        throw new Error(`measurement session ${active.measurement_session_id} is already active`);
    }
    if (active) {
        active.status = 'failed';
        active.ended_at = new Date().toISOString();
        active.error_code = 'orphaned_session_recovered';
        writeSessionState(paths, active);
    }

    const sessionId = crypto.randomUUID();
    const durationSeconds = positiveInteger(options.duration, 300, 10, 28800);
    const intervalSeconds = positiveInteger(options.interval, 10, 2, 300);
    const modules = normalizeModuleSelection(options.modules, env);
    const createPayload = {
        schema_version: SESSION_SCHEMA_VERSION,
        measurement_session_id: sessionId,
        idempotency_key: sessionId,
        site_id: fieldProfile.site_id || null,
        customer_id: fieldProfile.customer_id || null,
        field_profile: fieldProfile,
        timezone: 'Asia/Seoul',
        requested_duration_seconds: durationSeconds,
        correlation_window_ms: positiveInteger(options.correlation_window_ms, 1000, 100, 30000),
        modules,
        sampling: {
            wired_interval_ms: intervalSeconds * 1000,
            wireless_interval_ms: positiveInteger(
                env.WIFI_ANALYSIS_WIFI_INTERVAL_SECONDS,
                5,
                2,
                60
            ) * 1000,
            rf_interval_ms: positiveInteger(env.TINYSA_INTERVAL_SECONDS, 3, 1, 300) * 1000,
            system_interval_ms: intervalSeconds * 1000
        },
        operator: {
            name: fieldProfile.metro_contact?.name || os.userInfo().username
        },
        notes: String(options.notes || '')
    };
    const requestStartedAt = Date.now();
    const created = await nmsRequest(env, 'POST', sessionApiPath(env), createPayload);
    const requestFinishedAt = Date.now();
    const requestRoundTripMs = requestFinishedAt - requestStartedAt;
    const requestMidpoint = requestStartedAt + (requestRoundTripMs / 2);
    const serverClockDeltaMs = created.server_time
        ? Date.parse(created.server_time) - requestMidpoint
        : null;
    const preflight = await buildPreflight(env, serverClockDeltaMs);
    const serverClock = assessServerClock(
        serverClockDeltaMs,
        requestRoundTripMs,
        createPayload.correlation_window_ms
    );
    preflight.clock.server_round_trip_ms = requestRoundTripMs;
    preflight.clock.server_clock_uncertainty_ms = serverClock.uncertainty_ms;
    preflight.clock.server_clock_reliable_delta_ms = serverClock.reliable_delta_ms;
    preflight.clock.server_clock_state = serverClock.state;
    await nmsRequest(
        env,
        'POST',
        sessionApiPath(env, sessionId, '/preflight'),
        preflight
    );
    const state = {
        schema_version: SESSION_SCHEMA_VERSION,
        measurement_session_id: sessionId,
        status: 'preflight',
        timezone: 'Asia/Seoul',
        correlation_window_ms: createPayload.correlation_window_ms,
        field_profile: fieldProfile,
        duration_seconds: durationSeconds,
        interval_seconds: intervalSeconds,
        modules,
        module_runs: Object.fromEntries(MODULE_TYPES
            .filter((name) => modules[name])
            .map((name) => [name, {
                module_run_id: crypto.randomUUID(),
                status: 'pending',
                sample_count: 0,
                settings: {}
            }])),
        preflight,
        created_at: new Date().toISOString(),
        started_at: null,
        ends_at: null,
        worker_pid: null,
        log_path: path.join(paths.sessions, sessionId, 'worker.log')
    };
    writeSessionState(paths, state);
    fs.mkdirSync(path.dirname(state.log_path), { recursive: true, mode: 0o750 });
    const logFd = fs.openSync(state.log_path, 'a', 0o640);
    const worker = spawn(process.execPath, [
        __filename,
        'worker',
        '--session-id',
        sessionId,
        '--env-file',
        options.env_file || process.env.ENV_FILE || DEFAULT_ENV_FILE
    ], {
        detached: true,
        stdio: ['ignore', logFd, logFd],
        env: {
            ...process.env,
            ENV_FILE: options.env_file || process.env.ENV_FILE || DEFAULT_ENV_FILE
        }
    });
    fs.closeSync(logFd);
    state.worker_pid = worker.pid;
    const latestState = readJson(sessionFile(paths, sessionId));
    if (!latestState || latestState.status === 'preflight') {
        writeSessionState(paths, { ...state, ...(latestState || {}), worker_pid: worker.pid });
    }
    worker.unref();
    return {
        measurement_session_id: sessionId,
        status: state.status,
        worker_pid: worker.pid,
        modules,
        preflight: {
            ntp_state: preflight.clock.ntp_state,
            wired: preflight.interfaces.wired || null,
            wireless: preflight.interfaces.wireless || null,
            rf: preflight.devices.find((device) => device.measurement_type === 'rf')?.status || 'unknown'
        }
    };
}

function preflightDeviceStatus(state, measurementType) {
    return state.preflight?.devices?.find((device) => device.measurement_type === measurementType)?.status
        || 'unknown';
}

function requiredRfBands(env = {}) {
    const allowed = new Set(['wifi_2_4ghz', 'wifi_5ghz', 'wifi_6ghz']);
    return [...new Set(
        String(env.TINYSA_SESSION_BANDS || 'wifi_2_4ghz,wifi_5ghz,wifi_6ghz')
            .split(',')
            .map((value) => value.trim())
            .filter((value) => allowed.has(value))
    )];
}

function interruptedModuleResult(reason, moduleRun, sampleCount = 0) {
    if (reason !== 'operator_stop') return null;
    if (!moduleRun || !['pending', 'running', 'paused'].includes(moduleRun.status)) return null;
    return {
        status: 'stopped',
        sample_count: Math.max(0, Number(sampleCount) || Number(moduleRun.sample_count) || 0),
        error_code: 'operator_stopped',
        error_message: 'Operator safely stopped the measurement session'
    };
}

function controlSignals(action, state = {}) {
    if (action === 'pause') return ['SIGSTOP'];
    if (action === 'resume') return ['SIGCONT'];
    if (action === 'stop') {
        return state.paused_at ? ['SIGCONT', 'SIGTERM'] : ['SIGTERM'];
    }
    throw new Error(`unsupported control action: ${action}`);
}

async function finalizeWorker(env, paths, state, reason = 'natural_completion') {
    if (state.finalizing) return state;
    state.finalizing = true;
    state.finalize_reason = reason;
    writeSessionState(paths, state);
    const stats = readJson(path.join(
        paths.sessions,
        state.measurement_session_id,
        'wifi-analysis.json'
    )) || {};

    for (const measurementType of ['wireless', 'rf']) {
        if (!state.modules[measurementType]) continue;
        const count = Number(stats[`${measurementType}_sample_count`] || 0);
        const expectedRfBands = measurementType === 'rf' ? requiredRfBands(env) : [];
        const observedRfBands = measurementType === 'rf' && Array.isArray(stats.rf_bands)
            ? stats.rf_bands.filter((band) => expectedRfBands.includes(band))
            : [];
        const missingRfBands = expectedRfBands.filter((band) => !observedRfBands.includes(band));
        if (measurementType === 'rf') {
            state.module_runs.rf.settings = {
                ...(state.module_runs.rf.settings || {}),
                expected_bands: expectedRfBands,
                observed_bands: observedRfBands,
                missing_bands: missingRfBands
            };
        }
        if (count > 0 && measurementType === 'rf' && missingRfBands.length) {
            const stopped = reason === 'operator_stop';
            await postModuleRun(env, state, measurementType, stopped ? 'stopped' : 'failed', {
                sample_count: count,
                error_code: stopped ? 'operator_stopped_rf_coverage_partial' : 'rf_band_coverage_incomplete',
                error_message: `RF bands not measured: ${missingRfBands.join(', ')}`
            });
        } else if (count > 0) {
            await postModuleRun(env, state, measurementType, 'completed', { sample_count: count });
        } else if (interruptedModuleResult(reason, state.module_runs[measurementType], count)) {
            const interrupted = interruptedModuleResult(
                reason,
                state.module_runs[measurementType],
                count
            );
            await postModuleRun(env, state, measurementType, interrupted.status, interrupted);
        } else {
            const status = preflightDeviceStatus(state, measurementType);
            await postModuleRun(
                env,
                state,
                measurementType,
                status === 'unavailable' ? 'unsupported' : 'failed',
                {
                    sample_count: 0,
                    error_code: status === 'unavailable'
                        ? `${measurementType}_device_unavailable`
                        : `${measurementType}_samples_missing`,
                    error_message: status === 'unavailable'
                        ? `${measurementType} device was unavailable during preflight`
                        : `${measurementType} module produced no session samples`
                }
            );
        }
    }
    for (const measurementType of ['wired', 'system']) {
        if (!state.modules[measurementType]) continue;
        const interrupted = interruptedModuleResult(
            reason,
            state.module_runs[measurementType]
        );
        if (interrupted) {
            await postModuleRun(env, state, measurementType, interrupted.status, interrupted);
        }
    }
    if (state.modules.packet_capture) {
        const interrupted = interruptedModuleResult(
            reason,
            state.module_runs.packet_capture
        );
        if (interrupted) {
            await postModuleRun(env, state, 'packet_capture', interrupted.status, interrupted);
        } else if (state.module_runs.packet_capture?.status === 'running') {
            await postModuleRun(env, state, 'packet_capture', 'skipped', {
                error_code: 'packet_capture_not_requested_by_profile',
                error_message: 'Packet capture adapter is not enabled for this session profile'
            });
        }
    }
    const completed = await nmsRequest(
        env,
        'POST',
        sessionApiPath(env, state.measurement_session_id, '/complete'),
        { ended_at: new Date().toISOString() }
    );
    state.status = completed.status;
    state.ended_at = completed.ended_at || new Date().toISOString();
    state.module_summary = completed.module_summary || {};
    state.finalizing = false;
    writeSessionState(paths, state);
    return state;
}

async function runWorker(env, sessionId) {
    if (!UUID_PATTERN.test(sessionId)) throw new Error('worker session id must be a UUID');
    const paths = statePaths(env);
    const stateFile = sessionFile(paths, sessionId);
    const state = readJson(stateFile);
    if (!state) throw new Error(`measurement session state not found: ${sessionId}`);
    state.worker_pid = process.pid;
    state.status = 'running';
    state.started_at = new Date().toISOString();
    state.ends_at = new Date(Date.now() + state.duration_seconds * 1000).toISOString();
    await nmsRequest(env, 'PATCH', sessionApiPath(env, sessionId), { action: 'start' });
    writeSessionState(paths, state);

    let stopRequested = false;
    const stopHandler = () => {
        if (stopRequested) return;
        stopRequested = true;
        state.status = 'stopping';
        state.stopping_at ||= new Date().toISOString();
        writeSessionState(paths, state);
    };
    process.on('SIGTERM', stopHandler);
    process.on('SIGINT', stopHandler);

    for (const measurementType of Object.keys(state.module_runs)) {
        const deviceStatus = preflightDeviceStatus(state, measurementType);
        if (['wireless', 'rf'].includes(measurementType) && deviceStatus === 'unavailable') {
            await postModuleRun(env, state, measurementType, 'unsupported', {
                error_code: `${measurementType}_device_unavailable`,
                error_message: `${measurementType} device was unavailable during preflight`
            });
            continue;
        }
        await postModuleRun(env, state, measurementType, 'running');
    }
    writeSessionState(paths, state);

    try {
        if (state.modules.wired || state.modules.system) {
            const legacy = await runLocalMeasurementSession(
                env,
                state.duration_seconds,
                state.interval_seconds,
                state.field_profile,
                state.measurement_session_id,
                Object.fromEntries(Object.entries(state.module_runs).map(
                    ([measurementType, moduleRun]) => [
                        measurementType,
                        moduleRun.module_run_id
                    ]
                )),
                {
                    shouldStop: () => stopRequested,
                    onProgress: ({ rounds_completed: roundsCompleted, observed_at: observedAt }) => {
                        for (const measurementType of ['wired', 'system']) {
                            if (!state.modules[measurementType]) continue;
                            state.module_runs[measurementType].sample_count = roundsCompleted;
                            state.module_runs[measurementType].last_sample_at = observedAt;
                        }
                        writeSessionState(paths, state);
                    }
                }
            );
            const session = legacy.measurement_session || {};
            const sampleCount = Number(session.rounds_completed || 0);
            for (const measurementType of ['wired', 'system']) {
                if (!state.modules[measurementType]) continue;
                if (stopRequested) {
                    const interrupted = interruptedModuleResult(
                        'operator_stop',
                        state.module_runs[measurementType],
                        sampleCount
                    );
                    await postModuleRun(env, state, measurementType, interrupted.status, interrupted);
                } else {
                    await postModuleRun(env, state, measurementType, 'completed', {
                        sample_count: sampleCount
                    });
                }
            }
        } else {
            await new Promise((resolve) => setTimeout(resolve, state.duration_seconds * 1000));
        }
        await finalizeWorker(env, paths, state, stopRequested ? 'operator_stop' : 'natural_completion');
    } catch (error) {
        for (const measurementType of ['wired', 'system']) {
            if (!state.modules[measurementType]) continue;
            await postModuleRun(env, state, measurementType, 'failed', {
                error_code: 'measurement_worker_error',
                error_message: error.message
            }).catch(() => {});
        }
        state.error_code = 'measurement_worker_error';
        state.error_message = error.message;
        await finalizeWorker(env, paths, state, 'worker_error');
    }
}

async function controlSession(env, action) {
    const paths = statePaths(env);
    const state = readActiveState(paths);
    if (!state) throw new Error('no active measurement session');
    if (!processAlive(state.worker_pid)) {
        throw new Error(`measurement session worker is not running (pid=${state.worker_pid || 'missing'})`);
    }
    const signals = controlSignals(action, state);
    await nmsRequest(
        env,
        'PATCH',
        sessionApiPath(env, state.measurement_session_id),
        { action }
    );
    state.status = action === 'pause' ? 'paused'
        : action === 'resume' ? 'running'
            : 'stopping';
    if (action === 'pause') state.paused_at = new Date().toISOString();
    if (action === 'resume') state.paused_at = null;
    if (action === 'stop') state.stopping_at = new Date().toISOString();
    writeSessionState(paths, state);
    for (const signal of signals) {
        process.kill(Number(state.worker_pid), signal);
    }
    return {
        measurement_session_id: state.measurement_session_id,
        status: state.status,
        worker_pid: state.worker_pid
    };
}

function sessionStatus(env) {
    const paths = statePaths(env);
    const active = readJson(paths.active);
    if (!active) {
        const last = readJson(paths.last);
        return last ? { ...last, active: false, worker_alive: false } : { status: 'idle', active: false };
    }
    return {
        ...active,
        active: !['completed', 'partial', 'failed', 'cancelled'].includes(active.status),
        worker_alive: processAlive(active.worker_pid)
    };
}

function listSessionArchives(env) {
    const paths = statePaths(env);
    if (!fs.existsSync(paths.sessions)) return [];
    return fs.readdirSync(paths.sessions, { withFileTypes: true })
        .filter((entry) => entry.isDirectory() && UUID_PATTERN.test(entry.name))
        .map((entry) => readJson(sessionFile(paths, entry.name)))
        .filter(Boolean)
        .map((state) => ({
            measurement_session_id: state.measurement_session_id,
            status: state.status || 'unknown',
            customer_id: state.field_profile?.customer_id || null,
            customer_name: state.field_profile?.customer_name || null,
            site_id: state.field_profile?.site_id || null,
            site_name: state.field_profile?.site_name || null,
            created_at: state.created_at || null,
            started_at: state.started_at || null,
            ended_at: state.ended_at || null,
            duration_seconds: state.duration_seconds || null,
            modules: state.modules || {},
            active: !TERMINAL_SESSION_STATUSES.has(state.status) && processAlive(state.worker_pid)
        }))
        .sort((a, b) => String(b.started_at || b.created_at || '')
            .localeCompare(String(a.started_at || a.created_at || '')));
}

function readSessionArchive(env, sessionIdValue) {
    const sessionId = String(sessionIdValue || '').trim().toLowerCase();
    if (!UUID_PATTERN.test(sessionId)) throw new Error('session id must be a UUID');
    const state = readJson(sessionFile(statePaths(env), sessionId));
    if (!state) throw new Error(`measurement session archive not found: ${sessionId}`);
    return state;
}

function deleteSessionArchive(env, sessionIdValue) {
    const paths = statePaths(env);
    const state = readSessionArchive(env, sessionIdValue);
    if (!TERMINAL_SESSION_STATUSES.has(state.status) || processAlive(state.worker_pid)) {
        throw new Error('active measurement session archive cannot be deleted');
    }
    fs.rmSync(path.dirname(sessionFile(paths, state.measurement_session_id)), {
        recursive: true,
        force: false
    });
    const last = readJson(paths.last);
    if (last?.measurement_session_id === state.measurement_session_id) {
        const replacement = listSessionArchives(env)[0] || null;
        if (replacement) {
            writeJsonAtomically(paths.last, readSessionArchive(env, replacement.measurement_session_id));
        } else if (fs.existsSync(paths.last)) {
            fs.unlinkSync(paths.last);
        }
    }
    return {
        deleted: true,
        measurement_session_id: state.measurement_session_id,
        local_only: true
    };
}

async function main(argv = process.argv.slice(2)) {
    const command = argv[0] || 'status';
    const options = parseOptions(argv.slice(1));
    const envFile = options.env_file || process.env.ENV_FILE || DEFAULT_ENV_FILE;
    const env = loadCollectorEnv(envFile);
    if (command === 'start') {
        const fieldProfile = await readStdinJson();
        console.log(JSON.stringify(await startSession(env, { ...options, env_file: envFile }, fieldProfile), null, 2));
        return;
    }
    if (command === 'worker') {
        await runWorker(env, String(options.session_id || '').trim().toLowerCase());
        return;
    }
    if (['pause', 'resume', 'stop'].includes(command)) {
        console.log(JSON.stringify(await controlSession(env, command), null, 2));
        return;
    }
    if (command === 'status') {
        console.log(JSON.stringify(sessionStatus(env), null, 2));
        return;
    }
    if (command === 'list') {
        console.log(JSON.stringify({ sessions: listSessionArchives(env) }, null, 2));
        return;
    }
    if (command === 'show') {
        console.log(JSON.stringify(readSessionArchive(env, options.session_id), null, 2));
        return;
    }
    if (command === 'delete') {
        console.log(JSON.stringify(deleteSessionArchive(env, options.session_id), null, 2));
        return;
    }
    throw new Error('usage: nms-measurement-session.js [start|status|pause|resume|stop|list|show|delete|worker]');
}

if (require.main === module) {
    main().catch((error) => {
        console.error(`[nms-measurement-session] ${error.message}`);
        process.exitCode = 1;
    });
}

module.exports = {
    MeasurementSessionRequestError,
    buildPreflight,
    classifyClockState,
    controlSignals,
    deleteSessionArchive,
    inspectClock,
    assessServerClock,
    interruptedModuleResult,
    requiredRfBands,
    normalizeModuleSelection,
    parseChronyTracking,
    parseOptions,
    processAlive,
    readActiveState,
    readSessionArchive,
    listSessionArchives,
    sessionStatus,
    statePaths,
    writeJsonAtomically,
    writeSessionState
};
