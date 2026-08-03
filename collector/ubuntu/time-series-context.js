const crypto = require('crypto');
const fs = require('fs');

const DEFAULT_INTERVAL_SECONDS = 30;
const DEFAULT_TIMEZONE = 'Asia/Seoul';
const DEFAULT_STATE_FILE = '/var/lib/nms-collector/deployment-monitoring/active.json';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function intervalSeconds(value) {
    const parsed = Number.parseInt(String(value ?? ''), 10);
    return Number.isInteger(parsed) && parsed >= 5 && parsed <= 3600
        ? parsed
        : DEFAULT_INTERVAL_SECONDS;
}

function readActiveDeployment(filePath = DEFAULT_STATE_FILE) {
    try {
        const state = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const sessionId = String(state.deployment_session_id || '').trim().toLowerCase();
        if (!UUID_PATTERN.test(sessionId) || state.status !== 'running') return null;
        return {
            deployment_session_id: sessionId,
            status: 'running',
            started_at: state.started_at || null,
            timezone: String(state.timezone || DEFAULT_TIMEZONE),
            interval_seconds: intervalSeconds(state.interval_seconds),
            site_id: state.site_id || null,
            site_name: state.site_name || null
        };
    } catch {
        return null;
    }
}

function buildTimeSeriesContext(now = new Date(), state = null, configuredInterval = null) {
    const interval = intervalSeconds(state?.interval_seconds || configuredInterval);
    const epochMs = now.getTime();
    const windowMs = interval * 1000;
    const windowStartMs = Math.floor(epochMs / windowMs) * windowMs;
    return {
        deployment_session_id: state?.deployment_session_id || null,
        sequence_no: Math.floor(windowStartMs / windowMs),
        interval_seconds: interval,
        timezone: state?.timezone || DEFAULT_TIMEZONE,
        window_started_at: new Date(windowStartMs).toISOString(),
        window_ended_at: new Date(windowStartMs + windowMs).toISOString(),
        generated_at: now.toISOString(),
        clock_source: 'system_utc',
        missing_value_policy: 'unknown_not_zero'
    };
}

function newDeploymentState(options = {}, now = new Date()) {
    return {
        schema_version: 'metro-deployment-monitoring-v1',
        deployment_session_id: crypto.randomUUID(),
        status: 'running',
        started_at: now.toISOString(),
        timezone: String(options.timezone || DEFAULT_TIMEZONE),
        interval_seconds: intervalSeconds(options.interval_seconds),
        site_id: options.site_id || null,
        site_name: options.site_name || null
    };
}

module.exports = {
    DEFAULT_INTERVAL_SECONDS,
    DEFAULT_STATE_FILE,
    DEFAULT_TIMEZONE,
    buildTimeSeriesContext,
    intervalSeconds,
    newDeploymentState,
    readActiveDeployment
};
