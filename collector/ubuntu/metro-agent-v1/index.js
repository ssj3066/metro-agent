#!/usr/bin/env node

const crypto = require('crypto');
const os = require('os');
const path = require('path');
const {
    loadCollectorEnv,
    resolveNmsUrl,
    resolveNmsUrls
} = require('../nms-collector');
const queue = require('./lib/queue');
const { isEnabled, requestJson } = require('./lib/transport');
const pingPlugin = require('./plugins/ping');
const tcpPlugin = require('./plugins/tcp');
const httpPlugin = require('./plugins/http');
const systemPlugin = require('./plugins/system');
const {
    buildTimeSeriesContext,
    readActiveDeployment
} = require('../time-series-context');

const AGENT_VERSION = '0.1.0';
const DEFAULT_ENV_FILE = '/etc/nms-collector/collector.env';
const PLUGINS = {
    ping: pingPlugin,
    tcp: tcpPlugin,
    http: httpPlugin,
    system: systemPlugin
};
let preferredNmsBaseUrl = '';

function runtimePaths(env) {
    const root = String(env.METRO_AGENT_V1_STATE_DIR || '/var/lib/nms-collector/metro-agent-v1').trim();
    return {
        root,
        queue: String(env.METRO_AGENT_V1_QUEUE_DIR || path.join(root, 'queue')).trim(),
        config: path.join(root, 'config.json'),
        state: path.join(root, 'state.json')
    };
}

function collectorCredentials(env) {
    const collectorId = Number(env.COLLECTOR_ID);
    const token = String(env.COLLECTOR_TOKEN || env.AGENT_TOKEN || '').trim();
    if (!Number.isInteger(collectorId) || collectorId < 1) throw new Error('COLLECTOR_ID must be a positive integer');
    if (!token) throw new Error('COLLECTOR_TOKEN is required');
    return { collectorId, token };
}

function configUrl(env, collectorId) {
    return `${resolveNmsUrl(env).replace(/\/+$/, '')}/api/collectors/${collectorId}/metro-agent/config`;
}

function batchUrl(env, collectorId) {
    return `${resolveNmsUrl(env).replace(/\/+$/, '')}/api/collectors/${collectorId}/metro-agent/check-batches`;
}

async function requestWithFallback(env, pathSuffix, options, request) {
    const configuredUrls = resolveNmsUrls(env);
    const urls = preferredNmsBaseUrl && configuredUrls.includes(preferredNmsBaseUrl)
        ? [preferredNmsBaseUrl, ...configuredUrls.filter((url) => url !== preferredNmsBaseUrl)]
        : configuredUrls;
    let lastError = null;
    for (const baseUrl of urls) {
        try {
            const result = await request(`${baseUrl.replace(/\/+$/, '')}${pathSuffix}`, options);
            preferredNmsBaseUrl = baseUrl;
            return result;
        } catch (error) {
            lastError = error;
        }
    }
    throw lastError || new Error('metro agent has no NMS endpoint');
}

function validateConfig(config, expectedCollectorId) {
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('metro agent config is invalid');
    if (config.schema_version !== 'metro-agent-config-v1') throw new Error('metro agent config schema is unsupported');
    if (Number(config.collector_id) !== expectedCollectorId) throw new Error('metro agent config collector mismatch');
    if (!Number.isInteger(Number(config.revision)) || Number(config.revision) < 1) throw new Error('metro agent config revision is invalid');
    if (!Array.isArray(config.checks) || config.checks.length > 64) throw new Error('metro agent config checks are invalid');
    return {
        ...config,
        revision: Number(config.revision),
        interval_seconds: Math.max(30, Number(config.interval_seconds) || 60),
        enabled: config.enabled === true
    };
}

async function fetchConfig(env, credentials, dependencies = {}) {
    const request = dependencies.requestJson || requestJson;
    return validateConfig(await requestWithFallback(
        env,
        `/api/collectors/${credentials.collectorId}/metro-agent/config`,
        {
        method: 'GET',
        token: credentials.token,
        timeoutMs: Number(env.METRO_AGENT_V1_HTTP_TIMEOUT_MS) || 15000,
        env
        },
        request
    ), credentials.collectorId);
}

async function executePlan(config, dependencies = {}) {
    const plugins = dependencies.plugins || PLUGINS;
    const groups = await Promise.all(config.checks.map(async (check) => {
        const plugin = plugins[check.type];
        if (!plugin || typeof plugin.run !== 'function') {
            return [{
                result_id: `${check.key}:plugin`,
                check_key: check.key,
                check_type: check.type,
                target: check.target || null,
                status: 'unavailable',
                value: null,
                unit: null,
                observed_at: new Date().toISOString(),
                duration_ms: null,
                source: 'metro_agent_plugin_loader',
                error_code: 'plugin_unavailable',
                details: {}
            }];
        }
        try {
            return await plugin.run(check, dependencies.pluginContext || {});
        } catch (error) {
            return [{
                result_id: `${check.key}:execution`,
                check_key: check.key,
                check_type: check.type,
                target: check.target || null,
                status: 'failure',
                value: null,
                unit: null,
                observed_at: new Date().toISOString(),
                duration_ms: null,
                source: 'metro_agent_plugin_runner',
                error_code: String(error.code || 'plugin_failed').slice(0, 100),
                details: { message: String(error.message || 'plugin failed').slice(0, 500) }
            }];
        }
    }));
    return groups.flat();
}

function buildBatch(config, results, env, now = new Date()) {
    const deployment = readActiveDeployment(
        env.DEPLOYMENT_MONITORING_STATE_FILE
        || '/var/lib/nms-collector/deployment-monitoring/active.json'
    );
    const timeseries = buildTimeSeriesContext(now, deployment, config.interval_seconds);
    return {
        batch_id: crypto.randomUUID(),
        schema_version: 'metro-agent-check-batch-v1',
        config_revision: config.revision,
        generated_at: now.toISOString(),
        hostname: String(env.COLLECTOR_HOSTNAME || os.hostname()).trim(),
        agent_version: AGENT_VERSION,
        metadata: {
            platform: process.platform,
            architecture: process.arch,
            result_semantics: 'missing-is-not-zero',
            timeseries
        },
        results
    };
}

async function flushQueue(env, credentials, dependencies = {}) {
    const paths = runtimePaths(env);
    const request = dependencies.requestJson || requestJson;
    const files = queue.listBatchFiles(paths.queue).slice(0, Number(env.METRO_AGENT_V1_FLUSH_LIMIT) || 50);
    let delivered = 0;
    for (const filePath of files) {
        const batch = queue.readBatch(filePath);
        await requestWithFallback(
            env,
            `/api/collectors/${credentials.collectorId}/metro-agent/check-batches`,
            {
            method: 'POST',
            token: credentials.token,
            payload: batch,
            timeoutMs: Number(env.METRO_AGENT_V1_HTTP_TIMEOUT_MS) || 15000,
            env
            },
            request
        );
        queue.removeBatch(filePath);
        delivered += 1;
    }
    return {
        delivered,
        pending: queue.listBatchFiles(paths.queue).length
    };
}

function isRunDue(config, state, now = new Date()) {
    if (!state?.last_run_at) return true;
    const lastRun = new Date(state.last_run_at);
    if (Number.isNaN(lastRun.getTime())) return true;
    return now.getTime() - lastRun.getTime() >= config.interval_seconds * 1000;
}

async function runOnce(env, dependencies = {}, force = false) {
    const credentials = collectorCredentials(env);
    const paths = runtimePaths(env);
    queue.ensureDirectory(paths.queue);
    let config;
    let configSource = 'server';
    try {
        config = await fetchConfig(env, credentials, dependencies);
        queue.atomicWriteJson(paths.config, config);
    } catch (error) {
        config = queue.loadJson(paths.config);
        configSource = 'cache';
        if (!config) throw error;
        config = validateConfig(config, credentials.collectorId);
    }
    const flushPending = async () => {
        try {
            return await flushQueue(env, credentials, dependencies);
        } catch (error) {
            return {
                delivered: 0,
                pending: queue.listBatchFiles(paths.queue).length,
                error: error.message
            };
        }
    };
    if (!config.enabled) {
        return {
            state: 'disabled',
            config_source: configSource,
            config_revision: config.revision,
            delivery: await flushPending()
        };
    }
    if (!config.checks.length) {
        return {
            state: 'no_checks',
            config_source: configSource,
            config_revision: config.revision,
            delivery: await flushPending()
        };
    }
    const state = queue.loadJson(paths.state);
    if (!force && !isRunDue(config, state)) {
        return {
            state: 'not_due',
            config_source: configSource,
            config_revision: config.revision,
            delivery: await flushPending()
        };
    }
    const results = await executePlan(config, dependencies);
    const batch = buildBatch(config, results, env);
    queue.persistBatch(paths.queue, batch, Number(env.METRO_AGENT_V1_QUEUE_MAX_FILES) || 10000);
    queue.atomicWriteJson(paths.state, { last_run_at: batch.generated_at, config_revision: config.revision });
    const delivery = await flushPending();
    return {
        state: 'collected',
        config_source: configSource,
        config_revision: config.revision,
        result_count: results.length,
        delivery
    };
}

function doctor(env) {
    const paths = runtimePaths(env);
    const issues = [];
    try {
        collectorCredentials(env);
        resolveNmsUrl(env);
        queue.ensureDirectory(paths.queue);
    } catch (error) {
        issues.push(error.message);
    }
    return {
        ready: issues.length === 0,
        enabled: isEnabled(env.METRO_AGENT_V1_ENABLED),
        version: AGENT_VERSION,
        queue_directory: paths.queue,
        issues
    };
}

async function main(argv = process.argv.slice(2), suppliedEnv = null) {
    const env = suppliedEnv || loadCollectorEnv(process.env.ENV_FILE || DEFAULT_ENV_FILE);
    const command = argv[0] || 'doctor';
    if (command === 'run-once') {
        const result = await runOnce(env, {}, argv.includes('--force'));
        process.stdout.write(`${JSON.stringify(result)}\n`);
        return;
    }
    if (command === 'flush') {
        const result = await flushQueue(env, collectorCredentials(env));
        process.stdout.write(`${JSON.stringify(result)}\n`);
        return;
    }
    if (command === 'queue-status') {
        const paths = runtimePaths(env);
        process.stdout.write(`${JSON.stringify({ pending: queue.listBatchFiles(paths.queue).length })}\n`);
        return;
    }
    if (command === 'doctor') {
        const report = doctor(env);
        process.stdout.write(`${JSON.stringify(report)}\n`);
        if (!report.ready) process.exitCode = 1;
        return;
    }
    throw new Error(`unknown metro agent command: ${command}`);
}

if (require.main === module) {
    main().catch((error) => {
        console.error(`[metro-agent-v1] ${error.message}`);
        process.exitCode = 1;
    });
}

module.exports = {
    AGENT_VERSION,
    buildBatch,
    collectorCredentials,
    doctor,
    executePlan,
    fetchConfig,
    flushQueue,
    isRunDue,
    main,
    runOnce,
    runtimePaths,
    validateConfig
};
