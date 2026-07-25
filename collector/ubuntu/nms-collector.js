#!/usr/bin/env node

const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const net = require('net');
const os = require('os');
const path = require('path');
const { execFile, execFileSync } = require('child_process');
const { URL } = require('url');

const DEFAULT_ENV_FILE = '/etc/nms-collector/collector.env';
const DEFAULT_FIELD_MEASUREMENT_QUEUE_DIR = '/var/lib/nms-collector/field-measurements';
const EDGE_COLLECTOR_VERSION = 'ubuntu-edge-collector/0.2.1';
const PLACEHOLDER_TOKENS = new Set([
    'replace-with-agent-token',
    'changeme',
    'your-token-here'
]);
const COLLECTOR_ROLES = new Set(['ubuntu_agent', 'syslog_gateway', 'snmp_proxy', 'hybrid']);
const RSYSLOG_PROTOCOLS = new Set(['udp', 'tcp']);
const REMOTE_MANAGEMENT_MODES = new Set(['none', 'omada_vpn']);
const DIAGNOSTIC_COMMAND_TYPES = new Set([
    'ping',
    'traceroute',
    'dns',
    'tcp',
    'http',
    'tcpdump',
    'arpwatch',
    'bandwidth',
    'measurement',
    'gateway-info',
    'tools-info',
    'goal'
]);
const DIAGNOSTIC_PRIVATE_KEYWORDS = new Set(['gateway', 'default-gateway', 'default']);
const DIAGNOSTIC_TCPDUMP_FILTERS = {
    default: 'arp or icmp or icmp6 or port 53 or port 67 or port 68 or udp port 5353 or ether proto 0x88cc or tcp port 7443',
    overview: 'arp or icmp or icmp6 or port 53 or port 67 or port 68 or udp port 5353 or ether proto 0x88cc or tcp',
    syslog: 'udp port 514 or udp port 5514',
    trap: 'udp port 162 or udp port 1162',
    mdns: 'udp port 5353',
    arp: 'arp',
    icmp: 'icmp',
    dns: 'port 53',
    dhcp: 'port 67 or port 68',
    lldp: 'ether proto 0x88cc or ether[20:2] = 0x2000'
};
const PULSE_LOCAL_MAX_RESPONSE_BYTES = 65536;
const PACKET_CAPTURE_SCOPES = new Set(['collector_interface', 'span_mirror', 'trunk_observation', 'targeted_host']);

const EDGE_SEVERITY_RANK = {
    ok: 0,
    info: 1,
    warn: 2,
    danger: 3
};

function parseEnvFileContents(content, baseEnv = {}) {
    const env = { ...baseEnv };
    for (const rawLine of String(content || '').split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) {
            continue;
        }

        const separatorIndex = line.indexOf('=');
        if (separatorIndex === -1) {
            continue;
        }

        const key = line.slice(0, separatorIndex).trim();
        if (!key || env[key] !== undefined) {
            continue;
        }

        let value = line.slice(separatorIndex + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith('\'') && value.endsWith('\''))) {
            value = value.slice(1, -1);
        }

        env[key] = value;
    }

    return env;
}

function loadCollectorEnv(envFile = DEFAULT_ENV_FILE, baseEnv = process.env) {
    const env = { ...baseEnv, ENV_FILE: envFile };
    if (!fs.existsSync(envFile)) {
        return env;
    }

    return parseEnvFileContents(fs.readFileSync(envFile, 'utf8'), env);
}

function normalizeBaseUrl(value) {
    return String(value || '').trim().replace(/\/+$/, '');
}

function parsePositivePort(value, fallback) {
    const parsed = Number(String(value || '').trim());
    return Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535 ? parsed : fallback;
}

function parsePositiveInteger(value, fallback) {
    const parsed = Number(String(value || '').trim());
    return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function parseBoolean(value, fallback = false) {
    if (value === undefined || value === null || value === '') {
        return fallback;
    }

    const normalized = String(value).trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) {
        return true;
    }

    if (['0', 'false', 'no', 'off'].includes(normalized)) {
        return false;
    }

    return fallback;
}

function parseCsv(value) {
    return String(value || '')
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
}

function sleep(ms) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

function truncateText(value, maxLength = 240) {
    const normalized = String(value || '').trim();
    if (!normalized) {
        return '';
    }
    return normalized.length <= maxLength ? normalized : `${normalized.slice(0, maxLength - 3)}...`;
}

function requireShortText(value, label, maxLength = 160) {
    const normalized = truncateText(value, maxLength);
    if (!normalized) {
        throw new Error(`${label} is required`);
    }
    return normalized;
}

function normalizeFieldMeasurementProfile(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error('field profile must be a JSON object');
    }
    const metro = value.metro_contact;
    const customer = value.customer_contact;
    if (!metro || typeof metro !== 'object' || Array.isArray(metro)) {
        throw new Error('field profile metro contact is required');
    }
    if (!customer || typeof customer !== 'object' || Array.isArray(customer)) {
        throw new Error('field profile customer contact is required');
    }
    const normalized = {
        schema_version: truncateText(value.schema_version, 80) || 'collector-field-profile-v1',
        site_name: requireShortText(value.site_name, 'field profile site name'),
        customer_name: truncateText(value.customer_name, 160) || null,
        address: truncateText(value.address, 500) || null,
        scope_started_at: truncateText(value.scope_started_at, 80) || null,
        metro_contact: {
            name: requireShortText(metro.name, 'Metro contact name', 120),
            phone: requireShortText(metro.phone, 'Metro contact phone', 60)
        },
        customer_contact: {
            name: requireShortText(customer.name, 'Customer contact name', 120),
            phone: requireShortText(customer.phone, 'Customer contact phone', 60)
        }
    };
    for (const field of ['site_id', 'customer_id']) {
        if (value[field] === undefined || value[field] === null || value[field] === '') continue;
        const parsed = Number(value[field]);
        if (!Number.isInteger(parsed) || parsed < 1) {
            throw new Error(`field profile ${field} must be a positive integer`);
        }
        normalized[field] = parsed;
    }
    return normalized;
}

function maxSeverity(current, next) {
    return (EDGE_SEVERITY_RANK[next] || 0) > (EDGE_SEVERITY_RANK[current] || 0) ? next : current;
}

function safeExecOutput(command, args = [], execFn = execFileSync) {
    try {
        return {
            ok: true,
            stdout: execFn(command, args, {
                encoding: 'utf8',
                stdio: ['ignore', 'pipe', 'pipe']
            }),
            stderr: ''
        };
    } catch (error) {
        return {
            ok: false,
            stdout: String(error?.stdout || ''),
            stderr: String(error?.stderr || error?.message || '')
        };
    }
}

function resolveNmsUrl(env) {
    const explicitUrl = normalizeBaseUrl(env.NMS_URL);
    if (explicitUrl) {
        return explicitUrl;
    }

    const scheme = String(env.NMS_SCHEME || 'http').trim();
    const host = String(env.NMS_HOST || '127.0.0.1').trim();
    const port = parsePositivePort(env.NMS_PORT || '7443', 7443);
    const rawPath = String(env.NMS_PATH || '').trim();
    const normalizedPath = rawPath ? `/${rawPath.replace(/^\/+/, '').replace(/\/+$/, '')}` : '';

    if (!scheme || !host) {
        return '';
    }

    return `${scheme}://${host}:${port}${normalizedPath}`;
}

function resolveNmsUrls(env) {
    const urls = [resolveNmsUrl(env), normalizeBaseUrl(env.NMS_FALLBACK_URL)]
        .filter(Boolean);
    return [...new Set(urls)];
}

function isRetryableNmsError(error) {
    return Boolean(error && !/\bstatus=\d{3}\b/.test(String(error.message || '')));
}

async function withNmsFallback(env, operation) {
    const urls = resolveNmsUrls(env);
    let lastError = null;
    for (const baseUrl of urls) {
        try {
            return await operation(baseUrl);
        } catch (error) {
            lastError = error;
            if (!isRetryableNmsError(error)) {
                throw error;
            }
        }
    }
    throw lastError || new Error('no NMS endpoint is configured');
}

function detectPrivateIp(execFn = execFileSync) {
    try {
        const output = execFn('ip', ['-4', 'route', 'get', '1.1.1.1'], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore']
        });
        const match = output.match(/\bsrc\s+(\d+\.\d+\.\d+\.\d+)/);
        return match ? match[1] : null;
    } catch {
        return null;
    }
}

function inferCollectorRole(env, rsyslogRelayEnabled, trapRelayEnabled) {
    const explicitRole = String(env.COLLECTOR_ROLE || '').trim().toLowerCase();
    if (explicitRole) {
        return explicitRole;
    }

    if (rsyslogRelayEnabled && trapRelayEnabled) {
        return 'hybrid';
    }

    if (rsyslogRelayEnabled) {
        return 'syslog_gateway';
    }

    if (trapRelayEnabled) {
        return 'snmp_proxy';
    }

    return 'ubuntu_agent';
}

function getRemoteManagementSettings(env) {
    const requestedMode = String(env.REMOTE_MANAGEMENT_MODE || 'none').trim().toLowerCase() || 'none';
    const mode = REMOTE_MANAGEMENT_MODES.has(requestedMode) ? requestedMode : 'none';
    return {
        mode,
        requestedMode,
        profileLabel: String(env.REMOTE_MANAGEMENT_PROFILE_LABEL || '').trim(),
        wireGuardInterface: mode === 'omada_vpn'
            ? (String(env.WIREGUARD_INTERFACE || 'metro-omada').trim() || 'metro-omada')
            : null,
        handshakeStaleSeconds: parsePositiveInteger(env.WIREGUARD_HANDSHAKE_STALE_SECONDS || '180', 180),
        collectionDependency: false
    };
}

function getRsyslogSettings(env) {
    const targetHost = String(env.RSYSLOG_TARGET_HOST || '').trim();
    const targetPort = parsePositivePort(env.RSYSLOG_TARGET_PORT || '5514', 5514);
    const protocol = String(env.RSYSLOG_TARGET_PROTOCOL || 'udp').trim().toLowerCase() || 'udp';

    return {
        targetHost,
        targetPort,
        protocol
    };
}

function renderRsyslogConfig(env) {
    const rsyslog = getRsyslogSettings(env);
    if (!rsyslog.targetHost) {
        throw new Error('RSYSLOG_TARGET_HOST is required when ENABLE_RSYSLOG_RELAY=true');
    }

    if (!RSYSLOG_PROTOCOLS.has(rsyslog.protocol)) {
        throw new Error('RSYSLOG_TARGET_PROTOCOL must be udp or tcp');
    }

    return `# Generated by nms-collector.js render-rsyslog-config\n*.* action(\n  type="omfwd"\n  target="${rsyslog.targetHost}"\n  port="${rsyslog.targetPort}"\n  protocol="${rsyslog.protocol}"\n  action.resumeRetryCount="-1"\n  queue.type="linkedList"\n  queue.size="10000"\n)\n`;
}

function readSystemctlState(subcommand, unitName, execFn = execFileSync) {
    try {
        const output = execFn('systemctl', [subcommand, unitName], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe']
        });
        return String(output || '').trim() || 'unknown';
    } catch (error) {
        if (error && error.code === 'ENOENT') {
            return 'unavailable';
        }

        const stdout = String(error && error.stdout ? error.stdout : '').trim();
        if (stdout) {
            return stdout;
        }

        const stderr = String(error && error.stderr ? error.stderr : '').trim();
        if (/system has not been booted with systemd|failed to connect to bus/i.test(stderr)) {
            return 'unavailable';
        }

        return stderr || 'unknown';
    }
}

function inspectLocalServices(report, execFn = execFileSync) {
    const services = {
        heartbeatTimer: {
            active: readSystemctlState('is-active', 'nms-collector-heartbeat.timer', execFn),
            enabled: readSystemctlState('is-enabled', 'nms-collector-heartbeat.timer', execFn)
        }
    };

    if (report.features.trapRelayEnabled) {
        services.trapForwarder = {
            active: readSystemctlState('is-active', 'nms-collector-trap-forwarder.service', execFn),
            enabled: readSystemctlState('is-enabled', 'nms-collector-trap-forwarder.service', execFn)
        };
    }

    if (report.features.remoteDiagnosticsEnabled) {
        services.diagnosticWorker = {
            active: readSystemctlState('is-active', 'nms-collector-diagnostic-worker.service', execFn),
            enabled: readSystemctlState('is-enabled', 'nms-collector-diagnostic-worker.service', execFn)
        };
    }

    if (report.features.edgeAnalysisEnabled) {
        services.edgeAnalysisTimer = {
            active: readSystemctlState('is-active', 'nms-collector-edge-analysis.timer', execFn),
            enabled: readSystemctlState('is-enabled', 'nms-collector-edge-analysis.timer', execFn)
        };
    }

    if (report.features.rsyslogRelayEnabled) {
        services.rsyslog = {
            active: readSystemctlState('is-active', 'rsyslog.service', execFn),
            enabled: readSystemctlState('is-enabled', 'rsyslog.service', execFn)
        };
    }

    return services;
}

function inspectCollectorEnv(env) {
    const errors = [];
    const warnings = [];
    const resolvedNmsUrl = resolveNmsUrl(env);
    const resolvedNmsUrls = resolveNmsUrls(env);
    const collectorIdRaw = String(env.COLLECTOR_ID || '').trim();
    const parsedCollectorId = Number(collectorIdRaw);
    const collectorToken = String(env.COLLECTOR_TOKEN || '').trim();
    const trapRelayEnabled = parseBoolean(env.ENABLE_SNMPTRAP_RELAY, false);
    const rsyslogRelayEnabled = parseBoolean(env.ENABLE_RSYSLOG_RELAY, false);
    const remoteDiagnosticsEnabled = parseBoolean(env.REMOTE_DIAGNOSTICS_ENABLED, true);
    const edgeServerMode = parseBoolean(env.EDGE_SERVER_MODE, true);
    const edgeAnalysisEnabled = parseBoolean(env.EDGE_ANALYSIS_ENABLED, true);
    const edgeAiEnabled = parseBoolean(env.EDGE_AI_ENABLED, false);
    const trapAuthorizationDisabled = parseBoolean(env.SNMPTRAP_DISABLE_AUTHORIZATION, false);
    const trapCommunities = parseCsv(env.SNMPTRAP_COMMUNITIES || 'public');
    const collectorRole = inferCollectorRole(env, rsyslogRelayEnabled, trapRelayEnabled);
    const rsyslog = getRsyslogSettings(env);
    const insecureTls = parseBoolean(env.NMS_INSECURE_TLS, false) || String(env.NODE_TLS_REJECT_UNAUTHORIZED || '').trim() === '0';
    const caCertPath = String(env.NMS_CA_CERT_PATH || '').trim();
    const remoteManagement = getRemoteManagementSettings(env);

    if (!fs.existsSync(env.ENV_FILE || DEFAULT_ENV_FILE)) {
        errors.push(`env file not found: ${env.ENV_FILE || DEFAULT_ENV_FILE}`);
    }

    if (!resolvedNmsUrl) {
        errors.push('NMS_URL could not be resolved from NMS_URL or NMS_HOST/NMS_PORT');
    }

    if (caCertPath && !fs.existsSync(caCertPath)) {
        errors.push(`NMS_CA_CERT_PATH file not found: ${caCertPath}`);
    }

    if (!Number.isInteger(parsedCollectorId) || parsedCollectorId <= 0) {
        errors.push('COLLECTOR_ID must be a positive integer');
    }

    if (!collectorToken) {
        errors.push('COLLECTOR_TOKEN is required');
    } else if (PLACEHOLDER_TOKENS.has(collectorToken.toLowerCase())) {
        errors.push('COLLECTOR_TOKEN is still using the example placeholder value');
    }

    if (!COLLECTOR_ROLES.has(collectorRole)) {
        errors.push('COLLECTOR_ROLE must be one of: ubuntu_agent, syslog_gateway, snmp_proxy, hybrid');
    }

    if (rsyslogRelayEnabled && !rsyslog.targetHost) {
        errors.push('RSYSLOG_TARGET_HOST is required when ENABLE_RSYSLOG_RELAY=true');
    }

    if (rsyslogRelayEnabled && !RSYSLOG_PROTOCOLS.has(rsyslog.protocol)) {
        errors.push('RSYSLOG_TARGET_PROTOCOL must be udp or tcp');
    }

    if (trapRelayEnabled && !trapAuthorizationDisabled && trapCommunities.length === 0) {
        warnings.push('SNMP trap relay is enabled but SNMPTRAP_COMMUNITIES is empty while authorization is on');
    }

    if ((collectorRole === 'syslog_gateway' || collectorRole === 'hybrid') && !rsyslogRelayEnabled) {
        warnings.push(`collector role ${collectorRole} usually expects ENABLE_RSYSLOG_RELAY=true`);
    }

    if ((collectorRole === 'snmp_proxy' || collectorRole === 'hybrid') && !trapRelayEnabled) {
        warnings.push(`collector role ${collectorRole} usually expects ENABLE_SNMPTRAP_RELAY=true`);
    }

    if (collectorRole === 'ubuntu_agent' && (rsyslogRelayEnabled || trapRelayEnabled)) {
        warnings.push('collector role ubuntu_agent has relay features enabled; set COLLECTOR_ROLE=syslog_gateway, snmp_proxy, or hybrid if intentional');
    }

    if (resolvedNmsUrl.startsWith('https://') && insecureTls) {
        warnings.push('NMS_INSECURE_TLS=true disables TLS certificate verification');
    }

    if (edgeAiEnabled && !String(env.EDGE_AI_BASE_URL || '').trim()) {
        warnings.push('EDGE_AI_ENABLED=true but EDGE_AI_BASE_URL is empty; edge analysis will use deterministic rules only');
    }
    if (String(env.COLLECTOR_PRIVATE_IP || '').trim() && !parseBoolean(env.COLLECTOR_PRIVATE_IP_OVERRIDE, false)) {
        warnings.push('COLLECTOR_PRIVATE_IP is ignored for mobile/DHCP collection; set COLLECTOR_PRIVATE_IP_OVERRIDE=true only for an intentional static override');
    }
    if (remoteManagement.requestedMode !== remoteManagement.mode) {
        warnings.push('REMOTE_MANAGEMENT_MODE must be one of: none, omada_vpn; defaulted to none');
    }
    if (remoteManagement.mode === 'omada_vpn' && !remoteManagement.profileLabel) {
        warnings.push('REMOTE_MANAGEMENT_MODE=omada_vpn but REMOTE_MANAGEMENT_PROFILE_LABEL is empty');
    }

    return {
        ready: errors.length === 0,
        errors,
        warnings,
        resolvedNmsUrl,
        resolvedNmsUrls,
        collectorRole,
        collectorId: Number.isInteger(parsedCollectorId) && parsedCollectorId > 0 ? parsedCollectorId : null,
        features: {
            heartbeat: true,
            rsyslogRelayEnabled,
            trapRelayEnabled,
            remoteDiagnosticsEnabled,
            edgeServerMode,
            edgeAnalysisEnabled,
            edgeAiEnabled
        },
        rsyslog,
        trap: {
            port: parsePositivePort(env.SNMPTRAP_LISTEN_PORT || '1162', 1162),
            address: String(env.SNMPTRAP_LISTEN_ADDRESS || '0.0.0.0').trim() || '0.0.0.0',
            authorizationDisabled: trapAuthorizationDisabled,
            communities: trapCommunities
        },
        tls: {
            insecureTls,
            caCertPath
        },
        remoteManagement
    };
}

function buildHeartbeatPayload(env, options = {}) {
    const hostnameOverrideProvided = Object.prototype.hasOwnProperty.call(options, 'hostname');
    const privateIpOverrideProvided = Object.prototype.hasOwnProperty.call(options, 'privateIp');
    const publicIpOverrideProvided = Object.prototype.hasOwnProperty.call(options, 'publicIp');
    const hostname = String(
        env.COLLECTOR_HOSTNAME
        || (hostnameOverrideProvided ? options.hostname : '')
        || os.hostname().split('.')[0]
    ).trim();
    const collectorName = String(env.COLLECTOR_NAME || '').trim();
    const primaryNetwork = options.primaryNetwork || collectPrimaryNetwork(options.execFn || execFileSync);
    const configuredPrivateIp = String(env.COLLECTOR_PRIVATE_IP || '').trim();
    const allowConfiguredPrivateIp = parseBoolean(env.COLLECTOR_PRIVATE_IP_OVERRIDE, false);
    const privateIp = String(
        (privateIpOverrideProvided ? options.privateIp : '')
        || (allowConfiguredPrivateIp ? configuredPrivateIp : '')
        || (!privateIpOverrideProvided ? primaryNetwork.address || detectPrivateIp(options.execFn || execFileSync) : '')
        || ''
    ).trim();
    const publicIp = String(env.COLLECTOR_PUBLIC_IP || (publicIpOverrideProvided ? options.publicIp : '') || '').trim();
    const softwareVersion = String(env.COLLECTOR_SOFTWARE_VERSION || '0.1.0').trim() || '0.1.0';
    const status = String(env.COLLECTOR_STATUS || 'active').trim() || 'active';
    const platform = String(env.COLLECTOR_PLATFORM || 'ubuntu').trim() || 'ubuntu';
    const purpose = String(env.COLLECTOR_PURPOSE || 'field relay').trim() || 'field relay';
    const capabilities = parseCsv(env.COLLECTOR_CAPABILITIES || 'heartbeat');
    const rsyslogRelayEnabled = parseBoolean(env.ENABLE_RSYSLOG_RELAY, false);
    const trapRelayEnabled = parseBoolean(env.ENABLE_SNMPTRAP_RELAY, false);
    const remoteDiagnosticsEnabled = parseBoolean(env.REMOTE_DIAGNOSTICS_ENABLED, true);
    const edgeServerMode = parseBoolean(env.EDGE_SERVER_MODE, true);
    const edgeAnalysisEnabled = parseBoolean(env.EDGE_ANALYSIS_ENABLED, true);
    const edgeAiEnabled = parseBoolean(env.EDGE_AI_ENABLED, false);
    const remoteManagement = getRemoteManagementSettings(env);
    const wireGuardStatus = options.wireGuardStatus || collectWireGuardStatus(env, options.execFn || execFileSync);
    const normalizedCapabilities = capabilities.length > 0 ? [...capabilities] : ['heartbeat'];

    if (remoteDiagnosticsEnabled && !normalizedCapabilities.includes('diagnostics')) {
        normalizedCapabilities.push('diagnostics');
    }
    if (edgeServerMode && !normalizedCapabilities.includes('edge-analysis')) {
        normalizedCapabilities.push('edge-analysis');
    }

    const payload = {
        status,
        hostname,
        software_version: softwareVersion,
        metadata: {
            os: platform,
            purpose,
            capabilities: normalizedCapabilities,
            features: {
                rsyslog_relay: rsyslogRelayEnabled,
                snmptrap_relay: trapRelayEnabled,
                remote_diagnostics: remoteDiagnosticsEnabled,
                edge_server: edgeServerMode,
                edge_analysis: edgeAnalysisEnabled,
                edge_ai: edgeAiEnabled
            },
            remote_management: {
                mode: remoteManagement.mode,
                profile_label: remoteManagement.profileLabel || null,
                collection_dependency: false
            },
            current_network: primaryNetwork,
            vpn: wireGuardStatus
        }
    };

    if (collectorName) {
        payload.name = collectorName;
    }

    if (privateIp) {
        payload.private_ip = privateIp;
    }

    if (publicIp) {
        payload.public_ip = publicIp;
    }

    return payload;
}

function createJsonPostRequestOptions(targetUrl, headers, payload, env) {
    const parsedUrl = new URL(targetUrl);
    const requestBody = JSON.stringify(payload);
    const isHttps = parsedUrl.protocol === 'https:';
    const insecureTls = parseBoolean(env.NMS_INSECURE_TLS, false) || String(env.NODE_TLS_REJECT_UNAUTHORIZED || '').trim() === '0';
    const caCertPath = String(env.NMS_CA_CERT_PATH || '').trim();
    const requestOptions = {
        protocol: parsedUrl.protocol,
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: `${parsedUrl.pathname}${parsedUrl.search}`,
        method: 'POST',
        headers: {
            ...headers,
            'Content-Length': Buffer.byteLength(requestBody)
        }
    };

    if (isHttps) {
        if (insecureTls) {
            requestOptions.rejectUnauthorized = false;
        }

        if (caCertPath) {
            requestOptions.ca = fs.readFileSync(caCertPath, 'utf8');
        }
    }

    return {
        transport: isHttps ? https : http,
        requestOptions,
        requestBody,
        timeoutMs: parsePositiveInteger(env.NMS_HTTP_TIMEOUT_MS || '10000', 10000)
    };
}

function parsePulseLocalStatusResponse(rawResponse) {
    const rawText = Buffer.isBuffer(rawResponse)
        ? rawResponse.toString('utf8')
        : String(rawResponse || '');
    const jsonStart = rawText.indexOf('{');
    const jsonEnd = rawText.lastIndexOf('}');
    if (jsonStart === -1 || jsonEnd < jsonStart) {
        throw new Error('Pulse local status response did not contain JSON');
    }

    let payload;
    try {
        payload = JSON.parse(rawText.slice(jsonStart, jsonEnd + 1));
    } catch (error) {
        throw new Error(`Pulse local status JSON parse failed: ${error.message}`);
    }

    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new Error('Pulse local status payload must be a JSON object');
    }
    if (!Object.prototype.hasOwnProperty.call(payload, 'poeStatus')
        && !Object.prototype.hasOwnProperty.call(payload, 'linkStatus')) {
        throw new Error('Pulse local status payload has no PoE or link status');
    }

    return payload;
}

function firstNumber(value) {
    const match = String(value || '').match(/-?\d+(?:\.\d+)?/);
    if (!match) {
        return null;
    }
    const parsed = Number(match[0]);
    return Number.isFinite(parsed) ? parsed : null;
}

function averageNumbers(value) {
    const values = String(value || '')
        .match(/-?\d+(?:\.\d+)?/g)
        ?.map(Number)
        .filter(Number.isFinite) || [];
    if (values.length === 0) {
        return null;
    }
    return Number((values.reduce((sum, current) => sum + current, 0) / values.length).toFixed(3));
}

function buildPulseLocalStatusPayload(statusPayload, env, report, observedAt = new Date().toISOString()) {
    const host = String(env.PULSE_LOCAL_HOST || '').trim();
    const serialNumber = String(env.PULSE_LOCAL_SERIAL_NUMBER || '').trim();
    const macAddress = String(env.PULSE_LOCAL_MAC_ADDRESS || '').trim();
    return {
        ...statusPayload,
        ip: host,
        serial_number: serialNumber || undefined,
        mac_address: macAddress || undefined,
        collector_id: report.collectorId,
        collector_hostname: String(env.COLLECTOR_HOSTNAME || os.hostname().split('.')[0]).trim(),
        collection_source: 'ubuntu_collector_local_pulse_status',
        source_measurement_at: observedAt,
        poe_voltage_v: firstNumber(statusPayload.poeStatus),
        link_speed_mbps: firstNumber(statusPayload.linkStatus),
        gateway_ping_ms: averageNumbers(statusPayload.gatewayStatus)
    };
}

async function fetchPulseLocalStatus(env) {
    const host = String(env.PULSE_LOCAL_HOST || '').trim();
    if (!host) {
        throw new Error('PULSE_LOCAL_HOST is required when PULSE_LOCAL_POLL_ENABLED=true');
    }

    const port = parsePositivePort(env.PULSE_LOCAL_PORT || '80', 80);
    const rawPath = String(env.PULSE_LOCAL_STATUS_PATH || '/cgi-bin/ledstatus.cgi').trim();
    const requestPath = `/${rawPath.replace(/^\/+/, '')}`;
    const timeoutMs = parsePositiveInteger(env.PULSE_LOCAL_TIMEOUT_MS || '15000', 15000);

    return new Promise((resolve, reject) => {
        const chunks = [];
        let totalBytes = 0;
        let settled = false;
        const socket = net.createConnection({ host, port });

        const finish = (error, value = null) => {
            if (settled) {
                return;
            }
            settled = true;
            socket.destroy();
            if (error) {
                reject(error);
            } else {
                resolve(value);
            }
        };

        socket.setTimeout(timeoutMs);
        socket.on('connect', () => {
            socket.write(
                `GET ${requestPath} HTTP/1.0\r\n`
                + `Host: ${host}\r\n`
                + 'User-Agent: METRO-NMS-Collector/0.2\r\n'
                + `Referer: http://${host}/\r\n`
                + 'Accept: application/json\r\n'
                + 'Connection: close\r\n\r\n'
            );
        });
        socket.on('data', (chunk) => {
            totalBytes += chunk.length;
            if (totalBytes > PULSE_LOCAL_MAX_RESPONSE_BYTES) {
                finish(new Error(`Pulse local status response exceeded ${PULSE_LOCAL_MAX_RESPONSE_BYTES} bytes`));
                return;
            }
            chunks.push(chunk);
        });
        socket.on('end', () => {
            try {
                finish(null, parsePulseLocalStatusResponse(Buffer.concat(chunks)));
            } catch (error) {
                finish(error);
            }
        });
        socket.on('timeout', () => finish(new Error(`Pulse local status timeout=${timeoutMs}ms`)));
        socket.on('error', (error) => finish(new Error(`Pulse local status connection failed: ${error.message}`)));
    });
}

function getUptimeKumaPushSettings(env) {
    const url = String(env.UPTIME_KUMA_PUSH_URL || '').trim();
    return {
        enabled: Boolean(url),
        url,
        timeoutMs: parsePositiveInteger(env.UPTIME_KUMA_PUSH_TIMEOUT_MS || '10000', 10000)
    };
}

function shouldTreatServiceAsDown(serviceState) {
    return Boolean(serviceState) && !['active', 'unknown', 'unavailable'].includes(String(serviceState).trim().toLowerCase());
}

function buildCollectorUptimeKumaUpdate(report, services, { heartbeatError = null, heartbeatLatencyMs = null } = {}) {
    const issues = [];
    const details = [];

    if (report.features.rsyslogRelayEnabled) {
        if (shouldTreatServiceAsDown(services?.rsyslog?.active)) {
            issues.push('syslog relay inactive');
        } else {
            details.push('syslog relay active');
        }
    }

    if (report.features.trapRelayEnabled) {
        if (shouldTreatServiceAsDown(services?.trapForwarder?.active)) {
            issues.push('trap relay inactive');
        } else {
            details.push('trap relay active');
        }
    }

    if (report.features.remoteDiagnosticsEnabled) {
        if (shouldTreatServiceAsDown(services?.diagnosticWorker?.active)) {
            issues.push('diagnostic worker inactive');
        } else {
            details.push('diagnostic worker active');
        }
    }

    if (report.features.edgeAnalysisEnabled) {
        if (shouldTreatServiceAsDown(services?.edgeAnalysisTimer?.active)) {
            issues.push('edge analysis timer inactive');
        } else {
            details.push('edge analysis timer active');
        }
    }

    if (heartbeatError) {
        issues.push('nms heartbeat failed');
    } else {
        details.push('heartbeat ok');
    }

    const status = issues.length > 0 ? 'down' : 'up';
    const roleLabel = report.collectorRole || 'ubuntu_agent';
    const summary = issues.length > 0 ? issues.join(', ') : (details.join(', ') || 'collector ok');

    return {
        status,
        msg: truncateText(`role:${roleLabel}, ${summary}`),
        ping: heartbeatLatencyMs !== null && heartbeatLatencyMs !== undefined ? Number(heartbeatLatencyMs.toFixed(2)) : null
    };
}

async function sendUptimeKumaPush(env, update) {
    const settings = getUptimeKumaPushSettings(env);
    if (!settings.enabled) {
        return false;
    }

    const targetUrl = new URL(settings.url);
    targetUrl.searchParams.set('status', update.status === 'down' ? 'down' : 'up');
    if (update.msg) {
        targetUrl.searchParams.set('msg', truncateText(update.msg));
    }
    if (update.ping !== null && update.ping !== undefined && Number.isFinite(Number(update.ping))) {
        targetUrl.searchParams.set('ping', String(Number(update.ping)));
    }

    const isHttps = targetUrl.protocol === 'https:';
    const transport = isHttps ? https : http;
    const requestOptions = {
        protocol: targetUrl.protocol,
        hostname: targetUrl.hostname,
        port: targetUrl.port || (isHttps ? 443 : 80),
        path: `${targetUrl.pathname}${targetUrl.search}`,
        method: 'GET'
    };

    await new Promise((resolve, reject) => {
        const request = transport.request(requestOptions, (response) => {
            let responseText = '';
            response.setEncoding('utf8');
            response.on('data', (chunk) => {
                responseText += chunk;
            });
            response.on('end', () => {
                if (response.statusCode && response.statusCode >= 200 && response.statusCode < 300) {
                    resolve();
                    return;
                }

                reject(new Error(`uptime kuma push failed status=${response.statusCode || 'unknown'} body=${responseText.slice(0, 300)}`));
            });
        });

        request.setTimeout(settings.timeoutMs, () => {
            request.destroy(new Error(`uptime kuma push timeout=${settings.timeoutMs}ms`));
        });
        request.on('error', reject);
        request.end();
    });

    return true;
}

async function trySendUptimeKumaPush(env, update) {
    try {
        return await sendUptimeKumaPush(env, update);
    } catch (error) {
        console.error(`uptime kuma push failed: ${error.message}`);
        return false;
    }
}

async function ensureSuccessfulJsonPost(url, headers, payload, failurePrefix, env) {
    const {
        transport,
        requestOptions,
        requestBody,
        timeoutMs
    } = createJsonPostRequestOptions(url, headers, payload, env);

    return new Promise((resolve, reject) => {
        const request = transport.request(requestOptions, (response) => {
            let responseText = '';
            response.setEncoding('utf8');
            response.on('data', (chunk) => {
                responseText += chunk;
            });
            response.on('end', () => {
                if (response.statusCode && response.statusCode >= 200 && response.statusCode < 300) {
                    if (!responseText) {
                        resolve({});
                        return;
                    }
                    try {
                        resolve(JSON.parse(responseText));
                    } catch (error) {
                        reject(new Error(`${failurePrefix} returned invalid JSON: ${error.message}`));
                    }
                    return;
                }

                reject(
                    new Error(
                        `${failurePrefix} status=${response.statusCode || 'unknown'} body=${responseText.slice(0, 500)}`
                    )
                );
            });
        });

        request.setTimeout(timeoutMs, () => {
            request.destroy(new Error(`${failurePrefix} timeout=${timeoutMs}ms`));
        });
        request.on('error', reject);
        request.write(requestBody);
        request.end();
    });
}

async function requestJsonGet(url, headers, env) {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const insecureTls = parseBoolean(env.NMS_INSECURE_TLS, false) || String(env.NODE_TLS_REJECT_UNAUTHORIZED || '').trim() === '0';
    const caCertPath = String(env.NMS_CA_CERT_PATH || '').trim();
    const requestOptions = {
        protocol: parsedUrl.protocol,
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: `${parsedUrl.pathname}${parsedUrl.search}`,
        method: 'GET',
        headers
    };

    if (isHttps) {
        if (insecureTls) {
            requestOptions.rejectUnauthorized = false;
        }

        if (caCertPath) {
            requestOptions.ca = fs.readFileSync(caCertPath, 'utf8');
        }
    }

    const transport = isHttps ? https : http;
    const timeoutMs = parsePositiveInteger(env.NMS_HTTP_TIMEOUT_MS || '10000', 10000);

    return new Promise((resolve, reject) => {
        const request = transport.request(requestOptions, (response) => {
            let responseText = '';
            response.setEncoding('utf8');
            response.on('data', (chunk) => {
                responseText += chunk;
            });
            response.on('end', () => {
                if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
                    reject(new Error(`collector GET failed status=${response.statusCode || 'unknown'} body=${responseText.slice(0, 500)}`));
                    return;
                }

                try {
                    resolve(responseText ? JSON.parse(responseText) : {});
                } catch (error) {
                    reject(new Error(`collector GET returned invalid JSON: ${error.message}`));
                }
            });
        });

        request.setTimeout(timeoutMs, () => {
            request.destroy(new Error(`collector GET timeout=${timeoutMs}ms`));
        });
        request.on('error', reject);
        request.end();
    });
}

function runExecFile(command, args = [], options = {}) {
    const startedAt = Date.now();
    const timeoutMs = parsePositiveInteger(options.timeoutMs, 15000);
    const maxBuffer = parsePositiveInteger(options.maxBuffer, 128 * 1024);

    return new Promise((resolve) => {
        execFile(command, args, {
            encoding: 'utf8',
            timeout: timeoutMs,
            maxBuffer
        }, (error, stdout = '', stderr = '') => {
            const boundedStdout = options.preserveWhitespace
                ? String(stdout || '').slice(0, maxBuffer)
                : truncateText(stdout, maxBuffer);
            resolve({
                ok: !error,
                command,
                args,
                exit_code: error ? (Number.isInteger(error.code) ? error.code : null) : 0,
                signal: error?.signal || null,
                timed_out: Boolean(error?.killed),
                stdout: boundedStdout,
                stderr: truncateText(stderr, 4000),
                duration_ms: Date.now() - startedAt
            });
        });
    });
}

function getDefaultGateway(execFn = execFileSync) {
    try {
        const output = execFn('ip', ['route', 'show', 'default'], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore']
        });
        const match = String(output || '').match(/\bdefault\s+via\s+([^\s]+)/);
        return match ? match[1] : null;
    } catch {
        return null;
    }
}

function normalizeIpv4Prefix(value) {
    const prefix = Number(value);
    return Number.isInteger(prefix) && prefix >= 0 && prefix <= 32 ? prefix : null;
}

function ipv4ToInteger(value) {
    const parts = String(value || '').split('.').map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
        return null;
    }
    return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function integerToIpv4(value) {
    const normalized = Number(value) >>> 0;
    return [
        (normalized >>> 24) & 255,
        (normalized >>> 16) & 255,
        (normalized >>> 8) & 255,
        normalized & 255
    ].join('.');
}

function calculateIpv4Subnet(address, prefixlen) {
    const numericAddress = ipv4ToInteger(address);
    const prefix = normalizeIpv4Prefix(prefixlen);
    if (numericAddress === null || prefix === null) {
        return null;
    }
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return integerToIpv4(numericAddress & mask);
}

function collectPrimaryNetwork(execFn = execFileSync) {
    const routes = parseJsonCommand('ip', ['-j', '-4', 'route', 'get', '1.1.1.1'], execFn) || [];
    const route = Array.isArray(routes) ? routes[0] || {} : {};
    const interfaceName = String(route.dev || '').trim() || null;
    const addresses = parseJsonCommand('ip', ['-j', '-4', 'address', 'show'], execFn) || [];
    const device = Array.isArray(addresses)
        ? addresses.find((item) => item?.ifname === interfaceName) || null
        : null;
    const addressRows = Array.isArray(device?.addr_info) ? device.addr_info : [];
    const preferredAddress = String(route.prefsrc || '').trim();
    const selectedAddress = addressRows.find((item) => item?.local === preferredAddress)
        || addressRows.find((item) => item?.family === 'inet' && item?.scope === 'global')
        || null;
    const address = String(selectedAddress?.local || preferredAddress || detectPrivateIp(execFn) || '').trim() || null;
    const prefixlen = normalizeIpv4Prefix(selectedAddress?.prefixlen);
    const subnet = calculateIpv4Subnet(address, prefixlen);

    return {
        interface: interfaceName,
        address,
        prefixlen,
        cidr: address && prefixlen !== null ? `${address}/${prefixlen}` : null,
        subnet: subnet && prefixlen !== null ? `${subnet}/${prefixlen}` : null,
        default_gateway: String(route.gateway || getDefaultGateway(execFn) || '').trim() || null
    };
}

function collectWireGuardStatus(env, execFn = execFileSync, nowMs = Date.now()) {
    const remoteManagement = getRemoteManagementSettings(env);
    if (remoteManagement.mode !== 'omada_vpn' || !remoteManagement.wireGuardInterface) {
        return {
            configured: false,
            state: 'not_configured',
            interface: null,
            address: null,
            service_active: null,
            service_enabled: null,
            latest_handshake_at: null,
            handshake_age_seconds: null,
            stale_after_seconds: null
        };
    }

    const interfaceName = remoteManagement.wireGuardInterface;
    const links = parseJsonCommand('ip', ['-j', 'link', 'show', 'dev', interfaceName], execFn);
    const addresses = parseJsonCommand('ip', ['-j', '-4', 'address', 'show', 'dev', interfaceName], execFn);
    const interfacePresent = Array.isArray(links) && links.length > 0;
    const addressRows = Array.isArray(addresses?.[0]?.addr_info) ? addresses[0].addr_info : [];
    const address = addressRows.find((item) => item?.family === 'inet' && item?.scope === 'global')?.local || null;
    const serviceUnit = `wg-quick@${interfaceName}.service`;
    const serviceActive = readSystemctlState('is-active', serviceUnit, execFn);
    const serviceEnabled = readSystemctlState('is-enabled', serviceUnit, execFn);
    const handshakeCommand = safeExecOutput('wg', ['show', interfaceName, 'latest-handshakes'], execFn);
    const handshakeTimestamps = handshakeCommand.ok
        ? String(handshakeCommand.stdout || '')
            .split(/\r?\n/)
            .map((line) => Number(line.trim().split(/\s+/).at(-1)))
            .filter((value) => Number.isFinite(value) && value > 0)
        : [];
    const latestHandshakeSeconds = handshakeTimestamps.length > 0 ? Math.max(...handshakeTimestamps) : null;
    const handshakeAgeSeconds = latestHandshakeSeconds === null
        ? null
        : Math.max(0, Math.round((nowMs - (latestHandshakeSeconds * 1000)) / 1000));
    let state = 'active';
    if (!interfacePresent) {
        state = 'interface_missing';
    } else if (serviceActive !== 'active') {
        state = 'service_inactive';
    } else if (!handshakeCommand.ok) {
        state = 'unknown';
    } else if (latestHandshakeSeconds === null) {
        state = 'no_handshake';
    } else if (handshakeAgeSeconds > remoteManagement.handshakeStaleSeconds) {
        state = 'stale';
    }

    return {
        configured: true,
        state,
        interface: interfaceName,
        address,
        service_active: serviceActive,
        service_enabled: serviceEnabled,
        latest_handshake_at: latestHandshakeSeconds === null ? null : new Date(latestHandshakeSeconds * 1000).toISOString(),
        handshake_age_seconds: handshakeAgeSeconds,
        stale_after_seconds: remoteManagement.handshakeStaleSeconds
    };
}

function isPrivateIpv4Address(value) {
    const parts = String(value || '').split('.').map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
        return false;
    }

    const [a, b] = parts;
    return a === 10
        || a === 127
        || (a === 172 && b >= 16 && b <= 31)
        || (a === 192 && b === 168)
        || (a === 169 && b === 254)
        || (a === 100 && b >= 64 && b <= 127);
}

function isLikelyHostname(value) {
    const normalized = String(value || '').trim();
    return normalized.length > 0
        && normalized.length <= 253
        && /^[A-Za-z0-9.-]+$/.test(normalized)
        && /[A-Za-z]/.test(normalized);
}

function getNmsHostAndPort(env) {
    const diagnosticTarget = String(env.DIAGNOSTIC_NMS_TARGET || '').trim();
    if (diagnosticTarget) {
        const separator = diagnosticTarget.lastIndexOf(':');
        if (separator > 0) {
            const host = diagnosticTarget.slice(0, separator).trim();
            const port = parsePositivePort(diagnosticTarget.slice(separator + 1), null);
            if (host && port) {
                return { host, port };
            }
        }
    }
    try {
        const parsedUrl = new URL(resolveNmsUrl(env));
        return {
            host: parsedUrl.hostname,
            port: Number(parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80))
        };
    } catch {
        return {
            host: null,
            port: null
        };
    }
}

function isAllowedDiagnosticHost(host, env, options = {}) {
    const normalizedHost = String(host || '').trim();
    if (!normalizedHost) {
        return false;
    }

    if (DIAGNOSTIC_PRIVATE_KEYWORDS.has(normalizedHost.toLowerCase())) {
        return true;
    }

    const allowPublicTargets = parseBoolean(env.DIAGNOSTIC_ALLOW_PUBLIC_TARGETS, false);
    const allowHostnames = parseBoolean(env.DIAGNOSTIC_ALLOW_HOSTNAMES, false);
    const nms = getNmsHostAndPort(env);

    if (nms.host && normalizedHost === nms.host) {
        return true;
    }

    if (net.isIP(normalizedHost)) {
        return allowPublicTargets || isPrivateIpv4Address(normalizedHost);
    }

    if (options.allowHostname === true || allowHostnames) {
        return isLikelyHostname(normalizedHost);
    }

    return false;
}

function normalizeDiagnosticHost(value, env, options = {}) {
    const rawHost = String(value || '').trim();
    if (!rawHost) {
        throw new Error('diagnostic target host is required');
    }

    if (DIAGNOSTIC_PRIVATE_KEYWORDS.has(rawHost.toLowerCase())) {
        const gateway = getDefaultGateway();
        if (!gateway) {
            throw new Error('default gateway could not be detected');
        }
        return gateway;
    }

    if (!isAllowedDiagnosticHost(rawHost, env, options)) {
        throw new Error(`diagnostic target not allowed: ${rawHost}`);
    }

    return rawHost;
}

function parseTcpTarget(target, options = {}, env = {}) {
    let host = String(target || '').trim();
    let port = parsePositivePort(options.port, 0);

    if (host.includes(':') && !host.startsWith('http://') && !host.startsWith('https://')) {
        const parts = host.split(':');
        if (parts.length === 2 && /^\d+$/.test(parts[1])) {
            host = parts[0];
            port = parsePositivePort(parts[1], port);
        }
    }

    const nms = getNmsHostAndPort(env);
    if (host.toLowerCase() === 'nms' && nms.host) {
        host = nms.host;
        port = port || nms.port;
    } else if (!host && String(options.target || '').trim() === 'nms' && nms.host) {
        host = nms.host;
        port = nms.port || port;
    }

    if (!port) {
        throw new Error('tcp diagnostic requires options.port or target host:port');
    }

    return {
        host: normalizeDiagnosticHost(host, env),
        port
    };
}

function getTcpdumpFilter(target, options = {}, env = {}) {
    const key = String(target || options.profile || 'default').trim().toLowerCase() || 'default';
    if (parseBoolean(env.DIAGNOSTIC_ALLOW_RAW_TCPDUMP_FILTER, false) && String(options.filter || '').trim()) {
        return String(options.filter).trim();
    }

    return DIAGNOSTIC_TCPDUMP_FILTERS[key] || DIAGNOSTIC_TCPDUMP_FILTERS.default;
}

function incrementCount(map, key, amount = 1) {
    const normalized = String(key || '').trim();
    if (!normalized) {
        return;
    }
    map.set(normalized, (map.get(normalized) || 0) + amount);
}

function topCountRows(map, limit = 12, keyName = 'name') {
    return [...map.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .slice(0, limit)
        .map(([key, count]) => ({ [keyName]: key, count }));
}

function parseOptionalInteger(value) {
    const normalized = String(value ?? '').trim();
    return /^-?\d+$/.test(normalized) ? Number(normalized) : null;
}

function isBroadcastMac(value) {
    return String(value || '').trim().toLowerCase() === 'ff:ff:ff:ff:ff:ff';
}

function isMulticastMac(value) {
    const firstOctet = Number.parseInt(String(value || '').trim().split(':')[0], 16);
    return Number.isInteger(firstOctet) && (firstOctet & 1) === 1 && !isBroadcastMac(value);
}

const PACKET_FLOOD_THRESHOLDS_PPS = Object.freeze({
    broadcast: 100,
    multicast: 100,
    arp: 20,
    mdns: 10,
    ssdp: 10,
    name_resolution: 20
});

function buildPacketFloodSummary(counts, packetCount, observedDurationSeconds, linkLayerDestinationCount) {
    const count = (key) => Number(counts[key] || 0);
    const rate = (key) => observedDurationSeconds >= 5
        ? Number((count(key) / observedDurationSeconds).toFixed(2))
        : null;
    const ratio = (key) => packetCount > 0
        ? Number(((count(key) * 100) / packetCount).toFixed(2))
        : null;
    const rates = {
        broadcast: rate('broadcast'),
        multicast: rate('multicast'),
        arp: rate('arp'),
        mdns: rate('mdns'),
        ssdp: rate('ssdp'),
        llmnr: rate('llmnr'),
        nbns: rate('nbns'),
        dhcp: rate('dhcp'),
        name_resolution: observedDurationSeconds >= 5
            ? Number(((count('llmnr') + count('nbns')) / observedDurationSeconds).toFixed(2))
            : null
    };
    const missingData = [];
    if (observedDurationSeconds < 5) missingData.push('관측시간 5초 미만');
    if (packetCount < 20) missingData.push('패킷 20개 미만');
    if (linkLayerDestinationCount === 0) missingData.push('이더넷 목적지 MAC 미관측');
    const signals = [];
    if (observedDurationSeconds >= 5 && packetCount >= 20) {
        for (const [type, threshold] of Object.entries(PACKET_FLOOD_THRESHOLDS_PPS)) {
            const observed = rates[type];
            if (observed !== null && observed >= threshold) {
                signals.push({ type, observed_pps: observed, threshold_pps: threshold });
            }
        }
    }
    return {
        schema_version: 'metro-packet-flood-summary-v1',
        status: signals.length ? 'candidate' : (missingData.slice(0, 2).length ? 'insufficient_data' : 'no_candidate'),
        counts: {
            broadcast: count('broadcast'),
            multicast: count('multicast'),
            arp: count('arp'),
            mdns: count('mdns'),
            ssdp: count('ssdp'),
            llmnr: count('llmnr'),
            nbns: count('nbns'),
            dhcp: count('dhcp')
        },
        rates_pps: rates,
        ratios_pct: {
            broadcast: ratio('broadcast'),
            multicast: ratio('multicast'),
            arp: ratio('arp'),
            mdns: ratio('mdns'),
            ssdp: ratio('ssdp'),
            llmnr: ratio('llmnr'),
            nbns: ratio('nbns'),
            dhcp: ratio('dhcp')
        },
        thresholds_pps: PACKET_FLOOD_THRESHOLDS_PPS,
        signals,
        missing_data: missingData,
        scope_notice: '현재 인터페이스 관측값입니다. 전체 현장 확정에는 SPAN/미러 또는 트렁크 관측이 필요합니다.'
    };
}

function parseTsharkPacketRows(text) {
    const protocolCounts = new Map();
    const endpointCounts = new Map();
    const conversationCounts = new Map();
    const destinationPortCounts = new Map();
    const vlanIds = new Set();
    let packetCount = 0;
    let byteCount = 0;
    let ipv4Count = 0;
    let ipv6Count = 0;
    let broadcastCount = 0;
    let multicastCount = 0;
    let linkLayerDestinationCount = 0;
    const floodCounts = {
        broadcast: 0,
        multicast: 0,
        arp: 0,
        mdns: 0,
        ssdp: 0,
        llmnr: 0,
        nbns: 0,
        dhcp: 0
    };
    let firstEpoch = null;
    let lastEpoch = null;

    for (const line of String(text || '').split(/\r?\n/)) {
        if (!line.trim()) {
            continue;
        }
        const fields = line.split('\t');
        const epoch = Number(fields[0]);
        const frameLength = Number(fields[1]) || 0;
        const ethSource = String(fields[2] || '').trim();
        const ethDestination = String(fields[3] || '').trim();
        const ipv4Source = String(fields[4] || '').trim();
        const ipv4Destination = String(fields[5] || '').trim();
        const ipv6Source = String(fields[6] || '').trim();
        const ipv6Destination = String(fields[7] || '').trim();
        const protocol = String(fields[8] || 'UNKNOWN').trim().toUpperCase() || 'UNKNOWN';
        const tcpSourcePort = String(fields[9] || '').trim();
        const tcpDestinationPort = String(fields[10] || '').trim();
        const udpSourcePort = String(fields[11] || '').trim();
        const udpDestinationPort = String(fields[12] || '').trim();
        const vlanId = String(fields[13] || '').trim();
        const arpSource = String(fields[14] || '').trim();
        const arpDestination = String(fields[15] || '').trim();
        const source = ipv4Source || ipv6Source || arpSource || ethSource || 'unknown';
        const destination = ipv4Destination || ipv6Destination || arpDestination || ethDestination || 'unknown';
        const sourcePort = tcpSourcePort || udpSourcePort;
        const destinationPort = tcpDestinationPort || udpDestinationPort;
        const transport = tcpSourcePort || tcpDestinationPort ? 'TCP' : (udpSourcePort || udpDestinationPort ? 'UDP' : protocol);

        packetCount += 1;
        byteCount += frameLength;
        incrementCount(protocolCounts, protocol);
        incrementCount(endpointCounts, source);
        incrementCount(endpointCounts, destination);
        if (destinationPort) {
            incrementCount(destinationPortCounts, `${transport}/${destinationPort}`);
        }
        const endpointA = sourcePort ? `${source}:${sourcePort}` : source;
        const endpointB = destinationPort ? `${destination}:${destinationPort}` : destination;
        incrementCount(conversationCounts, `${transport} ${[endpointA, endpointB].sort().join(' <-> ')}`);

        if (ipv4Source || ipv4Destination) ipv4Count += 1;
        if (ipv6Source || ipv6Destination) ipv6Count += 1;
        if (ethDestination) {
            linkLayerDestinationCount += 1;
            if (isBroadcastMac(ethDestination)) {
                broadcastCount += 1;
                floodCounts.broadcast += 1;
            }
            if (isMulticastMac(ethDestination)) {
                multicastCount += 1;
                floodCounts.multicast += 1;
            }
        }
        const udpPorts = new Set([udpSourcePort, udpDestinationPort].filter(Boolean));
        if (protocol === 'ARP' || arpSource || arpDestination) floodCounts.arp += 1;
        if (protocol === 'MDNS' || udpPorts.has('5353')) floodCounts.mdns += 1;
        if (protocol === 'SSDP' || udpPorts.has('1900')) floodCounts.ssdp += 1;
        if (protocol === 'LLMNR' || udpPorts.has('5355')) floodCounts.llmnr += 1;
        if (protocol === 'NBNS' || protocol === 'NBNAME' || udpPorts.has('137')) floodCounts.nbns += 1;
        if (
            ['DHCP', 'DHCPV6', 'BOOTP'].includes(protocol)
            || ['67', '68', '546', '547'].some((port) => udpPorts.has(port))
        ) floodCounts.dhcp += 1;
        if (vlanId) {
            for (const value of vlanId.split(',')) {
                if (/^\d+$/.test(value.trim())) vlanIds.add(Number(value.trim()));
            }
        }
        if (Number.isFinite(epoch)) {
            firstEpoch = firstEpoch === null ? epoch : Math.min(firstEpoch, epoch);
            lastEpoch = lastEpoch === null ? epoch : Math.max(lastEpoch, epoch);
        }
    }

    const observedDurationSeconds = firstEpoch !== null && lastEpoch !== null
        ? Math.max(0, Number((lastEpoch - firstEpoch).toFixed(3)))
        : 0;
    return {
        packet_count: packetCount,
        byte_count: byteCount,
        average_packet_bytes: packetCount ? Number((byteCount / packetCount).toFixed(1)) : 0,
        observed_duration_seconds: observedDurationSeconds,
        packets_per_second: observedDurationSeconds > 0 ? Number((packetCount / observedDurationSeconds).toFixed(2)) : null,
        bits_per_second: observedDurationSeconds > 0 ? Number(((byteCount * 8) / observedDurationSeconds).toFixed(2)) : null,
        ipv4_count: ipv4Count,
        ipv6_count: ipv6Count,
        link_layer_visibility: linkLayerDestinationCount > 0,
        broadcast_count: broadcastCount,
        multicast_count: multicastCount,
        arp_count: floodCounts.arp,
        mdns_count: floodCounts.mdns,
        ssdp_count: floodCounts.ssdp,
        llmnr_count: floodCounts.llmnr,
        nbns_count: floodCounts.nbns,
        dhcp_count: floodCounts.dhcp,
        flood_summary: buildPacketFloodSummary(
            floodCounts,
            packetCount,
            observedDurationSeconds,
            linkLayerDestinationCount
        ),
        vlan_ids: [...vlanIds].sort((a, b) => a - b),
        top_protocols: topCountRows(protocolCounts, 12, 'protocol'),
        top_endpoints: topCountRows(endpointCounts, 12, 'endpoint'),
        top_conversations: topCountRows(conversationCounts, 12, 'conversation'),
        top_destination_ports: topCountRows(destinationPortCounts, 12, 'port')
    };
}

function parseTsharkDetailRows(text) {
    const dnsQueries = new Map();
    const discoveryDevices = new Map();
    const counters = {
        tcp_syn_count: 0,
        tcp_reset_count: 0,
        tcp_retransmission_count: 0,
        dns_query_count: 0,
        dns_response_count: 0,
        dns_error_count: 0,
        arp_request_count: 0,
        arp_reply_count: 0,
        icmp_echo_request_count: 0,
        icmp_echo_reply_count: 0,
        icmp_unreachable_count: 0
    };

    for (const line of String(text || '').split(/\r?\n/)) {
        if (!line.trim()) continue;
        const fields = line.split('\t');
        const syn = fields[0] === '1';
        const ack = fields[1] === '1';
        const reset = fields[2] === '1';
        const retransmission = fields[3] === '1';
        const dnsResponse = fields[4];
        const dnsRcode = parseOptionalInteger(fields[5]);
        const dnsQuery = String(fields[6] || '').trim();
        const arpOpcode = parseOptionalInteger(fields[7]);
        const icmpType = parseOptionalInteger(fields[8]);
        const lldpName = String(fields[9] || '').trim();
        const cdpName = String(fields[10] || '').trim();

        if (syn && !ack) counters.tcp_syn_count += 1;
        if (reset) counters.tcp_reset_count += 1;
        if (retransmission) counters.tcp_retransmission_count += 1;
        if (dnsResponse === '0') counters.dns_query_count += 1;
        if (dnsResponse === '1') counters.dns_response_count += 1;
        if (dnsResponse === '1' && Number.isFinite(dnsRcode) && dnsRcode !== 0) counters.dns_error_count += 1;
        if (dnsQuery) incrementCount(dnsQueries, dnsQuery.toLowerCase());
        if (arpOpcode === 1) counters.arp_request_count += 1;
        if (arpOpcode === 2) counters.arp_reply_count += 1;
        if (icmpType === 8) counters.icmp_echo_request_count += 1;
        if (icmpType === 0) counters.icmp_echo_reply_count += 1;
        if (icmpType === 3) counters.icmp_unreachable_count += 1;
        if (lldpName) incrementCount(discoveryDevices, `LLDP ${lldpName}`);
        if (cdpName) incrementCount(discoveryDevices, `CDP ${cdpName}`);
    }

    return {
        ...counters,
        top_dns_queries: topCountRows(dnsQueries, 10, 'query'),
        discovery_devices: topCountRows(discoveryDevices, 10, 'device')
    };
}

function prunePacketCaptureFiles(directory, retentionHours, nowMs = Date.now()) {
    if (!fs.existsSync(directory)) return 0;
    const cutoffMs = nowMs - (retentionHours * 60 * 60 * 1000);
    let deleted = 0;
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        if (!entry.isFile() || !/\.pcap(?:ng)?$/.test(entry.name)) continue;
        const fullPath = path.join(directory, entry.name);
        if (fs.statSync(fullPath).mtimeMs < cutoffMs) {
            fs.unlinkSync(fullPath);
            deleted += 1;
        }
    }
    return deleted;
}

async function runPingDiagnostic(command, env) {
    const count = Math.min(10, Math.max(1, parsePositiveInteger(command.options?.count, 4)));
    const waitSeconds = Math.min(10, Math.max(1, parsePositiveInteger(command.options?.timeout_seconds, 3)));
    const host = normalizeDiagnosticHost(command.target, env);
    return runExecFile('ping', ['-c', String(count), '-W', String(waitSeconds), host], {
        timeoutMs: (count * waitSeconds * 1000) + 5000
    });
}

async function runTracerouteDiagnostic(command, env) {
    const maxHops = Math.min(30, Math.max(1, parsePositiveInteger(command.options?.max_hops, 15)));
    const waitSeconds = Math.min(10, Math.max(1, parsePositiveInteger(command.options?.timeout_seconds, 3)));
    const host = normalizeDiagnosticHost(command.target, env);
    return runExecFile('traceroute', ['-n', '-m', String(maxHops), '-w', String(waitSeconds), host], {
        timeoutMs: (maxHops * waitSeconds * 1000) + 5000
    });
}

async function runBandwidthDiagnostic(command, env) {
    const host = normalizeDiagnosticHost(command.target, env);
    const localAddresses = new Set([
        detectPrivateIp(),
        env.COLLECTOR_PRIVATE_IP,
        '127.0.0.1',
        'localhost'
    ].map((value) => String(value || '').trim().toLowerCase()).filter(Boolean));
    if (localAddresses.has(String(host).toLowerCase())) {
        throw new Error('bandwidth diagnostic must target a different client/server host; self-test results are invalid');
    }
    const port = parsePositivePort(command.options?.port, 5201);
    const seconds = Math.min(30, Math.max(1, parsePositiveInteger(command.options?.seconds, 5)));
    const reverse = command.options?.reverse === true;
    const args = ['-c', host, '-p', String(port), '-t', String(seconds), '-J'];
    if (reverse) {
        args.push('-R');
    }
    const result = await runExecFile('iperf3', args, {
        timeoutMs: ((seconds + 10) * 1000)
    });
    let parsed = {};
    try {
        parsed = JSON.parse(result.stdout || '{}');
    } catch (_error) {
        parsed = {};
    }
    const sent = Number(parsed.end?.sum_sent?.bits_per_second);
    const received = Number(parsed.end?.sum_received?.bits_per_second);
    const retransmits = Number(parsed.end?.sum_sent?.retransmits);
    return {
        ok: result.ok && !parsed.error,
        target: `${host}:${port}`,
        direction: reverse ? 'download_from_server' : 'upload_to_server',
        duration_seconds: seconds,
        sent_mbps: Number.isFinite(sent) ? Number((sent / 1000000).toFixed(2)) : null,
        received_mbps: Number.isFinite(received) ? Number((received / 1000000).toFixed(2)) : null,
        retransmits: Number.isFinite(retransmits) ? retransmits : null,
        error: parsed.error || result.error || null
    };
}

async function runDnsDiagnostic(command, env) {
    const queryName = String(command.target || command.options?.query || env.DIAGNOSTIC_DEFAULT_DNS_QUERY || 'naver.com').trim();
    if (!isLikelyHostname(queryName)) {
        throw new Error('dns diagnostic target must be a hostname');
    }

    const server = String(command.options?.server || '').trim();
    const args = ['+time=3', '+tries=1', '+short', queryName];
    if (server) {
        args.push(`@${normalizeDiagnosticHost(server, env)}`);
    }

    const result = await runExecFile('dig', args, {
        timeoutMs: 10000
    });
    const answers = String(result.stdout || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    return {
        ...result,
        ok: result.ok && answers.length > 0,
        query: queryName,
        answer_count: answers.length,
        answers: answers.slice(0, 20)
    };
}

function runTcpDiagnostic(command, env) {
    const startedAt = Date.now();
    const target = parseTcpTarget(command.target, command.options || {}, env);
    const timeoutMs = Math.min(30000, Math.max(1000, parsePositiveInteger(command.options?.timeout_ms, 5000)));

    return new Promise((resolve) => {
        const socket = net.connect({ host: target.host, port: target.port });
        let settled = false;

        function finish(ok, extra = {}) {
            if (settled) {
                return;
            }
            settled = true;
            socket.destroy();
            resolve({
                ok,
                target: `${target.host}:${target.port}`,
                duration_ms: Date.now() - startedAt,
                ...extra
            });
        }

        socket.setTimeout(timeoutMs, () => finish(false, { error: `timeout=${timeoutMs}ms` }));
        socket.on('connect', () => finish(true));
        socket.on('error', (error) => finish(false, { error: error.message }));
    });
}

async function runHttpDiagnostic(command, env) {
    const targetUrl = new URL(String(command.target || '').trim());
    if (!['http:', 'https:'].includes(targetUrl.protocol)) {
        throw new Error('http diagnostic target must start with http:// or https://');
    }
    normalizeDiagnosticHost(targetUrl.hostname, env, { allowHostname: true });

    const startedAt = Date.now();
    const isHttps = targetUrl.protocol === 'https:';
    const transport = isHttps ? https : http;
    const timeoutMs = Math.min(30000, Math.max(1000, parsePositiveInteger(command.options?.timeout_ms, 10000)));

    return new Promise((resolve) => {
        const request = transport.request({
            protocol: targetUrl.protocol,
            hostname: targetUrl.hostname,
            port: targetUrl.port || (isHttps ? 443 : 80),
            path: `${targetUrl.pathname}${targetUrl.search}`,
            method: String(command.options?.method || 'GET').toUpperCase(),
            rejectUnauthorized: isHttps && parseBoolean(env.NMS_INSECURE_TLS, false) ? false : undefined
        }, (response) => {
            response.resume();
            response.on('end', () => {
                resolve({
                    ok: response.statusCode >= 200 && response.statusCode < 500,
                    status_code: response.statusCode,
                    duration_ms: Date.now() - startedAt
                });
            });
        });

        request.setTimeout(timeoutMs, () => {
            request.destroy(new Error(`timeout=${timeoutMs}ms`));
        });
        request.on('error', (error) => {
            resolve({
                ok: false,
                error: error.message,
                duration_ms: Date.now() - startedAt
            });
        });
        request.end();
    });
}

async function runTcpdumpDiagnostic(command, env) {
    const interfaceName = String(command.options?.interface || env.DIAGNOSTIC_CAPTURE_INTERFACE || 'any').trim() || 'any';
    const packetCount = Math.min(2000, Math.max(10, parsePositiveInteger(command.options?.count, 500)));
    const maxSeconds = Math.min(
        60,
        Math.max(5, parsePositiveInteger(command.options?.seconds, env.DIAGNOSTIC_TCPDUMP_MAX_SECONDS || 15))
    );
    const filter = getTcpdumpFilter(command.target, command.options || {}, env);
    const captureProfile = String(command.target || command.options?.profile || 'default').trim().toLowerCase() || 'default';
    const requestedScope = String(command.options?.capture_scope || 'collector_interface').trim().toLowerCase();
    const captureScope = PACKET_CAPTURE_SCOPES.has(requestedScope) ? requestedScope : 'collector_interface';
    const retentionHours = Math.min(168, Math.max(1, parsePositiveInteger(
        command.options?.retention_hours,
        env.DIAGNOSTIC_PCAP_RETENTION_HOURS || 24
    )));
    const captureDirectory = String(env.DIAGNOSTIC_PCAP_DIR || '/var/log/nms-pcap').trim() || '/var/log/nms-pcap';
    fs.mkdirSync(captureDirectory, { recursive: true, mode: 0o750 });
    const prunedFileCount = prunePacketCaptureFiles(captureDirectory, retentionHours);

    let tsharkPath;
    try {
        tsharkPath = execFileSync('which', ['tshark'], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore']
        }).trim();
    } catch {
        const fallback = await runExecFile('tcpdump', ['-nn', '-i', interfaceName, '-c', String(Math.min(packetCount, 200)), filter], {
            timeoutMs: (maxSeconds * 1000) + 1000,
            maxBuffer: 128 * 1024
        });
        return {
            ...fallback,
            packet_analysis: {
                schema_version: 'collector-packet-analysis-v1',
                available: false,
                reason: 'tshark_not_installed',
                capture_scope: captureScope,
                capture_scope_notice: '수집기 인터페이스에서 관측 가능한 트래픽만 포함하며 전체 현장 트래픽을 의미하지 않습니다.'
            }
        };
    }

    const startedAt = new Date();
    const safeProfile = captureProfile.replace(/[^a-z0-9_-]+/g, '-').slice(0, 40) || 'default';
    const commandId = Number.isInteger(Number(command.id)) ? Number(command.id) : 0;
    const stamp = startedAt.toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
    const pcapFilename = `collector-${commandId || 'manual'}-${safeProfile}-${stamp}.pcapng`;
    const pcapPath = path.join(captureDirectory, pcapFilename);
    const capture = await runExecFile(tsharkPath, [
        '-q', '-i', interfaceName,
        '-a', `duration:${maxSeconds}`,
        '-c', String(packetCount),
        '-f', filter,
        '-w', pcapPath
    ], {
        timeoutMs: (maxSeconds * 1000) + 10000,
        maxBuffer: 64 * 1024
    });

    if (!fs.existsSync(pcapPath)) {
        return {
            ...capture,
            ok: false,
            error: capture.stderr || 'packet capture file was not created',
            packet_analysis: {
                schema_version: 'collector-packet-analysis-v1',
                available: false,
                reason: 'capture_file_missing',
                capture_scope: captureScope
            }
        };
    }

    const commonFieldArgs = [
        '-r', pcapPath, '-T', 'fields',
        '-E', 'separator=\t', '-E', 'quote=n', '-E', 'occurrence=f'
    ];
    const packetRows = await runExecFile(tsharkPath, [
        ...commonFieldArgs,
        '-e', 'frame.time_epoch', '-e', 'frame.len',
        '-e', 'eth.src', '-e', 'eth.dst',
        '-e', 'ip.src', '-e', 'ip.dst',
        '-e', 'ipv6.src', '-e', 'ipv6.dst',
        '-e', '_ws.col.Protocol',
        '-e', 'tcp.srcport', '-e', 'tcp.dstport',
        '-e', 'udp.srcport', '-e', 'udp.dstport',
        '-e', 'vlan.id',
        '-e', 'arp.src.proto_ipv4', '-e', 'arp.dst.proto_ipv4'
    ], { timeoutMs: 30000, maxBuffer: 512 * 1024, preserveWhitespace: true });
    const detailRows = await runExecFile(tsharkPath, [
        ...commonFieldArgs,
        '-e', 'tcp.flags.syn', '-e', 'tcp.flags.ack', '-e', 'tcp.flags.reset',
        '-e', 'tcp.analysis.retransmission',
        '-e', 'dns.flags.response', '-e', 'dns.flags.rcode', '-e', 'dns.qry.name',
        '-e', 'arp.opcode', '-e', 'icmp.type',
        '-e', 'lldp.tlv.system.name', '-e', 'cdp.deviceid'
    ], { timeoutMs: 30000, maxBuffer: 512 * 1024, preserveWhitespace: true });
    const packetStats = packetRows.ok ? parseTsharkPacketRows(packetRows.stdout) : parseTsharkPacketRows('');
    const detailStats = detailRows.ok ? parseTsharkDetailRows(detailRows.stdout) : parseTsharkDetailRows('');
    const fileStat = fs.statSync(pcapPath);
    const fileHash = crypto.createHash('sha256').update(fs.readFileSync(pcapPath)).digest('hex');
    const completedAt = new Date();
    const retainedUntil = new Date(completedAt.getTime() + (retentionHours * 60 * 60 * 1000));
    const captureScopeNotice = captureScope === 'span_mirror'
        ? 'SPAN/미러 포트로 유입된 범위만 포함합니다. 미러 정책 밖의 트래픽은 포함되지 않습니다.'
        : captureScope === 'trunk_observation'
            ? '트렁크 인터페이스에서 관측된 태그/비태그 프레임만 포함합니다.'
            : captureScope === 'targeted_host'
                ? '지정한 대상과 수집기 인터페이스 사이에서 관측된 트래픽만 포함합니다.'
                : '수집기 인터페이스에서 관측 가능한 유니캐스트·브로드캐스트·멀티캐스트만 포함하며 전체 현장 트래픽을 의미하지 않습니다.';

    return {
        ok: capture.ok && packetRows.ok,
        source: 'tshark_local_pcap_summary',
        error: capture.ok ? (packetRows.ok ? null : packetRows.stderr || 'tshark analysis failed') : capture.stderr || 'tshark capture failed',
        packet_analysis: {
            schema_version: 'collector-packet-analysis-v1',
            available: true,
            source: 'tshark_local_pcap_summary',
            measured_at: startedAt.toISOString(),
            ingested_at: null,
            interface: interfaceName,
            profile: captureProfile,
            capture_filter: filter,
            capture_scope: captureScope,
            capture_scope_notice: captureScopeNotice,
            requested_duration_seconds: maxSeconds,
            requested_packet_limit: packetCount,
            capture_duration_ms: completedAt.getTime() - startedAt.getTime(),
            ...packetStats,
            ...detailStats,
            retransmission_interpretation: 'tshark_suspected_within_partial_capture',
            pcap: {
                local_filename: pcapFilename,
                local_path: pcapPath,
                size_bytes: fileStat.size,
                sha256: fileHash,
                retained_until: retainedUntil.toISOString(),
                uploaded_to_nms: false
            },
            privacy: {
                payload_uploaded: false,
                raw_pcap_uploaded: false,
                dns_query_names_in_summary: true
            },
            pruned_file_count: prunedFileCount,
            parser_errors: [
                packetRows.ok ? null : packetRows.stderr || 'packet row parsing failed',
                detailRows.ok ? null : detailRows.stderr || 'detail row parsing failed'
            ].filter(Boolean)
        }
    };
}

async function runArpwatchDiagnostic() {
    const result = await runExecFile('ip', ['neigh', 'show'], {
        timeoutMs: 10000,
        maxBuffer: 128 * 1024
    });
    const lines = String(result.stdout || '').split(/\r?\n/).filter(Boolean);
    const stateCounts = {};
    for (const line of lines) {
        const match = line.match(/\b(REACHABLE|STALE|DELAY|PROBE|FAILED|INCOMPLETE|PERMANENT|NOARP)\b/);
        const state = match ? match[1].toLowerCase() : 'unknown';
        stateCounts[state] = (stateCounts[state] || 0) + 1;
    }

    return {
        ...result,
        neighbor_count: lines.length,
        state_counts: stateCounts
    };
}

async function runGatewayInfoDiagnostic() {
    const route = await runExecFile('ip', ['route', 'show'], {
        timeoutMs: 10000,
        maxBuffer: 64 * 1024
    });
    const address = await runExecFile('ip', ['-brief', 'address'], {
        timeoutMs: 10000,
        maxBuffer: 64 * 1024
    });

    return {
        ok: route.ok && address.ok,
        default_gateway: getDefaultGateway(),
        route,
        address
    };
}

async function runToolsInfoDiagnostic() {
    const tools = ['ping', 'traceroute', 'dig', 'tcpdump', 'ip', 'curl', 'snmpget', 'node'];
    const checks = {};

    for (const tool of tools) {
        try {
            const found = execFileSync('which', [tool], {
                encoding: 'utf8',
                stdio: ['ignore', 'pipe', 'ignore']
            }).trim();
            checks[tool] = found || true;
        } catch {
            checks[tool] = false;
        }
    }

    return {
        ok: Object.values(checks).every(Boolean),
        tools: checks,
        node: process.version,
        platform: os.platform(),
        release: os.release()
    };
}

async function runConfiguredInternetPingDiagnostic(env, targetValue = null, targetLabel = null) {
    const target = String(targetValue || env.DIAGNOSTIC_INTERNET_PING_TARGET || '1.1.1.1').trim();
    if (!net.isIP(target) && !isLikelyHostname(target)) {
        throw new Error('DIAGNOSTIC_INTERNET_PING_TARGET must be an IP address or hostname');
    }

    const result = await runExecFile('ping', ['-c', '4', '-W', '3', target], {
        timeoutMs: 17000
    });
    return {
        ...result,
        target,
        target_label: targetLabel || target
    };
}

async function runMeasurementInternetPingDiagnostic(env, targetValue, targetLabel) {
    const target = String(targetValue || '').trim();
    if (!net.isIP(target) && !isLikelyHostname(target)) throw new Error('measurement ping target is invalid');
    const result = await runExecFile('ping', ['-c', '1', '-W', '2', target], { timeoutMs: 5000 });
    return { ...result, target, target_label: targetLabel || target };
}

function findDiagnosticStep(steps, name) {
    return steps.find((step) => step.name === name) || null;
}

function summarizePingStep(step) {
    if (!step || !step.result) return null;
    const stdout = String(step.result.stdout || '');
    const lossMatch = stdout.match(/([0-9.]+)%\s+packet loss/);
    const rttMatch = stdout.match(/(?:rtt|round-trip) min\/avg\/max\/(?:mdev|stddev)\s*=\s*([0-9.]+)\/([0-9.]+)\/([0-9.]+)\/([0-9.]+)\s*ms/);
    return {
        target: step.result.target || null,
        target_label: step.result.target_label || null,
        packet_loss_pct: lossMatch ? Number(lossMatch[1]) : null,
        latency_min_ms: rttMatch ? Number(rttMatch[1]) : null,
        latency_avg_ms: rttMatch ? Number(rttMatch[2]) : null,
        latency_max_ms: rttMatch ? Number(rttMatch[3]) : null,
        jitter_ms: rttMatch ? Number(rttMatch[4]) : null
    };
}

function readCpuTimes() {
    return os.cpus().reduce((total, cpu) => {
        const times = cpu.times || {};
        total.idle += Number(times.idle) || 0;
        total.total += Object.values(times).reduce((sum, value) => sum + (Number(value) || 0), 0);
        return total;
    }, { idle: 0, total: 0 });
}

function calculateCpuUsedPct(previous, current) {
    const totalDelta = current.total - previous.total;
    const idleDelta = current.idle - previous.idle;
    if (!Number.isFinite(totalDelta) || totalDelta <= 0 || !Number.isFinite(idleDelta)) return null;
    return Number((Math.max(0, Math.min(1, 1 - (idleDelta / totalDelta))) * 100).toFixed(3));
}

function readInterfaceCounters() {
    const counters = {};
    let names = [];
    try {
        names = fs.readdirSync('/sys/class/net');
    } catch {
        return counters;
    }
    for (const name of names.filter((value) => value !== 'lo').slice(0, 64)) {
        try {
            const state = fs.readFileSync(`/sys/class/net/${name}/operstate`, 'utf8').trim();
            if (state !== 'up' && state !== 'unknown') continue;
            const rxBytes = Number(fs.readFileSync(`/sys/class/net/${name}/statistics/rx_bytes`, 'utf8').trim());
            const txBytes = Number(fs.readFileSync(`/sys/class/net/${name}/statistics/tx_bytes`, 'utf8').trim());
            if (Number.isFinite(rxBytes) && Number.isFinite(txBytes)) counters[name] = { rx_bytes: rxBytes, tx_bytes: txBytes };
        } catch {
            // Interfaces can disappear while NetworkManager changes a connection.
        }
    }
    return counters;
}

function readRootDiskUsedPct(execFn = execFileSync) {
    const result = safeExecOutput('df', ['-P', '-k', '/'], execFn);
    const disks = parseDfOutput(result.stdout);
    const root = disks.find((item) => item.mount === '/') || disks[0];
    return Number.isFinite(root?.use_pct) ? root.use_pct : null;
}

function aggregateMeasurementMetric(aggregates, definition, value, observedAt, attempted = true) {
    const identity = `${definition.metric_key}\u0000${definition.target || ''}`;
    const row = aggregates.get(identity) || {
        ...definition,
        target: definition.target || '',
        attempted_count: 0,
        successful_count: 0,
        failed_count: 0,
        values: [],
        first_observed_at: null,
        last_observed_at: null
    };
    if (!attempted) {
        aggregates.set(identity, row);
        return;
    }
    row.attempted_count += 1;
    if (Number.isFinite(value)) {
        row.successful_count += 1;
        row.values.push(Number(value));
        row.first_observed_at ||= observedAt;
        row.last_observed_at = observedAt;
    } else {
        row.failed_count += 1;
    }
    aggregates.set(identity, row);
}

function finalizeMeasurementMetrics(aggregates) {
    return Array.from(aggregates.values()).map((row) => {
        const values = row.values;
        const sum = values.reduce((total, value) => total + value, 0);
        return {
            metric_key: row.metric_key,
            metric_label: row.metric_label,
            target: row.target,
            unit: row.unit,
            attempted_count: row.attempted_count,
            successful_count: row.successful_count,
            failed_count: row.failed_count,
            min_value: values.length ? Number(Math.min(...values).toFixed(3)) : null,
            avg_value: values.length ? Number((sum / values.length).toFixed(3)) : null,
            max_value: values.length ? Number(Math.max(...values).toFixed(3)) : null,
            latest_value: values.length ? Number(values.at(-1).toFixed(3)) : null,
            first_observed_at: row.first_observed_at,
            last_observed_at: row.last_observed_at,
            source: row.source
        };
    }).sort((a, b) => `${a.metric_key}:${a.target}`.localeCompare(`${b.metric_key}:${b.target}`));
}

async function runMeasurementSessionDiagnostic(command, env) {
    const requestedDurationSeconds = Math.min(28800, Math.max(10, parsePositiveInteger(command.options?.duration_seconds, 300)));
    const intervalSeconds = Math.min(300, Math.max(2, parsePositiveInteger(command.options?.interval_seconds, 10)));
    const moduleRunIds = command.options?.module_run_ids
        && typeof command.options.module_run_ids === 'object'
        && !Array.isArray(command.options.module_run_ids)
        ? command.options.module_run_ids
        : {};
    const timezone = String(command.options?.timezone || 'Asia/Seoul');
    const expectedRounds = Math.floor(requestedDurationSeconds / intervalSeconds) + 1;
    if (expectedRounds > 2000) throw new Error('measurement session exceeds the 2,000 round safety limit');

    const startedAtMs = Date.now();
    const startedAt = new Date(startedAtMs).toISOString();
    const gateway = getDefaultGateway();
    const pingTargets = [
        { key: 'gateway', label: '게이트웨이', target: gateway },
        { key: 'kt_dns', label: '국내 KT DNS', target: String(env.DIAGNOSTIC_KT_PING_TARGET || '168.126.63.1').trim() },
        { key: 'google_dns', label: '해외 Google DNS', target: String(env.DIAGNOSTIC_GOOGLE_PING_TARGET || '8.8.8.8').trim() }
    ];
    const aggregates = new Map();
    const rawSamples = [];
    const rawSampleStride = Math.max(1, Math.ceil(expectedRounds / 98));
    let previousCpu = readCpuTimes();
    let previousInterfaces = readInterfaceCounters();
    let previousInterfaceAtMs = startedAtMs;
    let roundsCompleted = 0;

    for (let round = 0; round < expectedRounds; round += 1) {
        const scheduledAtMs = startedAtMs + (round * intervalSeconds * 1000);
        const waitMs = scheduledAtMs - Date.now();
        if (waitMs > 0) await sleep(waitMs);

        const observedAt = new Date().toISOString();
        const sample = {
            sampled_at: observedAt,
            observed_at: observedAt,
            timezone,
            source_delay_ms: null,
            sample_status: 'success',
            values: {},
            failed_metrics: []
        };
        const pingResults = await Promise.all(pingTargets.map(async (item) => {
            if (!item.target) return { ...item, summary: null };
            const result = item.key === 'gateway'
                ? await runPingDiagnostic({ target: item.target, options: { count: 1, timeout_seconds: 2 } }, env)
                : await runMeasurementInternetPingDiagnostic(env, item.target, item.label);
            return { ...item, summary: summarizePingStep({ result: { ...result, target: item.target, target_label: item.label } }) };
        }));
        for (const ping of pingResults) {
            const latencyKey = `${ping.key}_latency_ms`;
            const lossKey = `${ping.key}_packet_loss_pct`;
            const latency = ping.summary?.latency_avg_ms ?? null;
            const loss = ping.summary?.packet_loss_pct ?? (ping.target ? 100 : null);
            aggregateMeasurementMetric(aggregates, {
                metric_key: latencyKey, metric_label: `${ping.label} 지연`, target: ping.target || '', unit: 'ms', source: 'icmp_ping'
            }, latency, observedAt);
            aggregateMeasurementMetric(aggregates, {
                metric_key: lossKey, metric_label: `${ping.label} 손실률`, target: ping.target || '', unit: 'percent', source: 'icmp_ping'
            }, loss, observedAt);
            sample.values[latencyKey] = latency;
            sample.values[lossKey] = loss;
            if (latency === null) sample.failed_metrics.push(latencyKey);
            if (loss === null) sample.failed_metrics.push(lossKey);
        }

        const currentCpu = readCpuTimes();
        const cpuUsedPct = calculateCpuUsedPct(previousCpu, currentCpu);
        previousCpu = currentCpu;
        const totalMem = os.totalmem();
        const memoryUsedPct = totalMem > 0 ? Number((((totalMem - os.freemem()) / totalMem) * 100).toFixed(3)) : null;
        const diskUsedPct = readRootDiskUsedPct();
        for (const metric of [
            ['cpu_used_pct', 'CPU 사용률', 'percent', cpuUsedPct, 'os_cpu_times'],
            ['memory_used_pct', '메모리 사용률', 'percent', memoryUsedPct, 'os_memory'],
            ['root_disk_used_pct', '루트 디스크 사용률', 'percent', diskUsedPct, 'df_root']
        ]) {
            aggregateMeasurementMetric(aggregates, {
                metric_key: metric[0], metric_label: metric[1], target: '', unit: metric[2], source: metric[4]
            }, metric[3], observedAt);
            sample.values[metric[0]] = metric[3];
            if (metric[3] === null) sample.failed_metrics.push(metric[0]);
        }

        const currentInterfaceAtMs = Date.now();
        const currentInterfaces = readInterfaceCounters();
        const elapsedSeconds = (currentInterfaceAtMs - previousInterfaceAtMs) / 1000;
        for (const [name, counters] of Object.entries(currentInterfaces)) {
            const previous = previousInterfaces[name];
            if (!previous || elapsedSeconds <= 0) continue;
            const rxMbps = counters.rx_bytes >= previous.rx_bytes ? ((counters.rx_bytes - previous.rx_bytes) * 8 / elapsedSeconds / 1000000) : null;
            const txMbps = counters.tx_bytes >= previous.tx_bytes ? ((counters.tx_bytes - previous.tx_bytes) * 8 / elapsedSeconds / 1000000) : null;
            for (const direction of [
                ['interface_rx_mbps', '인터페이스 수신 속도', rxMbps],
                ['interface_tx_mbps', '인터페이스 송신 속도', txMbps]
            ]) {
                aggregateMeasurementMetric(aggregates, {
                    metric_key: direction[0], metric_label: direction[1], target: name, unit: 'Mbps', source: 'sysfs_counter_delta'
                }, direction[2], observedAt);
            }
        }
        previousInterfaces = currentInterfaces;
        previousInterfaceAtMs = currentInterfaceAtMs;
        sample.source_delay_ms = Number(Math.max(
            0,
            Date.now() - new Date(observedAt).getTime()
        ).toFixed(3));
        if (Object.keys(sample.values).length
            && sample.failed_metrics.length === Object.keys(sample.values).length) {
            sample.sample_status = 'failure';
        }
        roundsCompleted += 1;
        if (round === 0 || round === expectedRounds - 1 || round % rawSampleStride === 0) rawSamples.push(sample);
    }

    const endedAtMs = Date.now();
    return {
        ok: true,
        measurement_session: {
            schema_version: 'collector-measurement-session-v1',
            source: 'ubuntu_collector_measurement_session',
            timezone,
            module_run_ids: moduleRunIds,
            started_at: startedAt,
            ended_at: new Date(endedAtMs).toISOString(),
            requested_duration_seconds: requestedDurationSeconds,
            observed_duration_seconds: Number(((endedAtMs - startedAtMs) / 1000).toFixed(3)),
            interval_seconds: intervalSeconds,
            rounds_attempted: expectedRounds,
            rounds_completed: roundsCompleted,
            targets: Object.fromEntries(pingTargets.map((item) => [item.key, item.target || null])),
            metrics: finalizeMeasurementMetrics(aggregates),
            raw_sample_retention: {
                retained_count: rawSamples.length,
                total_count: roundsCompleted,
                sampling_stride: rawSampleStride
            },
            raw_samples: rawSamples
        }
    };
}

function buildConnectivityAssessment(steps = []) {
    const gatewayPing = findDiagnosticStep(steps, 'gateway-ping');
    const legacyInternetPing = findDiagnosticStep(steps, 'internet-ping');
    const ktInternetPing = findDiagnosticStep(steps, 'internet-ping-kt');
    const googleInternetPing = findDiagnosticStep(steps, 'internet-ping-google');
    const internetPingSteps = [ktInternetPing, googleInternetPing].filter(Boolean);
    const internetPing = legacyInternetPing || (internetPingSteps.length ? {
        ok: internetPingSteps.some((step) => step.ok)
    } : null);
    const dns = findDiagnosticStep(steps, 'dns-default');
    const internetHttps = findDiagnosticStep(steps, 'internet-https');
    const nmsTcp = findDiagnosticStep(steps, 'nms-tcp');
    const facts = {
        gateway_ping: gatewayPing ? gatewayPing.ok : null,
        internet_ping: internetPing ? internetPing.ok : null,
        internet_ping_kt: ktInternetPing ? ktInternetPing.ok : null,
        internet_ping_google: googleInternetPing ? googleInternetPing.ok : null,
        dns: dns ? dns.ok : null,
        internet_https: internetHttps ? internetHttps.ok : null,
        nms_tcp: nmsTcp ? nmsTcp.ok : null
    };
    const missingData = Object.entries(facts)
        .filter(([, value]) => value === null)
        .map(([key]) => key);

    if (facts.gateway_ping === false) {
        return {
            state: 'local_gateway_unreachable',
            cause_label: 'gateway_router_wan',
            confidence: 'high',
            summary: '기본 게이트웨이 Ping 실패',
            facts,
            missing_data: missingData
        };
    }

    if (facts.internet_ping === true && facts.internet_https === false) {
        return {
            state: 'internet_service_restricted',
            cause_label: 'firewall_policy_session',
            confidence: facts.dns === true ? 'high' : 'medium',
            summary: '외부 Ping은 정상이지만 HTTPS 세션이 차단됨',
            facts,
            missing_data: missingData
        };
    }

    if (facts.gateway_ping === true && facts.nms_tcp === true && facts.internet_https === false) {
        return {
            state: 'selective_egress_restricted',
            cause_label: 'firewall_policy_session',
            confidence: 'medium',
            summary: '내부 게이트웨이와 중앙 NMS는 도달하지만 일반 인터넷 HTTPS가 차단됨',
            facts,
            missing_data: missingData
        };
    }

    if (facts.gateway_ping === true && facts.internet_ping === false && facts.internet_https === false) {
        return {
            state: 'internet_unreachable',
            cause_label: 'isp_circuit',
            confidence: 'low',
            summary: '게이트웨이는 정상이지만 외부 Ping과 HTTPS가 모두 실패함',
            facts,
            missing_data: missingData,
            contradictory_evidence: ['방화벽이 ICMP와 HTTPS를 함께 차단했을 가능성을 배제할 수 없음']
        };
    }

    if (facts.gateway_ping === true && facts.dns === true && facts.internet_https === true && facts.nms_tcp !== false) {
        return {
            state: 'healthy',
            cause_label: null,
            confidence: 'high',
            summary: '게이트웨이, DNS, 인터넷 HTTPS, 중앙 NMS 경로 정상',
            facts,
            missing_data: missingData
        };
    }

    return {
        state: 'insufficient_data',
        cause_label: 'unknown',
        confidence: 'low',
        summary: '현재 진단 조합만으로 원인을 확정할 수 없음',
        facts,
        missing_data: missingData
    };
}

async function runGoalDiagnostic(command, env) {
    const goal = String(command.target || 'site-standard-check').trim() || 'site-standard-check';
    const steps = [];
    const nms = getNmsHostAndPort(env);

    async function addStep(name, stepCommand) {
        try {
            const result = await executeDiagnosticPayload(stepCommand, env);
            steps.push({ name, command_type: stepCommand.command_type, ok: result.ok !== false, result });
        } catch (error) {
            steps.push({ name, command_type: stepCommand.command_type, ok: false, error: error.message });
        }
    }

    await addStep('gateway-info', { command_type: 'gateway-info', options: {} });
    await addStep('gateway-ping', { command_type: 'ping', target: 'gateway', options: { count: 4 } });
    const internetPingTargets = [
        { name: 'internet-ping-kt', label: '국내 KT DNS', target: command.options?.kt_ping_target || env.DIAGNOSTIC_KT_PING_TARGET || '168.126.63.1' },
        { name: 'internet-ping-google', label: '해외 Google DNS', target: command.options?.google_ping_target || env.DIAGNOSTIC_GOOGLE_PING_TARGET || '8.8.8.8' }
    ];
    for (const pingTarget of internetPingTargets) {
        try {
            const result = await runConfiguredInternetPingDiagnostic(env, pingTarget.target, pingTarget.label);
            steps.push({ name: pingTarget.name, command_type: 'ping', ok: result.ok !== false, result });
        } catch (error) {
            steps.push({ name: pingTarget.name, command_type: 'ping', ok: false, error: error.message });
        }
    }
    await addStep('dns-default', {
        command_type: 'dns',
        target: command.options?.dns_query || env.DIAGNOSTIC_DEFAULT_DNS_QUERY || 'naver.com',
        options: {}
    });
    await addStep('internet-https', {
        command_type: 'http',
        target: command.options?.internet_test_url || env.DIAGNOSTIC_INTERNET_TEST_URL || 'https://www.naver.com/',
        options: { timeout_ms: 10000 }
    });

    if (nms.host && nms.port) {
        await addStep('nms-tcp', {
            command_type: 'tcp',
            target: nms.host,
            options: { port: nms.port, timeout_ms: 5000 }
        });
    }

    if (goal === 'router-standard-check' || goal === 'firewall-standard-check') {
        await addStep('arp-neighbor', { command_type: 'arpwatch', options: {} });
    }

    const ok = steps.every((step) => step.ok);
    const assessment = buildConnectivityAssessment(steps);
    return {
        ok,
        goal,
        step_count: steps.length,
        failed_steps: steps.filter((step) => !step.ok).map((step) => step.name),
        assessment,
        steps
    };
}

async function executeDiagnosticPayload(command, env) {
    const commandType = String(command.command_type || '').trim().toLowerCase();
    if (!DIAGNOSTIC_COMMAND_TYPES.has(commandType)) {
        throw new Error(`unsupported diagnostic command_type: ${commandType || '(blank)'}`);
    }

    const normalizedCommand = {
        ...command,
        command_type: commandType,
        options: command.options && typeof command.options === 'object' ? command.options : {}
    };

    if (commandType === 'ping') {
        return runPingDiagnostic(normalizedCommand, env);
    }
    if (commandType === 'traceroute') {
        return runTracerouteDiagnostic(normalizedCommand, env);
    }
    if (commandType === 'bandwidth') {
        return runBandwidthDiagnostic(normalizedCommand, env);
    }
    if (commandType === 'measurement') {
        return runMeasurementSessionDiagnostic(normalizedCommand, env);
    }
    if (commandType === 'dns') {
        return runDnsDiagnostic(normalizedCommand, env);
    }
    if (commandType === 'tcp') {
        return runTcpDiagnostic(normalizedCommand, env);
    }
    if (commandType === 'http') {
        return runHttpDiagnostic(normalizedCommand, env);
    }
    if (commandType === 'tcpdump') {
        return runTcpdumpDiagnostic(normalizedCommand, env);
    }
    if (commandType === 'arpwatch') {
        return runArpwatchDiagnostic(normalizedCommand, env);
    }
    if (commandType === 'gateway-info') {
        return runGatewayInfoDiagnostic(normalizedCommand, env);
    }
    if (commandType === 'tools-info') {
        return runToolsInfoDiagnostic(normalizedCommand, env);
    }
    if (commandType === 'goal') {
        return runGoalDiagnostic(normalizedCommand, env);
    }

    throw new Error(`unsupported diagnostic command_type: ${commandType}`);
}

function buildDiagnosticResultExcerpt(command, result, error = null) {
    if (error) {
        return truncateText(`${command.command_type} failed: ${error.message}`, 1000);
    }

    if (result?.goal) {
        return truncateText(`${result.goal}: ${result.failed_steps?.length || 0} failed of ${result.step_count || 0} steps`, 1000);
    }

    if (result?.measurement_session) {
        const session = result.measurement_session;
        return truncateText(
            `measurement ${session.observed_duration_seconds}s / ${session.rounds_completed} rounds / ${session.metrics?.length || 0} metrics`,
            1000
        );
    }

    if (result?.packet_analysis?.available) {
        const packet = result.packet_analysis;
        return truncateText(
            `packet capture ${packet.packet_count || 0} packets / ${packet.byte_count || 0} bytes`
            + ` / suspected retransmissions ${packet.tcp_retransmission_count || 0}`
            + ` / DNS errors ${packet.dns_error_count || 0}`
            + ` / scope ${packet.capture_scope || 'collector_interface'}`,
            1000
        );
    }

    if (result?.stdout) {
        return truncateText(result.stdout, 1000);
    }

    if (result?.error) {
        return truncateText(result.error, 1000);
    }

    return truncateText(JSON.stringify(result || {}), 1000);
}

async function executeDiagnosticCommand(command, env) {
    const startedAt = Date.now();
    try {
        const result = await executeDiagnosticPayload(command, env);
        const ok = result.ok !== false;
        return {
            status: ok ? 'succeeded' : 'failed',
            result,
            result_excerpt: buildDiagnosticResultExcerpt(command, result),
            run_duration_ms: Date.now() - startedAt
        };
    } catch (error) {
        return {
            status: 'failed',
            result: {
                ok: false,
                error: error.message,
                command_type: command.command_type || null
            },
            result_excerpt: buildDiagnosticResultExcerpt(command, null, error),
            error_message: error.message,
            run_duration_ms: Date.now() - startedAt
        };
    }
}

async function claimDiagnosticCommands(env, report, limit = 1) {
    const payload = await withNmsFallback(env, (baseUrl) => requestJsonGet(
        `${baseUrl}/api/collectors/${report.collectorId}/diagnostic-commands/pending?limit=${limit}`,
        { 'X-Collector-Token': String(env.COLLECTOR_TOKEN).trim() }, env
    ));

    return Array.isArray(payload.commands) ? payload.commands : [];
}

async function postDiagnosticCommandResult(env, report, commandId, payload) {
    await withNmsFallback(env, (baseUrl) => ensureSuccessfulJsonPost(
        `${baseUrl}/api/collectors/${report.collectorId}/diagnostic-commands/${commandId}/result`,
        { 'Content-Type': 'application/json', 'X-Collector-Token': String(env.COLLECTOR_TOKEN).trim() },
        payload, `collector diagnostic result failed command_id=${commandId}`, env
    ));
}

function getFieldMeasurementQueueDirectories(env) {
    const root = String(env.FIELD_MEASUREMENT_QUEUE_DIR || DEFAULT_FIELD_MEASUREMENT_QUEUE_DIR).trim()
        || DEFAULT_FIELD_MEASUREMENT_QUEUE_DIR;
    return {
        root,
        pending: path.join(root, 'pending'),
        sent: path.join(root, 'sent')
    };
}

function writeJsonAtomically(filePath, payload) {
    const directory = path.dirname(filePath);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temporaryPath = path.join(
        directory,
        `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`
    );
    fs.writeFileSync(temporaryPath, `${JSON.stringify(payload, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(temporaryPath, filePath);
    fs.chmodSync(filePath, 0o600);
}

function safeReadFieldMeasurementQueueItem(filePath) {
    try {
        const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
            throw new Error('queue item must be a JSON object');
        }
        return value;
    } catch (error) {
        return { _invalid: true, _error: error.message };
    }
}

function listQueueFiles(directory) {
    if (!fs.existsSync(directory)) return [];
    return fs.readdirSync(directory, { withFileTypes: true })
        .filter((entry) => entry.isFile() && /^[A-Za-z0-9][A-Za-z0-9._-]{11,127}\.json$/.test(entry.name))
        .map((entry) => path.join(directory, entry.name))
        .sort();
}

function buildQueuedFieldMeasurement(fieldProfile, measurementSession, now = new Date(), measurementSessionId = null) {
    const clientSessionId = crypto.randomUUID();
    return {
        schema_version: 'collector-field-measurement-queue-v1',
        client_session_id: clientSessionId,
        status: 'pending',
        queued_at: now.toISOString(),
        attempts: 0,
        last_attempt_at: null,
        last_error: null,
        delivered_at: null,
        session_kind: 'measurement',
        measurement_session_id: measurementSessionId,
        field_profile: normalizeFieldMeasurementProfile(fieldProfile),
        measurement_session: measurementSession
    };
}

function buildQueuedFieldSnapshot(fieldProfile, measurementSession, localEvidence, now = new Date()) {
    const item = buildQueuedFieldMeasurement(fieldProfile, measurementSession, now);
    item.schema_version = 'collector-field-snapshot-queue-v1';
    item.session_kind = 'diagnostic_snapshot';
    item.local_evidence = localEvidence;
    return item;
}

function persistQueuedFieldMeasurement(env, item) {
    const directories = getFieldMeasurementQueueDirectories(env);
    const filePath = path.join(directories.pending, `${item.client_session_id}.json`);
    writeJsonAtomically(filePath, item);
    return filePath;
}

function summarizeQueuedFieldMeasurement(item, state, filePath) {
    const session = item.measurement_session || {};
    return {
        client_session_id: item.client_session_id || path.basename(filePath, '.json'),
        state,
        queued_at: item.queued_at || null,
        delivered_at: item.delivered_at || null,
        attempts: Number(item.attempts) || 0,
        last_error: item.last_error || null,
        session_kind: item.session_kind || 'measurement',
        site_name: item.field_profile?.site_name || null,
        started_at: session.started_at || null,
        ended_at: session.ended_at || null,
        metric_count: Array.isArray(session.metrics) ? session.metrics.length : 0
    };
}

function listQueuedFieldMeasurements(env) {
    const directories = getFieldMeasurementQueueDirectories(env);
    const rows = [];
    for (const [state, directory] of [['pending', directories.pending], ['sent', directories.sent]]) {
        for (const filePath of listQueueFiles(directory)) {
            const item = safeReadFieldMeasurementQueueItem(filePath);
            if (item._invalid) {
                rows.push({
                    client_session_id: path.basename(filePath, '.json'),
                    state: 'invalid',
                    queued_at: null,
                    delivered_at: null,
                    attempts: 0,
                    last_error: item._error,
                    site_name: null,
                    started_at: null,
                    ended_at: null,
                    metric_count: 0
                });
                continue;
            }
            rows.push(summarizeQueuedFieldMeasurement(item, state, filePath));
        }
    }
    return rows.sort((left, right) => String(right.queued_at || '').localeCompare(String(left.queued_at || '')));
}

async function postOfflineMeasurementSession(env, report, item) {
    return withNmsFallback(env, (baseUrl) => ensureSuccessfulJsonPost(
        `${baseUrl}/api/collectors/${report.collectorId}/measurement-sessions/offline`,
        { 'Content-Type': 'application/json', 'X-Collector-Token': String(env.COLLECTOR_TOKEN).trim() },
        {
            client_session_id: item.client_session_id,
            measurement_session_id: item.measurement_session_id || null,
            field_profile: item.field_profile,
            measurement_session: item.measurement_session
        },
        'collector offline measurement upload failed',
        env
    ));
}

async function flushQueuedFieldMeasurements(env) {
    const report = inspectCollectorEnv(env);
    if (!report.ready) throw new Error(report.errors.join('; '));
    const directories = getFieldMeasurementQueueDirectories(env);
    const result = { attempted: 0, delivered: 0, pending: 0, invalid: 0, items: [] };
    for (const filePath of listQueueFiles(directories.pending)) {
        const item = safeReadFieldMeasurementQueueItem(filePath);
        if (item._invalid) {
            result.invalid += 1;
            result.items.push({ client_session_id: path.basename(filePath, '.json'), state: 'invalid', error: item._error });
            continue;
        }
        result.attempted += 1;
        item.attempts = Math.max(0, Number(item.attempts) || 0) + 1;
        item.last_attempt_at = new Date().toISOString();
        try {
            const receipt = await postOfflineMeasurementSession(env, report, item);
            item.status = 'sent';
            item.delivered_at = new Date().toISOString();
            item.last_error = null;
            item.receipt = {
                id: receipt?.id || null,
                ingest_mode: receipt?.ingest_mode || null,
                received_at: item.delivered_at
            };
            const sentPath = path.join(directories.sent, `${item.client_session_id}.json`);
            writeJsonAtomically(sentPath, item);
            fs.unlinkSync(filePath);
            result.delivered += 1;
            result.items.push({ client_session_id: item.client_session_id, state: 'sent', receipt: item.receipt });
        } catch (error) {
            item.status = 'pending';
            item.last_error = truncateText(error.message, 1000) || 'upload failed';
            writeJsonAtomically(filePath, item);
            result.pending += 1;
            result.items.push({ client_session_id: item.client_session_id, state: 'pending', error: item.last_error });
        }
    }
    return result;
}

async function requestSelfMeasurementCommand(env, report, durationSeconds, intervalSeconds) {
    return withNmsFallback(env, (baseUrl) => ensureSuccessfulJsonPost(
        `${baseUrl}/api/collectors/${report.collectorId}/diagnostic-commands/self`,
        { 'Content-Type': 'application/json', 'X-Collector-Token': String(env.COLLECTOR_TOKEN).trim() },
        {
            command_type: 'measurement',
            options: {
                duration_seconds: durationSeconds,
                interval_seconds: intervalSeconds
            },
            expires_in_minutes: Math.ceil(durationSeconds / 60) + 10
        },
        'collector self measurement request failed',
        env
    ));
}

async function runLocalMeasurementSession(
    env,
    durationValue,
    intervalValue,
    fieldProfile,
    measurementSessionId = null,
    moduleRunIds = {}
) {
    const report = inspectCollectorEnv(env);
    if (!report.ready) throw new Error(report.errors.join('; '));
    const durationSeconds = Math.min(28800, Math.max(10, parsePositiveInteger(durationValue, 300)));
    const intervalSeconds = Math.min(300, Math.max(2, parsePositiveInteger(intervalValue, 10)));
    if (Math.floor(durationSeconds / intervalSeconds) + 1 > 2000) {
        throw new Error('measurement session exceeds the 2,000 round safety limit');
    }
    const profile = normalizeFieldMeasurementProfile(fieldProfile);
    const result = await runMeasurementSessionDiagnostic({
        command_type: 'measurement',
        options: {
            duration_seconds: durationSeconds,
            interval_seconds: intervalSeconds,
            timezone: 'Asia/Seoul',
            module_run_ids: moduleRunIds
        }
    }, env);
    const queued = buildQueuedFieldMeasurement(
        profile,
        result.measurement_session,
        new Date(),
        measurementSessionId
    );
    persistQueuedFieldMeasurement(env, queued);
    const delivery = await flushQueuedFieldMeasurements(env);
    const itemResult = delivery.items.find((item) => item.client_session_id === queued.client_session_id) || null;
    return {
        ...result,
        client_session_id: queued.client_session_id,
        field_profile: profile,
        delivery: itemResult?.state === 'sent'
            ? { state: 'sent', receipt: itemResult.receipt || null }
            : { state: 'pending', error: itemResult?.error || 'central NMS delivery pending' }
    };
}

function buildCollectionSourceStatus(snapshot, env = {}) {
    const observedAt = snapshot.collected_at;
    const listeners = snapshot.network?.listeners || {};
    const snmp = snapshot.network?.network_device_snmp || {};
    const discovery = snapshot.network?.lldp || {};
    const discoveryProtocols = discovery.protocol_counts || {};
    const cdpNeighborCount = Object.entries(discoveryProtocols)
        .filter(([protocol]) => protocol.startsWith('CDP'))
        .reduce((sum, [, count]) => sum + (Number(count) || 0), 0);
    const tools = snapshot.tools || {};
    const listenerState = (key) => listeners[key]?.listening ? 'active' : 'unavailable';
    return {
        schema_version: 'collector-source-readiness-v1',
        observed_at: observedAt,
        syslog: { state: listenerState('syslog_udp'), source: 'socket_listener', port: 5514 },
        snmp_polling: {
            state: snmp.enabled ? (snmp.target_count > 0 ? 'active' : 'configured') : 'unconfigured',
            source: 'snmp_polling_config',
            target_count: Number(snmp.target_count) || 0,
            target_up_count: Number(snmp.target_up_count) || 0
        },
        snmp_trap: { state: listenerState('snmp_trap'), source: 'socket_listener', port: 1162 },
        lldp_discovery: {
            state: discovery.available ? ((Number(discoveryProtocols.LLDP) || 0) > 0 ? 'active' : 'available') : 'unavailable',
            source: 'lldpd_neighbor_table',
            target_count: Number(discoveryProtocols.LLDP) || 0
        },
        cdp_discovery: {
            state: discovery.available ? (cdpNeighborCount > 0 ? 'active' : 'available') : 'unavailable',
            source: 'lldpd_cdp_receive',
            target_count: cdpNeighborCount
        },
        netflow: { state: listenerState('netflow'), source: 'socket_listener', port: 2055 },
        ipfix: { state: listenerState('ipfix'), source: 'socket_listener', port: 4739 },
        sflow: { state: listenerState('sflow'), source: 'socket_listener', port: 6343 },
        dhcp_dns_observation: {
            state: tools.tshark || tools.tcpdump ? 'available' : 'unavailable',
            source: 'bounded_packet_capture'
        },
        active_probes: {
            state: tools.ping && tools.dig ? 'available' : 'partial',
            source: 'local_diagnostic_tools'
        },
        omada_api: {
            state: String(env.OMADA_CONTROLLER_URL || '').trim() ? 'configured' : 'unconfigured',
            source: 'collector_configuration'
        },
        endpoint_collector: { state: 'active', source: 'metro_nms_collector' }
    };
}

function buildSnapshotMetric(metricKey, metricLabel, value, unit, source, observedAt, target = '') {
    const numeric = Number(value);
    const available = Number.isFinite(numeric) && numeric >= 0;
    return {
        metric_key: metricKey,
        metric_label: metricLabel,
        target,
        unit,
        attempted_count: 1,
        successful_count: available ? 1 : 0,
        failed_count: available ? 0 : 1,
        min_value: available ? numeric : null,
        avg_value: available ? numeric : null,
        max_value: available ? numeric : null,
        latest_value: available ? numeric : null,
        first_observed_at: observedAt,
        last_observed_at: observedAt,
        source
    };
}

function buildDiagnosticSnapshotSession(snapshot, deterministic, sourceStatus) {
    const observedAt = snapshot.collected_at;
    const network = snapshot.network || {};
    const interfaces = Array.isArray(network.interfaces) ? network.interfaces : [];
    const vlans = network.observed_vlans || {};
    const lldp = network.lldp || {};
    const wireless = network.wireless || {};
    const snmp = network.network_device_snmp || {};
    const listenerCount = Object.values(network.listeners || {}).filter((item) => item?.listening).length;
    const activeServiceCount = Object.values(snapshot.services || {}).filter((service) => (
        service === 'active' || service?.active === 'active'
    )).length;
    const diskValues = (Array.isArray(snapshot.disks) ? snapshot.disks : [])
        .map((disk) => Number(disk.use_pct)).filter(Number.isFinite);
    const values = {
        memory_used_pct: snapshot.memory?.used_pct ?? null,
        load_average_1m: Array.isArray(snapshot.loadavg) ? snapshot.loadavg[0] : null,
        disk_max_used_pct: diskValues.length ? Math.max(...diskValues) : null,
        interface_count: interfaces.length,
        arp_neighbor_count: Number(network.neighbors?.total) || 0,
        observed_vlan_count: Array.isArray(vlans.vlan_ids) ? vlans.vlan_ids.length : 0,
        lldp_neighbor_count: Number(lldp.neighbor_count) || 0,
        wireless_ap_count: Number(wireless.access_point_count) || 0,
        snmp_target_up_count: Number(snmp.target_up_count) || 0,
        active_listener_count: listenerCount,
        active_service_count: activeServiceCount
    };
    const definitions = [
        ['memory_used_pct', '메모리 사용률', 'percent', 'os_memory'],
        ['load_average_1m', '1분 시스템 부하', 'count', 'os_loadavg'],
        ['disk_max_used_pct', '최대 디스크 사용률', 'percent', 'df_filesystem'],
        ['interface_count', '네트워크 인터페이스 수', 'count', 'ip_link'],
        ['arp_neighbor_count', 'ARP 이웃 수', 'count', 'ip_neigh'],
        ['observed_vlan_count', '관측 VLAN 수', 'count', 'tshark_vlan_observation'],
        ['lldp_neighbor_count', 'LLDP 이웃 수', 'count', 'lldpd'],
        ['wireless_ap_count', '주변 무선 AP 수', 'count', 'nmcli_wifi_scan'],
        ['snmp_target_up_count', 'SNMP 응답 장비 수', 'count', 'snmp_polling'],
        ['active_listener_count', '활성 수신 포트 수', 'count', 'ss_listener'],
        ['active_service_count', '활성 수집 서비스 수', 'count', 'systemd']
    ];
    const boundedSnapshot = {
        schema_version: 'collector-diagnostic-snapshot-v1',
        observed_at: observedAt,
        hostname: snapshot.hostname,
        primary_network: network.primary_network || null,
        default_gateway: network.default_gateway || null,
        vpn: network.vpn || null,
        interface_count: interfaces.length,
        interfaces: interfaces.slice(0, 16),
        neighbors: network.neighbors || null,
        observed_vlans: vlans,
        lldp,
        wireless: {
            available: Boolean(wireless.available),
            radios: Array.isArray(wireless.radios) ? wireless.radios.slice(0, 8) : [],
            access_point_count: Number(wireless.access_point_count) || 0,
            channel_counts: wireless.channel_counts || {}
        },
        network_device_snmp: {
            enabled: Boolean(snmp.enabled),
            target_count: Number(snmp.target_count) || 0,
            target_up_count: Number(snmp.target_up_count) || 0,
            target_down_count: Number(snmp.target_down_count) || 0,
            interface_error_count: Number(snmp.interface_error_count) || 0,
            interface_discard_count: Number(snmp.interface_discard_count) || 0
        },
        source_status: sourceStatus,
        deterministic
    };
    return {
        schema_version: 'collector-diagnostic-snapshot-session-v1',
        source: 'ubuntu_collector_diagnostic_snapshot',
        started_at: observedAt,
        ended_at: observedAt,
        requested_duration_seconds: 10,
        observed_duration_seconds: 0,
        interval_seconds: 10,
        rounds_attempted: 1,
        rounds_completed: 1,
        targets: {},
        metrics: definitions.map(([key, label, unit, source]) => (
            buildSnapshotMetric(key, label, values[key], unit, source, observedAt)
        )),
        raw_sample_retention: { retained_count: 1, total_count: 1, sampling_stride: 1 },
        raw_samples: [{ observed_at: observedAt, values, failed_metrics: [] }],
        diagnostic_snapshot: boundedSnapshot
    };
}

async function runLocalDiagnosticSnapshot(env, fieldProfile, sendImmediately = false) {
    const profile = normalizeFieldMeasurementProfile(fieldProfile);
    const snapshot = collectEdgeSnapshot(env);
    const deterministic = analyzeEdgeSnapshot(snapshot, env);
    const sourceStatus = buildCollectionSourceStatus(snapshot, env);
    const session = buildDiagnosticSnapshotSession(snapshot, deterministic, sourceStatus);
    const queued = buildQueuedFieldSnapshot(profile, session, {
        schema_version: 'collector-local-diagnostic-evidence-v1',
        snapshot,
        deterministic,
        source_status: sourceStatus
    });
    const filePath = persistQueuedFieldMeasurement(env, queued);
    let delivery = { state: 'pending', error: 'saved locally; central delivery not requested' };
    if (sendImmediately) {
        const result = await flushQueuedFieldMeasurements(env);
        const itemResult = result.items.find((item) => item.client_session_id === queued.client_session_id) || null;
        delivery = itemResult?.state === 'sent'
            ? { state: 'sent', receipt: itemResult.receipt || null }
            : { state: 'pending', error: itemResult?.error || 'central NMS delivery pending' };
    }
    return {
        ok: true,
        client_session_id: queued.client_session_id,
        field_profile: profile,
        saved_path: filePath,
        observed_at: snapshot.collected_at,
        severity: deterministic.severity,
        finding_count: deterministic.finding_count,
        source_status: sourceStatus,
        metric_count: session.metrics.length,
        delivery
    };
}

async function runDiagnosticWorkerOnce(env) {
    const report = inspectCollectorEnv(env);
    if (!report.ready) {
        throw new Error(report.errors.join('; '));
    }

    if (!report.features.remoteDiagnosticsEnabled) {
        console.log('[nms-collector] remote diagnostics disabled');
        return 0;
    }

    const limit = Math.min(5, Math.max(1, parsePositiveInteger(env.DIAGNOSTIC_COMMAND_LIMIT, 1)));
    const commands = await claimDiagnosticCommands(env, report, limit);
    for (const command of commands) {
        const result = await executeDiagnosticCommand(command, env);
        await postDiagnosticCommandResult(env, report, command.id, result);
        console.log(`[nms-collector] diagnostic command ${command.id} ${result.status}`);
    }

    return commands.length;
}

async function runDiagnosticWorker(env) {
    const pollSeconds = Math.min(300, Math.max(5, parsePositiveInteger(env.DIAGNOSTIC_POLL_INTERVAL_SECONDS, 15)));
    console.log(`[nms-collector] diagnostic-worker started poll=${pollSeconds}s`);

    while (true) {
        try {
            await runDiagnosticWorkerOnce(env);
        } catch (error) {
            console.error(`[nms-collector] diagnostic-worker error: ${error.message}`);
        }

        await sleep(pollSeconds * 1000);
    }
}

function parseDfOutput(output) {
    const rows = [];
    for (const line of String(output || '').split(/\r?\n/).slice(1)) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 6) {
            continue;
        }

        const usePct = Number(String(parts[4] || '').replace('%', ''));
        rows.push({
            filesystem: parts[0],
            size_kb: Number(parts[1]) || 0,
            used_kb: Number(parts[2]) || 0,
            available_kb: Number(parts[3]) || 0,
            use_pct: Number.isFinite(usePct) ? usePct : null,
            mount: parts.slice(5).join(' ')
        });
    }
    return rows;
}

function parseIpNeighborSummary(output) {
    const lines = String(output || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const stateCounts = {};
    const entries = [];
    for (const line of lines) {
        const match = line.match(/\b(REACHABLE|STALE|DELAY|PROBE|FAILED|INCOMPLETE|PERMANENT|NOARP)\b/);
        const state = match ? match[1].toLowerCase() : 'unknown';
        stateCounts[state] = (stateCounts[state] || 0) + 1;
        const parts = line.split(/\s+/);
        const deviceIndex = parts.indexOf('dev');
        const macIndex = parts.indexOf('lladdr');
        const ipAddress = parts[0] || null;
        entries.push({
            ip_address: ipAddress,
            address_family: ipAddress?.includes(':') ? 'ipv6' : 'ipv4',
            interface_name: deviceIndex >= 0 ? parts[deviceIndex + 1] || null : null,
            mac_address: macIndex >= 0 ? String(parts[macIndex + 1] || '').toLowerCase() || null : null,
            state,
            is_router: parts.includes('router'),
            raw_flags: parts.filter((part) => ['router', 'extern_learn', 'managed', 'use'].includes(part))
        });
    }
    return {
        total: lines.length,
        state_counts: stateCounts,
        entries: entries.slice(0, 256),
        sample: lines.slice(0, 20)
    };
}

function collectToolAvailability(execFn = execFileSync) {
    const tools = ['ping', 'traceroute', 'dig', 'tcpdump', 'ip', 'curl', 'snmpget', 'snmpwalk', 'node', 'rsyslogd', 'lldpcli', 'iw', 'nmcli', 'iperf3', 'tshark'];
    const result = {};
    for (const tool of tools) {
        const check = safeExecOutput('which', [tool], execFn);
        result[tool] = check.ok ? String(check.stdout || '').trim() || true : false;
    }
    return result;
}

function parseJsonCommand(command, args, execFn = execFileSync) {
    const result = safeExecOutput(command, args, execFn);
    if (!result.ok || !String(result.stdout || '').trim()) {
        return null;
    }
    try {
        return JSON.parse(result.stdout);
    } catch (_error) {
        return null;
    }
}

function collectInterfaceSnapshot(execFn = execFileSync) {
    const links = parseJsonCommand('ip', ['-j', '-d', 'link', 'show'], execFn) || [];
    const addresses = parseJsonCommand('ip', ['-j', 'address', 'show'], execFn) || [];
    const addressesByIndex = new Map(addresses.map((item) => [item.ifindex, item]));
    return links.filter((link) => link.ifname !== 'lo').map((link) => {
        const address = addressesByIndex.get(link.ifindex) || {};
        const linkInfo = link.linkinfo || {};
        return {
            name: link.ifname,
            state: link.operstate || 'UNKNOWN',
            mac: link.address || null,
            mtu: link.mtu || null,
            kind: linkInfo.info_kind || link.link_type || null,
            vlan_id: linkInfo.info_kind === 'vlan' ? linkInfo.info_data?.id ?? null : null,
            parent: link.link || null,
            addresses: (address.addr_info || []).map((item) => ({
                family: item.family,
                address: item.local,
                prefixlen: item.prefixlen,
                scope: item.scope
            })).slice(0, 12)
        };
    }).slice(0, 32);
}

function collectLldpSnapshot(execFn = execFileSync) {
    const parsed = parseJsonCommand('lldpcli', ['-f', 'json', 'show', 'neighbors', 'details'], execFn);
    const interfaces = parsed?.lldp?.interface;
    if (!interfaces || typeof interfaces !== 'object') {
        return { available: Boolean(parsed), neighbor_count: 0, neighbors: [] };
    }
    const neighbors = Object.entries(interfaces).flatMap(([interfaceName, value]) => {
        const entries = Array.isArray(value) ? value : [value];
        return entries.map((entry) => {
            const chassisContainer = entry?.chassis && typeof entry.chassis === 'object' ? entry.chassis : {};
            const namedChassis = Object.entries(chassisContainer)
                .find(([, candidate]) => candidate && typeof candidate === 'object' && !Array.isArray(candidate));
            const chassisName = entry?.chassis?.name || namedChassis?.[0] || null;
            const chassis = namedChassis?.[1] || chassisContainer;
            const protocol = String(entry?.via || entry?.protocol || 'LLDP').trim().toUpperCase();
            return {
                protocol,
                local_interface: interfaceName,
                chassis_name: chassisName,
                chassis_id: chassis?.id?.value || chassis?.id || null,
                chassis_description: chassis?.descr || null,
                port_id: entry?.port?.id?.value || entry?.port?.id || null,
                port_description: entry?.port?.descr || null,
                management_ip: chassis?.['mgmt-ip'] || null,
                vlan: entry?.vlan || null,
                ttl: entry?.port?.ttl || entry?.ttl || null,
                age: entry?.age || null
            };
        });
    }).slice(0, 32);
    const protocolCounts = {};
    for (const neighbor of neighbors) {
        protocolCounts[neighbor.protocol] = (protocolCounts[neighbor.protocol] || 0) + 1;
    }
    return { available: true, neighbor_count: neighbors.length, protocol_counts: protocolCounts, neighbors };
}

function parseNmcliWifi(output) {
    function splitEscapedFields(line) {
        const fields = [];
        let current = '';
        let escaped = false;
        for (const character of line) {
            if (escaped) {
                current += character;
                escaped = false;
            } else if (character === '\\') {
                escaped = true;
            } else if (character === ':') {
                fields.push(current);
                current = '';
            } else {
                current += character;
            }
        }
        fields.push(current);
        return fields;
    }
    return String(output || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
        const fields = splitEscapedFields(line);
        return {
            interface: fields[0] || null,
            active: fields[1] === 'yes',
            ssid: fields[2] || '(hidden)',
            bssid: fields[3] || null,
            channel: Number(fields[4]) || null,
            frequency_mhz: Number(fields[5]) || null,
            signal_pct: Number(fields[6]) || 0,
            security: fields[7] || 'open'
        };
    }).sort((a, b) => b.signal_pct - a.signal_pct).slice(0, 64);
}

function collectWirelessSnapshot(execFn = execFileSync) {
    const devices = safeExecOutput('iw', ['dev'], execFn);
    if (!devices.ok || !String(devices.stdout || '').trim()) {
        return { available: false, radios: [], access_point_count: 0, access_points: [] };
    }
    const radios = Array.from(String(devices.stdout).matchAll(/Interface\s+(\S+)/g), (match) => match[1]);
    const scan = safeExecOutput('nmcli', [
        '-t',
        '-f', 'DEVICE,IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY',
        'device', 'wifi', 'list', '--rescan', 'yes'
    ], execFn);
    const accessPoints = scan.ok ? parseNmcliWifi(scan.stdout) : [];
    const channelCounts = {};
    for (const accessPoint of accessPoints) {
        if (accessPoint.channel) {
            channelCounts[accessPoint.channel] = (channelCounts[accessPoint.channel] || 0) + 1;
        }
    }
    return { available: true, radios, access_point_count: accessPoints.length, channel_counts: channelCounts, access_points: accessPoints };
}

function collectListenerSnapshot(execFn = execFileSync) {
    const listeners = safeExecOutput('ss', ['-H', '-lntu'], execFn);
    const text = String(listeners.stdout || '');
    const services = [
        { name: 'syslog_udp', protocol: 'udp', port: 5514 },
        { name: 'syslog_tcp', protocol: 'tcp', port: 5514 },
        { name: 'snmp_trap', protocol: 'udp', port: 1162 },
        { name: 'snmp_agent', protocol: 'udp', port: 161 },
        { name: 'iperf3', protocol: 'tcp', port: 5201 },
        { name: 'netflow', protocol: 'udp', port: 2055 },
        { name: 'ipfix', protocol: 'udp', port: 4739 },
        { name: 'sflow', protocol: 'udp', port: 6343 }
    ];
    return Object.fromEntries(services.map((service) => {
        const pattern = new RegExp(`^${service.protocol}\\s+.*:${service.port}\\b`, 'm');
        return [service.name, { ...service, listening: pattern.test(text) }];
    }));
}

function collectObservedVlans(env, execFn = execFileSync) {
    if (!parseBoolean(env.VLAN_PASSIVE_SCAN_ENABLED, true)) {
        return { enabled: false, interface: null, frame_count: 0, vlan_ids: [] };
    }
    const interfaceName = String(env.VLAN_PASSIVE_SCAN_INTERFACE || env.DIAGNOSTIC_CAPTURE_INTERFACE || 'any').trim() || 'any';
    const durationSeconds = Math.min(5, Math.max(1, parsePositiveInteger(env.VLAN_PASSIVE_SCAN_SECONDS, 2)));
    const scan = safeExecOutput('timeout', [
        String(durationSeconds + 2),
        'tshark',
        '-n',
        '-i', interfaceName,
        '-a', `duration:${durationSeconds}`,
        '-Y', 'vlan',
        '-T', 'fields',
        '-e', 'vlan.id'
    ], execFn);
    const ids = String(scan.stdout || '').split(/\r?\n/)
        .flatMap((line) => line.split(','))
        .map((value) => Number(value.trim()))
        .filter((value) => Number.isInteger(value) && value >= 1 && value <= 4094);
    const counts = {};
    for (const id of ids) {
        counts[id] = (counts[id] || 0) + 1;
    }
    return {
        enabled: true,
        interface: interfaceName,
        duration_seconds: durationSeconds,
        frame_count: ids.length,
        vlan_ids: Object.keys(counts).map(Number).sort((a, b) => a - b),
        frame_counts: counts,
        error: scan.ok || scan.status === 124 ? null : truncateText(scan.stderr || 'VLAN passive scan failed', 500)
    };
}

function parseSnmpTargets(env) {
    const raw = String(env.NETWORK_DEVICE_SNMP_TARGETS || '').trim();
    if (!raw) {
        return [];
    }
    try {
        const parsed = JSON.parse(raw);
        return (Array.isArray(parsed) ? parsed : []).slice(0, 32).map((target, index) => ({
            index: index + 1,
            name: String(target.name || target.host || `snmp-target-${index + 1}`),
            role: String(target.role || 'network_device'),
            host: String(target.host || '').trim(),
            port: Math.min(65535, Math.max(1, Number(target.port) || Number(env.NETWORK_DEVICE_SNMP_DEFAULT_PORT) || 161)),
            version: String(target.version || env.NETWORK_DEVICE_SNMP_DEFAULT_VERSION || '2c'),
            timeout_seconds: Math.min(10, Math.max(1, Number(target.timeout_seconds) || Number(env.NETWORK_DEVICE_SNMP_TIMEOUT_SECONDS) || 2)),
            retries: Math.min(3, Math.max(0, Number(target.retries) || Number(env.NETWORK_DEVICE_SNMP_RETRIES) || 1)),
            community: String(target.community || env.NETWORK_DEVICE_SNMP_COMMUNITY || '').trim()
        })).filter((target) => target.host);
    } catch (_error) {
        return [];
    }
}

function parseSnmpScalar(output) {
    const text = String(output || '').trim();
    const separator = text.indexOf('=');
    if (separator < 0) {
        return text || null;
    }
    return text.slice(separator + 1).trim().replace(/^[A-Z0-9-]+:\s*/i, '').replace(/^"(.*)"$/, '$1') || null;
}

function parseSnmpTable(output) {
    return String(output || '').split(/\r?\n/).map((line) => {
        const match = line.match(/\.([0-9]+)\s*=\s*[^:]+:\s*(.*)$/);
        return match ? { index: Number(match[1]), value: match[2].replace(/^"(.*)"$/, '$1') } : null;
    }).filter(Boolean);
}

function parseSnmpOidTable(output, baseOid) {
    const normalizedBase = String(baseOid || '').replace(/^\./, '');
    return String(output || '').split(/\r?\n/).map((line) => {
        const match = line.match(/^\.?([0-9.]+)\s*=\s*([^:]+):\s*(.*)$/);
        if (!match) return null;
        const oid = match[1];
        if (oid !== normalizedBase && !oid.startsWith(`${normalizedBase}.`)) return null;
        const suffix = oid === normalizedBase ? [] : oid.slice(normalizedBase.length + 1).split('.').map(Number);
        return { oid, suffix, type: match[2].trim(), value: match[3].trim().replace(/^"(.*)"$/, '$1') };
    }).filter(Boolean);
}

function parseSnmpNumber(value) {
    const match = String(value || '').match(/-?\d+/);
    return match ? Number(match[0]) : null;
}

function parseHexBytes(value) {
    const normalized = String(value || '').replace(/^Hex-STRING:\s*/i, '').trim();
    const matches = normalized.match(/[0-9a-fA-F]{2}/g) || [];
    return matches.map((item) => Number.parseInt(item, 16));
}

function decodePortBitmap(value) {
    const ports = [];
    parseHexBytes(value).forEach((byte, byteIndex) => {
        for (let bit = 0; bit < 8; bit += 1) {
            if (byte & (1 << (7 - bit))) ports.push((byteIndex * 8) + bit + 1);
        }
    });
    return ports;
}

function macFromOidSuffix(suffix) {
    const bytes = (suffix || []).slice(-6);
    if (bytes.length !== 6 || bytes.some((item) => item < 0 || item > 255)) return null;
    return bytes.map((item) => item.toString(16).padStart(2, '0')).join(':');
}

function collectSnmpWalk(target, oid, execFn) {
    const result = runSnmpCommand(target, oid, { walk: true }, execFn);
    return result.ok ? parseSnmpOidTable(result.stdout, oid) : [];
}

function buildSwitchTopology(target, execFn = execFileSync) {
    const oids = {
        basePortIfIndex: '1.3.6.1.2.1.17.1.4.1.2',
        stpPortState: '1.3.6.1.2.1.17.2.15.1.3',
        vlanName: '1.3.6.1.2.1.17.7.1.4.3.1.1',
        vlanEgress: '1.3.6.1.2.1.17.7.1.4.2.1.4',
        vlanUntagged: '1.3.6.1.2.1.17.7.1.4.2.1.5',
        pvid: '1.3.6.1.2.1.17.7.1.4.5.1.1',
        qFdbPort: '1.3.6.1.2.1.17.7.1.2.2.1.2',
        bridgeFdbPort: '1.3.6.1.2.1.17.4.3.1.2',
        lldpChassis: '1.0.8802.1.1.2.1.4.1.1.5',
        lldpPortId: '1.0.8802.1.1.2.1.4.1.1.7',
        lldpPortDescr: '1.0.8802.1.1.2.1.4.1.1.8',
        lldpSysName: '1.0.8802.1.1.2.1.4.1.1.9',
        poeAdmin: '1.3.6.1.2.1.105.1.1.1.3',
        poeDetection: '1.3.6.1.2.1.105.1.1.1.6'
    };
    const tables = Object.fromEntries(Object.entries(oids).map(([key, oid]) => [key, collectSnmpWalk(target, oid, execFn)]));
    const basePortToIfIndex = Object.fromEntries(tables.basePortIfIndex.map((row) => [row.suffix.at(-1), parseSnmpNumber(row.value)]));
    const pvidByPort = Object.fromEntries(tables.pvid.map((row) => [row.suffix.at(-1), parseSnmpNumber(row.value)]));
    const stpByPort = Object.fromEntries(tables.stpPortState.map((row) => [row.suffix.at(-1), parseSnmpNumber(row.value)]));
    const vlanNames = Object.fromEntries(tables.vlanName.map((row) => [row.suffix.at(-1), row.value]));
    const egressByVlan = {};
    const untaggedByVlan = {};
    for (const row of tables.vlanEgress) egressByVlan[row.suffix.at(-1)] = decodePortBitmap(row.value);
    for (const row of tables.vlanUntagged) untaggedByVlan[row.suffix.at(-1)] = decodePortBitmap(row.value);
    const vlanIds = [...new Set([...Object.keys(vlanNames), ...Object.keys(egressByVlan), ...Object.values(pvidByPort)].map(Number).filter(Boolean))].sort((a, b) => a - b);
    const vlans = vlanIds.map((vlanId) => {
        const egressPorts = egressByVlan[vlanId] || [];
        const untaggedPorts = untaggedByVlan[vlanId] || [];
        return {
            vlan_id: vlanId,
            name: vlanNames[vlanId] || null,
            tagged_ports: egressPorts.filter((port) => !untaggedPorts.includes(port)),
            untagged_ports: untaggedPorts,
            member_ports: egressPorts
        };
    });
    const fdb = [...tables.qFdbPort.map((row) => ({ vlan_id: row.suffix.at(-7) || null, mac: macFromOidSuffix(row.suffix), base_port: parseSnmpNumber(row.value) })),
        ...tables.bridgeFdbPort.map((row) => ({ vlan_id: null, mac: macFromOidSuffix(row.suffix), base_port: parseSnmpNumber(row.value) }))]
        .filter((row) => row.mac && row.base_port).slice(0, 2048)
        .map((row) => ({ ...row, if_index: basePortToIfIndex[row.base_port] || null }));
    const lldpRows = new Map();
    for (const [field, source] of [['chassis_id', tables.lldpChassis], ['port_id', tables.lldpPortId], ['port_description', tables.lldpPortDescr], ['system_name', tables.lldpSysName]]) {
        for (const row of source) {
            const key = row.suffix.slice(-2).join('.');
            const current = lldpRows.get(key) || { local_port: row.suffix.at(-2), remote_index: row.suffix.at(-1) };
            current[field] = row.type.toLowerCase().includes('hex') ? parseHexBytes(row.value).map((item) => item.toString(16).padStart(2, '0')).join(':') : row.value;
            lldpRows.set(key, current);
        }
    }
    const poeByPort = {};
    for (const row of tables.poeAdmin) {
        const port = row.suffix.at(-1);
        poeByPort[port] = { base_port: port, admin_enabled: parseSnmpNumber(row.value) === 1 };
    }
    for (const row of tables.poeDetection) {
        const port = row.suffix.at(-1);
        poeByPort[port] = { ...(poeByPort[port] || { base_port: port }), detection_status: parseSnmpNumber(row.value) };
    }
    return {
        supported: Object.values(tables).some((rows) => rows.length > 0),
        base_port_to_if_index: basePortToIfIndex,
        pvid_by_port: pvidByPort,
        stp_state_by_port: stpByPort,
        vlans,
        fdb,
        lldp_neighbors: Array.from(lldpRows.values()).slice(0, 256),
        poe_ports: Object.values(poeByPort),
        vlan_count: vlans.length,
        fdb_count: fdb.length,
        lldp_neighbor_count: lldpRows.size,
        poe_port_count: Object.keys(poeByPort).length
    };
}

function runSnmpCommand(target, oid, { walk = false } = {}, execFn = execFileSync) {
    const args = [
        '-On',
        '-v', target.version === '1' ? '1' : '2c',
        '-c', target.community,
        '-t', String(target.timeout_seconds || 2),
        '-r', String(target.retries ?? 1),
        `${target.host}:${target.port}`,
        oid
    ];
    return safeExecOutput(walk ? 'snmpwalk' : 'snmpget', args, execFn);
}

function collectSnmpTarget(target, execFn = execFileSync) {
    const startedAt = Date.now();
    const empty = {
        index: target.index,
        name: target.name,
        role: target.role,
        host: target.host,
        port: target.port,
        ok: false,
        latency_ms: null,
        interfaces: [],
        interface_count: 0,
        interface_up_count: 0,
        interface_down_count: 0,
        interface_error_count: 0,
        interface_discard_count: 0
    };
    if (!target.community) {
        return { ...empty, error: 'SNMP community is not configured' };
    }
    const sysName = runSnmpCommand(target, '1.3.6.1.2.1.1.5.0', {}, execFn);
    if (!sysName.ok) {
        return { ...empty, error: truncateText(sysName.stderr || 'SNMP request failed', 500) };
    }
    const scalarOids = {
        sys_descr: '1.3.6.1.2.1.1.1.0',
        sys_object_id: '1.3.6.1.2.1.1.2.0',
        sys_uptime_ticks: '1.3.6.1.2.1.1.3.0'
    };
    const scalars = {};
    for (const [key, oid] of Object.entries(scalarOids)) {
        const result = runSnmpCommand(target, oid, {}, execFn);
        scalars[key] = result.ok ? parseSnmpScalar(result.stdout) : null;
    }
    const tableOids = {
        name: '1.3.6.1.2.1.31.1.1.1.1',
        descr: '1.3.6.1.2.1.2.2.1.2',
        speed_bps: '1.3.6.1.2.1.2.2.1.5',
        admin_status: '1.3.6.1.2.1.2.2.1.7',
        oper_status: '1.3.6.1.2.1.2.2.1.8',
        in_octets: '1.3.6.1.2.1.2.2.1.10',
        in_errors: '1.3.6.1.2.1.2.2.1.14',
        out_octets: '1.3.6.1.2.1.2.2.1.16',
        out_errors: '1.3.6.1.2.1.2.2.1.20',
        in_discards: '1.3.6.1.2.1.2.2.1.13',
        out_discards: '1.3.6.1.2.1.2.2.1.19'
    };
    const rows = new Map();
    for (const [key, oid] of Object.entries(tableOids)) {
        const result = runSnmpCommand(target, oid, { walk: true }, execFn);
        if (!result.ok) {
            continue;
        }
        for (const item of parseSnmpTable(result.stdout)) {
            const row = rows.get(item.index) || { index: item.index };
            row[key] = ['speed_bps', 'admin_status', 'oper_status', 'in_octets', 'out_octets', 'in_errors', 'out_errors', 'in_discards', 'out_discards'].includes(key)
                ? Number(String(item.value).match(/\d+/)?.[0] || 0)
                : item.value;
            rows.set(item.index, row);
        }
    }
    const topology = buildSwitchTopology(target, execFn);
    const ifIndexToBasePort = Object.fromEntries(Object.entries(topology.base_port_to_if_index || {}).map(([port, ifIndex]) => [ifIndex, Number(port)]));
    const interfaces = Array.from(rows.values()).slice(0, 128).map((row) => {
        const basePort = ifIndexToBasePort[row.index] || null;
        return {
            ...row,
            base_port: basePort,
            pvid: basePort ? topology.pvid_by_port?.[basePort] ?? null : null,
            stp_state: basePort ? topology.stp_state_by_port?.[basePort] ?? null : null,
            poe: basePort ? topology.poe_ports?.find((item) => item.base_port === basePort) || null : null
        };
    });
    return {
        ...empty,
        ok: true,
        latency_ms: Date.now() - startedAt,
        sys_name: parseSnmpScalar(sysName.stdout),
        sys_descr: scalars.sys_descr,
        sys_object_id: scalars.sys_object_id,
        sys_uptime_ticks: Number(String(scalars.sys_uptime_ticks || '').match(/\d+/)?.[0] || 0) || null,
        interfaces,
        interface_count: interfaces.length,
        interface_up_count: interfaces.filter((item) => item.oper_status === 1).length,
        interface_down_count: interfaces.filter((item) => item.oper_status !== 1).length,
        interface_error_count: interfaces.filter((item) => (item.in_errors || 0) + (item.out_errors || 0) > 0).length,
        interface_discard_count: interfaces.filter((item) => (item.in_discards || 0) + (item.out_discards || 0) > 0).length,
        switch_topology: topology,
        error: null
    };
}

function collectNetworkDeviceSnmp(env, execFn = execFileSync) {
    const enabled = parseBoolean(env.NETWORK_DEVICE_SNMP_ENABLED, false);
    const configured = parseSnmpTargets(env);
    if (!enabled) {
        return { enabled: false, target_count: configured.length, targets: [] };
    }
    const targets = configured.map((target) => collectSnmpTarget(target, execFn));
    return {
        enabled: true,
        target_count: targets.length,
        target_up_count: targets.filter((target) => target.ok).length,
        target_down_count: targets.filter((target) => !target.ok).length,
        interface_count: targets.reduce((sum, target) => sum + target.interface_count, 0),
        interface_up_count: targets.reduce((sum, target) => sum + target.interface_up_count, 0),
        interface_down_count: targets.reduce((sum, target) => sum + target.interface_down_count, 0),
        interface_error_count: targets.reduce((sum, target) => sum + target.interface_error_count, 0),
        interface_discard_count: targets.reduce((sum, target) => sum + target.interface_discard_count, 0),
        targets
    };
}

function collectEdgeSnapshot(env, execFn = execFileSync) {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const routeOutput = safeExecOutput('ip', ['route', 'show'], execFn);
    const addressOutput = safeExecOutput('ip', ['-brief', 'address'], execFn);
    const neighborOutput = safeExecOutput('ip', ['neigh', 'show'], execFn);
    const diskOutput = safeExecOutput('df', ['-P', '-k'], execFn);
    const report = inspectCollectorEnv(env);
    const primaryNetwork = collectPrimaryNetwork(execFn);
    const wireGuardStatus = collectWireGuardStatus(env, execFn);

    return {
        collected_at: new Date().toISOString(),
        version: EDGE_COLLECTOR_VERSION,
        hostname: os.hostname(),
        platform: os.platform(),
        release: os.release(),
        uptime_seconds: Math.round(os.uptime()),
        cpu_count: os.cpus().length,
        loadavg: os.loadavg(),
        memory: {
            total_bytes: totalMem,
            free_bytes: freeMem,
            used_pct: totalMem > 0 ? Number((((totalMem - freeMem) / totalMem) * 100).toFixed(2)) : null
        },
        network: {
            default_gateway: primaryNetwork.default_gateway,
            private_ip: primaryNetwork.address || detectPrivateIp(execFn),
            primary_network: primaryNetwork,
            vpn: wireGuardStatus,
            routes_excerpt: truncateText(routeOutput.stdout, 3000),
            addresses_excerpt: truncateText(addressOutput.stdout, 3000),
            neighbors: parseIpNeighborSummary(neighborOutput.stdout),
            interfaces: collectInterfaceSnapshot(execFn),
            observed_vlans: collectObservedVlans(env, execFn),
            lldp: collectLldpSnapshot(execFn),
            wireless: collectWirelessSnapshot(execFn),
            listeners: collectListenerSnapshot(execFn),
            network_device_snmp: collectNetworkDeviceSnmp(env, execFn)
        },
        disks: parseDfOutput(diskOutput.stdout),
        tools: collectToolAvailability(execFn),
        services: inspectLocalServices(report, execFn),
        features: report.features,
        tls_mode: report.tls.insecureTls ? 'insecure' : report.tls.caCertPath ? 'custom-ca' : 'system-ca'
    };
}

function analyzeEdgeSnapshot(snapshot, env = {}) {
    const findings = [];
    let severity = 'ok';
    const diskWarnPct = Math.min(100, Math.max(1, parsePositiveInteger(env.EDGE_DISK_WARN_PCT || '85', 85)));
    const diskDangerPct = Math.min(100, Math.max(diskWarnPct, parsePositiveInteger(env.EDGE_DISK_DANGER_PCT || '95', 95)));
    const memWarnPct = Math.min(100, Math.max(1, parsePositiveInteger(env.EDGE_MEMORY_WARN_PCT || '85', 85)));
    const memDangerPct = Math.min(100, Math.max(memWarnPct, parsePositiveInteger(env.EDGE_MEMORY_DANGER_PCT || '95', 95)));
    const cpuCount = Math.max(1, Number(snapshot.cpu_count) || 1);
    const loadWarn = Number(env.EDGE_LOAD_WARN_PER_CPU || '2') || 2;

    function addFinding(level, title, detail, extra = {}) {
        severity = maxSeverity(severity, level);
        findings.push({
            severity: level,
            title,
            detail,
            ...extra
        });
    }

    for (const disk of Array.isArray(snapshot.disks) ? snapshot.disks : []) {
        if (!Number.isFinite(disk.use_pct)) {
            continue;
        }
        if (disk.use_pct >= diskDangerPct) {
            addFinding('danger', 'disk usage critical', `${disk.mount} ${disk.use_pct}% used`, { mount: disk.mount, use_pct: disk.use_pct });
        } else if (disk.use_pct >= diskWarnPct) {
            addFinding('warn', 'disk usage warning', `${disk.mount} ${disk.use_pct}% used`, { mount: disk.mount, use_pct: disk.use_pct });
        }
    }

    const memoryUsedPct = snapshot.memory?.used_pct;
    if (Number.isFinite(memoryUsedPct)) {
        if (memoryUsedPct >= memDangerPct) {
            addFinding('danger', 'memory usage critical', `memory ${memoryUsedPct}% used`, { used_pct: memoryUsedPct });
        } else if (memoryUsedPct >= memWarnPct) {
            addFinding('warn', 'memory usage warning', `memory ${memoryUsedPct}% used`, { used_pct: memoryUsedPct });
        }
    }

    const load1 = Array.isArray(snapshot.loadavg) ? Number(snapshot.loadavg[0]) : 0;
    if (Number.isFinite(load1) && load1 > cpuCount * loadWarn) {
        addFinding('warn', 'load average high', `1m load ${load1.toFixed(2)} on ${cpuCount} CPU cores`, { load1, cpu_count: cpuCount });
    }

    if (!snapshot.network?.default_gateway) {
        addFinding('warn', 'default gateway missing', 'default gateway could not be detected');
    }

    const vpn = snapshot.network?.vpn || {};
    if (vpn.configured && ['interface_missing', 'service_inactive', 'no_handshake', 'stale'].includes(vpn.state)) {
        addFinding('warn', 'remote VPN unavailable', `state=${vpn.state}`, {
            vpn_state: vpn.state,
            vpn_interface: vpn.interface || null,
            vpn_handshake_age_seconds: vpn.handshake_age_seconds ?? null
        });
    }

    const failedNeighbors = Number(snapshot.network?.neighbors?.state_counts?.failed || 0);
    const incompleteNeighbors = Number(snapshot.network?.neighbors?.state_counts?.incomplete || 0);
    if (failedNeighbors + incompleteNeighbors > 0) {
        addFinding('warn', 'arp neighbor issues', `failed=${failedNeighbors}, incomplete=${incompleteNeighbors}`, {
            failed_neighbors: failedNeighbors,
            incomplete_neighbors: incompleteNeighbors
        });
    }

    const requiredTools = ['ping', 'traceroute', 'dig', 'tcpdump', 'ip', 'snmpget'];
    const missingTools = requiredTools.filter((tool) => !snapshot.tools?.[tool]);
    if (missingTools.length > 0) {
        addFinding('info', 'diagnostic tools missing', missingTools.join(', '), { missing_tools: missingTools });
    }

    const summary = findings.length > 0
        ? findings.slice(0, 4).map((finding) => `${finding.severity}:${finding.title}`).join(', ')
        : 'edge collector baseline is healthy';

    return {
        severity,
        summary,
        finding_count: findings.length,
        findings
    };
}

function buildEdgeAiPrompt(snapshot, deterministicAnalysis) {
    return [
        '너는 고객사 내부 NMS 수집서버의 경량 보조 분석기다.',
        '관측값에 없는 내용은 추측하지 말고, 장애 가능성과 현장 확인 항목을 짧게 정리해라.',
        '응답은 한국어로 작성하고 observed / 판단 / 다음조치 3개 항목으로 나눠라.',
        '',
        `deterministic=${JSON.stringify(deterministicAnalysis)}`,
        `snapshot=${JSON.stringify({
            collected_at: snapshot.collected_at,
            hostname: snapshot.hostname,
            uptime_seconds: snapshot.uptime_seconds,
            loadavg: snapshot.loadavg,
            memory: snapshot.memory,
            network: {
                default_gateway: snapshot.network?.default_gateway,
                private_ip: snapshot.network?.private_ip,
                vpn: snapshot.network?.vpn,
                neighbors: snapshot.network?.neighbors
            },
            disks: snapshot.disks,
            services: snapshot.services,
            tools: snapshot.tools
        })}`
    ].join('\n');
}

async function requestEdgeAiSummary(env, snapshot, deterministicAnalysis) {
    const baseUrl = normalizeBaseUrl(env.EDGE_AI_BASE_URL);
    if (!parseBoolean(env.EDGE_AI_ENABLED, false) || !baseUrl) {
        return null;
    }

    const model = String(env.EDGE_AI_MODEL || 'metro-report:latest').trim();
    const apiKey = String(env.EDGE_AI_API_KEY || '').trim();
    const targetUrl = `${baseUrl.replace(/\/v1\/?$/, '')}/v1/chat/completions`;
    const payload = {
        model,
        messages: [
            {
                role: 'system',
                content: 'You are a concise Korean NMS edge diagnostics assistant.'
            },
            {
                role: 'user',
                content: buildEdgeAiPrompt(snapshot, deterministicAnalysis)
            }
        ],
        temperature: 0.2,
        max_tokens: Math.min(1200, Math.max(128, parsePositiveInteger(env.EDGE_AI_MAX_TOKENS || '500', 500)))
    };
    const headers = {
        'Content-Type': 'application/json'
    };
    if (apiKey) {
        headers.Authorization = `Bearer ${apiKey}`;
    }

    const {
        transport,
        requestOptions,
        requestBody
    } = createJsonPostRequestOptions(targetUrl, headers, payload, env);
    requestOptions.timeout = Math.min(120000, Math.max(5000, parsePositiveInteger(env.EDGE_AI_TIMEOUT_MS || '30000', 30000)));

    return new Promise((resolve, reject) => {
        const request = transport.request(requestOptions, (response) => {
            let responseText = '';
            response.setEncoding('utf8');
            response.on('data', (chunk) => {
                responseText += chunk;
            });
            response.on('end', () => {
                if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
                    reject(new Error(`edge AI failed status=${response.statusCode || 'unknown'} body=${responseText.slice(0, 500)}`));
                    return;
                }
                try {
                    const parsed = JSON.parse(responseText);
                    resolve({
                        provider: 'openai-compatible',
                        model,
                        content: truncateText(parsed.choices?.[0]?.message?.content || '', 4000)
                    });
                } catch (error) {
                    reject(new Error(`edge AI returned invalid JSON: ${error.message}`));
                }
            });
        });

        request.setTimeout(requestOptions.timeout, () => {
            request.destroy(new Error(`edge AI timeout=${requestOptions.timeout}ms`));
        });
        request.on('error', reject);
        request.write(requestBody);
        request.end();
    });
}

async function buildEdgeAnalysis(env, execFn = execFileSync) {
    const snapshot = collectEdgeSnapshot(env, execFn);
    const deterministic = analyzeEdgeSnapshot(snapshot, env);
    let ai = null;
    let aiError = null;

    try {
        ai = await requestEdgeAiSummary(env, snapshot, deterministic);
    } catch (error) {
        aiError = error.message;
    }

    return {
        collected_at: snapshot.collected_at,
        version: EDGE_COLLECTOR_VERSION,
        deterministic,
        ai,
        ai_error: aiError,
        snapshot
    };
}

async function postCollectorHeartbeat(env, report, payload, failurePrefix = 'collector heartbeat failed') {
    await withNmsFallback(env, (baseUrl) => ensureSuccessfulJsonPost(
        `${baseUrl}/api/collectors/${report.collectorId}/heartbeat`,
        { 'Content-Type': 'application/json', 'X-Collector-Token': String(env.COLLECTOR_TOKEN).trim() },
        payload, failurePrefix, env
    ));
}

async function pollAndPostPulseLocalStatus(env, report) {
    if (!parseBoolean(env.PULSE_LOCAL_POLL_ENABLED, false)) {
        return null;
    }

    const observedAt = new Date().toISOString();
    const statusPayload = await fetchPulseLocalStatus(env);
    const payload = buildPulseLocalStatusPayload(statusPayload, env, report, observedAt);
    await withNmsFallback(env, (baseUrl) => ensureSuccessfulJsonPost(
        `${baseUrl}/pulse/vitals/`,
        { 'Content-Type': 'application/json' },
        payload,
        'Pulse local status ingest failed',
        env
    ));
    return payload;
}

function compactEdgeAnalysisForHeartbeat(analysis) {
    return {
        collected_at: analysis.collected_at,
        version: analysis.version,
        severity: analysis.deterministic?.severity || 'ok',
        summary: analysis.deterministic?.summary || '',
        finding_count: analysis.deterministic?.finding_count || 0,
        findings: Array.isArray(analysis.deterministic?.findings)
            ? analysis.deterministic.findings.slice(0, 8)
            : [],
        ai_summary: analysis.ai?.content || null,
        ai_error: analysis.ai_error || null,
        snapshot: {
            hostname: analysis.snapshot?.hostname,
            uptime_seconds: analysis.snapshot?.uptime_seconds,
            cpu_count: analysis.snapshot?.cpu_count,
            loadavg: analysis.snapshot?.loadavg,
            memory: analysis.snapshot?.memory,
            default_gateway: analysis.snapshot?.network?.default_gateway || null,
            private_ip: analysis.snapshot?.network?.private_ip || null,
            primary_network: analysis.snapshot?.network?.primary_network || null,
            neighbor_count: analysis.snapshot?.network?.neighbors?.total || 0,
            neighbor_state_counts: analysis.snapshot?.network?.neighbors?.state_counts || {},
            neighbor_entries: Array.isArray(analysis.snapshot?.network?.neighbors?.entries)
                ? analysis.snapshot.network.neighbors.entries.slice(0, 256)
                : [],
            interfaces: analysis.snapshot?.network?.interfaces || [],
            observed_vlans: analysis.snapshot?.network?.observed_vlans || { enabled: false, frame_count: 0, vlan_ids: [] },
            lldp: analysis.snapshot?.network?.lldp || { available: false, neighbor_count: 0, neighbors: [] },
            wireless: analysis.snapshot?.network?.wireless || { available: false, access_point_count: 0, access_points: [] },
            listeners: analysis.snapshot?.network?.listeners || {},
            network_device_snmp: analysis.snapshot?.network?.network_device_snmp || { enabled: false, target_count: 0, targets: [] },
            disks: Array.isArray(analysis.snapshot?.disks) ? analysis.snapshot.disks.slice(0, 12) : [],
            services: analysis.snapshot?.services || {},
            tools: analysis.snapshot?.tools || {}
        }
    };
}

async function runEdgeAnalysis(env) {
    const analysis = await buildEdgeAnalysis(env);
    console.log(JSON.stringify(compactEdgeAnalysisForHeartbeat(analysis), null, 2));
}

async function runEdgeAnalysisHeartbeat(env) {
    const report = inspectCollectorEnv(env);
    if (!report.ready) {
        throw new Error(report.errors.join('; '));
    }
    if (!report.features.edgeAnalysisEnabled) {
        console.log('[nms-collector] edge analysis disabled');
        return;
    }

    const analysis = await buildEdgeAnalysis(env);
    const payload = buildHeartbeatPayload(env);
    payload.status = analysis.deterministic?.severity === 'danger' ? 'error' : payload.status;
    payload.software_version = payload.software_version || EDGE_COLLECTOR_VERSION;
    payload.metadata.edge_analysis = compactEdgeAnalysisForHeartbeat(analysis);
    if (parseBoolean(env.EDGE_STANDARD_DIAGNOSTIC_ENABLED, true)) {
        try {
            const diagnostic = await runGoalDiagnostic({
                command_type: 'goal',
                target: env.EDGE_STANDARD_DIAGNOSTIC_GOAL || 'firewall-standard-check',
                options: {
                    dns_query: env.DIAGNOSTIC_DEFAULT_DNS_QUERY || 'naver.com',
                    internet_test_url: env.DIAGNOSTIC_INTERNET_TEST_URL || 'https://www.naver.com/'
                }
            }, env);
            payload.metadata.diagnostic = {
                state: diagnostic.assessment?.state || (diagnostic.ok ? 'healthy' : 'degraded'),
                confidence: diagnostic.assessment?.confidence || 'medium',
                summary: diagnostic.assessment?.summary || '',
                cause_label: diagnostic.assessment?.cause_label || null,
                facts: diagnostic.assessment?.facts || {},
                missing_data: diagnostic.assessment?.missing_data || [],
                goal: diagnostic.goal,
                step_count: diagnostic.step_count,
                failed_steps: diagnostic.failed_steps,
                ping_results: {
                    kt: summarizePingStep(findDiagnosticStep(diagnostic.steps, 'internet-ping-kt')),
                    google: summarizePingStep(findDiagnosticStep(diagnostic.steps, 'internet-ping-google'))
                }
            };
            if (!diagnostic.ok) {
                payload.status = 'error';
            }
        } catch (error) {
            payload.metadata.diagnostic = {
                state: 'unknown',
                confidence: 'low',
                summary: `표준 진단 실행 실패: ${error.message}`,
                cause_label: 'collector/ingress',
                facts: {},
                missing_data: ['standard_diagnostic'],
                goal: env.EDGE_STANDARD_DIAGNOSTIC_GOAL || 'firewall-standard-check',
                failed_steps: ['standard_diagnostic']
            };
        }
    }
    await postCollectorHeartbeat(env, report, payload, 'edge analysis heartbeat failed');
    console.log(`[nms-collector] edge analysis heartbeat sent: collector_id=${report.collectorId} severity=${analysis.deterministic?.severity || 'ok'} diagnostic=${payload.metadata.diagnostic?.state || 'disabled'}`);
}

async function runHeartbeat(env) {
    const report = inspectCollectorEnv(env);
    if (!report.ready) {
        throw new Error(report.errors.join('; '));
    }
    const services = inspectLocalServices(report);
    const heartbeatStartedAt = Date.now();
    let heartbeatError = null;

    try {
        const payload = buildHeartbeatPayload(env);
        await postCollectorHeartbeat(env, report, payload);
    } catch (error) {
        heartbeatError = error;
    }

    if (!heartbeatError) {
        try {
            const delivery = await flushQueuedFieldMeasurements(env);
            if (delivery.attempted > 0) {
                console.log(`[nms-collector] queued field measurements: delivered=${delivery.delivered} pending=${delivery.pending}`);
            }
        } catch (error) {
            // A measurement queue failure must not discard a successful heartbeat.
            console.error(`[nms-collector] queued field measurement flush failed: ${error.message}`);
        }
    }

    await trySendUptimeKumaPush(
        env,
        buildCollectorUptimeKumaUpdate(report, services, {
            heartbeatError,
            heartbeatLatencyMs: Date.now() - heartbeatStartedAt
        })
    );

    if (heartbeatError) {
        throw heartbeatError;
    }

    console.log(`collector heartbeat sent: collector_id=${report.collectorId}`);

    try {
        const pulsePayload = await pollAndPostPulseLocalStatus(env, report);
        if (pulsePayload) {
            console.log(
                `Pulse local status sent: host=${pulsePayload.ip}`
                + ` poe_voltage_v=${pulsePayload.poe_voltage_v ?? 'unknown'}`
                + ` measured_at=${pulsePayload.source_measurement_at}`
            );
        }
    } catch (error) {
        console.error(`[nms-collector] Pulse local status collection failed: ${error.message}`);
    }
}

function safeValue(value) {
    if (Buffer.isBuffer(value)) {
        return value.toString('hex');
    }

    if (typeof value === 'bigint') {
        return value.toString();
    }

    if (Array.isArray(value)) {
        return value.map((item) => safeValue(item));
    }

    if (value && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(([key, currentValue]) => [key, safeValue(currentValue)]));
    }

    return value;
}

function extractTrapOid(trap) {
    if (!trap || !trap.pdu || !Array.isArray(trap.pdu.varbinds)) {
        return trap && trap.pdu && trap.pdu.enterprise ? String(trap.pdu.enterprise) : null;
    }

    const trapOidVarbind = trap.pdu.varbinds.find((varbind) => varbind.oid === '1.3.6.1.6.3.1.1.4.1.0');
    if (trapOidVarbind) {
        return String(trapOidVarbind.value);
    }

    return trap.pdu.enterprise ? String(trap.pdu.enterprise) : null;
}

function buildTrapPayload(trap) {
    return {
        source_ip: trap && trap.rinfo && trap.rinfo.address ? trap.rinfo.address : null,
        source_port: trap && trap.rinfo && trap.rinfo.port ? trap.rinfo.port : null,
        trap_oid: extractTrapOid(trap),
        enterprise_oid: trap && trap.pdu && trap.pdu.enterprise ? String(trap.pdu.enterprise) : null,
        pdu_type: trap && trap.pdu && trap.pdu.type !== undefined ? trap.pdu.type : null,
        community: trap && trap.community ? String(trap.community) : null,
        version: trap && trap.version !== undefined && trap.version !== null ? String(trap.version) : null,
        varbind_count: trap && trap.pdu && Array.isArray(trap.pdu.varbinds) ? trap.pdu.varbinds.length : 0,
        varbinds: trap && trap.pdu && Array.isArray(trap.pdu.varbinds) ? safeValue(trap.pdu.varbinds) : [],
        raw_trap: safeValue(trap)
    };
}

async function runTrapForwarder(env) {
    const report = inspectCollectorEnv(env);
    if (!report.ready) {
        throw new Error(report.errors.join('; '));
    }

    const snmp = require('net-snmp');
    const receiver = snmp.createReceiver(
        {
            port: report.trap.port,
            transport: 'udp4',
            address: report.trap.address,
            disableAuthorization: report.trap.authorizationDisabled
        },
        async (error, trap) => {
            if (error) {
                console.error(`[nms-collector] trap receiver error: ${error.message}`);
                return;
            }

            const payload = buildTrapPayload(trap);
            if (!payload.source_ip) {
                console.error('[nms-collector] dropped trap without source_ip');
                return;
            }

            if (payload.pdu_type !== null && snmp.PduType[payload.pdu_type] !== undefined) {
                payload.pdu_type = String(snmp.PduType[payload.pdu_type]);
            } else if (payload.pdu_type !== null) {
                payload.pdu_type = String(payload.pdu_type);
            }

            try {
                await withNmsFallback(env, (baseUrl) => ensureSuccessfulJsonPost(
                    `${baseUrl}/api/collectors/${report.collectorId}/snmp-traps`,
                    {
                        'Content-Type': 'application/json',
                        'X-Collector-Token': String(env.COLLECTOR_TOKEN).trim()
                    },
                    payload,
                    'collector trap forward failed',
                    env
                ));
                console.log(
                    `[nms-collector] forwarded trap source_ip=${payload.source_ip} trap_oid=${payload.trap_oid || 'unknown'}`
                );
            } catch (postError) {
                console.error(`[nms-collector] ${postError.message}`);
            }
        }
    );

    if (!report.trap.authorizationDisabled) {
        const authorizer = receiver.getAuthorizer();
        for (const community of report.trap.communities) {
            authorizer.addCommunity(community);
        }
    }

    console.log(`[nms-collector] trap-forwarder listening on ${report.trap.address}:${report.trap.port}`);
}

function runDoctor(env, execFn = execFileSync) {
    const report = inspectCollectorEnv(env);
    const services = inspectLocalServices(report, execFn);
    const lines = [
        `env_file=${env.ENV_FILE || DEFAULT_ENV_FILE}`,
        `ready=${report.ready ? 'true' : 'false'}`,
        `collector_role=${report.collectorRole}`,
        `nms_url=${report.resolvedNmsUrls?.join(' -> ') || report.resolvedNmsUrl || '(unresolved)'}`,
        `nms_tls_mode=${report.tls.insecureTls ? 'insecure' : report.tls.caCertPath ? `custom-ca:${report.tls.caCertPath}` : 'system-ca'}`,
        `collector_id=${report.collectorId || '(invalid)'}`,
        `heartbeat=enabled`,
        `rsyslog_relay=${report.features.rsyslogRelayEnabled ? `enabled ${report.rsyslog.targetHost}:${report.rsyslog.targetPort}/${report.rsyslog.protocol}` : 'disabled'}`,
        `snmptrap_relay=${report.features.trapRelayEnabled ? `enabled ${report.trap.address}:${report.trap.port}` : 'disabled'}`,
        `remote_diagnostics=${report.features.remoteDiagnosticsEnabled ? 'enabled' : 'disabled'}`,
        `edge_server=${report.features.edgeServerMode ? 'enabled' : 'disabled'}`,
        `edge_analysis=${report.features.edgeAnalysisEnabled ? 'enabled' : 'disabled'}`,
        `edge_ai=${report.features.edgeAiEnabled ? 'enabled' : 'disabled'}`,
        `remote_management=${report.remoteManagement.mode}${report.remoteManagement.profileLabel ? `:${report.remoteManagement.profileLabel}` : ''}`,
        'remote_management_collection_dependency=false',
        `heartbeat_timer_service=active:${services.heartbeatTimer.active} enabled:${services.heartbeatTimer.enabled}`
    ];

    if (services.rsyslog) {
        lines.push(`rsyslog_service=active:${services.rsyslog.active} enabled:${services.rsyslog.enabled}`);
    }

    if (services.trapForwarder) {
        lines.push(`snmptrap_service=active:${services.trapForwarder.active} enabled:${services.trapForwarder.enabled}`);
    }

    if (services.diagnosticWorker) {
        lines.push(`diagnostic_worker_service=active:${services.diagnosticWorker.active} enabled:${services.diagnosticWorker.enabled}`);
    }

    if (services.edgeAnalysisTimer) {
        lines.push(`edge_analysis_timer=active:${services.edgeAnalysisTimer.active} enabled:${services.edgeAnalysisTimer.enabled}`);
    }

    for (const line of lines) {
        console.log(`[doctor] ${line}`);
    }

    for (const warning of report.warnings) {
        console.warn(`[doctor] warning: ${warning}`);
    }

    for (const error of report.errors) {
        console.error(`[doctor] error: ${error}`);
    }

    return report.ready ? 0 : 1;
}

async function readFieldMeasurementProfileFromStdin() {
    const chunks = [];
    let byteLength = 0;
    for await (const chunk of process.stdin) {
        byteLength += Buffer.byteLength(chunk);
        if (byteLength > 16384) {
            throw new Error('field profile input exceeds 16 KiB');
        }
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const raw = Buffer.concat(chunks).toString('utf8').trim();
    if (!raw) {
        throw new Error('field profile JSON is required on standard input');
    }
    try {
        return normalizeFieldMeasurementProfile(JSON.parse(raw));
    } catch (error) {
        if (error instanceof SyntaxError) {
            throw new Error('field profile input is not valid JSON');
        }
        throw error;
    }
}

async function main(argv = process.argv.slice(2), env = null) {
    const envFile = process.env.ENV_FILE || DEFAULT_ENV_FILE;
    const effectiveEnv = env || loadCollectorEnv(envFile);
    const command = argv[0] || 'doctor';

    if (command === 'heartbeat') {
        await runHeartbeat(effectiveEnv);
        return;
    }

    if (command === 'trap-forwarder') {
        await runTrapForwarder(effectiveEnv);
        return;
    }

    if (command === 'diagnostic-worker') {
        await runDiagnosticWorker(effectiveEnv);
        return;
    }

    if (command === 'diagnostic-once') {
        await runDiagnosticWorkerOnce(effectiveEnv);
        return;
    }

    if (command === 'edge-analysis') {
        await runEdgeAnalysis(effectiveEnv);
        return;
    }

    if (command === 'measurement-session') {
        if (argv[3] !== '--field-profile-stdin') {
            throw new Error('measurement-session requires --field-profile-stdin');
        }
        const parentSessionIndex = argv.indexOf('--measurement-session-id');
        const parentSessionId = parentSessionIndex >= 0 ? String(argv[parentSessionIndex + 1] || '').trim() : null;
        if (parentSessionId
            && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(parentSessionId)) {
            throw new Error('measurement-session --measurement-session-id must be a UUID');
        }
        const result = await runLocalMeasurementSession(
            effectiveEnv,
            argv[1],
            argv[2],
            await readFieldMeasurementProfileFromStdin(),
            parentSessionId
        );
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        return;
    }

    if (command === 'snapshot-session') {
        if (argv[1] !== '--field-profile-stdin') {
            throw new Error('snapshot-session requires --field-profile-stdin');
        }
        const result = await runLocalDiagnosticSnapshot(
            effectiveEnv,
            await readFieldMeasurementProfileFromStdin(),
            argv[2] === '--send'
        );
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        return;
    }

    if (command === 'offline-measurements') {
        const action = argv[1] || 'list';
        if (action === 'list') {
            const items = listQueuedFieldMeasurements(effectiveEnv);
            process.stdout.write(`${JSON.stringify({ items, pending_count: items.filter((item) => item.state === 'pending').length }, null, 2)}\n`);
            return;
        }
        if (action === 'flush') {
            const result = await flushQueuedFieldMeasurements(effectiveEnv);
            process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
            return;
        }
        throw new Error('offline-measurements action must be list or flush');
    }

    if (command === 'edge-analysis-heartbeat') {
        await runEdgeAnalysisHeartbeat(effectiveEnv);
        return;
    }

    if (command === 'doctor') {
        const exitCode = runDoctor(effectiveEnv);
        if (exitCode !== 0) {
            process.exitCode = exitCode;
        }
        return;
    }

    if (command === 'render-rsyslog-config') {
        process.stdout.write(renderRsyslogConfig(effectiveEnv));
        return;
    }

    throw new Error(`unknown command: ${command}`);
}

if (require.main === module) {
    main().catch((error) => {
        console.error(`[nms-collector] ${error.message}`);
        process.exitCode = 1;
    });
}

module.exports = {
    analyzeEdgeSnapshot,
    aggregateMeasurementMetric,
    buildSwitchTopology,
    buildConnectivityAssessment,
    buildEdgeAnalysis,
    buildDiagnosticResultExcerpt,
    buildHeartbeatPayload,
    buildPulseLocalStatusPayload,
    buildTrapPayload,
    calculateIpv4Subnet,
    collectEdgeSnapshot,
    collectLldpSnapshot,
    collectPrimaryNetwork,
    collectWireGuardStatus,
    calculateCpuUsedPct,
    executeDiagnosticCommand,
    finalizeMeasurementMetrics,
    extractTrapOid,
    getTcpdumpFilter,
    getRemoteManagementSettings,
    inferCollectorRole,
    inspectCollectorEnv,
    inspectLocalServices,
    isAllowedDiagnosticHost,
    isPrivateIpv4Address,
    loadCollectorEnv,
    main,
    parseDfOutput,
    parseEnvFileContents,
    parseIpNeighborSummary,
    parseTsharkDetailRows,
    parseTsharkPacketRows,
    parsePulseLocalStatusResponse,
    parseSnmpOidTable,
    parsePositivePort,
    parseTcpTarget,
    normalizeFieldMeasurementProfile,
    buildQueuedFieldMeasurement,
    buildQueuedFieldSnapshot,
    buildCollectionSourceStatus,
    buildDiagnosticSnapshotSession,
    persistQueuedFieldMeasurement,
    listQueuedFieldMeasurements,
    flushQueuedFieldMeasurements,
    readSystemctlState,
    renderRsyslogConfig,
    resolveNmsUrl,
    resolveNmsUrls,
    runLocalMeasurementSession,
    runLocalDiagnosticSnapshot,
    runMeasurementSessionDiagnostic,
    fetchPulseLocalStatus,
    pollAndPostPulseLocalStatus,
    summarizePingStep
};
