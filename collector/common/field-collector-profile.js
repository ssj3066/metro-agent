const COLLECTOR_PROFILE_VERSION = 2;

const USER_ROLES = Object.freeze(['admin', 'operator', 'field_technician', 'viewer']);
const COLLECTOR_PLATFORMS = Object.freeze(['ubuntu', 'windows']);
const COLLECTOR_ROLES = Object.freeze(['agent', 'syslog_gateway', 'snmp_proxy', 'hybrid']);
const TLS_MODES = Object.freeze(['system-ca', 'insecure', 'custom-ca']);
const RSYSLOG_PROTOCOLS = Object.freeze(['udp', 'tcp']);
const REMOTE_MANAGEMENT_MODES = Object.freeze(['none', 'omada_vpn']);

const PLACEHOLDER_TOKEN = 'replace-with-agent-token';

const SETTING_DEFINITIONS = Object.freeze({
    heartbeat_interval_seconds: {
        type: 'integer',
        default: 60,
        min: 15,
        max: 3600,
        editableBy: ['admin', 'operator'],
        section: 'runtime'
    },
    diagnostic_poll_interval_seconds: {
        type: 'integer',
        default: 15,
        min: 10,
        max: 300,
        editableBy: ['admin', 'operator'],
        section: 'diagnostics'
    },
    diagnostic_command_limit: {
        type: 'integer',
        default: 1,
        min: 1,
        max: 10,
        editableBy: ['admin', 'operator'],
        section: 'diagnostics'
    },
    diagnostic_tcpdump_max_seconds: {
        type: 'integer',
        default: 10,
        min: 1,
        max: 60,
        editableBy: ['admin', 'operator'],
        section: 'diagnostics'
    },
    diagnostic_allow_public_targets: {
        type: 'boolean',
        default: false,
        editableBy: ['admin'],
        section: 'diagnostics-security'
    },
    diagnostic_allow_hostnames: {
        type: 'boolean',
        default: false,
        editableBy: ['admin', 'operator'],
        section: 'diagnostics-security'
    },
    diagnostic_allow_raw_tcpdump_filter: {
        type: 'boolean',
        default: false,
        editableBy: ['admin'],
        section: 'diagnostics-security'
    },
    diagnostic_capture_interface: {
        type: 'string',
        default: 'any',
        maxLength: 64,
        editableBy: ['admin', 'operator', 'field_technician'],
        section: 'diagnostics'
    },
    diagnostic_default_dns_query: {
        type: 'string',
        default: 'naver.com',
        maxLength: 120,
        editableBy: ['admin', 'operator', 'field_technician'],
        section: 'diagnostics'
    },
    diagnostic_internet_ping_target: {
        type: 'string',
        default: '1.1.1.1',
        maxLength: 253,
        editableBy: ['admin', 'operator'],
        section: 'diagnostics'
    },
    diagnostic_internet_test_url: {
        type: 'string',
        default: 'https://www.naver.com/',
        maxLength: 300,
        editableBy: ['admin', 'operator'],
        section: 'diagnostics'
    },
    remote_management_mode: {
        type: 'enum',
        default: 'none',
        values: REMOTE_MANAGEMENT_MODES,
        editableBy: ['admin', 'operator'],
        section: 'remote-management'
    },
    remote_management_profile_label: {
        type: 'string',
        default: '',
        maxLength: 120,
        editableBy: ['admin', 'operator', 'field_technician'],
        section: 'remote-management'
    },
    wireguard_interface: {
        type: 'string',
        default: 'metro-omada',
        maxLength: 64,
        editableBy: ['admin', 'operator'],
        section: 'remote-management'
    },
    wireguard_handshake_stale_seconds: {
        type: 'integer',
        default: 180,
        min: 30,
        max: 3600,
        editableBy: ['admin', 'operator'],
        section: 'remote-management'
    },
    snmp_timeout_ms: {
        type: 'integer',
        default: 5000,
        min: 500,
        max: 30000,
        editableBy: ['admin', 'operator'],
        section: 'snmp'
    },
    snmp_retries: {
        type: 'integer',
        default: 1,
        min: 0,
        max: 5,
        editableBy: ['admin', 'operator'],
        section: 'snmp'
    },
    rsyslog_target_port: {
        type: 'integer',
        default: 5514,
        min: 1,
        max: 65535,
        editableBy: ['admin'],
        section: 'relay'
    },
    rsyslog_target_protocol: {
        type: 'enum',
        default: 'udp',
        values: RSYSLOG_PROTOCOLS,
        editableBy: ['admin'],
        section: 'relay'
    },
    snmptrap_listen_port: {
        type: 'integer',
        default: 1162,
        min: 1,
        max: 65535,
        editableBy: ['admin'],
        section: 'relay'
    },
    snmptrap_listen_address: {
        type: 'string',
        default: '0.0.0.0',
        maxLength: 64,
        editableBy: ['admin'],
        section: 'relay'
    },
    edge_disk_warn_pct: {
        type: 'integer',
        default: 85,
        min: 50,
        max: 98,
        editableBy: ['admin', 'operator'],
        section: 'edge-analysis'
    },
    edge_disk_danger_pct: {
        type: 'integer',
        default: 95,
        min: 60,
        max: 99,
        editableBy: ['admin', 'operator'],
        section: 'edge-analysis'
    },
    edge_memory_warn_pct: {
        type: 'integer',
        default: 85,
        min: 50,
        max: 98,
        editableBy: ['admin', 'operator'],
        section: 'edge-analysis'
    },
    edge_memory_danger_pct: {
        type: 'integer',
        default: 95,
        min: 60,
        max: 99,
        editableBy: ['admin', 'operator'],
        section: 'edge-analysis'
    },
    edge_load_warn_per_cpu: {
        type: 'number',
        default: 2,
        min: 0.5,
        max: 20,
        editableBy: ['admin', 'operator'],
        section: 'edge-analysis'
    },
    ai_timeout_ms: {
        type: 'integer',
        default: 30000,
        min: 5000,
        max: 120000,
        editableBy: ['admin', 'operator'],
        section: 'ai'
    },
    ai_max_tokens: {
        type: 'integer',
        default: 500,
        min: 100,
        max: 4000,
        editableBy: ['admin', 'operator'],
        section: 'ai'
    }
});

const FIELD_EDITABLE_PATHS = Object.freeze(new Set([
    'identity.display_name',
    'identity.site_label',
    'metadata.notes',
    'metadata.tags',
    'settings.diagnostic_capture_interface',
    'settings.diagnostic_default_dns_query'
]));

const OPERATOR_EXTRA_PATHS = Object.freeze(new Set([
    'identity.purpose',
    'features.remote_diagnostics',
    'features.edge_analysis',
    'features.ai_helper',
    ...Object.entries(SETTING_DEFINITIONS)
        .filter(([, definition]) => definition.editableBy.includes('operator'))
        .map(([key]) => `settings.${key}`)
]));

const ADMIN_EXTRA_PATHS = Object.freeze(new Set([
    'identity.platform',
    'identity.collector_role',
    'targets.nms_base_url',
    'targets.tls_mode',
    'targets.ca_cert_path',
    'features.rsyslog_relay',
    'features.snmptrap_relay',
    'features.packet_capture',
    ...Object.keys(SETTING_DEFINITIONS).map((key) => `settings.${key}`)
]));

function unique(values) {
    return [...new Set(values.filter(Boolean))];
}

function cloneJson(value) {
    return JSON.parse(JSON.stringify(value));
}

function normalizeRole(role) {
    const normalized = String(role || '').trim().toLowerCase();
    return USER_ROLES.includes(normalized) ? normalized : 'viewer';
}

function normalizeEnumValue(value, allowedValues, fallback, warnings, path) {
    const normalized = String(value || '').trim().toLowerCase();
    if (allowedValues.includes(normalized)) {
        return normalized;
    }

    if (value !== undefined && value !== null && value !== '') {
        warnings.push(`${path} uses unsupported value; defaulted to ${fallback}`);
    }
    return fallback;
}

function normalizeBoolean(value, fallback = false) {
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

function normalizeString(value, fallback, maxLength, warnings, path) {
    let normalized = String(value === undefined || value === null ? fallback : value).trim();
    if (!normalized) {
        normalized = String(fallback || '').trim();
    }
    if (maxLength && normalized.length > maxLength) {
        warnings.push(`${path} was truncated to ${maxLength} characters`);
        normalized = normalized.slice(0, maxLength);
    }
    return normalized;
}

function normalizeInteger(value, definition, warnings, path) {
    const parsed = Number(String(value ?? '').trim());
    let normalized = Number.isInteger(parsed) ? parsed : definition.default;
    if (!Number.isInteger(parsed) && value !== undefined && value !== null && value !== '') {
        warnings.push(`${path} is not an integer; defaulted to ${definition.default}`);
    }
    if (normalized < definition.min) {
        warnings.push(`${path} raised to minimum ${definition.min}`);
        normalized = definition.min;
    }
    if (normalized > definition.max) {
        warnings.push(`${path} lowered to maximum ${definition.max}`);
        normalized = definition.max;
    }
    return normalized;
}

function normalizeNumber(value, definition, warnings, path) {
    const parsed = Number(String(value ?? '').trim());
    let normalized = Number.isFinite(parsed) ? parsed : definition.default;
    if (!Number.isFinite(parsed) && value !== undefined && value !== null && value !== '') {
        warnings.push(`${path} is not a number; defaulted to ${definition.default}`);
    }
    if (normalized < definition.min) {
        warnings.push(`${path} raised to minimum ${definition.min}`);
        normalized = definition.min;
    }
    if (normalized > definition.max) {
        warnings.push(`${path} lowered to maximum ${definition.max}`);
        normalized = definition.max;
    }
    return normalized;
}

function normalizeSetting(key, value, warnings) {
    const definition = SETTING_DEFINITIONS[key];
    const path = `settings.${key}`;
    if (!definition) {
        return undefined;
    }

    if (definition.type === 'integer') {
        return normalizeInteger(value, definition, warnings, path);
    }
    if (definition.type === 'number') {
        return normalizeNumber(value, definition, warnings, path);
    }
    if (definition.type === 'boolean') {
        return normalizeBoolean(value, definition.default);
    }
    if (definition.type === 'enum') {
        return normalizeEnumValue(value, definition.values, definition.default, warnings, path);
    }
    return normalizeString(value, definition.default, definition.maxLength, warnings, path);
}

function normalizeTags(value) {
    if (Array.isArray(value)) {
        return unique(value.map((item) => String(item || '').trim()).filter(Boolean)).slice(0, 20);
    }
    return unique(String(value || '').split(',').map((item) => item.trim()).filter(Boolean)).slice(0, 20);
}

function createDefaultCollectorProfile(options = {}) {
    const platform = COLLECTOR_PLATFORMS.includes(String(options.platform || '').toLowerCase())
        ? String(options.platform).toLowerCase()
        : 'ubuntu';
    const collectorRole = COLLECTOR_ROLES.includes(String(options.collector_role || '').toLowerCase())
        ? String(options.collector_role).toLowerCase()
        : 'agent';
    const settings = {};
    for (const [key, definition] of Object.entries(SETTING_DEFINITIONS)) {
        settings[key] = definition.default;
    }

    return {
        profile_version: COLLECTOR_PROFILE_VERSION,
        identity: {
            display_name: String(options.display_name || 'nms-field-collector').trim(),
            site_label: String(options.site_label || '').trim(),
            platform,
            collector_role: collectorRole,
            purpose: String(options.purpose || 'field network collection').trim()
        },
        targets: {
            nms_base_url: String(options.nms_base_url || 'https://112.167.190.125:7443').trim(),
            nms_fallback_url: String(options.nms_fallback_url || 'https://192.168.1.33:7443').trim(),
            tls_mode: 'system-ca',
            ca_cert_path: ''
        },
        features: {
            heartbeat: true,
            remote_diagnostics: true,
            edge_analysis: true,
            ai_helper: false,
            rsyslog_relay: false,
            snmptrap_relay: false,
            packet_capture: true
        },
        settings,
        metadata: {
            notes: '',
            tags: []
        }
    };
}

function normalizeCollectorProfile(input = {}) {
    const warnings = [];
    const errors = [];
    const defaults = createDefaultCollectorProfile();
    const source = input && typeof input === 'object' ? input : {};
    const sourceIdentity = source.identity && typeof source.identity === 'object' ? source.identity : {};
    const sourceTargets = source.targets && typeof source.targets === 'object' ? source.targets : {};
    const sourceFeatures = source.features && typeof source.features === 'object' ? source.features : {};
    const sourceSettings = source.settings && typeof source.settings === 'object' ? source.settings : {};
    const sourceMetadata = source.metadata && typeof source.metadata === 'object' ? source.metadata : {};

    const platform = normalizeEnumValue(
        sourceIdentity.platform,
        COLLECTOR_PLATFORMS,
        defaults.identity.platform,
        warnings,
        'identity.platform'
    );
    const collectorRole = normalizeEnumValue(
        sourceIdentity.collector_role,
        COLLECTOR_ROLES,
        defaults.identity.collector_role,
        warnings,
        'identity.collector_role'
    );
    const tlsMode = normalizeEnumValue(
        sourceTargets.tls_mode,
        TLS_MODES,
        defaults.targets.tls_mode,
        warnings,
        'targets.tls_mode'
    );
    const settings = {};
    for (const key of Object.keys(SETTING_DEFINITIONS)) {
        settings[key] = normalizeSetting(
            key,
            Object.prototype.hasOwnProperty.call(sourceSettings, key) ? sourceSettings[key] : defaults.settings[key],
            warnings
        );
    }

    const profile = {
        profile_version: COLLECTOR_PROFILE_VERSION,
        identity: {
            display_name: normalizeString(
                sourceIdentity.display_name,
                defaults.identity.display_name,
                120,
                warnings,
                'identity.display_name'
            ),
            site_label: normalizeString(sourceIdentity.site_label, defaults.identity.site_label, 120, warnings, 'identity.site_label'),
            platform,
            collector_role: collectorRole,
            purpose: normalizeString(sourceIdentity.purpose, defaults.identity.purpose, 200, warnings, 'identity.purpose')
        },
        targets: {
            nms_base_url: normalizeString(sourceTargets.nms_base_url, defaults.targets.nms_base_url, 300, warnings, 'targets.nms_base_url').replace(/\/+$/, ''),
            nms_fallback_url: normalizeString(sourceTargets.nms_fallback_url, defaults.targets.nms_fallback_url, 300, warnings, 'targets.nms_fallback_url').replace(/\/+$/, ''),
            tls_mode: tlsMode,
            ca_cert_path: normalizeString(sourceTargets.ca_cert_path, defaults.targets.ca_cert_path, 260, warnings, 'targets.ca_cert_path')
        },
        features: {
            heartbeat: true,
            remote_diagnostics: normalizeBoolean(sourceFeatures.remote_diagnostics, defaults.features.remote_diagnostics),
            edge_analysis: normalizeBoolean(sourceFeatures.edge_analysis, defaults.features.edge_analysis),
            ai_helper: normalizeBoolean(sourceFeatures.ai_helper, defaults.features.ai_helper),
            rsyslog_relay: normalizeBoolean(sourceFeatures.rsyslog_relay, defaults.features.rsyslog_relay),
            snmptrap_relay: normalizeBoolean(sourceFeatures.snmptrap_relay, defaults.features.snmptrap_relay),
            packet_capture: normalizeBoolean(sourceFeatures.packet_capture, defaults.features.packet_capture)
        },
        settings,
        metadata: {
            notes: normalizeString(sourceMetadata.notes, defaults.metadata.notes, 1000, warnings, 'metadata.notes'),
            tags: normalizeTags(sourceMetadata.tags)
        }
    };

    if (!/^https?:\/\//i.test(profile.targets.nms_base_url)) {
        errors.push('targets.nms_base_url must start with http:// or https://');
    }
    if (/^https?:\/\/(?:127\.0\.0\.1|localhost)(?::\d+)?(?:\/|$)/i.test(profile.targets.nms_base_url)) {
        errors.push('targets.nms_base_url must not use localhost or 127.0.0.1 for a field collector');
    }
    if (profile.targets.nms_fallback_url && !/^https?:\/\//i.test(profile.targets.nms_fallback_url)) {
        errors.push('targets.nms_fallback_url must start with http:// or https://');
    }
    if (profile.targets.tls_mode === 'custom-ca' && !profile.targets.ca_cert_path) {
        errors.push('targets.ca_cert_path is required when tls_mode=custom-ca');
    }
    if (!/^https?:\/\//i.test(profile.settings.diagnostic_internet_test_url)) {
        errors.push('settings.diagnostic_internet_test_url must start with http:// or https://');
    }
    if (
        profile.settings.remote_management_mode === 'omada_vpn'
        && !profile.settings.remote_management_profile_label
    ) {
        warnings.push('OMADA VPN is selected without a remote management profile label');
    }
    if (profile.settings.edge_disk_danger_pct <= profile.settings.edge_disk_warn_pct) {
        warnings.push('settings.edge_disk_danger_pct adjusted above warning threshold');
        profile.settings.edge_disk_danger_pct = Math.min(99, profile.settings.edge_disk_warn_pct + 1);
    }
    if (profile.settings.edge_memory_danger_pct <= profile.settings.edge_memory_warn_pct) {
        warnings.push('settings.edge_memory_danger_pct adjusted above warning threshold');
        profile.settings.edge_memory_danger_pct = Math.min(99, profile.settings.edge_memory_warn_pct + 1);
    }
    if ((profile.identity.collector_role === 'syslog_gateway' || profile.identity.collector_role === 'hybrid') && !profile.features.rsyslog_relay) {
        warnings.push(`collector role ${profile.identity.collector_role} usually expects features.rsyslog_relay=true`);
    }
    if ((profile.identity.collector_role === 'snmp_proxy' || profile.identity.collector_role === 'hybrid') && !profile.features.snmptrap_relay) {
        warnings.push(`collector role ${profile.identity.collector_role} usually expects features.snmptrap_relay=true`);
    }
    if (profile.identity.platform === 'windows' && (profile.features.rsyslog_relay || profile.features.snmptrap_relay)) {
        warnings.push('windows collector relay features are planned; use ubuntu for production syslog/trap relay');
    }

    return {
        valid: errors.length === 0,
        errors,
        warnings,
        profile
    };
}

function listEditableProfilePaths(role) {
    const normalizedRole = normalizeRole(role);
    if (normalizedRole === 'viewer') {
        return [];
    }

    const paths = [...FIELD_EDITABLE_PATHS];
    if (normalizedRole === 'operator' || normalizedRole === 'admin') {
        paths.push(...OPERATOR_EXTRA_PATHS);
    }
    if (normalizedRole === 'admin') {
        paths.push(...ADMIN_EXTRA_PATHS);
    }
    return unique(paths).sort();
}

function canEditCollectorProfilePath(role, path) {
    return listEditableProfilePaths(role).includes(path);
}

function flattenPatch(value, prefix = '') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return [[prefix, value]];
    }

    const entries = [];
    for (const [key, nestedValue] of Object.entries(value)) {
        const path = prefix ? `${prefix}.${key}` : key;
        if (nestedValue && typeof nestedValue === 'object' && !Array.isArray(nestedValue)) {
            entries.push(...flattenPatch(nestedValue, path));
        } else {
            entries.push([path, nestedValue]);
        }
    }
    return entries;
}

function setPath(target, path, value) {
    const parts = path.split('.');
    let cursor = target;
    for (const part of parts.slice(0, -1)) {
        if (!cursor[part] || typeof cursor[part] !== 'object') {
            cursor[part] = {};
        }
        cursor = cursor[part];
    }
    cursor[parts[parts.length - 1]] = value;
}

function getKnownProfilePaths() {
    return unique([
        'identity.display_name',
        'identity.site_label',
        'identity.platform',
        'identity.collector_role',
        'identity.purpose',
        'targets.nms_base_url',
        'targets.tls_mode',
        'targets.ca_cert_path',
        'features.remote_diagnostics',
        'features.edge_analysis',
        'features.ai_helper',
        'features.rsyslog_relay',
        'features.snmptrap_relay',
        'features.packet_capture',
        'metadata.notes',
        'metadata.tags',
        ...Object.keys(SETTING_DEFINITIONS).map((key) => `settings.${key}`)
    ]).sort();
}

function applyCollectorProfilePatch(currentProfile, patch, actorRole) {
    const base = normalizeCollectorProfile(currentProfile).profile;
    const next = cloneJson(base);
    const allowed = [];
    const denied = [];
    const errors = [];
    const knownPaths = new Set(getKnownProfilePaths());

    for (const [path, value] of flattenPatch(patch)) {
        if (!knownPaths.has(path)) {
            errors.push(`unknown profile path: ${path}`);
            continue;
        }
        if (!canEditCollectorProfilePath(actorRole, path)) {
            denied.push(path);
            continue;
        }
        setPath(next, path, value);
        allowed.push(path);
    }

    const normalized = normalizeCollectorProfile(next);
    return {
        valid: errors.length === 0 && normalized.valid,
        allowed: unique(allowed).sort(),
        denied: unique(denied).sort(),
        errors: [...errors, ...normalized.errors],
        warnings: normalized.warnings,
        profile: normalized.profile
    };
}

function buildCollectorCapabilities(profile) {
    const normalized = normalizeCollectorProfile(profile).profile;
    const capabilities = ['heartbeat'];
    if (normalized.features.remote_diagnostics) {
        capabilities.push('diagnostics');
    }
    if (normalized.features.edge_analysis) {
        capabilities.push('edge-analysis');
    }
    if (normalized.features.packet_capture) {
        capabilities.push('packet-capture');
    }
    if (normalized.features.rsyslog_relay) {
        capabilities.push('syslog');
    }
    if (normalized.features.snmptrap_relay) {
        capabilities.push('trap');
    }
    if (normalized.features.ai_helper) {
        capabilities.push('ai-helper');
    }
    return capabilities;
}

function toUbuntuCollectorRole(profileRole) {
    if (profileRole === 'agent') {
        return 'ubuntu_agent';
    }
    return profileRole;
}

function renderEnvValue(value) {
    const raw = String(value ?? '');
    if (/^[A-Za-z0-9_./:@,+-]*$/.test(raw)) {
        return raw;
    }
    return JSON.stringify(raw);
}

function renderUbuntuEnv(profile, options = {}) {
    const normalized = normalizeCollectorProfile(profile).profile;
    const tlsMode = normalized.targets.tls_mode;
    const lines = [
        '# Generated from field collector profile. Do not store real tokens in source control.',
        `NMS_URL=${renderEnvValue(normalized.targets.nms_base_url)}`,
        `NMS_FALLBACK_URL=${renderEnvValue(normalized.targets.nms_fallback_url)}`,
        `NMS_INSECURE_TLS=${tlsMode === 'insecure' ? 'true' : 'false'}`,
        `NMS_CA_CERT_PATH=${renderEnvValue(tlsMode === 'custom-ca' ? normalized.targets.ca_cert_path : '')}`,
        `COLLECTOR_ID=${renderEnvValue(options.collectorId || '1')}`,
        `COLLECTOR_TOKEN=${renderEnvValue(options.collectorToken || PLACEHOLDER_TOKEN)}`,
        `COLLECTOR_HOSTNAME=${renderEnvValue(normalized.identity.display_name)}`,
        `COLLECTOR_PLATFORM=${renderEnvValue(normalized.identity.platform)}`,
        `COLLECTOR_ROLE=${renderEnvValue(toUbuntuCollectorRole(normalized.identity.collector_role))}`,
        `COLLECTOR_PURPOSE=${renderEnvValue(normalized.identity.purpose)}`,
        `COLLECTOR_CAPABILITIES=${renderEnvValue(buildCollectorCapabilities(normalized).join(','))}`,
        `REMOTE_DIAGNOSTICS_ENABLED=${normalized.features.remote_diagnostics ? 'true' : 'false'}`,
        `DIAGNOSTIC_POLL_INTERVAL_SECONDS=${normalized.settings.diagnostic_poll_interval_seconds}`,
        `DIAGNOSTIC_COMMAND_LIMIT=${normalized.settings.diagnostic_command_limit}`,
        `DIAGNOSTIC_ALLOW_PUBLIC_TARGETS=${normalized.settings.diagnostic_allow_public_targets ? 'true' : 'false'}`,
        `DIAGNOSTIC_ALLOW_HOSTNAMES=${normalized.settings.diagnostic_allow_hostnames ? 'true' : 'false'}`,
        `DIAGNOSTIC_CAPTURE_INTERFACE=${renderEnvValue(normalized.settings.diagnostic_capture_interface)}`,
        `DIAGNOSTIC_TCPDUMP_MAX_SECONDS=${normalized.settings.diagnostic_tcpdump_max_seconds}`,
        `DIAGNOSTIC_DEFAULT_DNS_QUERY=${renderEnvValue(normalized.settings.diagnostic_default_dns_query)}`,
        `DIAGNOSTIC_INTERNET_PING_TARGET=${renderEnvValue(normalized.settings.diagnostic_internet_ping_target)}`,
        `DIAGNOSTIC_INTERNET_TEST_URL=${renderEnvValue(normalized.settings.diagnostic_internet_test_url)}`,
        `DIAGNOSTIC_ALLOW_RAW_TCPDUMP_FILTER=${normalized.settings.diagnostic_allow_raw_tcpdump_filter ? 'true' : 'false'}`,
        `REMOTE_MANAGEMENT_MODE=${renderEnvValue(normalized.settings.remote_management_mode)}`,
        `REMOTE_MANAGEMENT_PROFILE_LABEL=${renderEnvValue(normalized.settings.remote_management_profile_label)}`,
        `WIREGUARD_INTERFACE=${renderEnvValue(normalized.settings.wireguard_interface)}`,
        `WIREGUARD_HANDSHAKE_STALE_SECONDS=${normalized.settings.wireguard_handshake_stale_seconds}`,
        `ENABLE_RSYSLOG_RELAY=${normalized.features.rsyslog_relay ? 'true' : 'false'}`,
        'RSYSLOG_TARGET_HOST=127.0.0.1',
        `RSYSLOG_TARGET_PORT=${normalized.settings.rsyslog_target_port}`,
        `RSYSLOG_TARGET_PROTOCOL=${normalized.settings.rsyslog_target_protocol}`,
        `ENABLE_SNMPTRAP_RELAY=${normalized.features.snmptrap_relay ? 'true' : 'false'}`,
        `SNMPTRAP_LISTEN_ADDRESS=${renderEnvValue(normalized.settings.snmptrap_listen_address)}`,
        `SNMPTRAP_LISTEN_PORT=${normalized.settings.snmptrap_listen_port}`,
        `EDGE_SERVER_MODE=${normalized.features.edge_analysis ? 'true' : 'false'}`,
        `EDGE_ANALYSIS_ENABLED=${normalized.features.edge_analysis ? 'true' : 'false'}`,
        `EDGE_DISK_WARN_PCT=${normalized.settings.edge_disk_warn_pct}`,
        `EDGE_DISK_DANGER_PCT=${normalized.settings.edge_disk_danger_pct}`,
        `EDGE_MEMORY_WARN_PCT=${normalized.settings.edge_memory_warn_pct}`,
        `EDGE_MEMORY_DANGER_PCT=${normalized.settings.edge_memory_danger_pct}`,
        `EDGE_LOAD_WARN_PER_CPU=${normalized.settings.edge_load_warn_per_cpu}`,
        `EDGE_AI_ENABLED=${normalized.features.ai_helper ? 'true' : 'false'}`,
        `EDGE_AI_TIMEOUT_MS=${normalized.settings.ai_timeout_ms}`,
        `EDGE_AI_MAX_TOKENS=${normalized.settings.ai_max_tokens}`
    ];

    return `${lines.join('\n')}\n`;
}

function renderPowerShellString(value) {
    return `"${String(value ?? '').replace(/`/g, '``').replace(/"/g, '`"')}"`;
}

function renderWindowsEnv(profile, options = {}) {
    const normalized = normalizeCollectorProfile(profile).profile;
    const capabilities = buildCollectorCapabilities(normalized).map(renderPowerShellString).join(', ');
    const lines = [
        '# Generated from field collector profile. Do not store real tokens in source control.',
        `$NmsUrl = ${renderPowerShellString(normalized.targets.nms_base_url)}`,
        `$NmsFallbackUrl = ${renderPowerShellString(normalized.targets.nms_fallback_url)}`,
        `$NmsSkipCertificateCheck = ${normalized.targets.tls_mode === 'insecure' ? '$true' : '$false'}`,
        `$CollectorId = ${renderPowerShellString(options.collectorId || '1')}`,
        `$CollectorToken = ${renderPowerShellString(options.collectorToken || PLACEHOLDER_TOKEN)}`,
        `$CollectorHostname = ${renderPowerShellString(normalized.identity.display_name)}`,
        '$CollectorPrivateIp = ""',
        '$CollectorPublicIp = ""',
        '$CollectorSoftwareVersion = "0.1.0"',
        '$CollectorStatus = "active"',
        '$CollectorPlatform = "windows"',
        `$CollectorPurpose = ${renderPowerShellString(normalized.identity.purpose)}`,
        `$CollectorCapabilities = @(${capabilities})`,
        `$RemoteDiagnosticsEnabled = ${normalized.features.remote_diagnostics ? '$true' : '$false'}`,
        `$DiagnosticPollIntervalSeconds = ${normalized.settings.diagnostic_poll_interval_seconds}`,
        `$DiagnosticCommandLimit = ${normalized.settings.diagnostic_command_limit}`,
        `$DiagnosticAllowPublicTargets = ${normalized.settings.diagnostic_allow_public_targets ? '$true' : '$false'}`,
        `$DiagnosticAllowHostnames = ${normalized.settings.diagnostic_allow_hostnames ? '$true' : '$false'}`,
        `$DiagnosticDefaultDnsQuery = ${renderPowerShellString(normalized.settings.diagnostic_default_dns_query)}`,
        `$DiagnosticInternetPingTarget = ${renderPowerShellString(normalized.settings.diagnostic_internet_ping_target)}`,
        `$DiagnosticInternetTestUrl = ${renderPowerShellString(normalized.settings.diagnostic_internet_test_url)}`,
        `$RemoteManagementMode = ${renderPowerShellString(normalized.settings.remote_management_mode)}`,
        `$RemoteManagementProfileLabel = ${renderPowerShellString(normalized.settings.remote_management_profile_label)}`,
        `$AiHelperEnabled = ${normalized.features.ai_helper ? '$true' : '$false'}`,
        `$AiTimeoutMs = ${normalized.settings.ai_timeout_ms}`,
        `$AiMaxTokens = ${normalized.settings.ai_max_tokens}`
    ];

    return `${lines.join('\n')}\n`;
}

function getProfileUiSchema(role = 'viewer') {
    const editable = new Set(listEditableProfilePaths(role));
    return {
        role: normalizeRole(role),
        profile_version: COLLECTOR_PROFILE_VERSION,
        paths: getKnownProfilePaths().map((path) => {
            const settingKey = path.startsWith('settings.') ? path.slice('settings.'.length) : null;
            return {
                path,
                editable: editable.has(path),
                definition: settingKey ? SETTING_DEFINITIONS[settingKey] : null
            };
        })
    };
}

module.exports = {
    COLLECTOR_PLATFORMS,
    COLLECTOR_PROFILE_VERSION,
    COLLECTOR_ROLES,
    REMOTE_MANAGEMENT_MODES,
    SETTING_DEFINITIONS,
    TLS_MODES,
    USER_ROLES,
    applyCollectorProfilePatch,
    buildCollectorCapabilities,
    canEditCollectorProfilePath,
    createDefaultCollectorProfile,
    getKnownProfilePaths,
    getProfileUiSchema,
    listEditableProfilePaths,
    normalizeCollectorProfile,
    renderUbuntuEnv,
    renderWindowsEnv
};
