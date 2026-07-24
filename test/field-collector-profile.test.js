const test = require('node:test');
const assert = require('node:assert/strict');

const {
    applyCollectorProfilePatch,
    buildCollectorCapabilities,
    canEditCollectorProfilePath,
    createDefaultCollectorProfile,
    getProfileUiSchema,
    normalizeCollectorProfile,
    renderUbuntuEnv,
    renderWindowsEnv
} = require('../collector/common/field-collector-profile');

test('default profile is valid and normalized for ubuntu collectors', () => {
    const result = normalizeCollectorProfile(createDefaultCollectorProfile({
        display_name: 'dongshin-field-collector',
        platform: 'ubuntu'
    }));

    assert.equal(result.valid, true);
    assert.equal(result.profile.identity.display_name, 'dongshin-field-collector');
    assert.equal(result.profile.identity.platform, 'ubuntu');
    assert.equal(result.profile.features.heartbeat, true);
    assert.equal(result.profile.settings.heartbeat_interval_seconds, 60);
    assert.equal(result.profile.settings.remote_management_mode, 'none');
});

test('settings are clamped to safe editable ranges', () => {
    const result = normalizeCollectorProfile({
        identity: { display_name: 'collector-a' },
        targets: { nms_base_url: 'https://nms.example.com:7443/' },
        settings: {
            heartbeat_interval_seconds: 2,
            diagnostic_command_limit: 100,
            edge_disk_warn_pct: 98,
            edge_disk_danger_pct: 60,
            ai_max_tokens: 99999
        }
    });

    assert.equal(result.valid, true);
    assert.equal(result.profile.targets.nms_base_url, 'https://nms.example.com:7443');
    assert.equal(result.profile.settings.heartbeat_interval_seconds, 15);
    assert.equal(result.profile.settings.diagnostic_command_limit, 10);
    assert.equal(result.profile.settings.edge_disk_danger_pct, 99);
    assert.equal(result.profile.settings.ai_max_tokens, 4000);
    assert.match(result.warnings.join('\n'), /minimum 15/);
    assert.match(result.warnings.join('\n'), /maximum 10/);
});

test('invalid nms target is rejected before deployment', () => {
    const result = normalizeCollectorProfile({
        targets: {
            nms_base_url: '192.168.1.33:7443'
        }
    });

    assert.equal(result.valid, false);
    assert.match(result.errors.join('\n'), /http/);
});

test('field collector profile rejects a loopback NMS target', () => {
    const result = normalizeCollectorProfile({
        targets: {
            nms_base_url: 'https://127.0.0.1:7443'
        }
    });

    assert.equal(result.valid, false);
    assert.match(result.errors.join('\n'), /localhost or 127\.0\.0\.1/);
});

test('operator can tune runtime settings but cannot change ingress target or raw capture policy', () => {
    const current = createDefaultCollectorProfile();
    const result = applyCollectorProfilePatch(current, {
        targets: { nms_base_url: 'https://public.example.com:7443' },
        settings: {
            diagnostic_poll_interval_seconds: 30,
            diagnostic_allow_raw_tcpdump_filter: true
        },
        features: {
            edge_analysis: false
        }
    }, 'operator');

    assert.equal(result.profile.targets.nms_base_url, 'https://112.167.190.125:7443');
    assert.equal(result.profile.settings.diagnostic_poll_interval_seconds, 30);
    assert.equal(result.profile.settings.diagnostic_allow_raw_tcpdump_filter, false);
    assert.equal(result.profile.features.edge_analysis, false);
    assert.deepEqual(result.denied, [
        'settings.diagnostic_allow_raw_tcpdump_filter',
        'targets.nms_base_url'
    ]);
});

test('field technician can edit labels and local diagnostic defaults only', () => {
    const current = createDefaultCollectorProfile();
    const result = applyCollectorProfilePatch(current, {
        identity: {
            display_name: 'onsite-mini-pc',
            collector_role: 'hybrid'
        },
        settings: {
            diagnostic_default_dns_query: 'daum.net',
            snmp_retries: 4
        },
        metadata: {
            notes: 'temporary customer visit',
            tags: ['visit', 'urgent', 'visit']
        }
    }, 'field_technician');

    assert.equal(result.profile.identity.display_name, 'onsite-mini-pc');
    assert.equal(result.profile.identity.collector_role, 'agent');
    assert.equal(result.profile.settings.diagnostic_default_dns_query, 'daum.net');
    assert.equal(result.profile.settings.snmp_retries, 1);
    assert.deepEqual(result.profile.metadata.tags, ['visit', 'urgent']);
    assert.deepEqual(result.denied, [
        'identity.collector_role',
        'settings.snmp_retries'
    ]);
});

test('viewer cannot edit collector profile values', () => {
    const result = applyCollectorProfilePatch(createDefaultCollectorProfile(), {
        identity: { display_name: 'blocked' }
    }, 'viewer');

    assert.equal(result.profile.identity.display_name, 'nms-field-collector');
    assert.deepEqual(result.allowed, []);
    assert.deepEqual(result.denied, ['identity.display_name']);
});

test('ui schema exposes editable paths by current user role', () => {
    const operatorSchema = getProfileUiSchema('operator');
    const rawCapture = operatorSchema.paths.find((item) => item.path === 'settings.diagnostic_allow_raw_tcpdump_filter');
    const heartbeatInterval = operatorSchema.paths.find((item) => item.path === 'settings.heartbeat_interval_seconds');

    assert.equal(rawCapture.editable, false);
    assert.equal(heartbeatInterval.editable, true);
    assert.equal(heartbeatInterval.definition.min, 15);
    assert.equal(canEditCollectorProfilePath('admin', 'targets.nms_base_url'), true);
});

test('env renderers share the same normalized profile and keep token as placeholder by default', () => {
    const profile = normalizeCollectorProfile({
        identity: {
            display_name: 'site-a collector',
            platform: 'ubuntu',
            collector_role: 'hybrid',
            purpose: 'customer field diagnosis'
        },
        targets: {
            nms_base_url: 'https://112.167.190.125:7443',
            tls_mode: 'insecure'
        },
        features: {
            rsyslog_relay: true,
            snmptrap_relay: true,
            ai_helper: true
        },
        settings: {
            diagnostic_poll_interval_seconds: 20,
            rsyslog_target_protocol: 'tcp',
            remote_management_mode: 'omada_vpn',
            remote_management_profile_label: 'site-a-vpn'
        }
    }).profile;

    assert.deepEqual(buildCollectorCapabilities(profile), [
        'heartbeat',
        'diagnostics',
        'edge-analysis',
        'packet-capture',
        'syslog',
        'trap',
        'ai-helper'
    ]);

    const ubuntuEnv = renderUbuntuEnv(profile);
    assert.match(ubuntuEnv, /NMS_URL=https:\/\/112\.167\.190\.125:7443/);
    assert.match(ubuntuEnv, /COLLECTOR_TOKEN=replace-with-agent-token/);
    assert.match(ubuntuEnv, /COLLECTOR_ROLE=hybrid/);
    assert.match(ubuntuEnv, /RSYSLOG_TARGET_PROTOCOL=tcp/);
    assert.match(ubuntuEnv, /REMOTE_MANAGEMENT_MODE=omada_vpn/);
    assert.match(ubuntuEnv, /REMOTE_MANAGEMENT_PROFILE_LABEL=site-a-vpn/);
    assert.match(ubuntuEnv, /WIREGUARD_INTERFACE=metro-omada/);
    assert.match(ubuntuEnv, /WIREGUARD_HANDSHAKE_STALE_SECONDS=180/);
    assert.match(ubuntuEnv, /DIAGNOSTIC_INTERNET_TEST_URL=https:\/\/www\.naver\.com\//);

    const windowsEnv = renderWindowsEnv(profile);
    assert.match(windowsEnv, /\$NmsUrl = "https:\/\/112\.167\.190\.125:7443"/);
    assert.match(windowsEnv, /\$CollectorToken = "replace-with-agent-token"/);
    assert.match(windowsEnv, /\$AiHelperEnabled = \$true/);
});

test('windows relay profile warns that production relay should stay on ubuntu for now', () => {
    const result = normalizeCollectorProfile({
        identity: {
            platform: 'windows',
            collector_role: 'hybrid'
        },
        features: {
            rsyslog_relay: true,
            snmptrap_relay: true
        }
    });

    assert.equal(result.valid, true);
    assert.match(result.warnings.join('\n'), /windows collector relay features are planned/);
});
