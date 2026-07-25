const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
    aggregateMeasurementMetric,
    analyzeEdgeSnapshot,
    buildSwitchTopology,
    buildConnectivityAssessment,
    buildDiagnosticResultExcerpt,
    buildHeartbeatPayload,
    buildPulseLocalStatusPayload,
    calculateCpuUsedPct,
    calculateIpv4Subnet,
    collectPrimaryNetwork,
    collectLldpSnapshot,
    collectWireGuardStatus,
    getTcpdumpFilter,
    getRemoteManagementSettings,
    inferCollectorRole,
    inspectCollectorEnv,
    inspectLocalServices,
    isAllowedDiagnosticHost,
    isPrivateIpv4Address,
    parseEnvFileContents,
    parseDfOutput,
    parseIpNeighborSummary,
    parseTsharkDetailRows,
    parseTsharkPacketRows,
    parsePulseLocalStatusResponse,
    parseSnmpOidTable,
    parseTcpTarget,
    normalizeFieldMeasurementProfile,
    buildQueuedFieldMeasurement,
    buildQueuedFieldSnapshot,
    buildCollectionSourceStatus,
    buildDiagnosticSnapshotSession,
    persistQueuedFieldMeasurement,
    listQueuedFieldMeasurements,
    readSystemctlState,
    renderRsyslogConfig,
    resolveNmsUrl,
    finalizeMeasurementMetrics,
    summarizePingStep
} = require('../collector/ubuntu/nms-collector');

test('field measurement profile requires independent site and contact data', () => {
    const profile = normalizeFieldMeasurementProfile({
        site_id: 17,
        customer_id: 9,
        site_name: '테스트 현장',
        customer_name: '테스트 고객',
        metro_contact: { name: '메트로 담당자', phone: '010-0000-0000' },
        customer_contact: { name: '고객사 담당자', phone: '010-0000-0001' }
    });

    assert.equal(profile.site_name, '테스트 현장');
    assert.equal(profile.site_id, 17);
    assert.equal(profile.customer_id, 9);
    assert.equal(profile.customer_name, '테스트 고객');
    assert.throws(
        () => normalizeFieldMeasurementProfile({
            site_id: '잘못된 값',
            site_name: '테스트 현장',
            metro_contact: { name: '메트로 담당자', phone: '010-0000-0000' },
            customer_contact: { name: '고객사 담당자', phone: '010-0000-0001' }
        }),
        /site_id must be a positive integer/
    );
    assert.throws(() => normalizeFieldMeasurementProfile({ site_name: '누락' }), /metro contact/);
});

test('field measurement queue persists a pending item without a server connection', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'metro-field-queue-'));
    try {
        const env = { FIELD_MEASUREMENT_QUEUE_DIR: root };
        const item = buildQueuedFieldMeasurement({
            site_name: '오프라인 현장',
            metro_contact: { name: '메트로', phone: '010-0000-0000' },
            customer_contact: { name: '고객', phone: '010-0000-0001' }
        }, {
            started_at: '2026-07-21T00:00:00.000Z',
            ended_at: '2026-07-21T00:00:10.000Z',
            metrics: []
        }, new Date(), '2bb9b1a0-8322-4d4c-8781-c78d5654a366');
        assert.equal(item.measurement_session_id, '2bb9b1a0-8322-4d4c-8781-c78d5654a366');
        persistQueuedFieldMeasurement(env, item);

        const rows = listQueuedFieldMeasurements(env);
        assert.equal(rows.length, 1);
        assert.equal(rows[0].state, 'pending');
        assert.equal(rows[0].site_name, '오프라인 현장');
        assert.equal(rows[0].client_session_id, item.client_session_id);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('diagnostic snapshot keeps full local evidence and bounded central metrics', () => {
    const observedAt = '2026-07-23T01:02:03.000Z';
    const snapshot = {
        collected_at: observedAt,
        hostname: 'metro-agent',
        loadavg: [0.25, 0.2, 0.1],
        memory: { used_pct: 42.5 },
        disks: [{ mount: '/', use_pct: 31 }],
        services: { heartbeatTimer: { active: 'active', enabled: 'enabled' } },
        tools: { ping: true, dig: true, tshark: true, tcpdump: true },
        network: {
            default_gateway: '192.168.11.1',
            primary_network: { interface: 'enp1s0', address: '192.168.11.2', prefix_length: 25 },
            vpn: { configured: true, state: 'connected' },
            interfaces: [{ name: 'enp1s0', state: 'UP', addresses: [] }],
            neighbors: { total: 3, state_counts: { reachable: 3 }, entries: [] },
            observed_vlans: { enabled: true, vlan_ids: [10, 20], frame_count: 2 },
            lldp: { available: true, neighbor_count: 1, neighbors: [] },
            wireless: { available: true, radios: ['wlan0'], access_point_count: 4, channel_counts: { 1: 2 } },
            listeners: {
                syslog_udp: { listening: true }, snmp_trap: { listening: true },
                netflow: { listening: false }, ipfix: { listening: false }, sflow: { listening: false }
            },
            network_device_snmp: { enabled: true, target_count: 2, target_up_count: 1, target_down_count: 1 }
        }
    };
    const sourceStatus = buildCollectionSourceStatus(snapshot, {});
    const session = buildDiagnosticSnapshotSession(snapshot, { severity: 'ok', finding_count: 0, findings: [] }, sourceStatus);
    const queueItem = buildQueuedFieldSnapshot({
        site_name: '이동 현장',
        metro_contact: { name: '메트로', phone: '010-0000-0000' },
        customer_contact: { name: '고객', phone: '010-0000-0001' }
    }, session, { snapshot });

    assert.equal(queueItem.session_kind, 'diagnostic_snapshot');
    assert.equal(queueItem.local_evidence.snapshot.network.wireless.access_point_count, 4);
    assert.equal(session.source, 'ubuntu_collector_diagnostic_snapshot');
    assert.equal(session.diagnostic_snapshot.source_status.syslog.state, 'active');
    assert.equal(session.diagnostic_snapshot.source_status.netflow.state, 'unavailable');
    assert.equal(session.metrics.find((item) => item.metric_key === 'lldp_neighbor_count').latest_value, 1);
    assert.equal(session.metrics.every((item) => item.attempted_count === item.successful_count + item.failed_count), true);
});

test('LLDP snapshot preserves actual keyed chassis names and CDP protocol', () => {
    const payload = {
        lldp: {
            interface: {
                eth0: {
                    via: 'CDPv2', age: '0 day, 00:00:20',
                    chassis: {
                        'Cisco-Core': {
                            id: { type: 'mac', value: '00:11:22:33:44:55' },
                            descr: 'Cisco IOS', 'mgmt-ip': '10.0.0.2'
                        }
                    },
                    port: { id: { type: 'ifname', value: 'Gi1/0/1' }, descr: 'uplink', ttl: '180' }
                }
            }
        }
    };
    const snapshot = collectLldpSnapshot((command) => {
        assert.equal(command, 'lldpcli');
        return JSON.stringify(payload);
    });

    assert.equal(snapshot.neighbor_count, 1);
    assert.equal(snapshot.protocol_counts.CDPV2, 1);
    assert.equal(snapshot.neighbors[0].protocol, 'CDPV2');
    assert.equal(snapshot.neighbors[0].chassis_name, 'Cisco-Core');
    assert.equal(snapshot.neighbors[0].management_ip, '10.0.0.2');
    assert.equal(snapshot.neighbors[0].port_id, 'Gi1/0/1');
});

test('measurement aggregates reconcile success failures and min average max', () => {
    const rows = new Map();
    const definition = { metric_key: 'gateway_latency_ms', metric_label: '게이트웨이 지연', target: '192.168.1.1', unit: 'ms', source: 'icmp_ping' };
    aggregateMeasurementMetric(rows, definition, 1, '2026-07-20T10:00:00.000Z');
    aggregateMeasurementMetric(rows, definition, null, '2026-07-20T10:00:02.000Z');
    aggregateMeasurementMetric(rows, definition, 5, '2026-07-20T10:00:04.000Z');
    const metric = finalizeMeasurementMetrics(rows)[0];
    assert.equal(metric.attempted_count, 3);
    assert.equal(metric.successful_count, 2);
    assert.equal(metric.failed_count, 1);
    assert.equal(metric.min_value, 1);
    assert.equal(metric.avg_value, 3);
    assert.equal(metric.max_value, 5);
    assert.equal(metric.latest_value, 5);
});

test('CPU percentage uses counter deltas instead of load average', () => {
    assert.equal(calculateCpuUsedPct({ idle: 100, total: 200 }, { idle: 130, total: 300 }), 70);
    assert.equal(calculateCpuUsedPct({ idle: 100, total: 200 }, { idle: 100, total: 200 }), null);
});

test('parseTsharkPacketRows builds bounded traffic statistics', () => {
    const rows = [
        ['1000.000', '100', '00:11:22:33:44:55', 'ff:ff:ff:ff:ff:ff', '192.168.1.10', '192.168.1.255', '', '', 'ARP', '', '', '', '', '10'],
        ['1001.000', '200', '00:11:22:33:44:55', '00:aa:bb:cc:dd:ee', '192.168.1.10', '8.8.8.8', '', '', 'DNS', '', '', '53000', '53', '10'],
        ['1002.000', '300', '00:aa:bb:cc:dd:ee', '01:00:5e:00:00:fb', '', '', 'fe80::1', 'ff02::fb', 'MDNS', '', '', '5353', '5353', '20']
    ].map((row) => row.join('\t')).join('\n');
    const summary = parseTsharkPacketRows(rows);

    assert.equal(summary.packet_count, 3);
    assert.equal(summary.byte_count, 600);
    assert.equal(summary.broadcast_count, 1);
    assert.equal(summary.multicast_count, 1);
    assert.equal(summary.arp_count, 1);
    assert.equal(summary.mdns_count, 1);
    assert.equal(summary.flood_summary.status, 'insufficient_data');
    assert.equal(summary.flood_summary.counts.mdns, 1);
    assert.match(summary.flood_summary.scope_notice, /SPAN/);
    assert.equal(summary.link_layer_visibility, true);
    assert.deepEqual(summary.vlan_ids, [10, 20]);
    assert.equal(summary.top_protocols[0].count, 1);
    assert.equal(summary.observed_duration_seconds, 2);
    assert.equal(summary.packets_per_second, 1.5);
});

test('parseTsharkPacketRows uses ARP protocol addresses when any interface hides Ethernet headers', () => {
    const row = ['1000.000', '84', '', '', '', '', '', '', 'ARP', '', '', '', '', '', '192.168.1.130', '192.168.1.1'].join('\t');
    const summary = parseTsharkPacketRows(row);

    assert.equal(summary.link_layer_visibility, false);
    assert.equal(summary.broadcast_count, 0);
    assert.deepEqual(summary.top_endpoints.map((item) => item.endpoint), ['192.168.1.1', '192.168.1.130']);
});

test('parseTsharkPacketRows classifies flooding protocols by UDP port', () => {
    const row = (epoch, protocol, sourcePort, destinationPort) => [
        epoch, '100', '00:11:22:33:44:55', '01:00:5e:00:00:fb',
        '192.168.1.10', '224.0.0.251', '', '', protocol,
        '', '', sourcePort, destinationPort, ''
    ].join('\t');
    const rows = [
        row('1000.000', 'UDP', '5353', '5353'),
        row('1001.000', 'UDP', '1900', '1900'),
        row('1002.000', 'UDP', '5355', '5355'),
        row('1003.000', 'UDP', '137', '137'),
        row('1006.000', 'UDP', '68', '67'),
        ...Array.from({ length: 15 }, (_, index) => row(String(1006.1 + index / 10), 'UDP', '5000', '5001'))
    ].join('\n');
    const summary = parseTsharkPacketRows(rows);

    assert.equal(summary.mdns_count, 1);
    assert.equal(summary.ssdp_count, 1);
    assert.equal(summary.llmnr_count, 1);
    assert.equal(summary.nbns_count, 1);
    assert.equal(summary.dhcp_count, 1);
    assert.equal(summary.flood_summary.status, 'no_candidate');
});

test('parseTsharkDetailRows counts errors and discovery evidence', () => {
    const rows = [
        ['1', '0', '0', '1', '', '', '', '', '', '', ''],
        ['', '', '', '', '0', '0', 'example.com', '', '', '', ''],
        ['', '', '', '', '1', '3', 'failed.example', '', '', '', ''],
        ['', '', '', '', '', '', '', '1', '', '', ''],
        ['', '', '', '', '', '', '', '', '3', '', ''],
        ['', '', '', '', '', '', '', '', '', 'access-switch', '']
    ].map((row) => row.join('\t')).join('\n');
    const summary = parseTsharkDetailRows(rows);

    assert.equal(summary.tcp_syn_count, 1);
    assert.equal(summary.tcp_retransmission_count, 1);
    assert.equal(summary.dns_query_count, 1);
    assert.equal(summary.dns_response_count, 1);
    assert.equal(summary.dns_error_count, 1);
    assert.equal(summary.arp_request_count, 1);
    assert.equal(summary.icmp_echo_request_count, 0);
    assert.equal(summary.icmp_echo_reply_count, 0);
    assert.equal(summary.icmp_unreachable_count, 1);
    assert.equal(summary.top_dns_queries[0].query, 'example.com');
    assert.equal(summary.discovery_devices[0].device, 'LLDP access-switch');
});

test('parseTsharkDetailRows does not treat empty ICMP fields as echo replies', () => {
    const rows = [
        ['1', '0', '0', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '1', '', '', '']
    ].map((row) => row.join('\t')).join('\n');
    const summary = parseTsharkDetailRows(rows);

    assert.equal(summary.icmp_echo_request_count, 0);
    assert.equal(summary.icmp_echo_reply_count, 0);
    assert.equal(summary.icmp_unreachable_count, 0);
});

test('parsePulseLocalStatusResponse accepts Pulse malformed CGI headers', () => {
    const payload = parsePulseLocalStatusResponse(Buffer.from(
        'HTTP/1.0 200 OK\r\napplication/json\n\n'
        + '{"poeStatus":"PoE voltage: 49.0 ","linkStatus":"Speed: 100\\nDuplex: full"}'
    ));

    assert.equal(payload.poeStatus, 'PoE voltage: 49.0 ');
    assert.match(payload.linkStatus, /100/);
});

test('buildPulseLocalStatusPayload records source timestamp and normalized values', () => {
    const payload = buildPulseLocalStatusPayload({
        poeStatus: 'PoE voltage: 49.0 ',
        linkStatus: 'Speed: 100\nDuplex: full',
        gatewayStatus: 'Ping (ICMP): 0.797ms, 0.580ms, 0.410ms'
    }, {
        PULSE_LOCAL_HOST: '192.168.1.129',
        PULSE_LOCAL_SERIAL_NUMBER: '3597063',
        COLLECTOR_HOSTNAME: 'field-collector-130'
    }, {
        collectorId: 18
    }, '2026-07-20T10:00:00.000Z');

    assert.equal(payload.ip, '192.168.1.129');
    assert.equal(payload.serial_number, '3597063');
    assert.equal(payload.poe_voltage_v, 49);
    assert.equal(payload.link_speed_mbps, 100);
    assert.equal(payload.gateway_ping_ms, 0.596);
    assert.equal(payload.collection_source, 'ubuntu_collector_local_pulse_status');
    assert.equal(payload.source_measurement_at, '2026-07-20T10:00:00.000Z');
});

test('parseSnmpOidTable preserves multi-index suffixes', () => {
    const rows = parseSnmpOidTable('SNMPv2-SMI::mib-2.17.7.1.2.2.1.2.10.0.17.34.51.68.85 = INTEGER: 7\n', '1.3.6.1.2.1.17.7.1.2.2.1.2');
    assert.equal(rows.length, 0, 'symbolic OIDs are intentionally ignored');
    const numeric = parseSnmpOidTable('.1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.17.34.51.68.85 = INTEGER: 7\n', '1.3.6.1.2.1.17.7.1.2.2.1.2');
    assert.deepEqual(numeric[0].suffix, [10, 0, 17, 34, 51, 68, 85]);
});

test('buildSwitchTopology normalizes VLAN membership FDB LLDP STP and PoE', () => {
    const outputs = {
        '1.3.6.1.2.1.17.1.4.1.2': '.1.3.6.1.2.1.17.1.4.1.2.1 = INTEGER: 101\n.1.3.6.1.2.1.17.1.4.1.2.2 = INTEGER: 102\n',
        '1.3.6.1.2.1.17.2.15.1.3': '.1.3.6.1.2.1.17.2.15.1.3.1 = INTEGER: 5\n',
        '1.3.6.1.2.1.17.7.1.4.3.1.1': '.1.3.6.1.2.1.17.7.1.4.3.1.1.10 = STRING: users\n',
        '1.3.6.1.2.1.17.7.1.4.2.1.4': '.1.3.6.1.2.1.17.7.1.4.2.1.4.0.10 = Hex-STRING: C0\n',
        '1.3.6.1.2.1.17.7.1.4.2.1.5': '.1.3.6.1.2.1.17.7.1.4.2.1.5.0.10 = Hex-STRING: 80\n',
        '1.3.6.1.2.1.17.7.1.4.5.1.1': '.1.3.6.1.2.1.17.7.1.4.5.1.1.1 = INTEGER: 10\n',
        '1.3.6.1.2.1.17.7.1.2.2.1.2': '.1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.17.34.51.68.85 = INTEGER: 2\n',
        '1.0.8802.1.1.2.1.4.1.1.5': '.1.0.8802.1.1.2.1.4.1.1.5.0.1.1 = STRING: chassis-a\n',
        '1.0.8802.1.1.2.1.4.1.1.9': '.1.0.8802.1.1.2.1.4.1.1.9.0.1.1 = STRING: access-sw\n',
        '1.3.6.1.2.1.105.1.1.1.3': '.1.3.6.1.2.1.105.1.1.1.3.1.1 = INTEGER: 1\n',
        '1.3.6.1.2.1.105.1.1.1.6': '.1.3.6.1.2.1.105.1.1.1.6.1.1 = INTEGER: 3\n'
    };
    const topology = buildSwitchTopology({ host: '10.0.0.2', port: 161, version: '2c', community: 'test', timeout_seconds: 1, retries: 0 }, (_command, args) => {
        const oid = args.at(-1);
        return outputs[oid] || '';
    });
    assert.equal(topology.vlan_count, 1);
    assert.deepEqual(topology.vlans[0].untagged_ports, [1]);
    assert.deepEqual(topology.vlans[0].tagged_ports, [2]);
    assert.equal(topology.fdb[0].mac, '00:11:22:33:44:55');
    assert.equal(topology.fdb[0].if_index, 102);
    assert.equal(topology.lldp_neighbors[0].system_name, 'access-sw');
    assert.equal(topology.poe_ports[0].admin_enabled, true);
});

test('parseEnvFileContents keeps existing values and parses quoted assignments', () => {
    const parsed = parseEnvFileContents(`
NMS_HOST=10.0.0.5
COLLECTOR_TOKEN="abc 123"
`, {
        NMS_HOST: 'preexisting-host'
    });

    assert.equal(parsed.NMS_HOST, 'preexisting-host');
    assert.equal(parsed.COLLECTOR_TOKEN, 'abc 123');
});

test('resolveNmsUrl prefers explicit URL and otherwise builds from components', () => {
    assert.equal(resolveNmsUrl({
        NMS_URL: 'https://collector.example.com:8443/root/'
    }), 'https://collector.example.com:8443/root');

    assert.equal(resolveNmsUrl({
        NMS_SCHEME: 'http',
        NMS_HOST: '192.168.1.10',
        NMS_PORT: '7443',
        NMS_PATH: 'nms'
    }), 'http://192.168.1.10:7443/nms');
});

test('inspectCollectorEnv rejects placeholder token values', () => {
    const report = inspectCollectorEnv({
        ENV_FILE: __filename,
        NMS_HOST: '127.0.0.1',
        NMS_PORT: '7443',
        COLLECTOR_ID: '12',
        COLLECTOR_TOKEN: 'replace-with-agent-token'
    });

    assert.equal(report.ready, false);
    assert.match(report.errors.join('\n'), /placeholder/);
});

test('inspectCollectorEnv infers collector role from enabled relay features', () => {
    const report = inspectCollectorEnv({
        ENV_FILE: __filename,
        NMS_HOST: '127.0.0.1',
        NMS_PORT: '7443',
        COLLECTOR_ID: '12',
        COLLECTOR_TOKEN: 'real-secret',
        ENABLE_RSYSLOG_RELAY: 'true',
        ENABLE_SNMPTRAP_RELAY: 'false',
        RSYSLOG_TARGET_HOST: '192.168.1.20',
        RSYSLOG_TARGET_PORT: '5514',
        RSYSLOG_TARGET_PROTOCOL: 'tcp'
    });

    assert.equal(report.ready, true);
    assert.equal(report.collectorRole, 'syslog_gateway');
    assert.equal(report.rsyslog.protocol, 'tcp');
});

test('inspectCollectorEnv warns when explicit hybrid role lacks relay flags', () => {
    const report = inspectCollectorEnv({
        ENV_FILE: __filename,
        NMS_HOST: '127.0.0.1',
        NMS_PORT: '7443',
        COLLECTOR_ID: '12',
        COLLECTOR_TOKEN: 'real-secret',
        COLLECTOR_ROLE: 'hybrid',
        ENABLE_RSYSLOG_RELAY: 'false',
        ENABLE_SNMPTRAP_RELAY: 'false'
    });

    assert.equal(report.ready, true);
    assert.match(report.warnings.join('\n'), /hybrid/);
});

test('renderRsyslogConfig uses configured target host port and protocol', () => {
    const config = renderRsyslogConfig({
        RSYSLOG_TARGET_HOST: '192.168.1.20',
        RSYSLOG_TARGET_PORT: '5514',
        RSYSLOG_TARGET_PROTOCOL: 'tcp'
    });

    assert.match(config, /target="192\.168\.1\.20"/);
    assert.match(config, /port="5514"/);
    assert.match(config, /protocol="tcp"/);
});

test('readSystemctlState uses stdout from non-zero systemctl responses', () => {
    const state = readSystemctlState('is-enabled', 'nms-collector-heartbeat.timer', () => {
        const error = new Error('disabled');
        error.stdout = 'disabled\n';
        throw error;
    });

    assert.equal(state, 'disabled');
});

test('inspectLocalServices includes rsyslog and trap units only when enabled', () => {
    const calls = [];
    const services = inspectLocalServices({
        features: {
            rsyslogRelayEnabled: true,
            trapRelayEnabled: true,
            remoteDiagnosticsEnabled: true,
            edgeAnalysisEnabled: true
        }
    }, (command, args) => {
        calls.push(`${command} ${args.join(' ')}`);
        if (args[0] === 'is-active') {
            return 'active\n';
        }

        return 'enabled\n';
    });

    assert.equal(services.heartbeatTimer.active, 'active');
    assert.equal(services.rsyslog.enabled, 'enabled');
    assert.equal(services.trapForwarder.active, 'active');
    assert.equal(services.diagnosticWorker.active, 'active');
    assert.equal(services.edgeAnalysisTimer.active, 'active');
    assert.equal(calls.length, 10);
});

test('buildHeartbeatPayload normalizes metadata, feature flags, and omits blank IP values', () => {
    const payload = buildHeartbeatPayload({
        COLLECTOR_NAME: '메트로정보통신 네트워크 현장 분석기',
        COLLECTOR_HOSTNAME: 'site-a-agent',
        COLLECTOR_SOFTWARE_VERSION: '0.2.0',
        COLLECTOR_STATUS: 'active',
        COLLECTOR_PLATFORM: 'ubuntu',
        COLLECTOR_PURPOSE: 'hybrid relay',
        COLLECTOR_CAPABILITIES: 'heartbeat, syslog , trap',
        COLLECTOR_PRIVATE_IP: '',
        COLLECTOR_PUBLIC_IP: '',
        REMOTE_DIAGNOSTICS_ENABLED: 'true',
        EDGE_SERVER_MODE: 'true',
        EDGE_ANALYSIS_ENABLED: 'true',
        EDGE_AI_ENABLED: 'true',
        REMOTE_MANAGEMENT_MODE: 'omada_vpn',
        REMOTE_MANAGEMENT_PROFILE_LABEL: 'field-site-a'
    }, {
        privateIp: '',
        hostname: 'ignored-host'
    });

    assert.equal(payload.name, '메트로정보통신 네트워크 현장 분석기');
    assert.equal(payload.hostname, 'site-a-agent');
    assert.equal(payload.software_version, '0.2.0');
    assert.deepEqual(payload.metadata.capabilities, ['heartbeat', 'syslog', 'trap', 'diagnostics', 'edge-analysis']);
    assert.equal(payload.metadata.features.remote_diagnostics, true);
    assert.equal(payload.metadata.features.edge_server, true);
    assert.equal(payload.metadata.features.edge_analysis, true);
    assert.equal(payload.metadata.features.edge_ai, true);
    assert.deepEqual(payload.metadata.remote_management, {
        mode: 'omada_vpn',
        profile_label: 'field-site-a',
        collection_dependency: false
    });
    assert.equal(payload.metadata.vpn.configured, true);
    assert.equal(payload.metadata.vpn.interface, 'metro-omada');
    assert.equal('private_ip' in payload, false);
    assert.equal('public_ip' in payload, false);
});

test('mobile collectors prefer the active route address over a stale configured private IP', () => {
    const payload = buildHeartbeatPayload({
        COLLECTOR_PRIVATE_IP: '192.168.1.130',
        COLLECTOR_PRIVATE_IP_OVERRIDE: 'false'
    }, {
        primaryNetwork: { address: '192.168.11.130' }
    });

    assert.equal(payload.private_ip, '192.168.11.130');
});

test('primary network preserves the active interface IP prefix subnet and gateway', () => {
    const execFn = (_command, args) => {
        if (args.join(' ') === '-j -4 route get 1.1.1.1') {
            return JSON.stringify([{ dev: 'enp1s0', gateway: '172.20.16.1', prefsrc: '172.20.18.44' }]);
        }
        if (args.join(' ') === '-j -4 address show') {
            return JSON.stringify([{
                ifname: 'enp1s0',
                addr_info: [{ family: 'inet', local: '172.20.18.44', prefixlen: 22, scope: 'global' }]
            }]);
        }
        throw new Error(`unexpected command: ${args.join(' ')}`);
    };

    assert.equal(calculateIpv4Subnet('172.20.18.44', 22), '172.20.16.0');
    assert.deepEqual(collectPrimaryNetwork(execFn), {
        interface: 'enp1s0',
        address: '172.20.18.44',
        prefixlen: 22,
        cidr: '172.20.18.44/22',
        subnet: '172.20.16.0/22',
        default_gateway: '172.20.16.1'
    });
});

test('WireGuard status records handshake freshness without exposing peer details', () => {
    const nowMs = Date.parse('2026-07-21T09:00:00.000Z');
    const execFn = (command, args) => {
        const input = `${command} ${args.join(' ')}`;
        if (input === 'ip -j link show dev metro-omada') {
            return JSON.stringify([{ ifname: 'metro-omada' }]);
        }
        if (input === 'ip -j -4 address show dev metro-omada') {
            return JSON.stringify([{ addr_info: [{ family: 'inet', scope: 'global', local: '10.0.2.130' }] }]);
        }
        if (input === 'systemctl is-active wg-quick@metro-omada.service') {
            return 'active\n';
        }
        if (input === 'systemctl is-enabled wg-quick@metro-omada.service') {
            return 'enabled\n';
        }
        if (input === 'wg show metro-omada latest-handshakes') {
            return 'peer-key-redacted 1784624330\n';
        }
        throw new Error(`unexpected command: ${input}`);
    };

    const status = collectWireGuardStatus({
        REMOTE_MANAGEMENT_MODE: 'omada_vpn',
        WIREGUARD_INTERFACE: 'metro-omada',
        WIREGUARD_HANDSHAKE_STALE_SECONDS: '180'
    }, execFn, nowMs);

    assert.equal(status.state, 'active');
    assert.equal(status.address, '10.0.2.130');
    assert.equal(status.handshake_age_seconds, 70);
    assert.equal('peer' in status, false);
});

test('remote management defaults to none and never becomes a collection dependency', () => {
    assert.deepEqual(getRemoteManagementSettings({}), {
        mode: 'none',
        requestedMode: 'none',
        profileLabel: '',
        wireGuardInterface: null,
        handshakeStaleSeconds: 180,
        collectionDependency: false
    });
    assert.equal(getRemoteManagementSettings({
        REMOTE_MANAGEMENT_MODE: 'omada_vpn',
        REMOTE_MANAGEMENT_PROFILE_LABEL: 'customer-vpn'
    }).mode, 'omada_vpn');
});

test('inferCollectorRole falls back to ubuntu_agent when no relay feature is enabled', () => {
    assert.equal(inferCollectorRole({}, false, false), 'ubuntu_agent');
    assert.equal(inferCollectorRole({}, true, true), 'hybrid');
});

test('diagnostic host policy defaults to private IP, gateway, and NMS host only', () => {
    const env = {
        NMS_URL: 'https://112.167.190.125:7443',
        DIAGNOSTIC_ALLOW_PUBLIC_TARGETS: 'false',
        DIAGNOSTIC_ALLOW_HOSTNAMES: 'false'
    };

    assert.equal(isPrivateIpv4Address('192.168.1.1'), true);
    assert.equal(isPrivateIpv4Address('8.8.8.8'), false);
    assert.equal(isAllowedDiagnosticHost('gateway', env), true);
    assert.equal(isAllowedDiagnosticHost('192.168.1.1', env), true);
    assert.equal(isAllowedDiagnosticHost('112.167.190.125', env), true);
    assert.equal(isAllowedDiagnosticHost('8.8.8.8', env), false);
    assert.equal(isAllowedDiagnosticHost('example.com', env), false);
});

test('parseTcpTarget supports host:port and keeps public targets blocked by default', () => {
    const target = parseTcpTarget('192.168.1.1:80', {}, {
        NMS_URL: 'https://112.167.190.125:7443'
    });

    assert.deepEqual(target, { host: '192.168.1.1', port: 80 });
    assert.throws(() => parseTcpTarget('8.8.8.8:53', {}, {
        NMS_URL: 'https://112.167.190.125:7443'
    }), /not allowed/);
});

test('getTcpdumpFilter uses presets unless raw filters are explicitly enabled', () => {
    assert.equal(getTcpdumpFilter('mdns'), 'udp port 5353');
    assert.equal(getTcpdumpFilter('unknown'), 'arp or icmp or icmp6 or port 53 or port 67 or port 68 or udp port 5353 or ether proto 0x88cc or tcp port 7443');
    assert.equal(getTcpdumpFilter('dhcp'), 'port 67 or port 68');
    assert.match(getTcpdumpFilter('overview'), /or tcp$/);
    assert.equal(getTcpdumpFilter('unknown', { filter: 'host 192.168.1.1' }, {
        DIAGNOSTIC_ALLOW_RAW_TCPDUMP_FILTER: 'true'
    }), 'host 192.168.1.1');
});

test('buildDiagnosticResultExcerpt summarizes goal results and errors', () => {
    assert.equal(
        buildDiagnosticResultExcerpt({ command_type: 'goal' }, { goal: 'site-standard-check', step_count: 4, failed_steps: ['dns'] }),
        'site-standard-check: 1 failed of 4 steps'
    );
    assert.match(
        buildDiagnosticResultExcerpt({ command_type: 'ping' }, null, new Error('target blocked')),
        /ping failed: target blocked/
    );
});

test('connectivity assessment identifies ping-only firewall policy restrictions', () => {
    const assessment = buildConnectivityAssessment([
        { name: 'gateway-ping', ok: true },
        { name: 'internet-ping', ok: true },
        { name: 'dns-default', ok: true },
        { name: 'internet-https', ok: false },
        { name: 'nms-tcp', ok: true }
    ]);

    assert.equal(assessment.state, 'internet_service_restricted');
    assert.equal(assessment.cause_label, 'firewall_policy_session');
    assert.equal(assessment.confidence, 'high');
});

test('connectivity assessment accepts dual domestic and overseas ping evidence', () => {
    const assessment = buildConnectivityAssessment([
        { name: 'gateway-ping', ok: true },
        { name: 'internet-ping-kt', ok: true },
        { name: 'internet-ping-google', ok: true },
        { name: 'dns-default', ok: true },
        { name: 'internet-https', ok: true },
        { name: 'nms-tcp', ok: true }
    ]);
    assert.equal(assessment.state, 'healthy');
    assert.equal(assessment.facts.internet_ping_kt, true);
    assert.equal(assessment.facts.internet_ping_google, true);
});

test('summarizePingStep preserves target and normalized latency metrics', () => {
    const summary = summarizePingStep({
        result: {
            target: '168.126.63.1',
            target_label: '국내 KT DNS',
            stdout: '4 packets transmitted, 4 received, 0% packet loss\nrtt min/avg/max/mdev = 2.336/2.500/2.708/0.151 ms'
        }
    });
    assert.equal(summary.target, '168.126.63.1');
    assert.equal(summary.target_label, '국내 KT DNS');
    assert.equal(summary.packet_loss_pct, 0);
    assert.equal(summary.latency_avg_ms, 2.5);
    assert.equal(summary.jitter_ms, 0.151);
});

test('connectivity assessment keeps ambiguous total internet loss low confidence', () => {
    const assessment = buildConnectivityAssessment([
        { name: 'gateway-ping', ok: true },
        { name: 'internet-ping', ok: false },
        { name: 'dns-default', ok: false },
        { name: 'internet-https', ok: false },
        { name: 'nms-tcp', ok: false }
    ]);

    assert.equal(assessment.state, 'internet_unreachable');
    assert.equal(assessment.cause_label, 'isp_circuit');
    assert.equal(assessment.confidence, 'low');
    assert.equal(assessment.contradictory_evidence.length, 1);
});

test('parseDfOutput and parseIpNeighborSummary normalize edge snapshot inputs', () => {
    const disks = parseDfOutput(`Filesystem 1K-blocks Used Available Use% Mounted on
/dev/sda1 1000 900 100 90% /
tmpfs 100 1 99 1% /run
`);
    const neighbors = parseIpNeighborSummary(`192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE
192.168.1.99 dev eth0 FAILED
`);

    assert.equal(disks[0].mount, '/');
    assert.equal(disks[0].use_pct, 90);
    assert.equal(neighbors.total, 2);
    assert.equal(neighbors.state_counts.reachable, 1);
    assert.equal(neighbors.state_counts.failed, 1);
    assert.deepEqual(neighbors.entries[0], {
        ip_address: '192.168.1.1',
        address_family: 'ipv4',
        interface_name: 'eth0',
        mac_address: '00:11:22:33:44:55',
        state: 'reachable',
        is_router: true,
        raw_flags: ['router']
    });
    assert.equal(neighbors.entries[1].ip_address, '192.168.1.99');
    assert.equal(neighbors.entries[1].mac_address, null);
});

test('analyzeEdgeSnapshot reports disk memory gateway and arp findings', () => {
    const analysis = analyzeEdgeSnapshot({
        cpu_count: 2,
        loadavg: [6, 4, 2],
        memory: { used_pct: 96 },
        network: {
            default_gateway: null,
            neighbors: {
                state_counts: {
                    failed: 1,
                    incomplete: 1
                }
            }
        },
        disks: [
            { mount: '/', use_pct: 96 },
            { mount: '/data', use_pct: 70 }
        ],
        tools: {
            ping: true,
            traceroute: true,
            dig: true,
            tcpdump: false,
            ip: true,
            snmpget: false
        }
    });

    assert.equal(analysis.severity, 'danger');
    assert.match(analysis.summary, /disk usage critical/);
    assert(analysis.findings.some((finding) => finding.title === 'default gateway missing'));
    assert(analysis.findings.some((finding) => finding.title === 'diagnostic tools missing'));
});
