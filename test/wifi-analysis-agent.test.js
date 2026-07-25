const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
    IncidentWindowManager,
    NmsRequestError,
    TimeRingBuffer,
    attachMeasurementContext,
    buildBatch,
    classifyIncident,
    enteredMeasurementSession,
    frequencyToChannel,
    flushQueue,
    normalSampleKey,
    parseDefaultGateway,
    parseIwChannelWidth,
    parseIwLink,
    parsePingOutput,
    parseRouteVerification,
    readActiveMeasurementSession,
    resolveNmsBaseUrl,
    measurementRfProfiles,
    splitRecordsIntoBatches
} = require('../collector/ubuntu/nms-wifi-analysis');

test('Wi-Fi analysis service can update simultaneous measurement session stats', () => {
    const unit = fs.readFileSync(
        path.join(__dirname, '../collector/ubuntu/systemd/nms-wifi-analysis.service'),
        'utf8'
    );
    assert.match(
        unit,
        /ReadWritePaths=.*\/var\/lib\/nms-collector\/measurement-sessions/
    );
});

test('resolves the existing collector NMS_URL contract before legacy aliases', () => {
    assert.equal(resolveNmsBaseUrl({
        NMS_URL: 'https://metrocom.kr:7443/',
        NMS_BASE_URL: 'http://ignored.example'
    }), 'https://metrocom.kr:7443');
    assert.equal(resolveNmsBaseUrl({
        NMS_SCHEME: 'https',
        NMS_HOST: 'nms.example',
        NMS_PORT: '7443',
        NMS_PATH: '/collector/'
    }), 'https://nms.example:7443/collector');
});

test('parses successful and failed ping output without inventing latency', () => {
    assert.deepEqual(parsePingOutput('64 bytes: time=12.3 ms\n1 transmitted, 1 received, 0% packet loss'), {
        success: true, latency_ms: 12.3, packet_loss_pct: 0
    });
    assert.deepEqual(parsePingOutput('1 transmitted, 0 received, 100% packet loss'), {
        success: false, latency_ms: null, packet_loss_pct: 100
    });
});

test('parses iw link evidence and keeps unavailable SNR null', () => {
    const row = parseIwLink(`Connected to 5c:62:8b:07:c3:ce (on wlan0)
\tSSID: metro
\tfreq: 2437
\tsignal: -67 dBm
\trx bitrate: 1.0 MBit/s
\ttx bitrate: 51.6 MBit/s`, 'wlan0', '2026-07-24T00:00:00.000Z');
    assert.equal(row.bssid, '5c:62:8b:07:c3:ce');
    assert.equal(row.channel, 6);
    assert.equal(row.signal_dbm, -67);
    assert.equal(row.snr_db, null);
    assert.equal(row.tx_link_mbps, 51.6);
});

test('parses channel width, gateway and bound route evidence', () => {
    assert.equal(parseIwChannelWidth('Interface wlan0\n\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz', 'wlan0'), 20);
    assert.equal(parseRouteVerification('8.8.8.8 via 192.168.1.1 dev wlan0 src 192.168.1.20', 'wlan0'), true);
    assert.equal(parseRouteVerification('8.8.8.8 via 192.168.11.1 dev eth0', 'wlan0'), false);
    assert.equal(parseDefaultGateway('[{"dst":"default","gateway":"192.168.1.1","dev":"wlan0"}]'), '192.168.1.1');
});

test('maps 2.4, 5 and 6 GHz frequencies to channels', () => {
    assert.equal(frequencyToChannel(2437), 6);
    assert.equal(frequencyToChannel(5180), 36);
    assert.equal(frequencyToChannel(5955), 1);
});

test('incident buffer preserves the full pre and post window', () => {
    const ring = new TimeRingBuffer(15 * 60 * 1000);
    for (let second = 0; second <= 20; second += 1) {
        ring.add({ kind: 'connectivity', observed_at: new Date(second * 1000).toISOString(), success: second !== 10 });
    }
    const manager = new IncidentWindowManager({ preMs: 5000, postMs: 5000, cooldownMs: 0 });
    manager.trigger('packet_loss_burst', { count: 3 }, new Date(10000).toISOString());
    const completed = manager.collectCompleted(ring, 15000);
    assert.equal(completed.length, 1);
    assert.equal(completed[0].records.length, 11);
    assert.equal(completed[0].records[0].observed_at, new Date(5000).toISOString());
});

test('classification distinguishes common path and wireless-only failures', () => {
    assert.equal(classifyIncident([
        { kind: 'connectivity', target_kind: 'google_dns', interface_role: 'wired', success: false },
        { kind: 'connectivity', target_kind: 'google_dns', interface_role: 'wireless', success: false }
    ], 'packet_loss_burst').classification, 'upstream_or_common_path');
    assert.equal(classifyIncident([
        { kind: 'connectivity', target_kind: 'google_dns', interface_role: 'wired', success: true },
        { kind: 'connectivity', target_kind: 'google_dns', interface_role: 'wireless', success: false }
    ], 'packet_loss_burst').classification, 'wireless_or_ap_path');
});

test('batch separates normalized sample families', () => {
    const sessionId = '2bb9b1a0-8322-4d4c-8781-c78d5654a366';
    const batch = buildBatch([
        { kind: 'connectivity', observed_at: '2026-07-24T00:00:00Z', measurement_session_id: sessionId },
        { kind: 'wifi', observed_at: '2026-07-24T00:00:01Z', measurement_session_id: sessionId },
        { kind: 'rf', observed_at: '2026-07-24T00:00:02Z', measurement_session_id: sessionId }
    ]);
    assert.equal(batch.measurement_session_id, sessionId);
    assert.equal(batch.connectivity_samples.length, 1);
    assert.equal(batch.wifi_samples.length, 1);
    assert.equal(batch.rf_sweeps.length, 1);
    assert.equal('measurement_session_id' in batch.wifi_samples[0], false);
});

test('active measurement session reader accepts running manifests only', () => {
    const directory = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'metro-session-state-'));
    const filePath = path.join(directory, 'active.json');
    fs.writeFileSync(filePath, JSON.stringify({
        measurement_session_id: '2bb9b1a0-8322-4d4c-8781-c78d5654a366',
        status: 'running',
        timezone: 'Asia/Seoul',
        module_runs: {
            wireless: {
                module_run_id: 'dfc71a60-7c2f-44cc-bad5-4c9be50ddc3a'
            }
        },
        ends_at: new Date(Date.now() + 60000).toISOString()
    }));
    const active = readActiveMeasurementSession(filePath);
    assert.equal(active.status, 'running');
    assert.equal(
        active.module_run_ids.wireless,
        'dfc71a60-7c2f-44cc-bad5-4c9be50ddc3a'
    );
    fs.writeFileSync(filePath, JSON.stringify({
        measurement_session_id: '2bb9b1a0-8322-4d4c-8781-c78d5654a366',
        status: 'paused'
    }));
    assert.equal(readActiveMeasurementSession(filePath), null);
});

test('a new measurement session resets periodic wireless and RF sampling', () => {
    const active = {
        measurement_session_id: '2bb9b1a0-8322-4d4c-8781-c78d5654a366'
    };
    assert.equal(enteredMeasurementSession(null, active), true);
    assert.equal(
        enteredMeasurementSession(active.measurement_session_id, active),
        false
    );
    assert.equal(enteredMeasurementSession(active.measurement_session_id, null), false);
});

test('measurement context maps selected modules and excludes unselected background samples', () => {
    const session = {
        measurement_session_id: '2bb9b1a0-8322-4d4c-8781-c78d5654a366',
        timezone: 'Asia/Seoul',
        module_run_ids: {
            wireless: 'dfc71a60-7c2f-44cc-bad5-4c9be50ddc3a'
        }
    };
    const wireless = attachMeasurementContext(
        {
            kind: 'wifi',
            observed_at: '2026-07-24T00:00:00.000Z',
            connected: true
        },
        session,
        new Date('2026-07-24T00:00:00.250Z')
    );
    assert.equal(wireless.measurement_session_id, session.measurement_session_id);
    assert.equal(wireless.module_run_id, session.module_run_ids.wireless);
    assert.equal(wireless.source_delay_ms, 250);
    assert.equal(wireless.sample_status, 'success');

    const unselectedRf = attachMeasurementContext(
        { kind: 'rf', observed_at: '2026-07-24T00:00:00.000Z' },
        session,
        new Date('2026-07-24T00:00:00.100Z')
    );
    assert.equal(unselectedRf.measurement_session_id, null);
    assert.equal(unselectedRf.module_run_id, null);
});

test('tinySA collector uses the ZS407 profile and hardware point limit', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'collector', 'ubuntu', 'nms-wifi-analysis.js'), 'utf8');
    assert.match(source, /tinySA Ultra\+ ZS407/);
    assert.match(source, /env\.TINYSA_POINTS, 290, 51, 450/);
    assert.match(source, /--device-model/);
});

test('simultaneous measurement cycles all network RF bands', () => {
    assert.deepEqual(
        measurementRfProfiles({}).map((profile) => profile.band),
        ['wifi_2_4ghz', 'wifi_5ghz', 'wifi_6ghz']
    );
    assert.deepEqual(
        measurementRfProfiles({ TINYSA_SESSION_BANDS: 'wifi_5ghz,wifi_2_4ghz' })
            .map((profile) => profile.band),
        ['wifi_2_4ghz', 'wifi_5ghz']
    );
    assert.equal(measurementRfProfiles({ TINYSA_SESSION_BANDS: 'unsupported' }).length, 0);
});

test('measurement stats preserve observed RF band coverage', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '..', 'collector', 'ubuntu', 'nms-wifi-analysis.js'),
        'utf8'
    );
    assert.match(source, /rf_bands: rfBands/);
    assert.match(source, /previous\.rf_bands/);
});

test('normal sample keys keep Wi-Fi and connectivity downsampling independent', () => {
    assert.equal(normalSampleKey({
        kind: 'connectivity',
        interface_role: 'wireless',
        target_kind: 'gateway'
    }), 'connectivity:wireless:gateway');
    assert.equal(normalSampleKey({
        kind: 'wifi',
        interface_name: 'wlan0'
    }), 'wifi:wlan0');
    assert.equal(normalSampleKey({ kind: 'rf' }), null);
});

test('large incident windows are split to central ingestion limits', () => {
    const records = [
        ...Array.from({ length: 1601 }, (_, index) => ({ kind: 'connectivity', index })),
        ...Array.from({ length: 401 }, (_, index) => ({ kind: 'wifi', index })),
        ...Array.from({ length: 41 }, (_, index) => ({ kind: 'rf', index }))
    ];
    const parts = splitRecordsIntoBatches(records);
    assert.equal(parts.length, 3);
    assert.ok(parts.every((part) => part.filter((item) => item.kind === 'connectivity').length <= 800));
    assert.ok(parts.every((part) => part.filter((item) => item.kind === 'wifi').length <= 200));
    assert.ok(parts.every((part) => part.filter((item) => item.kind === 'rf').length <= 20));
});

test('HTTP errors retain the server detail needed for field diagnosis', () => {
    const error = new NmsRequestError(
        500,
        JSON.stringify({ error: 'Internal server error', detail: 'scope_key is required' })
    );
    assert.equal(error.statusCode, 500);
    assert.match(error.message, /scope_key is required/);
});

test('permanently invalid batches are quarantined without blocking later batches', async () => {
    const stateDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'metro-wifi-queue-'));
    const queueDir = path.join(stateDir, 'queue');
    fs.mkdirSync(queueDir, { recursive: true });
    fs.writeFileSync(path.join(queueDir, '01-invalid.json'), JSON.stringify({ batch_id: 'invalid' }));
    fs.writeFileSync(path.join(queueDir, '02-valid.json'), JSON.stringify({ batch_id: 'valid' }));
    const env = {
        NMS_URL: 'https://nms.example',
        COLLECTOR_ID: '18',
        COLLECTOR_TOKEN: 'test-token'
    };
    const result = await flushQueue(stateDir, env, {
        requestJson: async (_url, payload) => {
            if (payload.batch_id === 'invalid') throw new NmsRequestError(400, '{"detail":"bad payload"}');
            return { status_code: 201 };
        }
    });
    assert.deepEqual(result, { sent: 1, pending: 0, invalid: 1 });
    assert.equal(fs.existsSync(path.join(stateDir, 'invalid', '01-invalid.json')), true);
    assert.equal(fs.existsSync(path.join(queueDir, '02-valid.json')), false);
});
