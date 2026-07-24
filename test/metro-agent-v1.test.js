const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
    buildBatch,
    executePlan,
    flushQueue,
    isRunDue,
    runOnce,
    validateConfig
} = require('../collector/ubuntu/metro-agent-v1');
const { parsePingOutput } = require('../collector/ubuntu/metro-agent-v1/plugins/ping');
const { parseTarget } = require('../collector/ubuntu/metro-agent-v1/plugins/tcp');
const { parseMeminfo } = require('../collector/ubuntu/metro-agent-v1/plugins/system');

function sampleConfig(overrides = {}) {
    return {
        schema_version: 'metro-agent-config-v1',
        collector_id: 17,
        revision: 3,
        enabled: true,
        interval_seconds: 60,
        checks: [{ key: 'system', type: 'system', target: null, timeout_ms: 5000, options: {} }],
        ...overrides
    };
}

test('Metro Agent config validation preserves server revision and checks', () => {
    const config = validateConfig(sampleConfig(), 17);
    assert.equal(config.revision, 3);
    assert.equal(config.checks[0].type, 'system');
    assert.throws(() => validateConfig(sampleConfig({ collector_id: 18 }), 17), /collector mismatch/);
});

test('Metro Agent batch carries source semantics and config revision', () => {
    const batch = buildBatch(sampleConfig(), [{
        result_id: 'system:uptime',
        check_key: 'system.uptime',
        check_type: 'system',
        status: 'success',
        observed_at: '2026-07-24T00:00:00.000Z',
        source: 'test',
        details: {}
    }], { COLLECTOR_HOSTNAME: 'field-130' }, new Date('2026-07-24T00:00:00.000Z'));
    assert.equal(batch.config_revision, 3);
    assert.equal(batch.hostname, 'field-130');
    assert.equal(batch.metadata.result_semantics, 'missing-is-not-zero');
    assert.match(batch.batch_id, /^[0-9a-f-]{36}$/);
});

test('plugin plan isolates one plugin failure from other checks', async () => {
    const results = await executePlan(sampleConfig({
        checks: [
            { key: 'ok', type: 'system' },
            { key: 'bad', type: 'ping', target: 'gateway' }
        ]
    }), {
        plugins: {
            system: { run: async () => [{ result_id: 'ok:1', check_key: 'ok', check_type: 'system', status: 'success' }] },
            ping: { run: async () => { throw new Error('probe failed'); } }
        }
    });
    assert.equal(results.length, 2);
    assert.equal(results[0].status, 'success');
    assert.equal(results[1].status, 'failure');
    assert.equal(results[1].error_code, 'plugin_failed');
});

test('runOnce caches config and retains failed uploads for later flush', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'metro-agent-v1-'));
    const env = {
        NMS_URL: 'http://127.0.0.1:7443',
        COLLECTOR_ID: '17',
        COLLECTOR_TOKEN: 'test-token',
        METRO_AGENT_V1_STATE_DIR: root
    };
    try {
        const result = await runOnce(env, {
            requestJson: async (url, options) => {
                if (options.method === 'GET') return sampleConfig();
                throw new Error('offline');
            },
            plugins: {
                system: {
                    run: async () => [{
                        result_id: 'system:uptime',
                        check_key: 'system.uptime',
                        check_type: 'system',
                        target: 'field-130',
                        status: 'success',
                        value: 100,
                        unit: 'seconds',
                        observed_at: new Date().toISOString(),
                        duration_ms: null,
                        source: 'test',
                        error_code: null,
                        details: {}
                    }]
                }
            }
        }, true);
        assert.equal(result.state, 'collected');
        assert.equal(result.delivery.pending, 1);
        assert.equal(fs.existsSync(path.join(root, 'config.json')), true);

        const delivery = await flushQueue(env, { collectorId: 17, token: 'test-token' }, {
            requestJson: async () => ({ duplicate: false, accepted_results: 1 })
        });
        assert.deepEqual(delivery, { delivered: 1, pending: 0 });
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('schedule gate respects profile interval', () => {
    const config = sampleConfig({ interval_seconds: 300 });
    assert.equal(isRunDue(config, { last_run_at: '2026-07-24T00:00:00.000Z' }, new Date('2026-07-24T00:04:59.000Z')), false);
    assert.equal(isRunDue(config, { last_run_at: '2026-07-24T00:00:00.000Z' }, new Date('2026-07-24T00:05:00.000Z')), true);
});

test('ping and TCP parsers retain units and endpoints', () => {
    const ping = parsePingOutput('4 packets transmitted, 4 received, 0% packet loss\nrtt min/avg/max/mdev = 1.1/2.2/3.3/0.4 ms');
    assert.equal(ping.packet_loss_pct, 0);
    assert.equal(ping.latency_avg_ms, 2.2);
    assert.deepEqual(parseTarget({ target: '10.0.0.1:443', options: {} }), { host: '10.0.0.1', port: 443 });
});

test('system memory uses Linux MemAvailable rather than treating cache as used', () => {
    assert.equal(parseMeminfo('MemTotal:       1000000 kB\nMemAvailable:    750000 kB\n'), 25);
    assert.equal(parseMeminfo('MemTotal:       1000000 kB\n'), null);
});
