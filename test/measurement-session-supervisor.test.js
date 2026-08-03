const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
    classifyClockState,
    assessServerClock,
    controlSignals,
    deleteSessionArchive,
    interruptedModuleResult,
    normalizeModuleSelection,
    parseChronyTracking,
    parseOptions,
    requiredRfBands,
    readActiveState,
    readSessionArchive,
    listSessionArchives,
    sessionStatus,
    statePaths,
    writeSessionState
} = require('../collector/ubuntu/nms-measurement-session');

const SESSION_ID = '2bb9b1a0-8322-4d4c-8781-c78d5654a366';

test('measurement session transport supports a pinned NMS CA', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '../collector/ubuntu/nms-measurement-session.js'),
        'utf8'
    );
    assert.match(source, /NMS_CA_CERT_PATH/);
    assert.match(source, /options\.ca = fs\.readFileSync/);
});

test('measurement supervisor enables bounded module selection', () => {
    assert.deepEqual(
        normalizeModuleSelection('wired,wireless,rf,system'),
        {
            wired: true,
            wireless: true,
            rf: true,
            packet_capture: false,
            system: true
        }
    );
    assert.equal(
        normalizeModuleSelection('wired', { MEASUREMENT_PACKET_CAPTURE_DEFAULT: 'true' })
            .packet_capture,
        true
    );
    assert.throws(
        () => normalizeModuleSelection('wired,unknown-module'),
        /unknown measurement modules/
    );
});

test('measurement supervisor parses chrony offset as milliseconds', () => {
    const offsetMs = parseChronyTracking('Last offset     : -0.000123456 seconds');
    assert.ok(Math.abs(offsetMs - (-0.123456)) < 1e-9);
    assert.equal(parseChronyTracking('Reference ID    : 1234'), null);
});

test('measurement supervisor classifies NTP offset without inventing synchronization', () => {
    assert.equal(classifyClockState('yes', 999), 'synced');
    assert.equal(classifyClockState('yes', 1001), 'degraded');
    assert.equal(classifyClockState('yes', 5001), 'unsynced');
    assert.equal(classifyClockState('no', 0), 'unsynced');
    assert.equal(classifyClockState('', null), 'unknown');
});

test('server clock assessment accounts for request round trip uncertainty', () => {
    assert.deepEqual(assessServerClock(7507, 15000, 1000), {
        state: 'synced',
        reliable_delta_ms: 7,
        uncertainty_ms: 7500
    });
    assert.deepEqual(assessServerClock(2500, 200, 1000), {
        state: 'unsynced',
        reliable_delta_ms: 2400,
        uncertainty_ms: 100
    });
});

test('measurement supervisor parses CLI options without consuming flags', () => {
    assert.deepEqual(
        parseOptions(['--duration', '300', '--modules', 'wired,system', '--detached']),
        { duration: '300', modules: 'wired,system', detached: true }
    );
});

test('safe stop closes running modules without calling them failed', () => {
    assert.deepEqual(
        interruptedModuleResult('operator_stop', { status: 'running', sample_count: 3 }),
        {
            status: 'stopped',
            sample_count: 3,
            error_code: 'operator_stopped',
            error_message: 'Operator safely stopped the measurement session'
        }
    );
    assert.equal(
        interruptedModuleResult('natural_completion', { status: 'running' }),
        null
    );
    assert.equal(
        interruptedModuleResult('operator_stop', { status: 'completed' }),
        null
    );
});

test('safe stop wakes a paused worker before requesting termination', () => {
    assert.deepEqual(controlSignals('stop', { paused_at: '2026-07-25T11:40:18Z' }), [
        'SIGCONT',
        'SIGTERM'
    ]);
    assert.deepEqual(controlSignals('stop', { paused_at: null }), ['SIGTERM']);
    assert.deepEqual(controlSignals('pause', {}), ['SIGSTOP']);
    assert.deepEqual(controlSignals('resume', {}), ['SIGCONT']);
});

test('measurement session requires explicit network RF band coverage', () => {
    assert.deepEqual(
        requiredRfBands({}),
        ['wifi_2_4ghz', 'wifi_5ghz', 'wifi_6ghz']
    );
    assert.deepEqual(
        requiredRfBands({ TINYSA_SESSION_BANDS: 'wifi_5ghz,invalid,wifi_5ghz' }),
        ['wifi_5ghz']
    );
});

test('measurement supervisor atomically tracks active and terminal state', (context) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'metro-measurement-session-'));
    context.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const paths = statePaths({ MEASUREMENT_SESSION_STATE_DIR: root });
    const running = {
        measurement_session_id: SESSION_ID,
        status: 'running',
        worker_pid: process.pid
    };

    writeSessionState(paths, running);
    assert.equal(readActiveState(paths).measurement_session_id, SESSION_ID);
    assert.equal(sessionStatus({ MEASUREMENT_SESSION_STATE_DIR: root }).active, true);
    assert.equal(fs.statSync(paths.active).mode & 0o777, 0o640);

    writeSessionState(paths, { ...running, status: 'completed' });
    assert.equal(readActiveState(paths), null);
    const terminal = sessionStatus({ MEASUREMENT_SESSION_STATE_DIR: root });
    assert.equal(terminal.status, 'completed');
    assert.equal(terminal.active, false);
});

test('measurement supervisor lists, reads, and deletes terminal local archives', (context) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'metro-measurement-archive-'));
    context.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const env = { MEASUREMENT_SESSION_STATE_DIR: root };
    const state = {
        measurement_session_id: SESSION_ID,
        status: 'completed',
        worker_pid: 999999,
        created_at: '2026-08-03T01:00:00Z',
        field_profile: {
            customer_id: 7,
            customer_name: '테스트 고객',
            site_id: 9,
            site_name: '테스트 현장'
        }
    };
    writeSessionState(statePaths(env), state);
    assert.equal(listSessionArchives(env)[0].site_name, '테스트 현장');
    assert.equal(readSessionArchive(env, SESSION_ID).status, 'completed');
    assert.equal(deleteSessionArchive(env, SESSION_ID).local_only, true);
    assert.deepEqual(listSessionArchives(env), []);
});

test('measurement supervisor refuses to delete an active local archive', (context) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'metro-measurement-active-'));
    context.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const env = { MEASUREMENT_SESSION_STATE_DIR: root };
    writeSessionState(statePaths(env), {
        measurement_session_id: SESSION_ID,
        status: 'running',
        worker_pid: process.pid
    });
    assert.throws(() => deleteSessionArchive(env, SESSION_ID), /active measurement session/);
});
