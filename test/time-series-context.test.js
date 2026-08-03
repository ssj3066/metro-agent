const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
    buildTimeSeriesContext,
    newDeploymentState,
    readActiveDeployment
} = require('../collector/ubuntu/time-series-context');

test('all processes align to the same epoch window', () => {
    const first = buildTimeSeriesContext(new Date('2026-07-29T06:42:01.100Z'), null, 30);
    const second = buildTimeSeriesContext(new Date('2026-07-29T06:42:29.999Z'), null, 30);
    assert.equal(first.sequence_no, second.sequence_no);
    assert.equal(first.window_started_at, '2026-07-29T06:42:00.000Z');
    assert.equal(first.window_ended_at, '2026-07-29T06:42:30.000Z');
});

test('active deployment survives process restart through root-owned state', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'deployment-state-'));
    const filePath = path.join(directory, 'active.json');
    const state = newDeploymentState({ site_name: 'field-a', interval_seconds: 30 });
    fs.writeFileSync(filePath, JSON.stringify(state));
    const restored = readActiveDeployment(filePath);
    assert.equal(restored.deployment_session_id, state.deployment_session_id);
    assert.equal(restored.site_name, 'field-a');
    fs.rmSync(directory, { recursive: true, force: true });
});
