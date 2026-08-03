const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');

function read(relativePath) {
    return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

test('Ubuntu collector has boot and network-change recovery assets', () => {
    const installer = read('collector/ubuntu/install-collector.sh');
    const bootstrap = read('collector/ubuntu/ensure-collector-autostart.sh');
    const dispatcher = read('collector/ubuntu/nms-collector-network-change.sh');
    const recovery = read('collector/ubuntu/apply-collector-autostart-recovery.sh');
    const unit = read('collector/ubuntu/systemd/nms-collector-autostart.service');

    assert.match(installer, /ensure-collector-autostart\.sh/);
    assert.match(installer, /90-nms-collector-network-change/);
    assert.match(installer, /nms-collector-autostart\.service/);
    assert.match(installer, /NetworkManager-wait-online\.service/);
    assert.match(installer, /networkmanager-wait-online-override\.conf/);
    const waitOverride = read('collector/ubuntu/systemd/networkmanager-wait-online-override.conf');
    assert.match(waitOverride, /nm-online .*--quiet .*--timeout=30/);
    assert.doesNotMatch(waitOverride, /--any|--wait-for-startup/);
    assert.match(bootstrap, /nms-collector-heartbeat\.timer/);
    assert.match(bootstrap, /nms-collector-diagnostic-worker\.service/);
    assert.match(dispatcher, /dhcp4-change/);
    assert.match(dispatcher, /WIREGUARD_INTERFACE/);
    assert.match(dispatcher, /REMOTE_MANAGEMENT_MODE=omada_vpn/);
    assert.match(dispatcher, /wg-quick@\$\{wireguard_interface\}\.service/);
    assert.match(dispatcher, /systemctl is-active --quiet/);
    assert.match(dispatcher, /nms-collector-heartbeat\.service/);
    assert.match(unit, /After=network-online\.target/);
    assert.match(unit, /Restart=on-failure/);
    assert.match(recovery, /nms-collector-autostart\.service/);
    assert.match(recovery, /--clear-private-ip/);
    assert.match(recovery, /90-nms-collector-network-change/);
});

test('Heartbeat retries pending field measurements after central delivery recovers', () => {
    const collector = read('collector/ubuntu/nms-collector.js');

    assert.match(collector, /await flushQueuedFieldMeasurements\(env\)/);
    assert.match(collector, /queued field measurement flush failed/);
});
