#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const {
    DEFAULT_STATE_FILE,
    newDeploymentState,
    readActiveDeployment
} = require('./time-series-context');

function writeJson(filePath, value) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o750 });
    const temporary = `${filePath}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o640 });
    fs.renameSync(temporary, filePath);
}

function start(filePath, options = {}) {
    const current = readActiveDeployment(filePath);
    if (current) return current;
    const state = newDeploymentState(options);
    writeJson(filePath, state);
    return state;
}

function stop(filePath, now = new Date()) {
    let state;
    try {
        state = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch {
        return { status: 'stopped', deployment_session_id: null };
    }
    state.status = 'stopped';
    state.stopped_at = now.toISOString();
    writeJson(filePath, state);
    return state;
}

function option(argv, name) {
    const index = argv.indexOf(name);
    return index >= 0 ? argv[index + 1] : null;
}

function main(argv = process.argv.slice(2)) {
    const command = argv[0] || 'status';
    const filePath = process.env.DEPLOYMENT_MONITORING_STATE_FILE || DEFAULT_STATE_FILE;
    let result;
    if (command === 'start') {
        result = start(filePath, {
            interval_seconds: option(argv, '--interval'),
            site_id: option(argv, '--site-id'),
            site_name: option(argv, '--site-name')
        });
    } else if (command === 'stop') {
        result = stop(filePath);
    } else if (command === 'status') {
        result = readActiveDeployment(filePath) || { status: 'stopped', deployment_session_id: null };
    } else {
        throw new Error('usage: deployment-monitoring-control.js [start|stop|status]');
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (require.main === module) {
    try {
        main();
    } catch (error) {
        console.error(`[deployment-monitoring] ${error.message}`);
        process.exitCode = 1;
    }
}

module.exports = { main, start, stop };
