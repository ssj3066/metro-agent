const fs = require('fs');
const path = require('path');

function ensureDirectory(directory) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
}

function atomicWriteJson(filePath, payload) {
    ensureDirectory(path.dirname(filePath));
    const temporaryPath = `${filePath}.${process.pid}.tmp`;
    fs.writeFileSync(temporaryPath, `${JSON.stringify(payload)}\n`, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(temporaryPath, filePath);
}

function persistBatch(queueDirectory, batch, maximumFiles = 10000) {
    ensureDirectory(queueDirectory);
    const files = listBatchFiles(queueDirectory);
    if (files.length >= maximumFiles) {
        throw new Error(`metro agent queue limit reached (${maximumFiles})`);
    }
    const filePath = path.join(queueDirectory, `${batch.batch_id}.json`);
    atomicWriteJson(filePath, batch);
    return filePath;
}

function listBatchFiles(queueDirectory) {
    if (!fs.existsSync(queueDirectory)) return [];
    return fs.readdirSync(queueDirectory)
        .filter((name) => /^[0-9a-f-]{36}\.json$/i.test(name))
        .map((name) => {
            const filePath = path.join(queueDirectory, name);
            return { filePath, modifiedAt: fs.statSync(filePath).mtimeMs };
        })
        .sort((left, right) => left.modifiedAt - right.modifiedAt || left.filePath.localeCompare(right.filePath))
        .map((item) => item.filePath);
}

function readBatch(filePath) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function removeBatch(filePath) {
    fs.unlinkSync(filePath);
}

function loadJson(filePath) {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

module.exports = {
    atomicWriteJson,
    ensureDirectory,
    listBatchFiles,
    loadJson,
    persistBatch,
    readBatch,
    removeBatch
};
