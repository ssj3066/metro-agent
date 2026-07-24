#!/usr/bin/env node

const { main } = require('./nms-collector');

main(['trap-forwarder']).catch((error) => {
    console.error(`[trap-forwarder] startup failed: ${error.message}`);
    process.exit(1);
});
