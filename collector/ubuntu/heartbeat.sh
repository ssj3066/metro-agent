#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="${NODE_BIN:-/usr/bin/node}"

exec "$NODE_BIN" "${SCRIPT_DIR}/nms-collector.js" heartbeat "$@"
