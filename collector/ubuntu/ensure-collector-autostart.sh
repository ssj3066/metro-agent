#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-/etc/nms-collector/collector.env}"
NODE_BIN="${NODE_BIN:-/usr/local/bin/node}"
COLLECTOR_BIN="${COLLECTOR_BIN:-/opt/nms-collector/nms-collector.js}"

setting_enabled() {
  grep -Eq "^${1}=true$" "$ENV_FILE" 2>/dev/null
}

if [[ ! -r "$ENV_FILE" ]]; then
  echo "nms collector autostart: env file is unavailable: $ENV_FILE" >&2
  exit 1
fi

if ! "$NODE_BIN" "$COLLECTOR_BIN" doctor; then
  echo "nms collector autostart: collector doctor failed; will retry after configuration or network recovery" >&2
  exit 1
fi

systemctl enable nms-collector-heartbeat.timer
systemctl start nms-collector-heartbeat.service || true
systemctl start nms-collector-heartbeat.timer

if setting_enabled REMOTE_DIAGNOSTICS_ENABLED; then
  systemctl enable nms-collector-diagnostic-worker.service
  systemctl restart nms-collector-diagnostic-worker.service
fi

if setting_enabled EDGE_ANALYSIS_ENABLED; then
  systemctl enable nms-collector-edge-analysis.timer
  systemctl start nms-collector-edge-analysis.service || true
  systemctl start nms-collector-edge-analysis.timer
fi

echo "nms collector autostart: services armed"
