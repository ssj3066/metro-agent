#!/usr/bin/env bash
# Applies the non-secret, portable collector recovery controls after a field move.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    exec sudo --preserve-env=PATH bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEMD_DIR=/etc/systemd/system

for file in \
    "$SCRIPT_DIR/nms-collector.js" \
    "$SCRIPT_DIR/apply-collector-network-identity-update.sh" \
    "$SCRIPT_DIR/apply-collector-autostart-recovery.sh" \
    "$SCRIPT_DIR/ensure-collector-autostart.sh" \
    "$SCRIPT_DIR/nms-collector-network-change.sh" \
    "$SCRIPT_DIR/systemd/nms-collector-autostart.service" \
    "$SCRIPT_DIR/systemd/nms-collector-heartbeat.service" \
    "$SCRIPT_DIR/systemd/nms-collector-heartbeat.timer" \
    "$SCRIPT_DIR/systemd/nms-collector-diagnostic-worker.service" \
    "$SCRIPT_DIR/systemd/nms-collector-edge-analysis.service" \
    "$SCRIPT_DIR/systemd/nms-collector-edge-analysis.timer"; do
    if [[ ! -f "$file" ]]; then
        printf 'required update file is missing: %s\n' "$file" >&2
        exit 2
    fi
done

install -m 0644 "$SCRIPT_DIR/systemd/nms-collector-diagnostic-worker.service" "$SYSTEMD_DIR/nms-collector-diagnostic-worker.service"
install -m 0644 "$SCRIPT_DIR/systemd/nms-collector-edge-analysis.service" "$SYSTEMD_DIR/nms-collector-edge-analysis.service"
systemctl daemon-reload

bash "$SCRIPT_DIR/apply-collector-network-identity-update.sh"
bash "$SCRIPT_DIR/apply-collector-autostart-recovery.sh" --clear-private-ip

systemctl enable --now nms-collector-diagnostic-worker.service
systemctl is-active --quiet nms-collector-heartbeat.timer
systemctl is-active --quiet nms-collector-diagnostic-worker.service
systemctl is-active --quiet nms-collector-edge-analysis.timer
systemctl is-enabled --quiet nms-collector-autostart.service

printf '%s\n' 'Portable collector resilience update applied.'
printf '%s\n' 'Dynamic private/public IP reporting and automatic startup are enabled.'
