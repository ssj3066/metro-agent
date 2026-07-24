#!/usr/bin/env bash
# Run from the extracted update package as root on an Ubuntu field collector.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    exec sudo --preserve-env=PATH bash "$0" "$@"
fi

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly INSTALL_DIR=/opt/nms-collector
readonly ENV_FILE=/etc/nms-collector/collector.env
readonly STAMP=$(date +%Y%m%d-%H%M%S)
readonly BACKUP_DIR="${INSTALL_DIR}/backups/network-identity-${STAMP}"

[[ -f "${SCRIPT_DIR}/nms-collector.js" ]] || {
    echo "nms-collector.js is missing from this update package" >&2
    exit 2
}
[[ -f "${INSTALL_DIR}/nms-collector.js" ]] || {
    echo "collector installation was not found: ${INSTALL_DIR}/nms-collector.js" >&2
    exit 2
}

install -d -m 0750 "$BACKUP_DIR"
cp -a "${INSTALL_DIR}/nms-collector.js" "$BACKUP_DIR/nms-collector.js"
[[ -f "$ENV_FILE" ]] && cp -a "$ENV_FILE" "$BACKUP_DIR/collector.env"

install -m 0755 "${SCRIPT_DIR}/nms-collector.js" "${INSTALL_DIR}/nms-collector.js"

if [[ -f "$ENV_FILE" ]]; then
    for key in COLLECTOR_PRIVATE_IP COLLECTOR_PUBLIC_IP COLLECTOR_PRIVATE_IP_OVERRIDE; do
        sed -i -E "/^${key}=/d" "$ENV_FILE"
    done
    {
        echo "COLLECTOR_PRIVATE_IP="
        echo "COLLECTOR_PRIVATE_IP_OVERRIDE=false"
        echo "COLLECTOR_PUBLIC_IP="
    } >> "$ENV_FILE"
fi

if ! node --check "${INSTALL_DIR}/nms-collector.js"; then
    cp -a "$BACKUP_DIR/nms-collector.js" "${INSTALL_DIR}/nms-collector.js"
    [[ -f "$BACKUP_DIR/collector.env" ]] && cp -a "$BACKUP_DIR/collector.env" "$ENV_FILE"
    echo "Validation failed; restored ${BACKUP_DIR}" >&2
    exit 1
fi

systemctl restart nms-collector-heartbeat.service
systemctl restart nms-collector-edge-analysis.service 2>/dev/null || true

echo "Dynamic collector network identity update applied. Backup: ${BACKUP_DIR}"
echo "The next heartbeat reports the active interface, private IP, prefix, and gateway."
