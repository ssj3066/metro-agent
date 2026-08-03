#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEMD_DIR="/etc/systemd/system"
DISPATCHER_DIR="/etc/NetworkManager/dispatcher.d"
CLEAR_PRIVATE_IP=false

case "${1:-}" in
  "") ;;
  --clear-private-ip) CLEAR_PRIVATE_IP=true ;;
  *)
    echo "usage: sudo bash $0 [--clear-private-ip]" >&2
    exit 2
    ;;
esac

require_file() {
  [[ -f "$1" ]] || {
    echo "required package file is missing: $1" >&2
    exit 2
  }
}

for file in \
  "${SCRIPT_DIR}/ensure-collector-autostart.sh" \
  "${SCRIPT_DIR}/nms-collector-network-change.sh" \
  "${SCRIPT_DIR}/systemd/nms-collector-autostart.service" \
  "${SCRIPT_DIR}/systemd/nms-collector-heartbeat.service" \
  "${SCRIPT_DIR}/systemd/nms-collector-heartbeat.timer" \
  "${SCRIPT_DIR}/systemd/nms-collector-edge-analysis.timer" \
  "${SCRIPT_DIR}/systemd/networkmanager-wait-online-override.conf"; do
  require_file "$file"
done

install -m 755 "${SCRIPT_DIR}/ensure-collector-autostart.sh" "/opt/nms-collector/ensure-collector-autostart.sh"
install -m 644 "${SCRIPT_DIR}/systemd/nms-collector-autostart.service" "${SYSTEMD_DIR}/nms-collector-autostart.service"
install -m 644 "${SCRIPT_DIR}/systemd/nms-collector-heartbeat.service" "${SYSTEMD_DIR}/nms-collector-heartbeat.service"
install -m 644 "${SCRIPT_DIR}/systemd/nms-collector-heartbeat.timer" "${SYSTEMD_DIR}/nms-collector-heartbeat.timer"
install -m 644 "${SCRIPT_DIR}/systemd/nms-collector-edge-analysis.timer" "${SYSTEMD_DIR}/nms-collector-edge-analysis.timer"
install -d -m 755 "$DISPATCHER_DIR"
install -m 755 "${SCRIPT_DIR}/nms-collector-network-change.sh" "${DISPATCHER_DIR}/90-nms-collector-network-change"

if [[ "$CLEAR_PRIVATE_IP" == "true" && -f /etc/nms-collector/collector.env ]]; then
  backup="/etc/nms-collector/collector.env.$(date +%Y%m%d%H%M%S).bak"
  cp -a /etc/nms-collector/collector.env "$backup"
  sed -i -E 's/^COLLECTOR_PRIVATE_IP=.*/COLLECTOR_PRIVATE_IP=/' /etc/nms-collector/collector.env
  sed -i -E 's/^COLLECTOR_PRIVATE_IP_OVERRIDE=.*/COLLECTOR_PRIVATE_IP_OVERRIDE=false/' /etc/nms-collector/collector.env
  echo "cleared static private IP override; backup: $backup"
fi

install -d -m 755 /etc/systemd/system/NetworkManager-wait-online.service.d
install -m 644 \
  "${SCRIPT_DIR}/systemd/networkmanager-wait-online-override.conf" \
  /etc/systemd/system/NetworkManager-wait-online.service.d/override.conf

systemctl daemon-reload
systemctl enable NetworkManager-wait-online.service 2>/dev/null || true
systemctl enable nms-collector-autostart.service
systemctl restart nms-collector-autostart.service || true

echo "collector autostart recovery applied"
echo "check: sudo systemctl status nms-collector-autostart.service --no-pager"
echo "check: sudo systemctl list-timers nms-collector-heartbeat.timer nms-collector-edge-analysis.timer"
