#!/bin/sh
set -eu

# NetworkManager invokes dispatcher scripts as root. A new DHCP lease or a
# restored link should not wait for the next timer tick before reporting.
case "${2:-}" in
  up|dhcp4-change|connectivity-change)
    ;;
  *)
    exit 0
    ;;
esac

[ -r /etc/nms-collector/collector.env ] || exit 0

systemctl start --no-block nms-collector-heartbeat.service >/dev/null 2>&1 || true

if grep -Eq '^EDGE_ANALYSIS_ENABLED=true$' /etc/nms-collector/collector.env 2>/dev/null; then
  systemctl start --no-block nms-collector-edge-analysis.service >/dev/null 2>&1 || true
fi
