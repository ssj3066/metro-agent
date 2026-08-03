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

# wg-quick can fail during early boot when DHCP or DNS is not ready yet.
# Retry it after a physical network recovery, but never react to its own link.
wireguard_interface="$(
  sed -n 's/^WIREGUARD_INTERFACE=//p' /etc/nms-collector/collector.env 2>/dev/null |
    tail -n 1
)"
wireguard_interface="${wireguard_interface:-metro-omada}"
if [ "${1:-}" != "$wireguard_interface" ] &&
   grep -Eq '^REMOTE_MANAGEMENT_MODE=omada_vpn$' /etc/nms-collector/collector.env 2>/dev/null &&
   ! systemctl is-active --quiet "wg-quick@${wireguard_interface}.service"; then
  systemctl restart --no-block "wg-quick@${wireguard_interface}.service" >/dev/null 2>&1 || true
fi

systemctl start --no-block nms-collector-heartbeat.service >/dev/null 2>&1 || true

if grep -Eq '^EDGE_ANALYSIS_ENABLED=true$' /etc/nms-collector/collector.env 2>/dev/null; then
  systemctl start --no-block nms-collector-edge-analysis.service >/dev/null 2>&1 || true
fi
