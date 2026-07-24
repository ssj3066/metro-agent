#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

REGDOMAIN="${REGDOMAIN:-KR}"
SKIP_APT_UPDATE="${SKIP_APT_UPDATE:-false}"
BACKUP_SUFFIX="$(date +%Y%m%d%H%M%S).bak"
LLDPD_DEFAULTS="/etc/default/lldpd"
REGDOMAIN_UNIT="/etc/systemd/system/nms-wireless-regdomain.service"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root: sudo bash install-field-tools.sh" >&2
  exit 1
fi

echo "[1/5] installing field diagnostic packages"
if [[ "$SKIP_APT_UPDATE" != "true" ]]; then
  apt-get update
fi
apt-get install -y \
  arp-scan \
  avahi-utils \
  bridge-utils \
  ethtool \
  fping \
  iperf3 \
  iw \
  lldpd \
  lshw \
  mtr-tiny \
  nmap \
  pciutils \
  rfkill \
  smartmontools \
  smbclient \
  snmpd \
  tcpdump \
  tshark \
  usbutils \
  vlan \
  wireless-tools
apt-get install -y network-manager-openvpn network-manager-openvpn-gnome openvpn wireguard-tools

echo "[2/5] keeping active probes disabled until an operator starts them"
systemctl disable --now iperf3.service 2>/dev/null || true
systemctl disable --now snmpd.service 2>/dev/null || true

echo "[3/5] configuring LLDP/CDP in receive-only mode"
if [[ -f "$LLDPD_DEFAULTS" ]]; then
  cp -a "$LLDPD_DEFAULTS" "${LLDPD_DEFAULTS}.${BACKUP_SUFFIX}"
fi

if grep -q '^DAEMON_ARGS=' "$LLDPD_DEFAULTS" 2>/dev/null; then
  sed -i 's/^DAEMON_ARGS=.*/DAEMON_ARGS="-r -c"/' "$LLDPD_DEFAULTS"
else
  printf '\nDAEMON_ARGS="-r -c"\n' >> "$LLDPD_DEFAULTS"
fi

systemctl enable --now lldpd.service
systemctl restart lldpd.service

echo "[4/5] applying wireless regulatory domain ${REGDOMAIN}"
if [[ -f "$REGDOMAIN_UNIT" ]]; then
  cp -a "$REGDOMAIN_UNIT" "${REGDOMAIN_UNIT}.${BACKUP_SUFFIX}"
fi

install -m 644 /dev/stdin "$REGDOMAIN_UNIT" <<EOF
[Unit]
Description=Set wireless regulatory domain for NMS field collector
After=systemd-modules-load.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/iw reg set ${REGDOMAIN}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now nms-wireless-regdomain.service

echo "[5/5] reporting installed capabilities"
printf 'lldpd: '
systemctl is-active lldpd.service
printf 'iperf3 daemon: '
systemctl is-enabled iperf3.service 2>/dev/null || true
printf 'regdomain: '
iw reg get | awk '/country / { print $2; exit }'
printf 'tools: '
for tool in arp-scan ethtool fping iperf3 iw lldpcli lshw mtr nmap smartctl smbclient tcpdump tshark; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '%s ' "$tool"
  fi
done
printf '\n'
