#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-/etc/nms-collector/collector.env}"
SNMPD_CONFIG="/etc/snmp/snmpd.conf"
BACKUP_ROOT="/opt/nms-collector/backups"
LISTEN_ADDRESS="${SNMP_AGENT_LISTEN_ADDRESS:-udp:0.0.0.0:161}"
ALLOWED_NETWORK="${SNMP_AGENT_ALLOWED_NETWORK:-192.168.1.0/24}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root: sudo bash configure-snmp-agent.sh" >&2
  exit 1
fi

apt-get install -y snmpd openssl
install -d -m 755 "$BACKUP_ROOT"

if [[ -f "$SNMPD_CONFIG" ]]; then
  cp -a "$SNMPD_CONFIG" "${BACKUP_ROOT}/snmpd.conf.$(date +%Y%m%d%H%M%S).bak"
fi

community="$(sed -n 's/^SNMP_AGENT_COMMUNITY=//p' "$ENV_FILE" 2>/dev/null | tail -1)"
if [[ -z "$community" ]]; then
  community="$(openssl rand -hex 18)"
  printf '\nSNMP_AGENT_COMMUNITY=%s\n' "$community" >> "$ENV_FILE"
fi

cat > "$SNMPD_CONFIG" <<EOF
agentAddress ${LISTEN_ADDRESS}
view metroSystem included .1.3.6.1.2.1.1
view metroSystem included .1.3.6.1.2.1.2
view metroSystem included .1.3.6.1.2.1.25.1
rocommunity ${community} ${ALLOWED_NETWORK} -V metroSystem
sysLocation METRO field collector
sysContact METRO NMS
dontLogTCPWrappersConnects yes
EOF

chmod 600 "$ENV_FILE"
systemctl enable --now snmpd.service
systemctl restart snmpd.service

echo "snmpd configured: ${LISTEN_ADDRESS}, allowed=${ALLOWED_NETWORK}"
echo "community is stored only in ${ENV_FILE}"
