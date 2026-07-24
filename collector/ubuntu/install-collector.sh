#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/nms-collector"
ENV_DIR="/etc/nms-collector"
SYSTEMD_DIR="/etc/systemd/system"
RSYSLOG_DIR="/etc/rsyslog.d"
ENV_SOURCE_FILE="${ENV_SOURCE_FILE:-}"

usage() {
  cat <<'USAGE'
Usage: sudo bash install-collector.sh [--env-file PATH]

Options:
  --env-file, -e PATH  Install PATH as /etc/nms-collector/collector.env.
  --help, -h           Show this help.

The env file is normally exported from /field-collector.html, then edited with
the real COLLECTOR_TOKEN before running this installer.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file|-e)
      if [[ $# -lt 2 ]]; then
        echo "--env-file requires a path" >&2
        exit 2
      fi
      ENV_SOURCE_FILE="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "$ENV_SOURCE_FILE" && ! -f "$ENV_SOURCE_FILE" ]]; then
  echo "env file not found: ${ENV_SOURCE_FILE}" >&2
  exit 2
fi

echo "[1/8] installing base packages, supported Node.js, and field diagnostics"
apt-get update
apt-get install -y ca-certificates curl jq rsyslog snmp xz-utils iproute2 iputils-ping traceroute dnsutils netcat-openbsd tcpdump
bash "${SCRIPT_DIR}/install-node-lts.sh"
SKIP_APT_UPDATE=true bash "${SCRIPT_DIR}/install-field-tools.sh"

echo "[2/8] creating directories"
install -d -m 755 "$INSTALL_DIR"
install -d -m 755 "$ENV_DIR"

echo "[3/8] installing collector runtime"
install -m 755 "${SCRIPT_DIR}/nms-collector.js" "${INSTALL_DIR}/nms-collector.js"
install -m 755 "${SCRIPT_DIR}/nms-packet-capture.sh" "${INSTALL_DIR}/nms-packet-capture.sh"
install -m 755 "${SCRIPT_DIR}/nms-gui-operations.sh" "${INSTALL_DIR}/nms-gui-operations.sh"
install -m 755 "${SCRIPT_DIR}/nms-wireless-scan.py" "${INSTALL_DIR}/nms-wireless-scan.py"
install -d -m 755 "${INSTALL_DIR}/metro-agent-v1/lib" "${INSTALL_DIR}/metro-agent-v1/plugins"
install -m 755 "${SCRIPT_DIR}/metro-agent-v1/index.js" "${INSTALL_DIR}/metro-agent-v1/index.js"
install -m 644 "${SCRIPT_DIR}/metro-agent-v1/lib/queue.js" "${INSTALL_DIR}/metro-agent-v1/lib/queue.js"
install -m 644 "${SCRIPT_DIR}/metro-agent-v1/lib/transport.js" "${INSTALL_DIR}/metro-agent-v1/lib/transport.js"
install -m 644 "${SCRIPT_DIR}/metro-agent-v1/plugins/"*.js "${INSTALL_DIR}/metro-agent-v1/plugins/"
install -m 755 "${SCRIPT_DIR}/summarize-syn-sources.sh" "${INSTALL_DIR}/summarize-syn-sources.sh"
install -m 755 "${SCRIPT_DIR}/heartbeat.sh" "${INSTALL_DIR}/heartbeat.sh"
install -m 755 "${SCRIPT_DIR}/ensure-collector-autostart.sh" "${INSTALL_DIR}/ensure-collector-autostart.sh"
install -m 755 "${SCRIPT_DIR}/trap-forwarder.js" "${INSTALL_DIR}/trap-forwarder.js"
install -m 755 "${SCRIPT_DIR}/configure-snmp-agent.sh" "${INSTALL_DIR}/configure-snmp-agent.sh"
install -m 755 "${SCRIPT_DIR}/configure-snmp-targets.sh" "${INSTALL_DIR}/configure-snmp-targets.sh"
install -m 755 "${SCRIPT_DIR}/nms-field-diagnostics.py" "/usr/local/bin/metro-nms-field-diagnostics"
install -d -m 755 "/usr/local/lib/metro-nms-collector"
install -m 644 "${SCRIPT_DIR}/ict_field_client.py" "/usr/local/lib/metro-nms-collector/ict_field_client.py"
install -m 644 "${SCRIPT_DIR}/metro-nms-field-diagnostics.desktop" "/usr/share/applications/metro-nms-field-diagnostics.desktop"
install -m 644 "${SCRIPT_DIR}/package.json" "${INSTALL_DIR}/package.json"

if [[ -n "$ENV_SOURCE_FILE" ]]; then
  echo "[4/8] installing env file from ${ENV_SOURCE_FILE}"
  source_abs="$(readlink -f "$ENV_SOURCE_FILE")"
  target_abs="$(readlink -m "${ENV_DIR}/collector.env")"
  if [[ "$source_abs" == "$target_abs" ]]; then
    echo "using existing env file: ${ENV_DIR}/collector.env"
  else
    if [[ -f "${ENV_DIR}/collector.env" ]]; then
      backup_file="${ENV_DIR}/collector.env.$(date +%Y%m%d%H%M%S).bak"
      cp -a "${ENV_DIR}/collector.env" "$backup_file"
      echo "backed up existing env file: ${backup_file}"
    fi
    install -m 640 "$ENV_SOURCE_FILE" "${ENV_DIR}/collector.env"
  fi
elif [[ ! -f "${ENV_DIR}/collector.env" ]]; then
  echo "[4/8] installing example env file"
  install -m 640 "${SCRIPT_DIR}/collector.env.example" "${ENV_DIR}/collector.env"
else
  echo "[4/8] keeping existing env file: ${ENV_DIR}/collector.env"
fi

echo "[5/8] validating collector env"
COLLECTOR_READY=false
if /usr/local/bin/node "${INSTALL_DIR}/nms-collector.js" doctor; then
  COLLECTOR_READY=true
else
  echo "collector env is not ready yet; heartbeat/trap services will stay disabled until collector.env is fixed"
fi

echo "[6/8] installing systemd units"
install -m 644 "${SCRIPT_DIR}/systemd/nms-collector-heartbeat.service" "${SYSTEMD_DIR}/nms-collector-heartbeat.service"
install -m 644 "${SCRIPT_DIR}/systemd/nms-collector-heartbeat.timer" "${SYSTEMD_DIR}/nms-collector-heartbeat.timer"
install -m 644 "${SCRIPT_DIR}/systemd/nms-collector-autostart.service" "${SYSTEMD_DIR}/nms-collector-autostart.service"
install -m 644 "${SCRIPT_DIR}/systemd/nms-collector-trap-forwarder.service" "${SYSTEMD_DIR}/nms-collector-trap-forwarder.service"
install -m 644 "${SCRIPT_DIR}/systemd/nms-collector-diagnostic-worker.service" "${SYSTEMD_DIR}/nms-collector-diagnostic-worker.service"
install -m 644 "${SCRIPT_DIR}/systemd/nms-collector-edge-analysis.service" "${SYSTEMD_DIR}/nms-collector-edge-analysis.service"
install -m 644 "${SCRIPT_DIR}/systemd/nms-collector-edge-analysis.timer" "${SYSTEMD_DIR}/nms-collector-edge-analysis.timer"
install -m 644 "${SCRIPT_DIR}/systemd/nms-iperf3-server.service" "${SYSTEMD_DIR}/nms-iperf3-server.service"
install -m 644 "${SCRIPT_DIR}/systemd/nms-metro-agent-v1.service" "${SYSTEMD_DIR}/nms-metro-agent-v1.service"
install -m 644 "${SCRIPT_DIR}/systemd/nms-metro-agent-v1.timer" "${SYSTEMD_DIR}/nms-metro-agent-v1.timer"
install -d -m 700 /var/lib/nms-collector/metro-agent-v1 /var/lib/nms-collector/metro-agent-v1/queue
install -d -m 755 /etc/NetworkManager/dispatcher.d
install -m 755 "${SCRIPT_DIR}/nms-collector-network-change.sh" "/etc/NetworkManager/dispatcher.d/90-nms-collector-network-change"
systemctl daemon-reload
systemctl enable NetworkManager-wait-online.service 2>/dev/null || true
systemctl enable nms-collector-autostart.service

if grep -q '^ENABLE_FIELD_SERVER=true' "${ENV_DIR}/collector.env"; then
  echo "[server] enabling local syslog and bandwidth-test listeners"
  install -d -m 750 -o syslog -g adm /var/log/nms-remote
  install -m 640 "${SCRIPT_DIR}/rsyslog-field-receiver.conf" "${RSYSLOG_DIR}/30-nms-field-receiver.conf"
  systemctl enable --now rsyslog nms-iperf3-server.service
  systemctl restart rsyslog nms-iperf3-server.service
else
  rm -f "${RSYSLOG_DIR}/30-nms-field-receiver.conf"
  systemctl disable --now nms-iperf3-server.service 2>/dev/null || true
fi

if grep -q '^ENABLE_RSYSLOG_RELAY=true' "${ENV_DIR}/collector.env"; then
  echo "[7/8] installing rsyslog relay config"
  /usr/local/bin/node "${INSTALL_DIR}/nms-collector.js" render-rsyslog-config > "${RSYSLOG_DIR}/49-nms-relay.conf"
  systemctl enable --now rsyslog
  systemctl restart rsyslog
else
  echo "[7/8] rsyslog relay disabled in env file"
  rm -f "${RSYSLOG_DIR}/49-nms-relay.conf"
  systemctl restart rsyslog 2>/dev/null || true
fi

if grep -q '^ENABLE_SNMPTRAP_RELAY=true' "${ENV_DIR}/collector.env"; then
  echo "[8/8] installing Node.js trap forwarder dependencies"
  apt-get install -y npm
  (
    cd "${INSTALL_DIR}"
    /usr/local/bin/npm install --omit=dev
  )
  if [[ "$COLLECTOR_READY" == "true" ]]; then
    systemctl enable --now nms-collector-trap-forwarder.service
    systemctl restart nms-collector-trap-forwarder.service
  else
    systemctl disable --now nms-collector-trap-forwarder.service 2>/dev/null || true
    echo "snmp trap relay kept disabled until nms-collector doctor passes"
  fi
else
  echo "[8/8] snmp trap relay disabled in env file"
  systemctl disable --now nms-collector-trap-forwarder.service 2>/dev/null || true
fi

if [[ "$COLLECTOR_READY" == "true" ]]; then
  systemctl enable --now nms-collector-heartbeat.timer
  systemctl start nms-collector-heartbeat.service || true
else
  systemctl disable --now nms-collector-heartbeat.timer nms-collector-heartbeat.service 2>/dev/null || true
fi

if grep -q '^REMOTE_DIAGNOSTICS_ENABLED=true' "${ENV_DIR}/collector.env"; then
  if [[ "$COLLECTOR_READY" == "true" ]]; then
    systemctl enable --now nms-collector-diagnostic-worker.service
    systemctl restart nms-collector-diagnostic-worker.service
  else
    systemctl disable --now nms-collector-diagnostic-worker.service 2>/dev/null || true
    echo "diagnostic worker kept disabled until nms-collector doctor passes"
  fi
else
  systemctl disable --now nms-collector-diagnostic-worker.service 2>/dev/null || true
fi

if grep -q '^EDGE_ANALYSIS_ENABLED=true' "${ENV_DIR}/collector.env"; then
  if [[ "$COLLECTOR_READY" == "true" ]]; then
    systemctl enable --now nms-collector-edge-analysis.timer
    systemctl start nms-collector-edge-analysis.service || true
  else
    systemctl disable --now nms-collector-edge-analysis.timer nms-collector-edge-analysis.service 2>/dev/null || true
    echo "edge analysis kept disabled until nms-collector doctor passes"
  fi
else
  systemctl disable --now nms-collector-edge-analysis.timer nms-collector-edge-analysis.service 2>/dev/null || true
fi

if grep -q '^METRO_AGENT_V1_ENABLED=true' "${ENV_DIR}/collector.env"; then
  if [[ "$COLLECTOR_READY" == "true" ]]; then
    systemctl enable --now nms-metro-agent-v1.timer
    systemctl start nms-metro-agent-v1.service || true
  else
    systemctl disable --now nms-metro-agent-v1.timer nms-metro-agent-v1.service 2>/dev/null || true
    echo "Metro Agent V1 kept disabled until nms-collector doctor passes"
  fi
else
  systemctl disable --now nms-metro-agent-v1.timer nms-metro-agent-v1.service 2>/dev/null || true
fi

# The autostart service owns boot recovery. It is independent of the desktop
# GUI and is safe to run even when the current network cannot reach NMS yet.
systemctl start nms-collector-autostart.service || true

echo
echo "collector install complete"
echo "edit ${ENV_DIR}/collector.env and rerun if needed"
echo "doctor: /usr/local/bin/node ${INSTALL_DIR}/nms-collector.js doctor"
echo "check: systemctl status nms-collector-heartbeat.timer"
echo "autostart: systemctl status nms-collector-autostart.service"
echo "diagnostics: systemctl status nms-collector-diagnostic-worker.service"
echo "edge analysis: systemctl status nms-collector-edge-analysis.timer"
echo "Metro Agent V1: systemctl status nms-metro-agent-v1.timer"
