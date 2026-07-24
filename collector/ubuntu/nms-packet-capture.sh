#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  nms-packet-capture.sh <profile> [target_ip]

Profiles:
  syslog               Capture syslog relay traffic on udp/5514
  trap                 Capture SNMP trap traffic on udp/1162
  mirrored-wan-syn     Capture mirrored WAN TCP SYN traffic

Environment overrides:
  CAPTURE_INTERFACE    default: any
  CAPTURE_OUTPUT_DIR   default: /var/log/nms-pcap
  CAPTURE_FILE_SIZE_MB default: 50
  CAPTURE_FILE_COUNT   default: 5
  CAPTURE_PREFIX       optional file prefix override

Examples:
  sudo CAPTURE_INTERFACE=eth0 ./nms-packet-capture.sh syslog
  sudo CAPTURE_INTERFACE=eth0 ./nms-packet-capture.sh trap
  sudo CAPTURE_INTERFACE=eth0 ./nms-packet-capture.sh mirrored-wan-syn 222.114.95.51
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

PROFILE="$1"
TARGET_IP="${2:-}"
INTERFACE="${CAPTURE_INTERFACE:-any}"
OUTPUT_DIR="${CAPTURE_OUTPUT_DIR:-/var/log/nms-pcap}"
FILE_SIZE_MB="${CAPTURE_FILE_SIZE_MB:-50}"
FILE_COUNT="${CAPTURE_FILE_COUNT:-5}"
PREFIX="${CAPTURE_PREFIX:-}"

case "${PROFILE}" in
  syslog)
    FILTER='udp port 5514'
    PREFIX="${PREFIX:-syslog}"
    ;;
  trap)
    FILTER='udp port 1162'
    PREFIX="${PREFIX:-trap}"
    ;;
  mirrored-wan-syn)
    if [[ -z "${TARGET_IP}" ]]; then
      echo "target_ip is required for mirrored-wan-syn" >&2
      usage
      exit 1
    fi
    FILTER="tcp[tcpflags] & tcp-syn != 0 and dst host ${TARGET_IP}"
    PREFIX="${PREFIX:-wan-syn}"
    ;;
  *)
    echo "unknown profile: ${PROFILE}" >&2
    usage
    exit 1
    ;;
esac

mkdir -p "${OUTPUT_DIR}"

echo "profile=${PROFILE}"
echo "interface=${INTERFACE}"
echo "output_dir=${OUTPUT_DIR}"
echo "filter=${FILTER}"
echo "ring_buffer=${FILE_COUNT} files x ${FILE_SIZE_MB}MB"

exec tcpdump \
  -ni "${INTERFACE}" \
  -C "${FILE_SIZE_MB}" \
  -W "${FILE_COUNT}" \
  -w "${OUTPUT_DIR}/${PREFIX}-%Y%m%d%H%M%S.pcap" \
  "${FILTER}"
