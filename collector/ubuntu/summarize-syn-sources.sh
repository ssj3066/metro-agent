#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  summarize-syn-sources.sh <pcap_file> <target_ip>

Example:
  summarize-syn-sources.sh /var/log/nms-pcap/wan-syn-20260430013000.pcap 222.114.95.51
EOF
}

if [[ $# -ne 2 ]]; then
  usage
  exit 1
fi

PCAP_FILE="$1"
TARGET_IP="$2"

if [[ ! -f "${PCAP_FILE}" ]]; then
  echo "pcap file not found: ${PCAP_FILE}" >&2
  exit 1
fi

tcpdump -nn -tttt -r "${PCAP_FILE}" "tcp[tcpflags] & tcp-syn != 0 and dst host ${TARGET_IP}" 2>/dev/null \
  | awk '
      {
        src=$3
        sub(/\.[0-9]+$/, "", src)
        count[src]++
      }
      END {
        for (ip in count) {
          printf "%7d %s\n", count[ip], ip
        }
      }
    ' \
  | sort -nr
