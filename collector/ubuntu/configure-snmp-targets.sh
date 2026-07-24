#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-/etc/nms-collector/collector.env}"
ACTION="${1:-show}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root: sudo bash configure-snmp-targets.sh" >&2
  exit 1
fi

read_env() {
  sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | tail -1
}

set_env() {
  local key="$1" value="$2" temporary
  temporary="$(mktemp)"
  grep -v "^${key}=" "$ENV_FILE" > "$temporary" || true
  printf '%s=%s\n' "$key" "$value" >> "$temporary"
  install -m 600 "$temporary" "$ENV_FILE"
  rm -f "$temporary"
}

case "$ACTION" in
  show|show-json)
    targets="$(read_env NETWORK_DEVICE_SNMP_TARGETS)"
    jq -cn --argjson targets "${targets:-[]}" \
      --arg enabled "$(read_env NETWORK_DEVICE_SNMP_ENABLED)" \
      --arg version "$(read_env NETWORK_DEVICE_SNMP_DEFAULT_VERSION)" \
      --arg port "$(read_env NETWORK_DEVICE_SNMP_DEFAULT_PORT)" \
      --arg timeout "$(read_env NETWORK_DEVICE_SNMP_TIMEOUT_SECONDS)" \
      --arg retries "$(read_env NETWORK_DEVICE_SNMP_RETRIES)" \
      --arg community "$([[ -n "$(read_env NETWORK_DEVICE_SNMP_COMMUNITY)" ]] && echo true || echo false)" \
      '{enabled:($enabled == "true"),version:$version,port:($port|tonumber),timeout:($timeout|tonumber),retries:($retries|tonumber),community_configured:($community == "true"),targets:($targets|map(del(.community))),target_count:($targets|length)}'
    ;;
  defaults)
    version="${2:-2c}"; port="${3:-161}"; timeout="${4:-2}"; retries="${5:-1}"
    [[ "$version" =~ ^(1|2c)$ ]] || { echo "version must be 1 or 2c" >&2; exit 2; }
    [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)) || { echo "invalid port" >&2; exit 2; }
    [[ "$timeout" =~ ^[0-9]+$ ]] && ((timeout >= 1 && timeout <= 10)) || { echo "timeout must be 1..10" >&2; exit 2; }
    [[ "$retries" =~ ^[0-9]+$ ]] && ((retries >= 0 && retries <= 3)) || { echo "retries must be 0..3" >&2; exit 2; }
    set_env NETWORK_DEVICE_SNMP_DEFAULT_VERSION "$version"
    set_env NETWORK_DEVICE_SNMP_DEFAULT_PORT "$port"
    set_env NETWORK_DEVICE_SNMP_TIMEOUT_SECONDS "$timeout"
    set_env NETWORK_DEVICE_SNMP_RETRIES "$retries"
    echo "SNMP defaults updated"
    ;;
  community)
    community="${2:-}"
    if [[ "$community" == "--stdin" ]]; then
      IFS= read -r community
    fi
    if [[ -z "$community" ]]; then
      read -r -s -p "SNMP read-only community: " community
      echo
    fi
    [[ -n "$community" ]] || { echo "community is required" >&2; exit 2; }
    set_env NETWORK_DEVICE_SNMP_COMMUNITY "$community"
    echo "SNMP community updated (value hidden)"
    ;;
  add)
    name="${2:-}"; host="${3:-}"; role="${4:-switch}"
    [[ -n "$name" && -n "$host" ]] || { echo "usage: $0 add NAME HOST [ROLE]" >&2; exit 2; }
    targets="$(read_env NETWORK_DEVICE_SNMP_TARGETS)"
    updated="$(jq -cn --argjson current "${targets:-[]}" --arg name "$name" --arg host "$host" --arg role "$role" '
      ($current | map(select(.host != $host))) + [{name:$name,host:$host,role:$role}]
    ')"
    set_env NETWORK_DEVICE_SNMP_TARGETS "$updated"
    set_env NETWORK_DEVICE_SNMP_ENABLED true
    echo "SNMP target added: ${name} (${host})"
    ;;
  remove)
    host="${2:-}"; [[ -n "$host" ]] || { echo "usage: $0 remove HOST" >&2; exit 2; }
    targets="$(read_env NETWORK_DEVICE_SNMP_TARGETS)"
    set_env NETWORK_DEVICE_SNMP_TARGETS "$(jq -c --arg host "$host" 'map(select(.host != $host))' <<<"${targets:-[]}")"
    echo "SNMP target removed: ${host}"
    ;;
  enable|disable)
    set_env NETWORK_DEVICE_SNMP_ENABLED "$([[ "$ACTION" == enable ]] && echo true || echo false)"
    echo "SNMP polling ${ACTION}d"
    ;;
  *)
    echo "usage: $0 {show-json|defaults [VERSION PORT TIMEOUT RETRIES]|community [--stdin]|add NAME HOST [ROLE]|remove HOST|enable|disable}" >&2
    exit 2
    ;;
esac
