#!/usr/bin/env bash
set -euo pipefail

NODE=/usr/local/bin/node
SUPERVISOR=/opt/nms-collector/nms-measurement-session.js
action="${1:-}"

[[ -x "$NODE" && -f "$SUPERVISOR" ]] || {
  echo "measurement session supervisor is not installed" >&2
  exit 2
}

case "$action" in
  status|pause|resume|stop)
    [[ "$#" -eq 1 ]] || { echo "unexpected measurement session arguments" >&2; exit 2; }
    exec "$NODE" "$SUPERVISOR" "$action"
    ;;
  list)
    [[ "$#" -eq 1 ]] || { echo "unexpected measurement session arguments" >&2; exit 2; }
    exec "$NODE" "$SUPERVISOR" list
    ;;
  show|delete)
    [[ "$#" -eq 2 && "${2:-}" =~ ^[0-9a-fA-F-]{36}$ ]] \
      || { echo "a valid session UUID is required" >&2; exit 2; }
    exec "$NODE" "$SUPERVISOR" "$action" --session-id "$2"
    ;;
  start)
    shift
    duration=""
    interval=""
    modules=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --duration)
          duration="${2:-}"; shift 2 ;;
        --interval)
          interval="${2:-}"; shift 2 ;;
        --modules)
          modules="${2:-}"; shift 2 ;;
        *)
          echo "unsupported measurement session option" >&2
          exit 2
          ;;
      esac
    done
    [[ "$duration" =~ ^[0-9]+$ ]] && (( duration >= 10 && duration <= 28800 )) \
      || { echo "duration must be 10..28800 seconds" >&2; exit 2; }
    [[ "$interval" =~ ^[0-9]+$ ]] && (( interval >= 2 && interval <= 300 )) \
      || { echo "interval must be 2..300 seconds" >&2; exit 2; }
    [[ "$modules" =~ ^(wired|wireless|rf|packet_capture|system)(,(wired|wireless|rf|packet_capture|system))*$ ]] \
      || { echo "invalid measurement modules" >&2; exit 2; }
    exec "$NODE" "$SUPERVISOR" start \
      --duration "$duration" \
      --interval "$interval" \
      --modules "$modules"
    ;;
  *)
    echo "usage: $0 start|status|pause|resume|stop|list|show|delete" >&2
    exit 2
    ;;
esac
