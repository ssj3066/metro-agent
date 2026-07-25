#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="/var/log/nms-pcap"
WIRELESS_SCAN="/opt/nms-collector/nms-wireless-scan.py"
PACKET_FLOOD_ANALYZER="/usr/local/bin/nms_packet_flood.py"
COLLECTOR_ENV="/etc/nms-collector/collector.env"
action="${1:-}"
declare -A nm_wireguard_profiles=()

require_interface() {
  [[ "$1" =~ ^[a-zA-Z0-9_.:-]+$ ]] || { echo "invalid interface" >&2; exit 2; }
  ip link show "$1" >/dev/null 2>&1 || { echo "interface not found: $1" >&2; exit 2; }
}

require_live_capture_pid() {
  local pid="${1:-}" command_line pgid
  [[ "$pid" =~ ^[0-9]+$ ]] && ((pid > 1)) || { echo "invalid capture pid" >&2; exit 2; }
  [[ -r "/proc/${pid}/cmdline" ]] || { echo "capture process is not running"; return 1; }
  command_line="$(tr '\0' ' ' < "/proc/${pid}/cmdline")"
  [[ "$command_line" == *"nms-gui-operations.sh live-capture"* ]] \
    || { echo "pid is not a METRO live capture" >&2; exit 2; }
  pgid="$(ps -o pgid= -p "$pid" | tr -d ' ')"
  [[ "$pgid" =~ ^[0-9]+$ ]] && ((pgid > 1)) || { echo "capture process group not found" >&2; exit 2; }
  printf '%s\n' "$pgid"
}

wait_for_process_exit() {
  local pid="$1" attempts="$2"
  local index
  for ((index=0; index<attempts; index++)); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
  return 1
}

capture_filter() {
  case "$1" in
    overview) printf '%s' '' ;;
    flood) printf '%s' 'ether broadcast or ether multicast or arp' ;;
    basic) printf '%s' 'arp or icmp or icmp6 or port 53 or port 67 or port 68 or ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc' ;;
    dns) printf '%s' 'port 53' ;;
    dhcp) printf '%s' 'port 67 or port 68' ;;
    arp) printf '%s' 'arp' ;;
    icmp) printf '%s' 'icmp or icmp6' ;;
    discovery|lldp) printf '%s' 'ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc' ;;
    *) echo "unsupported capture profile" >&2; return 2 ;;
  esac
}

systemd_wireguard_profile() {
  local reference="${1:-}"
  [[ "$reference" =~ ^wg-quick:([a-zA-Z0-9_.-]+)$ ]] || return 1
  printf '%s\n' "${BASH_REMATCH[1]}"
}

systemd_wireguard_profile_from_uuid() {
  local uuid="${1:-}" connection_type device
  [[ "$uuid" =~ ^[0-9a-fA-F-]{36}$ ]] || return 1
  connection_type="$(nmcli -g connection.type connection show uuid "$uuid" 2>/dev/null || true)"
  [[ "$connection_type" == "wireguard" ]] || return 1
  device="$(nmcli -g GENERAL.DEVICES connection show uuid "$uuid" 2>/dev/null | head -1 || true)"
  [[ "$device" =~ ^[a-zA-Z0-9_.-]+$ ]] || return 1
  systemctl cat "wg-quick@${device}.service" >/dev/null 2>&1 || return 1
  printf '%s\n' "$device"
}

list_systemd_wireguard_profiles() {
  local unit load active sub profile
  while read -r unit load active sub; do
    [[ "$unit" =~ ^wg-quick@([a-zA-Z0-9_.-]+)\.service$ ]] || continue
    profile="${BASH_REMATCH[1]}"
    [[ -n "${nm_wireguard_profiles[$profile]:-}" ]] && continue
    printf '%s\twg-quick:%s\twireguard-systemd\t%s\n' "$profile" "$profile" "$active"
  done < <(systemctl list-units 'wg-quick@*.service' --all --no-legend --no-pager --plain 2>/dev/null || true)
}

show_interface_status() {
  local interface raw_state addresses service_state nm_state display_state
  printf '%-18s %-18s %s\n' '인터페이스' '상태' '주소'
  while read -r interface raw_state addresses; do
    [[ "$interface" == "lo" ]] && continue
    display_state="$raw_state"
    if ip -d link show dev "$interface" 2>/dev/null | grep -qw wireguard; then
      service_state="$(systemctl is-active "wg-quick@${interface}.service" 2>/dev/null || true)"
      nm_state="$(nmcli -g GENERAL.STATE connection show "$interface" 2>/dev/null || true)"
      if [[ "$service_state" == "active" || "$nm_state" == "activated" ]]; then
        display_state='터널 인터페이스 활성'
      elif [[ "$service_state" == "inactive" || "$nm_state" == "deactivated" ]]; then
        display_state='터널 비활성'
      else
        display_state='터널 인터페이스 상태 확인 필요'
      fi
    fi
    printf '%-18s %-18s %s\n' "$interface" "$display_state" "${addresses:-주소 없음}"
  done < <(ip -br address)
  printf '\n경로\n'
  ip route
}

case "$action" in
  tinysa-status)
    [[ -f "$COLLECTOR_ENV" ]] || { echo "collector env not found" >&2; exit 2; }
    enabled="$(awk -F= '$1 == "TINYSA_ENABLED" {value=$2} END {print value}' "$COLLECTOR_ENV")"
    [[ "$enabled" == "true" ]] || enabled=false
    jq -n --argjson enabled "$enabled" '{enabled:$enabled}'
    ;;
  arp-scan)
    interface="${2:-}"; require_interface "$interface"
    exec arp-scan --interface="$interface" --localnet
    ;;
  capture)
    interface="${2:-}"; profile="${3:-basic}"; duration="${4:-15}"
    require_interface "$interface"
    [[ "$duration" =~ ^[0-9]+$ ]] && ((duration >= 5 && duration <= 120)) || { echo "duration must be 5..120 seconds" >&2; exit 2; }
    filter="$(capture_filter "$profile")"
    install -d -m 750 -o root -g adm "$OUTPUT_DIR"
    file="$OUTPUT_DIR/gui-${profile}-$(date +%Y%m%d-%H%M%S).pcap"
    echo "캡처 시작: interface=$interface profile=$profile duration=${duration}s"
    tcpdump_args=(-ni "$interface" -s 256 -c 5000 -w "$file")
    [[ -n "$filter" ]] && tcpdump_args+=("$filter")
    timeout --signal=INT "${duration}s" tcpdump "${tcpdump_args[@]}" 2>&1 || rc=$?
    [[ "${rc:-0}" == 0 || "${rc:-0}" == 124 ]] || exit "$rc"
    chgrp adm "$file"; chmod 640 "$file"
    packets="$(capinfos -c "$file" 2>/dev/null | awk -F: '/Number of packets/ {gsub(/ /,"",$2); print $2}' || true)"
    echo "저장 완료: $file"
    echo "패킷 수: ${packets:-확인 불가}"
    ;;
  live-capture)
    interface="${2:-}"; profile="${3:-basic}"; duration="${4:-600}"
    require_interface "$interface"
    [[ "$duration" =~ ^[0-9]+$ ]] && ((duration >= 60 && duration <= 1800)) || { echo "duration must be 60..1800 seconds" >&2; exit 2; }
    filter="$(capture_filter "$profile")"
    install -d -m 750 -o root -g adm "$OUTPUT_DIR"
    file="$OUTPUT_DIR/live-${profile}-$(date +%Y%m%d-%H%M%S).pcapng"
    printf '#META\t%s\t%s\t%s\n' "$file" "$interface" "$profile"
    tshark_args=(
      -l -n -i "$interface" -s 256
      -a "duration:${duration}" -a filesize:51200
      -w "$file" -P -T fields -E separator=/t -E quote=n -E occurrence=f
      -e frame.number -e frame.time_epoch -e eth.src -e eth.dst
      -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst
      -e _ws.col.Protocol -e frame.len -e _ws.col.Info
      -e udp.srcport -e udp.dstport
    )
    [[ -n "$filter" ]] && tshark_args+=(-f "$filter")
    set +e
    capture_pid=''
    stop_signal=''
    forward_capture_signal() {
      stop_signal="$1"
      [[ -n "$capture_pid" ]] && kill "-${stop_signal}" "$capture_pid" 2>/dev/null || true
    }
    trap 'forward_capture_signal INT' INT
    trap 'forward_capture_signal TERM' TERM
    tshark "${tshark_args[@]}" 2>&1 &
    capture_pid=$!
    wait "$capture_pid"
    rc=$?
    if [[ -n "$stop_signal" ]] && kill -0 "$capture_pid" 2>/dev/null; then
      wait "$capture_pid"
      rc=$?
    fi
    trap - INT TERM
    set -e
    if [[ -f "$file" ]]; then
      chgrp adm "$file"
      chmod 640 "$file"
      packets="$(capinfos -c "$file" 2>/dev/null | awk -F: '/Number of packets/ {gsub(/ /,"",$2); print $2}' || true)"
      printf '#DONE\t%s\t%s\n' "$file" "${packets:-0}"
    fi
    [[ "$rc" == 0 || "$rc" == 130 || "$rc" == 143 ]] || exit "$rc"
    ;;
  stop-live-capture)
    pid="${2:-}"
    if ! pgid="$(require_live_capture_pid "$pid")"; then
      exit 0
    fi
    echo "requesting graceful capture stop: pid=${pid} pgid=${pgid}"
    kill -INT -- "-${pgid}" 2>/dev/null || true
    if wait_for_process_exit "$pid" 50; then
      echo "capture stopped with SIGINT"
      exit 0
    fi
    kill -TERM -- "-${pgid}" 2>/dev/null || true
    if wait_for_process_exit "$pid" 30; then
      echo "capture stopped with SIGTERM"
      exit 0
    fi
    kill -KILL -- "-${pgid}" 2>/dev/null || true
    wait_for_process_exit "$pid" 10 || true
    echo "capture required SIGKILL"
    ;;
  list-captures)
    find "$OUTPUT_DIR" -maxdepth 1 -type f \( -name 'gui-*.pcap' -o -name 'live-*.pcapng' \) -printf '%TY-%Tm-%Td %TH:%TM\t%k KB\t%p\n' 2>/dev/null | sort -r | head -30
    ;;
  summarize)
    file="${2:-}"
    case "$file" in
      "$OUTPUT_DIR"/gui-*.pcap|"$OUTPUT_DIR"/live-*.pcapng) ;;
      *) echo "invalid capture file" >&2; exit 2 ;;
    esac
    [[ -f "$file" ]] || { echo "capture file not found" >&2; exit 2; }
    if [[ -x "$PACKET_FLOOD_ANALYZER" ]]; then
      "$PACKET_FLOOD_ANALYZER" "$file"
      echo
    else
      echo "[플러딩 분석]"
      echo "분석기 미설치"
      echo
    fi
    echo "[프로토콜 분포]"
    tshark -r "$file" -q -z io,phs 2>/dev/null | head -60
    echo; echo "[상위 통신 흐름]"
    tshark -r "$file" -T fields -e ip.src -e ip.dst -e _ws.col.Protocol 2>/dev/null | awk 'NF' | sort | uniq -c | sort -nr | head -30
    ;;
  interface-status)
    show_interface_status
    ;;
  wireless-scan)
    [[ -x "$WIRELESS_SCAN" ]] || { echo "wireless scanner is not installed" >&2; exit 2; }
    exec "$WIRELESS_SCAN"
    ;;
  tinysa-config)
    model="${2:-}"
    device="${3:-}"
    band="${4:-}"
    start_hz="${5:-}"
    stop_hz="${6:-}"
    points="${7:-}"
    interval="${8:-}"
    antenna_profile="${9:-unknown}"
    calibration_state="${10:-uncalibrated}"
    aggregation="${11:-max_hold}"
    sweep_repetitions="${12:-8}"
    enabled="${13:-true}"
    [[ "$model" == "tinySA Ultra+ ZS407" ]] || { echo "unsupported tinySA model" >&2; exit 2; }
    [[ "$device" =~ ^/dev/[a-zA-Z0-9_.-]+$ && -c "$device" ]] || { echo "tinySA serial device not found" >&2; exit 2; }
    [[ "$band" =~ ^(wifi_2_4ghz|wifi_5ghz|wifi_6ghz|broadcast_fm|broadcast_vhf|broadcast_uhf_tv|satellite_lnb_if|appliance_rfid_13m|appliance_srd_433m|appliance_rfid_900m|appliance_2_4ghz|appliance_5_8ghz|custom)$ ]] \
      || { echo "unsupported tinySA band" >&2; exit 2; }
    [[ "$start_hz" =~ ^[0-9]+$ && "$stop_hz" =~ ^[0-9]+$ ]] || { echo "tinySA frequency must be an integer" >&2; exit 2; }
    (( start_hz >= 100000 && stop_hz > start_hz && stop_hz <= 7300000000 )) || { echo "tinySA frequency range must be 0.1..7300 MHz" >&2; exit 2; }
    [[ "$points" =~ ^[0-9]+$ ]] && (( points >= 51 && points <= 450 )) || { echo "tinySA points must be 51..450" >&2; exit 2; }
    [[ "$interval" =~ ^[0-9]+$ ]] && (( interval >= 5 && interval <= 300 )) || { echo "tinySA interval must be 5..300 seconds" >&2; exit 2; }
    [[ "$antenna_profile" =~ ^[a-zA-Z0-9._+-]{1,40}$ ]] || { echo "invalid tinySA antenna profile" >&2; exit 2; }
    [[ "$calibration_state" =~ ^(unknown|uncalibrated|level_calibrated)$ ]] || { echo "invalid tinySA calibration state" >&2; exit 2; }
    [[ "$aggregation" =~ ^(single_sweep|max_hold|average|min_hold)$ ]] || { echo "invalid tinySA aggregation" >&2; exit 2; }
    [[ "$sweep_repetitions" =~ ^[0-9]+$ ]] && (( sweep_repetitions >= 1 && sweep_repetitions <= 32 )) || { echo "tinySA repetitions must be 1..32" >&2; exit 2; }
    [[ "$enabled" =~ ^(true|false)$ ]] || { echo "tinySA enabled must be true or false" >&2; exit 2; }
    [[ "$aggregation" != "single_sweep" ]] || sweep_repetitions=1
    [[ -f "$COLLECTOR_ENV" ]] || { echo "collector env not found" >&2; exit 2; }
    cp -a "$COLLECTOR_ENV" "${COLLECTOR_ENV}.$(date +%Y%m%d%H%M%S).bak"
    temporary="$(mktemp)"
    awk '!/^TINYSA_(ENABLED|DEVICE|SENSOR_ID|DEVICE_MODEL|BAND|START_HZ|STOP_HZ|POINTS|SWEEP_REPETITIONS|AGGREGATION|INTERVAL_SECONDS|TIMEOUT_MS|ANTENNA_PROFILE|CALIBRATION_STATE)=/' "$COLLECTOR_ENV" > "$temporary"
    {
      printf 'TINYSA_ENABLED=%s\n' "$enabled"
      printf 'TINYSA_DEVICE=%s\n' "$device"
      printf 'TINYSA_SENSOR_ID=tinysa-zs407-400\n'
      printf 'TINYSA_DEVICE_MODEL=%s\n' "$model"
      printf 'TINYSA_BAND=%s\n' "$band"
      printf 'TINYSA_START_HZ=%s\n' "$start_hz"
      printf 'TINYSA_STOP_HZ=%s\n' "$stop_hz"
      printf 'TINYSA_POINTS=%s\n' "$points"
      printf 'TINYSA_SWEEP_REPETITIONS=%s\n' "$sweep_repetitions"
      printf 'TINYSA_AGGREGATION=%s\n' "$aggregation"
      printf 'TINYSA_INTERVAL_SECONDS=%s\n' "$interval"
      printf 'TINYSA_TIMEOUT_MS=15000\n'
      printf 'TINYSA_ANTENNA_PROFILE=%s\n' "$antenna_profile"
      printf 'TINYSA_CALIBRATION_STATE=%s\n' "$calibration_state"
    } >> "$temporary"
    install -m 600 -o root -g root "$temporary" "$COLLECTOR_ENV"
    rm -f "$temporary"
    systemctl restart nms-wifi-analysis.service
    jq -n \
      --arg model "$model" --arg device "$device" --arg band "$band" \
      --argjson start_hz "$start_hz" --argjson stop_hz "$stop_hz" \
      --argjson points "$points" --argjson interval_seconds "$interval" \
      --arg antenna_profile "$antenna_profile" --arg calibration_state "$calibration_state" \
      --arg aggregation "$aggregation" --argjson sweep_repetitions "$sweep_repetitions" --argjson enabled "$enabled" \
      '{model:$model,device:$device,band:$band,start_hz:$start_hz,stop_hz:$stop_hz,points:$points,interval_seconds:$interval_seconds,antenna_profile:$antenna_profile,calibration_state:$calibration_state,aggregation:$aggregation,sweep_repetitions:$sweep_repetitions,enabled:$enabled,service:"restarted"}'
    ;;
  collector-name)
    name="${2:-}"
    [[ -n "$name" && "${#name}" -le 80 ]] || { echo "collector name must contain 1..80 characters" >&2; exit 2; }
    [[ "$name" != *$'\n'* && "$name" != *$'\r'* && "$name" != *'='* && "$name" != *'"'* && "$name" != *'\'* ]] \
      || { echo "collector name contains unsupported characters" >&2; exit 2; }
    [[ -f "$COLLECTOR_ENV" ]] || { echo "collector env not found" >&2; exit 2; }
    cp -a "$COLLECTOR_ENV" "${COLLECTOR_ENV}.$(date +%Y%m%d%H%M%S).bak"
    temporary="$(mktemp)"
    awk '!/^COLLECTOR_NAME=/' "$COLLECTOR_ENV" > "$temporary"
    printf 'COLLECTOR_NAME=%s\n' "$name" >> "$temporary"
    install -m 640 -o root -g root "$temporary" "$COLLECTOR_ENV"
    rm -f "$temporary"
    systemctl restart nms-collector-heartbeat.service
    printf '{"collector_name":"%s","heartbeat":"sent"}\n' "$name"
    ;;
  vpn-list)
    while IFS=: read -r name uuid connection_type device; do
      [[ "$connection_type" == "vpn" || "$connection_type" == "wireguard" ]] || continue
      if profile="$(systemd_wireguard_profile_from_uuid "$uuid")"; then
        state="$(systemctl is-active "wg-quick@${profile}.service" 2>/dev/null || true)"
        nm_wireguard_profiles["$profile"]=1
        printf '%s\t%s\twireguard-systemd\t%s\n' "$name" "$uuid" "$state"
        continue
      fi
      printf '%s\t%s\t%s\t%s\n' "$name" "$uuid" "$connection_type" "$device"
    done < <(nmcli -t --escape no -f NAME,UUID,TYPE,DEVICE connection show 2>/dev/null || true)
    list_systemd_wireguard_profiles
    ;;
  vpn-import)
    vpn_type="${2:-}"; file="${3:-}"
    [[ "$vpn_type" == "openvpn" || "$vpn_type" == "wireguard" ]] || { echo "unsupported VPN type" >&2; exit 2; }
    file="$(readlink -f "$file" 2>/dev/null || true)"
    [[ -f "$file" && ( "$file" == /home/* || "$file" == /tmp/* ) ]] || { echo "VPN config file not found or outside allowed paths" >&2; exit 2; }
    case "$vpn_type:$file" in
      openvpn:*.ovpn|openvpn:*.conf|wireguard:*.conf) ;;
      *) echo "file extension does not match VPN type" >&2; exit 2 ;;
    esac
    nmcli connection import type "$vpn_type" file "$file"
    echo "VPN 설정을 가져왔습니다. 인증정보가 필요한 경우 연결 편집에서 입력하세요."
    ;;
  vpn-up|vpn-down|vpn-delete|vpn-details)
    uuid="${2:-}"
    if profile="$(systemd_wireguard_profile "$uuid")"; then
      unit="wg-quick@${profile}.service"
      case "$action" in
        vpn-up)
          [[ -f "/etc/wireguard/${profile}.conf" ]] || { echo "WireGuard profile not found: $profile" >&2; exit 2; }
          exec systemctl start "$unit"
          ;;
        vpn-down)
          [[ -f "/etc/wireguard/${profile}.conf" ]] || { echo "WireGuard profile not found: $profile" >&2; exit 2; }
          exec systemctl stop "$unit"
          ;;
        vpn-delete)
          echo "system-managed WireGuard profiles cannot be deleted from this GUI" >&2
          exit 2
          ;;
        vpn-details)
          state="$(systemctl is-active "$unit" 2>/dev/null || true)"
          printf 'Profile: %s\nService: %s\nState: %s\n' "$profile" "$unit" "${state:-unknown}"
          ip -br -4 address show dev "$profile" 2>/dev/null || true
          exit 0
          ;;
      esac
    fi
    if profile="$(systemd_wireguard_profile_from_uuid "$uuid")"; then
      unit="wg-quick@${profile}.service"
      case "$action" in
        vpn-up)
          exec systemctl start "$unit"
          ;;
        vpn-down)
          exec systemctl stop "$unit"
          ;;
        vpn-delete)
          echo "system-managed WireGuard profiles cannot be deleted from this GUI" >&2
          exit 2
          ;;
        vpn-details)
          state="$(systemctl is-active "$unit" 2>/dev/null || true)"
          printf 'Management: systemd wg-quick\nProfile: %s\nService: %s\nState: %s\n' "$profile" "$unit" "${state:-unknown}"
          nmcli -f GENERAL.NAME,GENERAL.UUID,GENERAL.STATE,GENERAL.DEVICES,IP4.ADDRESS,IP4.GATEWAY connection show uuid "$uuid" 2>/dev/null || true
          exit 0
          ;;
      esac
    fi
    [[ "$uuid" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo "invalid connection UUID" >&2; exit 2; }
    connection_type="$(nmcli -g connection.type connection show uuid "$uuid")"
    [[ "$connection_type" == "vpn" || "$connection_type" == "wireguard" ]] || { echo "selected connection is not a VPN" >&2; exit 2; }
    case "$action" in
      vpn-up) nmcli connection up uuid "$uuid" ;;
      vpn-down) nmcli connection down uuid "$uuid" ;;
      vpn-delete) nmcli connection delete uuid "$uuid" ;;
      vpn-details)
        nmcli -f GENERAL.NAME,GENERAL.UUID,GENERAL.STATE,GENERAL.DEVICES,IP4.ADDRESS,IP4.GATEWAY,IP4.ROUTE connection show uuid "$uuid" 2>/dev/null
        nmcli -f connection.id,connection.uuid,connection.type,connection.interface-name,connection.autoconnect connection show uuid "$uuid" 2>/dev/null
        ;;
    esac
    ;;
  *)
    echo "usage: $0 {arp-scan|capture|live-capture|list-captures|summarize|interface-status|wireless-scan|tinysa-config|collector-name|vpn-list|vpn-import|vpn-up|vpn-down|vpn-delete|vpn-details}" >&2
    exit 2
    ;;
esac
