#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="/var/log/nms-pcap"
WIRELESS_SCAN="/opt/nms-collector/nms-wireless-scan.py"
action="${1:-}"
declare -A nm_wireguard_profiles=()

require_interface() {
  [[ "$1" =~ ^[a-zA-Z0-9_.:-]+$ ]] || { echo "invalid interface" >&2; exit 2; }
  ip link show "$1" >/dev/null 2>&1 || { echo "interface not found: $1" >&2; exit 2; }
}

capture_filter() {
  case "$1" in
    overview) printf '%s' '' ;;
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
    )
    [[ -n "$filter" ]] && tshark_args+=(-f "$filter")
    set +e
    trap ':' INT TERM
    tshark "${tshark_args[@]}" 2>&1 &
    capture_pid=$!
    wait "$capture_pid"
    rc=$?
    trap - INT TERM
    set -e
    if [[ -f "$file" ]]; then
      chgrp adm "$file"
      chmod 640 "$file"
      packets="$(capinfos -c "$file" 2>/dev/null | awk -F: '/Number of packets/ {gsub(/ /,"",$2); print $2}' || true)"
      printf '#DONE\t%s\t%s\n' "$file" "${packets:-0}"
    fi
    [[ "$rc" == 0 || "$rc" == 130 ]] || exit "$rc"
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
    echo "usage: $0 {arp-scan|capture|live-capture|list-captures|summarize|interface-status|wireless-scan|vpn-list|vpn-import|vpn-up|vpn-down|vpn-delete|vpn-details}" >&2
    exit 2
    ;;
esac
