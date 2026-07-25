#!/usr/bin/env python3
import ipaddress
import getpass
import grp
import json
import math
import os
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

sys.path.insert(0, "/usr/local/lib/metro-nms-collector")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ict_field_client import IctFieldClient, load_device_config
from nms_packet_flood import add_packet, empty_counts, summarize_counts

HELPER = "/opt/nms-collector/configure-snmp-targets.sh"
NODE = "/usr/local/bin/node"
COLLECTOR = "/opt/nms-collector/nms-collector.js"
MEASUREMENT_SESSION = "/opt/nms-collector/nms-measurement-session.js"
MEASUREMENT_CONTROL = "/opt/nms-collector/measurement-session-control.sh"
GUI_OPS = "/opt/nms-collector/nms-gui-operations.sh"
TINYSA_HELPER = "/opt/nms-collector/nms-tinysa-sweep.py"
TINYSA_CONFIG_HELPER = "/opt/nms-collector/configure-tinysa.sh"
DEFAULT_COLLECTOR_NAME = "메트로정보통신 네트워크 현장 분석기"
TINYSA_MODEL = "tinySA Ultra+ ZS407"
TINYSA_DEVICE = "/dev/tinysa4"
TINYSA_BAND_CATALOG = {
    "AP": (
        {"id": "wifi_2_4ghz", "label": "2.4GHz Wi-Fi", "start_mhz": "2400", "stop_mhz": "2500", "axis": "wifi_2_4"},
        {"id": "wifi_5ghz", "label": "5GHz Wi-Fi", "start_mhz": "5150", "stop_mhz": "5850", "axis": "wifi_5"},
        {"id": "wifi_6ghz", "label": "6GHz Wi-Fi", "start_mhz": "5925", "stop_mhz": "7125", "axis": "wifi_6"},
    ),
    "방송": (
        {"id": "broadcast_fm", "label": "FM 라디오", "start_mhz": "87.5", "stop_mhz": "108", "axis": "frequency"},
        {"id": "broadcast_vhf", "label": "VHF 방송 (DMB 포함)", "start_mhz": "174", "stop_mhz": "216", "axis": "frequency"},
        {"id": "broadcast_uhf_tv", "label": "UHF 지상파 TV / TVWS", "start_mhz": "470", "stop_mhz": "698", "axis": "frequency"},
        {"id": "satellite_lnb_if", "label": "위성 LNB 출력 IF", "start_mhz": "950", "stop_mhz": "2150", "axis": "frequency"},
    ),
    "가전": (
        {"id": "appliance_rfid_13m", "label": "13.56MHz NFC / RFID", "start_mhz": "13.552", "stop_mhz": "13.568", "axis": "frequency"},
        {"id": "appliance_srd_433m", "label": "433MHz 소출력 기기", "start_mhz": "433.67", "stop_mhz": "434.17", "axis": "frequency"},
        {"id": "appliance_rfid_900m", "label": "900MHz RFID / IoT", "start_mhz": "917", "stop_mhz": "923.5", "axis": "frequency"},
        {"id": "appliance_2_4ghz", "label": "2.4GHz Bluetooth / Zigbee / 가전", "start_mhz": "2400", "stop_mhz": "2483.5", "axis": "frequency"},
        {"id": "appliance_5_8ghz", "label": "5.8GHz 데이터 / 가전", "start_mhz": "5725", "stop_mhz": "5825", "axis": "frequency"},
    ),
    "사용자 정의": (
        {"id": "custom", "label": "직접 입력", "start_mhz": "", "stop_mhz": "", "axis": "frequency"},
    ),
}
TINYSA_LEGACY_BANDS = {
    "2.4GHz": "wifi_2_4ghz",
    "5GHz": "wifi_5ghz",
    "6GHz": "wifi_6ghz",
    "custom": "custom",
}
TINYSA_WIFI_AXIS = {
    "wifi_2_4": {"label": "2.4 GHz Wi-Fi", "grid_step_hz": 10_000_000},
    "wifi_5": {"label": "5 GHz Wi-Fi", "grid_step_hz": 100_000_000},
    "wifi_6": {"label": "6 GHz Wi-Fi", "grid_step_hz": 200_000_000},
}
TINYSA_CALIBRATION_OPTIONS = {
    "교정 완료": "level_calibrated",
    "미보정": "uncalibrated",
    "확인 필요": "unknown",
}
TINYSA_AGGREGATION_OPTIONS = {
    "단일 스윕": "single_sweep",
    "최대값 유지 (Max Hold)": "max_hold",
    "평균 (Average)": "average",
    "최소값 유지 (Min Hold)": "min_hold",
}
TINYSA_ERROR_LABELS = {
    "device_not_found": "USB 장치를 찾지 못했습니다. 케이블과 장치 경로를 확인하세요.",
    "permission_denied": "장치 접근 권한이 없습니다. dialout 그룹과 udev 규칙을 확인하세요.",
    "device_busy": "다른 측정 작업이 장치를 사용 중입니다. 자동수집 완료 후 다시 시도하세요.",
    "command_timeout": "장비 응답 시간이 초과되었습니다. USB 연결과 펌웨어 상태를 확인하세요.",
    "dependency_missing": "pyserial 구성요소가 설치되지 않았습니다.",
    "protocol_error": "장비 응답 형식이 올바르지 않습니다. 모델과 펌웨어를 확인하세요.",
    "measurement_failed": "RF 측정에 실패했습니다. 장치 로그를 확인하세요.",
}

def tinysa_permission_message(device=TINYSA_DEVICE):
    path=Path(device)
    if not path.exists() or os.access(path,os.R_OK|os.W_OK):
        return None
    try:
        dialout=grp.getgrnam("dialout")
        configured=getpass.getuser() in dialout.gr_mem
        active=dialout.gr_gid in os.getgroups()
    except KeyError:
        configured=False; active=False
    if configured and not active:
        return (
            "현재 데스크톱 로그인에 새 dialout 권한이 아직 반영되지 않았습니다. "
            "앱을 다시 실행하거나 Ubuntu에서 한 번 로그아웃 후 로그인하세요."
        )
    return (
        "tinySA 장치 읽기·쓰기 권한이 없습니다. 설치 관리자가 사용자를 "
        "dialout 그룹에 추가하고 udev 규칙을 다시 적용해야 합니다."
    )
FIELD_PROFILE_STORE = Path.home() / ".config" / "metro-nms-field-collector" / "field-profiles.json"
COLLECTOR_SETTINGS_STORE = Path.home() / ".config" / "metro-nms-field-collector" / "collector-settings.json"
ICT_DEVICE_CONFIG = Path.home() / ".config" / "metro-nms-field-collector" / "ict-manager-device.json"
ICT_OFFLINE_QUEUE = Path.home() / ".config" / "metro-nms-field-collector" / "ict-manager-offline-queue.json"
ICT_SITE_CACHE = Path.home() / ".config" / "metro-nms-field-collector" / "ict-manager-sites-cache.json"
SERVICES = [
    ("중앙 서버 연결", "nms-collector-heartbeat.timer"),
    ("WireGuard 터널", "wg-quick@metro-omada.service"),
    ("원격 진단", "nms-collector-diagnostic-worker.service"),
    ("정기 분석", "nms-collector-edge-analysis.timer"),
    ("SNMP Trap", "nms-collector-trap-forwarder.service"),
    ("대역폭 측정 서버", "nms-iperf3-server.service"),
    ("Syslog 수신", "rsyslog.service"),
    ("LLDP 수신", "lldpd.service"),
]
COMMANDS = {
    "게이트웨이 Ping": "GW=$(ip route | awk '/default/ {print $3; exit}'); test -n \"$GW\" && ping -c 4 -W 2 \"$GW\"",
    "인터넷 Ping": "ping -c 4 -W 2 1.1.1.1",
    "DNS 확인": "getent hosts naver.com; resolvectl status 2>/dev/null | head -35",
    "경로 추적": "mtr -r -c 5 -w \"$NMS_DIAG_TARGET\" 2>&1 || traceroute -n -m 12 -w 2 \"$NMS_DIAG_TARGET\"",
    "ARP 이웃": "ip neigh",
    "무선 검색": "nmcli -f IN-USE,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY dev wifi list --rescan yes",
    "포트 점검": "nmap -Pn --top-ports 50 --open \"$NMS_DIAG_TARGET\"",
    "VLAN/LLDP/CDP": "ip -d link show type vlan; echo; lldpcli show neighbors 2>&1",
    "인터페이스": f"{GUI_OPS} interface-status; echo; for i in $(ip -o link show | awk -F': ' '$2 !~ /^lo/ {{print $2}}'); do echo ==== $i; ethtool $i 2>&1 | grep -E 'Speed:|Duplex:|Link detected:'; done",
}
CAPTURE_PROFILES = {
    "전체 헤더": "overview",
    "플러딩 분석": "flood",
    "기본 통신": "basic",
    "DNS": "dns",
    "DHCP": "dhcp",
    "ARP": "arp",
    "Ping": "icmp",
    "LLDP/CDP": "discovery",
}
NETWORK_STATUS_COMMAND = r'''
ROUTE=$(ip -4 route get 1.1.1.1 2>/dev/null | head -1)
IFACE=$(printf '%s\n' "$ROUTE" | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
SRC=$(printf '%s\n' "$ROUTE" | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')
CIDR=$(test -n "$IFACE" && ip -o -4 addr show dev "$IFACE" scope global 2>/dev/null | awk -v src="$SRC" '$4 ~ ("^" src "/") {print $4; exit}')
printf '현재 연결 네트워크\n'
printf '  인터페이스: %s\n' "${IFACE:-미확인}"
printf '  내부 IPv4: %s\n' "${CIDR:-미확인}"
printf '  기본 게이트웨이: %s\n' "$(ip route show default | awk '/default/ {print $3; exit}')"
printf '\n수집기 및 서비스 상태\n'
hostnamectl --static
echo
systemctl is-active nms-collector-heartbeat.timer nms-collector-diagnostic-worker.service nms-collector-edge-analysis.timer 2>&1
'''

def valid_host(value):
    value = value.strip()
    if not value or any(c.isspace() for c in value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return all(part and part.replace("-", "").isalnum() for part in value.rstrip(".").split("."))

def parse_settings(text):
    data = json.loads(text.strip())
    data.setdefault("targets", [])
    return data

def format_measurement_session_result(payload):
    state_labels={
        "idle":"대기","preflight":"사전 점검","running":"측정 중","paused":"일시 정지",
        "stopping":"안전 종료 중","completed":"완료","partial":"부분 완료",
        "failed":"실패","cancelled":"취소",
    }
    module_labels={
        "wired":"유선","wireless":"무선","rf":"RF 스펙트럼",
        "packet_capture":"패킷 캡처","system":"시스템",
    }
    module_state_labels={
        "pending":"대기","running":"측정 중","paused":"일시 정지","completed":"완료",
        "failed":"실패","unsupported":"지원 안 됨","skipped":"건너뜀","stopped":"안전 중지",
    }
    profile=payload.get("field_profile") if isinstance(payload.get("field_profile"),dict) else {}
    started=payload.get("started_at")
    ended=payload.get("ended_at")
    def local_time(value):
        if not value:
            return "-"
        try:
            return datetime.fromisoformat(str(value).replace("Z","+00:00")).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return str(value)
    lines=[
        "[측정 세션 결과]",
        f"현장: {profile.get('site_name') or '-'}",
        f"상태: {state_labels.get(payload.get('status'),payload.get('status') or '확인 불가')}",
        f"세션 ID: {payload.get('measurement_session_id') or '-'}",
        f"측정 시각: {local_time(started)} ~ {local_time(ended)}",
    ]
    module_runs=payload.get("module_runs") if isinstance(payload.get("module_runs"),dict) else {}
    summary=payload.get("module_summary") if isinstance(payload.get("module_summary"),dict) else {}
    safe_stopped=payload.get("finalize_reason")=="operator_stop" and payload.get("status") in (
        "completed","partial","failed","cancelled"
    )
    lines.append("")
    lines.append("[모듈별 결과]")
    for key in ("wired","wireless","rf","packet_capture","system"):
        module_run=module_runs.get(key) if isinstance(module_runs.get(key),dict) else {}
        summarized=summary.get(key) if isinstance(summary.get(key),dict) else {}
        if not module_run and not summarized:
            continue
        run={**module_run,**summarized}
        state=run.get("status") or "unknown"
        corrected=safe_stopped and state in ("pending","running","paused")
        if corrected:
            state="stopped"
        sample_count=int(run.get("sample_count") or 0)
        line=f"- {module_labels[key]}: {module_state_labels.get(state,state)} · 표본 {sample_count}개"
        if corrected:
            line+=" · 안전 중지 기록 보정"
        settings=run.get("settings") if isinstance(run.get("settings"),dict) else {}
        if key=="rf" and settings.get("expected_bands"):
            labels={
                "wifi_2_4ghz":"2.4GHz","wifi_5ghz":"5GHz","wifi_6ghz":"6GHz",
            }
            observed=", ".join(labels.get(value,value) for value in settings.get("observed_bands",[])) or "없음"
            expected=", ".join(labels.get(value,value) for value in settings["expected_bands"])
            line+=f" · 측정 대역 {observed} / 예정 {expected}"
        if run.get("error_message"):
            line+=f" · {run['error_message']}"
        lines.append(line)
    if payload.get("status")=="partial":
        lines.extend(("", "부분 완료는 안전 중지 또는 일부 모듈 실패를 뜻합니다. 완료된 모듈의 결과는 보존됩니다."))
    return "\n".join(lines)

def normalize_collector_name(value):
    name = str(value or "").strip()
    if not name:
        raise ValueError("수집기 이름을 입력하세요.")
    if len(name) > 80:
        raise ValueError("수집기 이름은 80자 이하여야 합니다.")
    if any(ord(character) < 32 for character in name) or any(character in name for character in ('=', '"', '\\')):
        raise ValueError("수집기 이름에 사용할 수 없는 문자가 있습니다.")
    return name

def load_collector_settings():
    try:
        payload = json.loads(COLLECTOR_SETTINGS_STORE.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}

def update_collector_settings(updates):
    payload = load_collector_settings()
    payload.update(updates)
    COLLECTOR_SETTINGS_STORE.parent.mkdir(parents=True, exist_ok=True)
    temporary = COLLECTOR_SETTINGS_STORE.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, COLLECTOR_SETTINGS_STORE)
    return payload

def load_collector_name():
    try:
        return normalize_collector_name(load_collector_settings().get("collector_name"))
    except ValueError:
        return DEFAULT_COLLECTOR_NAME

def save_collector_name(name):
    normalized = normalize_collector_name(name)
    update_collector_settings({"collector_name": normalized})
    return normalized

def tinysa_preset_by_id(preset_id):
    normalized = TINYSA_LEGACY_BANDS.get(str(preset_id or "").strip(), str(preset_id or "").strip())
    for category, presets in TINYSA_BAND_CATALOG.items():
        for preset in presets:
            if preset["id"] == normalized:
                return category, preset
    return None, None

def tinysa_preset_by_label(category, label):
    for preset in TINYSA_BAND_CATALOG.get(str(category or "").strip(), ()):
        if preset["label"] == str(label or "").strip():
            return preset
    return None

def tinysa_error_message(payload):
    if not isinstance(payload, dict):
        return "RF 장비 응답을 해석할 수 없습니다."
    error_code = payload.get("error_code") or "measurement_failed"
    detail = str(payload.get("error") or "").strip()
    message = TINYSA_ERROR_LABELS.get(error_code, TINYSA_ERROR_LABELS["measurement_failed"])
    return f"{message} ({detail})" if detail else message

def wifi_channel_centers(axis_mode):
    if axis_mode == "wifi_2_4":
        return [(channel, 2_412_000_000 + (channel - 1) * 5_000_000) for channel in range(1, 14)]
    if axis_mode == "wifi_5":
        channels = tuple(range(36, 65, 4)) + tuple(range(100, 145, 4)) + (149, 153, 157, 161, 165)
        return [(channel, (5000 + channel * 5) * 1_000_000) for channel in channels]
    if axis_mode == "wifi_6":
        return [(channel, (5950 + channel * 5) * 1_000_000) for channel in range(1, 234, 4)]
    return []

def evenly_sampled_ticks(values, maximum_ticks):
    if len(values) <= maximum_ticks:
        return list(values)
    indexes=sorted({
        round(index*(len(values)-1)/(maximum_ticks-1))
        for index in range(maximum_ticks)
    })
    return [values[index] for index in indexes]

def nice_frequency_step(start_hz, stop_hz, target_lines=8):
    span=max(1,stop_hz-start_hz)
    raw=span/max(2,target_lines)
    magnitude=10**math.floor(math.log10(raw))
    normalized=raw/magnitude
    factor=1 if normalized<=1 else 2 if normalized<=2 else 5 if normalized<=5 else 10
    return int(factor*magnitude)

def frequency_axis_ticks(start_hz, stop_hz, axis_mode):
    specification=TINYSA_WIFI_AXIS.get(axis_mode)
    step=(specification or {}).get("grid_step_hz") or nice_frequency_step(start_hz,stop_hz)
    first=math.ceil(start_hz/step)*step
    return [(frequency,"") for frequency in range(first,stop_hz+1,step)]

def wifi_channel_axis_ticks(start_hz, stop_hz, axis_mode, maximum_ticks=14):
    channels = [
        (frequency_hz, f"CH {channel}")
        for channel, frequency_hz in wifi_channel_centers(axis_mode)
        if start_hz <= frequency_hz <= stop_hz
    ]
    return evenly_sampled_ticks(channels,maximum_ticks)

def frequency_axis_summary(start_hz, stop_hz, axis_mode):
    specification=TINYSA_WIFI_AXIS.get(axis_mode)
    label=(specification or {}).get("label") or "사용자 지정 RF"
    step=(specification or {}).get("grid_step_hz") or nice_frequency_step(start_hz,stop_hz)
    return {
        "label": label,
        "grid_step_hz": step,
        "range_label": f"{format_frequency(start_hz)} - {format_frequency(stop_hz)}",
    }

def format_frequency(frequency_hz):
    if frequency_hz >= 1_000_000_000:
        return f"{frequency_hz / 1_000_000_000:.3f}".rstrip("0").rstrip(".") + " GHz"
    if frequency_hz >= 1_000_000:
        return f"{frequency_hz / 1_000_000:.3f}".rstrip("0").rstrip(".") + " MHz"
    return f"{frequency_hz / 1_000:.3f}".rstrip("0").rstrip(".") + " kHz"

def normalize_tinysa_settings(
    band, start_mhz, stop_mhz, points, interval_seconds, antenna_profile,
    category=None, calibration_state="uncalibrated", aggregation="max_hold", sweep_repetitions=8,
):
    band = TINYSA_LEGACY_BANDS.get(str(band or "").strip(), str(band or "").strip())
    preset_category, preset = tinysa_preset_by_id(band)
    if not preset:
        raise ValueError("측정 대역을 선택하세요.")
    if category and str(category).strip() != preset_category:
        raise ValueError("대분류와 중분류가 일치하지 않습니다.")
    try:
        start_hz = int(round(float(str(start_mhz).strip()) * 1_000_000))
        stop_hz = int(round(float(str(stop_mhz).strip()) * 1_000_000))
        point_count = int(str(points).strip())
        interval = int(str(interval_seconds).strip())
        repetitions = int(str(sweep_repetitions).strip())
    except ValueError as exc:
        raise ValueError("주파수, 포인트, 수집 주기는 숫자로 입력하세요.") from exc
    if not 100_000 <= start_hz < stop_hz <= 7_300_000_000:
        raise ValueError("ZS407 측정 범위는 0.1MHz 이상 7,300MHz 이하로 설정하세요.")
    if not 51 <= point_count <= 450:
        raise ValueError("스윕 포인트는 51~450으로 설정하세요.")
    if not 5 <= interval <= 300:
        raise ValueError("자동 수집 주기는 5~300초로 설정하세요.")
    antenna = str(antenna_profile or "unknown").strip()
    if not re.fullmatch(r"[a-zA-Z0-9._+-]{1,40}", antenna):
        raise ValueError("안테나 프로필은 영문, 숫자, 점, 밑줄, +, -만 사용할 수 있습니다.")
    calibration = str(calibration_state or "").strip()
    if calibration not in TINYSA_CALIBRATION_OPTIONS.values():
        raise ValueError("교정 상태를 선택하세요.")
    aggregation = str(aggregation or "").strip()
    if aggregation not in TINYSA_AGGREGATION_OPTIONS.values():
        raise ValueError("집계 방식을 선택하세요.")
    if not 1 <= repetitions <= 32:
        raise ValueError("스윕 반복 횟수는 1~32로 설정하세요.")
    if aggregation == "single_sweep":
        repetitions = 1
    return {
        "model": TINYSA_MODEL,
        "device": TINYSA_DEVICE,
        "band": band,
        "category": preset_category,
        "preset_label": preset["label"],
        "axis_mode": preset["axis"],
        "start_hz": start_hz,
        "stop_hz": stop_hz,
        "points": point_count,
        "interval_seconds": interval,
        "antenna_profile": antenna,
        "calibration_state": calibration,
        "aggregation": aggregation,
        "sweep_repetitions": repetitions,
    }

def load_tinysa_settings():
    defaults = {
        "enabled": "false",
        "category": "AP",
        "band": "wifi_5ghz",
        "start_mhz": "5150",
        "stop_mhz": "5850",
        "points": "290",
        "interval_seconds": "30",
        "antenna_profile": "unknown",
        "calibration_state": "uncalibrated",
        "aggregation": "max_hold",
        "sweep_repetitions": "8",
    }
    stored = load_collector_settings().get("tinysa")
    if isinstance(stored, dict):
        for key in defaults:
            if stored.get(key) is not None:
                defaults[key] = str(stored[key])
    defaults["band"] = TINYSA_LEGACY_BANDS.get(defaults["band"], defaults["band"])
    preset_category, preset = tinysa_preset_by_id(defaults["band"])
    if preset:
        defaults["category"] = preset_category
    try:
        normalize_tinysa_settings(
            defaults["band"], defaults["start_mhz"], defaults["stop_mhz"],
            defaults["points"], defaults["interval_seconds"], defaults["antenna_profile"], defaults["category"],
            defaults["calibration_state"], defaults["aggregation"], defaults["sweep_repetitions"],
        )
    except ValueError:
        return {
            "enabled": "false", "category": "AP", "band": "wifi_5ghz", "start_mhz": "5150", "stop_mhz": "5850",
            "points": "290", "interval_seconds": "30", "antenna_profile": "unknown",
            "calibration_state": "uncalibrated",
            "aggregation": "max_hold", "sweep_repetitions": "8",
        }
    return defaults

def save_tinysa_settings(settings):
    local = {
        "enabled": "true" if settings.get("enabled") else "false",
        "category": settings["category"],
        "band": settings["band"],
        "start_mhz": f'{settings["start_hz"] / 1_000_000:g}',
        "stop_mhz": f'{settings["stop_hz"] / 1_000_000:g}',
        "points": str(settings["points"]),
        "interval_seconds": str(settings["interval_seconds"]),
        "antenna_profile": settings["antenna_profile"],
        "calibration_state": settings["calibration_state"],
        "aggregation": settings["aggregation"],
        "sweep_repetitions": str(settings["sweep_repetitions"]),
    }
    update_collector_settings({"tinysa": local})
    return local

def calculate_interface_rates(previous, current, elapsed_seconds):
    if not previous or elapsed_seconds <= 0:
        return {"rx_mbps": 0.0, "tx_mbps": 0.0, "rx_pps": 0.0, "tx_pps": 0.0}
    def delta(key):
        return max(0, int(current.get(key, 0)) - int(previous.get(key, 0)))
    return {
        "rx_mbps": round(delta("rx_bytes") * 8 / elapsed_seconds / 1_000_000, 3),
        "tx_mbps": round(delta("tx_bytes") * 8 / elapsed_seconds / 1_000_000, 3),
        "rx_pps": round(delta("rx_packets") / elapsed_seconds, 1),
        "tx_pps": round(delta("tx_packets") / elapsed_seconds, 1),
    }

def parse_discovery_neighbors(text):
    try:
        payload=json.loads(text)
    except (TypeError,ValueError,json.JSONDecodeError):
        return []
    interfaces=((payload.get("lldp") or {}).get("interface") or {}) if isinstance(payload,dict) else {}
    neighbors=[]
    for interface,value in interfaces.items():
        entries=value if isinstance(value,list) else [value]
        for entry in entries:
            if not isinstance(entry,dict):
                continue
            chassis_container=entry.get("chassis") or {}
            named=next(((name,item) for name,item in chassis_container.items() if isinstance(item,dict)),(None,chassis_container))
            chassis_name,chassis=named
            port=entry.get("port") or {}
            neighbors.append({
                "protocol":str(entry.get("via") or entry.get("protocol") or "LLDP").upper(),
                "local_interface":interface,
                "device":chassis_name or "미확인",
                "management_ip":chassis.get("mgmt-ip") or "-",
                "port":((port.get("id") or {}).get("value") if isinstance(port.get("id"),dict) else port.get("id")) or port.get("descr") or "-",
                "age":entry.get("age") or "-",
            })
    return neighbors

def read_interface_counters(interface):
    base=Path("/sys/class/net") / interface / "statistics"
    values={}
    for key in ("rx_bytes","tx_bytes","rx_packets","tx_packets","rx_errors","tx_errors","rx_dropped","tx_dropped"):
        try: values[key]=int((base/key).read_text(encoding="ascii").strip())
        except (OSError,ValueError): values[key]=0
    return values

class App:
    def __init__(self, root):
        self.root = root
        root.title("METRO NMS Collecter")
        root.geometry("1240x780")
        root.minsize(1000, 650)
        self.events = queue.Queue()
        self.status = tk.StringVar(value="대기 중")
        self.page_title = tk.StringVar(value="현장 프로필")
        self.last_refresh = tk.StringVar(value="마지막 갱신: 확인 전")
        self.last_snapshot = tk.StringVar(value="최근 저장: 없음")
        self.pages = {}
        self.nav_buttons = {}
        self.refresh_batch_pending = set()
        self.refresh_batch_errors = 0
        self.running_jobs = 0
        self.collector_name = tk.StringVar(value=load_collector_name())
        self.collector_name_status = tk.StringVar(value="저장하면 다음 heartbeat부터 중앙 표시명에 반영됩니다.")
        self.pending_collector_name = None
        self.field_profile_name = tk.StringVar()
        self.field_site_name = tk.StringVar()
        self.metro_contact_name = tk.StringVar()
        self.metro_contact_phone = tk.StringVar()
        self.customer_contact_name = tk.StringVar()
        self.customer_contact_phone = tk.StringVar()
        self.active_profile_label = tk.StringVar(value="현장 프로필을 먼저 선택하거나 저장하세요.")
        self.ict_connection_status = tk.StringVar(value="119 연결 확인 전")
        self.field_profiles = self._load_field_profiles()
        self.pending_measurement_profile = None
        self.pending_snapshot_profile = None
        self.target = tk.StringVar(value="1.1.1.1")
        self.version, self.port = tk.StringVar(value="2c"), tk.StringVar(value="161")
        self.timeout, self.retries = tk.StringVar(value="2"), tk.StringVar(value="1")
        self.community_state = tk.StringVar(value="확인 전")
        self.interface = tk.StringVar()
        self.capture_profile = tk.StringVar(value="기본 통신")
        self.capture_seconds = tk.StringVar(value="15")
        self.live_capture_minutes = tk.StringVar(value="10")
        self.live_capture_status = tk.StringVar(value="정지됨")
        self.live_capture_process = None
        self.live_capture_stopping = False
        self.closing = False
        self.close_deadline = None
        self.live_capture_packet_count = 0
        self.live_capture_path = None
        self.live_flood_counts = empty_counts()
        self.live_flood_started_at = None
        self.live_flood_status = tk.StringVar(value="플러딩 분석 대기")
        self.live_monitor_interface = tk.StringVar()
        self.live_monitor_status = tk.StringVar(value="모니터링 정지")
        self.live_monitor_enabled = False
        self.live_monitor_in_flight = False
        self.live_monitor_previous = None
        self.live_monitor_previous_at = None
        self.live_monitor_after_id = None
        self.current_page = ""
        self.measurement_value = tk.StringVar(value="5")
        self.measurement_unit = tk.StringVar(value="분")
        self.measurement_interval = tk.StringVar(value="10")
        self.measurement_status = tk.StringVar(value="동시 측정 대기")
        self.measurement_module_vars = {
            "wired": tk.BooleanVar(value=True),
            "wireless": tk.BooleanVar(value=True),
            "rf": tk.BooleanVar(value=True),
            "packet_capture": tk.BooleanVar(value=False),
            "system": tk.BooleanVar(value=True),
        }
        self.wireless_hidden_only = tk.BooleanVar(value=False)
        self.wireless_payload = None
        tinysa = load_tinysa_settings()
        self.tinysa_auto_enabled = tk.BooleanVar(value=str(tinysa.get("enabled", "false")).lower() == "true")
        tinysa_category, tinysa_preset = tinysa_preset_by_id(tinysa["band"])
        self.tinysa_category = tk.StringVar(value=tinysa_category or "AP")
        self.tinysa_subcategory = tk.StringVar(value=(tinysa_preset or TINYSA_BAND_CATALOG["AP"][0])["label"])
        self.tinysa_band = tk.StringVar(value=tinysa["band"])
        self.tinysa_start_mhz = tk.StringVar(value=tinysa["start_mhz"])
        self.tinysa_stop_mhz = tk.StringVar(value=tinysa["stop_mhz"])
        self.tinysa_points = tk.StringVar(value=tinysa["points"])
        self.tinysa_interval = tk.StringVar(value=tinysa["interval_seconds"])
        self.tinysa_antenna = tk.StringVar(value=tinysa["antenna_profile"])
        calibration_label=next(
            (label for label,value in TINYSA_CALIBRATION_OPTIONS.items() if value == tinysa["calibration_state"]),
            "확인 필요",
        )
        self.tinysa_calibration = tk.StringVar(value=calibration_label)
        aggregation_label=next(
            (label for label,value in TINYSA_AGGREGATION_OPTIONS.items() if value == tinysa["aggregation"]),
            "최대값 유지 (Max Hold)",
        )
        self.tinysa_aggregation = tk.StringVar(value=aggregation_label)
        self.tinysa_repetitions = tk.StringVar(value=tinysa["sweep_repetitions"])
        self.tinysa_status = tk.StringVar(value="장비 상태 확인 전")
        self.tinysa_metric_vars = {}
        self.tinysa_payload = None
        self.tinysa_multi_payload = None
        self.pending_tinysa_settings = None
        self._configure_style()
        self._build()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(150, self._drain)
        self.root.after(350, self.refresh_status)
        self.root.after(700, self.refresh_assigned_sites)
        self.root.after(900, self.refresh_tinysa_config_state)

    def _configure_style(self):
        self.colors = {
            "background": "#f5f5f7",
            "surface": "#ffffff",
            "sidebar": "#202124",
            "sidebar_muted": "#a9adb5",
            "text": "#1d1d1f",
            "muted": "#6e6e73",
            "border": "#d2d2d7",
            "metro_blue": "#1768ac",
            "metro_blue_active": "#0f4f88",
            "metro_red": "#d9363e",
            "success": "#25855a",
        }
        self.root.configure(background=self.colors["background"])
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", font=("Noto Sans CJK KR", 10), background=self.colors["background"], foreground=self.colors["text"])
        style.configure("App.TFrame", background=self.colors["background"])
        style.configure("Surface.TFrame", background=self.colors["surface"])
        style.configure("Sidebar.TFrame", background=self.colors["sidebar"])
        style.configure("Sidebar.TLabel", background=self.colors["sidebar"], foreground="#ffffff")
        style.configure("SidebarMuted.TLabel", background=self.colors["sidebar"], foreground=self.colors["sidebar_muted"])
        style.configure("Brand.TLabel", background=self.colors["sidebar"], foreground="#ffffff", font=("Noto Sans CJK KR", 18, "bold"))
        style.configure("PageTitle.TLabel", background=self.colors["background"], foreground=self.colors["text"], font=("Noto Sans CJK KR", 17, "bold"))
        style.configure("Meta.TLabel", background=self.colors["background"], foreground=self.colors["muted"])
        style.configure("MetricLabel.TLabel", background=self.colors["surface"], foreground=self.colors["muted"], font=("Noto Sans CJK KR", 9))
        style.configure("MetricValue.TLabel", background=self.colors["surface"], foreground=self.colors["text"], font=("Noto Sans CJK KR", 14, "bold"))
        style.configure("Nav.TButton", background=self.colors["sidebar"], foreground="#f5f5f7", borderwidth=0, padding=(16, 10), anchor="w")
        style.map("Nav.TButton", background=[("active", "#34363a")], foreground=[("active", "#ffffff")])
        style.configure("NavActive.TButton", background=self.colors["metro_blue"], foreground="#ffffff", borderwidth=0, padding=(16, 10), anchor="w")
        style.map("NavActive.TButton", background=[("active", self.colors["metro_blue_active"])])
        style.configure("Accent.TButton", background=self.colors["metro_blue"], foreground="#ffffff", borderwidth=0, padding=(14, 8))
        style.map("Accent.TButton", background=[("active", self.colors["metro_blue_active"]), ("disabled", "#9ebbd3")])
        style.configure("Danger.TButton", background=self.colors["metro_red"], foreground="#ffffff", borderwidth=0, padding=(12, 7))
        style.configure("TButton", padding=(10, 7), borderwidth=1)
        style.configure("TLabelFrame", background=self.colors["surface"], bordercolor=self.colors["border"], borderwidth=1, relief="solid")
        style.configure("TLabelFrame.Label", background=self.colors["surface"], foreground=self.colors["text"], font=("Noto Sans CJK KR", 10, "bold"))
        style.configure("Treeview", background=self.colors["surface"], fieldbackground=self.colors["surface"], foreground=self.colors["text"], rowheight=28, bordercolor=self.colors["border"])
        style.configure("Treeview.Heading", background="#ececf0", foreground=self.colors["text"], relief="flat", padding=(8, 7), font=("Noto Sans CJK KR", 9, "bold"))
        style.map("Treeview", background=[("selected", self.colors["metro_blue"])], foreground=[("selected", "#ffffff")])
        style.configure("TEntry", fieldbackground=self.colors["surface"], bordercolor=self.colors["border"], padding=6)
        style.configure("TCombobox", fieldbackground=self.colors["surface"], bordercolor=self.colors["border"], padding=5)

    def _build(self):
        shell = ttk.Frame(self.root, style="App.TFrame")
        shell.pack(fill="both", expand=True)
        sidebar = ttk.Frame(shell, width=218, style="Sidebar.TFrame")
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        brand = ttk.Frame(sidebar, style="Sidebar.TFrame", padding=(18, 18, 14, 16))
        brand.pack(fill="x")
        ttk.Label(brand, text="METRO", style="Brand.TLabel").pack(anchor="w")
        ttk.Label(brand, text="NMS COLLECTER", style="SidebarMuted.TLabel").pack(anchor="w", pady=(1, 0))
        accent = tk.Frame(sidebar, background=self.colors["metro_red"], height=3)
        accent.pack(fill="x", padx=18, pady=(0, 12))
        self.nav = ttk.Frame(sidebar, style="Sidebar.TFrame")
        self.nav.pack(fill="both", expand=True, padx=10)
        footer = ttk.Frame(sidebar, style="Sidebar.TFrame", padding=(16, 12))
        footer.pack(fill="x", side="bottom")
        ttk.Label(footer, textvariable=self.status, style="Sidebar.TLabel", wraplength=185).pack(anchor="w")
        ttk.Label(footer, text="FIELD COLLECTOR · 130", style="SidebarMuted.TLabel").pack(anchor="w", pady=(4, 0))

        main = ttk.Frame(shell, style="App.TFrame", padding=(20, 16, 20, 18))
        main.pack(side="left", fill="both", expand=True)
        header = ttk.Frame(main, style="App.TFrame")
        header.pack(fill="x")
        title_block = ttk.Frame(header, style="App.TFrame")
        title_block.pack(side="left", fill="x", expand=True)
        ttk.Label(title_block, textvariable=self.page_title, style="PageTitle.TLabel").pack(anchor="w")
        ttk.Label(title_block, textvariable=self.last_refresh, style="Meta.TLabel").pack(anchor="w", pady=(3, 0))
        actions = ttk.Frame(header, style="App.TFrame")
        actions.pack(side="right")
        ttk.Button(actions, text="진단 저장", command=lambda: self.create_snapshot(False)).pack(side="left", padx=3)
        ttk.Button(actions, text="중앙 송신", command=self.flush_offline_queue).pack(side="left", padx=3)
        ttk.Button(actions, text="저장 후 송신", style="Accent.TButton", command=lambda: self.create_snapshot(True)).pack(side="left", padx=3)
        self.refresh_all_button = ttk.Button(actions, text="전체 새로고침", command=self.refresh_all)
        self.refresh_all_button.pack(side="left", padx=(9, 0))
        ttk.Label(main, textvariable=self.last_snapshot, style="Meta.TLabel").pack(fill="x", pady=(8, 8))
        self.page_host = ttk.Frame(main, style="Surface.TFrame")
        self.page_host.pack(fill="both", expand=True)
        self._field_profile_tab(); self._status_tab(); self._source_tab(); self._live_monitor_tab(); self._measurement_tab(); self._offline_queue_tab(); self._diag_tab(); self._wireless_tab(); self._spectrum_tab(); self._capture_tab(); self._vpn_tab(); self._snmp_tab(); self._service_tab()
        self.show_page("현장 프로필")
        self._polish_widgets(self.root)

    def _new_page(self, title):
        page = ttk.Frame(self.page_host, padding=16, style="Surface.TFrame")
        page.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.pages[title] = page
        button = ttk.Button(self.nav, text=title, style="Nav.TButton", command=lambda name=title: self.show_page(name))
        button.pack(fill="x", pady=2)
        self.nav_buttons[title] = button
        return page

    def show_page(self, title):
        page = self.pages.get(title)
        if not page:
            return
        page.lift()
        self.current_page=title
        self.page_title.set(title)
        for name, button in self.nav_buttons.items():
            button.configure(style="NavActive.TButton" if name == title else "Nav.TButton")
        if title == "실시간 모니터링" and not self.live_monitor_enabled:
            self.start_live_monitor()
        if title == "RF 스펙트럼":
            self.refresh_tinysa_connection()

    def _polish_widgets(self, widget):
        for child in widget.winfo_children():
            if isinstance(child, tk.Text):
                child.configure(background="#fbfbfc", foreground=self.colors["text"], insertbackground=self.colors["text"], relief="solid", borderwidth=1, highlightthickness=0, padx=10, pady=8)
            self._polish_widgets(child)

    def _field_profile_tab(self):
        tab = self._new_page("현장 프로필")
        saved = ttk.LabelFrame(tab, text="119 할당 현장", padding=10); saved.pack(fill="x")
        ttk.Label(saved, text="현장 선택").grid(row=0, column=0, sticky="w")
        self.field_profile_box = ttk.Combobox(saved, textvariable=self.field_profile_name, state="readonly", width=42)
        self.field_profile_box.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        self.field_profile_box.bind("<<ComboboxSelected>>", lambda _event: self._load_selected_field_profile())
        ttk.Button(saved, text="119 새로고침", command=self.refresh_assigned_sites).grid(row=0, column=2, padx=3)
        ttk.Label(saved, textvariable=self.ict_connection_status).grid(row=1, column=1, columnspan=2, sticky="w", padx=(8, 0), pady=(5, 0))
        saved.columnconfigure(1, weight=1)

        details = ttk.LabelFrame(tab, text="측정 현장 및 연락처", padding=10); details.pack(fill="x", pady=(10, 0))
        fields = (
            ("현장명", self.field_site_name),
            ("메트로 담당자", self.metro_contact_name),
            ("메트로 연락처", self.metro_contact_phone),
            ("고객사 담당자", self.customer_contact_name),
            ("고객사 연락처", self.customer_contact_phone),
        )
        for row, (label, variable) in enumerate(fields):
            ttk.Label(details, text=label).grid(row=row, column=0, sticky="w", pady=4)
            entry = ttk.Entry(details, textvariable=variable, width=48)
            if row == 0:
                entry.configure(state="readonly")
            entry.grid(row=row, column=1, sticky="ew", padx=(12, 0), pady=4)
        details.columnconfigure(1, weight=1)
        ttk.Button(tab, text="현장 프로필 저장", command=self._save_field_profile).pack(anchor="e", pady=(10, 0))
        ttk.Label(tab, text="고객·현장 기준정보는 119에서 자동으로 불러옵니다. 이 화면에서는 측정에 필요한 담당자 정보만 보완합니다.").pack(anchor="w", pady=(12, 0))
        self._refresh_field_profile_choices()

    def _load_field_profiles(self):
        try:
            payload = json.loads(FIELD_PROFILE_STORE.read_text(encoding="utf-8"))
            profiles = payload.get("profiles", []) if isinstance(payload, dict) else []
            return [
                profile for profile in profiles
                if isinstance(profile, dict) and int(profile.get("site_id") or 0) > 0
            ]
        except (OSError, ValueError, json.JSONDecodeError):
            return []

    def _write_field_profiles(self):
        FIELD_PROFILE_STORE.parent.mkdir(parents=True, exist_ok=True)
        temporary = FIELD_PROFILE_STORE.with_suffix(".tmp")
        temporary.write_text(json.dumps({"schema_version": "collector-field-profiles-v1", "profiles": self.field_profiles}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, FIELD_PROFILE_STORE)

    def _profile_display_name(self, profile):
        customer_name = str(profile.get("customer_name", "")).strip()
        site_name = str(profile.get("site_name", "")).strip()
        return f"{customer_name} / {site_name}" if customer_name else site_name

    def _refresh_field_profile_choices(self):
        if not hasattr(self, "field_profile_box"):
            return
        names = [self._profile_display_name(profile) for profile in self.field_profiles if self._profile_display_name(profile)]
        self.field_profile_box["values"] = tuple(names)

    def _field_profile_from_form(self):
        selected = self.field_profile_name.get().strip()
        assigned = next((item for item in self.field_profiles if self._profile_display_name(item) == selected), None)
        if not assigned:
            messagebox.showerror("현장 프로필", "119에서 할당 현장을 불러온 뒤 선택하세요.")
            return None
        profile = {
            "schema_version": "collector-field-profile-v1",
            "site_id": int(assigned["site_id"]),
            "customer_id": int(assigned["customer_id"]),
            "site_name": str(assigned.get("site_name") or "").strip(),
            "customer_name": str(assigned.get("customer_name") or "").strip(),
            "address": assigned.get("address"),
            "scope_started_at": assigned.get("scope_started_at"),
            "metro_contact": {"name": self.metro_contact_name.get().strip(), "phone": self.metro_contact_phone.get().strip()},
            "customer_contact": {"name": self.customer_contact_name.get().strip(), "phone": self.customer_contact_phone.get().strip()},
        }
        missing = [label for label, value in (
            ("현장명", profile["site_name"]),
            ("메트로 담당자", profile["metro_contact"]["name"]),
            ("메트로 연락처", profile["metro_contact"]["phone"]),
            ("고객사 담당자", profile["customer_contact"]["name"]),
            ("고객사 연락처", profile["customer_contact"]["phone"]),
        ) if not value]
        if missing:
            messagebox.showerror("현장 프로필", f"다음 항목을 입력하세요: {', '.join(missing)}")
            return None
        return profile

    def _apply_field_profile(self, profile):
        self.field_site_name.set(profile.get("site_name", ""))
        metro = profile.get("metro_contact") or {}
        customer = profile.get("customer_contact") or {}
        self.metro_contact_name.set(metro.get("name", "")); self.metro_contact_phone.set(metro.get("phone", ""))
        self.customer_contact_name.set(customer.get("name", "")); self.customer_contact_phone.set(customer.get("phone", ""))
        self.field_profile_name.set(self._profile_display_name(profile))
        self.active_profile_label.set(f"현재 측정 현장: {self.field_site_name.get().strip()}")

    def _ict_client(self):
        return IctFieldClient(
            load_device_config(ICT_DEVICE_CONFIG),
            ICT_OFFLINE_QUEUE,
            ICT_SITE_CACHE,
        )

    def refresh_assigned_sites(self):
        if self.running_jobs:
            self.ict_connection_status.set("119 현장 조회 대기")
        self.running_jobs += 1
        self.ict_connection_status.set("119 할당 현장 조회 중")
        def worker():
            try:
                payload, mode = self._ict_client().assigned_sites()
                self.events.put(("119 현장 조회", 0, json.dumps({"payload": payload, "mode": mode}, ensure_ascii=False)))
            except Exception as exc:
                self.events.put(("119 현장 조회", 1, str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _merge_assigned_sites(self, payload, mode):
        existing = {int(item.get("site_id") or 0): item for item in self.field_profiles}
        merged = []
        for site in payload.get("sites") or []:
            site_id = int(site.get("site_id") or 0)
            if not site_id:
                continue
            previous = existing.get(site_id) or {}
            merged.append({
                "schema_version": "collector-field-profile-v1",
                "site_id": site_id,
                "customer_id": int(site.get("customer_id") or 0),
                "site_name": site.get("site_name") or "",
                "customer_name": site.get("customer_name") or "",
                "address": site.get("address"),
                "scope_started_at": site.get("scope_started_at"),
                "metro_contact": previous.get("metro_contact") or {"name": "", "phone": ""},
                "customer_contact": previous.get("customer_contact") or {"name": "", "phone": ""},
            })
        self.field_profiles = sorted(merged, key=lambda item: self._profile_display_name(item))
        self._write_field_profiles()
        self._refresh_field_profile_choices()
        labels = {"vpn": "VPN 연결", "https_fallback": "HTTPS 대체 연결", "cached": "저장된 현장 목록"}
        self.ict_connection_status.set(f"{labels.get(mode, mode)} · 할당 {len(merged)}개")
        current = self.field_profile_name.get()
        names = [self._profile_display_name(item) for item in merged]
        if current not in names:
            self.field_profile_name.set(names[0] if names else "")
        self._load_selected_field_profile()

    def _load_selected_field_profile(self):
        selected = self.field_profile_name.get().strip()
        profile = next((item for item in self.field_profiles if self._profile_display_name(item) == selected), None)
        if profile:
            self._apply_field_profile(profile)

    def _new_field_profile(self):
        self.field_profile_name.set("")
        self.field_site_name.set(""); self.metro_contact_name.set(""); self.metro_contact_phone.set("")
        self.customer_contact_name.set(""); self.customer_contact_phone.set("")
        self.active_profile_label.set("새 현장 프로필을 입력하고 저장하세요.")

    def _save_field_profile(self):
        profile = self._field_profile_from_form()
        if not profile:
            return
        site_name = profile["site_name"]
        self.field_profiles = [
            item for item in self.field_profiles
            if int(item.get("site_id") or 0) != int(profile["site_id"])
        ]
        self.field_profiles.append(profile)
        self.field_profiles.sort(key=lambda item: self._profile_display_name(item))
        self._write_field_profiles()
        self._refresh_field_profile_choices(); self._apply_field_profile(profile)
        messagebox.showinfo("현장 프로필", f"{site_name} 현장 프로필을 저장했습니다.")

    def _delete_field_profile(self):
        selected = self.field_profile_name.get().strip()
        if not selected:
            messagebox.showinfo("현장 프로필", "삭제할 저장 현장을 선택하세요.")
            return
        if not messagebox.askyesno("현장 프로필 삭제", f"{selected} 현장 프로필을 삭제할까요?"):
            return
        self.field_profiles = [item for item in self.field_profiles if self._profile_display_name(item) != selected]
        self._write_field_profiles(); self._refresh_field_profile_choices(); self._new_field_profile()

    def _status_tab(self):
        tab=self._new_page("수집기 현황")
        identity=ttk.LabelFrame(tab,text="수집기 이름",padding=10); identity.pack(fill="x")
        ttk.Entry(identity,textvariable=self.collector_name,width=52).grid(row=0,column=0,sticky="ew")
        ttk.Button(identity,text="이름 저장",style="Accent.TButton",command=self.save_collector_identity).grid(row=0,column=1,padx=(8,0))
        ttk.Label(identity,textvariable=self.collector_name_status).grid(row=1,column=0,columnspan=2,sticky="w",pady=(6,0))
        identity.columnconfigure(0,weight=1)
        top=ttk.Frame(tab); top.pack(fill="x")
        ttk.Button(top,text="새로고침",command=self.refresh_status).pack(side="left")
        ttk.Label(top,text="현재 연결 네트워크는 수집기 heartbeat와 보고서에 함께 기록됩니다.").pack(side="left",padx=(12,0))
        self.summary=tk.Text(tab,height=11,wrap="word",state="disabled",font=("monospace",10)); self.summary.pack(fill="both",expand=True,pady=(10,0))

    def save_collector_identity(self):
        try:
            name=normalize_collector_name(self.collector_name.get())
        except ValueError as exc:
            messagebox.showerror("입력 오류",str(exc))
            return
        self.pending_collector_name=name
        self.collector_name_status.set("수집기 이름 저장 중")
        self.privileged([GUI_OPS,"collector-name",name],label="수집기 이름 저장",timeout=45)

    def _source_tab(self):
        tab=self._new_page("수집 소스")
        self.source_tree=ttk.Treeview(tab,columns=("source","state","evidence","endpoint"),show="headings",height=15)
        for key,title,width in (("source","수집 원천",190),("state","상태",115),("evidence","판단 근거",310),("endpoint","포트 / 대상",150)):
            self.source_tree.heading(key,text=title); self.source_tree.column(key,width=width,anchor="w")
        self.source_tree.pack(fill="both",expand=True)
        self.source_observed=tk.StringVar(value="진단 스냅샷을 저장하면 수집 원천 상태가 표시됩니다.")
        ttk.Label(tab,textvariable=self.source_observed).pack(anchor="w",pady=(8,0))

    def _update_source_status(self, payload):
        for row in self.source_tree.get_children(): self.source_tree.delete(row)
        if not isinstance(payload,dict):
            self.source_observed.set("수집 원천 상태를 불러오지 못했습니다.")
            return
        labels={
            "syslog":"Syslog", "snmp_polling":"SNMP Polling", "snmp_trap":"SNMP Trap",
            "lldp_discovery":"LLDP 이웃", "cdp_discovery":"CDP 이웃",
            "netflow":"NetFlow", "ipfix":"IPFIX", "sflow":"sFlow",
            "dhcp_dns_observation":"DHCP / DNS", "active_probes":"능동 진단",
            "omada_api":"Omada API", "endpoint_collector":"수집기 에이전트",
        }
        states={"active":"수집 중","available":"사용 가능","configured":"설정됨","partial":"일부 가능","unconfigured":"미설정","unavailable":"미수집","unknown":"미확인"}
        for key,value in payload.items():
            if key in ("schema_version","observed_at") or not isinstance(value,dict):
                continue
            endpoint=value.get("port") or value.get("target_count") or "-"
            if value.get("port"): endpoint=f"UDP/TCP {value['port']}"
            elif value.get("target_count") is not None: endpoint=f"대상 {value.get('target_count',0)} · 응답 {value.get('target_up_count',0)}"
            self.source_tree.insert("","end",values=(labels.get(key,key),states.get(value.get("state"),value.get("state") or "미확인"),value.get("source") or "-",endpoint))
        observed=str(payload.get("observed_at") or "").replace("T"," ").replace("Z","")
        self.source_observed.set(f"원천 상태 측정시각: {observed or '미확인'}")

    def _live_monitor_tab(self):
        tab=self._new_page("실시간 모니터링")
        controls=ttk.Frame(tab); controls.pack(fill="x")
        ttk.Label(controls,text="인터페이스").pack(side="left")
        self.live_interface_box=ttk.Combobox(controls,textvariable=self.live_monitor_interface,state="readonly",width=18)
        self.live_interface_box.pack(side="left",padx=(7,12))
        ttk.Button(controls,text="시작",style="Accent.TButton",command=self.start_live_monitor).pack(side="left")
        ttk.Button(controls,text="일시정지",command=self.stop_live_monitor).pack(side="left",padx=5)
        ttk.Label(controls,textvariable=self.live_monitor_status).pack(side="right")

        metrics=ttk.LabelFrame(tab,text="현재 트래픽",padding=12); metrics.pack(fill="x",pady=(12,0))
        self.live_metric_vars={}
        definitions=(
            ("rx_mbps","수신 속도"),("tx_mbps","송신 속도"),("rx_pps","수신 패킷"),("tx_pps","송신 패킷"),
            ("errors","누적 오류"),("drops","누적 드롭"),("gateway_latency","게이트웨이 지연"),("connections","활성 연결"),
        )
        for index,(key,label) in enumerate(definitions):
            block=ttk.Frame(metrics,style="Surface.TFrame",padding=(8,4))
            block.grid(row=index//4,column=index%4,sticky="ew",padx=4,pady=4)
            variable=tk.StringVar(value="-"); self.live_metric_vars[key]=variable
            ttk.Label(block,text=label,style="MetricLabel.TLabel").pack(anchor="w")
            ttk.Label(block,textvariable=variable,style="MetricValue.TLabel").pack(anchor="w",pady=(2,0))
        for column in range(4): metrics.columnconfigure(column,weight=1)

        network=ttk.LabelFrame(tab,text="링크 및 주소",padding=10); network.pack(fill="x",pady=(10,0))
        self.live_network=tk.StringVar(value="인터페이스를 선택하면 현재 주소와 링크 상태가 표시됩니다.")
        ttk.Label(network,textvariable=self.live_network).pack(anchor="w")

        neighbors=ttk.LabelFrame(tab,text="LLDP / CDP 이웃",padding=8); neighbors.pack(fill="both",expand=True,pady=(10,0))
        self.live_neighbor_tree=ttk.Treeview(neighbors,columns=("protocol","local","device","management","port","age"),show="headings",height=7)
        for key,title,width in (("protocol","프로토콜",85),("local","로컬 포트",120),("device","장비명",190),("management","관리 IP",140),("port","상대 포트",170),("age","관측 경과",130)):
            self.live_neighbor_tree.heading(key,text=title); self.live_neighbor_tree.column(key,width=width,anchor="w")
        self.live_neighbor_tree.pack(fill="both",expand=True)

    def start_live_monitor(self):
        if not self.live_monitor_interface.get():
            self.refresh_interfaces()
        if not self.live_monitor_interface.get():
            messagebox.showerror("인터페이스 없음","모니터링할 네트워크 인터페이스가 없습니다.")
            return
        self.live_monitor_enabled=True
        self.live_monitor_previous=None
        self.live_monitor_previous_at=None
        self.live_monitor_status.set("실시간 모니터링 시작")
        self.refresh_live_monitor()

    def stop_live_monitor(self):
        self.live_monitor_enabled=False
        if self.live_monitor_after_id:
            self.root.after_cancel(self.live_monitor_after_id)
            self.live_monitor_after_id=None
        self.live_monitor_status.set("모니터링 일시정지")

    def refresh_live_monitor(self):
        if not self.live_monitor_enabled or self.live_monitor_in_flight:
            return
        interface=self.live_monitor_interface.get().strip()
        if not interface:
            return
        self.live_monitor_in_flight=True
        self.running_jobs+=1
        threading.Thread(target=self._live_monitor_worker,args=(interface,),daemon=True).start()

    def _live_monitor_worker(self, interface):
        try:
            observed_monotonic=time.monotonic()
            counters=read_interface_counters(interface)
            elapsed=observed_monotonic-self.live_monitor_previous_at if self.live_monitor_previous_at else 0
            rates=calculate_interface_rates(self.live_monitor_previous,counters,elapsed)
            address_result=subprocess.run(["ip","-j","address","show","dev",interface],capture_output=True,text=True,timeout=3)
            address_payload=json.loads(address_result.stdout or "[]")
            addresses=[]
            if address_payload:
                addresses=[f"{row.get('local')}/{row.get('prefixlen')}" for row in address_payload[0].get("addr_info",[]) if row.get("family") in ("inet","inet6") and row.get("local")]
            route_result=subprocess.run(["ip","-j","-4","route","show","default"],capture_output=True,text=True,timeout=3)
            routes=json.loads(route_result.stdout or "[]")
            gateway=next((row.get("gateway") for row in routes if row.get("dev")==interface and row.get("gateway")),None)
            latency=None
            if gateway:
                ping=subprocess.run(["ping","-c","1","-W","1",gateway],capture_output=True,text=True,timeout=3)
                match=re.search(r"time[=<]([0-9.]+)\s*ms",ping.stdout)
                latency=float(match.group(1)) if match else None
            discovery=subprocess.run(["lldpcli","-f","json","show","neighbors","details"],capture_output=True,text=True,timeout=4)
            neighbors=parse_discovery_neighbors(discovery.stdout)
            connections=subprocess.run(["ss","-H","-tun","state","established"],capture_output=True,text=True,timeout=3)
            link_state=(Path("/sys/class/net")/interface/"operstate").read_text(encoding="ascii").strip()
            sample={
                "observed_at":datetime.now().astimezone().isoformat(timespec="seconds"),
                "observed_monotonic":observed_monotonic,
                "interface":interface,"link_state":link_state,"addresses":addresses,"gateway":gateway,
                "gateway_latency_ms":latency,"connections":len([line for line in connections.stdout.splitlines() if line.strip()]),
                "counters":counters,"rates":rates,"neighbors":neighbors,
            }
            self.events.put(("실시간 모니터링",0,json.dumps(sample,ensure_ascii=False)))
        except Exception as exc:
            self.events.put(("실시간 모니터링",1,str(exc)))

    def _update_live_monitor(self, sample):
        rates=sample.get("rates") or {}; counters=sample.get("counters") or {}
        self.live_metric_vars["rx_mbps"].set(f"{rates.get('rx_mbps',0):.3f} Mbps")
        self.live_metric_vars["tx_mbps"].set(f"{rates.get('tx_mbps',0):.3f} Mbps")
        self.live_metric_vars["rx_pps"].set(f"{rates.get('rx_pps',0):.1f} pps")
        self.live_metric_vars["tx_pps"].set(f"{rates.get('tx_pps',0):.1f} pps")
        self.live_metric_vars["errors"].set(str(counters.get("rx_errors",0)+counters.get("tx_errors",0)))
        self.live_metric_vars["drops"].set(str(counters.get("rx_dropped",0)+counters.get("tx_dropped",0)))
        latency=sample.get("gateway_latency_ms")
        self.live_metric_vars["gateway_latency"].set(f"{latency:.2f} ms" if isinstance(latency,(int,float)) else "응답 없음")
        self.live_metric_vars["connections"].set(str(sample.get("connections",0)))
        addresses=", ".join(sample.get("addresses") or []) or "주소 없음"
        self.live_network.set(f"{sample.get('interface')} · 링크 {sample.get('link_state')} · {addresses} · 게이트웨이 {sample.get('gateway') or '미확인'}")
        for row in self.live_neighbor_tree.get_children(): self.live_neighbor_tree.delete(row)
        for neighbor in sample.get("neighbors") or []:
            self.live_neighbor_tree.insert("","end",values=(neighbor.get("protocol"),neighbor.get("local_interface"),neighbor.get("device"),neighbor.get("management_ip"),neighbor.get("port"),neighbor.get("age")))
        self.live_monitor_previous=sample.get("counters")
        self.live_monitor_previous_at=sample.get("observed_monotonic")
        self.live_monitor_status.set(f"갱신 {sample.get('observed_at')} · 이웃 {len(sample.get('neighbors') or [])}대")

    def _snmp_tab(self):
        tab=self._new_page("SNMP 장비")
        settings=ttk.LabelFrame(tab,text="기본 설정",padding=10); settings.pack(fill="x")
        for col,(label,var,width) in enumerate((("버전",self.version,6),("포트",self.port,8),("시간초과(초)",self.timeout,8),("재시도",self.retries,6))):
            ttk.Label(settings,text=label).grid(row=0,column=col*2,sticky="w",padx=(0,4)); ttk.Entry(settings,textvariable=var,width=width).grid(row=0,column=col*2+1,padx=(0,12))
        ttk.Label(settings,textvariable=self.community_state).grid(row=1,column=0,columnspan=3,sticky="w",pady=(10,0))
        ttk.Button(settings,text="설정 불러오기",command=self.load_snmp).grid(row=1,column=4,pady=(8,0))
        ttk.Button(settings,text="기본값 저장",command=self.save_defaults).grid(row=1,column=5,pady=(8,0),padx=4)
        ttk.Button(settings,text="Community 변경",command=self.change_community).grid(row=1,column=6,columnspan=2,pady=(8,0))
        devices=ttk.LabelFrame(tab,text="관리 장비",padding=8); devices.pack(fill="both",expand=True,pady=(10,0))
        self.tree=ttk.Treeview(devices,columns=("name","host","role"),show="headings",height=12)
        for key,title,w in (("name","장비명",260),("host","IP / 호스트",180),("role","역할",160)):
            self.tree.heading(key,text=title); self.tree.column(key,width=w,anchor="w")
        self.tree.pack(fill="both",expand=True)
        bar=ttk.Frame(devices); bar.pack(fill="x",pady=(8,0))
        ttk.Button(bar,text="장비 추가",command=self.add_target).pack(side="left")
        ttk.Button(bar,text="선택 삭제",command=self.remove_target).pack(side="left",padx=5)
        ttk.Button(bar,text="지금 수집",command=lambda:self.privileged([NODE,COLLECTOR,"edge-analysis"])).pack(side="right")

    def _diag_tab(self):
        tab=self._new_page("네트워크 진단")
        top=ttk.Frame(tab); top.pack(fill="x"); ttk.Label(top,text="대상").pack(side="left"); ttk.Entry(top,textvariable=self.target,width=28).pack(side="left",padx=8)
        buttons=ttk.Frame(tab); buttons.pack(fill="x",pady=8)
        for i,label in enumerate(COMMANDS): ttk.Button(buttons,text=label,command=lambda x=label:self.run_diag(x)).grid(row=i//5,column=i%5,padx=3,pady=3,sticky="ew")
        ttk.Button(buttons,text="전체 ARP 검색",command=self.arp_scan).grid(row=1,column=4,padx=3,pady=3,sticky="ew")
        for i in range(5): buttons.columnconfigure(i,weight=1)
        self.output=tk.Text(tab,wrap="none",state="disabled",font=("monospace",10)); self.output.pack(fill="both",expand=True)
        bottom=ttk.Frame(tab); bottom.pack(fill="x",pady=(6,0))
        ttk.Button(bottom,text="결과 지우기",command=lambda:self._set_text(self.output,"")).pack(side="left")
        ttk.Button(bottom,text="결과 저장",command=self.save_result).pack(side="left",padx=5)

    def _wireless_tab(self):
        tab=self._new_page("무선 분석")
        top=ttk.Frame(tab); top.pack(fill="x")
        ttk.Button(top,text="주변 AP 스캔",command=self.refresh_wireless).pack(side="left")
        ttk.Checkbutton(top,text="숨김 SSID만 보기",variable=self.wireless_hidden_only,command=self.render_wireless).pack(side="left",padx=10)
        ttk.Button(top,text="결과 저장",command=self.save_wireless_result).pack(side="right")
        self.wireless_summary=tk.StringVar(value="주변 AP 스캔을 실행하면 숨김 SSID, 신호 품질과 채널 혼잡도를 분석합니다.")
        self.wireless_ap_detail=tk.StringVar(
            value="AP를 선택하면 신호 값과 숨김 BSSID의 의미를 간단히 설명합니다."
        )
        ttk.Label(tab,textvariable=self.wireless_summary).pack(anchor="w",pady=(8,0))
        frame=ttk.LabelFrame(tab,text="주변 무선 네트워크",padding=8); frame.pack(fill="both",expand=True,pady=(8,0))
        columns=("active","ssid","hidden","bssid","band","channel","frequency","signal","quality","security")
        self.wireless_tree=ttk.Treeview(frame,columns=columns,show="headings",height=12)
        headings=(
            ("active","현재",58),("ssid","SSID",190),("hidden","숨김",58),("bssid","BSSID",150),
            ("band","대역",80),("channel","채널",55),("frequency","주파수",90),("signal","신호",65),
            ("quality","품질",78),("security","보안",140),
        )
        for key,title,width in headings:
            self.wireless_tree.heading(key,text=title); self.wireless_tree.column(key,width=width,anchor="w")
        self.wireless_tree.pack(fill="both",expand=True)
        self.wireless_tree.bind("<<TreeviewSelect>>",self.show_wireless_ap_detail)
        ttk.Label(
            frame,textvariable=self.wireless_ap_detail,justify="left",wraplength=900
        ).pack(fill="x",pady=(7,0))
        self.wireless_ap_rows={}
        analysis=ttk.LabelFrame(tab,text="신호·채널 분석",padding=8); analysis.pack(fill="x",pady=(8,0))
        self.wireless_analysis=tk.Text(analysis,height=7,wrap="word",state="disabled",font=("monospace",10)); self.wireless_analysis.pack(fill="x")

    def refresh_wireless(self):
        self.async_run("무선 분석",[GUI_OPS,"wireless-scan"],timeout=45)

    def show_wireless_ap_detail(self, _event=None):
        selected=self.wireless_tree.selection()
        access_point=self.wireless_ap_rows.get(selected[0]) if selected else None
        if not access_point:
            self.wireless_ap_detail.set(
                "AP를 선택하면 신호 값과 숨김 BSSID의 의미를 간단히 설명합니다."
            )
            return
        ssid=access_point.get("ssid") or "숨김 SSID"
        bssid=access_point.get("bssid") or "BSSID 미확인"
        identity=access_point.get("identity_interpretation") or "장비 관계를 판단할 근거가 부족합니다."
        signal=access_point.get("signal_interpretation") or "신호 해석 정보가 없습니다."
        self.wireless_ap_detail.set(f"{ssid} · {bssid}\n{identity}\n{signal}")

    def render_wireless(self):
        if not self.wireless_payload:
            return
        payload=self.wireless_payload
        for row in self.wireless_tree.get_children(): self.wireless_tree.delete(row)
        self.wireless_ap_rows={}
        self.show_wireless_ap_detail()
        access_points=payload.get("access_points",[]) if isinstance(payload,dict) else []
        hidden_only=self.wireless_hidden_only.get()
        for access_point in access_points:
            if hidden_only and not access_point.get("hidden"):
                continue
            ssid=access_point.get("ssid") or "(숨김 SSID)"
            frequency=access_point.get("frequency_mhz")
            row_id=self.wireless_tree.insert("","end",values=(
                "연결중" if access_point.get("active") else "", ssid,
                "숨김" if access_point.get("hidden") else "", access_point.get("bssid") or "-",
                access_point.get("band") or "미확인", access_point.get("channel") or "-",
                f"{frequency} MHz" if frequency else "-", f"{access_point.get('signal_pct',0)}%",
                access_point.get("quality") or "미확인", access_point.get("security") or "개방형",
            ))
            self.wireless_ap_rows[row_id]=access_point
        if not payload.get("available"):
            self.wireless_summary.set(f"무선 스캔 불가: {payload.get('reason','원인을 확인하세요.')}")
            self._set_text(self.wireless_analysis,payload.get("reason","") + "\n")
            return
        summary=payload.get("summary") or {}
        bands=", ".join(f"{band} {count}개" for band,count in (summary.get("band_counts") or {}).items()) or "없음"
        supported=", ".join(summary.get("supported_bands") or []) or "지원 대역 미확인"
        self.wireless_summary.set(
            f"AP {summary.get('total_access_points',0)}개 · USB 무선장치 {summary.get('adapter_count',0)}개"
            f" · 검색 가능: {supported} · 검출: {bands}"
        )
        lines=["[무선 장치]"]
        for adapter in payload.get("usb_adapters") or []:
            state={"ready":"사용 가능","driver_missing":"드라이버 없음","interface_missing":"인터페이스 없음"}.get(adapter.get("state"),adapter.get("state") or "미확인")
            lines.append(
                f"- {adapter.get('usb_id') or '-'} · {adapter.get('product') or adapter.get('manufacturer') or 'USB 무선장치'}"
                f" · {state} · 인터페이스 {', '.join(adapter.get('interfaces') or []) or '-'}"
            )
        lines.append("\n[판단 기준]")
        lines.append("- 신호 %는 NetworkManager 품질값이며 100%는 상한 표시입니다. 거리·출력 판단에는 원시 dBm을 확인합니다.")
        lines.append("- 숨김 SSID와 로컬 MAC만으로 장비를 단정하지 않습니다. 채널·주파수·BSSID 관계와 AP 설정을 함께 확인합니다.")
        related=[item for item in access_points if item.get("related_bssid")]
        if related:
            lines.append("\n[숨김/가상 BSSID 후보]")
            for item in related[:10]:
                lines.append(
                    f"- {item.get('bssid')} → {item.get('related_ssid')}({item.get('related_bssid')})"
                    f" · {item.get('identity_interpretation')}"
                )
        lines.append("\n[채널 혼잡도]")
        for item in (summary.get("channel_load") or [])[:10]:
            lines.append(f"- {item.get('band')} ch.{item.get('channel')}: {item.get('network_count')}개 / 강한 신호 {item.get('strong_network_count')}개 / {item.get('level')}")
        lines.append("\n[권장 조치]")
        lines.extend(f"- {item}" for item in (summary.get("recommendations") or []))
        self._set_text(self.wireless_analysis,"\n".join(lines) + "\n")

    def save_wireless_result(self):
        if not self.wireless_payload:
            messagebox.showinfo("무선 분석","저장할 스캔 결과가 없습니다.")
            return
        folder=Path.home() / "Documents" / "METRO-NMS"; folder.mkdir(parents=True,exist_ok=True)
        path=folder / f"wireless-scan-{datetime.now():%Y%m%d-%H%M%S}.json"
        path.write_text(json.dumps(self.wireless_payload,ensure_ascii=False,indent=2) + "\n",encoding="utf-8")
        os.chmod(path,0o600)
        messagebox.showinfo("무선 분석",f"저장 완료: {path}")

    def _spectrum_tab(self):
        tab=self._new_page("RF 스펙트럼")
        device=ttk.LabelFrame(tab,text="분석기",padding=10); device.pack(fill="x")
        ttk.Label(device,text="모델").grid(row=0,column=0,sticky="w")
        ttk.Label(device,text=TINYSA_MODEL).grid(row=0,column=1,sticky="w",padx=(8,24))
        ttk.Label(device,text="장치").grid(row=0,column=2,sticky="w")
        ttk.Label(device,text=TINYSA_DEVICE).grid(row=0,column=3,sticky="w",padx=(8,24))
        ttk.Label(device,textvariable=self.tinysa_status).grid(row=0,column=4,sticky="e")
        device.columnconfigure(4,weight=1)

        settings=ttk.LabelFrame(tab,text="스윕 설정",padding=10); settings.pack(fill="x",pady=(10,0))
        ttk.Label(settings,text="대분류").grid(row=0,column=0,sticky="w")
        category_box=ttk.Combobox(settings,textvariable=self.tinysa_category,state="readonly",width=12,values=tuple(TINYSA_BAND_CATALOG))
        category_box.grid(row=0,column=1,padx=(5,14)); category_box.bind("<<ComboboxSelected>>",self.on_tinysa_category_change)
        ttk.Label(settings,text="중분류").grid(row=0,column=2,sticky="w")
        self.tinysa_subcategory_box=ttk.Combobox(settings,textvariable=self.tinysa_subcategory,state="readonly",width=28)
        self.tinysa_subcategory_box.grid(row=0,column=3,padx=(5,14)); self.tinysa_subcategory_box.bind("<<ComboboxSelected>>",lambda _event:self.apply_tinysa_preset())
        self._set_tinysa_subcategory_values()
        ttk.Label(settings,text="시작 MHz").grid(row=0,column=4,sticky="w")
        ttk.Entry(settings,textvariable=self.tinysa_start_mhz,width=10).grid(row=0,column=5,padx=(5,14))
        ttk.Label(settings,text="종료 MHz").grid(row=0,column=6,sticky="w")
        ttk.Entry(settings,textvariable=self.tinysa_stop_mhz,width=10).grid(row=0,column=7,padx=(5,14))
        ttk.Label(settings,text="포인트").grid(row=0,column=8,sticky="w")
        ttk.Spinbox(settings,from_=51,to=450,textvariable=self.tinysa_points,width=7).grid(row=0,column=9,padx=(5,14))
        ttk.Label(settings,text="주기(초)").grid(row=0,column=10,sticky="w")
        ttk.Spinbox(settings,from_=5,to=300,textvariable=self.tinysa_interval,width=7).grid(row=0,column=11,padx=(5,0))
        ttk.Label(settings,text="안테나 프로필").grid(row=1,column=0,sticky="w",pady=(9,0))
        ttk.Entry(settings,textvariable=self.tinysa_antenna,width=18).grid(row=1,column=1,columnspan=2,sticky="w",padx=(5,14),pady=(9,0))
        ttk.Label(settings,text="레벨 교정").grid(row=1,column=3,sticky="w",pady=(9,0))
        ttk.Combobox(
            settings,textvariable=self.tinysa_calibration,state="readonly",width=11,
            values=tuple(TINYSA_CALIBRATION_OPTIONS),
        ).grid(row=1,column=4,sticky="w",padx=(5,14),pady=(9,0))
        ttk.Label(settings,text="집계 방식").grid(row=1,column=5,sticky="w",pady=(9,0))
        aggregation_box=ttk.Combobox(
            settings,textvariable=self.tinysa_aggregation,state="readonly",width=21,
            values=tuple(TINYSA_AGGREGATION_OPTIONS),
        )
        aggregation_box.grid(row=1,column=6,columnspan=2,sticky="w",padx=(5,14),pady=(9,0))
        aggregation_box.bind("<<ComboboxSelected>>",self.on_tinysa_aggregation_change)
        ttk.Label(settings,text="반복").grid(row=1,column=8,sticky="w",pady=(9,0))
        self.tinysa_repetition_box=ttk.Spinbox(
            settings,from_=1,to=32,textvariable=self.tinysa_repetitions,width=6,
        )
        self.tinysa_repetition_box.grid(row=1,column=9,sticky="w",padx=(5,0),pady=(9,0))
        band_shortcuts=ttk.Frame(settings); band_shortcuts.grid(row=2,column=0,columnspan=6,sticky="w",pady=(8,0))
        ttk.Label(band_shortcuts,text="Wi-Fi 대역").pack(side="left",padx=(0,6))
        for label,preset_id in (("2.4 GHz","wifi_2_4ghz"),("5 GHz","wifi_5ghz"),("6 GHz","wifi_6ghz")):
            ttk.Button(
                band_shortcuts,text=label,
                command=lambda selected=preset_id:self.select_tinysa_wifi_band(selected),
            ).pack(side="left",padx=(0,4))
        actions=ttk.Frame(settings); actions.grid(row=2,column=5,columnspan=7,sticky="e",pady=(8,0))
        ttk.Checkbutton(
            actions,text="자동 RF 수집",variable=self.tinysa_auto_enabled,
        ).pack(side="left",padx=(0,8))
        ttk.Button(actions,text="장비 확인",command=self.refresh_tinysa_connection).pack(side="left")
        ttk.Button(actions,text="자동수집 설정 적용",command=self.save_tinysa_config).pack(side="left",padx=5)
        self.tinysa_all_scan_button=ttk.Button(
            actions,text="2.4/5/6 GHz 전체 측정",command=self.run_tinysa_all_scan,
        )
        self.tinysa_all_scan_button.pack(side="left",padx=(0,5))
        self.tinysa_scan_button=ttk.Button(actions,text="1회 측정",style="Accent.TButton",command=self.run_tinysa_scan)
        self.tinysa_scan_button.pack(side="left")
        self.on_tinysa_aggregation_change()

        metrics=ttk.LabelFrame(tab,text="최근 측정값",padding=9); metrics.pack(fill="x",pady=(10,0))
        for index,(key,label) in enumerate((
            ("peak","피크 전력"),("frequency","피크 주파수"),("average","평균 전력"),
            ("noise","노이즈 플로어"),("occupancy","RF 점유율"),("observed","측정시각"),
        )):
            block=ttk.Frame(metrics,style="Surface.TFrame",padding=(6,2)); block.grid(row=0,column=index,sticky="ew",padx=3)
            variable=tk.StringVar(value="-"); self.tinysa_metric_vars[key]=variable
            ttk.Label(block,text=label,style="MetricLabel.TLabel").pack(anchor="w")
            ttk.Label(block,textvariable=variable,style="MetricValue.TLabel").pack(anchor="w",pady=(2,0))
            metrics.columnconfigure(index,weight=1)

        plot_frame=ttk.LabelFrame(tab,text="주파수별 수신 전력 · 원본 스윕",padding=8); plot_frame.pack(fill="both",expand=True,pady=(10,0))
        self.tinysa_plot=tk.Canvas(plot_frame,background="#fbfbfc",highlightthickness=0,height=520)
        self.tinysa_plot.pack(fill="both",expand=True)
        self.tinysa_plot.bind("<Configure>",lambda _event:self._render_tinysa_plot())
        ttk.Label(tab,text="가로축은 주파수(MHz/GHz, Hz 기준)이며 AP 대역은 Wi-Fi 채널을 함께 표시합니다. 절대 전력은 안테나 보정 전 값입니다.").pack(anchor="w",pady=(7,0))
        ttk.Label(tab,text="위성은 안테나 직결 RF가 아니라 LNB 출력 IF(950~2150MHz) 측정용입니다. DC 차단과 입력 레벨 보호를 확인하세요.").pack(anchor="w",pady=(2,0))

    def _set_tinysa_subcategory_values(self):
        presets=TINYSA_BAND_CATALOG.get(self.tinysa_category.get(), ())
        labels=tuple(preset["label"] for preset in presets)
        self.tinysa_subcategory_box.configure(values=labels)
        if self.tinysa_subcategory.get() not in labels and labels:
            self.tinysa_subcategory.set(labels[0])

    def on_tinysa_category_change(self, _event=None):
        self._set_tinysa_subcategory_values()
        self.apply_tinysa_preset()

    def select_tinysa_wifi_band(self, preset_id):
        _,preset=tinysa_preset_by_id(preset_id)
        if not preset:
            return
        self.tinysa_category.set("AP")
        self._set_tinysa_subcategory_values()
        self.tinysa_subcategory.set(preset["label"])
        self.apply_tinysa_preset()

    def apply_tinysa_preset(self):
        preset=tinysa_preset_by_label(self.tinysa_category.get(),self.tinysa_subcategory.get())
        if not preset:
            return
        self.tinysa_band.set(preset["id"])
        if preset["id"] != "custom":
            self.tinysa_start_mhz.set(preset["start_mhz"]); self.tinysa_stop_mhz.set(preset["stop_mhz"])
        self.tinysa_payload=None
        self.tinysa_multi_payload=None
        for variable in self.tinysa_metric_vars.values():
            variable.set("-")
        self._render_tinysa_plot()

    def on_tinysa_aggregation_change(self, _event=None):
        single=TINYSA_AGGREGATION_OPTIONS.get(self.tinysa_aggregation.get()) == "single_sweep"
        if single:
            self.tinysa_repetitions.set("1")
        self.tinysa_repetition_box.configure(state="disabled" if single else "normal")

    def _tinysa_settings_from_form(self):
        settings=normalize_tinysa_settings(
            self.tinysa_band.get(),self.tinysa_start_mhz.get(),self.tinysa_stop_mhz.get(),
            self.tinysa_points.get(),self.tinysa_interval.get(),self.tinysa_antenna.get(),self.tinysa_category.get(),
            TINYSA_CALIBRATION_OPTIONS.get(self.tinysa_calibration.get()),
            TINYSA_AGGREGATION_OPTIONS.get(self.tinysa_aggregation.get()),self.tinysa_repetitions.get(),
        )
        settings["enabled"]=bool(self.tinysa_auto_enabled.get())
        return settings

    def refresh_tinysa_connection(self):
        service_state="자동 RF 수집 켜짐" if self.tinysa_auto_enabled.get() else "자동 RF 수집 꺼짐"
        self.tinysa_status.set(f"장비 응답 확인 중 · {service_state}")
        self.async_run("tinySA 장비 확인",[
            "python3",TINYSA_HELPER,"--json","--probe","--device",TINYSA_DEVICE,
            "--lock-timeout","2","--timeout","5",
        ],timeout=10)

    def refresh_tinysa_config_state(self):
        self.async_run(
            "tinySA 자동수집 상태",
            ["sudo","-n",TINYSA_CONFIG_HELPER,"--status"],
            timeout=10,
        )

    def save_tinysa_config(self):
        try:
            settings=self._tinysa_settings_from_form()
        except ValueError as exc:
            messagebox.showerror("입력 오류",str(exc)); return
        self.pending_tinysa_settings=settings
        self.tinysa_status.set("자동수집 설정 저장 중")
        self.async_run("tinySA 설정 저장",[
            "sudo","-n",TINYSA_CONFIG_HELPER,settings["model"],settings["device"],settings["band"],
            str(settings["start_hz"]),str(settings["stop_hz"]),str(settings["points"]),
            str(settings["interval_seconds"]),settings["antenna_profile"],settings["calibration_state"],
            settings["aggregation"],str(settings["sweep_repetitions"]),
            "true" if settings["enabled"] else "false",
        ],timeout=45)

    def run_tinysa_scan(self):
        try:
            settings=self._tinysa_settings_from_form()
        except ValueError as exc:
            messagebox.showerror("입력 오류",str(exc)); return
        if not Path(settings["device"]).exists():
            messagebox.showerror("장비 미연결",f"{settings['device']} 장치를 찾을 수 없습니다."); return
        permission_message=tinysa_permission_message(settings["device"])
        if permission_message:
            messagebox.showerror("측정 권한",permission_message); return
        self.tinysa_scan_button.configure(state="disabled")
        self.tinysa_status.set("1회 측정 중")
        self.async_run("tinySA 1회 측정",[
            "python3",TINYSA_HELPER,"--json","--device",settings["device"],
            "--lock-timeout","30",
            "--start-hz",str(settings["start_hz"]),"--stop-hz",str(settings["stop_hz"]),
            "--points",str(settings["points"]),"--band",settings["band"],
            "--sweep-repetitions",str(settings["sweep_repetitions"]),
            "--aggregation",settings["aggregation"],
            "--sensor-id","tinysa-zs407-400","--device-model",settings["model"],
            "--antenna-profile",settings["antenna_profile"],
            "--calibration-state",settings["calibration_state"],
        ],timeout=min(180,max(45,settings["sweep_repetitions"]*20+10)))

    def run_tinysa_all_scan(self):
        try:
            settings=self._tinysa_settings_from_form()
        except ValueError as exc:
            messagebox.showerror("입력 오류",str(exc)); return
        if not Path(settings["device"]).exists():
            messagebox.showerror("장비 미연결",f"{settings['device']} 장치를 찾을 수 없습니다."); return
        permission_message=tinysa_permission_message(settings["device"])
        if permission_message:
            messagebox.showerror("측정 권한",permission_message); return
        self.tinysa_all_scan_button.configure(state="disabled")
        self.tinysa_scan_button.configure(state="disabled")
        self.tinysa_status.set("2.4/5/6 GHz 연속 측정 중")
        self.async_run("tinySA 전체 대역 측정",[
            "python3",TINYSA_HELPER,"--json","--wifi-all","--device",settings["device"],
            "--lock-timeout","30","--points",str(settings["points"]),
            "--sweep-repetitions",str(settings["sweep_repetitions"]),
            "--aggregation",settings["aggregation"],
            "--sensor-id","tinysa-zs407-400","--device-model",settings["model"],
            "--antenna-profile",settings["antenna_profile"],
            "--calibration-state",settings["calibration_state"],
        ],timeout=min(540,max(120,settings["sweep_repetitions"]*60+30)))

    def _update_tinysa_result(self, payload):
        if not isinstance(payload,dict) or not payload.get("available"):
            raise ValueError(payload.get("error","tinySA 측정 결과가 없습니다.") if isinstance(payload,dict) else "tinySA 결과 형식 오류")
        self.tinysa_payload=payload
        self.tinysa_multi_payload=None
        self.tinysa_metric_vars["peak"].set(f"{payload.get('peak_dbm'):.2f} dBm")
        self.tinysa_metric_vars["frequency"].set(f"{payload.get('peak_frequency_hz') / 1_000_000:.3f} MHz")
        self.tinysa_metric_vars["average"].set(f"{payload.get('average_dbm'):.2f} dBm")
        self.tinysa_metric_vars["noise"].set(f"{payload.get('noise_floor_dbm'):.2f} dBm")
        self.tinysa_metric_vars["occupancy"].set(f"{payload.get('rf_occupancy_pct'):.2f} %")
        observed=str(payload.get("observed_at") or "").replace("T"," ").replace("Z","")
        self.tinysa_metric_vars["observed"].set(observed[11:19] if len(observed)>=19 else observed or "-")
        version=payload.get("device_version") or "펌웨어 미확인"
        calibration_label=next(
            (label for label,value in TINYSA_CALIBRATION_OPTIONS.items() if value == payload.get("calibration_state")),
            "교정 상태 확인 필요",
        )
        aggregation_label=next(
            (label for label,value in TINYSA_AGGREGATION_OPTIONS.items() if value == payload.get("aggregation")),
            payload.get("aggregation") or "방식 확인 필요",
        )
        repetitions=payload.get("sweep_repetitions") or 1
        self.tinysa_status.set(f"연결됨 · {version} · {calibration_label} · {aggregation_label} {repetitions}회")
        self._render_tinysa_plot()

    def _update_tinysa_multi_result(self, payload):
        bands=payload.get("bands") if isinstance(payload,dict) else None
        if not bands or len(bands) != 3:
            raise ValueError("전체 대역 측정 결과가 올바르지 않습니다.")
        self.tinysa_payload=None
        self.tinysa_multi_payload=payload
        peak=max(bands,key=lambda item:item.get("peak_dbm",float("-inf")))
        self.tinysa_metric_vars["peak"].set(f"{peak.get('peak_dbm'):.2f} dBm")
        self.tinysa_metric_vars["frequency"].set(f"{peak.get('peak_frequency_hz') / 1_000_000:.3f} MHz")
        self.tinysa_metric_vars["average"].set("대역별 그래프")
        self.tinysa_metric_vars["noise"].set("대역별 그래프")
        self.tinysa_metric_vars["occupancy"].set("대역별 그래프")
        self.tinysa_metric_vars["observed"].set("연속 측정")
        elapsed=payload.get("sweep_duration_ms",0) / 1000
        self.tinysa_status.set(f"2.4/5/6 GHz 측정 완료 · 순차 스윕 {elapsed:.1f}초")
        self._render_tinysa_plot()

    def _render_tinysa_plot(self):
        canvas=getattr(self,"tinysa_plot",None)
        if not canvas:
            return
        canvas.delete("all")
        width=max(300,canvas.winfo_width()); height=max(180,canvas.winfo_height())
        multi=(self.tinysa_multi_payload or {}).get("bands") or []
        if multi:
            panel_height=max(155,height/3)
            for index,payload in enumerate(multi):
                self._render_tinysa_plot_panel(canvas,payload,width,index*panel_height,panel_height)
            return
        payload=self.tinysa_payload or {}
        self._render_tinysa_plot_panel(canvas,payload,width,0,height)

    def _render_tinysa_plot_panel(self,canvas,payload,width,offset_y,panel_height):
        left,right,top,bottom=58,18,offset_y+38,36
        frequencies=payload.get("frequency_hz") or []; powers=payload.get("power_dbm") or []
        if len(frequencies)<2 or len(frequencies)!=len(powers):
            canvas.create_text(width/2,offset_y+panel_height/2,text="측정을 실행하면 원본 스펙트럼이 표시됩니다.",fill=self.colors["muted"])
            return
        minimum=min(powers); maximum=max(powers)
        padding=max(3.0,(maximum-minimum)*0.12)
        low,high=minimum-padding,maximum+padding
        plot_width=max(1,width-left-right); plot_height=max(1,panel_height-(top-offset_y)-bottom)
        for index in range(5):
            y=top+plot_height*index/4
            value=high-(high-low)*index/4
            canvas.create_line(left,y,width-right,y,fill="#e1e1e6")
            canvas.create_text(left-7,y,text=f"{value:.0f}",anchor="e",fill=self.colors["muted"],font=("Noto Sans CJK KR",8))
        start,stop=frequencies[0],frequencies[-1]
        _,preset=tinysa_preset_by_id(payload.get("band") or self.tinysa_band.get())
        axis_mode=(preset or {}).get("axis","frequency")
        axis_summary=frequency_axis_summary(start,stop,axis_mode)
        canvas.create_text(
            left,offset_y+5,
            text=(
                f"{axis_summary['label']}  |  {axis_summary['range_label']}"
                f"  |  격자 {format_frequency(axis_summary['grid_step_hz'])}"
            ),
            anchor="nw",fill=self.colors["text"],font=("Noto Sans CJK KR",9,"bold"),
        )
        for frequency,_label in frequency_axis_ticks(start,stop,axis_mode):
            x=left+(frequency-start)/(stop-start)*plot_width
            canvas.create_line(x,top,x,top+plot_height,fill="#d9dce3")
            tick_text=format_frequency(frequency)
            canvas.create_text(x,top+plot_height+7,text=tick_text,anchor="n",justify="center",fill=self.colors["muted"],font=("Noto Sans CJK KR",8))
        maximum_channel_ticks=max(7,min(16,int(plot_width/48)))
        for frequency,label in wifi_channel_axis_ticks(start,stop,axis_mode,maximum_channel_ticks):
            x=left+(frequency-start)/(stop-start)*plot_width
            canvas.create_line(x,top,x,top+plot_height,fill="#bfd4f6",dash=(2,4))
            canvas.create_text(
                x,top-5,text=label,anchor="s",fill=self.colors["metro_blue"],
                font=("Noto Sans CJK KR",8,"bold"),
            )
        points=[]
        for frequency,power in zip(frequencies,powers):
            x=left+(frequency-start)/(stop-start)*plot_width
            y=top+(high-power)/(high-low)*plot_height
            points.extend((x,y))
        canvas.create_line(*points,fill=self.colors["metro_blue"],width=2)
        peak_index=powers.index(maximum)
        peak_x,peak_y=points[peak_index*2],points[peak_index*2+1]
        canvas.create_oval(peak_x-3,peak_y-3,peak_x+3,peak_y+3,fill=self.colors["metro_red"],outline="")

    def _measurement_tab(self):
        tab=self._new_page("측정 세션")
        controls=ttk.LabelFrame(tab,text="동시 측정 설정",padding=10); controls.pack(fill="x")
        ttk.Label(controls,text="측정시간").grid(row=0,column=0,sticky="w")
        ttk.Spinbox(controls,from_=1,to=28800,textvariable=self.measurement_value,width=8).grid(row=0,column=1,padx=(5,3))
        ttk.Combobox(controls,textvariable=self.measurement_unit,state="readonly",width=7,values=("초","분","시간")).grid(row=0,column=2,padx=(0,15))
        ttk.Label(controls,text="측정간격(초)").grid(row=0,column=3,sticky="w")
        ttk.Spinbox(controls,from_=2,to=300,textvariable=self.measurement_interval,width=8).grid(row=0,column=4,padx=5)
        ttk.Button(controls,text="동시 측정 시작",style="Accent.TButton",command=self.start_measurement).grid(row=0,column=5,padx=(12,4))
        modules=ttk.Frame(controls); modules.grid(row=1,column=0,columnspan=6,sticky="w",pady=(10,0))
        labels={"wired":"유선","wireless":"무선","rf":"RF 스펙트럼","packet_capture":"패킷 캡처","system":"시스템"}
        for key in ("wired","wireless","rf","packet_capture","system"):
            ttk.Checkbutton(modules,text=labels[key],variable=self.measurement_module_vars[key]).pack(side="left",padx=(0,12))
        actions=ttk.Frame(controls); actions.grid(row=2,column=0,columnspan=6,sticky="ew",pady=(10,0))
        ttk.Button(actions,text="일시 정지",command=lambda:self.control_measurement("pause")).pack(side="left")
        ttk.Button(actions,text="계속",command=lambda:self.control_measurement("resume")).pack(side="left",padx=5)
        ttk.Button(actions,text="안전 중지",command=lambda:self.control_measurement("stop")).pack(side="left")
        ttk.Button(actions,text="결과/상태 새로고침",command=self.refresh_measurement_session).pack(side="left",padx=5)
        ttk.Label(actions,textvariable=self.measurement_status).pack(side="right")
        ttk.Label(controls,text="게이트웨이·KT/Google DNS, 유선·무선 품질, RF 2.4/5/6GHz 순환, 시스템 상태를 같은 측정 세션 ID와 시간축으로 저장합니다.").grid(row=3,column=0,columnspan=6,sticky="w",pady=(9,0))
        ttk.Label(controls,text="모듈 하나가 실패해도 성공한 측정은 보존되며 최종 상태는 완료·부분완료·실패로 구분됩니다.").grid(row=4,column=0,columnspan=6,sticky="w",pady=(4,0))
        ttk.Label(controls,textvariable=self.active_profile_label).grid(row=5,column=0,columnspan=5,sticky="w",pady=(8,0))
        ttk.Button(controls,text="현장 프로필",command=lambda:self.show_page("현장 프로필")).grid(row=5,column=5,sticky="e",pady=(8,0))
        self.measurement_output=tk.Text(tab,wrap="none",state="disabled",font=("monospace",10)); self.measurement_output.pack(fill="both",expand=True,pady=(10,0))

    def measurement_seconds(self):
        try: value=int(self.measurement_value.get()); interval=int(self.measurement_interval.get())
        except ValueError: return None, None
        multiplier={"초":1,"분":60,"시간":3600}.get(self.measurement_unit.get(),60)
        return value*multiplier, interval

    def start_measurement(self):
        if not os.path.isfile(MEASUREMENT_SESSION) or not os.path.isfile(MEASUREMENT_CONTROL):
            self.measurement_status.set("동시 측정 실행 모듈 누락")
            messagebox.showerror(
                "설치 복구 필요",
                "동시 측정 실행 모듈이 설치되지 않았습니다.\n"
                "수집기 설치 패키지를 다시 적용한 뒤 프로그램을 재실행하세요.\n\n"
                f"필요 파일: {MEASUREMENT_SESSION}\n{MEASUREMENT_CONTROL}",
            )
            return
        duration,interval=self.measurement_seconds()
        if duration is None or not 10 <= duration <= 28800: messagebox.showerror("입력 오류","측정시간은 10초~8시간입니다."); return
        if not 2 <= interval <= 300: messagebox.showerror("입력 오류","측정간격은 2~300초입니다."); return
        if duration//interval+1 > 2000: messagebox.showerror("입력 오류","측정 표본은 최대 2,000회입니다. 간격을 늘리세요."); return
        profile = self._field_profile_from_form()
        if not profile:
            self.show_page("현장 프로필")
            return
        selected=[key for key,variable in self.measurement_module_vars.items() if variable.get()]
        if not selected: messagebox.showerror("입력 오류","측정 모듈을 하나 이상 선택하세요."); return
        if not messagebox.askyesno("동시 측정 시작",f"{profile['site_name']}에서 {duration}초 동안 유선·무선·RF 데이터를 같은 시간축으로 측정할까요?"): return
        self.pending_measurement_profile = profile
        self.measurement_status.set("세션 생성 및 장비 사전 점검 중")
        self.async_run(
            "동시 측정 시작",
            [
                "sudo","-n",MEASUREMENT_CONTROL,"start",
                "--duration",str(duration),
                "--interval",str(interval),
                "--modules",",".join(selected),
            ],
            json.dumps(profile, ensure_ascii=False),
            timeout=180
        )

    def control_measurement(self, action):
        if not os.path.isfile(MEASUREMENT_SESSION) or not os.path.isfile(MEASUREMENT_CONTROL):
            self.measurement_status.set("동시 측정 실행 모듈 누락")
            messagebox.showerror("설치 복구 필요",f"누락 파일: {MEASUREMENT_SESSION}")
            return
        labels={"pause":"동시 측정 일시정지","resume":"동시 측정 계속","stop":"동시 측정 안전중지"}
        if action=="stop" and not messagebox.askyesno("안전 중지","현재 동시 측정을 안전하게 종료할까요?"):
            return
        self.async_run(labels[action],["sudo","-n",MEASUREMENT_CONTROL,action],timeout=60)

    def refresh_measurement_session(self):
        if not os.path.isfile(MEASUREMENT_SESSION):
            self.measurement_status.set("동시 측정 실행 모듈 누락")
            return
        self.async_run(
            "동시 측정 상태",
            ["sudo","-n",MEASUREMENT_CONTROL,"status"],
            timeout=30,
        )

    def _update_measurement_session_status(self, payload):
        state=payload.get("status") or "unknown"
        labels={
            "idle":"대기","preflight":"사전 점검","running":"측정 중","paused":"일시 정지",
            "stopping":"안전 종료 중","completed":"완료","partial":"부분 완료",
            "failed":"실패","cancelled":"취소",
        }
        session_id=str(payload.get("measurement_session_id") or "")
        suffix=f" · {session_id[:8]}" if session_id else ""
        terminal=state in ("completed","partial","failed","cancelled")
        worker="" if terminal or payload.get("worker_alive",True) else " · 작업 프로세스 확인 필요"
        preflight=payload.get("preflight") or {}
        clock=preflight.get("clock") if isinstance(preflight,dict) else {}
        ntp_state=(clock or {}).get("ntp_state") or preflight.get("ntp_state")
        clock_warning=""
        if ntp_state in ("degraded","unsynced","unknown"):
            clock_warning=f" · 시간동기화 {ntp_state}"
        self.measurement_status.set(f"{labels.get(state,state)}{suffix}{clock_warning}{worker}")

    def _offline_queue_tab(self):
        tab=self._new_page("저장/전송")
        ttk.Label(tab,text="중앙 NMS 연결이 실패한 측정은 로컬에 보존되며, 연결이 돌아오면 여기에서 재전송할 수 있습니다.").pack(anchor="w")
        frame=ttk.Frame(tab); frame.pack(fill="both",expand=True,pady=(10,0))
        self.queue_tree=ttk.Treeview(frame,columns=("state","kind","site","queued","attempts","error"),show="headings",height=14)
        for key,title,width in (("state","상태",90),("kind","종류",105),("site","현장",180),("queued","측정/저장 시각",165),("attempts","시도",55),("error","최근 결과",350)):
            self.queue_tree.heading(key,text=title); self.queue_tree.column(key,width=width,anchor="w")
        self.queue_tree.pack(fill="both",expand=True)
        bar=ttk.Frame(tab); bar.pack(fill="x",pady=(8,0))
        ttk.Button(bar,text="목록 새로고침",command=self.refresh_offline_queue).pack(side="left")
        ttk.Button(bar,text="미전송 결과 전송",command=self.flush_offline_queue).pack(side="left",padx=5)
        self.queue_status=tk.StringVar(value="목록 새로고침을 눌러 전송 대기 결과를 확인하세요.")
        ttk.Label(bar,textvariable=self.queue_status).pack(side="right")

    def refresh_offline_queue(self):
        self.privileged([NODE,COLLECTOR,"offline-measurements","list"],label="오프라인 큐 조회")

    def flush_offline_queue(self):
        self.privileged([NODE,COLLECTOR,"offline-measurements","flush"],label="미전송 결과 전송",timeout=180)
        self.retry_ict_queue()

    def retry_ict_queue(self):
        self.running_jobs += 1
        def worker():
            try:
                result = self._ict_client().retry_queue()
                self.events.put(("119 대기자료 전송", 0, json.dumps(result, ensure_ascii=False)))
            except Exception as exc:
                self.events.put(("119 대기자료 전송", 1, str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def sync_ict_profile(self, profile, evidence):
        if not profile or not profile.get("site_id"):
            return
        self.running_jobs += 1
        def worker():
            try:
                collected_at = evidence.get("observed_at") or evidence.get("started_at")
                result = self._ict_client().store_profile(
                    int(profile["site_id"]),
                    {
                        "field_profile": profile,
                        "evidence": evidence,
                        "missing_value_policy": {
                            "missing": "없음",
                            "not_tested": "테스트 안 됨",
                            "stale": "과거 측정값",
                        },
                    },
                    collected_at,
                )
                self.events.put(("119 현장 프로필 송신", 0, json.dumps(result, ensure_ascii=False)))
            except Exception as exc:
                self.events.put(("119 현장 프로필 송신", 1, str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def create_snapshot(self, send_immediately=False):
        profile = self._field_profile_from_form()
        if not profile:
            self.show_page("현장 프로필")
            return
        action = "저장 후 중앙으로 송신" if send_immediately else "로컬 대기열에 저장"
        if not messagebox.askyesno("현장 진단 스냅샷", f"{profile['site_name']}의 현재 진단값을 {action}할까요?"):
            return
        command = [NODE, COLLECTOR, "snapshot-session", "--field-profile-stdin"]
        if send_immediately:
            command.append("--send")
        self.pending_snapshot_profile = profile
        self.privileged(
            command,
            json.dumps(profile, ensure_ascii=False),
            label="진단 스냅샷 저장/송신" if send_immediately else "진단 스냅샷 저장",
            timeout=180,
        )

    def refresh_all(self):
        if self.refresh_batch_pending:
            return
        self.refresh_batch_pending = {"현황", "VPN 목록", "무선 분석", "오프라인 큐 조회"}
        self.refresh_batch_errors = 0
        self.refresh_all_button.configure(state="disabled")
        self.status.set("전체 새로고침 중")
        self.refresh_services()
        self.refresh_status()
        self.refresh_vpn()
        self.refresh_wireless()
        self.refresh_offline_queue()

    def _capture_tab(self):
        tab=self._new_page("패킷 캡처")
        controls=ttk.LabelFrame(tab,text="실시간 캡처",padding=10); controls.pack(fill="x")
        ttk.Label(controls,text="인터페이스").grid(row=0,column=0,sticky="w")
        self.interface_box=ttk.Combobox(controls,textvariable=self.interface,state="readonly",width=18); self.interface_box.grid(row=0,column=1,padx=(5,15))
        ttk.Label(controls,text="종류").grid(row=0,column=2,sticky="w")
        ttk.Combobox(controls,textvariable=self.capture_profile,state="readonly",width=16,values=tuple(CAPTURE_PROFILES)).grid(row=0,column=3,padx=(5,15))
        ttk.Label(controls,text="최대 시간(분)").grid(row=0,column=4,sticky="w")
        ttk.Spinbox(controls,from_=1,to=30,textvariable=self.live_capture_minutes,width=7).grid(row=0,column=5,padx=5)
        self.live_start_button=ttk.Button(controls,text="실시간 시작",style="Accent.TButton",command=self.start_live_capture)
        self.live_start_button.grid(row=0,column=6,padx=(12,4))
        self.live_stop_button=ttk.Button(controls,text="중지",command=self.stop_live_capture,state="disabled")
        self.live_stop_button.grid(row=0,column=7)
        ttk.Label(controls,textvariable=self.live_capture_status).grid(row=1,column=0,columnspan=8,sticky="w",pady=(8,0))
        ttk.Label(controls,textvariable=self.live_flood_status,wraplength=1040).grid(row=2,column=0,columnspan=8,sticky="w",pady=(4,0))

        live=ttk.LabelFrame(tab,text="실시간 패킷 헤더",padding=8); live.pack(fill="both",expand=True,pady=(10,0))
        self.live_capture_tree=ttk.Treeview(live,columns=("time","source","destination","protocol","length","info"),show="headings",height=9)
        for key,title,width in (("time","시각",105),("source","출발지",155),("destination","목적지",155),("protocol","프로토콜",90),("length","길이",65),("info","요약",310)):
            self.live_capture_tree.heading(key,text=title); self.live_capture_tree.column(key,width=width,anchor="w")
        self.live_capture_tree.pack(fill="both",expand=True)

        batch=ttk.LabelFrame(tab,text="단기 캡처 및 저장파일",padding=8); batch.pack(fill="x",pady=(10,0))
        ttk.Label(batch,text="시간(초)").pack(side="left")
        ttk.Spinbox(batch,from_=5,to=120,textvariable=self.capture_seconds,width=7).pack(side="left",padx=5)
        ttk.Button(batch,text="단기 캡처",command=self.start_capture).pack(side="left")
        ttk.Button(batch,text="저장 목록",command=self.list_captures).pack(side="left",padx=5)
        ttk.Button(batch,text="선택 경로 요약",command=self.summarize_capture).pack(side="right")
        self.capture_output=tk.Text(tab,height=5,wrap="none",state="disabled",font=("monospace",9)); self.capture_output.pack(fill="x",pady=(8,0))
        self.refresh_interfaces()

    def _vpn_tab(self):
        tab=self._new_page("VPN")
        top=ttk.Frame(tab); top.pack(fill="x")
        ttk.Button(top,text="OpenVPN 가져오기",command=lambda:self.import_vpn("openvpn")).pack(side="left")
        ttk.Button(top,text="WireGuard 가져오기",command=lambda:self.import_vpn("wireguard")).pack(side="left",padx=5)
        ttk.Button(top,text="새로고침",command=self.refresh_vpn).pack(side="right")
        frame=ttk.LabelFrame(tab,text="등록된 VPN",padding=8); frame.pack(fill="both",expand=True,pady=(10,0))
        self.vpn_tree=ttk.Treeview(frame,columns=("name","type","state","uuid"),show="headings",height=10)
        for key,title,width in (("name","연결 이름",250),("type","종류",110),("state","상태",130),("uuid","식별자",300)):
            self.vpn_tree.heading(key,text=title); self.vpn_tree.column(key,width=width,anchor="w")
        self.vpn_tree.pack(fill="both",expand=True)
        actions=ttk.Frame(frame); actions.pack(fill="x",pady=(8,0))
        ttk.Button(actions,text="연결",command=lambda:self.vpn_action("vpn-up")).pack(side="left")
        ttk.Button(actions,text="연결 해제",command=lambda:self.vpn_action("vpn-down")).pack(side="left",padx=5)
        ttk.Button(actions,text="상세 정보",command=lambda:self.vpn_action("vpn-details",privileged=False)).pack(side="left")
        ttk.Button(actions,text="설정 편집",command=self.edit_vpn).pack(side="left",padx=5)
        ttk.Button(actions,text="삭제",command=lambda:self.vpn_action("vpn-delete",confirm=True)).pack(side="right")
        self.vpn_output=tk.Text(tab,height=8,wrap="word",state="disabled",font=("monospace",10)); self.vpn_output.pack(fill="x",pady=(10,0))
        ttk.Label(tab,text="VPN 키와 비밀번호는 NetworkManager 또는 시스템 WireGuard가 관리하며 이 화면에는 표시하지 않습니다.").pack(anchor="w",pady=(6,0))
        self.refresh_vpn()

    def _service_tab(self):
        tab=self._new_page("서비스")
        self.service_tree=ttk.Treeview(tab,columns=("label","unit","state"),show="headings")
        for k,t,w in (("label","기능",220),("unit","서비스",360),("state","상태",130)): self.service_tree.heading(k,text=t); self.service_tree.column(k,width=w,anchor="w")
        self.service_tree.pack(fill="both",expand=True)
        bar=ttk.Frame(tab); bar.pack(fill="x",pady=8)
        ttk.Button(bar,text="상태 새로고침",command=self.refresh_services).pack(side="left")
        ttk.Button(bar,text="선택 재시작",command=self.restart_service).pack(side="left",padx=5)

    def async_run(self,label,cmd,input_text=None,timeout=120):
        self.running_jobs += 1
        self.status.set(f"실행 중: {label}")
        threading.Thread(target=self._worker,args=(label,cmd,input_text,timeout),daemon=True).start()
    def _worker(self,label,cmd,input_text,timeout):
        try:
            p=subprocess.run(cmd,input=input_text,capture_output=True,text=True,timeout=timeout,env={**os.environ,"NMS_DIAG_TARGET":self.target.get().strip()})
            self.events.put((label,p.returncode,p.stdout+p.stderr))
        except Exception as e: self.events.put((label,1,str(e)))
    def privileged(self,cmd,input_text=None,label="관리자 작업",timeout=120):
        self.async_run(label,["pkexec",*cmd],input_text,timeout)
    def refresh_status(self):
        cmd=["bash","-lc",NETWORK_STATUS_COMMAND]
        self.async_run("현황",cmd)
    def load_snmp(self): self.privileged([HELPER,"show-json"],label="SNMP 설정 조회")
    def save_defaults(self): self.privileged([HELPER,"defaults",self.version.get(),self.port.get(),self.timeout.get(),self.retries.get()],label="SNMP 기본값 저장")
    def change_community(self):
        value=simpledialog.askstring("SNMP Community","읽기 전용 Community를 입력하세요.",show="*")
        if value: self.privileged([HELPER,"community","--stdin"],value+"\n","Community 변경")
    def add_target(self):
        name=simpledialog.askstring("장비 추가","장비명")
        if not name:return
        host=simpledialog.askstring("장비 추가","IP 주소 또는 호스트명")
        if not host or not valid_host(host): messagebox.showerror("입력 오류","올바른 IP 주소 또는 호스트명을 입력하세요."); return
        role=simpledialog.askstring("장비 추가","역할 (예: core_switch)",initialvalue="switch") or "switch"
        self.privileged([HELPER,"add",name.strip(),host.strip(),role.strip()],label="SNMP 장비 추가")
    def remove_target(self):
        item=self.tree.focus()
        if not item:return
        host=self.tree.item(item,"values")[1]
        if messagebox.askyesno("장비 삭제",f"{host} 장비를 삭제할까요?"): self.privileged([HELPER,"remove",host],label="SNMP 장비 삭제")
    def run_diag(self,label):
        if label in ("경로 추적","포트 점검") and not valid_host(self.target.get()): messagebox.showerror("입력 오류","진단 대상 IP/호스트를 확인하세요."); return
        self.async_run(label,["bash","-lc",COMMANDS[label]])
    def refresh_interfaces(self):
        p=subprocess.run(["bash","-lc","ip -o link show | awk -F': ' '$2 !~ /^lo/ {print $2}' | sed 's/@.*//'"],capture_output=True,text=True)
        values=tuple(x for x in p.stdout.splitlines() if x)
        self.interface_box["values"]=values
        self.live_interface_box["values"]=values
        route=subprocess.run(["bash","-lc","ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1);exit}}'"],capture_output=True,text=True)
        preferred=route.stdout.strip() if route.stdout.strip() in values else (values[0] if values else "")
        if preferred and self.interface.get() not in values:self.interface.set(preferred)
        if preferred and self.live_monitor_interface.get() not in values:self.live_monitor_interface.set(preferred)
    def arp_scan(self):
        if not self.interface.get(): messagebox.showerror("인터페이스 없음","사용할 네트워크 인터페이스가 없습니다."); return
        self.privileged([GUI_OPS,"arp-scan",self.interface.get()],label="전체 ARP 검색")
    def start_capture(self):
        try: seconds=int(self.capture_seconds.get())
        except ValueError: seconds=0
        if not 5 <= seconds <= 120: messagebox.showerror("입력 오류","캡처 시간은 5~120초입니다."); return
        if not self.interface.get(): messagebox.showerror("인터페이스 없음","캡처 인터페이스를 선택하세요."); return
        self.privileged([GUI_OPS,"capture",self.interface.get(),CAPTURE_PROFILES[self.capture_profile.get()],str(seconds)],label="패킷 캡처")

    def start_live_capture(self):
        if self.live_capture_process and self.live_capture_process.poll() is None:
            messagebox.showinfo("실시간 캡처","이미 캡처가 실행 중입니다.")
            return
        if not self.interface.get():
            messagebox.showerror("인터페이스 없음","캡처 인터페이스를 선택하세요.")
            return
        try: minutes=int(self.live_capture_minutes.get())
        except ValueError: minutes=0
        if not 1 <= minutes <= 30:
            messagebox.showerror("입력 오류","실시간 캡처 시간은 1~30분입니다.")
            return
        profile=CAPTURE_PROFILES.get(self.capture_profile.get())
        if not profile:
            messagebox.showerror("입력 오류","캡처 종류를 확인하세요.")
            return
        for row in self.live_capture_tree.get_children(): self.live_capture_tree.delete(row)
        self.live_capture_packet_count=0
        self.live_capture_path=None
        self.live_flood_counts=empty_counts()
        self.live_flood_started_at=time.monotonic()
        self.live_flood_status.set("플러딩 분석 준비 중")
        command=["pkexec",GUI_OPS,"live-capture",self.interface.get(),profile,str(minutes*60)]
        try:
            self.live_capture_process=subprocess.Popen(
                command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                text=True,bufsize=1,start_new_session=True,
            )
        except OSError as exc:
            messagebox.showerror("실시간 캡처",str(exc)); return
        self.running_jobs+=1
        self.live_capture_stopping=False
        self.live_start_button.configure(state="disabled")
        self.live_stop_button.configure(state="normal")
        self.live_capture_status.set(f"인증 대기 또는 캡처 시작 중 · 최대 {minutes}분 / 50MB")
        threading.Thread(target=self._live_capture_worker,args=(self.live_capture_process,),daemon=True).start()

    def _live_capture_worker(self, process):
        try:
            batch=[]
            flush_at=time.monotonic()+0.2
            for line in process.stdout or ():
                batch.append(line.rstrip("\n"))
                if len(batch)>=100 or time.monotonic()>=flush_at:
                    self.events.put(("실시간 캡처 스트림",0,"\n".join(batch)))
                    batch=[]
                    flush_at=time.monotonic()+0.2
            if batch:
                self.events.put(("실시간 캡처 스트림",0,"\n".join(batch)))
            return_code=process.wait()
            self.events.put(("실시간 캡처 완료",return_code,""))
        except Exception as exc:
            self.events.put(("실시간 캡처 완료",1,str(exc)))

    def stop_live_capture(self):
        process=self.live_capture_process
        if not process or process.poll() is not None:
            return
        if self.live_capture_stopping:
            return
        self.live_capture_stopping=True
        self.live_capture_status.set("캡처 종료 중")
        self.live_stop_button.configure(state="disabled")
        self.running_jobs+=1
        threading.Thread(target=self._stop_live_capture_worker,args=(process,),daemon=True).start()

    def _stop_live_capture_worker(self, process):
        try:
            result=subprocess.run(
                ["pkexec",GUI_OPS,"stop-live-capture",str(process.pid)],
                capture_output=True,text=True,timeout=15,check=False,
            )
            text=(result.stdout or result.stderr or "").strip()
            self.events.put(("실시간 캡처 종료 요청",result.returncode,text))
        except subprocess.TimeoutExpired:
            self.events.put(("실시간 캡처 종료 요청",124,"캡처 종료 명령 시간이 초과되었습니다."))
        except OSError as exc:
            self.events.put(("실시간 캡처 종료 요청",1,str(exc)))

    def _handle_live_capture_line(self, line):
        if line.startswith("#META\t"):
            parts=line.split("\t")
            self.live_capture_path=parts[1] if len(parts)>1 else None
            self.live_capture_status.set(f"수집 중 · 0패킷 · {self.live_capture_path or '파일 준비 중'}")
            return
        if line.startswith("#DONE\t"):
            parts=line.split("\t")
            self.live_capture_path=parts[1] if len(parts)>1 else self.live_capture_path
            return
        fields=line.split("\t")
        if len(fields)<11 or not fields[0].isdigit():
            if line.strip(): self.live_capture_status.set(f"캡처 준비: {line[:120]}")
            return
        try: timestamp=datetime.fromtimestamp(float(fields[1])).strftime("%H:%M:%S.%f")[:-3]
        except (ValueError,OverflowError): timestamp=fields[1]
        source=fields[4] or fields[5] or fields[2] or "-"
        destination=fields[6] or fields[7] or fields[3] or "-"
        self.live_capture_tree.insert("","end",values=(timestamp,source,destination,fields[8] or "-",fields[9] or "-",fields[10] or "-"))
        self.live_capture_packet_count+=1
        add_packet(
            self.live_flood_counts,
            fields[8],
            fields[3],
            fields[11] if len(fields)>11 else "",
            fields[12] if len(fields)>12 else "",
        )
        elapsed=time.monotonic()-(self.live_flood_started_at or time.monotonic())
        flood=summarize_counts(self.live_flood_counts,elapsed)
        counts=flood["counts"]
        rates=flood["rates_pps"]
        state={
            "candidate":"플러딩 후보 있음",
            "no_candidate":"기준 초과 없음",
            "insufficient_data":"판단 자료 부족",
        }.get(flood["status"],"판단 불가")
        self.live_flood_status.set(
            f"{state} · 브로드캐스트 {counts['broadcast']} ({rates['broadcast'] or 0} pps)"
            f" · 멀티캐스트 {counts['multicast']} ({rates['multicast'] or 0} pps)"
            f" · ARP {counts['arp']} ({rates['arp'] or 0} pps)"
            f" · mDNS {counts['mdns']} ({rates['mdns'] or 0} pps)"
            f" · SSDP {counts['ssdp']} · LLMNR/NBNS {counts['llmnr'] + counts['nbns']}"
        )
        rows=self.live_capture_tree.get_children()
        if len(rows)>500: self.live_capture_tree.delete(rows[0])
        self.live_capture_tree.yview_moveto(1)
        self.live_capture_status.set(f"수집 중 · {self.live_capture_packet_count}패킷 · {self.live_capture_path or '파일 준비 중'}")
    def list_captures(self): self.privileged([GUI_OPS,"list-captures"],label="캡처 목록")
    def summarize_capture(self):
        try: selected=self.capture_output.get("sel.first","sel.last").strip()
        except tk.TclError: selected=""
        path=next((part for part in selected.split() if part.startswith("/var/log/nms-pcap/") and part.endswith((".pcap",".pcapng"))),"")
        if not path: messagebox.showinfo("캡처 선택","목록에서 PCAP 파일 경로를 마우스로 선택하세요."); return
        self.privileged([GUI_OPS,"summarize",path],label="캡처 요약")
    def save_result(self):
        text=self.output.get("1.0","end").strip()
        if not text:return
        folder=os.path.expanduser("~/Documents/METRO-NMS"); os.makedirs(folder,exist_ok=True)
        path=os.path.join(folder,f"diagnostics-{datetime.now():%Y%m%d-%H%M%S}.txt")
        with open(path,"w",encoding="utf-8") as f:f.write(text+"\n")
        messagebox.showinfo("저장 완료",path)
    def import_vpn(self,vpn_type):
        patterns=[("OpenVPN 설정","*.ovpn *.conf")] if vpn_type=="openvpn" else [("WireGuard 설정","*.conf")]
        path=filedialog.askopenfilename(title="VPN 설정파일 선택",filetypes=patterns+[("모든 파일","*")])
        if path:self.privileged([GUI_OPS,"vpn-import",vpn_type,path],label="VPN 가져오기")
    def refresh_vpn(self):
        self.async_run("VPN 목록",[GUI_OPS,"vpn-list"])
    def vpn_action(self,action,confirm=False,privileged=True):
        item=self.vpn_tree.focus()
        if not item: messagebox.showinfo("VPN 선택","VPN 연결을 선택하세요."); return
        name,connection_type,_,uuid=self.vpn_tree.item(item,"values")
        if action=="vpn-delete" and (uuid.startswith("wg-quick:") or connection_type=="시스템 WireGuard"):
            messagebox.showinfo("시스템 WireGuard","시스템 WireGuard 프로파일은 이 화면에서 삭제할 수 없습니다.")
            return
        if confirm and not messagebox.askyesno("VPN 삭제",f"{name} 연결을 삭제할까요?"):return
        cmd=[GUI_OPS,action,uuid]
        if privileged:self.privileged(cmd,label={"vpn-up":"VPN 연결","vpn-down":"VPN 해제","vpn-delete":"VPN 삭제"}.get(action,"VPN 작업"))
        else:self.async_run("VPN 상세",cmd)
    def edit_vpn(self):
        item=self.vpn_tree.focus()
        if not item: messagebox.showinfo("VPN 선택","VPN 연결을 선택하세요."); return
        name,connection_type,_,uuid=self.vpn_tree.item(item,"values")
        if uuid.startswith("wg-quick:") or connection_type=="시스템 WireGuard":
            messagebox.showinfo("시스템 WireGuard",f"{name}은(는) systemd wg-quick 서비스로 관리됩니다. 설정 편집은 차단되며, 연결·해제와 상세 정보만 이 화면에서 수행할 수 있습니다.")
            return
        try: subprocess.Popen(["nm-connection-editor","--edit",uuid])
        except OSError as exc: messagebox.showerror("편집기 실행 실패",str(exc))
    def refresh_services(self):
        for x in self.service_tree.get_children(): self.service_tree.delete(x)
        for label,unit in SERVICES:
            p=subprocess.run(["systemctl","is-active",unit],capture_output=True,text=True)
            self.service_tree.insert("", "end",values=(label,unit,p.stdout.strip() or "unknown"))
    def restart_service(self):
        item=self.service_tree.focus()
        if item:self.privileged(["/bin/systemctl","restart",self.service_tree.item(item,"values")[1]],label="서비스 재시작")
    def _drain(self):
        try:
            label,code,text=self.events.get_nowait()
            if label != "실시간 캡처 스트림":
                self.running_jobs=max(0,self.running_jobs-1)
            if label=="실시간 캡처 스트림":
                for stream_line in text.splitlines():
                    self._handle_live_capture_line(stream_line)
            elif label=="실시간 캡처 완료":
                self.live_capture_process=None
                self.live_capture_stopping=False
                self.live_start_button.configure(state="normal")
                self.live_stop_button.configure(state="disabled")
                if code in (0,130,-2,-15):
                    self.live_capture_status.set(f"캡처 완료 · {self.live_capture_packet_count}패킷 · {self.live_capture_path or '저장파일 확인'}")
                else:
                    self.live_capture_status.set(f"캡처 오류 ({code}) · {text or '권한 또는 인터페이스를 확인하세요'}")
                if self.closing:
                    self.root.after(10,self._finish_close)
            elif label=="실시간 캡처 종료 요청":
                if code==0:
                    self.live_capture_status.set("캡처 데이터 정리 중")
                else:
                    self.live_capture_stopping=False
                    self.live_capture_status.set(f"종료 실패 ({code}) · {text[:120]}")
                    self.live_stop_button.configure(state="normal")
            elif label=="실시간 모니터링":
                self.live_monitor_in_flight=False
                if code==0:
                    try: self._update_live_monitor(json.loads(text))
                    except (ValueError,json.JSONDecodeError): self.live_monitor_status.set("실시간 결과 형식 오류")
                else:
                    self.live_monitor_status.set(f"모니터링 오류: {text[:120]}")
                if self.live_monitor_enabled:
                    self.live_monitor_after_id=self.root.after(2000,self.refresh_live_monitor)
            elif label=="현황": self._set_text(self.summary,text)
            elif label=="수집기 이름 저장":
                if code==0 and self.pending_collector_name:
                    try:
                        saved_name=save_collector_name(self.pending_collector_name)
                        self.collector_name.set(saved_name)
                        self.collector_name_status.set("중앙 표시명 반영 완료")
                        messagebox.showinfo("수집기 이름",f"{saved_name}(으)로 변경했습니다.")
                        self.root.after(500,self.refresh_status)
                    except (OSError,ValueError) as exc:
                        self.collector_name_status.set(f"로컬 설정 저장 실패: {exc}")
                else:
                    self.collector_name_status.set(f"저장 실패: {text[:120]}")
                self.pending_collector_name=None
            elif label=="오프라인 큐 조회":
                if code==0:
                    try:
                        payload=json.loads(text); self._update_offline_queue(payload.get("items", []))
                    except (ValueError, json.JSONDecodeError):
                        self.queue_status.set("목록 형식 오류")
                else:
                    self.queue_status.set("목록 조회 실패")
                    self._set_text(self.output,f"$ {label}\n{text}\n",append=True)
            elif label=="미전송 결과 전송":
                if code==0:
                    try:
                        payload=json.loads(text)
                        self.queue_status.set(f"전송 {payload.get('delivered', 0)}건 / 보류 {payload.get('pending', 0)}건")
                    except (ValueError, json.JSONDecodeError):
                        self.queue_status.set("전송 결과 형식 오류")
                    self.root.after(300,self.refresh_offline_queue)
                else:
                    self.queue_status.set("전송 실패: 연결 또는 설정 확인")
                    self._set_text(self.output,f"$ {label}\n{text}\n",append=True)
            elif label=="119 현장 조회":
                if code==0:
                    try:
                        result=json.loads(text)
                        self._merge_assigned_sites(result.get("payload") or {}, result.get("mode") or "unknown")
                    except (ValueError,json.JSONDecodeError) as exc:
                        self.ict_connection_status.set(f"119 현장 목록 형식 오류: {exc}")
                else:
                    self.ict_connection_status.set(f"119 연결 실패: {text[:120]}")
            elif label=="119 대기자료 전송":
                if code==0:
                    try:
                        result=json.loads(text)
                        self.ict_connection_status.set(
                            f"119 재전송 {result.get('sent',0)}건 · 남음 {result.get('remaining',0)}건"
                        )
                    except (ValueError,json.JSONDecodeError):
                        self.ict_connection_status.set("119 재전송 결과 형식 오류")
                else:
                    self.ict_connection_status.set(f"119 재전송 실패: {text[:120]}")
            elif label=="119 현장 프로필 송신":
                if code==0:
                    try:
                        result=json.loads(text)
                        mode=result.get("transport_mode") or "unknown"
                        labels={"vpn":"VPN 저장 완료","https_fallback":"HTTPS 대체 저장 완료","offline_queue":"오프라인 저장"}
                        self.ict_connection_status.set(
                            f"{labels.get(mode,mode)} · 재전송 대기 {self._ict_client().queue_size()}건"
                        )
                    except (ValueError,json.JSONDecodeError):
                        self.ict_connection_status.set("119 송신 결과 형식 오류")
                else:
                    self.ict_connection_status.set(f"119 송신 실패: {text[:120]}")
            elif label in ("진단 스냅샷 저장", "진단 스냅샷 저장/송신"):
                if code==0:
                    try:
                        payload=json.loads(text)
                        delivery=payload.get("delivery") or {}
                        delivery_label="중앙 전송 완료" if delivery.get("state")=="sent" else "로컬 저장 완료 · 전송 대기"
                        observed=(payload.get("observed_at") or "").replace("T"," ").replace("Z","")
                        self.last_snapshot.set(f"최근 저장: {observed or '시각 미확인'} · {delivery_label}")
                        self.queue_status.set(delivery_label)
                        self._update_source_status(payload.get("source_status"))
                        self._set_text(self.measurement_output,json.dumps(payload,ensure_ascii=False,indent=2)+"\n")
                        self.sync_ict_profile(self.pending_snapshot_profile, payload)
                    except (ValueError,json.JSONDecodeError):
                        self.last_snapshot.set("최근 저장: 결과 형식 확인 필요")
                    self.pending_snapshot_profile = None
                    self.root.after(300,self.refresh_offline_queue)
                else:
                    self.last_snapshot.set("최근 저장: 실패 · 진단 로그를 확인하세요")
                    self._set_text(self.measurement_output,f"$ {label}\n{text}\n",append=True)
            elif label in (
                "동시 측정 시작","동시 측정 일시정지","동시 측정 계속",
                "동시 측정 안전중지","동시 측정 상태",
            ):
                if code==0:
                    try:
                        payload=json.loads(text)
                        self._update_measurement_session_status(payload)
                        summary=format_measurement_session_result(payload)
                        detail=json.dumps(payload,ensure_ascii=False,indent=2)
                        self._set_text(self.measurement_output,f"{summary}\n\n[상세 JSON]\n{detail}\n")
                        state=payload.get("status")
                        if state in ("preflight","running","paused","stopping"):
                            self.root.after(3000,self.refresh_measurement_session)
                    except (ValueError,json.JSONDecodeError):
                        self.measurement_status.set("측정 상태 형식 오류")
                        self._set_text(self.measurement_output,text+"\n",append=True)
                else:
                    self.measurement_status.set(f"{label} 실패")
                    self._set_text(self.measurement_output,f"$ {label}\n{text}\n",append=True)
                if label=="동시 측정 시작":
                    self.pending_measurement_profile=None
            elif label=="SNMP 설정 조회" and code==0:
                data=parse_settings(text); self.version.set(data.get("version","2c")); self.port.set(data.get("port",161)); self.timeout.set(data.get("timeout",2)); self.retries.set(data.get("retries",1)); self.community_state.set("Community: 설정됨" if data.get("community_configured") else "Community: 미설정")
                for x in self.tree.get_children():self.tree.delete(x)
                for t in data["targets"]:self.tree.insert("","end",values=(t.get("name",""),t.get("host",""),t.get("role","switch")))
            elif label=="tinySA 장비 확인":
                try:
                    payload=json.loads(text)
                except (ValueError,json.JSONDecodeError):
                    payload={"error":text or "응답 없음","error_code":"measurement_failed"}
                service_state="자동 RF 수집 켜짐" if self.tinysa_auto_enabled.get() else "자동 RF 수집 꺼짐"
                if code==0 and payload.get("available"):
                    version=payload.get("device_version") or "펌웨어 확인"
                    self.tinysa_status.set(f"장비 정상 · {version[:55]} · {service_state}")
                else:
                    self.tinysa_status.set(f"{tinysa_error_message(payload)} · {service_state}")
            elif label=="tinySA 자동수집 상태":
                if code==0:
                    try:
                        payload=json.loads(text)
                        enabled=bool(payload.get("enabled"))
                        self.tinysa_auto_enabled.set(enabled)
                        state="켜짐" if enabled else "꺼짐"
                        self.tinysa_status.set(f"자동 RF 수집 {state}")
                    except (ValueError,json.JSONDecodeError):
                        self.tinysa_status.set("자동 RF 수집 상태 확인 실패")
            elif label=="tinySA 설정 저장":
                if code==0 and self.pending_tinysa_settings:
                    save_tinysa_settings(self.pending_tinysa_settings)
                    state="켜짐" if self.pending_tinysa_settings.get("enabled") else "꺼짐"
                    self.tinysa_status.set(f"설정 저장 완료 · 자동 RF 수집 {state}")
                    self.root.after(500,self.refresh_tinysa_connection)
                else:
                    self.tinysa_status.set(f"설정 저장 실패: {text[:120]}")
                self.pending_tinysa_settings=None
            elif label=="tinySA 1회 측정":
                self.tinysa_scan_button.configure(state="normal")
                if code==0:
                    try:
                        self._update_tinysa_result(json.loads(text))
                    except (ValueError,TypeError,json.JSONDecodeError) as exc:
                        self.tinysa_status.set(f"측정 결과 오류: {exc}")
                else:
                    try:
                        payload=json.loads(text)
                    except (ValueError,json.JSONDecodeError):
                        payload={"error":text[:160],"error_code":"measurement_failed"}
                    self.tinysa_status.set(f"측정 실패: {tinysa_error_message(payload)}")
            elif label=="tinySA 전체 대역 측정":
                self.tinysa_all_scan_button.configure(state="normal")
                self.tinysa_scan_button.configure(state="normal")
                if code==0:
                    try:
                        self._update_tinysa_multi_result(json.loads(text))
                    except (ValueError,TypeError,json.JSONDecodeError) as exc:
                        self.tinysa_status.set(f"전체 대역 결과 오류: {exc}")
                else:
                    try:
                        payload=json.loads(text)
                    except (ValueError,json.JSONDecodeError):
                        payload={"error":text[:160],"error_code":"measurement_failed"}
                    self.tinysa_status.set(f"전체 대역 측정 실패: {tinysa_error_message(payload)}")
            elif label=="무선 분석":
                if code==0:
                    try:
                        payload=json.loads(text)
                        if not isinstance(payload,dict):
                            raise ValueError("무선 스캔 결과 형식이 올바르지 않습니다.")
                        self.wireless_payload=payload
                        self.render_wireless()
                    except (ValueError,json.JSONDecodeError) as exc:
                        self.wireless_summary.set("무선 스캔 결과를 해석할 수 없습니다.")
                        self._set_text(self.wireless_analysis,f"{exc}\n{text}")
                else:
                    self.wireless_summary.set("무선 스캔 실행 오류")
                    self._set_text(self.wireless_analysis,text)
            elif label=="VPN 목록":
                for x in self.vpn_tree.get_children():self.vpn_tree.delete(x)
                if code==0:
                    for line in text.splitlines():
                        parts=line.split("\t")
                        if len(parts)==4:
                            connection_type=parts[2].strip()
                            raw_state=parts[3].strip().lower()
                            if connection_type=="wireguard-systemd":
                                connected=raw_state=="active"
                            else:
                                connected=bool(raw_state and raw_state not in ("--","inactive","disconnected","unavailable"))
                            display_type="시스템 WireGuard" if connection_type=="wireguard-systemd" else connection_type
                            self.vpn_tree.insert("","end",values=(parts[0],display_type,"연결됨" if connected else "연결 안 됨",parts[1]))
                else:self._set_text(self.vpn_output,text)
            else:
                if label.startswith("VPN"):
                    target_widget=self.vpn_output
                    if code==0 and label != "VPN 상세":self.root.after(500,self.refresh_vpn)
                else:
                    if label == "측정 세션": target_widget=self.measurement_output
                    elif label in ("패킷 캡처","캡처 목록","캡처 요약"): target_widget=self.capture_output
                    else: target_widget=self.output
                if hasattr(self,"output"): self._set_text(target_widget,f"$ {label}\n{text}\n",append=True)
                if code==0 and label.startswith("SNMP"): self.root.after(300,self.load_snmp)
                if label == "측정 세션":
                    if code==0:
                        try:
                            payload=json.loads(text); delivery=payload.get("delivery", {})
                            state="중앙 전송 완료" if delivery.get("state")=="sent" else "로컬 저장 완료, 중앙 전송 대기"
                            self.queue_status.set(state)
                            self.sync_ict_profile(self.pending_measurement_profile, payload)
                        except (ValueError, json.JSONDecodeError):
                            pass
                    self.pending_measurement_profile = None
                    self.root.after(300,self.refresh_offline_queue)
            if label in ("관리자 작업","서비스 재시작"): self.refresh_services()
            if label in self.refresh_batch_pending:
                self.refresh_batch_pending.discard(label)
                if code != 0:
                    self.refresh_batch_errors += 1
                if not self.refresh_batch_pending:
                    stamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    suffix=f" · 오류 {self.refresh_batch_errors}건" if self.refresh_batch_errors else " · 정상"
                    self.last_refresh.set(f"마지막 갱신: {stamp}{suffix}")
                    self.refresh_all_button.configure(state="normal")
            if self.running_jobs:
                self.status.set(f"작업 {self.running_jobs}건 실행 중")
            else:
                self.status.set("완료" if code==0 else f"오류 ({code})")
        except queue.Empty: pass
        self.root.after(150,self._drain)
    def _set_text(self,widget,text,append=False):
        widget.configure(state="normal")
        if not append:widget.delete("1.0","end")
        widget.insert("end",text); widget.see("end"); widget.configure(state="disabled")

    def _update_offline_queue(self, items):
        for row in self.queue_tree.get_children(): self.queue_tree.delete(row)
        labels={"pending":"전송 대기","sent":"전송 완료","invalid":"파일 오류"}
        kinds={"measurement":"반복 측정","diagnostic_snapshot":"진단 스냅샷"}
        pending=0
        for item in items:
            state=item.get("state", "unknown")
            if state=="pending": pending += 1
            error=item.get("last_error") or ("중앙 NMS 전송 완료" if state=="sent" else "확인 필요")
            recorded=(item.get("queued_at") or item.get("started_at") or "").replace("T"," ").replace("Z","")
            self.queue_tree.insert("","end",values=(labels.get(state,state),kinds.get(item.get("session_kind"),item.get("session_kind") or "반복 측정"),item.get("site_name") or "-",recorded,item.get("attempts",0),error))
        self.queue_status.set(f"미전송 {pending}건")

    def on_close(self):
        if self.closing:
            return
        self.closing=True
        self.stop_live_monitor()
        process=self.live_capture_process
        if process and process.poll() is None:
            self.close_deadline=time.monotonic()+15
            self.stop_live_capture()
            self.root.after(100,self._finish_close)
            return
        self.root.destroy()

    def _finish_close(self):
        process=self.live_capture_process
        if not process or process.poll() is not None:
            self.root.destroy()
            return
        if self.close_deadline and time.monotonic() >= self.close_deadline:
            self.root.destroy()
            return
        self.root.after(100,self._finish_close)

if __name__ == "__main__":
    root=tk.Tk(); App(root); root.mainloop()
