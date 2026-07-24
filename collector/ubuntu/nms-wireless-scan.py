#!/usr/bin/env python3
"""Bounded Wi-Fi environment scan for the Ubuntu field collector."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any


NMCLI_FIELDS = "DEVICE,IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY"
BSSID_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


def split_escaped_fields(line: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line.rstrip("\r\n"):
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def to_int(value: str) -> int | None:
    match = re.search(r"-?\d+", str(value or ""))
    return int(match.group()) if match else None


def frequency_band(frequency_mhz: int | None) -> str:
    if frequency_mhz is None:
        return "미확인"
    if 2400 <= frequency_mhz < 2500:
        return "2.4 GHz"
    if 4900 <= frequency_mhz < 5925:
        return "5 GHz"
    if 5925 <= frequency_mhz <= 7125:
        return "6 GHz"
    return "기타"


def signal_quality(signal_pct: int) -> str:
    if signal_pct >= 75:
        return "매우 양호"
    if signal_pct >= 55:
        return "양호"
    if signal_pct >= 35:
        return "보통"
    return "약함"


def parse_nmcli_wifi(output: str) -> list[dict[str, Any]]:
    access_points: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = split_escaped_fields(line)
        # nmcli may omit the empty SSID field entirely for hidden networks.
        if len(fields) == 7 and BSSID_PATTERN.fullmatch(fields[2].strip()):
            fields.insert(2, "")
        fields.extend([""] * (8 - len(fields)))
        ssid = fields[2].strip()
        hidden = ssid in ("", "--")
        signal = max(0, min(100, to_int(fields[6]) or 0))
        frequency = to_int(fields[5])
        channel = to_int(fields[4])
        access_points.append({
            "interface": fields[0].strip() or None,
            "active": fields[1].strip() == "*",
            "ssid": None if hidden else ssid,
            "hidden": hidden,
            "bssid": fields[3].strip() or None,
            "channel": channel,
            "frequency_mhz": frequency,
            "band": frequency_band(frequency),
            "signal_pct": signal,
            "quality": signal_quality(signal),
            "security": fields[7].strip() or "개방형",
        })
    return sorted(access_points, key=lambda item: (not item["active"], -item["signal_pct"], item["bssid"] or ""))


def wifi_radios(runner=subprocess.run) -> list[str]:
    try:
        result = runner(["iw", "dev"], capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    radios: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            radios.append(line.removeprefix("Interface ").strip())
    return radios


def scan_wifi(runner=subprocess.run) -> dict[str, Any]:
    scanned_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        result = runner(
            ["nmcli", "-t", "--escape", "yes", "-f", NMCLI_FIELDS, "device", "wifi", "list", "--rescan", "yes"],
            capture_output=True,
            text=True,
            timeout=35,
            check=False,
        )
    except FileNotFoundError:
        return {"schema_version": "nms-wireless-scan-v1", "scanned_at": scanned_at, "available": False, "reason": "nmcli가 설치되지 않았습니다.", "radios": [], "access_points": []}
    except subprocess.TimeoutExpired:
        return {"schema_version": "nms-wireless-scan-v1", "scanned_at": scanned_at, "available": False, "reason": "무선 스캔 시간이 초과되었습니다.", "radios": wifi_radios(runner), "access_points": []}

    if result.returncode != 0:
        reason = (result.stderr or result.stdout or "무선 스캔을 실행할 수 없습니다.").strip()
        return {"schema_version": "nms-wireless-scan-v1", "scanned_at": scanned_at, "available": False, "reason": reason[:500], "radios": wifi_radios(runner), "access_points": []}

    access_points = parse_nmcli_wifi(result.stdout)
    return {
        "schema_version": "nms-wireless-scan-v1",
        "scanned_at": scanned_at,
        "available": True,
        "radios": wifi_radios(runner),
        "access_points": access_points,
        "summary": analyze_access_points(access_points),
    }


def analyze_access_points(access_points: list[dict[str, Any]]) -> dict[str, Any]:
    band_counts = Counter(str(item.get("band") or "미확인") for item in access_points)
    quality_counts = Counter(str(item.get("quality") or "미확인") for item in access_points)
    channels: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for item in access_points:
        channel = item.get("channel")
        if isinstance(channel, int):
            channels[(str(item.get("band") or "미확인"), channel)].append(item)

    channel_load: list[dict[str, Any]] = []
    for (band, channel), items in channels.items():
        strong_count = sum(1 for item in items if int(item.get("signal_pct") or 0) >= 55)
        hidden_count = sum(1 for item in items if item.get("hidden"))
        if len(items) >= 4 or strong_count >= 3:
            level = "높음"
        elif len(items) >= 2 or strong_count >= 2:
            level = "보통"
        else:
            level = "낮음"
        channel_load.append({
            "band": band,
            "channel": channel,
            "network_count": len(items),
            "strong_network_count": strong_count,
            "hidden_network_count": hidden_count,
            "level": level,
        })
    channel_load.sort(key=lambda item: (-item["network_count"], -item["strong_network_count"], item["band"], item["channel"]))

    active = [item for item in access_points if item.get("active")]
    recommendations: list[str] = []
    hidden_count = sum(1 for item in access_points if item.get("hidden"))
    if not access_points:
        recommendations.append("검출된 AP가 없습니다. 무선 어댑터 활성 상태와 스캔 권한을 확인하세요.")
    elif hidden_count:
        recommendations.append(f"숨김 SSID {hidden_count}개가 검출되었습니다. SSID 숨김은 전파 송출을 감추지 않으므로 BSSID·채널 기준으로 관리합니다.")
    crowded = [item for item in channel_load if item["level"] == "높음"]
    if crowded:
        labels = ", ".join(f"{item['band']} ch.{item['channel']}" for item in crowded[:4])
        recommendations.append(f"혼잡 가능 채널: {labels}. 실제 채널 변경 전에는 AP 채널폭과 인접 AP를 함께 확인하세요.")
    if active:
        current = active[0]
        if int(current.get("signal_pct") or 0) < 35:
            recommendations.append("현재 연결 AP 신호가 약합니다. 설치 위치, 장애물, 로밍과 재전송률을 점검하세요.")
        else:
            recommendations.append(f"현재 연결 AP 신호는 {current['signal_pct']}% ({current['quality']})입니다.")
    if access_points and not band_counts.get("5 GHz") and not band_counts.get("6 GHz"):
        recommendations.append("5/6 GHz AP가 검출되지 않았습니다. 고밀도 환경이면 2.4 GHz 혼잡 여부를 우선 확인하세요.")
    if access_points and not recommendations:
        recommendations.append("현재 스캔 기준으로 즉시 확인할 무선 경고는 없습니다.")

    return {
        "total_access_points": len(access_points),
        "hidden_access_points": hidden_count,
        "band_counts": dict(sorted(band_counts.items())),
        "quality_counts": dict(sorted(quality_counts.items())),
        "active_access_points": active,
        "channel_load": channel_load,
        "recommendations": recommendations,
    }


def main() -> int:
    json.dump(scan_wifi(), sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
