#!/usr/bin/env python3
"""Bounded Wi-Fi environment scan for the Ubuntu field collector."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


NMCLI_FIELDS = "DEVICE,IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY"
BSSID_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
WIRELESS_PRODUCT_PATTERN = re.compile(r"(wi-?fi|wireless|wlan|802\.11)", re.IGNORECASE)


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


def read_sysfs_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def parse_iw_phy_bands(output: str) -> list[dict[str, Any]]:
    radios: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    frequencies: set[int] = set()

    def finish() -> None:
        nonlocal current, frequencies
        if current is None:
            return
        bands = sorted(
            {frequency_band(value) for value in frequencies if frequency_band(value) != "기타"},
            key=lambda value: ("2.4 GHz", "5 GHz", "6 GHz").index(value),
        )
        current["supported_bands"] = bands
        current["frequency_count"] = len(frequencies)
        radios.append(current)
        current = None
        frequencies = set()

    for raw_line in str(output or "").splitlines():
        line = raw_line.strip()
        if line.startswith("Wiphy "):
            finish()
            current = {"phy": line.removeprefix("Wiphy ").strip()}
            continue
        if current is None:
            continue
        match = re.match(r"\*\s+(\d+)\s+MHz", line)
        if match:
            frequencies.add(int(match.group(1)))
    finish()
    return radios


def usb_wireless_adapters(sysfs_root: Path = Path("/sys/bus/usb/devices")) -> list[dict[str, Any]]:
    adapters: list[dict[str, Any]] = []
    if not sysfs_root.exists():
        return adapters
    for device in sorted(sysfs_root.iterdir(), key=lambda path: path.name):
        vendor = read_sysfs_text(device / "idVendor").lower()
        product_id = read_sysfs_text(device / "idProduct").lower()
        if not re.fullmatch(r"[0-9a-f]{4}", vendor) or not re.fullmatch(r"[0-9a-f]{4}", product_id):
            continue
        manufacturer = read_sysfs_text(device / "manufacturer")
        product = read_sysfs_text(device / "product")
        interfaces: list[str] = []
        # USB interface nodes are siblings named <device>:<config>.<interface>.
        # Do not recurse, because a root hub would otherwise inherit every
        # descendant network interface and be misreported as an adapter.
        net_directories = [device / "net", *device.glob(f"{device.name}:*/net")]
        for net_dir in net_directories:
            try:
                interfaces.extend(
                    interface.name for interface in net_dir.iterdir() if interface.name != "lo"
                )
            except OSError:
                continue
        interfaces = sorted(set(interfaces))
        driver_paths = [device / "driver", *device.glob("*/driver")]
        drivers = sorted({
            Path(os.path.realpath(driver)).name
            for driver in driver_paths
            if driver.exists()
        })
        descriptor = " ".join((manufacturer, product))
        if not interfaces and not WIRELESS_PRODUCT_PATTERN.search(descriptor):
            continue
        adapters.append({
            "usb_id": f"{vendor}:{product_id}",
            "manufacturer": manufacturer or None,
            "product": product or None,
            "interfaces": interfaces,
            "drivers": drivers,
            "state": "ready" if interfaces else ("driver_missing" if not drivers else "interface_missing"),
        })
    return adapters


def radio_capabilities(runner=subprocess.run) -> list[dict[str, Any]]:
    try:
        result = runner(["iw", "phy"], capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    return parse_iw_phy_bands(result.stdout)


def signal_quality(signal_pct: int) -> str:
    if signal_pct >= 75:
        return "매우 양호"
    if signal_pct >= 55:
        return "양호"
    if signal_pct >= 35:
        return "보통"
    return "약함"


def is_locally_administered_bssid(value: str | None) -> bool:
    if not value or not BSSID_PATTERN.fullmatch(value):
        return False
    return bool(int(value.split(":", 1)[0], 16) & 0x02)


def annotate_access_points(access_points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    annotated = [dict(item) for item in access_points]
    for item in annotated:
        bssid = str(item.get("bssid") or "")
        local_mac = is_locally_administered_bssid(bssid)
        signal = int(item.get("signal_pct") or 0)
        item["mac_address_type"] = "locally_administered" if local_mac else "globally_administered"
        if signal >= 100:
            item["signal_interpretation"] = (
                "신호 품질 상한값입니다. 실제 전파 세기가 100%라는 뜻은 아니며 원시 dBm 확인이 필요합니다."
            )
        elif signal >= 95:
            item["signal_interpretation"] = (
                "매우 강한 신호 품질입니다. 근접 AP 가능성이 있지만 거리 판단에는 원시 dBm 확인이 필요합니다."
            )
        else:
            item["signal_interpretation"] = (
                "NetworkManager가 드라이버 측정값을 0~100 품질로 변환한 값입니다."
            )
        item["identity_interpretation"] = (
            "로컬 관리 MAC입니다. 제조사 고유 MAC이 아니므로 OUI만으로 장비를 식별할 수 없습니다."
            if local_mac
            else "제조사 할당 MAC 형식입니다."
        )
        item["related_bssid"] = None
        item["related_ssid"] = None

        if not item.get("hidden") or not local_mac or not bssid:
            continue
        suffix = bssid.upper().split(":")[1:]
        candidates = [
            candidate
            for candidate in annotated
            if not candidate.get("hidden")
            and candidate.get("ssid")
            and str(candidate.get("bssid") or "").upper().split(":")[1:] == suffix
            and candidate.get("channel") == item.get("channel")
            and candidate.get("frequency_mhz") == item.get("frequency_mhz")
        ]
        same_interface = [
            candidate
            for candidate in candidates
            if candidate.get("interface") == item.get("interface")
        ]
        candidate = (same_interface or candidates or [None])[0]
        if candidate:
            item["related_bssid"] = candidate.get("bssid")
            item["related_ssid"] = candidate.get("ssid")
            item["identity_interpretation"] = (
                f"{candidate.get('ssid')}({candidate.get('bssid')})와 채널·주파수·MAC 뒷자리가 같습니다. "
                "동일 AP가 만든 숨김/가상 BSSID로 추정하며 AP 설정에서 최종 확인합니다."
            )
    return annotated


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
    ordered = sorted(
        access_points,
        key=lambda item: (not item["active"], -item["signal_pct"], item["bssid"] or ""),
    )
    return annotate_access_points(ordered)


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


def scan_wifi(runner=subprocess.run, sysfs_root: Path = Path("/sys/bus/usb/devices")) -> dict[str, Any]:
    scanned_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    radio_details = radio_capabilities(runner)
    adapters = usb_wireless_adapters(sysfs_root)
    supported_bands = sorted(
        {
            band
            for radio in radio_details
            for band in radio.get("supported_bands", [])
        },
        key=lambda value: ("2.4 GHz", "5 GHz", "6 GHz").index(value),
    )
    try:
        result = runner(
            ["nmcli", "-t", "--escape", "yes", "-f", NMCLI_FIELDS, "device", "wifi", "list", "--rescan", "yes"],
            capture_output=True,
            text=True,
            timeout=35,
            check=False,
        )
    except FileNotFoundError:
        return {"schema_version": "nms-wireless-scan-v2", "scanned_at": scanned_at, "available": False, "reason": "nmcli가 설치되지 않았습니다.", "radios": [], "radio_details": radio_details, "usb_adapters": adapters, "supported_bands": supported_bands, "access_points": []}
    except subprocess.TimeoutExpired:
        return {"schema_version": "nms-wireless-scan-v2", "scanned_at": scanned_at, "available": False, "reason": "무선 스캔 시간이 초과되었습니다.", "radios": wifi_radios(runner), "radio_details": radio_details, "usb_adapters": adapters, "supported_bands": supported_bands, "access_points": []}

    if result.returncode != 0:
        reason = (result.stderr or result.stdout or "무선 스캔을 실행할 수 없습니다.").strip()
        return {"schema_version": "nms-wireless-scan-v2", "scanned_at": scanned_at, "available": False, "reason": reason[:500], "radios": wifi_radios(runner), "radio_details": radio_details, "usb_adapters": adapters, "supported_bands": supported_bands, "access_points": []}

    access_points = parse_nmcli_wifi(result.stdout)
    return {
        "schema_version": "nms-wireless-scan-v2",
        "scanned_at": scanned_at,
        "available": True,
        "radios": wifi_radios(runner),
        "radio_details": radio_details,
        "usb_adapters": adapters,
        "supported_bands": supported_bands,
        "access_points": access_points,
        "summary": analyze_access_points(access_points, supported_bands, adapters),
    }


def analyze_access_points(
    access_points: list[dict[str, Any]],
    supported_bands: list[str] | None = None,
    adapters: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    supported_bands = list(supported_bands or [])
    adapters = list(adapters or [])
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
    for band in ("5 GHz", "6 GHz"):
        if band_counts.get(band):
            continue
        if band not in supported_bands:
            recommendations.append(f"{band}는 활성 어댑터가 지원하지 않아 AP 유무를 판단할 수 없습니다.")
        elif access_points:
            recommendations.append(f"{band} 검색은 가능하지만 이번 스캔에서 AP가 검출되지 않았습니다.")
    missing_driver = [item for item in adapters if item.get("state") == "driver_missing"]
    if missing_driver:
        labels = ", ".join(str(item.get("usb_id") or "USB 장치") for item in missing_driver[:4])
        recommendations.append(f"드라이버가 연결되지 않은 무선 장치: {labels}. 장치용 Linux 드라이버를 설치해야 합니다.")
    if access_points and not recommendations:
        recommendations.append("현재 스캔 기준으로 즉시 확인할 무선 경고는 없습니다.")

    return {
        "total_access_points": len(access_points),
        "hidden_access_points": hidden_count,
        "band_counts": dict(sorted(band_counts.items())),
        "quality_counts": dict(sorted(quality_counts.items())),
        "active_access_points": active,
        "channel_load": channel_load,
        "supported_bands": supported_bands,
        "adapter_count": len(adapters),
        "driver_missing_count": len(missing_driver),
        "recommendations": recommendations,
    }


def main() -> int:
    json.dump(scan_wifi(), sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
