#!/usr/bin/env python3
"""Bounded packet-flood counters shared by the field GUI and PCAP summary."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


MAC_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
RATE_THRESHOLDS_PPS = {
    "broadcast": 100.0,
    "multicast": 100.0,
    "arp": 20.0,
    "mdns": 10.0,
    "ssdp": 10.0,
    "name_resolution": 20.0,
}
MINIMUM_PACKETS = 20
MINIMUM_SECONDS = 5.0


def empty_counts() -> Counter[str]:
    return Counter({
        "total": 0,
        "link_layer_visible": 0,
        "broadcast": 0,
        "multicast": 0,
        "arp": 0,
        "mdns": 0,
        "ssdp": 0,
        "llmnr": 0,
        "nbns": 0,
        "dhcp": 0,
    })


def is_broadcast_mac(value: str | None) -> bool:
    return str(value or "").strip().lower() == "ff:ff:ff:ff:ff:ff"


def is_multicast_mac(value: str | None) -> bool:
    normalized = str(value or "").strip()
    if not MAC_PATTERN.fullmatch(normalized) or is_broadcast_mac(normalized):
        return False
    return bool(int(normalized.split(":", 1)[0], 16) & 1)


def packet_categories(
    protocol: str | None,
    destination_mac: str | None,
    udp_source_port: str | None = None,
    udp_destination_port: str | None = None,
) -> set[str]:
    normalized = str(protocol or "").strip().upper()
    udp_ports = {
        str(value or "").strip()
        for value in (udp_source_port, udp_destination_port)
        if str(value or "").strip()
    }
    categories: set[str] = set()
    if is_broadcast_mac(destination_mac):
        categories.add("broadcast")
    elif is_multicast_mac(destination_mac):
        categories.add("multicast")
    if normalized == "ARP":
        categories.add("arp")
    if normalized in {"MDNS", "MULTICASTDNS"} or "5353" in udp_ports:
        categories.add("mdns")
    if normalized == "SSDP" or "1900" in udp_ports:
        categories.add("ssdp")
    if normalized == "LLMNR" or "5355" in udp_ports:
        categories.add("llmnr")
    if normalized in {"NBNS", "NBNAME"} or "137" in udp_ports:
        categories.add("nbns")
    if normalized in {"DHCP", "DHCPV6", "BOOTP"} or udp_ports.intersection({"67", "68", "546", "547"}):
        categories.add("dhcp")
    return categories


def add_packet(
    counts: Counter[str],
    protocol: str | None,
    destination_mac: str | None,
    udp_source_port: str | None = None,
    udp_destination_port: str | None = None,
) -> set[str]:
    counts["total"] += 1
    if MAC_PATTERN.fullmatch(str(destination_mac or "").strip()):
        counts["link_layer_visible"] += 1
    categories = packet_categories(protocol, destination_mac, udp_source_port, udp_destination_port)
    for category in categories:
        counts[category] += 1
    return categories


def _round(value: float) -> float:
    return round(float(value), 2)


def summarize_counts(counts: Counter[str] | dict[str, int], elapsed_seconds: float) -> dict[str, Any]:
    elapsed = max(0.0, float(elapsed_seconds or 0))
    total = max(0, int(counts.get("total", 0)))
    rates = {
        key: (_round(int(counts.get(key, 0)) / elapsed) if elapsed >= MINIMUM_SECONDS else None)
        for key in ("broadcast", "multicast", "arp", "mdns", "ssdp", "llmnr", "nbns", "dhcp")
    }
    rates["name_resolution"] = (
        _round((int(counts.get("llmnr", 0)) + int(counts.get("nbns", 0))) / elapsed)
        if elapsed >= MINIMUM_SECONDS
        else None
    )
    ratios = {
        key: (_round(int(counts.get(key, 0)) * 100 / total) if total else None)
        for key in ("broadcast", "multicast", "arp", "mdns", "ssdp", "llmnr", "nbns", "dhcp")
    }
    missing_data: list[str] = []
    if elapsed < MINIMUM_SECONDS:
        missing_data.append(f"관측시간 {MINIMUM_SECONDS:g}초 미만")
    if total < MINIMUM_PACKETS:
        missing_data.append(f"패킷 {MINIMUM_PACKETS}개 미만")
    if int(counts.get("link_layer_visible", 0)) == 0:
        missing_data.append("이더넷 목적지 MAC 미관측")

    signals = []
    if not missing_data[:2]:
        for key, threshold in RATE_THRESHOLDS_PPS.items():
            observed = rates[key]
            if observed is not None and observed >= threshold:
                signals.append({
                    "type": key,
                    "observed_pps": observed,
                    "threshold_pps": threshold,
                    "evidence": f"{key} {int(counts.get(key, 0))}개/{elapsed:.1f}초",
                })
    return {
        "schema_version": "metro-packet-flood-summary-v1",
        "status": "candidate" if signals else ("insufficient_data" if missing_data[:2] else "no_candidate"),
        "elapsed_seconds": _round(elapsed),
        "packet_count": total,
        "counts": {key: int(counts.get(key, 0)) for key in empty_counts()},
        "rates_pps": rates,
        "ratios_pct": ratios,
        "thresholds_pps": dict(RATE_THRESHOLDS_PPS),
        "signals": signals,
        "missing_data": missing_data,
        "scope_notice": (
            "현재 인터페이스에서 관측된 패킷만 분석합니다. 전체 현장 플러딩 확정에는 "
            "스위치 SPAN/미러 포트 또는 트렁크 관측이 필요합니다."
        ),
    }


def parse_tshark_rows(lines: Iterable[str]) -> tuple[Counter[str], float]:
    counts = empty_counts()
    first_epoch: float | None = None
    last_epoch: float | None = None
    for line in lines:
        if not line.strip():
            continue
        fields = line.rstrip("\r\n").split("\t")
        fields.extend([""] * (5 - len(fields)))
        try:
            epoch = float(fields[0])
        except ValueError:
            epoch = None
        if epoch is not None:
            first_epoch = epoch if first_epoch is None else min(first_epoch, epoch)
            last_epoch = epoch if last_epoch is None else max(last_epoch, epoch)
        add_packet(counts, fields[2], fields[1], fields[3], fields[4])
    elapsed = max(0.0, (last_epoch or 0) - (first_epoch or 0)) if first_epoch is not None else 0.0
    return counts, elapsed


def analyze_pcap(path: Path) -> dict[str, Any]:
    result = subprocess.run(
        [
            "tshark", "-r", str(path), "-T", "fields",
            "-E", "separator=\t", "-E", "quote=n", "-E", "occurrence=f",
            "-e", "frame.time_epoch", "-e", "eth.dst", "-e", "_ws.col.Protocol",
            "-e", "udp.srcport", "-e", "udp.dstport",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or "tshark 분석 실패").strip())
    counts, elapsed = parse_tshark_rows(result.stdout.splitlines())
    return summarize_counts(counts, elapsed)


def render_text(summary: dict[str, Any]) -> str:
    labels = {
        "broadcast": "브로드캐스트",
        "multicast": "멀티캐스트",
        "arp": "ARP",
        "mdns": "mDNS",
        "ssdp": "SSDP",
        "llmnr": "LLMNR",
        "nbns": "NBNS",
        "dhcp": "DHCP",
    }
    state = {
        "candidate": "플러딩 후보 있음",
        "no_candidate": "현재 기준 초과 없음",
        "insufficient_data": "판단 자료 부족",
    }.get(summary.get("status"), "판단 불가")
    lines = [
        "[플러딩 분석]",
        f"판정: {state}",
        f"관측: {summary.get('packet_count', 0)}패킷 / {summary.get('elapsed_seconds', 0)}초",
    ]
    counts = summary.get("counts") or {}
    rates = summary.get("rates_pps") or {}
    ratios = summary.get("ratios_pct") or {}
    for key, label in labels.items():
        rate = rates.get(key)
        ratio = ratios.get(key)
        lines.append(
            f"- {label}: {counts.get(key, 0)}개"
            f" / {rate if rate is not None else '-'} pps"
            f" / {ratio if ratio is not None else '-'}%"
        )
    for signal in summary.get("signals") or []:
        lines.append(
            f"! {labels.get(signal['type'], signal['type'])} 후보:"
            f" {signal['observed_pps']} pps (기준 {signal['threshold_pps']} pps)"
        )
    if summary.get("missing_data"):
        lines.append("누락/제한: " + ", ".join(summary["missing_data"]))
    lines.append("범위: " + str(summary.get("scope_notice") or ""))
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3) or (len(argv) == 3 and argv[2] != "--json"):
        print("usage: nms_packet_flood.py PCAP [--json]", file=sys.stderr)
        return 2
    path = Path(argv[1]).resolve()
    if not path.is_file():
        print("capture file not found", file=sys.stderr)
        return 2
    summary = analyze_pcap(path)
    print(json.dumps(summary, ensure_ascii=False) if "--json" in argv else render_text(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
