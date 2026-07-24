"""Local network diagnostics for METRO NMS_Collecter."""

from __future__ import annotations

import json
import math
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping

try:
    from nms_field_collector_core import APP_VERSION, default_hostname
except ModuleNotFoundError:  # pragma: no cover - package import path for tests.
    from .nms_field_collector_core import APP_VERSION, default_hostname


DEFAULT_DNS_TARGET = "168.126.63.1"
DEFAULT_PACKET_DURATION_SECONDS = 10
MIN_PACKET_DURATION_SECONDS = 3
MAX_PACKET_DURATION_SECONDS = 60
DEFAULT_PACKET_MAX_FRAMES = 100
MAX_TEXT_CHARS = 12000


def utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def is_windows() -> bool:
    return os.name == "nt"


def compact_text(value: str, limit: int = MAX_TEXT_CHARS) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\\n...[truncated {len(text) - limit} chars]"


def run_command(command: list[str], timeout_seconds: int = 15) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "command": command,
            "ok": completed.returncode == 0,
            "exit_code": completed.returncode,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "stdout": compact_text(completed.stdout),
            "stderr": compact_text(completed.stderr),
        }
    except FileNotFoundError:
        return {
            "command": command,
            "ok": False,
            "exit_code": None,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "stdout": "",
            "stderr": "command not found",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "ok": False,
            "exit_code": None,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "stdout": compact_text(exc.stdout or ""),
            "stderr": compact_text((exc.stderr or "") + "\\ncommand timed out"),
        }


def run_powershell(script: str, timeout_seconds: int = 20) -> dict[str, Any]:
    executable = shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh")
    if not executable:
        return {
            "command": ["powershell", "-NoProfile", "-Command", script],
            "ok": False,
            "exit_code": None,
            "duration_ms": 0,
            "stdout": "",
            "stderr": "PowerShell not found",
        }
    return run_command([executable, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout_seconds)


def parse_json_output(command_result: Mapping[str, Any]) -> Any:
    stdout = str(command_result.get("stdout") or "").strip()
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def parse_ping_rtts(output: str) -> list[float]:
    values: list[float] = []
    for match in re.finditer(r"(?:time|시간)[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", output, re.IGNORECASE):
        values.append(float(match.group(1)))
    return values


def summarize_rtts(rtts: list[float], sent_count: int) -> dict[str, Any]:
    received = len(rtts)
    loss_pct = round(((sent_count - received) / sent_count) * 100, 2) if sent_count > 0 else None
    if not rtts:
        return {
            "sent": sent_count,
            "received": 0,
            "loss_pct": loss_pct,
            "min_ms": None,
            "avg_ms": None,
            "max_ms": None,
            "jitter_ms": None,
            "range_jitter_ms": None,
        }

    avg = sum(rtts) / len(rtts)
    variance = sum((item - avg) ** 2 for item in rtts) / len(rtts)
    return {
        "sent": sent_count,
        "received": received,
        "loss_pct": loss_pct,
        "min_ms": round(min(rtts), 3),
        "avg_ms": round(avg, 3),
        "max_ms": round(max(rtts), 3),
        "jitter_ms": round(math.sqrt(variance), 3),
        "range_jitter_ms": round(max(rtts) - min(rtts), 3),
    }


def ping_target(target: str, count: int) -> dict[str, Any]:
    normalized = str(target or "").strip()
    if not normalized:
        return {"target": "", "ok": False, "error": "target is empty"}
    count = max(1, min(20, int(count or 4)))
    command = ["ping", "-n", str(count), "-w", "1000", normalized] if is_windows() else ["ping", "-c", str(count), "-W", "1", normalized]
    result = run_command(command, timeout_seconds=max(8, count + 4))
    combined = f"{result.get('stdout') or ''}\\n{result.get('stderr') or ''}"
    rtts = parse_ping_rtts(combined)
    return {
        "target": normalized,
        "ok": bool(result.get("ok")) and bool(rtts),
        "summary": summarize_rtts(rtts, count),
        "raw": result,
    }


def parse_windows_default_gateway(route_print_output: str) -> str | None:
    for raw_line in str(route_print_output or "").splitlines():
        line = raw_line.strip()
        match = re.match(r"^0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9.]+)\s+([0-9.]+)\s+\d+", line)
        if match and match.group(1) != "0.0.0.0":
            return match.group(1)
    return None


def parse_linux_default_gateway(route_output: str) -> str | None:
    for raw_line in str(route_output or "").splitlines():
        line = raw_line.strip()
        match = re.match(r"^default\s+via\s+(\S+)", line)
        if match:
            return match.group(1)
    return None


def detect_gateway(commands: Mapping[str, Mapping[str, Any]]) -> str | None:
    if is_windows():
        return parse_windows_default_gateway(str(commands.get("route_print", {}).get("stdout") or ""))
    return parse_linux_default_gateway(str(commands.get("ip_route", {}).get("stdout") or ""))


def parse_dns_servers_from_text(text: str) -> list[str]:
    servers: list[str] = []
    for match in re.finditer(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", str(text or "")):
        value = match.group(0)
        if value not in servers:
            servers.append(value)
    return servers


def parse_arp_entries(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        match = re.search(r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b\s+([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})", line, re.IGNORECASE)
        if match:
            entries.append({
                "ip": match.group(1),
                "mac": match.group(2).replace("-", ":").lower(),
                "raw": line,
            })
    return entries


def extract_vlan_hints(text: str) -> list[str]:
    hints: list[str] = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if re.search(r"\b(vlan|802\.1q|priority\s*&\s*vlan|vlan\s+id)\b", line, re.IGNORECASE):
            if line and line not in hints:
                hints.append(line[:300])
    return hints[:80]


def extract_vpn_hints(text: str) -> list[str]:
    hints: list[str] = []
    pattern = re.compile(r"\b(vpn|wireguard|openvpn|fortinet|forticlient|cisco|anyconnect|juniper|pulse|globalprotect|sstp|l2tp|ikev2|ipsec|tap|tun)\b", re.IGNORECASE)
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if pattern.search(line):
            if line and line not in hints:
                hints.append(line[:300])
    return hints[:80]


def collect_platform_commands() -> dict[str, dict[str, Any]]:
    if is_windows():
        return {
            "ipconfig_all": run_command(["ipconfig", "/all"], 20),
            "route_print": run_command(["route", "print", "-4"], 20),
            "arp_a": run_command(["arp", "-a"], 20),
            "netsh_lan_interfaces": run_command(["netsh", "lan", "show", "interfaces"], 20),
            "netsh_wlan_interfaces": run_command(["netsh", "wlan", "show", "interfaces"], 20),
            "ps_ip_config": run_powershell("Get-NetIPConfiguration | ConvertTo-Json -Depth 5", 30),
            "ps_dns": run_powershell("Get-DnsClientServerAddress -AddressFamily IPv4 | ConvertTo-Json -Depth 5", 30),
            "ps_adapters": run_powershell("Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed,InterfaceIndex,VlanID | ConvertTo-Json -Depth 5", 30),
            "ps_vlan": run_powershell("Get-NetAdapterAdvancedProperty | Where-Object {$_.DisplayName -match 'VLAN|802.1Q|Priority'} | Select-Object Name,DisplayName,DisplayValue,RegistryKeyword,RegistryValue | ConvertTo-Json -Depth 5", 30),
            "ps_vpn": run_powershell("$items=@(); try {$items += Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue} catch {}; try {$items += Get-VpnConnection -ErrorAction SilentlyContinue} catch {}; $items | Select-Object Name,ServerAddress,TunnelType,ConnectionStatus,SplitTunneling,AllUserConnection | ConvertTo-Json -Depth 5", 30),
            "ps_lldp": run_powershell("try {Get-NetLldpAgent | ConvertTo-Json -Depth 5} catch {Write-Output $_.Exception.Message; exit 1}", 20),
        }

    commands = {
        "ip_addr_json": run_command(["ip", "-j", "addr"], 20),
        "ip_route": run_command(["ip", "route"], 20),
        "ip_link_detail": run_command(["ip", "-d", "link"], 20),
        "ip_neigh": run_command(["ip", "neigh", "show"], 20),
        "resolv_conf": run_command(["cat", "/etc/resolv.conf"], 10),
    }
    if shutil.which("resolvectl"):
        commands["resolvectl_dns"] = run_command(["resolvectl", "dns"], 15)
    if shutil.which("nmcli"):
        commands["nmcli_active"] = run_command(["nmcli", "-t", "-f", "NAME,TYPE,DEVICE,STATE", "con", "show", "--active"], 20)
        commands["nmcli_devices"] = run_command(["nmcli", "-f", "GENERAL,IP4,VLAN", "device", "show"], 25)
    if shutil.which("wg"):
        commands["wireguard"] = run_command(["wg", "show"], 15)
    return commands


def get_command_text(commands: Mapping[str, Mapping[str, Any]], names: list[str]) -> str:
    chunks: list[str] = []
    for name in names:
        item = commands.get(name) or {}
        chunks.append(str(item.get("stdout") or ""))
        chunks.append(str(item.get("stderr") or ""))
    return "\\n".join(chunks)


def collect_packet_info(settings: Mapping[str, Any]) -> dict[str, Any]:
    enabled = bool(settings.get("diagnostics_packet_enabled"))
    duration = parse_bounded_int(settings.get("diagnostics_packet_duration"), DEFAULT_PACKET_DURATION_SECONDS, MIN_PACKET_DURATION_SECONDS, MAX_PACKET_DURATION_SECONDS)
    max_frames = parse_bounded_int(settings.get("diagnostics_packet_max_frames"), DEFAULT_PACKET_MAX_FRAMES, 10, 500)
    interface = str(settings.get("diagnostics_packet_interface") or "").strip() or "1"

    tshark = shutil.which("tshark")
    dumpcap = shutil.which("dumpcap")
    result: dict[str, Any] = {
        "enabled": enabled,
        "tooling": {
            "tshark": tshark,
            "dumpcap": dumpcap,
        },
        "interface": interface,
        "duration_seconds": duration,
        "max_frames": max_frames,
        "interfaces": None,
        "capture": None,
        "lldp_cdp_detail": None,
    }

    if tshark:
        result["interfaces"] = run_command([tshark, "-D"], 20)
    elif dumpcap:
        result["interfaces"] = run_command([dumpcap, "-D"], 20)

    if not enabled:
        result["status"] = "disabled"
        return result
    if not tshark:
        result["status"] = "unavailable"
        result["message"] = "tshark not found. Install Wireshark/TShark and Npcap for packet capture."
        return result

    display_filter = "lldp || cdp || arp || icmp || dns"
    capture_command = [
        tshark,
        "-i",
        interface,
        "-a",
        f"duration:{duration}",
        "-c",
        str(max_frames),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.protocols",
        "-e",
        "eth.src",
        "-e",
        "eth.dst",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "_ws.col.Info",
    ]
    result["capture"] = run_command(capture_command, timeout_seconds=duration + 15)
    detail_command = [
        tshark,
        "-i",
        interface,
        "-a",
        f"duration:{max(3, min(duration, 15))}",
        "-c",
        str(max(10, min(max_frames, 60))),
        "-Y",
        "lldp || cdp",
        "-V",
    ]
    result["lldp_cdp_detail"] = run_command(detail_command, timeout_seconds=max(20, duration + 10))
    result["status"] = "captured" if (result["capture"] or {}).get("ok") else "failed"
    return result


def parse_bounded_int(value: Any, fallback: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return fallback
    return max(minimum, min(maximum, parsed))


def collect_network_diagnostics(settings: Mapping[str, Any]) -> dict[str, Any]:
    commands = collect_platform_commands()
    gateway = str(settings.get("diagnostics_gateway_target") or "").strip() or detect_gateway(commands)
    dns_target = str(settings.get("diagnostics_dns_target") or "").strip() or DEFAULT_DNS_TARGET
    ping_count = parse_bounded_int(settings.get("diagnostics_ping_count"), 6, 1, 20)

    dns_source_text = get_command_text(commands, ["ipconfig_all", "ps_dns", "resolvectl_dns", "resolv_conf"])
    arp_text = get_command_text(commands, ["arp_a", "ip_neigh"])
    vlan_text = get_command_text(commands, ["ps_vlan", "ps_adapters", "ip_link_detail", "nmcli_devices"])
    vpn_text = get_command_text(commands, ["ps_vpn", "ps_adapters", "nmcli_active", "wireguard", "ip_link_detail"])
    lldp_text = get_command_text(commands, ["ps_lldp", "netsh_lan_interfaces"])
    packet = collect_packet_info(settings)
    packet_lldp_text = get_command_text({
        "capture": packet.get("capture") or {},
        "detail": packet.get("lldp_cdp_detail") or {},
    }, ["capture", "detail"])

    gateway_ping = ping_target(gateway, ping_count) if gateway else {"target": "", "ok": False, "error": "gateway not detected"}
    dns_ping = ping_target(dns_target, ping_count)
    arp_entries = parse_arp_entries(arp_text)
    gateway_neighbor = next((item for item in arp_entries if gateway and item.get("ip") == gateway), None)

    report = {
        "schema_version": "metro-nms-collecter-diagnostics-v1",
        "collector_app_version": APP_VERSION,
        "collected_at": utc_now_iso(),
        "host": {
            "hostname": default_hostname(),
            "platform": platform.platform(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "targets": {
            "gateway": gateway,
            "dns": dns_target,
            "ping_count": ping_count,
        },
        "ip_info": {
            "dns_servers_detected": parse_dns_servers_from_text(dns_source_text),
            "default_gateway": gateway,
            "gateway_neighbor": gateway_neighbor,
            "commands": {
                key: commands[key]
                for key in commands
                if key in {"ipconfig_all", "ps_ip_config", "ip_addr_json", "route_print", "ip_route", "ps_dns", "resolv_conf", "resolvectl_dns"}
            },
        },
        "switch_info": {
            "link_commands": {
                key: commands[key]
                for key in commands
                if key in {"ps_adapters", "netsh_lan_interfaces", "netsh_wlan_interfaces", "ip_link_detail", "nmcli_devices"}
            },
            "gateway_neighbor": gateway_neighbor,
        },
        "vlan_info": {
            "hints": extract_vlan_hints(vlan_text),
            "commands": {
                key: commands[key]
                for key in commands
                if key in {"ps_vlan", "ps_adapters", "ip_link_detail", "nmcli_devices"}
            },
        },
        "vpn_info": {
            "hints": extract_vpn_hints(vpn_text),
            "commands": {
                key: commands[key]
                for key in commands
                if key in {"ps_vpn", "ps_adapters", "nmcli_active", "wireguard", "ip_link_detail"}
            },
        },
        "lldp_cdp_info": {
            "hints": extract_lldp_cdp_hints(f"{lldp_text}\\n{packet_lldp_text}"),
            "commands": {
                key: commands[key]
                for key in commands
                if key in {"ps_lldp", "netsh_lan_interfaces"}
            },
            "packet_detail": packet.get("lldp_cdp_detail"),
        },
        "ping": {
            "gateway": gateway_ping,
            "dns": dns_ping,
        },
        "arp_info": {
            "entry_count": len(arp_entries),
            "entries": arp_entries[:300],
            "commands": {
                key: commands[key]
                for key in commands
                if key in {"arp_a", "ip_neigh"}
            },
        },
        "packet_info": packet,
    }
    report["summary"] = summarize_diagnostics(report)
    return report


def extract_lldp_cdp_hints(text: str) -> list[str]:
    hints: list[str] = []
    pattern = re.compile(r"\b(lldp|cdp|chassis|port id|system name|device id|platform|ttl)\b", re.IGNORECASE)
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if pattern.search(line):
            if line and line not in hints:
                hints.append(line[:300])
    return hints[:120]


def summarize_diagnostics(report: Mapping[str, Any]) -> dict[str, Any]:
    ping = report.get("ping") if isinstance(report.get("ping"), Mapping) else {}
    gateway_ping = ping.get("gateway") if isinstance(ping.get("gateway"), Mapping) else {}
    dns_ping = ping.get("dns") if isinstance(ping.get("dns"), Mapping) else {}
    vlan = report.get("vlan_info") if isinstance(report.get("vlan_info"), Mapping) else {}
    vpn = report.get("vpn_info") if isinstance(report.get("vpn_info"), Mapping) else {}
    lldp = report.get("lldp_cdp_info") if isinstance(report.get("lldp_cdp_info"), Mapping) else {}
    arp = report.get("arp_info") if isinstance(report.get("arp_info"), Mapping) else {}
    packet = report.get("packet_info") if isinstance(report.get("packet_info"), Mapping) else {}
    targets = report.get("targets") if isinstance(report.get("targets"), Mapping) else {}

    return {
        "collected_at": report.get("collected_at"),
        "default_gateway": targets.get("gateway"),
        "dns_target": targets.get("dns"),
        "gateway_ping": gateway_ping.get("summary"),
        "dns_ping": dns_ping.get("summary"),
        "arp_entry_count": arp.get("entry_count", 0),
        "gateway_mac": (report.get("ip_info") or {}).get("gateway_neighbor", {}).get("mac") if isinstance(report.get("ip_info"), Mapping) and isinstance((report.get("ip_info") or {}).get("gateway_neighbor"), Mapping) else None,
        "vlan_hint_count": len(vlan.get("hints") or []),
        "vpn_hint_count": len(vpn.get("hints") or []),
        "lldp_cdp_hint_count": len(lldp.get("hints") or []),
        "packet_status": packet.get("status"),
        "packet_tool": "tshark" if (packet.get("tooling") or {}).get("tshark") else "none",
    }


def write_diagnostics_report(path: str | os.PathLike[str], report: Mapping[str, Any]) -> Path:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return target
