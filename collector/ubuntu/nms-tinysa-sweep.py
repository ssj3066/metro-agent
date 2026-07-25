#!/usr/bin/env python3
"""Bounded tinySA USB serial sweep with normalized JSON output."""

from __future__ import annotations

import argparse
import fcntl
import glob
import json
import math
import os
import re
import statistics
import sys
import time
from datetime import datetime, timezone
from typing import Any


SCHEMA_VERSION = "metro-tinysa-sweep-v1"
DEFAULT_DEVICE_MODEL = "tinySA Ultra+ ZS407"
TINYSA_STABLE_PATHS = (
    "/dev/tinysa4",
    "/dev/serial/by-id/*tinySA*",
    "/dev/serial/by-id/*tinysa*",
)
WIFI_BAND_PROFILES = (
    ("wifi_2_4ghz", 2_400_000_000, 2_500_000_000),
    ("wifi_5ghz", 5_150_000_000, 5_850_000_000),
    ("wifi_6ghz", 5_925_000_000, 7_125_000_000),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def find_serial_device(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    candidates: list[str] = []
    for pattern in TINYSA_STABLE_PATHS:
        candidates.extend(sorted(glob.glob(pattern)))
    candidates.extend(sorted(glob.glob("/dev/ttyACM*")))
    candidates.extend(sorted(glob.glob("/dev/ttyUSB*")))
    unique = list(dict.fromkeys(candidates))
    return unique[0] if unique else None


def classify_error(exc: Exception) -> str:
    message = str(exc).lower()
    if isinstance(exc, FileNotFoundError) or "was not found" in message:
        return "device_not_found"
    if isinstance(exc, PermissionError) or "permission denied" in message:
        return "permission_denied"
    if isinstance(exc, TimeoutError):
        return "device_busy" if "busy" in message else "command_timeout"
    if "pyserial is not installed" in message:
        return "dependency_missing"
    if "no numeric samples" in message or "frequency" in message or "protocol" in message:
        return "protocol_error"
    return "measurement_failed"


def strip_console_response(text: str, command: str) -> list[str]:
    lines: list[str] = []
    for raw in str(text or "").replace("\r", "\n").splitlines():
        line = raw.strip()
        if not line or line == "ch>" or line == command or line.startswith("ch>"):
            continue
        lines.append(line)
    return lines


def parse_scan_response(
    text: str,
    command: str,
    start_hz: int,
    stop_hz: int,
    points: int,
) -> tuple[list[int], list[float]]:
    rows: list[tuple[float, ...]] = []
    for line in strip_console_response(text, command):
        values = tuple(
            float(value)
            for value in re.findall(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?", line)
        )
        if values:
            rows.append(values)
    if not rows:
        raise ValueError("tinySA scan returned no numeric samples")

    if all(len(row) >= 2 for row in rows):
        frequencies = [int(round(row[0])) for row in rows]
        powers = [float(row[1]) for row in rows]
    else:
        powers = [float(row[0]) for row in rows]
        count = len(powers)
        if count == 1:
            frequencies = [start_hz]
        else:
            step = (stop_hz - start_hz) / (count - 1)
            frequencies = [int(round(start_hz + index * step)) for index in range(count)]
    if len(frequencies) != len(powers):
        raise ValueError("tinySA frequency and power sample counts differ")
    if len(powers) > max(points * 2, 4096):
        raise ValueError("tinySA returned an unexpected number of samples")
    return frequencies, powers


def percentile(values: list[float], ratio: float) -> float:
    if not values:
        raise ValueError("values are required")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * ratio))))
    return ordered[index]


def wifi_channel(frequency_hz: int) -> int | None:
    mhz = frequency_hz / 1_000_000
    if mhz == 2484:
        return 14
    if 2412 <= mhz <= 2472:
        return round((mhz - 2407) / 5)
    if 5000 <= mhz <= 5895:
        return round((mhz - 5000) / 5)
    if 5955 <= mhz <= 7115:
        return round((mhz - 5950) / 5)
    return None


def summarize_sweep(frequencies: list[int], powers: list[float]) -> dict[str, Any]:
    average = statistics.fmean(powers)
    noise_floor = percentile(powers, 0.2)
    occupied_threshold = noise_floor + 6.0
    occupied = [index for index, power in enumerate(powers) if power >= occupied_threshold]
    frequency_step = (
        statistics.median(
            [frequencies[index] - frequencies[index - 1] for index in range(1, len(frequencies))]
        )
        if len(frequencies) > 1
        else 0
    )
    occupied_bandwidth = len(occupied) * max(0, frequency_step)
    occupancy = len(occupied) / len(powers) * 100
    peak = max(powers)
    peak_index = powers.index(peak)
    narrow_peak = sum(1 for power in powers if power >= noise_floor + 12.0) <= max(
        2, math.ceil(len(powers) * 0.03)
    )

    channel_values: dict[int, list[float]] = {}
    for frequency, power in zip(frequencies, powers):
        channel = wifi_channel(frequency)
        if channel is not None:
            channel_values.setdefault(channel, []).append(power)
    channel_summary = [
        {
            "channel": channel,
            "peak_dbm": round(max(values), 3),
            "average_dbm": round(statistics.fmean(values), 3),
            "sample_count": len(values),
        }
        for channel, values in sorted(channel_values.items())
    ]
    return {
        "peak_dbm": round(peak, 3),
        "peak_frequency_hz": frequencies[peak_index],
        "average_dbm": round(average, 3),
        "noise_floor_dbm": round(noise_floor, 3),
        "occupied_bandwidth_hz": int(round(occupied_bandwidth)),
        "rf_occupancy_pct": round(occupancy, 3),
        # A single sweep cannot prove that a transient pulse did not occur.
        "pulse_detected": None,
        "continuous_wave_detected": bool(peak >= noise_floor + 12.0 and narrow_peak),
        "channel_summary": channel_summary,
    }

def aggregate_sweeps(sweeps: list[list[float]], aggregation: str) -> list[float]:
    if not sweeps:
        raise ValueError("at least one sweep is required")
    if any(len(sweep) != len(sweeps[0]) for sweep in sweeps[1:]):
        raise ValueError("tinySA repeated sweeps returned different sample counts")
    if aggregation == "single_sweep":
        return list(sweeps[0])
    reducers = {
        "max_hold": max,
        "min_hold": min,
        "average": statistics.fmean,
    }
    reducer = reducers.get(aggregation)
    if not reducer:
        raise ValueError("unsupported tinySA aggregation")
    return [float(reducer(samples)) for samples in zip(*sweeps)]


class SerialConsole:
    def __init__(self, device: str, baudrate: int = 115200, timeout: float = 1.0):
        try:
            import serial
        except ImportError as exc:
            raise RuntimeError("pyserial is not installed") from exc
        self.serial = serial.Serial(
            device,
            baudrate=baudrate,
            timeout=timeout,
            write_timeout=timeout,
        )

    def close(self) -> None:
        self.serial.close()

    def command(self, command: str, timeout_seconds: float) -> str:
        self.serial.reset_input_buffer()
        self.serial.write((command + "\r").encode("ascii"))
        self.serial.flush()
        deadline = time.monotonic() + timeout_seconds
        output = bytearray()
        while time.monotonic() < deadline:
            chunk = self.serial.read(4096)
            if chunk:
                output.extend(chunk)
                if b"ch>" in output:
                    break
            else:
                time.sleep(0.02)
        if b"ch>" not in output:
            raise TimeoutError(f"tinySA command timed out: {command.split()[0]}")
        return output.decode("ascii", errors="replace")


class SerialDeviceLock:
    def __init__(self, device: str, timeout_seconds: float):
        self.path = os.path.realpath(device)
        self.timeout_seconds = timeout_seconds
        self.handle = None

    def __enter__(self):
        descriptor = os.open(
            self.path,
            os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY | getattr(os, "O_NOFOLLOW", 0),
        )
        self.handle = os.fdopen(descriptor, "rb+", buffering=0)
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    self.handle.close()
                    self.handle = None
                    raise TimeoutError("tinySA is busy with another sweep")
                time.sleep(0.05)

    def __exit__(self, _exc_type, _exc, _traceback):
        if self.handle:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
            self.handle = None


def probe_device(args: argparse.Namespace, console_factory=SerialConsole) -> dict[str, Any]:
    device = find_serial_device(args.device)
    if not device:
        raise RuntimeError("tinySA USB serial device was not found")
    with SerialDeviceLock(device, args.lock_timeout):
        console = console_factory(device, args.baudrate, args.read_timeout)
        try:
            version_text = console.command("version", min(5.0, args.timeout))
        finally:
            console.close()
    version = " ".join(strip_console_response(version_text, "version"))[:200] or None
    if not version or "tinysa" not in version.lower():
        raise RuntimeError("serial device responded but is not recognized as tinySA")
    return {
        "schema_version": SCHEMA_VERSION,
        "observed_at": utc_now(),
        "available": True,
        "device_path": device,
        "resolved_device_path": os.path.realpath(device),
        "device_model": args.device_model,
        "device_version": version,
    }


def collect_sweep(args: argparse.Namespace, console_factory=SerialConsole) -> dict[str, Any]:
    device = find_serial_device(args.device)
    if not device:
        raise RuntimeError("tinySA USB serial device was not found")
    command = f"scan {args.start_hz} {args.stop_hz} {args.points} 3"
    started_at = utc_now()
    started = time.monotonic()
    with SerialDeviceLock(device, args.lock_timeout):
        console = console_factory(device, args.baudrate, args.read_timeout)
        try:
            version_text = console.command("version", min(5.0, args.timeout))
            if "tinySA4_" not in version_text:
                version_text = console.command("version", min(5.0, args.timeout))
            if args.stop_hz > 900_000_000:
                console.command("ultra on", min(5.0, args.timeout))
            sweep_results: list[tuple[list[int], list[float]]] = []
            repetitions = 1 if args.aggregation == "single_sweep" else args.sweep_repetitions
            for _index in range(repetitions):
                response = console.command(command, args.timeout)
                sweep_results.append(parse_scan_response(
                    response,
                    command,
                    args.start_hz,
                    args.stop_hz,
                    args.points,
                ))
        finally:
            console.close()
    frequencies = sweep_results[0][0]
    if any(result_frequencies != frequencies for result_frequencies, _powers in sweep_results[1:]):
        raise ValueError("tinySA repeated sweeps returned different frequency axes")
    powers = aggregate_sweeps(
        [result_powers for _result_frequencies, result_powers in sweep_results],
        args.aggregation,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "observed_at": started_at,
        "completed_at": utc_now(),
        "sweep_duration_ms": round((time.monotonic() - started) * 1000, 3),
        "sensor_id": args.sensor_id,
        "device_path": device,
        "resolved_device_path": os.path.realpath(device),
        "device_model": args.device_model,
        "device_version": " ".join(strip_console_response(version_text, "version"))[:200] or None,
        "band": args.band,
        "start_hz": args.start_hz,
        "stop_hz": args.stop_hz,
        "rbw_hz": args.rbw_hz,
        "attenuation_db": args.attenuation_db,
        "lna_enabled": args.lna_enabled,
        "antenna_profile": args.antenna_profile,
        "calibration_state": args.calibration_state,
        "sweep_repetitions": repetitions,
        "aggregation": args.aggregation,
        "frequency_hz": frequencies,
        "power_dbm": [round(value, 4) for value in powers],
        "sample_count": len(powers),
        "source": f"tinysa_usb_console_{args.aggregation}_{repetitions}",
        **summarize_sweep(frequencies, powers),
    }

def collect_wifi_bands(args: argparse.Namespace, collector=collect_sweep) -> dict[str, Any]:
    started_at = utc_now()
    started = time.monotonic()
    bands = []
    for band, start_hz, stop_hz in WIFI_BAND_PROFILES:
        band_args = argparse.Namespace(**vars(args))
        band_args.band = band
        band_args.start_hz = start_hz
        band_args.stop_hz = stop_hz
        bands.append(collector(band_args))
    return {
        "schema_version": SCHEMA_VERSION,
        "observed_at": started_at,
        "completed_at": utc_now(),
        "sweep_duration_ms": round((time.monotonic() - started) * 1000, 3),
        "available": True,
        "mode": "wifi_all_sequential",
        "measurement_note": "2.4, 5, 6 GHz sequential sweeps displayed together",
        "bands": bands,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--wifi-all", action="store_true")
    parser.add_argument("--device")
    parser.add_argument("--baudrate", type=int, default=115200)
    parser.add_argument("--read-timeout", type=float, default=0.2)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--lock-timeout", type=float, default=30.0)
    parser.add_argument("--start-hz", type=int)
    parser.add_argument("--stop-hz", type=int)
    parser.add_argument("--points", type=int, default=290)
    parser.add_argument("--sweep-repetitions", type=int, default=1)
    parser.add_argument(
        "--aggregation",
        choices=("single_sweep", "max_hold", "average", "min_hold"),
        default="single_sweep",
    )
    parser.add_argument("--band", default="2.4GHz")
    parser.add_argument("--sensor-id", default="tinysa-1")
    parser.add_argument("--device-model", default=DEFAULT_DEVICE_MODEL)
    parser.add_argument("--antenna-profile", default="unknown")
    parser.add_argument(
        "--calibration-state",
        choices=("unknown", "uncalibrated", "level_calibrated"),
        default="uncalibrated",
    )
    parser.add_argument("--rbw-hz", type=int)
    parser.add_argument("--attenuation-db", type=float)
    parser.add_argument("--lna-enabled", action=argparse.BooleanOptionalAction, default=None)
    args = parser.parse_args(argv)
    if not args.probe and not args.wifi_all and (args.start_hz is None or args.stop_hz is None):
        parser.error("start-hz and stop-hz are required unless --probe or --wifi-all is used")
    if not args.probe and not args.wifi_all and (args.start_hz <= 0 or args.stop_hz <= args.start_hz):
        parser.error("stop-hz must be greater than start-hz")
    if args.timeout <= 0 or args.lock_timeout <= 0:
        parser.error("timeouts must be greater than zero")
    if not 51 <= args.points <= 450:
        parser.error("points must be between 51 and 450")
    if not 1 <= args.sweep_repetitions <= 32:
        parser.error("sweep-repetitions must be between 1 and 32")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.probe:
            result = probe_device(args)
        elif args.wifi_all:
            result = collect_wifi_bands(args)
        else:
            result = collect_sweep(args)
    except Exception as exc:
        result = {
            "schema_version": SCHEMA_VERSION,
            "observed_at": utc_now(),
            "available": False,
            "error_code": classify_error(exc),
            "error": str(exc)[:300],
        }
        if args.json:
            print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        else:
            print(result["error"], file=sys.stderr)
        return 1
    result["available"] = True
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
