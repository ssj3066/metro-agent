import importlib.util
import pathlib
import unittest
from unittest import mock


PATH = pathlib.Path(__file__).parents[1] / "collector/ubuntu/nms-tinysa-sweep.py"


def load_module():
    spec = importlib.util.spec_from_file_location("nms_tinysa_sweep", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TinySASweepTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_parse_two_column_scan(self):
        command = "scan 2400000000 2500000000 3 3"
        frequencies, powers = self.mod.parse_scan_response(
            f"{command}\r\n2400000000 -80.0\r\n2450000000 -45.5\r\n2500000000 -81.0\r\nch>",
            command,
            2400000000,
            2500000000,
            3,
        )
        self.assertEqual(frequencies, [2400000000, 2450000000, 2500000000])
        self.assertEqual(powers[1], -45.5)

    def test_parse_power_only_scan_builds_linear_frequency_axis(self):
        command = "scan 2400000000 2500000000 3 3"
        frequencies, powers = self.mod.parse_scan_response(
            f"{command}\r\n-80\r\n-50\r\n-90\r\nch>",
            command,
            2400000000,
            2500000000,
            3,
        )
        self.assertEqual(frequencies, [2400000000, 2450000000, 2500000000])
        self.assertEqual(powers, [-80.0, -50.0, -90.0])

    def test_summary_preserves_physical_values_and_marks_pulse_unknown(self):
        frequencies = [2412000000 + index * 1000000 for index in range(20)]
        powers = [-90.0] * 20
        powers[10] = -55.0
        summary = self.mod.summarize_sweep(frequencies, powers)
        self.assertEqual(summary["peak_dbm"], -55.0)
        self.assertEqual(summary["noise_floor_dbm"], -90.0)
        self.assertTrue(summary["continuous_wave_detected"])
        self.assertIsNone(summary["pulse_detected"])

    def test_zs407_model_and_serial_lock_are_explicit(self):
        self.assertEqual(self.mod.DEFAULT_DEVICE_MODEL, "tinySA Ultra+ ZS407")
        lock = self.mod.SerialDeviceLock("/dev/tinysa4", 1)
        self.assertTrue(lock.path.endswith("/dev/tinysa4"))

    def test_probe_arguments_and_error_codes_are_stable(self):
        args = self.mod.parse_args(["--probe", "--device", "/dev/tinysa4"])
        self.assertTrue(args.probe)
        self.assertEqual(args.lock_timeout, 30.0)
        self.assertEqual(
            self.mod.classify_error(TimeoutError("tinySA is busy with another sweep")),
            "device_busy",
        )
        self.assertEqual(
            self.mod.classify_error(PermissionError("permission denied")),
            "permission_denied",
        )

    def test_ultra_mode_is_enabled_before_scanning_above_900mhz(self):
        commands = []

        class FakeConsole:
            def __init__(self, *_args):
                pass

            def command(self, command, _timeout):
                commands.append(command)
                if command == "version":
                    return "tinySA4_v1.4\r\nch>"
                if command == "ultra on":
                    return "ch>"
                return f"{command}\r\n2400000000 -80\r\n2500000000 -70\r\nch>"

            def close(self):
                pass

        args = self.mod.parse_args([
            "--device", "/dev/fake-tinysa",
            "--start-hz", "2400000000", "--stop-hz", "2500000000",
            "--points", "290", "--calibration-state", "level_calibrated",
        ])
        with mock.patch.object(self.mod, "SerialDeviceLock"):
            result = self.mod.collect_sweep(args, console_factory=FakeConsole)
        self.assertEqual(commands[:3], ["version", "ultra on", "scan 2400000000 2500000000 290 3"])
        self.assertEqual(result["calibration_state"], "level_calibrated")

    def test_repeated_sweeps_store_frequency_aligned_max_hold(self):
        scan_count = 0

        class FakeConsole:
            def __init__(self, *_args):
                pass

            def command(self, command, _timeout):
                nonlocal scan_count
                if command == "version":
                    return "tinySA4_v1.4\r\nch>"
                if command == "ultra on":
                    return "ch>"
                scan_count += 1
                peak = -80 + scan_count * 10
                return f"{command}\r\n2400000000 -90\r\n2500000000 {peak}\r\nch>"

            def close(self):
                pass

        args = self.mod.parse_args([
            "--device", "/dev/fake-tinysa",
            "--start-hz", "2400000000", "--stop-hz", "2500000000",
            "--points", "290", "--sweep-repetitions", "3", "--aggregation", "max_hold",
        ])
        with mock.patch.object(self.mod, "SerialDeviceLock"):
            result = self.mod.collect_sweep(args, console_factory=FakeConsole)
        self.assertEqual(result["power_dbm"], [-90.0, -50.0])
        self.assertEqual(result["aggregation"], "max_hold")
        self.assertEqual(result["sweep_repetitions"], 3)
        self.assertEqual(result["source"], "tinysa_usb_console_max_hold_3")

    def test_sweep_aggregation_modes(self):
        sweeps = [[-90.0, -50.0], [-80.0, -70.0], [-85.0, -60.0]]
        self.assertEqual(self.mod.aggregate_sweeps(sweeps, "single_sweep"), sweeps[0])
        self.assertEqual(self.mod.aggregate_sweeps(sweeps, "max_hold"), [-80.0, -50.0])
        self.assertEqual(self.mod.aggregate_sweeps(sweeps, "min_hold"), [-90.0, -70.0])
        self.assertEqual(self.mod.aggregate_sweeps(sweeps, "average"), [-85.0, -60.0])

    def test_wifi_all_collects_three_sequential_bands(self):
        observed = []

        def fake_collect(args):
            observed.append((args.band, args.start_hz, args.stop_hz))
            return {"available": True, "band": args.band, "observed_at": self.mod.utc_now()}

        args = self.mod.parse_args(["--wifi-all", "--device", "/dev/fake-tinysa"])
        result = self.mod.collect_wifi_bands(args, collector=fake_collect)
        self.assertEqual([item[0] for item in observed], ["wifi_2_4ghz", "wifi_5ghz", "wifi_6ghz"])
        self.assertEqual(result["mode"], "wifi_all_sequential")
        self.assertEqual(len(result["bands"]), 3)


if __name__ == "__main__":
    unittest.main()
