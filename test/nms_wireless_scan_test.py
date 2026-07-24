import importlib.util
import pathlib
import unittest


PATH = pathlib.Path(__file__).parents[1] / "collector/ubuntu/nms-wireless-scan.py"


def load_module():
    spec = importlib.util.spec_from_file_location("nms_wireless_scan", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WirelessScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_parser_preserves_hidden_ssid_and_unescapes_bssid(self):
        rows = self.mod.parse_nmcli_wifi(
            "wlan0:*:Metro\\:Guest:5C\\:62\\:8B\\:07\\:C3\\:CE:6:2437 MHz:62:WPA2\n"
            "wlan0: ::12\\:09\\:A5\\:01\\:4E\\:9E:2:2417 MHz:20:WPA2\n"
        )
        self.assertEqual(rows[0]["ssid"], "Metro:Guest")
        self.assertEqual(rows[0]["bssid"], "5C:62:8B:07:C3:CE")
        hidden = next(row for row in rows if row["hidden"])
        self.assertIsNone(hidden["ssid"])
        self.assertEqual(hidden["band"], "2.4 GHz")

    def test_analysis_marks_crowded_channel_and_hidden_networks(self):
        access_points = [
            {"band": "2.4 GHz", "channel": 6, "signal_pct": 80, "hidden": False, "active": True, "quality": "매우 양호"},
            {"band": "2.4 GHz", "channel": 6, "signal_pct": 75, "hidden": True, "active": False, "quality": "매우 양호"},
            {"band": "2.4 GHz", "channel": 6, "signal_pct": 60, "hidden": False, "active": False, "quality": "양호"},
            {"band": "2.4 GHz", "channel": 6, "signal_pct": 45, "hidden": False, "active": False, "quality": "보통"},
        ]
        summary = self.mod.analyze_access_points(access_points)
        self.assertEqual(summary["hidden_access_points"], 1)
        self.assertEqual(summary["channel_load"][0]["level"], "높음")
        self.assertTrue(any("숨김 SSID" in text for text in summary["recommendations"]))


if __name__ == "__main__":
    unittest.main()
