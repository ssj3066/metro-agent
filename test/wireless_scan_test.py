import importlib.util
import pathlib
import tempfile
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

    def test_iw_phy_parser_reports_actual_supported_bands(self):
        radios = self.mod.parse_iw_phy_bands(
            """
Wiphy phy0
    Frequencies:
        * 2412 MHz [1]
        * 5180 MHz [36]
Wiphy phy1
    Frequencies:
        * 5955 MHz [1]
"""
        )
        self.assertEqual(radios[0]["supported_bands"], ["2.4 GHz", "5 GHz"])
        self.assertEqual(radios[1]["supported_bands"], ["6 GHz"])

    def test_unbound_future_usb_adapter_is_visible_as_driver_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            device = pathlib.Path(directory) / "1-2"
            device.mkdir()
            (device / "idVendor").write_text("0bda\n", encoding="ascii")
            (device / "idProduct").write_text("b832\n", encoding="ascii")
            (device / "manufacturer").write_text("Realtek\n", encoding="utf-8")
            (device / "product").write_text("802.11ax WLAN\n", encoding="utf-8")
            adapters = self.mod.usb_wireless_adapters(pathlib.Path(directory))
        self.assertEqual(adapters[0]["usb_id"], "0bda:b832")
        self.assertEqual(adapters[0]["state"], "driver_missing")

    def test_root_hub_does_not_inherit_descendant_wireless_interface(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            hub = root / "usb1"
            child = root / "1-2"
            hub.mkdir()
            child.mkdir()
            (hub / "idVendor").write_text("1d6b\n", encoding="ascii")
            (hub / "idProduct").write_text("0002\n", encoding="ascii")
            (hub / "product").write_text("xHCI Host Controller\n", encoding="utf-8")
            (child / "idVendor").write_text("0bda\n", encoding="ascii")
            (child / "idProduct").write_text("b832\n", encoding="ascii")
            (child / "product").write_text("802.11ax WLAN\n", encoding="utf-8")
            net_dir = root / "1-2:1.0" / "net"
            net_dir.mkdir(parents=True)
            (net_dir / "wlan-test").mkdir()
            adapters = self.mod.usb_wireless_adapters(root)
        self.assertEqual([item["usb_id"] for item in adapters], ["0bda:b832"])

    def test_vendor_driver_with_net_directory_on_device_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            device = pathlib.Path(directory) / "1-8"
            net_dir = device / "net" / "wlan-vendor"
            net_dir.mkdir(parents=True)
            (device / "idVendor").write_text("a69c\n", encoding="ascii")
            (device / "idProduct").write_text("88dc\n", encoding="ascii")
            (device / "product").write_text("AIC8800DC\n", encoding="utf-8")
            adapters = self.mod.usb_wireless_adapters(pathlib.Path(directory))
        self.assertEqual(adapters[0]["interfaces"], ["wlan-vendor"])
        self.assertEqual(adapters[0]["state"], "ready")

    def test_missing_band_is_not_reported_as_no_ap_when_adapter_cannot_scan_it(self):
        summary = self.mod.analyze_access_points(
            [{"band": "2.4 GHz", "channel": 1, "signal_pct": 70, "hidden": False, "active": True, "quality": "양호"}],
            ["2.4 GHz"],
            [],
        )
        self.assertIn("5 GHz는 활성 어댑터가 지원하지 않아 AP 유무를 판단할 수 없습니다.", summary["recommendations"])
        self.assertIn("6 GHz는 활성 어댑터가 지원하지 않아 AP 유무를 판단할 수 없습니다.", summary["recommendations"])


if __name__ == "__main__":
    unittest.main()
