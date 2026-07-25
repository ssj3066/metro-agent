import importlib.util
import unittest
from pathlib import Path


PATH = Path(__file__).parents[1] / "collector" / "ubuntu" / "nms_packet_flood.py"
SPEC = importlib.util.spec_from_file_location("nms_packet_flood", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PacketFloodTest(unittest.TestCase):
    def test_classifies_link_and_discovery_protocols(self):
        self.assertEqual(
            MODULE.packet_categories("MDNS", "01:00:5e:00:00:fb"),
            {"multicast", "mdns"},
        )
        self.assertEqual(
            MODULE.packet_categories("ARP", "ff:ff:ff:ff:ff:ff"),
            {"broadcast", "arp"},
        )
        self.assertIn(
            "mdns",
            MODULE.packet_categories("UDP", "01:00:5e:00:00:fb", "5353", "5353"),
        )

    def test_summary_requires_enough_observation_data(self):
        counts = MODULE.empty_counts()
        for _ in range(10):
            MODULE.add_packet(counts, "ARP", "ff:ff:ff:ff:ff:ff")
        summary = MODULE.summarize_counts(counts, 2)
        self.assertEqual(summary["status"], "insufficient_data")
        self.assertIsNone(summary["rates_pps"]["arp"])
        self.assertIn("패킷 20개 미만", summary["missing_data"])

    def test_summary_marks_rate_threshold_candidate(self):
        counts = MODULE.empty_counts()
        for _ in range(120):
            MODULE.add_packet(counts, "ARP", "ff:ff:ff:ff:ff:ff")
        summary = MODULE.summarize_counts(counts, 5)
        self.assertEqual(summary["status"], "candidate")
        self.assertEqual(summary["rates_pps"]["arp"], 24)
        self.assertTrue(any(signal["type"] == "arp" for signal in summary["signals"]))

    def test_parses_tshark_rows(self):
        counts, elapsed = MODULE.parse_tshark_rows([
            "1000\tff:ff:ff:ff:ff:ff\tARP",
            "1006\t01:00:5e:00:00:fb\tMDNS",
        ])
        self.assertEqual(elapsed, 6)
        self.assertEqual(counts["broadcast"], 1)
        self.assertEqual(counts["multicast"], 1)
        self.assertEqual(counts["mdns"], 1)


if __name__ == "__main__":
    unittest.main()
