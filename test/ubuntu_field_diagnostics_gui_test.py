import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).parents[1] / "collector/ubuntu/nms-field-diagnostics.py"
try:
    import tkinter  # noqa: F401
except ImportError:
    tkinter = None

def load_module():
    spec = importlib.util.spec_from_file_location("field_gui", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

@unittest.skipIf(tkinter is None, "python3-tk is not installed in this environment")
class GuiHelpersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_valid_host(self):
        self.assertTrue(self.mod.valid_host("10.0.0.2"))
        self.assertTrue(self.mod.valid_host("switch-1.local"))
        self.assertFalse(self.mod.valid_host("bad host"))
    def test_settings_never_require_community_value(self):
        data=self.mod.parse_settings('{"community_configured":true,"targets":[{"name":"Core","host":"10.0.0.2"}]}')
        self.assertTrue(data["community_configured"])
        self.assertNotIn("community",data["targets"][0])

    def test_interface_rate_uses_counter_delta(self):
        rates=self.mod.calculate_interface_rates(
            {"rx_bytes":1000,"tx_bytes":2000,"rx_packets":10,"tx_packets":20},
            {"rx_bytes":1001000,"tx_bytes":502000,"rx_packets":210,"tx_packets":120},
            2,
        )
        self.assertEqual(rates["rx_mbps"],4.0)
        self.assertEqual(rates["tx_mbps"],2.0)
        self.assertEqual(rates["rx_pps"],100.0)

    def test_discovery_parser_preserves_cdp_neighbor(self):
        payload={"lldp":{"interface":{"eth0":{"via":"CDPv2","chassis":{"Core":{"mgmt-ip":"10.0.0.2"}},"port":{"id":{"value":"Gi1/0/1"}}}}}}
        rows=self.mod.parse_discovery_neighbors(__import__("json").dumps(payload))
        self.assertEqual(rows[0]["protocol"],"CDPV2")
        self.assertEqual(rows[0]["device"],"Core")

class GuiSourceTest(unittest.TestCase):
    def test_traceroute_target_is_not_used_as_mtr_wait_value(self):
        source = PATH.read_text(encoding="utf-8")
        self.assertIn('mtr -r -c 5 -w \\"$NMS_DIAG_TARGET\\"', source)
        self.assertNotIn('mtr -r -c 5 -w 2 \\"$NMS_DIAG_TARGET\\"', source)

    def test_capture_has_fixed_profiles_and_limits(self):
        helper = (PATH.parent / "nms-gui-operations.sh").read_text(encoding="utf-8")
        for profile in ("basic)", "dns)", "dhcp)", "arp)", "icmp)", "lldp)"):
            self.assertIn(profile, helper)
        self.assertIn("duration >= 5 && duration <= 120", helper)
        self.assertIn("-c 5000", helper)
        self.assertIn("live-capture)", helper)
        self.assertIn("duration >= 60 && duration <= 1800", helper)
        self.assertIn("filesize:51200", helper)
        self.assertIn("ether dst 01:00:0c:cc:cc:cc", helper)

    def test_vpn_operations_validate_type_uuid_and_file_path(self):
        helper = (PATH.parent / "nms-gui-operations.sh").read_text(encoding="utf-8")
        self.assertIn('vpn_type" == "openvpn" || "$vpn_type" == "wireguard"', helper)
        self.assertIn('"$file" == /home/* || "$file" == /tmp/*', helper)
        self.assertIn('^[0-9a-fA-F-]{36}$', helper)
        self.assertNotIn("connection.password", helper)

    def test_wireguard_interface_unknown_is_presented_as_tunnel_state(self):
        source = PATH.read_text(encoding="utf-8")
        helper = (PATH.parent / "nms-gui-operations.sh").read_text(encoding="utf-8")
        self.assertIn('"인터페이스": f"{GUI_OPS} interface-status', source)
        self.assertIn('wg-quick@${interface}.service', helper)
        self.assertIn("터널 인터페이스 활성", helper)

    def test_wireless_analysis_uses_a_structured_scanner(self):
        source = PATH.read_text(encoding="utf-8")
        helper = (PATH.parent / "nms-gui-operations.sh").read_text(encoding="utf-8")
        self.assertIn('self._new_page("무선 분석")', source)
        self.assertIn('[GUI_OPS,"wireless-scan"]', source)
        self.assertIn('wireless-scan)', helper)
        self.assertIn('nms-wireless-scan.py', helper)

    def test_measurement_session_has_bounded_duration_interval_and_server_upload(self):
        source = PATH.read_text(encoding="utf-8")
        self.assertIn('self._new_page("측정 세션")', source)
        self.assertIn('10 <= duration <= 28800', source)
        self.assertIn('2 <= interval <= 300', source)
        self.assertIn('"measurement-session"', source)
        collector = (PATH.parent / "nms-collector.js").read_text(encoding="utf-8")
        self.assertIn("collector-measurement-session-v1", collector)
        self.assertIn("successful_count", collector)
        self.assertIn("failed_count", collector)

    def test_metro_sidebar_and_unified_snapshot_actions_are_present(self):
        source = PATH.read_text(encoding="utf-8")
        self.assertIn('style.configure("NavActive.TButton"', source)
        self.assertIn('text="METRO"', source)
        self.assertIn('text="진단 저장"', source)
        self.assertIn('text="저장 후 송신"', source)
        self.assertIn('def refresh_all(self):', source)
        self.assertNotIn("ttk.Notebook", source)

    def test_snapshot_session_exposes_source_readiness_without_secrets(self):
        source = PATH.read_text(encoding="utf-8")
        collector = (PATH.parent / "nms-collector.js").read_text(encoding="utf-8")
        self.assertIn('self._new_page("수집 소스")', source)
        self.assertIn('"snapshot-session"', source)
        self.assertIn("collector-source-readiness-v1", collector)
        self.assertIn("local_evidence", collector)

    def test_realtime_monitor_and_packet_stream_are_available(self):
        source = PATH.read_text(encoding="utf-8")
        self.assertIn('self._new_page("실시간 모니터링")', source)
        self.assertIn('text="실시간 시작"', source)
        self.assertIn('def stop_live_capture(self):', source)
        self.assertIn('self.root.after(2000,self.refresh_live_monitor)', source)

    def test_ict_manager_assignments_are_authoritative_with_hybrid_transport(self):
        source = PATH.read_text(encoding="utf-8")
        client = (PATH.parent / "ict_field_client.py").read_text(encoding="utf-8")
        self.assertIn('text="119 새로고침"', source)
        self.assertIn("def refresh_assigned_sites(self):", source)
        self.assertIn("def sync_ict_profile(self, profile, evidence):", source)
        self.assertIn("DEFAULT_VPN_URL", client)
        self.assertIn("DEFAULT_HTTPS_URL", client)
        self.assertIn('"offline_queue"', client)

if __name__ == "__main__": unittest.main()
