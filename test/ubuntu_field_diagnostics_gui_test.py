import importlib.util
import pathlib
import unittest
from unittest import mock

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

    def test_collector_name_defaults_and_validation(self):
        self.assertEqual(
            self.mod.DEFAULT_COLLECTOR_NAME,
            "메트로정보통신 네트워크 현장 분석기",
        )
        self.assertEqual(self.mod.normalize_collector_name(" 현장 분석기 "), "현장 분석기")
        with self.assertRaises(ValueError):
            self.mod.normalize_collector_name("")
        with self.assertRaises(ValueError):
            self.mod.normalize_collector_name("invalid=name")

    def test_tinysa_zs407_settings_are_bounded(self):
        settings = self.mod.normalize_tinysa_settings(
            "wifi_6ghz", "5925", "7125", "450", "30", "unknown", "AP",
        )
        self.assertEqual(settings["model"], "tinySA Ultra+ ZS407")
        self.assertEqual(settings["category"], "AP")
        self.assertEqual(settings["axis_mode"], "wifi_6")
        self.assertEqual(settings["stop_hz"], 7_125_000_000)
        self.assertEqual(settings["points"], 450)
        with self.assertRaises(ValueError):
            self.mod.normalize_tinysa_settings("custom", "2400", "7400", "290", "30", "unknown")
        with self.assertRaises(ValueError):
            self.mod.normalize_tinysa_settings("wifi_2_4ghz", "2400", "2500", "451", "30", "unknown")
        with self.assertRaises(ValueError):
            self.mod.normalize_tinysa_settings("wifi_2_4ghz", "2400", "2500", "290", "30", "unknown", "방송")

    def test_tinysa_permission_message_distinguishes_stale_login_group(self):
        with mock.patch.object(self.mod.Path, "exists", return_value=True), \
                mock.patch.object(self.mod.os, "access", return_value=False), \
                mock.patch.object(
                    self.mod.grp,
                    "getgrnam",
                    return_value=type("Group", (), {"gr_gid": 20, "gr_mem": ["metro-agent"]})(),
                ), \
                mock.patch.object(self.mod.getpass, "getuser", return_value="metro-agent"), \
                mock.patch.object(self.mod.os, "getgroups", return_value=[4, 27]):
            message=self.mod.tinysa_permission_message("/dev/tinysa4")
        self.assertIn("로그아웃 후 로그인",message)

    def test_tinysa_catalog_and_wifi_channel_centers(self):
        self.assertEqual(tuple(self.mod.TINYSA_BAND_CATALOG), ("AP", "방송", "가전", "사용자 정의"))
        self.assertEqual(self.mod.wifi_channel_centers("wifi_2_4")[0], (1, 2_412_000_000))
        self.assertEqual(self.mod.wifi_channel_centers("wifi_2_4")[-1], (13, 2_472_000_000))
        self.assertIn((36, 5_180_000_000), self.mod.wifi_channel_centers("wifi_5"))
        self.assertIn((165, 5_825_000_000), self.mod.wifi_channel_centers("wifi_5"))
        self.assertEqual(self.mod.wifi_channel_centers("wifi_6")[0], (1, 5_955_000_000))
        self.assertEqual(self.mod.wifi_channel_centers("wifi_6")[-1], (233, 7_115_000_000))
        expectations=(
            ("wifi_2_4",2_400_000_000,2_500_000_000,10_000_000),
            ("wifi_5",5_150_000_000,5_850_000_000,100_000_000),
            ("wifi_6",5_925_000_000,7_125_000_000,200_000_000),
        )
        for axis,start,stop,step in expectations:
            ticks=self.mod.frequency_axis_ticks(start,stop,axis)
            self.assertGreaterEqual(len(ticks),6)
            self.assertTrue(all(
                ticks[index][0]-ticks[index-1][0] == step
                for index in range(1,len(ticks))
            ))
            self.assertEqual(self.mod.frequency_axis_summary(start,stop,axis)["grid_step_hz"],step)
        channels=self.mod.wifi_channel_axis_ticks(
            5_925_000_000,7_125_000_000,"wifi_6",14,
        )
        self.assertLessEqual(len(channels),14)
        self.assertTrue(all(label.startswith("CH ") for _,label in channels))

class GuiSourceTest(unittest.TestCase):
    def test_traceroute_target_is_not_used_as_mtr_wait_value(self):
        source = PATH.read_text(encoding="utf-8")
        self.assertIn('mtr -r -c 5 -w \\"$NMS_DIAG_TARGET\\"', source)
        self.assertNotIn('mtr -r -c 5 -w 2 \\"$NMS_DIAG_TARGET\\"', source)

    def test_capture_has_fixed_profiles_and_limits(self):
        helper = (PATH.parent / "nms-gui-operations.sh").read_text(encoding="utf-8")
        for profile in ("basic)", "dns)", "dhcp)", "arp)", "icmp)", "lldp)"):
            self.assertIn(profile, helper)
        self.assertIn("arp-scan-all)", helper)
        self.assertIn("arp_scan_interfaces()", helper)
        self.assertIn("no suitable broadcast-capable IPv4 interfaces found", helper)
        self.assertIn("duration >= 5 && duration <= 120", helper)
        self.assertIn("-c 5000", helper)
        self.assertIn("live-capture)", helper)
        self.assertIn("stop-live-capture)", helper)
        self.assertIn("capture stopped with SIGINT", helper)
        self.assertIn("kill -TERM", helper)
        self.assertIn("kill -KILL", helper)
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
        scanner = (PATH.parent / "nms-wireless-scan.py").read_text(encoding="utf-8")
        self.assertIn('self._new_page("무선 분석")', source)
        self.assertIn('["sudo","-n",GUI_OPS,"wireless-scan"]', source)
        self.assertIn('wireless-scan)', helper)
        self.assertIn('nms-wireless-scan.py', helper)
        self.assertIn("usb_wireless_adapters", scanner)
        self.assertIn("parse_iw_phy_bands", scanner)
        self.assertIn('"driver_missing"', scanner)
        self.assertIn('"supported_bands"', scanner)
        self.assertIn("show_wireless_ap_detail", source)
        self.assertIn("신호 %는 NetworkManager 품질값", source)
        self.assertIn("annotate_access_points", scanner)
        self.assertIn('"related_bssid"', scanner)

    def test_tinysa_zs407_monitoring_page_and_safe_config_are_present(self):
        source = PATH.read_text(encoding="utf-8")
        helper = (PATH.parent / "nms-gui-operations.sh").read_text(encoding="utf-8")
        self.assertIn('self._new_page("RF 스펙트럼")', source)
        self.assertIn('text="1회 측정"', source)
        self.assertIn('text="자동수집 설정 적용"', source)
        self.assertIn('text="자동 RF 수집"', source)
        self.assertIn('text="2.4/5/6 GHz 전체 측정"', source)
        self.assertIn('"--wifi-all"', source)
        self.assertIn('"--status"', source)
        self.assertIn('"tinySA Ultra+ ZS407"', source)
        self.assertIn('text="대분류"', source)
        self.assertIn('text="중분류"', source)
        self.assertIn('text="집계 방식"', source)
        self.assertIn('"최대값 유지 (Max Hold)"', source)
        self.assertIn('"평균 (Average)"', source)
        self.assertIn('"최소값 유지 (Min Hold)"', source)
        self.assertIn('"위성 LNB 출력 IF"', source)
        self.assertIn('text="Wi-Fi 대역"', source)
        self.assertIn('("2.4 GHz","wifi_2_4ghz")', source)
        self.assertIn('("5 GHz","wifi_5ghz")', source)
        self.assertIn('("6 GHz","wifi_6ghz")', source)
        self.assertIn("frequency_axis_summary", source)
        self.assertIn("wifi_channel_axis_ticks", source)
        self.assertIn('dash=(2,4)', source)
        self.assertIn("TINYSA_CONFIG_HELPER", source)
        self.assertIn("tinysa-config)", helper)
        self.assertIn("tinysa-status)", helper)
        self.assertIn("satellite_lnb_if|appliance_rfid_13m", helper)
        self.assertIn('|| { echo "unsupported tinySA band"', helper)
        self.assertIn("stop_hz <= 7300000000", helper)
        self.assertIn("points <= 450", helper)
        wrapper = (PATH.parent / "configure-tinysa.sh").read_text(encoding="utf-8")
        sudoers = (PATH.parent / "sudoers/metro-tinysa").read_text(encoding="utf-8")
        udev = (PATH.parent / "udev/70-metro-tinysa.rules").read_text(encoding="utf-8")
        installer = (PATH.parent / "install-collector.sh").read_text(encoding="utf-8")
        self.assertIn('exec "${GUI_OPS}" tinysa-config "$@"', wrapper)
        self.assertIn('"sudo","-n",TINYSA_CONFIG_HELPER', source)
        self.assertIn("NOPASSWD: /opt/nms-collector/configure-tinysa.sh *", sudoers)
        self.assertIn('TAG+="uaccess"', udev)
        self.assertIn('usermod -aG dialout "$GUI_USER"', installer)
        self.assertIn("udevadm control --reload-rules", installer)

    def test_collector_name_can_be_saved_from_the_status_page(self):
        source = PATH.read_text(encoding="utf-8")
        helper = (PATH.parent / "nms-gui-operations.sh").read_text(encoding="utf-8")
        collector = (PATH.parent / "nms-collector.js").read_text(encoding="utf-8")
        self.assertIn('text="수집기 이름"', source)
        self.assertIn('text="이름 저장"', source)
        self.assertIn('[GUI_OPS,"collector-name",name]', source)
        self.assertIn('collector-name)', helper)
        self.assertIn('COLLECTOR_NAME=', helper)
        self.assertIn('payload.name = collectorName', collector)

    def test_measurement_session_has_bounded_duration_interval_and_server_upload(self):
        source = PATH.read_text(encoding="utf-8")
        self.assertIn('self._new_page("측정 세션")', source)
        self.assertIn('10 <= duration <= 28800', source)
        self.assertIn('2 <= interval <= 300', source)
        self.assertIn('MEASUREMENT_SESSION = "/opt/nms-collector/nms-measurement-session.js"', source)
        self.assertIn('MEASUREMENT_CONTROL = "/opt/nms-collector/measurement-session-control.sh"', source)
        self.assertIn("if not os.path.isfile(MEASUREMENT_SESSION):", source)
        self.assertIn("동시 측정 실행 모듈이 설치되지 않았습니다.", source)
        self.assertIn('text="동시 측정 시작"', source)
        self.assertIn('text="일시 정지"', source)
        self.assertIn('text="계속"', source)
        self.assertIn('text="안전 중지"', source)
        self.assertIn('for key in ("wired","wireless","rf","packet_capture","system"):', source)
        self.assertIn('["sudo","-n",MEASUREMENT_CONTROL,"status"]', source)
        self.assertIn('"sudo","-n",MEASUREMENT_CONTROL,"start"', source)
        supervisor = (PATH.parent / "nms-measurement-session.js").read_text(encoding="utf-8")
        self.assertIn("metro-measurement-session-v1", supervisor)
        self.assertIn("orphaned_session_recovered", supervisor)
        self.assertIn("'SIGSTOP'", supervisor)
        self.assertIn("'SIGCONT'", supervisor)
        self.assertIn("'SIGTERM'", supervisor)
        self.assertIn('clock_warning=f" · 시간동기화 {ntp_state}"', source)
        collector = (PATH.parent / "nms-collector.js").read_text(encoding="utf-8")
        self.assertIn("collector-measurement-session-v1", collector)
        self.assertIn("successful_count", collector)
        self.assertIn("failed_count", collector)
        installer = (PATH.parent / "install-collector.sh").read_text(encoding="utf-8")
        self.assertIn("required runtime was not installed", installer)
        control_sudoers = (
            PATH.parent / "sudoers/metro-measurement-control"
        ).read_text(encoding="utf-8")
        self.assertIn("NOPASSWD: /opt/nms-collector/measurement-session-control.sh *", control_sudoers)
        control = (PATH.parent / "measurement-session-control.sh").read_text(encoding="utf-8")
        self.assertIn("duration >= 10 && duration <= 28800", control)
        self.assertIn("interval >= 2 && interval <= 300", control)
        self.assertIn("invalid measurement modules", control)
        self.assertIn("self.field_profile_confirmed = False", source)
        self.assertIn("def _confirm_selected_field_profile", source)
        self.assertIn("def _reset_site_measurement_view", source)
        self.assertIn("새 현장 · 테스트 안 됨", source)
        self.assertIn("이전 현장 데이터 혼입을 막기 위해", source)

    def test_gui_privileged_operations_do_not_open_authentication_dialogs(self):
        source = PATH.read_text(encoding="utf-8")
        self.assertNotIn('"pkexec"', source)
        self.assertIn('self.async_run(label,["sudo","-n",*cmd]', source)
        sudoers = (PATH.parent / "sudoers/metro-gui-operations").read_text(encoding="utf-8")
        self.assertIn(
            "NOPASSWD: /opt/nms-collector/nms-gui-operations.sh *",
            sudoers,
        )

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
        helper = (PATH.parent / "nms-gui-operations.sh").read_text(encoding="utf-8")
        installer = (PATH.parent / "install-collector.sh").read_text(encoding="utf-8")
        self.assertIn('self._new_page("실시간 모니터링")', source)
        self.assertIn('text="실시간 시작"', source)
        self.assertIn('"플러딩 분석": "flood"', source)
        self.assertIn("self.live_flood_status", source)
        self.assertIn("summarize_counts(self.live_flood_counts", source)
        self.assertIn('["sudo","-n",GUI_OPS,"arp-scan-all"]', source)
        network_scan_sudoers = (
            PATH.parent / "sudoers/metro-network-scans"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "NOPASSWD: /opt/nms-collector/nms-gui-operations.sh arp-scan-all",
            network_scan_sudoers,
        )
        self.assertIn(
            "NOPASSWD: /opt/nms-collector/nms-gui-operations.sh wireless-scan",
            network_scan_sudoers,
        )
        self.assertIn('def stop_live_capture(self):', source)
        self.assertIn('def _stop_live_capture_worker(self, process):', source)
        self.assertIn('["sudo","-n",GUI_OPS,"stop-live-capture",str(process.pid)]', source)
        self.assertIn('def _finish_close(self):', source)
        self.assertIn('"--probe"', source)
        self.assertIn('"--lock-timeout","30"', source)
        self.assertIn('self.root.after(2000,self.refresh_live_monitor)', source)
        self.assertIn("flood) printf '%s' 'ether broadcast or ether multicast or arp'", helper)
        self.assertIn('"$PACKET_FLOOD_ANALYZER" "$file"', helper)
        self.assertIn('nms_packet_flood.py" "/usr/local/bin/nms_packet_flood.py', installer)

    @unittest.skipIf(tkinter is None, "python3-tk is not installed in this environment")
    def test_measurement_result_is_readable_after_safe_stop(self):
        payload={
            "status":"partial",
            "finalize_reason":"operator_stop",
            "measurement_session_id":"934868f5-7c81-4564-8799-42410a55c9d6",
            "field_profile":{"site_name":"테스트 현장"},
            "started_at":"2026-07-24T13:36:04Z",
            "ended_at":"2026-07-24T13:37:11Z",
            "module_summary":{
                "wireless":{"status":"completed","sample_count":155},
                "wired":{"status":"running","sample_count":3},
            },
        }
        text=load_module().format_measurement_session_result(payload)
        self.assertIn("현장: 테스트 현장",text)
        self.assertIn("상태: 부분 완료",text)
        self.assertIn("무선: 완료 · 표본 155개",text)
        self.assertIn("유선: 안전 중지 · 표본 3개",text)
        self.assertIn("안전 중지 기록 보정",text)

    def test_ict_manager_assignments_are_authoritative_with_hybrid_transport(self):
        source = PATH.read_text(encoding="utf-8")
        client = (PATH.parent / "ict_field_client.py").read_text(encoding="utf-8")
        self.assertIn('text="119 새로고침"', source)
        self.assertIn("def refresh_assigned_sites(self):", source)
        self.assertIn("def sync_ict_profile(self, profile, evidence):", source)
        self.assertIn("DEFAULT_VPN_URL", client)
        self.assertIn("DEFAULT_HTTPS_URL", client)
        self.assertIn('"offline_queue"', client)

    def test_all_gui_root_operations_use_passwordless_bounded_helpers(self):
        source = PATH.read_text(encoding="utf-8")
        helper = (PATH.parent / "nms-gui-operations.sh").read_text(encoding="utf-8")
        sudoers = (PATH.parent / "sudoers/metro-gui-operations").read_text(encoding="utf-8")
        self.assertIn("NOPASSWD: /opt/nms-collector/nms-gui-operations.sh *", sudoers)
        for action in (
            "edge-analysis",
            "snapshot-session",
            "snmp",
            "service-restart",
            "offline-list",
            "offline-flush",
            "arp-scan-all",
            "wireless-scan",
            "capture",
            "live-capture",
            "vpn-import",
        ):
            self.assertIn(f"  {action})", helper)
        self.assertNotIn('self.privileged([NODE,COLLECTOR', source)
        self.assertNotIn('self.privileged([HELPER', source)
        self.assertNotIn('self.privileged(["/bin/systemctl"', source)
        self.assertNotIn("GUI_OPERATIONS", source)

if __name__ == "__main__": unittest.main()
