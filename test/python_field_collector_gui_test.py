import json
import tempfile
import unittest
from pathlib import Path

from collector.python_gui.nms_field_collector_core import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_BASE_URL,
    ApiClientError,
    IctManagerTransport,
    _extract_error_message,
    build_collector_payload,
    build_heartbeat_payload,
    clamp_interval_seconds,
    load_config,
    normalize_base_url,
    redact_mapping,
    save_config,
)
from collector.python_gui.nms_field_collector_diagnostics import (
    extract_vlan_hints,
    extract_vpn_hints,
    parse_arp_entries,
    parse_ping_rtts,
    parse_windows_default_gateway,
    summarize_diagnostics,
    summarize_rtts,
)


class FieldCollectorCoreTest(unittest.TestCase):
    def test_app_name_is_defined(self):
        self.assertEqual(APP_NAME, "METRO NMS_Collecter")

    def test_normalize_base_url_defaults_to_public_7443(self):
        self.assertEqual(normalize_base_url("112.167.190.125"), DEFAULT_BASE_URL)
        self.assertEqual(normalize_base_url("https://112.167.190.125"), DEFAULT_BASE_URL)
        self.assertEqual(normalize_base_url("https://112.167.190.125:7443/"), DEFAULT_BASE_URL)

    def test_clamp_interval_seconds(self):
        self.assertEqual(clamp_interval_seconds("1"), 15)
        self.assertEqual(clamp_interval_seconds("60"), 60)
        self.assertEqual(clamp_interval_seconds("99999"), 3600)
        self.assertEqual(clamp_interval_seconds("bad"), 60)

    def test_build_collector_payload(self):
        payload = build_collector_payload({
            "collector_name": "Dongsin field PC",
            "collector_type": "windows_agent",
            "platform": "windows",
            "status": "active",
            "customer_id": "10",
            "site_id": "",
            "device_id": "20",
            "hostname": "field-mini-pc",
            "private_ip": "192.168.10.50",
            "public_ip": "112.167.190.125",
            "purpose": "field diagnosis",
            "capabilities": "heartbeat,diagnostics",
            "notes": "portable",
        })

        self.assertEqual(payload["name"], "Dongsin field PC")
        self.assertEqual(payload["collector_type"], "windows_agent")
        self.assertEqual(payload["platform"], "windows")
        self.assertEqual(payload["customer_id"], 10)
        self.assertEqual(payload["device_id"], 20)
        self.assertEqual(payload["private_ip"], "192.168.10.50")
        self.assertEqual(payload["public_ip"], "112.167.190.125")
        self.assertEqual(payload["software_version"], APP_VERSION)
        self.assertEqual(payload["metadata"]["capabilities"], ["heartbeat", "diagnostics"])

    def test_build_heartbeat_payload(self):
        payload = build_heartbeat_payload({
            "status": "active",
            "hostname": "field-mini-pc",
            "private_ip": "192.168.10.50",
            "purpose": "field diagnosis",
            "capabilities": "heartbeat",
        })

        self.assertEqual(payload["status"], "active")
        self.assertEqual(payload["hostname"], "field-mini-pc")
        self.assertEqual(payload["private_ip"], "192.168.10.50")
        self.assertIn("last_seen_at", payload)
        self.assertEqual(payload["metadata"]["collector_gui"], "python")

    def test_save_config_omits_password_and_optionally_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            save_config(path, {
                "base_url": DEFAULT_BASE_URL,
                "admin_password": "do-not-store",
                "collector_token": "secret-token",
            }, include_token=False)
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn("admin_password", saved)
            self.assertNotIn("collector_token", saved)

            save_config(path, {
                "base_url": DEFAULT_BASE_URL,
                "admin_password": "do-not-store",
                "collector_token": "secret-token",
            }, include_token=True)
            loaded = load_config(path)
            self.assertNotIn("admin_password", loaded)
            self.assertEqual(loaded["collector_token"], "secret-token")

    def test_redact_mapping_masks_secrets(self):
        self.assertEqual(redact_mapping({
            "collector_token": "secret-token",
            "nested": {"api_key": "key"},
            "name": "collector",
        }), {
            "collector_token": "***",
            "nested": {"api_key": "***"},
            "name": "collector",
        })

    def test_extract_error_message_prefers_detail_for_generic_http_errors(self):
        self.assertEqual(
            _extract_error_message('{"error":"Unauthorized","detail":"Invalid username or password"}'),
            "Invalid username or password",
        )
        self.assertEqual(
            _extract_error_message('{"error":"Bad request","detail":"collector name is required"}'),
            "collector name is required",
        )

    def test_diagnostics_parse_ping_and_jitter(self):
        rtts = parse_ping_rtts("""
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64
Reply from 192.168.1.1: bytes=32 time=4ms TTL=64
Reply from 192.168.1.1: bytes=32 time=7ms TTL=64
""")
        self.assertEqual(rtts, [1.0, 4.0, 7.0])
        summary = summarize_rtts(rtts, 4)
        self.assertEqual(summary["received"], 3)
        self.assertEqual(summary["loss_pct"], 25.0)
        self.assertEqual(summary["range_jitter_ms"], 6.0)

    def test_diagnostics_parse_gateway_arp_vlan_vpn(self):
        self.assertEqual(
            parse_windows_default_gateway("0.0.0.0          0.0.0.0    192.168.1.1  192.168.1.192     25"),
            "192.168.1.1",
        )
        arp = parse_arp_entries("192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic")
        self.assertEqual(arp[0]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(extract_vlan_hints("Priority & VLAN Enabled\nVLAN ID 10"), ["Priority & VLAN Enabled", "VLAN ID 10"])
        self.assertEqual(extract_vpn_hints("FortiClient VPN connected")[0], "FortiClient VPN connected")

    def test_diagnostics_summary_shape(self):
        summary = summarize_diagnostics({
            "collected_at": "2026-06-29T08:00:00Z",
            "targets": {
                "gateway": "192.168.1.1",
                "dns": "168.126.63.1",
            },
            "ip_info": {
                "gateway_neighbor": {
                    "mac": "aa:bb:cc:dd:ee:ff",
                },
            },
            "ping": {
                "gateway": {"summary": {"avg_ms": 1.2}},
                "dns": {"summary": {"avg_ms": 5.4}},
            },
            "arp_info": {"entry_count": 3},
            "vlan_info": {"hints": ["VLAN ID 10"]},
            "vpn_info": {"hints": ["VPN connected"]},
            "lldp_cdp_info": {"hints": ["System Name: switch-1"]},
            "packet_info": {"status": "captured", "tooling": {"tshark": "/usr/bin/tshark"}},
        })
        self.assertEqual(summary["default_gateway"], "192.168.1.1")
        self.assertEqual(summary["gateway_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(summary["vlan_hint_count"], 1)
        self.assertEqual(summary["packet_tool"], "tshark")

    def test_ict_transport_prefers_vpn_and_falls_back_to_https(self):
        calls = []

        class FakeClient:
            def __init__(self, base_url, **_kwargs):
                self.base_url = base_url

            def request_json(self, method, path, payload=None, headers=None):
                calls.append((self.base_url, method, path, payload, headers))
                if self.base_url.startswith("http://192.168.1.119"):
                    raise ApiClientError("vpn unavailable")
                return {"sites": [{"site_id": 11}]}

        with tempfile.TemporaryDirectory() as tmp:
            client = IctManagerTransport(
                device_token="x" * 32,
                queue_path=Path(tmp) / "queue.json",
                client_factory=FakeClient,
            )
            result = client.assigned_sites()

        self.assertEqual(result["transport_mode"], "https_fallback")
        self.assertEqual(result["data"]["sites"][0]["site_id"], 11)
        self.assertEqual(calls[0][2], "/api/field-client/sites")
        self.assertEqual(calls[1][2], "/api/ict-field/sites")

    def test_ict_transport_queues_session_and_profile_then_retries_in_order(self):
        state = {"online": False, "paths": []}

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def request_json(self, _method, path, payload=None, headers=None):
                state["paths"].append(path)
                if not state["online"]:
                    raise ApiClientError("offline")
                return {"ok": True, "session_id": (payload or {}).get("session_id")}

        with tempfile.TemporaryDirectory() as tmp:
            client = IctManagerTransport(
                device_token="x" * 32,
                queue_path=Path(tmp) / "queue.json",
                client_factory=FakeClient,
            )
            session = client.start_session(11)
            upload = client.upload_profile(session["session_id"], 11, {"vlan": {"status": "not_tested"}})
            self.assertTrue(session["queued"])
            self.assertTrue(upload["queued"])
            self.assertEqual(client.queue_size(), 2)

            state["online"] = True
            retried = client.retry_queue()

        self.assertEqual(retried["sent"], 2)
        self.assertEqual(retried["remaining"], 0)
        successful_paths = [path for path in state["paths"] if path.startswith("/api/field-client")]
        self.assertEqual(successful_paths[-2:], [
            "/api/field-client/sessions",
            "/api/field-client/profile-snapshots",
        ])


if __name__ == "__main__":
    unittest.main()
