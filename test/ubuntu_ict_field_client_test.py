import tempfile
import unittest
from pathlib import Path

from collector.ubuntu.ict_field_client import IctFieldClient, IctFieldClientError


class FakeIctFieldClient(IctFieldClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.online = False
        self.calls = []

    def _request_once(self, base_url, prefix, mode, method, path, payload=None):
        self.calls.append((mode, method, path, payload))
        if not self.online:
            raise IctFieldClientError(f"{mode} unavailable")
        return {"ok": True, "sites": [{"site_id": 11}]}


class UbuntuIctFieldClientTest(unittest.TestCase):
    def build_client(self, root):
        return FakeIctFieldClient(
            {
                "device_token": "x" * 32,
                "vpn_url": "http://192.168.1.119:8660",
                "https_url": "https://112.167.190.125:7443",
            },
            Path(root) / "queue.json",
            Path(root) / "sites.json",
        )

    def test_vpn_is_attempted_before_https_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            client = self.build_client(root)
            client.online = True
            _, mode = client.request("GET", "/sites")
            self.assertEqual(mode, "vpn")
            self.assertEqual(client.calls[0][:3], ("vpn", "GET", "/sites"))

    def test_offline_profile_is_queued_and_retried_in_dependency_order(self):
        with tempfile.TemporaryDirectory() as root:
            client = self.build_client(root)
            result = client.store_profile(11, {"vlan": {"status": "not_tested"}})
            self.assertTrue(result["queued"])
            self.assertEqual(client.queue_size(), 2)

            client.online = True
            retried = client.retry_queue()
            self.assertEqual(retried["sent"], 2)
            self.assertEqual(retried["remaining"], 0)
            successful = [call[2] for call in client.calls if call[0] == "vpn" and client.online]
            self.assertEqual(successful[-2:], ["/sessions", "/profile-snapshots"])


if __name__ == "__main__":
    unittest.main()
