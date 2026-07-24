"""119 ICT Manager field-client transport with VPN preference and offline queue."""

from __future__ import annotations

import json
import ssl
import time
import uuid
from pathlib import Path
from urllib import error, request

DEFAULT_VPN_URL = "http://192.168.1.119:8660"
DEFAULT_HTTPS_URL = "https://112.167.190.125:7443"


class IctFieldClientError(RuntimeError):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def _atomic_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def load_device_config(path):
    source = Path(path)
    if not source.is_file():
        return {}
    payload = json.loads(source.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


class IctFieldClient:
    def __init__(self, config, queue_path, cache_path, timeout=8):
        self.vpn_url = str(config.get("vpn_url") or DEFAULT_VPN_URL).rstrip("/")
        self.https_url = str(config.get("https_url") or DEFAULT_HTTPS_URL).rstrip("/")
        self.device_token = str(config.get("device_token") or "").strip()
        self.verify_tls = bool(config.get("verify_tls", True))
        self.queue_path = Path(queue_path)
        self.cache_path = Path(cache_path)
        self.timeout = timeout

    def _request_once(self, base_url, prefix, mode, method, path, payload=None):
        if len(self.device_token) < 20:
            raise IctFieldClientError("119 장치 토큰이 설정되지 않았습니다.", 401)
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "User-Agent": "METRO-NMS-Collecter/ubuntu",
            "X-Ict-Device-Token": self.device_token,
            "X-Ict-Transport-Mode": mode,
        }
        if data is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
        req = request.Request(
            f"{base_url}{prefix}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        context = None
        if base_url.startswith("https://") and not self.verify_tls:
            context = ssl._create_unverified_context()
        try:
            with request.urlopen(req, timeout=self.timeout, context=context) as response:
                body = response.read().decode("utf-8", errors="replace")
                return json.loads(body) if body.strip() else {}
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                message = json.loads(body).get("detail") or json.loads(body).get("error")
            except (ValueError, json.JSONDecodeError):
                message = body[:240]
            raise IctFieldClientError(message or f"HTTP {exc.code}", exc.code) from exc
        except (error.URLError, TimeoutError, OSError) as exc:
            raise IctFieldClientError(str(exc)) from exc

    def request(self, method, path, payload=None):
        errors = []
        for mode, base_url, prefix in (
            ("vpn", self.vpn_url, "/api/field-client"),
            ("https_fallback", self.https_url, "/api/ict-field"),
        ):
            try:
                return self._request_once(base_url, prefix, mode, method, path, payload), mode
            except IctFieldClientError as exc:
                errors.append(f"{mode}: {exc}")
                if exc.status_code is not None and exc.status_code < 500:
                    raise
        raise IctFieldClientError(" / ".join(errors))

    def assigned_sites(self):
        try:
            payload, mode = self.request("GET", "/sites")
        except IctFieldClientError:
            if not self.cache_path.is_file():
                raise
            return json.loads(self.cache_path.read_text(encoding="utf-8")), "cached"
        _atomic_json(self.cache_path, payload)
        return payload, mode

    def _load_queue(self):
        if not self.queue_path.is_file():
            return []
        try:
            payload = json.loads(self.queue_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return []
        return payload if isinstance(payload, list) else []

    def _save_queue(self, entries):
        _atomic_json(self.queue_path, entries)

    def queue_size(self):
        return len(self._load_queue())

    def _enqueue(self, operation, path, payload):
        entries = self._load_queue()
        entries.append({
            "queue_id": str(uuid.uuid4()),
            "operation": operation,
            "path": path,
            "payload": payload,
            "queued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "attempts": 0,
        })
        self._save_queue(entries)

    def store_profile(self, site_id, profile, source_collected_at=None):
        session_id = str(uuid.uuid4())
        session = {
            "session_id": session_id,
            "site_id": int(site_id),
            "client_started_at": source_collected_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "transport_mode": "automatic",
            "metadata": {"client": "130-ubuntu-field-diagnostics"},
        }
        snapshot = {
            "session_id": session_id,
            "site_id": int(site_id),
            "schema_version": "ict-field-profile-v1",
            "profile": profile,
            "source_collected_at": source_collected_at,
            "transport_mode": "automatic",
            "idempotency_key": str(uuid.uuid4()),
        }
        try:
            _, session_mode = self.request("POST", "/sessions", session)
            response, mode = self.request("POST", "/profile-snapshots", snapshot)
            return {"queued": False, "transport_mode": mode or session_mode, "response": response}
        except IctFieldClientError as exc:
            if exc.status_code is not None and exc.status_code < 500:
                raise
            snapshot["queued_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._enqueue("session", "/sessions", session)
            self._enqueue("profile_snapshot", "/profile-snapshots", snapshot)
            return {"queued": True, "transport_mode": "offline_queue"}

    def retry_queue(self):
        entries = self._load_queue()
        remaining = []
        sent = 0
        mode = "none"
        for index, entry in enumerate(entries):
            try:
                _, mode = self.request("POST", entry["path"], entry["payload"])
            except IctFieldClientError as exc:
                entry["attempts"] = int(entry.get("attempts") or 0) + 1
                entry["last_error"] = str(exc)[:300]
                remaining.extend([entry, *entries[index + 1:]])
                break
            sent += 1
        self._save_queue(remaining)
        return {"sent": sent, "remaining": len(remaining), "transport_mode": mode}
