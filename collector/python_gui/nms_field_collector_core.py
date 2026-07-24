"""Core helpers for the METRO NMS_Collecter GUI."""

from __future__ import annotations

import json
import os
import platform
import re
import socket
import ssl
import time
import uuid
from dataclasses import dataclass
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib import error, parse, request


APP_NAME = "METRO NMS_Collecter"
APP_VERSION = "python-gui-0.2.0"
DEFAULT_BASE_URL = "https://112.167.190.125:7443"
DEFAULT_ICT_VPN_URL = "http://192.168.1.119:8660"
DEFAULT_ICT_HTTPS_URL = DEFAULT_BASE_URL
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_INTERVAL_SECONDS = 60
MIN_INTERVAL_SECONDS = 15
MAX_INTERVAL_SECONDS = 3600

ALLOWED_COLLECTOR_TYPES = ("windows_agent", "ubuntu_agent", "linux_agent", "hybrid", "syslog_gateway", "snmp_proxy")
SERVER_COLLECTOR_TYPES = ("windows_agent", "ubuntu_agent", "hybrid", "syslog_gateway", "snmp_proxy")
ALLOWED_PLATFORMS = ("windows", "ubuntu", "linux", "container", "other")
ALLOWED_STATUSES = ("planned", "active", "inactive", "error", "retired")
SECRET_KEYS = ("password", "token", "secret", "api_key", "authorization", "cookie")


class ApiClientError(RuntimeError):
    """Raised when the NMS API returns an error or cannot be reached."""

    def __init__(self, message: str, status_code: int | None = None, response_body: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


def normalize_base_url(value: str | None) -> str:
    raw = (value or DEFAULT_BASE_URL).strip()
    if not raw:
        raw = DEFAULT_BASE_URL

    if "://" not in raw:
        raw = f"https://{raw}"

    parts = parse.urlsplit(raw)
    scheme = parts.scheme or "https"
    netloc = parts.netloc or parts.path
    path = parts.path if parts.netloc else ""

    if not netloc:
        return DEFAULT_BASE_URL

    host_part = netloc.rsplit("@", 1)[-1]
    has_explicit_port = bool(re.search(r":\d+$", host_part)) or (host_part.startswith("[") and "]:" in host_part)
    if not has_explicit_port and scheme in {"http", "https"}:
        netloc = f"{netloc}:7443"

    normalized_path = f"/{path.strip('/')}" if path and path.strip("/") else ""
    return parse.urlunsplit((scheme, netloc, normalized_path, "", "")).rstrip("/")


def clamp_interval_seconds(value: Any) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_SECONDS

    return max(MIN_INTERVAL_SECONDS, min(MAX_INTERVAL_SECONDS, parsed))


def normalize_optional_int(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = int(text)
    except ValueError:
        raise ValueError(f"positive integer expected: {text}") from None
    if parsed <= 0:
        raise ValueError(f"positive integer expected: {text}")
    return parsed


def normalize_optional_ip(value: str | None, field_name: str) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        socket.inet_pton(socket.AF_INET, text)
        return text
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, text)
        return text
    except OSError:
        raise ValueError(f"{field_name} is not a valid IP address: {text}") from None


def split_csv(value: str | None) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def detect_private_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 80))
            return sock.getsockname()[0]
    except OSError:
        return ""


def default_hostname() -> str:
    return socket.gethostname() or platform.node() or "field-collector"


def default_platform() -> str:
    name = platform.system().lower()
    if name.startswith("win"):
        return "windows"
    if name == "linux":
        return "linux"
    return "other"


def default_collector_type(platform_name: str | None = None) -> str:
    current = (platform_name or default_platform()).lower()
    if current == "windows":
        return "windows_agent"
    if current in {"ubuntu", "linux"}:
        return "ubuntu_agent"
    return "hybrid"


def build_collector_payload(settings: Mapping[str, Any]) -> dict[str, Any]:
    name = str(settings.get("collector_name") or "").strip()
    collector_type = str(settings.get("collector_type") or default_collector_type(settings.get("platform"))).strip()
    platform_name = str(settings.get("platform") or default_platform()).strip()
    status = str(settings.get("status") or "active").strip()

    if not name:
        raise ValueError("collector name is required")
    if collector_type not in SERVER_COLLECTOR_TYPES:
        raise ValueError(f"collector_type must be one of: {', '.join(SERVER_COLLECTOR_TYPES)}")
    if platform_name not in ALLOWED_PLATFORMS:
        raise ValueError(f"platform must be one of: {', '.join(ALLOWED_PLATFORMS)}")
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"status must be one of: {', '.join(ALLOWED_STATUSES)}")

    payload: dict[str, Any] = {
        "name": name,
        "collector_type": collector_type,
        "platform": platform_name,
        "status": status,
        "hostname": str(settings.get("hostname") or default_hostname()).strip(),
        "software_version": APP_VERSION,
        "metadata": build_metadata(settings),
    }

    for source_key, target_key in (
        ("customer_id", "customer_id"),
        ("site_id", "site_id"),
        ("device_id", "device_id"),
    ):
        parsed = normalize_optional_int(settings.get(source_key))
        if parsed is not None:
            payload[target_key] = parsed

    private_ip = normalize_optional_ip(settings.get("private_ip"), "private_ip")
    public_ip = normalize_optional_ip(settings.get("public_ip"), "public_ip")
    if private_ip:
        payload["private_ip"] = private_ip
    if public_ip:
        payload["public_ip"] = public_ip

    return payload


def build_heartbeat_payload(settings: Mapping[str, Any]) -> dict[str, Any]:
    status = str(settings.get("status") or "active").strip()
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"status must be one of: {', '.join(ALLOWED_STATUSES)}")

    payload: dict[str, Any] = {
        "status": status,
        "hostname": str(settings.get("hostname") or default_hostname()).strip(),
        "software_version": APP_VERSION,
        "last_seen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "metadata": build_metadata(settings),
    }

    private_ip = normalize_optional_ip(settings.get("private_ip"), "private_ip")
    public_ip = normalize_optional_ip(settings.get("public_ip"), "public_ip")
    if private_ip:
        payload["private_ip"] = private_ip
    if public_ip:
        payload["public_ip"] = public_ip

    return payload


def build_metadata(settings: Mapping[str, Any]) -> dict[str, Any]:
    capabilities = split_csv(settings.get("capabilities")) or ["heartbeat"]
    metadata = {
        "collector_gui": "python",
        "app_version": APP_VERSION,
        "os": platform.platform(),
        "machine": platform.machine(),
        "purpose": str(settings.get("purpose") or "field collector").strip(),
        "capabilities": capabilities,
    }
    notes = str(settings.get("notes") or "").strip()
    if notes:
        metadata["notes"] = notes
    return metadata


def get_default_config_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        return base / "MetroNMSFieldCollector" / "config.json"
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "metro-nms-field-collector" / "config.json"


def get_default_queue_path() -> Path:
    return get_default_config_path().with_name("ict-offline-queue.json")


def save_config(path: str | os.PathLike[str], settings: Mapping[str, Any], include_token: bool = False) -> Path:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)

    serializable = dict(settings)
    serializable.pop("admin_password", None)
    if not include_token:
        serializable.pop("collector_token", None)
        serializable.pop("ict_device_token", None)
    target.write_text(json.dumps(serializable, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return target


def load_config(path: str | os.PathLike[str]) -> dict[str, Any]:
    source = Path(path).expanduser()
    return json.loads(source.read_text(encoding="utf-8"))


def redact_mapping(values: Mapping[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in values.items():
        normalized_key = key.lower()
        if any(secret in normalized_key for secret in SECRET_KEYS):
            redacted[key] = "***" if value else ""
        elif isinstance(value, Mapping):
            redacted[key] = redact_mapping(value)
        else:
            redacted[key] = value
    return redacted


@dataclass
class ApiClient:
    base_url: str = DEFAULT_BASE_URL
    verify_tls: bool = True
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    opener_factory: Callable[..., request.OpenerDirector] | None = None

    def __post_init__(self) -> None:
        self.base_url = normalize_base_url(self.base_url)
        self.cookie_jar = CookieJar()
        handlers: list[Any] = [request.HTTPCookieProcessor(self.cookie_jar)]
        if self.base_url.startswith("https://"):
            context = ssl.create_default_context() if self.verify_tls else ssl._create_unverified_context()
            handlers.append(request.HTTPSHandler(context=context))
        factory = self.opener_factory or request.build_opener
        self.opener = factory(*handlers)

    def request_json(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        data = None
        request_headers = {
            "Accept": "application/json",
            "User-Agent": f"{APP_NAME}/{APP_VERSION}",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            request_headers["Content-Type"] = "application/json; charset=utf-8"
        if headers:
            request_headers.update(headers)

        req = request.Request(url, data=data, headers=request_headers, method=method.upper())
        try:
            with self.opener.open(req, timeout=self.timeout_seconds) as response:
                body = response.read().decode("utf-8", errors="replace")
                if not body.strip():
                    return {}
                return json.loads(body)
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            message = _extract_error_message(body) or f"HTTP {exc.code}"
            raise ApiClientError(message, exc.code, body) from exc
        except error.URLError as exc:
            raise ApiClientError(f"NMS connection failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise ApiClientError("NMS connection timed out") from exc
        except json.JSONDecodeError as exc:
            raise ApiClientError(f"NMS returned non-JSON response: {exc}") from exc

    def health(self) -> Any:
        return self.request_json("GET", "/health")

    def login(self, username: str, password: str) -> Any:
        return self.request_json("POST", "/api/auth/login", {
            "username": username.strip(),
            "password": password,
        })

    def me(self) -> Any:
        return self.request_json("GET", "/api/auth/me")

    def create_collector(self, payload: Mapping[str, Any]) -> Any:
        return self.request_json("POST", "/api/collectors", payload)

    def heartbeat(self, collector_id: int | str, collector_token: str, payload: Mapping[str, Any]) -> Any:
        collector_id_text = str(collector_id).strip()
        if not collector_id_text.isdigit() or int(collector_id_text) <= 0:
            raise ValueError("collector_id must be a positive integer")
        token = str(collector_token or "").strip()
        if not token:
            raise ValueError("collector token is required")
        return self.request_json(
            "POST",
            f"/api/collectors/{collector_id_text}/heartbeat",
            payload,
            headers={"X-Collector-Token": token},
        )


@dataclass
class IctManagerTransport:
    vpn_base_url: str = DEFAULT_ICT_VPN_URL
    https_base_url: str = DEFAULT_ICT_HTTPS_URL
    device_token: str = ""
    verify_tls: bool = True
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    queue_path: str | os.PathLike[str] | None = None
    client_factory: Callable[..., ApiClient] = ApiClient

    def __post_init__(self) -> None:
        self.vpn_base_url = normalize_base_url(self.vpn_base_url)
        self.https_base_url = normalize_base_url(self.https_base_url)
        self.queue_path = Path(self.queue_path or get_default_queue_path()).expanduser()

    def _headers(self, mode: str) -> dict[str, str]:
        token = str(self.device_token or "").strip()
        if len(token) < 20:
            raise ValueError("ICT Manager device token is required")
        return {
            "X-Ict-Device-Token": token,
            "X-Ict-Transport-Mode": mode,
        }

    def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> tuple[Any, str]:
        normalized_path = path if path.startswith("/") else f"/{path}"
        attempts = (
            ("vpn", self.vpn_base_url, f"/api/field-client{normalized_path}"),
            ("https_fallback", self.https_base_url, f"/api/ict-field{normalized_path}"),
        )
        errors: list[str] = []
        for mode, base_url, endpoint in attempts:
            client = self.client_factory(
                base_url=base_url,
                verify_tls=self.verify_tls,
                timeout_seconds=self.timeout_seconds,
            )
            try:
                return client.request_json(method, endpoint, payload, self._headers(mode)), mode
            except ApiClientError as exc:
                errors.append(f"{mode}: {exc}")
                if exc.status_code is not None and exc.status_code < 500:
                    raise
        raise ApiClientError("ICT Manager connection failed: " + " / ".join(errors))

    def _cache_path(self) -> Path:
        return Path(self.queue_path).with_name("ict-sites-cache.json")

    @staticmethod
    def _write_json_atomic(path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)

    def assigned_sites(self) -> dict[str, Any]:
        try:
            payload, mode = self._request("GET", "/sites")
        except ApiClientError:
            cache_path = self._cache_path()
            if not cache_path.is_file():
                raise
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            return {"data": cached, "transport_mode": "cached", "stale": True}
        self._write_json_atomic(self._cache_path(), payload)
        return {"data": payload, "transport_mode": mode, "stale": False}

    def latest_site_profile(self, site_id: int) -> dict[str, Any]:
        payload, mode = self._request("GET", f"/sites/{int(site_id)}/profile")
        return {"data": payload, "transport_mode": mode}

    def _load_queue(self) -> list[dict[str, Any]]:
        path = Path(self.queue_path)
        if not path.is_file():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return payload if isinstance(payload, list) else []

    def _save_queue(self, entries: list[dict[str, Any]]) -> None:
        self._write_json_atomic(Path(self.queue_path), entries)

    def queue_size(self) -> int:
        return len(self._load_queue())

    def _enqueue(
        self,
        operation: str,
        path: str,
        payload: Mapping[str, Any],
        coalesce: bool = False,
    ) -> dict[str, Any]:
        entries = self._load_queue()
        if coalesce:
            entries = [entry for entry in entries if entry.get("operation") != operation]
        entry = {
            "queue_id": str(uuid.uuid4()),
            "operation": operation,
            "method": "POST",
            "path": path,
            "payload": dict(payload),
            "queued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "attempts": 0,
        }
        entries.append(entry)
        self._save_queue(entries)
        return entry

    def start_session(
        self,
        site_id: int,
        metadata: Mapping[str, Any] | None = None,
        client_started_at: str | None = None,
    ) -> dict[str, Any]:
        session_id = str(uuid.uuid4())
        payload = {
            "session_id": session_id,
            "site_id": int(site_id),
            "client_started_at": client_started_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "transport_mode": "automatic",
            "metadata": dict(metadata or {}),
        }
        try:
            response, mode = self._request("POST", "/sessions", payload)
            return {"data": response, "session_id": session_id, "transport_mode": mode, "queued": False}
        except ApiClientError as exc:
            if exc.status_code is not None and exc.status_code < 500:
                raise
            self._enqueue("session", "/sessions", payload)
            return {"data": None, "session_id": session_id, "transport_mode": "offline_queue", "queued": True}

    def upload_profile(
        self,
        session_id: str,
        site_id: int,
        profile: Mapping[str, Any],
        source_collected_at: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "session_id": session_id,
            "site_id": int(site_id),
            "schema_version": "ict-field-profile-v1",
            "profile": dict(profile),
            "source_collected_at": source_collected_at,
            "transport_mode": "automatic",
            "idempotency_key": str(uuid.uuid4()),
        }
        try:
            response, mode = self._request("POST", "/profile-snapshots", payload)
            return {"data": response, "transport_mode": mode, "queued": False}
        except ApiClientError as exc:
            if exc.status_code is not None and exc.status_code < 500:
                raise
            payload["queued_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._enqueue("profile_snapshot", "/profile-snapshots", payload)
            return {"data": None, "transport_mode": "offline_queue", "queued": True}

    def heartbeat(self, site_id: int | None, metadata: Mapping[str, Any] | None = None) -> dict[str, Any]:
        payload = {
            "site_id": int(site_id) if site_id else None,
            "transport_mode": "automatic",
            "metadata": dict(metadata or {}),
        }
        try:
            response, mode = self._request("POST", "/heartbeat", payload)
            return {"data": response, "transport_mode": mode, "queued": False}
        except ApiClientError as exc:
            if exc.status_code is not None and exc.status_code < 500:
                raise
            self._enqueue("heartbeat", "/heartbeat", payload, coalesce=True)
            return {"data": None, "transport_mode": "offline_queue", "queued": True}

    def retry_queue(self) -> dict[str, Any]:
        entries = self._load_queue()
        remaining: list[dict[str, Any]] = []
        sent = 0
        last_mode = "none"
        for index, entry in enumerate(entries):
            try:
                _, last_mode = self._request(
                    str(entry.get("method") or "POST"),
                    str(entry.get("path") or ""),
                    entry.get("payload") or {},
                )
            except (ApiClientError, ValueError) as exc:
                entry["attempts"] = int(entry.get("attempts") or 0) + 1
                entry["last_error"] = str(exc)[:300]
                remaining.extend([entry, *entries[index + 1:]])
                break
            else:
                sent += 1
        self._save_queue(remaining)
        return {
            "sent": sent,
            "remaining": len(remaining),
            "transport_mode": last_mode,
        }


def _extract_error_message(body: str) -> str:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return body.strip()[:240]
    if isinstance(payload, dict):
        error_value = payload.get("error")
        detail_value = payload.get("detail")
        message_value = payload.get("message")
        if isinstance(detail_value, str) and detail_value.strip():
            if error_value in {"Unauthorized", "Forbidden", "Bad request", "Internal server error"}:
                return detail_value
        for value in (error_value, detail_value, message_value):
            if isinstance(value, str) and value.strip():
                return value
    return body.strip()[:240]
