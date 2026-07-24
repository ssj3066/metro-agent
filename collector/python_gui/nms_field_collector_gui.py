"""Tkinter GUI for registering and running METRO NMS_Collecter."""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

from nms_field_collector_core import (
    ALLOWED_PLATFORMS,
    ALLOWED_STATUSES,
    DEFAULT_BASE_URL,
    DEFAULT_INTERVAL_SECONDS,
    DEFAULT_ICT_HTTPS_URL,
    DEFAULT_ICT_VPN_URL,
    APP_NAME,
    APP_VERSION,
    ApiClient,
    IctManagerTransport,
    build_collector_payload,
    build_heartbeat_payload,
    clamp_interval_seconds,
    default_collector_type,
    default_hostname,
    default_platform,
    detect_private_ip,
    get_default_config_path,
    get_default_queue_path,
    load_config,
    normalize_base_url,
    save_config,
)
from nms_field_collector_diagnostics import (
    DEFAULT_DNS_TARGET,
    DEFAULT_PACKET_DURATION_SECONDS,
    DEFAULT_PACKET_MAX_FRAMES,
    collect_network_diagnostics,
    write_diagnostics_report,
)


SERVER_COLLECTOR_TYPES = ("windows_agent", "ubuntu_agent", "hybrid", "syslog_gateway", "snmp_proxy")


class FieldCollectorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("980x720")
        self.minsize(900, 640)
        self.message_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.periodic_stop = threading.Event()
        self.periodic_thread: threading.Thread | None = None
        self.latest_diagnostics: dict[str, Any] | None = None
        self.field_session_id: str | None = None
        self.assigned_sites_by_label: dict[str, dict[str, Any]] = {}
        self.busy_count = 0

        self.vars: dict[str, tk.Variable] = {}
        self._create_variables()
        self._build_ui()
        self._poll_queue()

    def _create_variables(self) -> None:
        platform_name = default_platform()
        self.vars = {
            "base_url": tk.StringVar(value=DEFAULT_BASE_URL),
            "ict_vpn_url": tk.StringVar(value=DEFAULT_ICT_VPN_URL),
            "ict_https_url": tk.StringVar(value=DEFAULT_ICT_HTTPS_URL),
            "ict_device_token": tk.StringVar(value=""),
            "ict_queue_path": tk.StringVar(value=str(get_default_queue_path())),
            "ict_site_label": tk.StringVar(value=""),
            "ict_transport_status": tk.StringVar(value="연결 확인 전"),
            "allow_insecure_tls": tk.BooleanVar(value=True),
            "admin_username": tk.StringVar(value=""),
            "admin_password": tk.StringVar(value=""),
            "collector_name": tk.StringVar(value=f"{default_hostname()} METRO NMS_Collecter"),
            "collector_type": tk.StringVar(value=default_collector_type(platform_name)),
            "platform": tk.StringVar(value=platform_name if platform_name in ALLOWED_PLATFORMS else "other"),
            "status": tk.StringVar(value="active"),
            "customer_id": tk.StringVar(value=""),
            "site_id": tk.StringVar(value=""),
            "device_id": tk.StringVar(value=""),
            "collector_id": tk.StringVar(value=""),
            "collector_token": tk.StringVar(value=""),
            "hostname": tk.StringVar(value=default_hostname()),
            "private_ip": tk.StringVar(value=detect_private_ip()),
            "public_ip": tk.StringVar(value=""),
            "purpose": tk.StringVar(value="external field collector"),
            "capabilities": tk.StringVar(value="heartbeat,diagnostics,ping,arp,vlan,vpn,lldp-cdp,packet"),
            "notes": tk.StringVar(value=""),
            "interval_seconds": tk.StringVar(value=str(DEFAULT_INTERVAL_SECONDS)),
            "diagnostics_gateway_target": tk.StringVar(value=""),
            "diagnostics_dns_target": tk.StringVar(value=DEFAULT_DNS_TARGET),
            "diagnostics_ping_count": tk.StringVar(value="6"),
            "diagnostics_packet_enabled": tk.BooleanVar(value=True),
            "diagnostics_packet_interface": tk.StringVar(value="1"),
            "diagnostics_packet_duration": tk.StringVar(value=str(DEFAULT_PACKET_DURATION_SECONDS)),
            "diagnostics_packet_max_frames": tk.StringVar(value=str(DEFAULT_PACKET_MAX_FRAMES)),
            "include_diagnostics_in_heartbeat": tk.BooleanVar(value=True),
            "diagnostics_output_path": tk.StringVar(value=str(get_default_config_path().with_name("diagnostics-last.json"))),
            "save_token": tk.BooleanVar(value=False),
            "show_token": tk.BooleanVar(value=False),
            "config_path": tk.StringVar(value=str(get_default_config_path())),
        }

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        root = ttk.Frame(self, padding=14)
        root.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        notebook = ttk.Notebook(root)
        notebook.grid(row=0, column=0, sticky="nsew")

        self._build_connection_tab(notebook)
        self._build_collector_tab(notebook)
        self._build_site_profile_tab(notebook)
        self._build_runtime_tab(notebook)
        self._build_diagnostics_tab(notebook)
        self._build_config_tab(notebook)

        log_frame = ttk.LabelFrame(root, text="작업 로그", padding=8)
        log_frame.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log_text = tk.Text(log_frame, height=9, wrap="word", state="disabled")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)

        status_bar = ttk.Frame(root)
        status_bar.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        status_bar.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="준비")
        ttk.Label(status_bar, textvariable=self.status_var).grid(row=0, column=0, sticky="w")

        self.log(f"기본 NMS 주소: {DEFAULT_BASE_URL}")

    def _build_connection_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=16)
        notebook.add(frame, text="연결")
        for column in range(3):
            frame.columnconfigure(column, weight=1 if column == 1 else 0)

        self._add_entry(frame, 0, "NMS 주소", "base_url", width=52)
        ttk.Button(frame, text="연결 테스트", command=self.test_connection).grid(row=0, column=2, padx=(8, 0), sticky="ew")
        ttk.Checkbutton(
            frame,
            text="자가서명 인증서 허용",
            variable=self.vars["allow_insecure_tls"],
        ).grid(row=1, column=1, sticky="w", pady=(4, 12))

        ttk.Separator(frame).grid(row=2, column=0, columnspan=3, sticky="ew", pady=10)
        ttk.Label(frame, text="토큰 자동 발급용 관리자 로그인").grid(row=3, column=0, columnspan=3, sticky="w")
        self._add_entry(frame, 4, "관리자 ID", "admin_username")
        self._add_entry(frame, 5, "비밀번호", "admin_password", show="*")
        ttk.Button(frame, text="로그인 후 토큰 발급", command=self.issue_token).grid(row=6, column=1, sticky="e", pady=(10, 0))

    def _build_collector_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=16)
        notebook.add(frame, text="Collector 등록")
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)

        self._add_entry(frame, 0, "Collector 이름", "collector_name", column_span=3, width=64)
        self._add_combo(frame, 1, "플랫폼", "platform", ALLOWED_PLATFORMS, self._handle_platform_change)
        self._add_combo(frame, 1, "역할", "collector_type", SERVER_COLLECTOR_TYPES, None, start_column=2)
        self._add_combo(frame, 2, "상태", "status", ALLOWED_STATUSES)
        self._add_entry(frame, 2, "호스트명", "hostname", start_column=2)
        self._add_entry(frame, 3, "사설 IP", "private_ip")
        self._add_entry(frame, 3, "공인 IP", "public_ip", start_column=2)

        ttk.Separator(frame).grid(row=4, column=0, columnspan=4, sticky="ew", pady=12)
        ttk.Label(frame, text="선택 연결 ID").grid(row=5, column=0, columnspan=4, sticky="w")
        self._add_entry(frame, 6, "고객 ID", "customer_id")
        self._add_entry(frame, 6, "현장 ID", "site_id", start_column=2)
        self._add_entry(frame, 7, "장비 ID", "device_id")

        ttk.Separator(frame).grid(row=8, column=0, columnspan=4, sticky="ew", pady=12)
        self._add_entry(frame, 9, "목적", "purpose", column_span=3, width=64)
        self._add_entry(frame, 10, "기능", "capabilities", column_span=3, width=64)
        self._add_entry(frame, 11, "메모", "notes", column_span=3, width=64)

    def _build_runtime_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=16)
        notebook.add(frame, text="실행")
        frame.columnconfigure(1, weight=1)

        self._add_entry(frame, 0, "Collector ID", "collector_id")
        self._add_entry(frame, 1, "Collector Token", "collector_token", show="*")
        ttk.Checkbutton(frame, text="토큰 표시", variable=self.vars["show_token"], command=self._toggle_token_visibility).grid(
            row=1, column=2, padx=(8, 0), sticky="w"
        )
        ttk.Button(frame, text="토큰 복사", command=self.copy_token).grid(row=1, column=3, padx=(8, 0), sticky="ew")
        self._add_entry(frame, 2, "전송 주기(초)", "interval_seconds")

        buttons = ttk.Frame(frame)
        buttons.grid(row=3, column=1, columnspan=3, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Heartbeat 1회 전송", command=self.send_heartbeat_once).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(buttons, text="주기 전송 시작", command=self.start_periodic_heartbeat).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(buttons, text="중지", command=self.stop_periodic_heartbeat).grid(row=0, column=2)

    def _build_site_profile_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=16)
        notebook.add(frame, text="현장 프로필")
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)

        self._add_entry(frame, 0, "VPN 직접 주소", "ict_vpn_url", column_span=3, width=64)
        self._add_entry(frame, 1, "HTTPS 대체 주소", "ict_https_url", column_span=3, width=64)
        self._add_entry(frame, 2, "119 장치 토큰", "ict_device_token", column_span=3, width=64, show="*")
        self._add_entry(frame, 3, "오프라인 큐", "ict_queue_path", column_span=2, width=64)
        ttk.Button(frame, text="찾기", command=self.browse_ict_queue_path).grid(
            row=3, column=3, padx=(8, 0), sticky="ew"
        )

        ttk.Separator(frame).grid(row=4, column=0, columnspan=4, sticky="ew", pady=12)
        ttk.Label(frame, text="할당 현장").grid(row=5, column=0, sticky="w", pady=5)
        self.ict_site_combo = ttk.Combobox(
            frame,
            textvariable=self.vars["ict_site_label"],
            values=(),
            state="readonly",
        )
        self.ict_site_combo.grid(row=5, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=5)
        self.ict_site_combo.bind("<<ComboboxSelected>>", lambda _event: self._handle_ict_site_change())
        ttk.Button(frame, text="현장 새로고침", command=self.refresh_ict_sites).grid(
            row=5, column=3, padx=(8, 0), sticky="ew"
        )

        ttk.Label(frame, text="통신 상태").grid(row=6, column=0, sticky="w", pady=5)
        ttk.Label(frame, textvariable=self.vars["ict_transport_status"]).grid(
            row=6, column=1, columnspan=3, sticky="w", padx=(8, 0), pady=5
        )

        buttons = ttk.Frame(frame)
        buttons.grid(row=7, column=1, columnspan=3, sticky="e", pady=(14, 0))
        ttk.Button(buttons, text="측정 세션 시작", command=self.start_ict_session).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Button(buttons, text="현재 진단값 적용", command=self.upload_ict_profile).grid(
            row=0, column=1, padx=(0, 8)
        )
        ttk.Button(buttons, text="대기 자료 재전송", command=self.retry_ict_queue).grid(row=0, column=2)

    def _build_diagnostics_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=16)
        notebook.add(frame, text="진단 수집")
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)
        frame.rowconfigure(6, weight=1)

        self._add_entry(frame, 0, "Gateway 대상", "diagnostics_gateway_target")
        self._add_entry(frame, 0, "DNS 대상", "diagnostics_dns_target", start_column=2)
        self._add_entry(frame, 1, "Ping 횟수", "diagnostics_ping_count")
        self._add_entry(frame, 1, "패킷 인터페이스", "diagnostics_packet_interface", start_column=2)
        self._add_entry(frame, 2, "캡처 시간(초)", "diagnostics_packet_duration")
        self._add_entry(frame, 2, "최대 프레임", "diagnostics_packet_max_frames", start_column=2)

        ttk.Checkbutton(
            frame,
            text="Wireshark/TShark 패킷 캡처 포함",
            variable=self.vars["diagnostics_packet_enabled"],
        ).grid(row=3, column=1, sticky="w", pady=(4, 4))
        ttk.Checkbutton(
            frame,
            text="다음 Heartbeat에 진단 요약 포함",
            variable=self.vars["include_diagnostics_in_heartbeat"],
        ).grid(row=3, column=3, sticky="w", pady=(4, 4))

        self._add_entry(frame, 4, "저장 경로", "diagnostics_output_path", column_span=2, width=64)
        ttk.Button(frame, text="찾기", command=self.browse_diagnostics_path).grid(row=4, column=3, padx=(8, 0), sticky="ew")

        buttons = ttk.Frame(frame)
        buttons.grid(row=5, column=1, columnspan=3, sticky="e", pady=(8, 8))
        ttk.Button(buttons, text="진단 수집", command=self.collect_diagnostics).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(buttons, text="결과 저장", command=self.save_diagnostics_report).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(buttons, text="요약 복사", command=self.copy_diagnostics_summary).grid(row=0, column=2)

        result_frame = ttk.LabelFrame(frame, text="수집 결과", padding=8)
        result_frame.grid(row=6, column=0, columnspan=4, sticky="nsew")
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        self.diagnostics_text = tk.Text(result_frame, height=16, wrap="none", state="disabled")
        self.diagnostics_text.grid(row=0, column=0, sticky="nsew")
        y_scroll = ttk.Scrollbar(result_frame, orient="vertical", command=self.diagnostics_text.yview)
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll = ttk.Scrollbar(result_frame, orient="horizontal", command=self.diagnostics_text.xview)
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.diagnostics_text.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

    def _build_config_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=16)
        notebook.add(frame, text="설정 파일")
        frame.columnconfigure(1, weight=1)

        self._add_entry(frame, 0, "설정 경로", "config_path", width=64)
        ttk.Button(frame, text="찾기", command=self.browse_config_path).grid(row=0, column=2, padx=(8, 0), sticky="ew")
        ttk.Checkbutton(
            frame,
            text="설정 파일에 Collector Token 저장",
            variable=self.vars["save_token"],
        ).grid(row=1, column=1, sticky="w", pady=(4, 12))

        buttons = ttk.Frame(frame)
        buttons.grid(row=2, column=1, columnspan=2, sticky="e")
        ttk.Button(buttons, text="설정 저장", command=self.save_current_config).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(buttons, text="설정 불러오기", command=self.load_current_config).grid(row=0, column=1)

    def _add_entry(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        variable_name: str,
        start_column: int = 0,
        column_span: int = 1,
        width: int = 28,
        show: str | None = None,
    ) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(row=row, column=start_column, sticky="w", pady=5)
        entry = ttk.Entry(parent, textvariable=self.vars[variable_name], width=width, show=show or "")
        entry.grid(row=row, column=start_column + 1, columnspan=column_span, sticky="ew", padx=(8, 0), pady=5)
        if variable_name == "collector_token":
            self.token_entry = entry
        return entry

    def _add_combo(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        variable_name: str,
        values: tuple[str, ...],
        callback: Callable[[], None] | None = None,
        start_column: int = 0,
    ) -> ttk.Combobox:
        ttk.Label(parent, text=label).grid(row=row, column=start_column, sticky="w", pady=5)
        combo = ttk.Combobox(parent, textvariable=self.vars[variable_name], values=values, state="readonly", width=26)
        combo.grid(row=row, column=start_column + 1, sticky="ew", padx=(8, 0), pady=5)
        if callback:
            combo.bind("<<ComboboxSelected>>", lambda _event: callback())
        return combo

    def _handle_platform_change(self) -> None:
        self.vars["collector_type"].set(default_collector_type(self.vars["platform"].get()))

    def _toggle_token_visibility(self) -> None:
        self.token_entry.configure(show="" if self.vars["show_token"].get() else "*")

    def _client(self) -> ApiClient:
        return ApiClient(
            base_url=normalize_base_url(self.vars["base_url"].get()),
            verify_tls=not bool(self.vars["allow_insecure_tls"].get()),
        )

    def _ict_client(self) -> IctManagerTransport:
        return IctManagerTransport(
            vpn_base_url=self.vars["ict_vpn_url"].get(),
            https_base_url=self.vars["ict_https_url"].get(),
            device_token=self.vars["ict_device_token"].get(),
            verify_tls=not bool(self.vars["allow_insecure_tls"].get()),
            queue_path=self.vars["ict_queue_path"].get(),
        )

    def collect_settings(self) -> dict[str, Any]:
        return {key: variable.get() for key, variable in self.vars.items() if key != "show_token"}

    def test_connection(self) -> None:
        def work() -> Any:
            return self._client().health()

        self.run_background("연결 테스트", work, lambda payload: self.log(f"연결 성공: {payload}"))

    def _set_ict_transport_status(self, mode: str, queue_count: int = 0, stale: bool = False) -> None:
        labels = {
            "vpn": "VPN 연결",
            "https_fallback": "HTTPS 대체 연결",
            "offline_queue": "오프라인 저장",
            "cached": "저장된 현장 목록",
            "none": "연결 확인 전",
        }
        label = labels.get(mode, mode)
        if stale:
            label += " (과거 목록)"
        if queue_count:
            label += f" / 재전송 대기 {queue_count}건"
        self.vars["ict_transport_status"].set(label)

    def refresh_ict_sites(self) -> None:
        def work() -> Any:
            client = self._ict_client()
            result = client.assigned_sites()
            result["queue_count"] = client.queue_size()
            return result

        def done(result: dict[str, Any]) -> None:
            payload = result.get("data") or {}
            sites = payload.get("sites") or []
            self.assigned_sites_by_label = {
                f"{site.get('customer_name')} / {site.get('site_name')} (#{site.get('site_id')})": site
                for site in sites
            }
            labels = tuple(self.assigned_sites_by_label)
            self.ict_site_combo.configure(values=labels)
            current = self.vars["ict_site_label"].get()
            if current not in self.assigned_sites_by_label:
                self.vars["ict_site_label"].set(labels[0] if labels else "")
            self._handle_ict_site_change()
            self._set_ict_transport_status(
                str(result.get("transport_mode") or "none"),
                int(result.get("queue_count") or 0),
                bool(result.get("stale")),
            )
            self.log(f"119 할당 현장 조회: {len(sites)}개")

        self.run_background("119 현장 조회", work, done)

    def _handle_ict_site_change(self) -> None:
        site = self.assigned_sites_by_label.get(self.vars["ict_site_label"].get())
        if not site:
            return
        self.vars["site_id"].set(str(site.get("site_id") or ""))
        self.vars["customer_id"].set(str(site.get("customer_id") or ""))
        self.field_session_id = None

    def _selected_ict_site_id(self) -> int:
        site = self.assigned_sites_by_label.get(self.vars["ict_site_label"].get())
        if not site:
            raise ValueError("119에서 할당 현장을 먼저 불러오고 선택하세요.")
        return int(site["site_id"])

    def start_ict_session(self) -> None:
        def work() -> Any:
            client = self._ict_client()
            result = client.start_session(
                self._selected_ict_site_id(),
                metadata={"hostname": self.vars["hostname"].get(), "app_version": APP_VERSION},
            )
            result["queue_count"] = client.queue_size()
            return result

        def done(result: dict[str, Any]) -> None:
            self.field_session_id = str(result["session_id"])
            self._set_ict_transport_status(
                str(result.get("transport_mode") or "none"),
                int(result.get("queue_count") or 0),
            )
            self.log(f"현장 측정 세션 준비: {self.field_session_id}")

        self.run_background("현장 측정 세션", work, done)

    def upload_ict_profile(self) -> None:
        if not self.latest_diagnostics:
            messagebox.showinfo("진단 결과 없음", "먼저 진단 수집을 실행하세요.")
            return

        def work() -> Any:
            client = self._ict_client()
            site_id = self._selected_ict_site_id()
            session_id = self.field_session_id
            session_result = None
            if not session_id:
                session_result = client.start_session(
                    site_id,
                    metadata={"hostname": self.vars["hostname"].get(), "app_version": APP_VERSION},
                )
                session_id = str(session_result["session_id"])
            result = client.upload_profile(
                session_id,
                site_id,
                self.latest_diagnostics or {},
                source_collected_at=str((self.latest_diagnostics or {}).get("collected_at") or "") or None,
            )
            result["session_id"] = session_id
            result["session_result"] = session_result
            result["queue_count"] = client.queue_size()
            return result

        def done(result: dict[str, Any]) -> None:
            self.field_session_id = str(result["session_id"])
            self._set_ict_transport_status(
                str(result.get("transport_mode") or "none"),
                int(result.get("queue_count") or 0),
            )
            status = "오프라인 큐 저장" if result.get("queued") else "119 저장 완료"
            self.log(f"현장 프로필 적용: {status}")

        self.run_background("현장 프로필 적용", work, done)

    def retry_ict_queue(self) -> None:
        def work() -> Any:
            return self._ict_client().retry_queue()

        def done(result: dict[str, Any]) -> None:
            self._set_ict_transport_status(
                str(result.get("transport_mode") or "none"),
                int(result.get("remaining") or 0),
            )
            self.log(f"대기 자료 재전송: 성공 {result.get('sent')}건 / 남음 {result.get('remaining')}건")

        self.run_background("대기 자료 재전송", work, done)

    def issue_token(self) -> None:
        username = self.vars["admin_username"].get().strip()
        password = self.vars["admin_password"].get()
        if not username or not password:
            messagebox.showwarning("입력 필요", "관리자 ID와 비밀번호를 입력하세요.")
            return

        def work() -> Any:
            client = self._client()
            try:
                login_payload = client.login(username, password)
            except Exception as exc:  # noqa: BLE001 - preserve exact stage for operators.
                raise RuntimeError(f"로그인 실패: {exc}") from exc
            try:
                session_payload = client.me()
            except Exception as exc:  # noqa: BLE001 - preserve exact stage for operators.
                raise RuntimeError(f"로그인 후 세션 확인 실패: {exc}") from exc
            payload = build_collector_payload(self.collect_settings())
            try:
                collector_payload = client.create_collector(payload)
            except Exception as exc:  # noqa: BLE001 - preserve exact stage for operators.
                raise RuntimeError(f"Collector 생성 실패: {exc}") from exc
            return {
                "login": login_payload,
                "session": session_payload,
                "collector": collector_payload,
            }

        def done(payload: dict[str, Any]) -> None:
            collector = payload.get("collector") or {}
            user = (payload.get("login") or {}).get("user") or {}
            self.vars["collector_id"].set(str(collector.get("id") or ""))
            self.vars["collector_token"].set(str(collector.get("agent_token") or ""))
            self.log(f"로그인 성공: {user.get('username') or username}")
            self.log(f"Collector 등록 완료: id={collector.get('id')} / token=issued")
            self.status_var.set("토큰 발급 완료")

        self.run_background("토큰 발급", work, done)

    def send_heartbeat_once(self) -> None:
        def work() -> Any:
            settings = self.collect_settings()
            payload = build_heartbeat_payload(settings)
            self._attach_diagnostics_summary(payload)
            return self._client().heartbeat(settings.get("collector_id", ""), settings.get("collector_token", ""), payload)

        def done(payload: dict[str, Any]) -> None:
            self.log(f"Heartbeat 성공: collector id={payload.get('id')} status={payload.get('status')}")
            self.status_var.set("Heartbeat 성공")

        self.run_background("Heartbeat 전송", work, done)

    def start_periodic_heartbeat(self) -> None:
        if self.periodic_thread and self.periodic_thread.is_alive():
            self.log("주기 전송이 이미 실행 중입니다.")
            return

        interval = clamp_interval_seconds(self.vars["interval_seconds"].get())
        self.vars["interval_seconds"].set(str(interval))
        self.periodic_stop.clear()
        self.periodic_thread = threading.Thread(target=self._periodic_worker, args=(interval,), daemon=True)
        self.periodic_thread.start()
        self.log(f"주기 전송 시작: {interval}초")
        self.status_var.set("주기 전송 실행 중")

    def stop_periodic_heartbeat(self) -> None:
        self.periodic_stop.set()
        self.log("주기 전송 중지 요청")
        self.status_var.set("중지 요청됨")

    def _periodic_worker(self, interval: int) -> None:
        while not self.periodic_stop.is_set():
            try:
                settings = self.collect_settings()
                payload = build_heartbeat_payload(settings)
                self._attach_diagnostics_summary(payload)
                response = self._client().heartbeat(settings.get("collector_id", ""), settings.get("collector_token", ""), payload)
                self.message_queue.put(("log", f"주기 Heartbeat 성공: collector id={response.get('id')}"))
            except Exception as exc:  # noqa: BLE001 - show operator-facing error.
                self.message_queue.put(("error", f"주기 Heartbeat 실패: {exc}"))
            if self.periodic_stop.wait(interval):
                break
        self.message_queue.put(("status", "주기 전송 중지됨"))

    def save_current_config(self) -> None:
        path = self.vars["config_path"].get().strip() or str(get_default_config_path())
        try:
            saved = save_config(path, self.collect_settings(), include_token=bool(self.vars["save_token"].get()))
        except Exception as exc:  # noqa: BLE001 - user-facing dialog.
            messagebox.showerror("저장 실패", str(exc))
            return
        self.log(f"설정 저장 완료: {saved}")

    def load_current_config(self) -> None:
        path = self.vars["config_path"].get().strip() or str(get_default_config_path())
        try:
            loaded = load_config(path)
        except Exception as exc:  # noqa: BLE001 - user-facing dialog.
            messagebox.showerror("불러오기 실패", str(exc))
            return

        for key, value in loaded.items():
            variable = self.vars.get(key)
            if variable is not None:
                variable.set(value)
        self.log(f"설정 불러오기 완료: {path}")

    def browse_config_path(self) -> None:
        path = filedialog.asksaveasfilename(
            title="설정 파일 선택",
            defaultextension=".json",
            filetypes=(("JSON", "*.json"), ("All files", "*.*")),
            initialfile=Path(self.vars["config_path"].get()).name,
        )
        if path:
            self.vars["config_path"].set(path)

    def browse_diagnostics_path(self) -> None:
        path = filedialog.asksaveasfilename(
            title="진단 결과 저장 위치",
            defaultextension=".json",
            filetypes=(("JSON", "*.json"), ("All files", "*.*")),
            initialfile=Path(self.vars["diagnostics_output_path"].get()).name,
        )
        if path:
            self.vars["diagnostics_output_path"].set(path)

    def browse_ict_queue_path(self) -> None:
        path = filedialog.asksaveasfilename(
            title="ICT 오프라인 큐 저장 위치",
            defaultextension=".json",
            filetypes=(("JSON", "*.json"), ("All files", "*.*")),
            initialfile=Path(self.vars["ict_queue_path"].get()).name,
        )
        if path:
            self.vars["ict_queue_path"].set(path)

    def collect_diagnostics(self) -> None:
        def work() -> Any:
            return collect_network_diagnostics(self.collect_settings())

        def done(report: dict[str, Any]) -> None:
            self.latest_diagnostics = report
            rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
            self._set_diagnostics_text(rendered)
            summary = report.get("summary") or {}
            self.log(
                "진단 수집 완료: "
                f"gateway={summary.get('default_gateway') or 'unknown'}, "
                f"arp={summary.get('arp_entry_count')}, "
                f"vlan_hints={summary.get('vlan_hint_count')}, "
                f"packet={summary.get('packet_status')}"
            )
            self.status_var.set("진단 수집 완료")

        self.run_background("진단 수집", work, done)

    def save_diagnostics_report(self) -> None:
        if not self.latest_diagnostics:
            messagebox.showinfo("진단 결과 없음", "먼저 진단 수집을 실행하세요.")
            return
        path = self.vars["diagnostics_output_path"].get().strip()
        try:
            saved = write_diagnostics_report(path, self.latest_diagnostics)
        except Exception as exc:  # noqa: BLE001 - user-facing dialog.
            messagebox.showerror("저장 실패", str(exc))
            return
        self.log(f"진단 결과 저장 완료: {saved}")

    def copy_diagnostics_summary(self) -> None:
        if not self.latest_diagnostics:
            messagebox.showinfo("진단 결과 없음", "먼저 진단 수집을 실행하세요.")
            return
        summary = self.latest_diagnostics.get("summary") or {}
        self.clipboard_clear()
        self.clipboard_append(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
        self.log("진단 요약을 클립보드에 복사했습니다.")

    def _set_diagnostics_text(self, value: str) -> None:
        self.diagnostics_text.configure(state="normal")
        self.diagnostics_text.delete("1.0", "end")
        self.diagnostics_text.insert("1.0", value)
        self.diagnostics_text.configure(state="disabled")

    def _attach_diagnostics_summary(self, heartbeat_payload: dict[str, Any]) -> None:
        if not self.latest_diagnostics or not self.vars["include_diagnostics_in_heartbeat"].get():
            return
        metadata = heartbeat_payload.setdefault("metadata", {})
        metadata["diagnostics"] = self.latest_diagnostics.get("summary") or {}

    def copy_token(self) -> None:
        token = self.vars["collector_token"].get().strip()
        if not token:
            messagebox.showinfo("토큰 없음", "복사할 Collector Token이 없습니다.")
            return
        self.clipboard_clear()
        self.clipboard_append(token)
        self.log("Collector Token을 클립보드에 복사했습니다.")

    def run_background(self, label: str, work: Callable[[], Any], on_success: Callable[[Any], None] | None = None) -> None:
        self._set_busy(True, f"{label} 중...")

        def runner() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001 - show exact operator-facing failure.
                self.message_queue.put(("failure", label, str(exc)))
            else:
                self.message_queue.put(("success", label, result, on_success))

        threading.Thread(target=runner, daemon=True).start()

    def _set_busy(self, busy: bool, message: str | None = None) -> None:
        self.busy_count = max(0, self.busy_count + (1 if busy else -1))
        if message:
            self.status_var.set(message)
        elif self.busy_count == 0:
            self.status_var.set("준비")
        self.configure(cursor="watch" if self.busy_count else "")

    def _poll_queue(self) -> None:
        try:
            while True:
                item = self.message_queue.get_nowait()
                kind = item[0]
                if kind == "success":
                    _, label, result, callback = item
                    self._set_busy(False)
                    self.log(f"{label} 완료")
                    if callback:
                        callback(result)
                elif kind == "failure":
                    _, label, message = item
                    self._set_busy(False)
                    self.log(f"{label} 실패: {message}")
                    self.status_var.set(f"{label} 실패")
                elif kind == "log":
                    self.log(str(item[1]))
                elif kind == "error":
                    self.log(str(item[1]))
                    self.status_var.set(str(item[1])[:80])
                elif kind == "status":
                    self.status_var.set(str(item[1]))
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")


def main() -> None:
    app = FieldCollectorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
