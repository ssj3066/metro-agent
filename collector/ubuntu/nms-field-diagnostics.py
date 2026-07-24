#!/usr/bin/env python3
import ipaddress
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

sys.path.insert(0, "/usr/local/lib/metro-nms-collector")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ict_field_client import IctFieldClient, load_device_config

HELPER = "/opt/nms-collector/configure-snmp-targets.sh"
NODE = "/usr/local/bin/node"
COLLECTOR = "/opt/nms-collector/nms-collector.js"
GUI_OPS = "/opt/nms-collector/nms-gui-operations.sh"
FIELD_PROFILE_STORE = Path.home() / ".config" / "metro-nms-field-collector" / "field-profiles.json"
ICT_DEVICE_CONFIG = Path.home() / ".config" / "metro-nms-field-collector" / "ict-manager-device.json"
ICT_OFFLINE_QUEUE = Path.home() / ".config" / "metro-nms-field-collector" / "ict-manager-offline-queue.json"
ICT_SITE_CACHE = Path.home() / ".config" / "metro-nms-field-collector" / "ict-manager-sites-cache.json"
SERVICES = [
    ("중앙 서버 연결", "nms-collector-heartbeat.timer"),
    ("WireGuard 터널", "wg-quick@metro-omada.service"),
    ("원격 진단", "nms-collector-diagnostic-worker.service"),
    ("정기 분석", "nms-collector-edge-analysis.timer"),
    ("SNMP Trap", "nms-collector-trap-forwarder.service"),
    ("대역폭 측정 서버", "nms-iperf3-server.service"),
    ("Syslog 수신", "rsyslog.service"),
    ("LLDP 수신", "lldpd.service"),
]
COMMANDS = {
    "게이트웨이 Ping": "GW=$(ip route | awk '/default/ {print $3; exit}'); test -n \"$GW\" && ping -c 4 -W 2 \"$GW\"",
    "인터넷 Ping": "ping -c 4 -W 2 1.1.1.1",
    "DNS 확인": "getent hosts naver.com; resolvectl status 2>/dev/null | head -35",
    "경로 추적": "mtr -r -c 5 -w \"$NMS_DIAG_TARGET\" 2>&1 || traceroute -n -m 12 -w 2 \"$NMS_DIAG_TARGET\"",
    "ARP 이웃": "ip neigh",
    "무선 검색": "nmcli -f IN-USE,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY dev wifi list --rescan yes",
    "포트 점검": "nmap -Pn --top-ports 50 --open \"$NMS_DIAG_TARGET\"",
    "VLAN/LLDP/CDP": "ip -d link show type vlan; echo; lldpcli show neighbors 2>&1",
    "인터페이스": f"{GUI_OPS} interface-status; echo; for i in $(ip -o link show | awk -F': ' '$2 !~ /^lo/ {{print $2}}'); do echo ==== $i; ethtool $i 2>&1 | grep -E 'Speed:|Duplex:|Link detected:'; done",
}
CAPTURE_PROFILES = {
    "전체 헤더": "overview",
    "기본 통신": "basic",
    "DNS": "dns",
    "DHCP": "dhcp",
    "ARP": "arp",
    "Ping": "icmp",
    "LLDP/CDP": "discovery",
}
NETWORK_STATUS_COMMAND = r'''
ROUTE=$(ip -4 route get 1.1.1.1 2>/dev/null | head -1)
IFACE=$(printf '%s\n' "$ROUTE" | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
SRC=$(printf '%s\n' "$ROUTE" | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')
CIDR=$(test -n "$IFACE" && ip -o -4 addr show dev "$IFACE" scope global 2>/dev/null | awk -v src="$SRC" '$4 ~ ("^" src "/") {print $4; exit}')
printf '현재 연결 네트워크\n'
printf '  인터페이스: %s\n' "${IFACE:-미확인}"
printf '  내부 IPv4: %s\n' "${CIDR:-미확인}"
printf '  기본 게이트웨이: %s\n' "$(ip route show default | awk '/default/ {print $3; exit}')"
printf '\n수집기 및 서비스 상태\n'
hostnamectl --static
echo
systemctl is-active nms-collector-heartbeat.timer nms-collector-diagnostic-worker.service nms-collector-edge-analysis.timer 2>&1
'''

def valid_host(value):
    value = value.strip()
    if not value or any(c.isspace() for c in value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return all(part and part.replace("-", "").isalnum() for part in value.rstrip(".").split("."))

def parse_settings(text):
    data = json.loads(text.strip())
    data.setdefault("targets", [])
    return data

def calculate_interface_rates(previous, current, elapsed_seconds):
    if not previous or elapsed_seconds <= 0:
        return {"rx_mbps": 0.0, "tx_mbps": 0.0, "rx_pps": 0.0, "tx_pps": 0.0}
    def delta(key):
        return max(0, int(current.get(key, 0)) - int(previous.get(key, 0)))
    return {
        "rx_mbps": round(delta("rx_bytes") * 8 / elapsed_seconds / 1_000_000, 3),
        "tx_mbps": round(delta("tx_bytes") * 8 / elapsed_seconds / 1_000_000, 3),
        "rx_pps": round(delta("rx_packets") / elapsed_seconds, 1),
        "tx_pps": round(delta("tx_packets") / elapsed_seconds, 1),
    }

def parse_discovery_neighbors(text):
    try:
        payload=json.loads(text)
    except (TypeError,ValueError,json.JSONDecodeError):
        return []
    interfaces=((payload.get("lldp") or {}).get("interface") or {}) if isinstance(payload,dict) else {}
    neighbors=[]
    for interface,value in interfaces.items():
        entries=value if isinstance(value,list) else [value]
        for entry in entries:
            if not isinstance(entry,dict):
                continue
            chassis_container=entry.get("chassis") or {}
            named=next(((name,item) for name,item in chassis_container.items() if isinstance(item,dict)),(None,chassis_container))
            chassis_name,chassis=named
            port=entry.get("port") or {}
            neighbors.append({
                "protocol":str(entry.get("via") or entry.get("protocol") or "LLDP").upper(),
                "local_interface":interface,
                "device":chassis_name or "미확인",
                "management_ip":chassis.get("mgmt-ip") or "-",
                "port":((port.get("id") or {}).get("value") if isinstance(port.get("id"),dict) else port.get("id")) or port.get("descr") or "-",
                "age":entry.get("age") or "-",
            })
    return neighbors

def read_interface_counters(interface):
    base=Path("/sys/class/net") / interface / "statistics"
    values={}
    for key in ("rx_bytes","tx_bytes","rx_packets","tx_packets","rx_errors","tx_errors","rx_dropped","tx_dropped"):
        try: values[key]=int((base/key).read_text(encoding="ascii").strip())
        except (OSError,ValueError): values[key]=0
    return values

class App:
    def __init__(self, root):
        self.root = root
        root.title("METRO NMS Collecter")
        root.geometry("1240x780")
        root.minsize(1000, 650)
        self.events = queue.Queue()
        self.status = tk.StringVar(value="대기 중")
        self.page_title = tk.StringVar(value="현장 프로필")
        self.last_refresh = tk.StringVar(value="마지막 갱신: 확인 전")
        self.last_snapshot = tk.StringVar(value="최근 저장: 없음")
        self.pages = {}
        self.nav_buttons = {}
        self.refresh_batch_pending = set()
        self.refresh_batch_errors = 0
        self.running_jobs = 0
        self.field_profile_name = tk.StringVar()
        self.field_site_name = tk.StringVar()
        self.metro_contact_name = tk.StringVar()
        self.metro_contact_phone = tk.StringVar()
        self.customer_contact_name = tk.StringVar()
        self.customer_contact_phone = tk.StringVar()
        self.active_profile_label = tk.StringVar(value="현장 프로필을 먼저 선택하거나 저장하세요.")
        self.ict_connection_status = tk.StringVar(value="119 연결 확인 전")
        self.field_profiles = self._load_field_profiles()
        self.pending_measurement_profile = None
        self.pending_snapshot_profile = None
        self.target = tk.StringVar(value="1.1.1.1")
        self.version, self.port = tk.StringVar(value="2c"), tk.StringVar(value="161")
        self.timeout, self.retries = tk.StringVar(value="2"), tk.StringVar(value="1")
        self.community_state = tk.StringVar(value="확인 전")
        self.interface = tk.StringVar()
        self.capture_profile = tk.StringVar(value="기본 통신")
        self.capture_seconds = tk.StringVar(value="15")
        self.live_capture_minutes = tk.StringVar(value="10")
        self.live_capture_status = tk.StringVar(value="정지됨")
        self.live_capture_process = None
        self.live_capture_packet_count = 0
        self.live_capture_path = None
        self.live_monitor_interface = tk.StringVar()
        self.live_monitor_status = tk.StringVar(value="모니터링 정지")
        self.live_monitor_enabled = False
        self.live_monitor_in_flight = False
        self.live_monitor_previous = None
        self.live_monitor_previous_at = None
        self.live_monitor_after_id = None
        self.current_page = ""
        self.measurement_value = tk.StringVar(value="5")
        self.measurement_unit = tk.StringVar(value="분")
        self.measurement_interval = tk.StringVar(value="10")
        self.wireless_hidden_only = tk.BooleanVar(value=False)
        self.wireless_payload = None
        self._configure_style()
        self._build()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(150, self._drain)
        self.root.after(350, self.refresh_status)
        self.root.after(700, self.refresh_assigned_sites)

    def _configure_style(self):
        self.colors = {
            "background": "#f5f5f7",
            "surface": "#ffffff",
            "sidebar": "#202124",
            "sidebar_muted": "#a9adb5",
            "text": "#1d1d1f",
            "muted": "#6e6e73",
            "border": "#d2d2d7",
            "metro_blue": "#1768ac",
            "metro_blue_active": "#0f4f88",
            "metro_red": "#d9363e",
            "success": "#25855a",
        }
        self.root.configure(background=self.colors["background"])
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", font=("Noto Sans CJK KR", 10), background=self.colors["background"], foreground=self.colors["text"])
        style.configure("App.TFrame", background=self.colors["background"])
        style.configure("Surface.TFrame", background=self.colors["surface"])
        style.configure("Sidebar.TFrame", background=self.colors["sidebar"])
        style.configure("Sidebar.TLabel", background=self.colors["sidebar"], foreground="#ffffff")
        style.configure("SidebarMuted.TLabel", background=self.colors["sidebar"], foreground=self.colors["sidebar_muted"])
        style.configure("Brand.TLabel", background=self.colors["sidebar"], foreground="#ffffff", font=("Noto Sans CJK KR", 18, "bold"))
        style.configure("PageTitle.TLabel", background=self.colors["background"], foreground=self.colors["text"], font=("Noto Sans CJK KR", 17, "bold"))
        style.configure("Meta.TLabel", background=self.colors["background"], foreground=self.colors["muted"])
        style.configure("MetricLabel.TLabel", background=self.colors["surface"], foreground=self.colors["muted"], font=("Noto Sans CJK KR", 9))
        style.configure("MetricValue.TLabel", background=self.colors["surface"], foreground=self.colors["text"], font=("Noto Sans CJK KR", 14, "bold"))
        style.configure("Nav.TButton", background=self.colors["sidebar"], foreground="#f5f5f7", borderwidth=0, padding=(16, 10), anchor="w")
        style.map("Nav.TButton", background=[("active", "#34363a")], foreground=[("active", "#ffffff")])
        style.configure("NavActive.TButton", background=self.colors["metro_blue"], foreground="#ffffff", borderwidth=0, padding=(16, 10), anchor="w")
        style.map("NavActive.TButton", background=[("active", self.colors["metro_blue_active"])])
        style.configure("Accent.TButton", background=self.colors["metro_blue"], foreground="#ffffff", borderwidth=0, padding=(14, 8))
        style.map("Accent.TButton", background=[("active", self.colors["metro_blue_active"]), ("disabled", "#9ebbd3")])
        style.configure("Danger.TButton", background=self.colors["metro_red"], foreground="#ffffff", borderwidth=0, padding=(12, 7))
        style.configure("TButton", padding=(10, 7), borderwidth=1)
        style.configure("TLabelFrame", background=self.colors["surface"], bordercolor=self.colors["border"], borderwidth=1, relief="solid")
        style.configure("TLabelFrame.Label", background=self.colors["surface"], foreground=self.colors["text"], font=("Noto Sans CJK KR", 10, "bold"))
        style.configure("Treeview", background=self.colors["surface"], fieldbackground=self.colors["surface"], foreground=self.colors["text"], rowheight=28, bordercolor=self.colors["border"])
        style.configure("Treeview.Heading", background="#ececf0", foreground=self.colors["text"], relief="flat", padding=(8, 7), font=("Noto Sans CJK KR", 9, "bold"))
        style.map("Treeview", background=[("selected", self.colors["metro_blue"])], foreground=[("selected", "#ffffff")])
        style.configure("TEntry", fieldbackground=self.colors["surface"], bordercolor=self.colors["border"], padding=6)
        style.configure("TCombobox", fieldbackground=self.colors["surface"], bordercolor=self.colors["border"], padding=5)

    def _build(self):
        shell = ttk.Frame(self.root, style="App.TFrame")
        shell.pack(fill="both", expand=True)
        sidebar = ttk.Frame(shell, width=218, style="Sidebar.TFrame")
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        brand = ttk.Frame(sidebar, style="Sidebar.TFrame", padding=(18, 18, 14, 16))
        brand.pack(fill="x")
        ttk.Label(brand, text="METRO", style="Brand.TLabel").pack(anchor="w")
        ttk.Label(brand, text="NMS COLLECTER", style="SidebarMuted.TLabel").pack(anchor="w", pady=(1, 0))
        accent = tk.Frame(sidebar, background=self.colors["metro_red"], height=3)
        accent.pack(fill="x", padx=18, pady=(0, 12))
        self.nav = ttk.Frame(sidebar, style="Sidebar.TFrame")
        self.nav.pack(fill="both", expand=True, padx=10)
        footer = ttk.Frame(sidebar, style="Sidebar.TFrame", padding=(16, 12))
        footer.pack(fill="x", side="bottom")
        ttk.Label(footer, textvariable=self.status, style="Sidebar.TLabel", wraplength=185).pack(anchor="w")
        ttk.Label(footer, text="FIELD COLLECTOR · 130", style="SidebarMuted.TLabel").pack(anchor="w", pady=(4, 0))

        main = ttk.Frame(shell, style="App.TFrame", padding=(20, 16, 20, 18))
        main.pack(side="left", fill="both", expand=True)
        header = ttk.Frame(main, style="App.TFrame")
        header.pack(fill="x")
        title_block = ttk.Frame(header, style="App.TFrame")
        title_block.pack(side="left", fill="x", expand=True)
        ttk.Label(title_block, textvariable=self.page_title, style="PageTitle.TLabel").pack(anchor="w")
        ttk.Label(title_block, textvariable=self.last_refresh, style="Meta.TLabel").pack(anchor="w", pady=(3, 0))
        actions = ttk.Frame(header, style="App.TFrame")
        actions.pack(side="right")
        ttk.Button(actions, text="진단 저장", command=lambda: self.create_snapshot(False)).pack(side="left", padx=3)
        ttk.Button(actions, text="중앙 송신", command=self.flush_offline_queue).pack(side="left", padx=3)
        ttk.Button(actions, text="저장 후 송신", style="Accent.TButton", command=lambda: self.create_snapshot(True)).pack(side="left", padx=3)
        self.refresh_all_button = ttk.Button(actions, text="전체 새로고침", command=self.refresh_all)
        self.refresh_all_button.pack(side="left", padx=(9, 0))
        ttk.Label(main, textvariable=self.last_snapshot, style="Meta.TLabel").pack(fill="x", pady=(8, 8))
        self.page_host = ttk.Frame(main, style="Surface.TFrame")
        self.page_host.pack(fill="both", expand=True)
        self._field_profile_tab(); self._status_tab(); self._source_tab(); self._live_monitor_tab(); self._measurement_tab(); self._offline_queue_tab(); self._diag_tab(); self._wireless_tab(); self._capture_tab(); self._vpn_tab(); self._snmp_tab(); self._service_tab()
        self.show_page("현장 프로필")
        self._polish_widgets(self.root)

    def _new_page(self, title):
        page = ttk.Frame(self.page_host, padding=16, style="Surface.TFrame")
        page.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.pages[title] = page
        button = ttk.Button(self.nav, text=title, style="Nav.TButton", command=lambda name=title: self.show_page(name))
        button.pack(fill="x", pady=2)
        self.nav_buttons[title] = button
        return page

    def show_page(self, title):
        page = self.pages.get(title)
        if not page:
            return
        page.lift()
        self.current_page=title
        self.page_title.set(title)
        for name, button in self.nav_buttons.items():
            button.configure(style="NavActive.TButton" if name == title else "Nav.TButton")
        if title == "실시간 모니터링" and not self.live_monitor_enabled:
            self.start_live_monitor()

    def _polish_widgets(self, widget):
        for child in widget.winfo_children():
            if isinstance(child, tk.Text):
                child.configure(background="#fbfbfc", foreground=self.colors["text"], insertbackground=self.colors["text"], relief="solid", borderwidth=1, highlightthickness=0, padx=10, pady=8)
            self._polish_widgets(child)

    def _field_profile_tab(self):
        tab = self._new_page("현장 프로필")
        saved = ttk.LabelFrame(tab, text="119 할당 현장", padding=10); saved.pack(fill="x")
        ttk.Label(saved, text="현장 선택").grid(row=0, column=0, sticky="w")
        self.field_profile_box = ttk.Combobox(saved, textvariable=self.field_profile_name, state="readonly", width=42)
        self.field_profile_box.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        self.field_profile_box.bind("<<ComboboxSelected>>", lambda _event: self._load_selected_field_profile())
        ttk.Button(saved, text="119 새로고침", command=self.refresh_assigned_sites).grid(row=0, column=2, padx=3)
        ttk.Label(saved, textvariable=self.ict_connection_status).grid(row=1, column=1, columnspan=2, sticky="w", padx=(8, 0), pady=(5, 0))
        saved.columnconfigure(1, weight=1)

        details = ttk.LabelFrame(tab, text="측정 현장 및 연락처", padding=10); details.pack(fill="x", pady=(10, 0))
        fields = (
            ("현장명", self.field_site_name),
            ("메트로 담당자", self.metro_contact_name),
            ("메트로 연락처", self.metro_contact_phone),
            ("고객사 담당자", self.customer_contact_name),
            ("고객사 연락처", self.customer_contact_phone),
        )
        for row, (label, variable) in enumerate(fields):
            ttk.Label(details, text=label).grid(row=row, column=0, sticky="w", pady=4)
            entry = ttk.Entry(details, textvariable=variable, width=48)
            if row == 0:
                entry.configure(state="readonly")
            entry.grid(row=row, column=1, sticky="ew", padx=(12, 0), pady=4)
        details.columnconfigure(1, weight=1)
        ttk.Button(tab, text="현장 프로필 저장", command=self._save_field_profile).pack(anchor="e", pady=(10, 0))
        ttk.Label(tab, text="고객·현장 기준정보는 119에서 자동으로 불러옵니다. 이 화면에서는 측정에 필요한 담당자 정보만 보완합니다.").pack(anchor="w", pady=(12, 0))
        self._refresh_field_profile_choices()

    def _load_field_profiles(self):
        try:
            payload = json.loads(FIELD_PROFILE_STORE.read_text(encoding="utf-8"))
            profiles = payload.get("profiles", []) if isinstance(payload, dict) else []
            return [
                profile for profile in profiles
                if isinstance(profile, dict) and int(profile.get("site_id") or 0) > 0
            ]
        except (OSError, ValueError, json.JSONDecodeError):
            return []

    def _write_field_profiles(self):
        FIELD_PROFILE_STORE.parent.mkdir(parents=True, exist_ok=True)
        temporary = FIELD_PROFILE_STORE.with_suffix(".tmp")
        temporary.write_text(json.dumps({"schema_version": "collector-field-profiles-v1", "profiles": self.field_profiles}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, FIELD_PROFILE_STORE)

    def _profile_display_name(self, profile):
        customer_name = str(profile.get("customer_name", "")).strip()
        site_name = str(profile.get("site_name", "")).strip()
        return f"{customer_name} / {site_name}" if customer_name else site_name

    def _refresh_field_profile_choices(self):
        if not hasattr(self, "field_profile_box"):
            return
        names = [self._profile_display_name(profile) for profile in self.field_profiles if self._profile_display_name(profile)]
        self.field_profile_box["values"] = tuple(names)

    def _field_profile_from_form(self):
        selected = self.field_profile_name.get().strip()
        assigned = next((item for item in self.field_profiles if self._profile_display_name(item) == selected), None)
        if not assigned:
            messagebox.showerror("현장 프로필", "119에서 할당 현장을 불러온 뒤 선택하세요.")
            return None
        profile = {
            "schema_version": "collector-field-profile-v1",
            "site_id": int(assigned["site_id"]),
            "customer_id": int(assigned["customer_id"]),
            "site_name": str(assigned.get("site_name") or "").strip(),
            "customer_name": str(assigned.get("customer_name") or "").strip(),
            "address": assigned.get("address"),
            "scope_started_at": assigned.get("scope_started_at"),
            "metro_contact": {"name": self.metro_contact_name.get().strip(), "phone": self.metro_contact_phone.get().strip()},
            "customer_contact": {"name": self.customer_contact_name.get().strip(), "phone": self.customer_contact_phone.get().strip()},
        }
        missing = [label for label, value in (
            ("현장명", profile["site_name"]),
            ("메트로 담당자", profile["metro_contact"]["name"]),
            ("메트로 연락처", profile["metro_contact"]["phone"]),
            ("고객사 담당자", profile["customer_contact"]["name"]),
            ("고객사 연락처", profile["customer_contact"]["phone"]),
        ) if not value]
        if missing:
            messagebox.showerror("현장 프로필", f"다음 항목을 입력하세요: {', '.join(missing)}")
            return None
        return profile

    def _apply_field_profile(self, profile):
        self.field_site_name.set(profile.get("site_name", ""))
        metro = profile.get("metro_contact") or {}
        customer = profile.get("customer_contact") or {}
        self.metro_contact_name.set(metro.get("name", "")); self.metro_contact_phone.set(metro.get("phone", ""))
        self.customer_contact_name.set(customer.get("name", "")); self.customer_contact_phone.set(customer.get("phone", ""))
        self.field_profile_name.set(self._profile_display_name(profile))
        self.active_profile_label.set(f"현재 측정 현장: {self.field_site_name.get().strip()}")

    def _ict_client(self):
        return IctFieldClient(
            load_device_config(ICT_DEVICE_CONFIG),
            ICT_OFFLINE_QUEUE,
            ICT_SITE_CACHE,
        )

    def refresh_assigned_sites(self):
        if self.running_jobs:
            self.ict_connection_status.set("119 현장 조회 대기")
        self.running_jobs += 1
        self.ict_connection_status.set("119 할당 현장 조회 중")
        def worker():
            try:
                payload, mode = self._ict_client().assigned_sites()
                self.events.put(("119 현장 조회", 0, json.dumps({"payload": payload, "mode": mode}, ensure_ascii=False)))
            except Exception as exc:
                self.events.put(("119 현장 조회", 1, str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _merge_assigned_sites(self, payload, mode):
        existing = {int(item.get("site_id") or 0): item for item in self.field_profiles}
        merged = []
        for site in payload.get("sites") or []:
            site_id = int(site.get("site_id") or 0)
            if not site_id:
                continue
            previous = existing.get(site_id) or {}
            merged.append({
                "schema_version": "collector-field-profile-v1",
                "site_id": site_id,
                "customer_id": int(site.get("customer_id") or 0),
                "site_name": site.get("site_name") or "",
                "customer_name": site.get("customer_name") or "",
                "address": site.get("address"),
                "scope_started_at": site.get("scope_started_at"),
                "metro_contact": previous.get("metro_contact") or {"name": "", "phone": ""},
                "customer_contact": previous.get("customer_contact") or {"name": "", "phone": ""},
            })
        self.field_profiles = sorted(merged, key=lambda item: self._profile_display_name(item))
        self._write_field_profiles()
        self._refresh_field_profile_choices()
        labels = {"vpn": "VPN 연결", "https_fallback": "HTTPS 대체 연결", "cached": "저장된 현장 목록"}
        self.ict_connection_status.set(f"{labels.get(mode, mode)} · 할당 {len(merged)}개")
        current = self.field_profile_name.get()
        names = [self._profile_display_name(item) for item in merged]
        if current not in names:
            self.field_profile_name.set(names[0] if names else "")
        self._load_selected_field_profile()

    def _load_selected_field_profile(self):
        selected = self.field_profile_name.get().strip()
        profile = next((item for item in self.field_profiles if self._profile_display_name(item) == selected), None)
        if profile:
            self._apply_field_profile(profile)

    def _new_field_profile(self):
        self.field_profile_name.set("")
        self.field_site_name.set(""); self.metro_contact_name.set(""); self.metro_contact_phone.set("")
        self.customer_contact_name.set(""); self.customer_contact_phone.set("")
        self.active_profile_label.set("새 현장 프로필을 입력하고 저장하세요.")

    def _save_field_profile(self):
        profile = self._field_profile_from_form()
        if not profile:
            return
        site_name = profile["site_name"]
        self.field_profiles = [
            item for item in self.field_profiles
            if int(item.get("site_id") or 0) != int(profile["site_id"])
        ]
        self.field_profiles.append(profile)
        self.field_profiles.sort(key=lambda item: self._profile_display_name(item))
        self._write_field_profiles()
        self._refresh_field_profile_choices(); self._apply_field_profile(profile)
        messagebox.showinfo("현장 프로필", f"{site_name} 현장 프로필을 저장했습니다.")

    def _delete_field_profile(self):
        selected = self.field_profile_name.get().strip()
        if not selected:
            messagebox.showinfo("현장 프로필", "삭제할 저장 현장을 선택하세요.")
            return
        if not messagebox.askyesno("현장 프로필 삭제", f"{selected} 현장 프로필을 삭제할까요?"):
            return
        self.field_profiles = [item for item in self.field_profiles if self._profile_display_name(item) != selected]
        self._write_field_profiles(); self._refresh_field_profile_choices(); self._new_field_profile()

    def _status_tab(self):
        tab=self._new_page("수집기 현황")
        top=ttk.Frame(tab); top.pack(fill="x")
        ttk.Button(top,text="새로고침",command=self.refresh_status).pack(side="left")
        ttk.Label(top,text="현재 연결 네트워크는 수집기 heartbeat와 보고서에 함께 기록됩니다.").pack(side="left",padx=(12,0))
        self.summary=tk.Text(tab,height=13,wrap="word",state="disabled",font=("monospace",10)); self.summary.pack(fill="both",expand=True,pady=(10,0))

    def _source_tab(self):
        tab=self._new_page("수집 소스")
        self.source_tree=ttk.Treeview(tab,columns=("source","state","evidence","endpoint"),show="headings",height=15)
        for key,title,width in (("source","수집 원천",190),("state","상태",115),("evidence","판단 근거",310),("endpoint","포트 / 대상",150)):
            self.source_tree.heading(key,text=title); self.source_tree.column(key,width=width,anchor="w")
        self.source_tree.pack(fill="both",expand=True)
        self.source_observed=tk.StringVar(value="진단 스냅샷을 저장하면 수집 원천 상태가 표시됩니다.")
        ttk.Label(tab,textvariable=self.source_observed).pack(anchor="w",pady=(8,0))

    def _update_source_status(self, payload):
        for row in self.source_tree.get_children(): self.source_tree.delete(row)
        if not isinstance(payload,dict):
            self.source_observed.set("수집 원천 상태를 불러오지 못했습니다.")
            return
        labels={
            "syslog":"Syslog", "snmp_polling":"SNMP Polling", "snmp_trap":"SNMP Trap",
            "lldp_discovery":"LLDP 이웃", "cdp_discovery":"CDP 이웃",
            "netflow":"NetFlow", "ipfix":"IPFIX", "sflow":"sFlow",
            "dhcp_dns_observation":"DHCP / DNS", "active_probes":"능동 진단",
            "omada_api":"Omada API", "endpoint_collector":"수집기 에이전트",
        }
        states={"active":"수집 중","available":"사용 가능","configured":"설정됨","partial":"일부 가능","unconfigured":"미설정","unavailable":"미수집","unknown":"미확인"}
        for key,value in payload.items():
            if key in ("schema_version","observed_at") or not isinstance(value,dict):
                continue
            endpoint=value.get("port") or value.get("target_count") or "-"
            if value.get("port"): endpoint=f"UDP/TCP {value['port']}"
            elif value.get("target_count") is not None: endpoint=f"대상 {value.get('target_count',0)} · 응답 {value.get('target_up_count',0)}"
            self.source_tree.insert("","end",values=(labels.get(key,key),states.get(value.get("state"),value.get("state") or "미확인"),value.get("source") or "-",endpoint))
        observed=str(payload.get("observed_at") or "").replace("T"," ").replace("Z","")
        self.source_observed.set(f"원천 상태 측정시각: {observed or '미확인'}")

    def _live_monitor_tab(self):
        tab=self._new_page("실시간 모니터링")
        controls=ttk.Frame(tab); controls.pack(fill="x")
        ttk.Label(controls,text="인터페이스").pack(side="left")
        self.live_interface_box=ttk.Combobox(controls,textvariable=self.live_monitor_interface,state="readonly",width=18)
        self.live_interface_box.pack(side="left",padx=(7,12))
        ttk.Button(controls,text="시작",style="Accent.TButton",command=self.start_live_monitor).pack(side="left")
        ttk.Button(controls,text="일시정지",command=self.stop_live_monitor).pack(side="left",padx=5)
        ttk.Label(controls,textvariable=self.live_monitor_status).pack(side="right")

        metrics=ttk.LabelFrame(tab,text="현재 트래픽",padding=12); metrics.pack(fill="x",pady=(12,0))
        self.live_metric_vars={}
        definitions=(
            ("rx_mbps","수신 속도"),("tx_mbps","송신 속도"),("rx_pps","수신 패킷"),("tx_pps","송신 패킷"),
            ("errors","누적 오류"),("drops","누적 드롭"),("gateway_latency","게이트웨이 지연"),("connections","활성 연결"),
        )
        for index,(key,label) in enumerate(definitions):
            block=ttk.Frame(metrics,style="Surface.TFrame",padding=(8,4))
            block.grid(row=index//4,column=index%4,sticky="ew",padx=4,pady=4)
            variable=tk.StringVar(value="-"); self.live_metric_vars[key]=variable
            ttk.Label(block,text=label,style="MetricLabel.TLabel").pack(anchor="w")
            ttk.Label(block,textvariable=variable,style="MetricValue.TLabel").pack(anchor="w",pady=(2,0))
        for column in range(4): metrics.columnconfigure(column,weight=1)

        network=ttk.LabelFrame(tab,text="링크 및 주소",padding=10); network.pack(fill="x",pady=(10,0))
        self.live_network=tk.StringVar(value="인터페이스를 선택하면 현재 주소와 링크 상태가 표시됩니다.")
        ttk.Label(network,textvariable=self.live_network).pack(anchor="w")

        neighbors=ttk.LabelFrame(tab,text="LLDP / CDP 이웃",padding=8); neighbors.pack(fill="both",expand=True,pady=(10,0))
        self.live_neighbor_tree=ttk.Treeview(neighbors,columns=("protocol","local","device","management","port","age"),show="headings",height=7)
        for key,title,width in (("protocol","프로토콜",85),("local","로컬 포트",120),("device","장비명",190),("management","관리 IP",140),("port","상대 포트",170),("age","관측 경과",130)):
            self.live_neighbor_tree.heading(key,text=title); self.live_neighbor_tree.column(key,width=width,anchor="w")
        self.live_neighbor_tree.pack(fill="both",expand=True)

    def start_live_monitor(self):
        if not self.live_monitor_interface.get():
            self.refresh_interfaces()
        if not self.live_monitor_interface.get():
            messagebox.showerror("인터페이스 없음","모니터링할 네트워크 인터페이스가 없습니다.")
            return
        self.live_monitor_enabled=True
        self.live_monitor_previous=None
        self.live_monitor_previous_at=None
        self.live_monitor_status.set("실시간 모니터링 시작")
        self.refresh_live_monitor()

    def stop_live_monitor(self):
        self.live_monitor_enabled=False
        if self.live_monitor_after_id:
            self.root.after_cancel(self.live_monitor_after_id)
            self.live_monitor_after_id=None
        self.live_monitor_status.set("모니터링 일시정지")

    def refresh_live_monitor(self):
        if not self.live_monitor_enabled or self.live_monitor_in_flight:
            return
        interface=self.live_monitor_interface.get().strip()
        if not interface:
            return
        self.live_monitor_in_flight=True
        self.running_jobs+=1
        threading.Thread(target=self._live_monitor_worker,args=(interface,),daemon=True).start()

    def _live_monitor_worker(self, interface):
        try:
            observed_monotonic=time.monotonic()
            counters=read_interface_counters(interface)
            elapsed=observed_monotonic-self.live_monitor_previous_at if self.live_monitor_previous_at else 0
            rates=calculate_interface_rates(self.live_monitor_previous,counters,elapsed)
            address_result=subprocess.run(["ip","-j","address","show","dev",interface],capture_output=True,text=True,timeout=3)
            address_payload=json.loads(address_result.stdout or "[]")
            addresses=[]
            if address_payload:
                addresses=[f"{row.get('local')}/{row.get('prefixlen')}" for row in address_payload[0].get("addr_info",[]) if row.get("family") in ("inet","inet6") and row.get("local")]
            route_result=subprocess.run(["ip","-j","-4","route","show","default"],capture_output=True,text=True,timeout=3)
            routes=json.loads(route_result.stdout or "[]")
            gateway=next((row.get("gateway") for row in routes if row.get("dev")==interface and row.get("gateway")),None)
            latency=None
            if gateway:
                ping=subprocess.run(["ping","-c","1","-W","1",gateway],capture_output=True,text=True,timeout=3)
                match=re.search(r"time[=<]([0-9.]+)\s*ms",ping.stdout)
                latency=float(match.group(1)) if match else None
            discovery=subprocess.run(["lldpcli","-f","json","show","neighbors","details"],capture_output=True,text=True,timeout=4)
            neighbors=parse_discovery_neighbors(discovery.stdout)
            connections=subprocess.run(["ss","-H","-tun","state","established"],capture_output=True,text=True,timeout=3)
            link_state=(Path("/sys/class/net")/interface/"operstate").read_text(encoding="ascii").strip()
            sample={
                "observed_at":datetime.now().astimezone().isoformat(timespec="seconds"),
                "observed_monotonic":observed_monotonic,
                "interface":interface,"link_state":link_state,"addresses":addresses,"gateway":gateway,
                "gateway_latency_ms":latency,"connections":len([line for line in connections.stdout.splitlines() if line.strip()]),
                "counters":counters,"rates":rates,"neighbors":neighbors,
            }
            self.events.put(("실시간 모니터링",0,json.dumps(sample,ensure_ascii=False)))
        except Exception as exc:
            self.events.put(("실시간 모니터링",1,str(exc)))

    def _update_live_monitor(self, sample):
        rates=sample.get("rates") or {}; counters=sample.get("counters") or {}
        self.live_metric_vars["rx_mbps"].set(f"{rates.get('rx_mbps',0):.3f} Mbps")
        self.live_metric_vars["tx_mbps"].set(f"{rates.get('tx_mbps',0):.3f} Mbps")
        self.live_metric_vars["rx_pps"].set(f"{rates.get('rx_pps',0):.1f} pps")
        self.live_metric_vars["tx_pps"].set(f"{rates.get('tx_pps',0):.1f} pps")
        self.live_metric_vars["errors"].set(str(counters.get("rx_errors",0)+counters.get("tx_errors",0)))
        self.live_metric_vars["drops"].set(str(counters.get("rx_dropped",0)+counters.get("tx_dropped",0)))
        latency=sample.get("gateway_latency_ms")
        self.live_metric_vars["gateway_latency"].set(f"{latency:.2f} ms" if isinstance(latency,(int,float)) else "응답 없음")
        self.live_metric_vars["connections"].set(str(sample.get("connections",0)))
        addresses=", ".join(sample.get("addresses") or []) or "주소 없음"
        self.live_network.set(f"{sample.get('interface')} · 링크 {sample.get('link_state')} · {addresses} · 게이트웨이 {sample.get('gateway') or '미확인'}")
        for row in self.live_neighbor_tree.get_children(): self.live_neighbor_tree.delete(row)
        for neighbor in sample.get("neighbors") or []:
            self.live_neighbor_tree.insert("","end",values=(neighbor.get("protocol"),neighbor.get("local_interface"),neighbor.get("device"),neighbor.get("management_ip"),neighbor.get("port"),neighbor.get("age")))
        self.live_monitor_previous=sample.get("counters")
        self.live_monitor_previous_at=sample.get("observed_monotonic")
        self.live_monitor_status.set(f"갱신 {sample.get('observed_at')} · 이웃 {len(sample.get('neighbors') or [])}대")

    def _snmp_tab(self):
        tab=self._new_page("SNMP 장비")
        settings=ttk.LabelFrame(tab,text="기본 설정",padding=10); settings.pack(fill="x")
        for col,(label,var,width) in enumerate((("버전",self.version,6),("포트",self.port,8),("시간초과(초)",self.timeout,8),("재시도",self.retries,6))):
            ttk.Label(settings,text=label).grid(row=0,column=col*2,sticky="w",padx=(0,4)); ttk.Entry(settings,textvariable=var,width=width).grid(row=0,column=col*2+1,padx=(0,12))
        ttk.Label(settings,textvariable=self.community_state).grid(row=1,column=0,columnspan=3,sticky="w",pady=(10,0))
        ttk.Button(settings,text="설정 불러오기",command=self.load_snmp).grid(row=1,column=4,pady=(8,0))
        ttk.Button(settings,text="기본값 저장",command=self.save_defaults).grid(row=1,column=5,pady=(8,0),padx=4)
        ttk.Button(settings,text="Community 변경",command=self.change_community).grid(row=1,column=6,columnspan=2,pady=(8,0))
        devices=ttk.LabelFrame(tab,text="관리 장비",padding=8); devices.pack(fill="both",expand=True,pady=(10,0))
        self.tree=ttk.Treeview(devices,columns=("name","host","role"),show="headings",height=12)
        for key,title,w in (("name","장비명",260),("host","IP / 호스트",180),("role","역할",160)):
            self.tree.heading(key,text=title); self.tree.column(key,width=w,anchor="w")
        self.tree.pack(fill="both",expand=True)
        bar=ttk.Frame(devices); bar.pack(fill="x",pady=(8,0))
        ttk.Button(bar,text="장비 추가",command=self.add_target).pack(side="left")
        ttk.Button(bar,text="선택 삭제",command=self.remove_target).pack(side="left",padx=5)
        ttk.Button(bar,text="지금 수집",command=lambda:self.privileged([NODE,COLLECTOR,"edge-analysis"])).pack(side="right")

    def _diag_tab(self):
        tab=self._new_page("네트워크 진단")
        top=ttk.Frame(tab); top.pack(fill="x"); ttk.Label(top,text="대상").pack(side="left"); ttk.Entry(top,textvariable=self.target,width=28).pack(side="left",padx=8)
        buttons=ttk.Frame(tab); buttons.pack(fill="x",pady=8)
        for i,label in enumerate(COMMANDS): ttk.Button(buttons,text=label,command=lambda x=label:self.run_diag(x)).grid(row=i//5,column=i%5,padx=3,pady=3,sticky="ew")
        ttk.Button(buttons,text="전체 ARP 검색",command=self.arp_scan).grid(row=1,column=4,padx=3,pady=3,sticky="ew")
        for i in range(5): buttons.columnconfigure(i,weight=1)
        self.output=tk.Text(tab,wrap="none",state="disabled",font=("monospace",10)); self.output.pack(fill="both",expand=True)
        bottom=ttk.Frame(tab); bottom.pack(fill="x",pady=(6,0))
        ttk.Button(bottom,text="결과 지우기",command=lambda:self._set_text(self.output,"")).pack(side="left")
        ttk.Button(bottom,text="결과 저장",command=self.save_result).pack(side="left",padx=5)

    def _wireless_tab(self):
        tab=self._new_page("무선 분석")
        top=ttk.Frame(tab); top.pack(fill="x")
        ttk.Button(top,text="주변 AP 스캔",command=self.refresh_wireless).pack(side="left")
        ttk.Checkbutton(top,text="숨김 SSID만 보기",variable=self.wireless_hidden_only,command=self.render_wireless).pack(side="left",padx=10)
        ttk.Button(top,text="결과 저장",command=self.save_wireless_result).pack(side="right")
        self.wireless_summary=tk.StringVar(value="주변 AP 스캔을 실행하면 숨김 SSID, 신호 품질과 채널 혼잡도를 분석합니다.")
        ttk.Label(tab,textvariable=self.wireless_summary).pack(anchor="w",pady=(8,0))
        frame=ttk.LabelFrame(tab,text="주변 무선 네트워크",padding=8); frame.pack(fill="both",expand=True,pady=(8,0))
        columns=("active","ssid","hidden","bssid","band","channel","frequency","signal","quality","security")
        self.wireless_tree=ttk.Treeview(frame,columns=columns,show="headings",height=12)
        headings=(
            ("active","현재",58),("ssid","SSID",190),("hidden","숨김",58),("bssid","BSSID",150),
            ("band","대역",80),("channel","채널",55),("frequency","주파수",90),("signal","신호",65),
            ("quality","품질",78),("security","보안",140),
        )
        for key,title,width in headings:
            self.wireless_tree.heading(key,text=title); self.wireless_tree.column(key,width=width,anchor="w")
        self.wireless_tree.pack(fill="both",expand=True)
        analysis=ttk.LabelFrame(tab,text="신호·채널 분석",padding=8); analysis.pack(fill="x",pady=(8,0))
        self.wireless_analysis=tk.Text(analysis,height=7,wrap="word",state="disabled",font=("monospace",10)); self.wireless_analysis.pack(fill="x")

    def refresh_wireless(self):
        self.async_run("무선 분석",[GUI_OPS,"wireless-scan"],timeout=45)

    def render_wireless(self):
        if not self.wireless_payload:
            return
        payload=self.wireless_payload
        for row in self.wireless_tree.get_children(): self.wireless_tree.delete(row)
        access_points=payload.get("access_points",[]) if isinstance(payload,dict) else []
        hidden_only=self.wireless_hidden_only.get()
        for access_point in access_points:
            if hidden_only and not access_point.get("hidden"):
                continue
            ssid=access_point.get("ssid") or "(숨김 SSID)"
            frequency=access_point.get("frequency_mhz")
            self.wireless_tree.insert("","end",values=(
                "연결중" if access_point.get("active") else "", ssid,
                "숨김" if access_point.get("hidden") else "", access_point.get("bssid") or "-",
                access_point.get("band") or "미확인", access_point.get("channel") or "-",
                f"{frequency} MHz" if frequency else "-", f"{access_point.get('signal_pct',0)}%",
                access_point.get("quality") or "미확인", access_point.get("security") or "개방형",
            ))
        if not payload.get("available"):
            self.wireless_summary.set(f"무선 스캔 불가: {payload.get('reason','원인을 확인하세요.')}")
            self._set_text(self.wireless_analysis,payload.get("reason","") + "\n")
            return
        summary=payload.get("summary") or {}
        bands=", ".join(f"{band} {count}개" for band,count in (summary.get("band_counts") or {}).items()) or "없음"
        self.wireless_summary.set(f"AP {summary.get('total_access_points',0)}개 · 숨김 SSID {summary.get('hidden_access_points',0)}개 · 대역: {bands}")
        lines=["[채널 혼잡도]"]
        for item in (summary.get("channel_load") or [])[:10]:
            lines.append(f"- {item.get('band')} ch.{item.get('channel')}: {item.get('network_count')}개 / 강한 신호 {item.get('strong_network_count')}개 / {item.get('level')}")
        lines.append("\n[권장 조치]")
        lines.extend(f"- {item}" for item in (summary.get("recommendations") or []))
        self._set_text(self.wireless_analysis,"\n".join(lines) + "\n")

    def save_wireless_result(self):
        if not self.wireless_payload:
            messagebox.showinfo("무선 분석","저장할 스캔 결과가 없습니다.")
            return
        folder=Path.home() / "Documents" / "METRO-NMS"; folder.mkdir(parents=True,exist_ok=True)
        path=folder / f"wireless-scan-{datetime.now():%Y%m%d-%H%M%S}.json"
        path.write_text(json.dumps(self.wireless_payload,ensure_ascii=False,indent=2) + "\n",encoding="utf-8")
        os.chmod(path,0o600)
        messagebox.showinfo("무선 분석",f"저장 완료: {path}")

    def _measurement_tab(self):
        tab=self._new_page("측정 세션")
        controls=ttk.LabelFrame(tab,text="반복 측정 설정",padding=10); controls.pack(fill="x")
        ttk.Label(controls,text="측정시간").grid(row=0,column=0,sticky="w")
        ttk.Spinbox(controls,from_=1,to=28800,textvariable=self.measurement_value,width=8).grid(row=0,column=1,padx=(5,3))
        ttk.Combobox(controls,textvariable=self.measurement_unit,state="readonly",width=7,values=("초","분","시간")).grid(row=0,column=2,padx=(0,15))
        ttk.Label(controls,text="측정간격(초)").grid(row=0,column=3,sticky="w")
        ttk.Spinbox(controls,from_=2,to=300,textvariable=self.measurement_interval,width=8).grid(row=0,column=4,padx=5)
        ttk.Button(controls,text="측정 시작",command=self.start_measurement).grid(row=0,column=5,padx=(12,4))
        ttk.Label(controls,text="게이트웨이·국내 KT DNS·해외 Google DNS, CPU·메모리·디스크, 인터페이스 송수신 속도를 반복 측정합니다.").grid(row=1,column=0,columnspan=6,sticky="w",pady=(9,0))
        ttk.Label(controls,text="결과는 먼저 이 수집기에 저장되고, 중앙 NMS 연결 시 단위·측정시각·시도/성공/실패 수와 최소·평균·최대값으로 전송됩니다.").grid(row=2,column=0,columnspan=6,sticky="w",pady=(4,0))
        ttk.Label(controls,textvariable=self.active_profile_label).grid(row=3,column=0,columnspan=5,sticky="w",pady=(8,0))
        ttk.Button(controls,text="현장 프로필",command=lambda:self.show_page("현장 프로필")).grid(row=3,column=5,sticky="e",pady=(8,0))
        self.measurement_output=tk.Text(tab,wrap="none",state="disabled",font=("monospace",10)); self.measurement_output.pack(fill="both",expand=True,pady=(10,0))

    def measurement_seconds(self):
        try: value=int(self.measurement_value.get()); interval=int(self.measurement_interval.get())
        except ValueError: return None, None
        multiplier={"초":1,"분":60,"시간":3600}.get(self.measurement_unit.get(),60)
        return value*multiplier, interval

    def start_measurement(self):
        duration,interval=self.measurement_seconds()
        if duration is None or not 10 <= duration <= 28800: messagebox.showerror("입력 오류","측정시간은 10초~8시간입니다."); return
        if not 2 <= interval <= 300: messagebox.showerror("입력 오류","측정간격은 2~300초입니다."); return
        if duration//interval+1 > 2000: messagebox.showerror("입력 오류","측정 표본은 최대 2,000회입니다. 간격을 늘리세요."); return
        profile = self._field_profile_from_form()
        if not profile:
            self.show_page("현장 프로필")
            return
        if not messagebox.askyesno("측정 시작",f"{profile['site_name']}에서 {duration}초 동안 {interval}초 간격으로 측정할까요?"): return
        self.pending_measurement_profile = profile
        self.privileged(
            [NODE,COLLECTOR,"measurement-session",str(duration),str(interval),"--field-profile-stdin"],
            json.dumps(profile, ensure_ascii=False),
            label="측정 세션",
            timeout=duration+180
        )

    def _offline_queue_tab(self):
        tab=self._new_page("저장/전송")
        ttk.Label(tab,text="중앙 NMS 연결이 실패한 측정은 로컬에 보존되며, 연결이 돌아오면 여기에서 재전송할 수 있습니다.").pack(anchor="w")
        frame=ttk.Frame(tab); frame.pack(fill="both",expand=True,pady=(10,0))
        self.queue_tree=ttk.Treeview(frame,columns=("state","kind","site","queued","attempts","error"),show="headings",height=14)
        for key,title,width in (("state","상태",90),("kind","종류",105),("site","현장",180),("queued","측정/저장 시각",165),("attempts","시도",55),("error","최근 결과",350)):
            self.queue_tree.heading(key,text=title); self.queue_tree.column(key,width=width,anchor="w")
        self.queue_tree.pack(fill="both",expand=True)
        bar=ttk.Frame(tab); bar.pack(fill="x",pady=(8,0))
        ttk.Button(bar,text="목록 새로고침",command=self.refresh_offline_queue).pack(side="left")
        ttk.Button(bar,text="미전송 결과 전송",command=self.flush_offline_queue).pack(side="left",padx=5)
        self.queue_status=tk.StringVar(value="목록 새로고침을 눌러 전송 대기 결과를 확인하세요.")
        ttk.Label(bar,textvariable=self.queue_status).pack(side="right")

    def refresh_offline_queue(self):
        self.privileged([NODE,COLLECTOR,"offline-measurements","list"],label="오프라인 큐 조회")

    def flush_offline_queue(self):
        self.privileged([NODE,COLLECTOR,"offline-measurements","flush"],label="미전송 결과 전송",timeout=180)
        self.retry_ict_queue()

    def retry_ict_queue(self):
        self.running_jobs += 1
        def worker():
            try:
                result = self._ict_client().retry_queue()
                self.events.put(("119 대기자료 전송", 0, json.dumps(result, ensure_ascii=False)))
            except Exception as exc:
                self.events.put(("119 대기자료 전송", 1, str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def sync_ict_profile(self, profile, evidence):
        if not profile or not profile.get("site_id"):
            return
        self.running_jobs += 1
        def worker():
            try:
                collected_at = evidence.get("observed_at") or evidence.get("started_at")
                result = self._ict_client().store_profile(
                    int(profile["site_id"]),
                    {
                        "field_profile": profile,
                        "evidence": evidence,
                        "missing_value_policy": {
                            "missing": "없음",
                            "not_tested": "테스트 안 됨",
                            "stale": "과거 측정값",
                        },
                    },
                    collected_at,
                )
                self.events.put(("119 현장 프로필 송신", 0, json.dumps(result, ensure_ascii=False)))
            except Exception as exc:
                self.events.put(("119 현장 프로필 송신", 1, str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def create_snapshot(self, send_immediately=False):
        profile = self._field_profile_from_form()
        if not profile:
            self.show_page("현장 프로필")
            return
        action = "저장 후 중앙으로 송신" if send_immediately else "로컬 대기열에 저장"
        if not messagebox.askyesno("현장 진단 스냅샷", f"{profile['site_name']}의 현재 진단값을 {action}할까요?"):
            return
        command = [NODE, COLLECTOR, "snapshot-session", "--field-profile-stdin"]
        if send_immediately:
            command.append("--send")
        self.pending_snapshot_profile = profile
        self.privileged(
            command,
            json.dumps(profile, ensure_ascii=False),
            label="진단 스냅샷 저장/송신" if send_immediately else "진단 스냅샷 저장",
            timeout=180,
        )

    def refresh_all(self):
        if self.refresh_batch_pending:
            return
        self.refresh_batch_pending = {"현황", "VPN 목록", "무선 분석", "오프라인 큐 조회"}
        self.refresh_batch_errors = 0
        self.refresh_all_button.configure(state="disabled")
        self.status.set("전체 새로고침 중")
        self.refresh_services()
        self.refresh_status()
        self.refresh_vpn()
        self.refresh_wireless()
        self.refresh_offline_queue()

    def _capture_tab(self):
        tab=self._new_page("패킷 캡처")
        controls=ttk.LabelFrame(tab,text="실시간 캡처",padding=10); controls.pack(fill="x")
        ttk.Label(controls,text="인터페이스").grid(row=0,column=0,sticky="w")
        self.interface_box=ttk.Combobox(controls,textvariable=self.interface,state="readonly",width=18); self.interface_box.grid(row=0,column=1,padx=(5,15))
        ttk.Label(controls,text="종류").grid(row=0,column=2,sticky="w")
        ttk.Combobox(controls,textvariable=self.capture_profile,state="readonly",width=16,values=tuple(CAPTURE_PROFILES)).grid(row=0,column=3,padx=(5,15))
        ttk.Label(controls,text="최대 시간(분)").grid(row=0,column=4,sticky="w")
        ttk.Spinbox(controls,from_=1,to=30,textvariable=self.live_capture_minutes,width=7).grid(row=0,column=5,padx=5)
        self.live_start_button=ttk.Button(controls,text="실시간 시작",style="Accent.TButton",command=self.start_live_capture)
        self.live_start_button.grid(row=0,column=6,padx=(12,4))
        self.live_stop_button=ttk.Button(controls,text="중지",command=self.stop_live_capture,state="disabled")
        self.live_stop_button.grid(row=0,column=7)
        ttk.Label(controls,textvariable=self.live_capture_status).grid(row=1,column=0,columnspan=8,sticky="w",pady=(8,0))

        live=ttk.LabelFrame(tab,text="실시간 패킷 헤더",padding=8); live.pack(fill="both",expand=True,pady=(10,0))
        self.live_capture_tree=ttk.Treeview(live,columns=("time","source","destination","protocol","length","info"),show="headings",height=9)
        for key,title,width in (("time","시각",105),("source","출발지",155),("destination","목적지",155),("protocol","프로토콜",90),("length","길이",65),("info","요약",310)):
            self.live_capture_tree.heading(key,text=title); self.live_capture_tree.column(key,width=width,anchor="w")
        self.live_capture_tree.pack(fill="both",expand=True)

        batch=ttk.LabelFrame(tab,text="단기 캡처 및 저장파일",padding=8); batch.pack(fill="x",pady=(10,0))
        ttk.Label(batch,text="시간(초)").pack(side="left")
        ttk.Spinbox(batch,from_=5,to=120,textvariable=self.capture_seconds,width=7).pack(side="left",padx=5)
        ttk.Button(batch,text="단기 캡처",command=self.start_capture).pack(side="left")
        ttk.Button(batch,text="저장 목록",command=self.list_captures).pack(side="left",padx=5)
        ttk.Button(batch,text="선택 경로 요약",command=self.summarize_capture).pack(side="right")
        self.capture_output=tk.Text(tab,height=5,wrap="none",state="disabled",font=("monospace",9)); self.capture_output.pack(fill="x",pady=(8,0))
        self.refresh_interfaces()

    def _vpn_tab(self):
        tab=self._new_page("VPN")
        top=ttk.Frame(tab); top.pack(fill="x")
        ttk.Button(top,text="OpenVPN 가져오기",command=lambda:self.import_vpn("openvpn")).pack(side="left")
        ttk.Button(top,text="WireGuard 가져오기",command=lambda:self.import_vpn("wireguard")).pack(side="left",padx=5)
        ttk.Button(top,text="새로고침",command=self.refresh_vpn).pack(side="right")
        frame=ttk.LabelFrame(tab,text="등록된 VPN",padding=8); frame.pack(fill="both",expand=True,pady=(10,0))
        self.vpn_tree=ttk.Treeview(frame,columns=("name","type","state","uuid"),show="headings",height=10)
        for key,title,width in (("name","연결 이름",250),("type","종류",110),("state","상태",130),("uuid","식별자",300)):
            self.vpn_tree.heading(key,text=title); self.vpn_tree.column(key,width=width,anchor="w")
        self.vpn_tree.pack(fill="both",expand=True)
        actions=ttk.Frame(frame); actions.pack(fill="x",pady=(8,0))
        ttk.Button(actions,text="연결",command=lambda:self.vpn_action("vpn-up")).pack(side="left")
        ttk.Button(actions,text="연결 해제",command=lambda:self.vpn_action("vpn-down")).pack(side="left",padx=5)
        ttk.Button(actions,text="상세 정보",command=lambda:self.vpn_action("vpn-details",privileged=False)).pack(side="left")
        ttk.Button(actions,text="설정 편집",command=self.edit_vpn).pack(side="left",padx=5)
        ttk.Button(actions,text="삭제",command=lambda:self.vpn_action("vpn-delete",confirm=True)).pack(side="right")
        self.vpn_output=tk.Text(tab,height=8,wrap="word",state="disabled",font=("monospace",10)); self.vpn_output.pack(fill="x",pady=(10,0))
        ttk.Label(tab,text="VPN 키와 비밀번호는 NetworkManager 또는 시스템 WireGuard가 관리하며 이 화면에는 표시하지 않습니다.").pack(anchor="w",pady=(6,0))
        self.refresh_vpn()

    def _service_tab(self):
        tab=self._new_page("서비스")
        self.service_tree=ttk.Treeview(tab,columns=("label","unit","state"),show="headings")
        for k,t,w in (("label","기능",220),("unit","서비스",360),("state","상태",130)): self.service_tree.heading(k,text=t); self.service_tree.column(k,width=w,anchor="w")
        self.service_tree.pack(fill="both",expand=True)
        bar=ttk.Frame(tab); bar.pack(fill="x",pady=8)
        ttk.Button(bar,text="상태 새로고침",command=self.refresh_services).pack(side="left")
        ttk.Button(bar,text="선택 재시작",command=self.restart_service).pack(side="left",padx=5)

    def async_run(self,label,cmd,input_text=None,timeout=120):
        self.running_jobs += 1
        self.status.set(f"실행 중: {label}")
        threading.Thread(target=self._worker,args=(label,cmd,input_text,timeout),daemon=True).start()
    def _worker(self,label,cmd,input_text,timeout):
        try:
            p=subprocess.run(cmd,input=input_text,capture_output=True,text=True,timeout=timeout,env={**os.environ,"NMS_DIAG_TARGET":self.target.get().strip()})
            self.events.put((label,p.returncode,p.stdout+p.stderr))
        except Exception as e: self.events.put((label,1,str(e)))
    def privileged(self,cmd,input_text=None,label="관리자 작업",timeout=120):
        self.async_run(label,["pkexec",*cmd],input_text,timeout)
    def refresh_status(self):
        cmd=["bash","-lc",NETWORK_STATUS_COMMAND]
        self.async_run("현황",cmd)
    def load_snmp(self): self.privileged([HELPER,"show-json"],label="SNMP 설정 조회")
    def save_defaults(self): self.privileged([HELPER,"defaults",self.version.get(),self.port.get(),self.timeout.get(),self.retries.get()],label="SNMP 기본값 저장")
    def change_community(self):
        value=simpledialog.askstring("SNMP Community","읽기 전용 Community를 입력하세요.",show="*")
        if value: self.privileged([HELPER,"community","--stdin"],value+"\n","Community 변경")
    def add_target(self):
        name=simpledialog.askstring("장비 추가","장비명")
        if not name:return
        host=simpledialog.askstring("장비 추가","IP 주소 또는 호스트명")
        if not host or not valid_host(host): messagebox.showerror("입력 오류","올바른 IP 주소 또는 호스트명을 입력하세요."); return
        role=simpledialog.askstring("장비 추가","역할 (예: core_switch)",initialvalue="switch") or "switch"
        self.privileged([HELPER,"add",name.strip(),host.strip(),role.strip()],label="SNMP 장비 추가")
    def remove_target(self):
        item=self.tree.focus()
        if not item:return
        host=self.tree.item(item,"values")[1]
        if messagebox.askyesno("장비 삭제",f"{host} 장비를 삭제할까요?"): self.privileged([HELPER,"remove",host],label="SNMP 장비 삭제")
    def run_diag(self,label):
        if label in ("경로 추적","포트 점검") and not valid_host(self.target.get()): messagebox.showerror("입력 오류","진단 대상 IP/호스트를 확인하세요."); return
        self.async_run(label,["bash","-lc",COMMANDS[label]])
    def refresh_interfaces(self):
        p=subprocess.run(["bash","-lc","ip -o link show | awk -F': ' '$2 !~ /^lo/ {print $2}' | sed 's/@.*//'"],capture_output=True,text=True)
        values=tuple(x for x in p.stdout.splitlines() if x)
        self.interface_box["values"]=values
        self.live_interface_box["values"]=values
        route=subprocess.run(["bash","-lc","ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1);exit}}'"],capture_output=True,text=True)
        preferred=route.stdout.strip() if route.stdout.strip() in values else (values[0] if values else "")
        if preferred and self.interface.get() not in values:self.interface.set(preferred)
        if preferred and self.live_monitor_interface.get() not in values:self.live_monitor_interface.set(preferred)
    def arp_scan(self):
        if not self.interface.get(): messagebox.showerror("인터페이스 없음","사용할 네트워크 인터페이스가 없습니다."); return
        self.privileged([GUI_OPS,"arp-scan",self.interface.get()],label="전체 ARP 검색")
    def start_capture(self):
        try: seconds=int(self.capture_seconds.get())
        except ValueError: seconds=0
        if not 5 <= seconds <= 120: messagebox.showerror("입력 오류","캡처 시간은 5~120초입니다."); return
        if not self.interface.get(): messagebox.showerror("인터페이스 없음","캡처 인터페이스를 선택하세요."); return
        self.privileged([GUI_OPS,"capture",self.interface.get(),CAPTURE_PROFILES[self.capture_profile.get()],str(seconds)],label="패킷 캡처")

    def start_live_capture(self):
        if self.live_capture_process and self.live_capture_process.poll() is None:
            messagebox.showinfo("실시간 캡처","이미 캡처가 실행 중입니다.")
            return
        if not self.interface.get():
            messagebox.showerror("인터페이스 없음","캡처 인터페이스를 선택하세요.")
            return
        try: minutes=int(self.live_capture_minutes.get())
        except ValueError: minutes=0
        if not 1 <= minutes <= 30:
            messagebox.showerror("입력 오류","실시간 캡처 시간은 1~30분입니다.")
            return
        profile=CAPTURE_PROFILES.get(self.capture_profile.get())
        if not profile:
            messagebox.showerror("입력 오류","캡처 종류를 확인하세요.")
            return
        for row in self.live_capture_tree.get_children(): self.live_capture_tree.delete(row)
        self.live_capture_packet_count=0
        self.live_capture_path=None
        command=["pkexec",GUI_OPS,"live-capture",self.interface.get(),profile,str(minutes*60)]
        try:
            self.live_capture_process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1,start_new_session=True)
        except OSError as exc:
            messagebox.showerror("실시간 캡처",str(exc)); return
        self.running_jobs+=1
        self.live_start_button.configure(state="disabled")
        self.live_stop_button.configure(state="normal")
        self.live_capture_status.set(f"인증 대기 또는 캡처 시작 중 · 최대 {minutes}분 / 50MB")
        threading.Thread(target=self._live_capture_worker,args=(self.live_capture_process,),daemon=True).start()

    def _live_capture_worker(self, process):
        try:
            batch=[]
            flush_at=time.monotonic()+0.2
            for line in process.stdout or ():
                batch.append(line.rstrip("\n"))
                if len(batch)>=100 or time.monotonic()>=flush_at:
                    self.events.put(("실시간 캡처 스트림",0,"\n".join(batch)))
                    batch=[]
                    flush_at=time.monotonic()+0.2
            if batch:
                self.events.put(("실시간 캡처 스트림",0,"\n".join(batch)))
            return_code=process.wait()
            self.events.put(("실시간 캡처 완료",return_code,""))
        except Exception as exc:
            self.events.put(("실시간 캡처 완료",1,str(exc)))

    def stop_live_capture(self):
        process=self.live_capture_process
        if not process or process.poll() is not None:
            return
        self.live_capture_status.set("캡처 종료 중")
        try: os.killpg(process.pid,signal.SIGINT)
        except (OSError,ProcessLookupError): process.terminate()

    def _handle_live_capture_line(self, line):
        if line.startswith("#META\t"):
            parts=line.split("\t")
            self.live_capture_path=parts[1] if len(parts)>1 else None
            self.live_capture_status.set(f"수집 중 · 0패킷 · {self.live_capture_path or '파일 준비 중'}")
            return
        if line.startswith("#DONE\t"):
            parts=line.split("\t")
            self.live_capture_path=parts[1] if len(parts)>1 else self.live_capture_path
            return
        fields=line.split("\t")
        if len(fields)<11 or not fields[0].isdigit():
            if line.strip(): self.live_capture_status.set(f"캡처 준비: {line[:120]}")
            return
        try: timestamp=datetime.fromtimestamp(float(fields[1])).strftime("%H:%M:%S.%f")[:-3]
        except (ValueError,OverflowError): timestamp=fields[1]
        source=fields[4] or fields[5] or fields[2] or "-"
        destination=fields[6] or fields[7] or fields[3] or "-"
        self.live_capture_tree.insert("","end",values=(timestamp,source,destination,fields[8] or "-",fields[9] or "-",fields[10] or "-"))
        self.live_capture_packet_count+=1
        rows=self.live_capture_tree.get_children()
        if len(rows)>500: self.live_capture_tree.delete(rows[0])
        self.live_capture_tree.yview_moveto(1)
        self.live_capture_status.set(f"수집 중 · {self.live_capture_packet_count}패킷 · {self.live_capture_path or '파일 준비 중'}")
    def list_captures(self): self.privileged([GUI_OPS,"list-captures"],label="캡처 목록")
    def summarize_capture(self):
        try: selected=self.capture_output.get("sel.first","sel.last").strip()
        except tk.TclError: selected=""
        path=next((part for part in selected.split() if part.startswith("/var/log/nms-pcap/") and part.endswith((".pcap",".pcapng"))),"")
        if not path: messagebox.showinfo("캡처 선택","목록에서 PCAP 파일 경로를 마우스로 선택하세요."); return
        self.privileged([GUI_OPS,"summarize",path],label="캡처 요약")
    def save_result(self):
        text=self.output.get("1.0","end").strip()
        if not text:return
        folder=os.path.expanduser("~/Documents/METRO-NMS"); os.makedirs(folder,exist_ok=True)
        path=os.path.join(folder,f"diagnostics-{datetime.now():%Y%m%d-%H%M%S}.txt")
        with open(path,"w",encoding="utf-8") as f:f.write(text+"\n")
        messagebox.showinfo("저장 완료",path)
    def import_vpn(self,vpn_type):
        patterns=[("OpenVPN 설정","*.ovpn *.conf")] if vpn_type=="openvpn" else [("WireGuard 설정","*.conf")]
        path=filedialog.askopenfilename(title="VPN 설정파일 선택",filetypes=patterns+[("모든 파일","*")])
        if path:self.privileged([GUI_OPS,"vpn-import",vpn_type,path],label="VPN 가져오기")
    def refresh_vpn(self):
        self.async_run("VPN 목록",[GUI_OPS,"vpn-list"])
    def vpn_action(self,action,confirm=False,privileged=True):
        item=self.vpn_tree.focus()
        if not item: messagebox.showinfo("VPN 선택","VPN 연결을 선택하세요."); return
        name,connection_type,_,uuid=self.vpn_tree.item(item,"values")
        if action=="vpn-delete" and (uuid.startswith("wg-quick:") or connection_type=="시스템 WireGuard"):
            messagebox.showinfo("시스템 WireGuard","시스템 WireGuard 프로파일은 이 화면에서 삭제할 수 없습니다.")
            return
        if confirm and not messagebox.askyesno("VPN 삭제",f"{name} 연결을 삭제할까요?"):return
        cmd=[GUI_OPS,action,uuid]
        if privileged:self.privileged(cmd,label={"vpn-up":"VPN 연결","vpn-down":"VPN 해제","vpn-delete":"VPN 삭제"}.get(action,"VPN 작업"))
        else:self.async_run("VPN 상세",cmd)
    def edit_vpn(self):
        item=self.vpn_tree.focus()
        if not item: messagebox.showinfo("VPN 선택","VPN 연결을 선택하세요."); return
        name,connection_type,_,uuid=self.vpn_tree.item(item,"values")
        if uuid.startswith("wg-quick:") or connection_type=="시스템 WireGuard":
            messagebox.showinfo("시스템 WireGuard",f"{name}은(는) systemd wg-quick 서비스로 관리됩니다. 설정 편집은 차단되며, 연결·해제와 상세 정보만 이 화면에서 수행할 수 있습니다.")
            return
        try: subprocess.Popen(["nm-connection-editor","--edit",uuid])
        except OSError as exc: messagebox.showerror("편집기 실행 실패",str(exc))
    def refresh_services(self):
        for x in self.service_tree.get_children(): self.service_tree.delete(x)
        for label,unit in SERVICES:
            p=subprocess.run(["systemctl","is-active",unit],capture_output=True,text=True)
            self.service_tree.insert("", "end",values=(label,unit,p.stdout.strip() or "unknown"))
    def restart_service(self):
        item=self.service_tree.focus()
        if item:self.privileged(["/bin/systemctl","restart",self.service_tree.item(item,"values")[1]],label="서비스 재시작")
    def _drain(self):
        try:
            label,code,text=self.events.get_nowait()
            if label != "실시간 캡처 스트림":
                self.running_jobs=max(0,self.running_jobs-1)
            if label=="실시간 캡처 스트림":
                for stream_line in text.splitlines():
                    self._handle_live_capture_line(stream_line)
            elif label=="실시간 캡처 완료":
                self.live_capture_process=None
                self.live_start_button.configure(state="normal")
                self.live_stop_button.configure(state="disabled")
                if code in (0,130,-2,-15):
                    self.live_capture_status.set(f"캡처 완료 · {self.live_capture_packet_count}패킷 · {self.live_capture_path or '저장파일 확인'}")
                else:
                    self.live_capture_status.set(f"캡처 오류 ({code}) · {text or '권한 또는 인터페이스를 확인하세요'}")
            elif label=="실시간 모니터링":
                self.live_monitor_in_flight=False
                if code==0:
                    try: self._update_live_monitor(json.loads(text))
                    except (ValueError,json.JSONDecodeError): self.live_monitor_status.set("실시간 결과 형식 오류")
                else:
                    self.live_monitor_status.set(f"모니터링 오류: {text[:120]}")
                if self.live_monitor_enabled:
                    self.live_monitor_after_id=self.root.after(2000,self.refresh_live_monitor)
            elif label=="현황": self._set_text(self.summary,text)
            elif label=="오프라인 큐 조회":
                if code==0:
                    try:
                        payload=json.loads(text); self._update_offline_queue(payload.get("items", []))
                    except (ValueError, json.JSONDecodeError):
                        self.queue_status.set("목록 형식 오류")
                else:
                    self.queue_status.set("목록 조회 실패")
                    self._set_text(self.output,f"$ {label}\n{text}\n",append=True)
            elif label=="미전송 결과 전송":
                if code==0:
                    try:
                        payload=json.loads(text)
                        self.queue_status.set(f"전송 {payload.get('delivered', 0)}건 / 보류 {payload.get('pending', 0)}건")
                    except (ValueError, json.JSONDecodeError):
                        self.queue_status.set("전송 결과 형식 오류")
                    self.root.after(300,self.refresh_offline_queue)
                else:
                    self.queue_status.set("전송 실패: 연결 또는 설정 확인")
                    self._set_text(self.output,f"$ {label}\n{text}\n",append=True)
            elif label=="119 현장 조회":
                if code==0:
                    try:
                        result=json.loads(text)
                        self._merge_assigned_sites(result.get("payload") or {}, result.get("mode") or "unknown")
                    except (ValueError,json.JSONDecodeError) as exc:
                        self.ict_connection_status.set(f"119 현장 목록 형식 오류: {exc}")
                else:
                    self.ict_connection_status.set(f"119 연결 실패: {text[:120]}")
            elif label=="119 대기자료 전송":
                if code==0:
                    try:
                        result=json.loads(text)
                        self.ict_connection_status.set(
                            f"119 재전송 {result.get('sent',0)}건 · 남음 {result.get('remaining',0)}건"
                        )
                    except (ValueError,json.JSONDecodeError):
                        self.ict_connection_status.set("119 재전송 결과 형식 오류")
                else:
                    self.ict_connection_status.set(f"119 재전송 실패: {text[:120]}")
            elif label=="119 현장 프로필 송신":
                if code==0:
                    try:
                        result=json.loads(text)
                        mode=result.get("transport_mode") or "unknown"
                        labels={"vpn":"VPN 저장 완료","https_fallback":"HTTPS 대체 저장 완료","offline_queue":"오프라인 저장"}
                        self.ict_connection_status.set(
                            f"{labels.get(mode,mode)} · 재전송 대기 {self._ict_client().queue_size()}건"
                        )
                    except (ValueError,json.JSONDecodeError):
                        self.ict_connection_status.set("119 송신 결과 형식 오류")
                else:
                    self.ict_connection_status.set(f"119 송신 실패: {text[:120]}")
            elif label in ("진단 스냅샷 저장", "진단 스냅샷 저장/송신"):
                if code==0:
                    try:
                        payload=json.loads(text)
                        delivery=payload.get("delivery") or {}
                        delivery_label="중앙 전송 완료" if delivery.get("state")=="sent" else "로컬 저장 완료 · 전송 대기"
                        observed=(payload.get("observed_at") or "").replace("T"," ").replace("Z","")
                        self.last_snapshot.set(f"최근 저장: {observed or '시각 미확인'} · {delivery_label}")
                        self.queue_status.set(delivery_label)
                        self._update_source_status(payload.get("source_status"))
                        self._set_text(self.measurement_output,json.dumps(payload,ensure_ascii=False,indent=2)+"\n")
                        self.sync_ict_profile(self.pending_snapshot_profile, payload)
                    except (ValueError,json.JSONDecodeError):
                        self.last_snapshot.set("최근 저장: 결과 형식 확인 필요")
                    self.pending_snapshot_profile = None
                    self.root.after(300,self.refresh_offline_queue)
                else:
                    self.last_snapshot.set("최근 저장: 실패 · 진단 로그를 확인하세요")
                    self._set_text(self.measurement_output,f"$ {label}\n{text}\n",append=True)
            elif label=="SNMP 설정 조회" and code==0:
                data=parse_settings(text); self.version.set(data.get("version","2c")); self.port.set(data.get("port",161)); self.timeout.set(data.get("timeout",2)); self.retries.set(data.get("retries",1)); self.community_state.set("Community: 설정됨" if data.get("community_configured") else "Community: 미설정")
                for x in self.tree.get_children():self.tree.delete(x)
                for t in data["targets"]:self.tree.insert("","end",values=(t.get("name",""),t.get("host",""),t.get("role","switch")))
            elif label=="무선 분석":
                if code==0:
                    try:
                        payload=json.loads(text)
                        if not isinstance(payload,dict):
                            raise ValueError("무선 스캔 결과 형식이 올바르지 않습니다.")
                        self.wireless_payload=payload
                        self.render_wireless()
                    except (ValueError,json.JSONDecodeError) as exc:
                        self.wireless_summary.set("무선 스캔 결과를 해석할 수 없습니다.")
                        self._set_text(self.wireless_analysis,f"{exc}\n{text}")
                else:
                    self.wireless_summary.set("무선 스캔 실행 오류")
                    self._set_text(self.wireless_analysis,text)
            elif label=="VPN 목록":
                for x in self.vpn_tree.get_children():self.vpn_tree.delete(x)
                if code==0:
                    for line in text.splitlines():
                        parts=line.split("\t")
                        if len(parts)==4:
                            connection_type=parts[2].strip()
                            raw_state=parts[3].strip().lower()
                            if connection_type=="wireguard-systemd":
                                connected=raw_state=="active"
                            else:
                                connected=bool(raw_state and raw_state not in ("--","inactive","disconnected","unavailable"))
                            display_type="시스템 WireGuard" if connection_type=="wireguard-systemd" else connection_type
                            self.vpn_tree.insert("","end",values=(parts[0],display_type,"연결됨" if connected else "연결 안 됨",parts[1]))
                else:self._set_text(self.vpn_output,text)
            else:
                if label.startswith("VPN"):
                    target_widget=self.vpn_output
                    if code==0 and label != "VPN 상세":self.root.after(500,self.refresh_vpn)
                else:
                    if label == "측정 세션": target_widget=self.measurement_output
                    elif label in ("패킷 캡처","캡처 목록","캡처 요약"): target_widget=self.capture_output
                    else: target_widget=self.output
                if hasattr(self,"output"): self._set_text(target_widget,f"$ {label}\n{text}\n",append=True)
                if code==0 and label.startswith("SNMP"): self.root.after(300,self.load_snmp)
                if label == "측정 세션":
                    if code==0:
                        try:
                            payload=json.loads(text); delivery=payload.get("delivery", {})
                            state="중앙 전송 완료" if delivery.get("state")=="sent" else "로컬 저장 완료, 중앙 전송 대기"
                            self.queue_status.set(state)
                            self.sync_ict_profile(self.pending_measurement_profile, payload)
                        except (ValueError, json.JSONDecodeError):
                            pass
                    self.pending_measurement_profile = None
                    self.root.after(300,self.refresh_offline_queue)
            if label in ("관리자 작업","서비스 재시작"): self.refresh_services()
            if label in self.refresh_batch_pending:
                self.refresh_batch_pending.discard(label)
                if code != 0:
                    self.refresh_batch_errors += 1
                if not self.refresh_batch_pending:
                    stamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    suffix=f" · 오류 {self.refresh_batch_errors}건" if self.refresh_batch_errors else " · 정상"
                    self.last_refresh.set(f"마지막 갱신: {stamp}{suffix}")
                    self.refresh_all_button.configure(state="normal")
            if self.running_jobs:
                self.status.set(f"작업 {self.running_jobs}건 실행 중")
            else:
                self.status.set("완료" if code==0 else f"오류 ({code})")
        except queue.Empty: pass
        self.root.after(150,self._drain)
    def _set_text(self,widget,text,append=False):
        widget.configure(state="normal")
        if not append:widget.delete("1.0","end")
        widget.insert("end",text); widget.see("end"); widget.configure(state="disabled")

    def _update_offline_queue(self, items):
        for row in self.queue_tree.get_children(): self.queue_tree.delete(row)
        labels={"pending":"전송 대기","sent":"전송 완료","invalid":"파일 오류"}
        kinds={"measurement":"반복 측정","diagnostic_snapshot":"진단 스냅샷"}
        pending=0
        for item in items:
            state=item.get("state", "unknown")
            if state=="pending": pending += 1
            error=item.get("last_error") or ("중앙 NMS 전송 완료" if state=="sent" else "확인 필요")
            recorded=(item.get("queued_at") or item.get("started_at") or "").replace("T"," ").replace("Z","")
            self.queue_tree.insert("","end",values=(labels.get(state,state),kinds.get(item.get("session_kind"),item.get("session_kind") or "반복 측정"),item.get("site_name") or "-",recorded,item.get("attempts",0),error))
        self.queue_status.set(f"미전송 {pending}건")

    def on_close(self):
        self.stop_live_monitor()
        self.stop_live_capture()
        self.root.after(100,self.root.destroy)

if __name__ == "__main__":
    root=tk.Tk(); App(root); root.mainloop()
