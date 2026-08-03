# Ubuntu Collector

고객사 내부 Ubuntu 수집 서버를 빠르게 배포하기 위한 아티팩트입니다.

포함 항목:

- `install-collector.sh`
- `install-field-tools.sh`
- `install-node-lts.sh`
- `nms-collector.js`
- `nms-packet-capture.sh`
- `nms_packet_flood.py`
- `nms-wireless-scan.py`
- `install-wireless-adapter-support.sh`
- `summarize-syn-sources.sh`
- `heartbeat.sh` (compatibility wrapper)
- `ensure-collector-autostart.sh`
- `nms-collector-network-change.sh`
- `apply-collector-autostart-recovery.sh`
- `trap-forwarder.js` (compatibility wrapper)
- `package.json`
- `collector.env.example`
- `systemd/nms-collector-heartbeat.service`
- `systemd/nms-collector-heartbeat.timer`
- `systemd/nms-collector-autostart.service`
- `systemd/nms-collector-trap-forwarder.service`
- `systemd/nms-collector-diagnostic-worker.service`
- `systemd/nms-collector-edge-analysis.service`
- `systemd/nms-collector-edge-analysis.timer`
- `metro-agent-v1/` (중앙 설정 기반 Ping/TCP/HTTP/System 실행 계층)
- `systemd/nms-metro-agent-v1.service`
- `systemd/nms-metro-agent-v1.timer`
- `rsyslog/49-nms-relay.conf`

역할 정의:

- `Ubuntu 내부 수집서버`
  고객사 내부에 설치하는 상시 수집/분석 서버입니다. Synology Docker보다 넓은 범위를 맡고, syslog/SNMP trap relay, 내부 진단, edge 분석, 경량 AI 보조 판단을 처리합니다.
- `Synology Docker collector`
  NAS 안에서 NAS 상태, 파일작업, 게이트웨이/NMS probe, tcpdump/arpwatch 샘플을 수집합니다. NAS 운영 현장 표준입니다.

원격관리 정의:

- `REMOTE_MANAGEMENT_MODE=none`
  기본값입니다. 수집기는 현장 사설 IP에서 중앙 33번으로 outbound HTTPS만 사용합니다.
- `REMOTE_MANAGEMENT_MODE=omada_vpn`
  원격 유지관리 접속이 필요할 때만 선택합니다. VPN 연결 여부가 heartbeat, 진단, 데이터 전송의 필수 조건이 되어서는 안 됩니다.
- `REMOTE_MANAGEMENT_PROFILE_LABEL`
  OMADA에 등록한 사이트 또는 VPN 프로필을 사람이 알아볼 수 있게 적는 선택값입니다. 계정, 비밀번호, PSK는 기록하지 않습니다.
- `WIREGUARD_INTERFACE=metro-omada`
  `REMOTE_MANAGEMENT_MODE=omada_vpn`일 때 상태를 확인할 WireGuard 인터페이스입니다.
- `WIREGUARD_HANDSHAKE_STALE_SECONDS=180`
  최근 handshake가 이 시간을 넘으면 원격관리 경고로 표시합니다. VPN 경고는 HTTPS 수집 실패로 처리하지 않습니다.

권장 `COLLECTOR_ROLE`:

- `ubuntu_agent`
  heartbeat, 로컬 점검, 필요 시 syslog relay
- `syslog_gateway`
  고객사 내부 syslog를 중앙 NMS로 포워딩
- `snmp_proxy`
  고객사 내부 장비 대상 SNMP 수집 보조
- `hybrid`
  위 기능을 한 서버에서 같이 수행

기본 순서:

1. 중앙 NMS에서 collector를 등록합니다.
2. 응답의 `id`, `agent_token`을 확보합니다.
3. Ubuntu 서버에 이 디렉터리를 복사합니다.
4. `/field-collector.html`에서 Ubuntu 설정을 생성해 `collector.env`를 다운로드합니다.
5. `collector.env`의 `COLLECTOR_TOKEN`을 실제 `agent_token`으로 채웁니다.
6. `sudo bash install-collector.sh --env-file ./collector.env` 실행
7. `node /opt/nms-collector/nms-collector.js doctor`가 `ready=true`인지 확인
8. `systemctl status nms-collector-heartbeat.timer` 확인

`--env-file` 없이 실행하면 기존 `/etc/nms-collector/collector.env`를 유지하고, 파일이 없을 때만 `collector.env.example`을 배치합니다. `--env-file`을 지정하면 기존 설정 파일은 timestamp가 붙은 `.bak` 파일로 백업됩니다.

설치 스크립트는 현장 진단에 필요한 `ethtool`, `iperf3`, `mtr`,
`arp-scan`, `nmap`, `tshark`, `lldpd`, 무선 진단 도구도 함께 설치합니다.
`iperf3` 서버는 자동 실행하지 않으며 LLDP는 기본적으로 수신 전용입니다.

동시 측정 세션에서 RF 모듈을 선택하면 평상시 자동수집의 단일 `TINYSA_BAND`
설정과 별개로 2.4GHz, 5GHz, 6GHz Wi-Fi 대역을 순환 측정합니다.
`TINYSA_SESSION_BANDS`로 순환 대역을 제한할 수 있고, 각 sweep에는 실제
대역과 시작·종료 주파수가 저장됩니다. 짧은 세션에서도 대역을 한 번씩
확인할 수 있도록 세션용 Max Hold 반복 기본값은 2회입니다.
Ubuntu 기본 Node.js 패키지 대신 공식 Node.js LTS 바이너리를 SHA-256 검증 후
`/opt`에 설치하고 `/usr/local/bin/node`를 서비스 실행 경로로 사용합니다.
진단 도구만 별도로 다시 구성할 때는 다음을 실행합니다.

```bash
sudo bash install-field-tools.sh
```

중앙 등록 예시:

```bash
export NMS_HOST="nms.example.com"
export NMS_PORT="7443"
export NMS_SCHEME="https"
export NMS_PATH=""
NMS_BASE_URL="${NMS_SCHEME}://${NMS_HOST}:${NMS_PORT}${NMS_PATH:+/$NMS_PATH}"
curl -X POST "${NMS_BASE_URL}/api/collectors" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": 1,
    "site_id": 1,
    "name": "site-a-ubuntu-agent",
    "collector_type": "ubuntu_agent",
    "platform": "ubuntu",
    "private_ip": "10.10.1.15",
    "status": "planned",
    "metadata": {
      "purpose": "syslog relay and local checks",
      "capabilities": ["heartbeat", "syslog"]
    }
  }'
```

`nms-collector.js`는 `heartbeat`, `trap-forwarder`, `diagnostic-worker`, `diagnostic-once`, `edge-analysis`, `edge-analysis-heartbeat`, `doctor`, `render-rsyslog-config` 서브커맨드를 한 런타임에서 제공합니다. 설치 스크립트도 이 런타임을 사용해 env를 검증하고 rsyslog relay 설정을 생성합니다.

systemd 타이머는 기본 60초 주기로 heartbeat를 전송합니다. Desktop GUI를 열지 않아도 부팅 후 `network-online.target`에서 `nms-collector-autostart.service`가 heartbeat, 원격진단, edge 분석을 준비합니다. NetworkManager가 DHCP 주소를 새로 받거나 링크가 복구되면 dispatcher가 즉시 heartbeat와 edge 분석을 한 번 실행합니다. `REMOTE_MANAGEMENT_MODE=omada_vpn`인데 WireGuard 서비스가 비활성 상태이면 dispatcher가 물리 네트워크 복구 시 VPN도 다시 시작합니다. WireGuard는 원격 접속용 선택 기능이며, VPN 상태와 무관하게 중앙 NMS HTTPS 전송은 계속 시도합니다.

Wi-Fi/RF 실시간 전송도 `NMS_URL`과 `NMS_FALLBACK_URL`을 순서대로 사용합니다. 공인 경로가 타임아웃되고 VPN 내부 경로가 성공하면 실행 중인 서비스는 성공한 경로를 우선 캐시하므로 이후 배치가 매번 공인 타임아웃을 기다리지 않습니다. 이동 후 Pulse 주소가 현재 기본 유선 서브넷 밖에 있으면 이전 현장 설정으로 보고 로컬 Pulse 폴링을 건너뜁니다. 의도적으로 라우팅된 Pulse VLAN만 `PULSE_LOCAL_REQUIRE_PRIMARY_SUBNET=false`로 예외 처리합니다.

## Metro Agent V1

`Metro Agent V1`은 기존 heartbeat, 원격진단, Wi-Fi/RF 수집기를 대체하지
않는 별도 실행 계층입니다. 기존 `COLLECTOR_ID`, `COLLECTOR_TOKEN`,
`NMS_URL`을 그대로 사용하며 33번 중앙 NMS에서 배포한 점검 프로필에
따라 `ping`, `tcp`, `http`, `system` 플러그인을 실행합니다.

```env
METRO_AGENT_V1_ENABLED=true
METRO_AGENT_V1_STATE_DIR=/var/lib/nms-collector/metro-agent-v1
```

중앙 API는 다음 계약을 사용합니다.

- `GET /api/collectors/:id/metro-agent/config`
- `POST /api/collectors/:id/metro-agent/check-batches`

실패한 배치는 `METRO_AGENT_V1_STATE_DIR/queue`에 권한 `0600`으로
저장하고 다음 실행 때 순서대로 재전송합니다. `batch_id`는 중앙 DB의
고유 키이므로 응답 유실 후 같은 배치를 재전송해도 중복 저장되지
않습니다. 마지막 정상 설정은 로컬에 캐시하므로 현장 인터넷이 끊겨도
수집은 계속할 수 있습니다.

```bash
sudo systemctl status nms-metro-agent-v1.timer
sudo ENV_FILE=/etc/nms-collector/collector.env \
  node /opt/nms-collector/metro-agent-v1/index.js doctor
sudo ENV_FILE=/etc/nms-collector/collector.env \
  node /opt/nms-collector/metro-agent-v1/index.js run-once --force
sudo ENV_FILE=/etc/nms-collector/collector.env \
  node /opt/nms-collector/metro-agent-v1/index.js queue-status
```

이미 설치된 수집기에 이 자동 복구 구성만 추가할 때는 패키지 안에서 `sudo bash apply-collector-autostart-recovery.sh`를 실행합니다. 이동형/DHCP 수집기에 이전 사설 IP가 남아 있으면 `sudo bash apply-collector-autostart-recovery.sh --clear-private-ip`를 실행합니다. 이 옵션은 collector.env를 timestamp 백업한 뒤 `COLLECTOR_PRIVATE_IP` 고정값만 비우며 token은 변경하지 않습니다.

현장 이동 후 현재 연결 정보는 heartbeat metadata의 `current_network`에 인터페이스, 내부 IP/CIDR, 서브넷, 기본 게이트웨이, 수집 시각으로 기록됩니다. 중앙 NMS가 본 공인 IP는 ingress 관측값으로 별도 기록합니다. `REMOTE_MANAGEMENT_MODE=omada_vpn`이면 VPN 인터페이스, 서비스 상태, handshake 신선도도 `vpn` metadata에 기록합니다. VPN 경고와 HTTPS 수집 상태는 분리하며, 공인 IP와 고객사 사설 IP는 collector.env에 고정하지 않습니다.

공인 IPv4는 heartbeat마다 외부 확인 서비스에서 수집하고 `public_ip`와
`metadata.public_ip_observation`에 값, 원천, 측정시각, 상태를 기록합니다.
기본값은 `PUBLIC_IP_COLLECTION_ENABLED=true`,
`PUBLIC_IP_ENDPOINTS=https://api.ipify.org,https://ifconfig.me/ip`,
`PUBLIC_IP_TIMEOUT_MS=3000`입니다. 사설/VPN/CGNAT 주소는 공인 IP로 저장하지
않으며, 외부 조회가 차단되면 값을 만들지 않고 `unavailable`로 남깁니다.

현장 반출 표준 순서는 `유선 DHCP 확인 -> 공인 HTTPS와 VPN 대체 경로 확인 -> 119 현장 직접 선택 -> 기존 화면 초기화 확인 -> 짧은 동시 측정 -> 안전 중지 및 표본 저장 확인 -> 필요 시 패킷 캡처`입니다. 현장을 선택하지 않은 상태에서는 측정을 시작하지 않으며, 선택 직후 화면은 `테스트 안 됨`으로 초기화됩니다. 일반 액세스 포트 캡처는 수집기 자신에게 보이는 트래픽만 포함하므로 현장 전체 플러딩 판정에는 스위치 SPAN/미러 포트를 사용합니다.

syslog relay를 켜면 `RSYSLOG_TARGET_HOST`, `RSYSLOG_TARGET_PORT`, `RSYSLOG_TARGET_PROTOCOL` 기준으로 `/etc/rsyslog.d/49-nms-relay.conf`를 생성합니다. `COLLECTOR_ROLE`은 `ubuntu_agent`, `syslog_gateway`, `snmp_proxy`, `hybrid` 중 하나를 쓸 수 있고, `doctor`가 역할과 실제 기능 플래그(`ENABLE_RSYSLOG_RELAY`, `ENABLE_SNMPTRAP_RELAY`)가 어긋나면 경고를 출력합니다.

원격 진단을 켜면 `nms-collector-diagnostic-worker.service`가 중앙 NMS의 `/api/collectors/:collectorId/diagnostic-commands/pending`을 poll 방식으로 확인하고, 명령 실행 후 `/api/collectors/:collectorId/diagnostic-commands/:commandId/result`로 결과를 올립니다. 지원 명령은 `ping`, `traceroute`, `dns`, `tcp`, `http`, `tcpdump`, `arpwatch`, `bandwidth`, `measurement`, `gateway-info`, `tools-info`, `goal`입니다. 기본 보안값은 내부망/RFC1918 IP와 gateway 키워드 중심이며, 공인 IP 대상 진단은 `DIAGNOSTIC_ALLOW_PUBLIC_TARGETS=true`로 명시해야 합니다.

Ubuntu Desktop GUI의 `현장 프로필`은 119 ICT Manager에서 이 장치에 할당된 고객·현장을 자동으로 불러옵니다. 수집기에서 고객명이나 현장명을 새로 만들지 않으며, 사용자는 할당 현장을 선택하고 메트로 담당자/연락처와 고객사 담당자/연락처만 보완한 뒤 `측정 세션`을 시작합니다. 모든 연락처 항목은 측정 시작 전 필수입니다.

119 연결은 `http://192.168.1.119:8660` VPN 직접 경로를 먼저 사용하고, 실패하면 `https://112.167.190.125:7443/api/ict-field/*` 대체 경로를 사용합니다. 두 경로가 모두 실패하면 측정 세션과 프로필 스냅샷을 사용자 설정 폴더의 `0600` 큐에 저장하고 `중앙 송신` 또는 `미전송 결과 전송`에서 순서대로 재전송합니다. 장치 토큰은 `~/.config/metro-nms-field-collector/ict-manager-device.json`에 저장하며 119 사용자 ID나 비밀번호를 수집기에 저장하지 않습니다.

GUI는 Metro 색상 체계와 좌측 탐색을 사용하는 현장 작업 화면입니다. 상단의 `진단 저장`은 VLAN, LLDP, ARP, 무선, 인터페이스, SNMP, VPN, 수집 서비스와 시스템 상태를 하나의 시각 기준 스냅샷으로 로컬 대기열에 저장합니다. `저장 후 송신`은 동일 파일을 33 NMS와 119 ICT Manager에 각각 저장하고, `중앙 송신`은 두 시스템의 기존 미전송 파일을 재전송합니다. 전송용 세션은 원천, 단위, 측정시각과 수집 가능 상태만 제한된 크기로 담고, 상세 원천 스냅샷은 로컬 `0600` 큐 파일에 유지합니다.

`수집기 현황` 화면의 `수집기 이름`은 사용자가 수정할 수 있습니다. 기본 이름은 `메트로정보통신 네트워크 현장 분석기`이며, 저장하면 root 전용 `collector.env`를 timestamp 백업한 뒤 `COLLECTOR_NAME`을 갱신하고 heartbeat를 즉시 전송합니다. 이 값은 장치 OS 호스트명과 분리된 33 NMS 표시명입니다.

`수집 소스` 화면은 Syslog, SNMP polling/trap, NetFlow, IPFIX, sFlow, DHCP/DNS 관측, 능동 진단, Omada API, endpoint collector를 `수집 중`, `사용 가능`, `설정됨`, `미설정`, `미수집`으로 구분합니다. 포트나 설정이 없는 원천은 정상으로 간주하지 않습니다. `전체 새로고침`은 현재 네트워크, VPN, 서비스, 무선, 오프라인 큐를 함께 갱신하며 완료 시각과 오류 건수를 표시합니다.

`실시간 모니터링` 화면은 선택 인터페이스의 커널 누적 counter를 2초 간격으로 차분해 수신·송신 Mbps와 PPS를 표시합니다. 누적 오류·드롭, 게이트웨이 ICMP 지연, 활성 연결 수, 현재 주소와 링크 상태도 함께 표시합니다. `lldpd`는 receive-only `-r -c`로 실행해 LLDP와 Cisco CDP를 모두 수신하며, 이웃 표에는 원천 프로토콜, 로컬 포트, 장비명, 관리 IP, 상대 포트와 관측 경과를 구분해 표시합니다. 일반 access 포트에서는 직접 연결된 이웃 광고만 볼 수 있으며, 스위치에서 LLDP/CDP가 비활성화된 경우 0건은 정상 판정이 아니라 미관측입니다.

`패킷 캡처` 화면의 실시간 모드는 TShark 헤더 요약을 연속 표시하면서 `/var/log/nms-pcap/live-*.pcapng`에 원본을 저장합니다. 임의 BPF 입력 대신 전체 헤더, 플러딩 분석, 기본 통신, DNS, DHCP, ARP, Ping, LLDP/CDP 프로필만 제공하며 최대 30분, 50MB, 패킷당 256바이트에서 자동 종료됩니다. 화면에는 최근 500개 헤더만 유지합니다. 중지 버튼은 캡처 프로세스 그룹에 종료 신호를 보내고, 완료된 파일은 `adm` 그룹 읽기와 `0640` 권한으로 보관합니다.

`선택 요약/전송`은 선택한 PCAP을 다시 분석해 측정시각, 통계, 원본 파일 해시와 관측 범위만 중앙 NMS에 저장합니다. 원본 PCAP과 패킷 payload는 130번에만 남기며 중앙으로 전송하지 않습니다.

플러딩 분석은 Broadcast, Multicast, ARP, mDNS, SSDP, LLMNR, NBNS, DHCP를 개수, 비율, pps로 집계합니다. 프로토콜 디코딩이 UDP로만 표시되는 경우에도 표준 UDP 포트로 다시 분류합니다. 관측시간 5초 또는 패킷 20개 미만이면 임계값 판정을 하지 않고 `판단 자료 부족`으로 표시합니다. pps 임계값 초과는 `플러딩 후보`이며 확정 장애가 아닙니다. 전체 현장 판단에는 스위치 SPAN/미러 포트 또는 트렁크 관측이 필요합니다.

GUI의 `무선 분석` 탭은 NetworkManager Wi-Fi 스캔을 다시 실행해 SSID, 숨김 SSID, BSSID, 대역, 채널, 주파수, 신호율, 보안 방식을 표시합니다. 숨김 SSID는 이름을 추정하지 않고 `(숨김 SSID)`와 BSSID·채널로만 표시합니다. 대역별 AP 수, 채널별 검출/강한 신호 수, 현재 연결 AP 신호 품질을 바탕으로 혼잡 가능성과 현장 확인 항목을 안내하며, 원본 결과는 사용자 Documents 아래 JSON으로 저장할 수 있습니다. 이 기능은 Wi-Fi AP 스캔 기준이며, 비 Wi-Fi 간섭원까지 측정하는 RF 스펙트럼 분석을 대체하지 않습니다.

`RF 스펙트럼` 탭은 측정 목적을 `AP`, `방송`, `가전`, `사용자 정의` 대분류로 나누고 각 대분류의 중분류 프리셋을 제공합니다. AP의 2.4/5/6GHz 스윕 그래프는 주파수(MHz/GHz, 내부 Hz 기준)와 Wi-Fi 채널 번호를 가로축에 함께 표시합니다. 방송과 가전은 FM, VHF/UHF 방송, 위성 LNB 출력 IF, NFC/RFID, 433/900MHz 소출력, 2.4/5.8GHz 데이터 기기 범위를 선택할 수 있습니다. 위성 프리셋은 위성 안테나의 고주파 신호 직결용이 아니라 LNB가 변환한 950~2150MHz IF 동축 경로용이며, DC 차단과 입력 레벨 보호를 먼저 확인해야 합니다.

RF 화면의 기본 AP 대역은 5GHz(5150~5850MHz)입니다. `자동 RF 수집`을
해제하고 설정을 적용하면 AP 검색과 유무선 품질 수집은 유지한 채 tinySA
자동 스윕만 중지됩니다. `2.4/5/6 GHz 전체 측정`은 한 대의 tinySA로 세
대역을 빠르게 순차 스윕하고 각 측정시각을 보존한 뒤 한 화면에 함께
표시합니다.

`측정 세션`의 시작, 상태, 일시정지, 재개, 안전중지는
`measurement-session-control.sh`의 검증된 인수만 비밀번호 없이 실행할 수
있습니다. GUI가 root 전용 `collector.env`나 상태 저장소를 직접 읽지 않으므로
데스크톱 로그인 사용자의 파일 권한과 관계없이 같은 제어 경로를 사용합니다.

`측정 세션`은 10초~8시간의 측정시간과 2~300초의 간격을 지정합니다. 게이트웨이, KT DNS `168.126.63.1`, Google DNS `8.8.8.8`, CPU, 메모리, 루트 디스크, 인터페이스 송수신 속도를 반복 측정합니다. 지연 평균은 성공 표본만 사용하지만 시도/성공/실패 수를 함께 저장하며, 인터페이스 Mbps는 누적 바이트가 아니라 측정 간 counter delta로 계산합니다. 결과에는 원천 측정시각과 33번 적재시각이 분리됩니다.

인터넷 또는 중앙 NMS 연결이 없는 현장에서는 측정 결과를 먼저 `/var/lib/nms-collector/field-measurements/pending/`에 권한 `0600`으로 저장합니다. GUI의 `저장/전송` 탭에서 `미전송 결과 전송`을 누르면 연결이 복구된 뒤 재전송합니다. 각 결과는 `client_session_id`로 멱등 처리되므로 재시도해도 중앙 측정 세션이 중복 생성되지 않습니다. 중앙에서 수신 확인된 파일은 같은 경로의 `sent/`에 보관됩니다. 큐 파일에는 collector 토큰, VPN 비밀정보, 관리자 비밀번호를 저장하지 않습니다.

최신 collector는 heartbeat 성공 뒤 pending 측정 큐도 자동 전송합니다. 현장에서는 GUI를 실행해 둘 필요가 없습니다.

edge 분석을 켜면 `nms-collector-edge-analysis.timer`가 10분마다 서버 로컬 상태를 요약하고 heartbeat metadata에 `edge_analysis`로 올립니다. 기본 분석은 규칙 기반이며, `EDGE_AI_ENABLED=true`와 OpenAI-compatible endpoint를 지정하면 118번 LLM Ops 또는 Ollama OpenAI shim으로 경량 보조 분석을 추가할 수 있습니다.

TLS 메모:

- 기본 예시는 `https://...:7443` 기준입니다.
- 중앙 NMS가 self-signed 인증서를 쓴다면 인증서를 `/etc/nms-collector/nms-ca.crt`에 설치하고 `NMS_CA_CERT_PATH`로 고정하는 방식을 사용합니다. `NMS_INSECURE_TLS=true`는 인증서 교체 중 임시 진단에만 사용합니다.
- `doctor` 출력에는 현재 TLS 모드(`system-ca`, `custom-ca`, `insecure`)도 함께 표시됩니다.

Uptime Kuma 메모:

- `UPTIME_KUMA_PUSH_URL`을 넣으면 heartbeat 실행 후 `Push monitor`도 함께 갱신합니다.
- 권장 URL 형식:
  - `http://192.168.1.33:3001/api/push/<token>`
- collector는 아래 기준으로 `up/down`을 보냅니다.
  - `up`: heartbeat 성공, 활성화된 relay/diagnostic/edge-analysis 서비스 정상
  - `down`: heartbeat 실패 또는 활성화된 relay/diagnostic/edge-analysis 서비스 비정상
- `ping` 값에는 최근 heartbeat 왕복 시간(ms)을 사용합니다.

역할별 예시:

`syslog_gateway`

```env
COLLECTOR_ROLE=syslog_gateway
COLLECTOR_CAPABILITIES=heartbeat,syslog
COLLECTOR_PURPOSE=syslog gateway
ENABLE_RSYSLOG_RELAY=true
RSYSLOG_TARGET_HOST=192.168.1.10
RSYSLOG_TARGET_PORT=5514
RSYSLOG_TARGET_PROTOCOL=udp
ENABLE_SNMPTRAP_RELAY=false
```

`hybrid`

```env
COLLECTOR_ROLE=hybrid
COLLECTOR_CAPABILITIES=heartbeat,syslog,trap,diagnostics,edge-analysis
COLLECTOR_PURPOSE=internal edge collection server
ENABLE_RSYSLOG_RELAY=true
RSYSLOG_TARGET_HOST=192.168.1.10
RSYSLOG_TARGET_PORT=5514
RSYSLOG_TARGET_PROTOCOL=tcp
ENABLE_SNMPTRAP_RELAY=true
SNMPTRAP_LISTEN_ADDRESS=0.0.0.0
SNMPTRAP_LISTEN_PORT=1162
SNMPTRAP_COMMUNITIES=public
REMOTE_DIAGNOSTICS_ENABLED=true
DIAGNOSTIC_POLL_INTERVAL_SECONDS=15
EDGE_SERVER_MODE=true
EDGE_ANALYSIS_ENABLED=true
```

SNMP trap relay를 켜면 `nms-collector-trap-forwarder.service`가 `SNMPTRAP_LISTEN_PORT`(기본값 `1162`)에서 trap을 수신한 뒤, 원본 `source_ip`, `trap_oid`, `varbinds`를 포함한 JSON payload를 중앙 NMS의 `POST /api/collectors/:collectorId/snmp-traps`로 전송합니다.

`doctor`는 가능하면 `systemctl is-active/is-enabled`로 아래 로컬 서비스 상태도 함께 보여줍니다.

- `nms-collector-heartbeat.timer`
- `nms-collector-diagnostic-worker.service`
- `nms-collector-edge-analysis.timer`
- `nms-collector-trap-forwarder.service`
- `rsyslog.service`

운영 팁:

1. 중앙 NMS에는 해당 현장 장비의 실제 IP가 `devices.ip_address` 또는 `device_ip_aliases.ip_address`로 등록돼 있어야 합니다.
2. Ubuntu collector의 heartbeat와 trap forwarder는 같은 `COLLECTOR_ID`, `COLLECTOR_TOKEN`을 사용합니다.
3. 표준 trap 포트 `162/udp`가 필요하면 권한 또는 포트 포워딩을 별도로 설계하고, `SNMPTRAP_LISTEN_PORT=162`로 변경하세요.
4. `SNMPTRAP_DISABLE_AUTHORIZATION=false`를 기본값으로 두고, `SNMPTRAP_COMMUNITIES`를 실제 community 값으로 맞추는 편이 안전합니다.
5. example env 그대로 두면 installer가 서비스를 올리지 않습니다. 먼저 실제 `COLLECTOR_ID`, `COLLECTOR_TOKEN`, `NMS_HOST/NMS_URL`을 넣고 `doctor`를 통과시켜야 합니다.
6. `syslog_gateway`나 `hybrid` 역할이면 `ENABLE_RSYSLOG_RELAY=true`와 `RSYSLOG_TARGET_*`를 같이 맞추는 편이 안전합니다.
7. self-signed TLS를 쓰는 현장도 `NMS_CA_CERT_PATH=/etc/nms-collector/nms-ca.crt`로 인증서를 검증합니다. `NMS_INSECURE_TLS=true`를 운영 기본값으로 두지 않습니다.
8. 원격 진단은 기본 활성화(`REMOTE_DIAGNOSTICS_ENABLED=true`)입니다. 현장 서버를 단순 heartbeat 전용으로 쓸 때만 false로 끕니다.
9. `tcpdump` 원격진단은 기본 15초/500패킷, 최대 60초/2,000패킷으로 제한합니다. 원본 PCAPNG는 130번 `/var/log/nms-pcap`에 기본 24시간만 보관하고 중앙에는 패킷 payload 없이 프로토콜·통신쌍·DNS/ARP/ICMP/TCP 이상·VLAN/LLDP 통계와 원본 SHA-256만 올립니다. `capture_scope=collector_interface`가 기본이며 SPAN/미러 또는 트렁크가 확인되지 않으면 전체 현장 트래픽으로 해석하지 않습니다. `any` 인터페이스처럼 Ethernet 목적지 주소가 노출되지 않는 캡처의 Broadcast/Multicast는 `0`이 아니라 `측정 불가`로 처리합니다. TCP 재전송은 부분 캡처 안에서 TShark가 판정한 의심 건수이며 회선 전체의 확정 재전송 수가 아닙니다. 비어 있는 프로토콜 필드는 `0`과 구분해 집계 대상에서 제외합니다.
10. Edge heartbeat의 `neighbor_entries`는 `ip neigh`를 IP, MAC, 인터페이스, 상태, 주소 구분, 라우터 플래그로 구조화한 현재 스냅샷입니다. 커널 neighbor cache이므로 현장 전체 자산 목록으로 해석하지 않습니다. LLDP 상세는 `lldpcli`와 스위치 SNMP LLDP-MIB 원천을 구분하며, 0건은 정상 장비 0대가 아니라 미광고·비지원·관측 범위 부족 가능성을 포함합니다.
11. `EDGE_ANALYSIS_ENABLED=true`는 내부서버 로컬 상태를 10분마다 분석해 중앙 heartbeat metadata에 올립니다.
12. 경량 AI 보조 분석은 기본 off입니다. 현장 서버 자체 GPU가 없으면 118번 LLM Ops 같은 내부 AI 서버를 `EDGE_AI_BASE_URL`로 지정하는 방식을 권장합니다.
13. 부팅 자동 시작 상태는 `sudo systemctl status nms-collector-autostart.service`, heartbeat는 `sudo systemctl status nms-collector-heartbeat.timer`, 마지막 오류는 `sudo journalctl -u nms-collector-heartbeat.service -n 50 --no-pager`로 확인합니다.

## Remote Diagnostics

중앙 NMS 운영 콘솔의 `수집/연결 > Collector 원격진단`에서 명령을 만들면 우분투 콜렉터가 가져가 실행합니다.

빠른 현장 표준점검은 `goal` 명령을 사용합니다.

```bash
sudo ENV_FILE=/etc/nms-collector/collector.env \
  node /opt/nms-collector/nms-collector.js diagnostic-once
```

권장 goal:

- `site-standard-check`: gateway 정보, gateway ping, DNS, NMS TCP 연결 확인
- `router-standard-check`: site 표준점검 + 외부 Ping/HTTPS + ARP neighbor 요약
- `firewall-standard-check`: site 표준점검 + 외부 Ping/HTTPS + ARP neighbor 요약
- 게이트웨이 Ping이 성공하더라도 평균 지연이 20ms 이상이면 `local_gateway_degraded`로 판정한다. LAN 게이트웨이 지연을 인터넷 정상으로 숨기지 않으며, 게이트웨이 장비 부하와 연결 포트/경로를 추가로 분리 점검한다.
- 상시 분석은 유선 게이트웨이 지연이 기본 20ms 이상으로 3회 연속 관측되면 `gateway_latency_degraded` 사건을 생성한다. `WIFI_ANALYSIS_GATEWAY_LATENCY_THRESHOLD_MS`와 `WIFI_ANALYSIS_GATEWAY_LATENCY_BURST_COUNT`로 현장 기준선을 조정할 수 있다.

모든 표준점검은 gateway Ping, 외부 Ping, DNS, 인터넷 HTTPS, 중앙 NMS TCP를 분리합니다. 외부 Ping은 정상이지만 HTTPS가 실패하면 `firewall_policy_session` 후보로 기록합니다. 이는 인증받지 않은 단말에 ICMP만 허용하고 인터넷 세션을 차단하는 현장 정책을 찾기 위한 규칙입니다.

보안 기본값:

- `DIAGNOSTIC_ALLOW_PUBLIC_TARGETS=false`: ping/traceroute/tcp는 내부 IP, gateway, 중앙 NMS host 중심
- `DIAGNOSTIC_ALLOW_HOSTNAMES=false`: 일반 ping/tcp/traceroute 대상 hostname 사용 금지
- `DIAGNOSTIC_ALLOW_RAW_TCPDUMP_FILTER=false`: 운영자가 임의 tcpdump filter를 보내지 못하고 `syslog`, `trap`, `mdns`, `arp`, `icmp`, `dns` preset만 사용

## Edge Analysis And Lightweight AI

Ubuntu 내부 수집서버는 NAS Docker보다 넓은 현장 관측 지점을 맡습니다. `edge-analysis`는 아래 값을 수집합니다.

- CPU core/load average
- 메모리 사용률
- `df -P -k` 기준 디스크 사용률
- 기본 게이트웨이와 사설 IP
- `ip neigh` 기준 ARP neighbor 상태
- heartbeat, diagnostic worker, trap forwarder, rsyslog, edge analysis timer 상태
- 진단 도구 설치 여부

수동 실행:

```bash
sudo ENV_FILE=/etc/nms-collector/collector.env \
  node /opt/nms-collector/nms-collector.js edge-analysis
```

중앙 heartbeat까지 전송:

```bash
sudo ENV_FILE=/etc/nms-collector/collector.env \
  node /opt/nms-collector/nms-collector.js edge-analysis-heartbeat
```

118번 LLM Ops를 보조 분석기로 붙이는 예:

```env
EDGE_AI_ENABLED=true
EDGE_AI_BASE_URL=http://192.168.1.118:8090/v1
EDGE_AI_MODEL=metro-report:latest
EDGE_AI_API_KEY=
EDGE_AI_TIMEOUT_MS=30000
```

AI 결과는 판단 보조값입니다. 중앙 NMS/ERP 판단 기준은 먼저 규칙 기반 `severity`, `findings`, 실제 로그/metric을 사용하고, AI 문장은 보고서 초안이나 현장 점검 힌트로 사용합니다.

## On-Demand Packet Capture

현장 분석용으로 `nms-packet-capture.sh`를 함께 둡니다. 기본 원칙은 `상시 비활성`, `짧은 ring buffer`, `필요 시에만 실행`입니다.

예시:

```bash
sudo CAPTURE_INTERFACE=eth0 ./nms-packet-capture.sh syslog
sudo CAPTURE_INTERFACE=eth0 ./nms-packet-capture.sh trap
sudo CAPTURE_INTERFACE=eth0 ./nms-packet-capture.sh mirrored-wan-syn 222.114.95.51
```

`mirrored-wan-syn`은 WAN 공격처럼 `게이트웨이 자체에서 드롭한 트래픽`의 source IP를 잡을 때 씁니다. 이 경우 collector 서버만으로는 부족하고, Omada `Port Mirroring`으로 ER7206 WAN 트래픽을 collector NIC 쪽으로 복제해야 합니다. 공통 절차는 [WAN_ATTACK_SOURCE_CAPTURE_REFERENCE.md](/home/metro/network-server/WAN_ATTACK_SOURCE_CAPTURE_REFERENCE.md)를 기준으로 진행합니다.
# METRO NMS Ubuntu Field Collector

## Desktop field diagnostics

Ubuntu Desktop installations receive the `METRO NMS Field Diagnostics` launcher in the Applications menu and on the `metro-agent` desktop. It provides one-click checks for interface/routing state, gateway and Internet ping, DNS, MTR/traceroute, ARP, Wi-Fi scan, Nmap top-port scan, and Ethernet link details. The collector services continue to run independently in the background.

Installed maintenance tools include `nmap`, `mtr`, `fping`, `arp-scan`, `tcpdump`, `tshark`, `iperf3`, `bmon`, `iftop`, `nload`, `vnstat`, `wavemon`, `iw`, `ethtool`, `snmpwalk`, `lldpctl`, `nmcli`, `conntrack`, `socat`, and OpenVPN NetworkManager integration. Use `tshark`/`tcpdump` only with customer authorization and capture the smallest required time window.

## Switch SNMP settings

The Ubuntu field collector keeps SNMP credentials only in the root-readable
`/etc/nms-collector/collector.env`. Central heartbeat data never includes the
community value.

```bash
sudo /opt/nms-collector/configure-snmp-targets.sh defaults 2c 161 2 1
sudo /opt/nms-collector/configure-snmp-targets.sh community
sudo /opt/nms-collector/configure-snmp-targets.sh add "Core switch" 10.0.0.2 core_switch
sudo /opt/nms-collector/configure-snmp-targets.sh show
sudo systemctl start nms-collector-edge-analysis.service
```

The collector reads standard system and IF-MIB values plus BRIDGE-MIB,
Q-BRIDGE-MIB, LLDP-MIB, P-BRIDGE/STP and POWER-ETHERNET-MIB where the switch
exposes them. Unsupported tables are returned as empty with `supported=false`;
missing data is not treated as a healthy VLAN/PoE state.

Launcher command:

```bash
/usr/local/bin/metro-nms-field-diagnostics
```

The GUI is an operator convenience layer. Heartbeat, edge analysis, and remote diagnostics remain centrally recorded by NMS 33 and visualized in Grafana; local GUI output is not treated as authoritative history until it is submitted through the central diagnostic workflow.

## Wired, Wi-Fi and tinySA timeline analysis

`WIFI_ANALYSIS_ENABLED=true` enables `nms-wifi-analysis.service` independently
from heartbeat. It binds Ping to the configured wired and Wi-Fi interfaces,
collects BSSID/channel/RSSI/link speed with `iw`, and keeps a 15-minute local
ring. A Ping whose egress interface cannot be verified is stored as
`route_unverified` and is not used as valid path evidence.

Normal connectivity is reduced to a configurable representative interval.
When latency, loss, RSSI, BSSID or RF triggers fire, the agent preserves the
five minutes before and after the event. Offline batches remain under
`/var/lib/nms-collector/wifi-analysis/queue`.

tinySA is optional. Keep `TINYSA_ENABLED=false` until the USB device, supported
band and antenna profile are verified. A single sweep cannot prove that no
short pulse occurred, so unavailable pulse evidence remains `null`. tinySA
power dBm and Wi-Fi RSSI are not treated as the same absolute measurement.
The helper enables Ultra mode before every sweep whose stop frequency exceeds
900 MHz. The GUI stores operator-confirmed antenna and level-calibration
profiles instead of inferring calibration from the serial console.
Wi-Fi presets use eight frequency-aligned sweeps and store their pointwise
maximum as an explicit `max_hold` record so short AP transmissions are less
likely to be missed. Non-Wi-Fi presets default to one raw sweep.
The RF GUI can switch between `single_sweep`, `max_hold`, `average`, and
`min_hold` and set 1-32 repetitions. The selected mode and actual repetition
count are written into the normalized source metadata.

The Wi-Fi scan inventories USB wireless hardware and reads the actual frequency
list from `iw phy`. A missing 5/6 GHz result is reported as unsupported when no
active radio can scan that band, instead of being reported as "no AP". USB
devices without a bound interface are retained as `driver_missing`, so newly
attached adapters remain visible to the operator. The pinned RTL8832BU/RTL8852BU
support installer can be run for known Realtek USB IDs:

```bash
sudo /opt/nms-collector/install-wireless-adapter-support.sh
```

RTL8852BU is dual-band 2.4/5 GHz hardware. A separate Wi-Fi 6E/7 adapter whose
Linux driver exposes 6 GHz frequencies is required for 6 GHz AP scanning.
The RF "장비 확인" action opens the serial device and verifies the tinySA
firmware response. It distinguishes missing device, permission, busy, timeout,
dependency, and protocol errors. Stable `/dev/tinysa4` and `/dev/serial/by-id`
paths are preferred over transient `ttyACM*` names.

The RF page provides direct 2.4 GHz, 5 GHz, and 6 GHz Wi-Fi band selectors.
Its spectrum chart uses regular frequency grid intervals (10 MHz, 100 MHz,
and 200 MHz respectively) and overlays Wi-Fi channel-center guides as a
separate dashed layer. Frequency and channel labels are not treated as the
same axis value.

The installer adds the desktop operator to `dialout` and installs
`70-metro-tinysa.rules` with both the `dialout` group and the active-session
`uaccess` tag. If the desktop was already logged in when the group was added,
sign out once and sign in again. A GUI process started by the old login session
cannot inherit the newly added supplementary group.

```bash
node /opt/nms-collector/nms-wifi-analysis.js doctor
systemctl status nms-wifi-analysis.service
journalctl -u nms-wifi-analysis.service -n 100 --no-pager
```
