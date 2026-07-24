# METRO Agent

METRO 현장 네트워크 수집기와 진단 GUI의 독립 저장소입니다.

## 범위

- Ubuntu 현장 수집기와 자동 시작/복구 서비스
- 유선·무선 네트워크 진단
- Ping, DNS, traceroute, ARP, VLAN, LLDP/CDP, SNMP, 패킷 캡처
- iperf3 대역폭 측정
- WireGuard 원격 관리 상태 확인
- 현장 프로필과 오프라인 측정 큐
- Windows/Python 진단 GUI

중앙 NMS API, PostgreSQL migration, Grafana 대시보드는
`network-server` 저장소가 담당합니다. 이 저장소에는 토큰, 비밀번호,
실제 `collector.env`, 패킷 원본 및 운영 백업을 저장하지 않습니다.

## 디렉터리

```text
collector/common/       공통 현장 프로필 규격
collector/ubuntu/       Ubuntu 수집기, GUI, 설치 스크립트, systemd
collector/python_gui/   Windows/Linux Python GUI
docs/                   요구사항, 구현 계획, 운영 문서
test/                   Node.js 및 Python 테스트
```

## Ubuntu 설치

```bash
cd collector/ubuntu
cp collector.env.example collector.env
# collector.env에 운영 서버 주소와 별도로 발급한 토큰을 입력
sudo bash install-collector.sh --env-file ./collector.env
```

설치 후 확인:

```bash
sudo systemctl status nms-collector-heartbeat.timer
sudo systemctl status nms-collector-diagnostic-worker.service
sudo systemctl status nms-collector-edge-analysis.timer
node /opt/nms-collector/nms-collector.js doctor
```

## 테스트

```bash
npm test
```

Wi-Fi 품질 분석 1차 개발 범위는
[docs/WIFI_ANALYSIS_PHASE1_PLAN.md](docs/WIFI_ANALYSIS_PHASE1_PLAN.md)를
기준으로 진행합니다.

기존 33 NMS와 130 수집기를 유지하면서 추가하는 Metro Agent 실행
계층과 중앙 API 계약은
[docs/METRO_AGENT_PLATFORM_V1.md](docs/METRO_AGENT_PLATFORM_V1.md)를
기준으로 합니다.
