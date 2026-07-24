# METRO NMS_Collecter

외부 현장 PC에서 NMS Collector를 등록하고 heartbeat를 전송하는 Python GUI입니다.

## 기본값

- NMS 주소: `https://112.167.190.125:7443`
- 전송 방식: `POST /api/collectors/{id}/heartbeat`
- 인증 헤더: `X-Collector-Token`
- 토큰 발급: 관리자 로그인 후 `POST /api/collectors`
- 119 VPN 주소: `http://192.168.1.119:8660`
- 119 HTTPS 대체 주소: `https://112.167.190.125:7443`
- 119 인증: 취소 가능한 장치 토큰 `X-Ict-Device-Token`

## 실행

Python이 설치된 PC에서는 아래처럼 바로 실행할 수 있습니다.

```powershell
python METRO_NMS_Collecter.pyz
```

소스 폴더에서 실행할 때는 아래 명령을 사용합니다.

```powershell
python nms_field_collector_gui.py
```

## Windows exe 만들기

Windows PC에서 이 폴더를 압축 해제한 뒤 아래 파일을 실행합니다.

```cmd
build-windows-exe.cmd
```

완료 후 실행 파일은 `dist\METRO_NMS_Collecter.exe`에 생성됩니다.

## 사용 순서

1. `연결` 탭에서 NMS 주소가 `https://112.167.190.125:7443`인지 확인합니다.
2. 현재 7443 인증서가 사설/자가서명 인증서면 `자가서명 인증서 허용`을 켭니다.
3. `연결 테스트`를 눌러 `/health` 응답을 확인합니다.
4. `Collector 등록` 탭에서 이름, 플랫폼, 역할, 현장 ID, IP, 메모를 입력합니다.
5. `연결` 탭에서 관리자 ID/비밀번호를 입력하고 `로그인 후 토큰 발급`을 누릅니다.
6. `실행` 탭에서 발급된 `Collector ID`와 `Collector Token`을 확인합니다.
7. `Heartbeat 1회 전송`으로 정상 전송을 확인합니다.
8. 필요하면 `주기 전송 시작`으로 계속 heartbeat를 보냅니다.
9. `현장 프로필` 탭에 119 장치 토큰을 입력하고 `현장 새로고침`을 누릅니다.
10. 119가 할당한 현장을 선택하고 진단 수집 후 `현재 진단값 적용`을 누릅니다.

## 119 현장 동기화

고객·현장 기준정보는 119 ICT Manager가 소유합니다. 수집기에서는 고객명이나 현장명을 별도로 만들지 않고, 장치 토큰에 할당된 현장만 자동 조회합니다.

전송은 VPN 직접 경로를 먼저 사용하고 실패하면 공인 HTTPS 대체 경로를 사용합니다. 두 경로가 모두 실패하면 세션과 프로필을 오프라인 큐에 저장하며 `대기 자료 재전송`으로 복구할 수 있습니다. 화면의 통신 상태는 `VPN 연결`, `HTTPS 대체 연결`, `오프라인 저장`, `저장된 현장 목록`으로 구분됩니다.

## 진단 수집

`진단 수집` 탭은 현장 PC 기준으로 아래 정보를 모아 JSON으로 보여주고 저장합니다.

- 스위치/링크 정보: 어댑터 상태, MAC, 링크 속도, 기본 게이트웨이 MAC
- LLDP/CDP 정보: Windows 기본값과 TShark 패킷 캡처 결과에서 힌트 추출
- VLAN 정보: Windows 어댑터 고급 속성, Linux `ip -d link`, `nmcli`의 VLAN 관련 값
- VPN 정보: Windows `Get-VpnConnection`, VPN/TAP/TUN/WireGuard/OpenVPN/Forti/Cisco 계열 어댑터 힌트
- Ping/Jitter: gateway, DNS 대상 RTT, 손실률, 평균, jitter
- ARP 정보: `arp -a` 또는 `ip neigh`
- IP/DNS/라우팅 정보: `ipconfig`, `route print`, `ip`, `resolvectl` 등
- Wireshark 패킷 정보: TShark가 있으면 LLDP/CDP/ARP/ICMP/DNS 샘플 캡처

Gateway 대상이 비어 있으면 기본 라우트에서 자동 탐지합니다. 패킷 캡처는 Windows에서 Wireshark/TShark와 Npcap이 필요하며, 관리자 권한이 필요할 수 있습니다. 수집 결과 전체는 로컬 JSON으로 저장하고, `다음 Heartbeat에 진단 요약 포함`을 켜면 요약만 NMS heartbeat metadata에 포함합니다.

## 설정 파일

- 기본 경로는 기존 설정 호환을 위해 Windows `%APPDATA%\MetroNMSFieldCollector\config.json`, Linux `~/.config/metro-nms-field-collector/config.json`입니다.
- 관리자 비밀번호는 저장하지 않습니다.
- Collector Token과 119 장치 토큰은 `설정 파일에 Collector Token 저장`을 켠 경우에만 저장합니다.
