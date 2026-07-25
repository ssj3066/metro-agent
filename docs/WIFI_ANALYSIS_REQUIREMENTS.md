# 130 Server Wi-Fi Analysis Requirements

## 목표

130 분석 서버에서 다음 원천을 같은 시간축으로 결합해 간헐적인
지연과 끊김 원인을 분류한다.

- 유선·무선 네트워크 측정
- Wi-Fi 프로토콜과 연결 상태
- Omada AP 운영 데이터
- tinySA Ultra+ ZS407 RF 스펙트럼

분류 대상은 상위 유선망/회선, AP/uplink, AP 부하, 채널 혼잡,
비-Wi-Fi RF 간섭, 로밍/인증, 커버리지 경계이다.

## 수집 항목

- 유선: 게이트웨이·내부 서버·외부 IP Ping, DNS 응답시간, 손실
- Wi-Fi: SSID/BSSID, 채널·주파수·폭, RSSI/SNR, 링크 속도,
  Retry, Deauth/Disassoc, 로밍
- Omada: AP CPU/메모리, 클라이언트, 채널 이용률, 트래픽,
  DFS·채널 변경·재부팅·uplink·연결 해제 이벤트
- tinySA: USB 직렬 스윕, 실제 RF 에너지, 순간 펄스, 연속파

tinySA는 측정시각, 센서, 대역, 시작/종료 주파수, RBW, 감쇠,
LNA, 안테나 프로필, 주파수/전력 배열, peak/average/noise floor,
occupied bandwidth, occupancy와 탐지 결과를 저장한다.

## 주기와 장애 창

- 유선·무선 Ping: 1초
- Wi-Fi 상태: 5초
- Omada 상태: 10~30초
- tinySA 스윕: 현재 30초 저장 주기, 장애 시 수동 고밀도 측정
- 공통 NTP 기준 사용
- 최근 15분 순환 버퍼 유지
- 장애 발생 시 전 5분과 후 5분 영구 저장

## 판정 원칙

- 유선과 무선 동시 이상: 공통 구간·게이트웨이·회선 가능성
- 유선 정상, 무선과 AP 관리 Ping 이상: AP 또는 uplink 가능성
- 유선/AP 정상, Retry와 RF 에너지 증가: RF 간섭 가능성
- Wi-Fi 활동은 적고 RF 에너지 높음: 비-Wi-Fi 간섭 가능성
- RF 변화 없이 BSSID/Deauth/재연결: 로밍·인증 가능성
- AP 부하·airtime·채널 이용률 증가: AP 포화 가능성
- RSSI/SNR만 낮음: 커버리지 경계 가능성

누락 원천이 있으면 확정하지 않는다. tinySA는 물리계층 보조 센서,
Wi-Fi 어댑터는 802.11 계층, Omada는 AP 운영 상태의 근거로 사용한다.
규칙 기반 결과는 원천을 숨기거나 자동 확정하는 기능이 아니라 사용자가
판단할 수 있도록 시간축과 가능성을 정리하는 보조 정보이다.
