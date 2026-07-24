# Wi-Fi Analysis Phase 1 Plan

## 현재 상태

- 130번은 유선과 USB 무선을 동시에 사용하며 NTP가 동기화되어 있다.
- `iw link`에서 BSSID, 채널, RSSI, TX/RX 링크 속도를 읽을 수 있다.
- 현재 드라이버의 `iw station dump`는 비어 있어 Retry 수집은 추가 검증이 필요하다.
- tinySA 장치는 아직 연결되지 않았고 Python `pyserial`도 미설치이다.
- 기존 무선 스캔은 주변 AP 검색용이며 연결 품질 시계열은 아니다.
- 33번 DB의 기존 측정 테이블은 세션 요약 중심이다.

## 1차 구현

1. 유선·무선 인터페이스를 명시한 1초 Ping을 동시에 수집한다.
2. 5초마다 RSSI, BSSID, 채널과 링크 속도를 수집한다.
3. 15분 로컬 순환 버퍼와 장애 전후 5분 보존을 구현한다.
4. tinySA USB 연결과 단일 대역 스윕을 구현한다.
5. 정상 구간은 축약하고 장애 창은 1초 원본으로 중앙 전송한다.
6. 규칙 기반 이벤트를 생성하고 누락 원천은 `unknown`으로 유지한다.
7. Omada 컨트롤러 종류, 버전, API와 제공 지표를 조사한다.
8. 33번의 같은 시간축 Grafana 패널은 `network-server`에서 구현한다.

## 중앙 계약

예정 ingress:

```text
POST /api/collectors/:id/wifi-analysis/batches
```

배치는 `batch_id`로 멱등 처리하고 connectivity, Wi-Fi, RF 스윕,
이벤트를 함께 전송한다. 실제 DB migration과 API 구현은
`network-server` 저장소가 소유한다.

## 위험 관리

- 인터페이스 바인딩 후 실제 egress route를 검증한다.
- monitor mode가 필요한 기능은 기본 무선 연결을 끊을 수 있어 1차에서 제외한다.
- tinySA 실제 스윕 시간과 지원 대역은 실장비로 확인한다.
- 정상 1초 데이터를 무제한 중앙 저장하지 않는다.
- 신규 분석기는 기존 heartbeat와 분리된 systemd 서비스로 배포한다.

