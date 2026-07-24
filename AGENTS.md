# Metro Agent Repository Rules

## Ownership

- 이 저장소는 130번 Ubuntu 현장 수집기와 이동형 수집기 프로그램을 관리한다.
- 중앙 NMS API, PostgreSQL, Grafana 변경은 `network-server` 저장소에서 관리한다.
- 실제 운영 기준 데이터는 33번 NMS PostgreSQL/API 값이다.

## Accuracy

- 모든 측정값은 값, 단위, 원천, 측정시각, 신선도 상태를 포함한다.
- 미수집 값은 정상값으로 바꾸지 않고 `unknown` 또는 `insufficient_data`로 표시한다.
- tinySA dBm과 Wi-Fi RSSI를 같은 절대값으로 비교하지 않는다.
- 지정 인터페이스로 실제 라우팅되지 않은 Ping은 유선/무선 비교 근거로 사용하지 않는다.
- 원본값, 변환식, 반올림 기준을 보존한다.

## Security

- 토큰, 비밀번호, WireGuard private key, SNMP community와 실제 환경파일을 커밋하지 않는다.
- 패킷 원본과 고객 개인정보를 저장소에 커밋하지 않는다.
- 예제 설정에는 placeholder만 사용한다.

## Changes

- 기존 heartbeat와 진단 기능을 깨지 않도록 새 기능을 독립 서비스로 추가한다.
- 파일 변경 전 운영 파일을 백업한다.
- 변경 후 Node.js/Python 테스트와 systemd/API smoke test를 실행한다.
- Git commit/push는 사용자가 명시적으로 요청한 경우에만 수행한다.

