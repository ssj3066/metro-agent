# 동시 측정 세션 구조 구현 결과

작성일: 2026-07-24  
개발 절차: 8단계 `동시 측정 세션 구조 구현`

## 구현 결과

- `measurement_session_id`를 UUID v4 공통 작업 식별자로 사용한다.
- 130번 감독기가 유선, 무선, RF, 선택 패킷 캡처, 시스템 모듈을 하나의 세션으로 시작한다.
- 시작 전 NTP 상태, chrony 오프셋, 서버 시각 차이, 유선/무선 인터페이스, RF 장비 상태를 사전 점검한다.
- 모듈별 실행 상태와 표본 수, 오류 코드, 오류 메시지를 독립 저장한다.
- 한 모듈이 실패해도 성공한 모듈 결과를 보존하고 최종 상태를 `completed`, `partial`, `failed`로 구분한다.
- 기존 반복 측정, Wi-Fi/연결성/RF 배치, 패킷 캡처 요약에 상위 세션 참조를 추가한다.
- 119의 현장 ID와 33의 NMS `sites.id`가 다른 네임스페이스임을 분리 저장한다.
- GUI에서 동시 측정 시작, 일시 정지, 계속, 안전 중지, 상태 새로고침을 제공한다.
- 로컬 상태는 원자적 JSON 파일로 기록하고 종료 상태는 `last.json`에 보존한다.

## 주요 변경 파일

33번 NMS 저장소:

- `db/migrations/062_add_simultaneous_measurement_sessions.sql`
- `lib/measurement-session-store.js`
- `lib/measurement-session-route-handler.js`
- `lib/collector-ingress-handler.js`
- `lib/request-paths.js`
- `lib/wifi-analysis-store.js`
- `server.js`
- `test/measurement-session-*.test.js`
- `test/collector-ingress-handler.test.js`
- `test/request-paths.test.js`
- `test/wifi-analysis-store.test.js`

Metro Agent 저장소:

- `collector/ubuntu/nms-measurement-session.js`
- `collector/ubuntu/nms-wifi-analysis.js`
- `collector/ubuntu/nms-collector.js`
- `collector/ubuntu/nms-field-diagnostics.py`
- `collector/ubuntu/install-collector.sh`
- `collector/ubuntu/collector.env.example`
- `test/measurement-session-supervisor.test.js`
- `test/wifi-analysis-agent.test.js`
- `test/collector-ubuntu.test.js`
- `test/ubuntu_field_diagnostics_gui_test.py`

## 검증 결과

- 33번 NMS Node 테스트: 368개 통과
- Metro Agent Node 테스트: 76개 통과
- Metro Agent Python 테스트: 49개 통과, 환경 의존 테스트 7개 제외
- Node 문법 검사 통과
- Python bytecode 컴파일 통과
- 설치 셸 스크립트 문법 검사 통과
- 두 저장소 `git diff --check` 통과

## 현재 제한

- 운영 33번 DB 마이그레이션과 130번 설치는 아직 수행하지 않았다.
- 개별 표본의 공통 필드, 장비 지연, 수신 지연, 서로 다른 주기의 시간 윈도우 정규화는 9단계 대상이다.
- 패킷 캡처 모듈은 세션 상태를 기록하지만 자동 캡처 어댑터는 아직 연결하지 않았다.
- 공통 세션 생성 API가 끊긴 상태에서 측정을 시작하는 오프라인 수명주기와 재전송은 후속 구현 대상이다.
- 상관 분석, 118 AI 분석, 119 자동 보고서는 각각 10~12단계 대상이다.

## 다음 단계

9단계에서는 UTC 표본 공통 필드, `module_run_id`, 원천/수신 지연, ±1초 기본 시간 윈도우, NTP 불량 경고와 누락값 `null` 정책을 실제 표본에 적용한다.
