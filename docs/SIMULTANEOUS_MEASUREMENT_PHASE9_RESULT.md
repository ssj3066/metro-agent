# 시간 동기화 및 데이터 정규화 구현 결과

작성일: 2026-07-24  
개발 절차: 9단계 `시간 동기화 및 데이터 정규화 구현`

## 구현 결과

- 표본 저장 시각을 UTC ISO 8601로 정규화하고 표시 타임존은 `Asia/Seoul`로 분리했다.
- 연결성, Wi-Fi, RF 표본에 공통 세션과 모듈 실행 ID를 연결했다.
- 각 표본에 원천 처리 지연과 33번 수신 지연을 별도로 저장한다.
- 표본 상태를 `success`, `failure`, `unsupported`, `skipped`, `unknown`으로 제한했다.
- 측정되지 않은 값은 `null`, 자료가 없는 모듈 커버리지는 `unknown`으로 유지한다.
- 서로 다른 주기의 표본을 세션별 시간 윈도우로 가장 가까운 값끼리 정렬한다.
- 기본 상관 윈도우는 ±1초이며 100ms~30초 범위에서 조회 시 변경할 수 있다.
- NTP/서버 시각 차이가 불량하면 `clock_warning`과
  `insufficient_time_alignment` 정책을 반환한다.
- 선택하지 않은 모듈의 평상시 수집값은 활성 측정 세션에 잘못 귀속하지 않는다.
- GUI 상태문구에 NTP 저하, 비동기, 확인 불가 상태를 직접 표시한다.

## 주요 변경 파일

33번 NMS 저장소:

- `db/migrations/063_add_measurement_time_normalization.sql`
- `lib/measurement-time-normalizer.js`
- `lib/measurement-session-store.js`
- `lib/measurement-session-route-handler.js`
- `lib/wifi-analysis-store.js`
- `server.js`
- `test/measurement-time-*.test.js`
- `test/measurement-session-*.test.js`
- `test/wifi-analysis-store.test.js`

Metro Agent 저장소:

- `collector/ubuntu/nms-measurement-session.js`
- `collector/ubuntu/nms-wifi-analysis.js`
- `collector/ubuntu/nms-collector.js`
- `collector/ubuntu/nms-field-diagnostics.py`
- `test/wifi-analysis-agent.test.js`
- `test/ubuntu_field_diagnostics_gui_test.py`
- `docs/SIMULTANEOUS_MEASUREMENT_API_CONTRACT.md`

## API

- `GET /api/measurement-sessions/:sessionId/timeline`
- 선택 매개변수: `from`, `to`, `window_ms`, `limit`
- 반환값: 원천 표본, 모듈별 커버리지, NTP 경고, 시간 정렬 프레임

## 검증 결과

- 33번 NMS Node 테스트: 377개 통과
- Metro Agent Node 테스트: 77개 통과
- Metro Agent Python 테스트: 49개 통과, 환경 의존 테스트 7개 제외
- Node 문법 검사 통과
- Python bytecode 컴파일 통과
- 설치 셸 스크립트 문법 검사 통과
- 두 저장소 `git diff --check` 통과

## 현재 제한

- 운영 33번 DB와 130번 수집기에는 아직 배포하지 않았다.
- 반복 측정의 세부 원본은 기존 JSON 표본 형식을 유지하고, 집계 지표를
  유선/시스템 모듈 실행 ID에 연결한다.
- 패킷 캡처는 정규화 컬럼을 준비했지만 동시 측정 자동 실행 어댑터가 아직 없다.
- 시간 프레임은 데이터 정렬 결과이며 원인 판정은 하지 않는다.
- 규칙 기반 상관 원인 판정은 10단계에서 구현한다.
