# 상관 분석 엔진 구현 결과

작성일: 2026-07-24  
개발 절차: 10단계 `상관 분석 엔진 구현`

## 구현 결과

- 9단계의 UTC 시간 프레임을 입력으로 사용하는 순수 규칙 엔진을 구현했다.
- 분석 실행 이력과 규칙별 결과를 분리하여 저장한다.
- 같은 세션, 엔진 버전, 임계값, 원천 표본은 입력 해시로 중복 분석을 방지한다.
- 결과에는 등급, 이상 시작·종료 시각, 값·단위·원천·측정시각,
  판단 근거, 원인 후보별 신뢰도, 반박 근거, 누락 데이터, 추가 확인,
  현장 조치, 재측정 조건을 저장한다.
- 유선·무선·RF 커버리지와 NTP 상태를 신뢰도 정책에 반영한다.
- 원천 모듈이 빠지면 정상으로 판정하지 않고 `unknown/판단 보류`로 남긴다.
- NTP 경고가 있으면 상관 원인의 최대 신뢰도를 0.35로 제한한다.
- 반복된 동일 규칙은 하나의 이상 시간 구간으로 병합한다.
- RF 간섭은 지속성, 순간성, 비 Wi-Fi 후보를 구분하되 장비가 제공하지
  않는 사실은 확정하지 않는다.

## 구현 규칙

- RSSI 양호 + 무선 통신 품질 저하
- SNR 저하 + RF Noise Floor 상승
- 패킷 손실 증가 + RF Peak/점유율 증가
- 지연 증가 + RF 점유율 상승
- 재전송 카운터 증가 + 동일·인접 채널 혼잡 근거
- 무선 연결 해제 + RF 변화
- 유선 경로 이상과 무선 구간 이상 분리
- 약한 RSSI + 무선 품질 저하에 대한 AP 음영/단말 후보
- Pulse/연속파 + RF 변화에 대한 비 Wi-Fi 간섭 후보

## DB 변경

- `db/migrations/064_add_measurement_correlation_results.sql`
- `measurement_correlation_runs`
- `correlation_results`

AI 분석은 이 테이블에 섞지 않고 11단계에서 별도 구조로 구현한다.

## API

- `POST /api/measurement-sessions/:sessionId/analyze`
- `GET /api/measurement-sessions/:sessionId/analysis`
- `GET /api/measurement-sessions/:sessionId/analysis?run_id=:runId`

상세 계약은 `docs/SIMULTANEOUS_MEASUREMENT_API_CONTRACT.md`에 반영했다.

## 주요 변경 파일

33번 NMS 저장소:

- `db/migrations/064_add_measurement_correlation_results.sql`
- `lib/measurement-correlation-engine.js`
- `lib/measurement-session-store.js`
- `lib/measurement-session-route-handler.js`
- `server.js`
- `test/measurement-correlation-*.test.js`
- `test/measurement-session-*.test.js`
- `README.md`

Metro Agent 저장소:

- `docs/SIMULTANEOUS_MEASUREMENT_API_CONTRACT.md`
- `docs/SIMULTANEOUS_MEASUREMENT_PHASE10_RESULT.md`

## 정확도 정책

- 규칙은 측정된 수치가 임계값을 충족할 때만 실행한다.
- 관련 측정값은 값, 단위, 원천, 원천 ID, 측정시각, 인터페이스·대상·채널
  차원을 보존한다.
- 비 Wi-Fi 간섭은 `continuous_wave_detected` 하나만으로 확정하지 않는다.
- RF 장비가 지원하지 않는 Jitter, 재전송률, AP airtime 등은 누락 또는
  추가 확인 항목으로 명시한다.
- 규칙 임계값 사용자 변경은 허용 목록, 수치 범위, 상·하위 임계값 관계를
  검증한다.

## 검증 결과

- 33번 NMS Node 테스트: 390개 통과
- Metro Agent Node 테스트: 77개 통과
- Metro Agent Python 테스트: 49개 통과, 환경 의존 테스트 7개 제외
- 규칙 엔진 대표 시나리오, 임계값 검증, DB migration, API 권한,
  분석 결과 영속화와 중복 실행 재사용 테스트 통과
- Node 문법 검사와 두 저장소 `git diff --check` 통과

## 현재 제한

- 운영 33번 DB/API에는 아직 배포하지 않았다.
- 분석은 저장된 표본을 대상으로 요청 시 실행하며 실시간 스트리밍 실행은
  아직 연결하지 않았다.
- RF의 단일 Sweep만으로 간섭원 종류를 확정할 수 없다.
- Jitter, 실제 재전송률, AP airtime, 인터페이스 error/discard 원천은
  현재 동시 측정 표본에 없으므로 판정 근거로 생성하지 않는다.
- AI 설명과 판단은 11단계 구현 대상이다.
- 119번 보고서 연결은 12단계 구현 대상이다.
