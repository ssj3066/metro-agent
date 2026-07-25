# Metro Agent 동시 측정·분석·보고서 1차 설계

작성일: 2026-07-24  
대상: Metro Agent(130), NMS 중앙 서버(33), ICT Manager 보고서 서버(119)

## 1. 조사 범위와 확인 결과

### Metro Agent 저장소

경로: `/home/metro/work/metro-agent`

현재 재사용 가능한 기능:

- `nms-field-diagnostics.py`
  - 현장 선택, 반복 측정 시작, 패킷 캡처 시작/안전 중지, RF 단발 측정
  - 오프라인 큐 조회/재전송
  - 119 현장 프로필 동기화
- `nms-collector.js`
  - 게이트웨이·KT DNS·Google DNS Ping, CPU/메모리/디스크, 인터페이스 송수신량 반복 측정
  - `client_session_id` 기반 로컬 원자적 JSON 큐
  - 33번 오프라인 측정 업로드와 멱등 처리
  - 패킷 캡처 요약, 원본 경로와 SHA-256 관리
- `nms-wifi-analysis.js`
  - 유선/무선 경로별 연결성 측정
  - 무선 연결 품질과 RF 스윕을 한 루프에서 수집
  - 정상 표본 축약, 장애 전후 링 버퍼, 이벤트 분류, 배치 재전송
- `nms-tinysa-sweep.py`
  - tinySA Ultra ZS407 스윕
  - 주파수/전력 원본 배열, Peak, 평균, Noise Floor, 점유율, 보정 상태 저장
- `ict_field_client.py`
  - VPN 우선, HTTPS 대체 경로
  - 119 장치 인증, 현장 목록 캐시, 오프라인 재전송

현재 한계:

- 반복 측정, Wi-Fi/RF 서비스, 패킷 캡처가 서로 다른 세션으로 동작한다.
- 공통 `measurement_session_id`를 모든 배치와 원본 파일에 전달하지 않는다.
- 일시 정지/재개 및 세션 단위 안전 중지 상태 머신이 없다.
- NTP 오프셋과 수집 지연을 세션 근거로 보존하지 않는다.
- 메모와 사진을 세션에 첨부하는 전송 계약이 없다.

### 33번 NMS 저장소와 운영 DB

개발 경로: `/home/metro/network-server`  
운영 경로: `/home/metrodesk/network-server`

현재 재사용 가능한 기능:

- `collector_measurement_sessions`, `collector_measurement_metrics`
  - 반복 측정 원본 표본과 최소/평균/최대 통계
  - `(collector_id, client_session_id)` 멱등 저장
- `collector_wifi_analysis_batches`
  - `batch_id` 기반 멱등 저장
- `collector_connectivity_samples`, `collector_wifi_samples`, `collector_rf_sweeps`
  - UTC 측정시각 기반 원천 데이터 저장
- `collector_packet_capture_summaries`
  - 캡처 범위, 통계, 원본 파일 메타데이터, 해시 저장
- `collector_check_batches`, `collector_check_results`
  - Metro Agent v1 일반 점검 결과 저장
- 수집기 토큰 인증과 ingress 전용 API

2026-07-24 운영 DB 확인값:

- 반복 측정 세션: 7건
- Wi-Fi 분석 배치: 2,314건
- RF 스윕: 798건

현재 한계:

- 위 데이터가 같은 작업을 나타내더라도 공통 외래키가 없다.
- 장비, 파일, 세션 모듈 상태, 상관 분석, AI 분석, 보고서 작업 테이블이 없다.
- RF 원본 배열이 JSONB에 함께 저장되어 대형 스윕 확장에 불리하다.
- 세션 조회/완료/분석/보고서 요청 API가 없다.

### 119번 ICT Manager 저장소와 운영 서비스

개발 경로: `/home/metro/work/ict-manager-119`  
운영 경로: `/home/metro/apps/ict-manager`  
서비스: `ict-manager.service`, TCP 8660

현재 재사용 가능한 기능:

- 현장 수집 데이터 조회: `GET /api/nms/field-collection`
- 고객사/현장/수집기 매핑
- 수집 성능자료 HTML 미리보기, 인쇄, PDF 생성
- 인터페이스/IP, ARP, LLDP, 반복 측정, iPerf, 패킷 캡처, Pulse 보고서 페이지
- PDF와 유지보수 점검표 첨부 저장
- `field_profile_sessions`와 현장 프로필 스냅샷 멱등 저장

운영 DB 확인값:

- 저장 보고서: 8건
- 수집기-현장 매핑: 1건
- 등록 현장 클라이언트: 1대

현재 한계:

- PDF는 브라우저에서 생성해 업로드하므로 측정 종료 후 자동 생성되지 않는다.
- 특정 공통 측정 세션을 선택해 33번 원천 데이터를 고정하는 구조가 없다.
- HTML/PDF/JSON/CSV 파일 세트와 파일별 해시를 한 보고서로 관리하지 않는다.
- 보고서 생성 작업 상태와 실패 재시도 정보가 없다.

## 2. 재사용·누락·호환성 변경 구분

### 그대로 재사용

- 현장/고객/수집기 등록과 119 장치 인증
- 130의 네트워크 진단, Wi-Fi, tinySA, 캡처 수집기
- 기존 원자적 JSON 큐와 배치 멱등 처리 방식
- 33번의 원천 데이터 테이블과 collector token 인증
- 119의 수집 성능자료 레이아웃, PDF 보관, 점검표 첨부

### 확장 후 재사용

- `collector_measurement_sessions`
  - 새 상위 세션 테이블의 `measurement_session_id`를 참조하도록 확장
- Wi-Fi/RF/연결성 배치
  - 공통 세션 ID, 모듈 실행 ID, 수집 지연을 추가
- 패킷 캡처 요약
  - 공통 세션과 원본 파일 레코드를 참조하도록 확장
- 119 보고서
  - 브라우저 즉시 생성은 유지하고 서버 자동 생성 작업을 추가

### 신규 구현

- 세션 상태 머신과 모듈 감독기
- 장비/모듈/파일/첨부/이벤트 메타데이터
- 시간 정규화와 ±1초 기본 상관 윈도우
- 규칙 기반 상관 분석 결과
- 118 LLM 분석 결과와 규칙 결과의 분리 저장
- 119 보고서 작업 큐와 HTML/PDF/JSON/CSV 자동 생성

## 3. 현재 흐름과 목표 흐름

### 현재

```text
130 반복 측정 --------> 33 collector_measurement_sessions
130 Wi-Fi/RF 서비스 --> 33 wifi/connectivity/rf tables
130 패킷 캡처 -------> 33 packet capture summary
130 현장 프로필 -----> 119 field profile snapshot
119 화면 -----------> 33 집계 조회 -> 브라우저 PDF -> 119 저장
```

같은 현장에서 같은 시간에 측정해도 각 결과 사이에 공통 작업 식별자가 없다.

### 목표

```text
119 현장 선택
    |
130 동시 측정 시작
    |
    +-- 세션 생성/시간 동기화 확인
    +-- 유선 모듈
    +-- 무선 모듈
    +-- RF 모듈
    +-- 선택 패킷 캡처
    +-- 시스템 상태
    |
로컬 세션 manifest + 모듈별 원본/해시 + 전송 큐
    |
33 세션/원천/파일 메타데이터 저장
    |
33 규칙 기반 시간 상관 분석
    |
118 근거 패키지 기반 AI 설명
    |
119 보고서 작업 생성
    |
HTML + PDF + JSON + CSV + 첨부파일 보관
```

## 4. 공통 세션 계약

공통 ID는 UUID v4 문자열 `measurement_session_id`로 정의한다.

세션 상태:

```text
created -> preflight -> running -> paused -> running
running/paused -> stopping -> completed
created/preflight/running/paused/stopping -> partial
created/preflight/running/paused/stopping -> failed
```

`partial`은 한 개 이상 모듈이 성공하고 다른 모듈이 실패한 상태다. 모듈 하나의 실패가 전체 프로세스를 종료시키지 않는다.

모든 측정 레코드의 공통 필드:

```json
{
  "measurement_session_id": "uuid",
  "module_run_id": "uuid",
  "site_id": 10,
  "agent_id": 17,
  "device_id": "local-device-or-instrument-id",
  "measurement_type": "wired|wireless|rf|packet_capture|system",
  "sampled_at": "2026-07-24T10:00:00.123Z",
  "timezone": "Asia/Seoul",
  "source_delay_ms": 12.3,
  "ingest_delay_ms": 84.7,
  "status": "success|failure|unsupported|skipped",
  "error_code": null,
  "error_message": null
}
```

원천 장비가 제공하지 않는 값은 `null`, 실행하지 않은 측정은 `skipped`, 장비 미지원은 `unsupported`로 구분한다.

## 5. 시간 동기화 설계

세션 시작 전 다음을 저장한다.

- `timedatectl show`의 NTP 동기화 상태
- `chronyc tracking` 또는 `timedatectl timesync-status`의 오프셋
- 서버 시각 왕복 측정으로 구한 추정 API 시각 차이
- 로컬 타임존과 UTC 변환 기준

판정:

- 오프셋 절댓값 1초 이하: `synced`
- 1초 초과 5초 이하: `degraded`
- 5초 초과 또는 확인 불가: `unsynced`/`unknown`

저장은 UTC, 표시만 `Asia/Seoul`로 변환한다. 상관 분석 기본 윈도우는 ±1초이며 세션별로 100ms~30초 범위에서 변경 가능하게 한다. `unsynced` 상태에서는 자동 원인 확정을 금지하고 `판단 보류` 경고를 생성한다.

## 6. 33번 DB 마이그레이션 설계

예정 파일: `db/migrations/062_add_simultaneous_measurement_sessions.sql`

### 신규 테이블

`measurement_sessions`

- UUID 기본키
- collector/customer/site/agent 참조
- 상태, 시작/종료, timezone
- 샘플 주기, 상관 윈도우
- NTP 상태/오프셋/API 시각 차이
- 메모, 모듈 선택, 성공/실패 요약
- idempotency key, 생성/수정시각

`measurement_devices`

- 세션, 모듈 종류, 장치 종류
- 모델명, 시리얼, 펌웨어, 인터페이스/장치 경로
- 안테나, 보정상태, 설정 JSON

`measurement_module_runs`

- 세션, 모듈 종류, 상태
- 시작/종료, 표본 수, 오류 코드/메시지
- 원천 지연과 수집 지연 통계

`wired_samples`

- 세션/모듈/UTC 시각
- 링크, 속도, duplex, IP/subnet/gateway/DNS/DHCP/VLAN
- Ping/loss/jitter/TCP/업다운 속도
- 오류 카운터와 사용률
- 원천, 단위 메타데이터

`measurement_files`

- 세션/모듈/파일 종류
- 로컬 상대경로 또는 object key
- 크기, MIME, SHA-256, 보존기한
- 업로드 상태와 idempotency key

`measurement_events`

- 세션, 등급, 시작/종료
- 규칙 ID, 근거 JSON, 누락 근거, 상태

`correlation_results`

- 세션/이벤트
- 규칙 버전, 결과 등급, 원인 후보
- 신뢰도, 근거, 반박 근거, 추가 확인, 조치, 재측정 조건

`ai_analysis_results`

- 세션, 분석 제공자/모델/프롬프트 버전
- evidence pack hash
- 상태, 확정 사실/추정/반박/누락/조치
- 오류와 생성시각

`report_jobs`

- 세션, 요청 출력 형식, 상태, 재시도 수
- 119 callback URL이 아닌 119 작업 참조 ID
- 오류, 요청/완료시각

### 기존 테이블 변경

- `collector_measurement_sessions.measurement_session_id UUID NULL`
- `collector_wifi_analysis_batches.measurement_session_id UUID NULL`
- `collector_connectivity_samples.measurement_session_id UUID NULL`
- `collector_wifi_samples.measurement_session_id UUID NULL`
- `collector_rf_sweeps.measurement_session_id UUID NULL`
- `collector_packet_capture_summaries.measurement_session_id UUID NULL`
- 각 테이블에 `(measurement_session_id, observed_at)` 계열 인덱스 추가

기존 행은 모두 `NULL`을 허용하여 운영 호환성을 유지한다. 기존 API와 대시보드는 변경 없이 계속 동작해야 한다.

RF 주파수/전력 배열은 1차에서 기존 JSONB를 유지하되, 배열 직렬화 크기가 임계값을 넘으면 `measurement_files`에 gzip JSON/CSV로 분리하고 DB에는 요약값과 파일 참조만 저장한다.

## 7. 119번 DB 변경 설계

예정 변경:

- `measurement_report_jobs`
  - 세션 ID, 현장/고객/수집기, 상태, 출력 형식, 오류, 재시도, 요청자
- `generated_measurement_reports`
  - 작업 ID, 세션 ID, 버전, 스냅샷 JSON
  - HTML/PDF/JSON/CSV 경로와 SHA-256
  - 생성자/확인자/서명 정보
- `measurement_report_attachments`
  - 보고서, 종류, 파일명, 경로, MIME, 크기, SHA-256

기존 `nms_collection_reports`는 이전 보고서 호환용으로 유지한다. 신규 자동 보고서는 별도 테이블을 사용하고 목록 화면에서 두 유형을 함께 표시한다.

## 8. API 계약

### 33번 Collector ingress

`POST /api/collectors/:collectorId/measurement-sessions`

- 세션 생성
- `X-Collector-Token` 인증
- `Idempotency-Key` 필수
- 응답: 세션 ID, 서버 시각, 허용 모듈, 설정 버전

`POST /api/collectors/:collectorId/measurement-sessions/:sessionId/module-runs`

- 모듈 시작/종료/실패 상태 저장

`POST /api/collectors/:collectorId/measurement-sessions/:sessionId/samples`

- 유선/무선/RF/시스템 표본 배치 업로드
- 최대 건수와 본문 크기 제한
- `batch_id` 멱등 처리

`POST /api/collectors/:collectorId/measurement-sessions/:sessionId/files`

- 파일 메타데이터 등록 후 업로드 ID 발급
- 원본 파일과 일반 JSON을 분리

`PUT /api/collectors/:collectorId/measurement-sessions/:sessionId/files/:fileId/content`

- 스트리밍 업로드
- 완료 시 크기와 SHA-256 검증

`POST /api/collectors/:collectorId/measurement-sessions/:sessionId/complete`

- 모듈 상태를 취합하여 `completed|partial|failed` 확정
- 상관 분석 작업 예약

`GET /api/measurement-sessions/:sessionId`

- 관리자 인증
- 세션/장비/모듈/요약/신선도 조회

`GET /api/measurement-sessions/:sessionId/timeline`

- 시간축 정규화 결과 조회
- `from`, `to`, `resolution_ms`, `window_ms` 지원

`POST /api/measurement-sessions/:sessionId/analyze`

- 규칙 분석 재실행 또는 118 AI 분석 요청

`GET /api/measurement-sessions/:sessionId/analysis`

- 규칙 결과와 AI 결과를 분리하여 반환

### 119번 보고서 API

`POST /api/nms/measurement-reports`

- 세션 ID, 고객/현장, 제목, 작업자, 메모, 출력 형식 요청
- 33번 세션 범위와 현장 매핑 검증 후 작업 생성

`GET /api/nms/measurement-reports/jobs/:jobId`

- queued/running/completed/failed 상태와 오류 조회

`GET /api/nms/measurement-reports/:reportId`

- 저장 스냅샷, 파일 해시, 첨부, 생성정보 조회

`GET /api/nms/measurement-reports/:reportId/{html|pdf|json|csv}`

- 생성 파일 다운로드

`POST /api/nms/measurement-reports/:reportId/attachments`

- 사진/점검표/계획표 첨부

## 9. 상관 분석 1차 규칙

규칙 결과는 AI 결과와 별도 저장한다.

- 양호 RSSI + 높은 손실/지연: AP 부하, 상위 유선, 방화벽/회선 후보
- SNR 하락 + RF Noise Floor 상승: RF 간섭 후보
- 손실 증가 + 동일 시간 RF Peak 상승: 특정 대역 간섭 후보
- 지터 상승 + 점유율 상승: 채널 혼잡 후보
- 재전송 상승 + 동일/인접 채널 AP 증가: Wi-Fi 경합 후보
- 연결 끊김 + RF 변화 없음: AP/인증/단말/상위망 후보
- 유선·무선 동시 악화: 공통 게이트웨이/회선 후보
- 무선만 악화: AP/RF/무선 단말 후보

각 결과는 근거값, 단위, 원천 시각, 시간차, 신선도, 반박 근거, 누락 데이터를 포함한다. 근거가 부족하면 원인 등급을 확정하지 않고 `insufficient_data`로 저장한다.

## 10. 변경 대상 파일

### Metro Agent

- `collector/ubuntu/nms-field-diagnostics.py`
  - 동시 측정 화면, 진행률, 모듈 상태, 일시정지/재개/안전중지, 메모/사진
- `collector/ubuntu/nms-collector.js`
  - 세션 생성/완료, 유선·시스템 표본, 공통 큐/해시/재전송
- `collector/ubuntu/nms-wifi-analysis.js`
  - 활성 세션 인식, Wi-Fi/RF 표본에 세션 ID 부여
- `collector/ubuntu/nms-tinysa-sweep.py`
  - 세션/장비 메타데이터, 지원하지 않는 필드의 명시적 null
- `collector/ubuntu/ict_field_client.py`
  - 119 보고서 요청/상태/열기
- 신규 `collector/ubuntu/nms-measurement-session.js`
  - 세션 상태 머신과 모듈 감독
- 신규 `collector/ubuntu/nms-measurement-correlation.js`
  - 로컬 미리보기용 시간 정렬과 1차 규칙
- 관련 systemd 설치 스크립트와 테스트

### 33번 network-server

- 신규 `db/migrations/062_add_simultaneous_measurement_sessions.sql`
- 신규 `lib/measurement-session-store.js`
- 신규 `lib/measurement-session-route-handler.js`
- 신규 `lib/measurement-correlation.js`
- `lib/collector-ingress-handler.js`
- `lib/request-paths.js`
- `lib/wifi-analysis-store.js`
- `server.js`
- 관련 Node 단위/통합 테스트

### 119번 ICT Manager

- `ict_manager/schema.sql`
- `ict_manager/db.py`
- `ict_manager/main.py`
- `ict_manager/static/index.html`
- `ict_manager/static/app.js`
- `ict_manager/static/styles.css`
- 신규 `ict_manager/measurement_report.py`
- 보고서/브라우저 검증 스크립트

## 11. 구현 순서

1. 33번 상위 세션 DB/API를 추가한다.
2. 130 세션 감독기와 공통 로컬 manifest/큐를 구현한다.
3. 기존 유선/Wi-Fi/RF/캡처 모듈에 세션 ID를 전달한다.
4. 시간 동기화와 지연 측정을 추가한다.
5. 규칙 기반 시간 상관 분석을 추가한다.
6. 118 evidence pack 기반 AI 분석을 연결한다.
7. 119 서버 자동 보고서 작업과 HTML/PDF/JSON/CSV를 구현한다.
8. GUI와 현장 운영 흐름을 연결한다.
9. 장애/오프라인/중복/장치 분리 시나리오를 통합 검증한다.

## 12. 테스트와 위험요소

필수 자동 테스트:

- 정상 동시 측정과 동일 세션 저장
- 무선만 실패, RF 미연결/중도 분리
- 캡처 안전 중지 후 재시작
- 측정 중 서버 단절과 재전송
- 중복 배치/파일 업로드
- NTP 불량과 상관 분석 보류
- 서로 다른 주기 표본의 ±1초 정렬
- 일부 데이터 누락 보고서
- 대용량 RF 원본 분리 저장
- 118 응답 실패 시 규칙 결과만으로 보고서 생성

주요 위험:

- 기존 운영 DB에 대형 인덱스를 즉시 만들면 잠금이 생길 수 있다.
- tinySA의 실제 지원 필드는 펌웨어별로 다르므로 null 허용이 필수다.
- 브라우저 PDF는 자동 작업에 적합하지 않으므로 119 서버 렌더러가 필요하다.
- Wi-Fi 서비스가 상시 수집 중이므로 세션 시작/종료 경계의 표본 포함 규칙이 필요하다.
- 33과 119 현장 매핑이 어긋나면 다른 고객 데이터가 보고서에 섞일 수 있다.

운영 반영 원칙:

- 33과 119 DB는 변경 전 백업한다.
- 모든 신규 컬럼은 1차에서 nullable로 추가한다.
- 기존 ingress와 보고서 API는 제거하거나 의미를 바꾸지 않는다.
- 개발 저장소 테스트 후 운영 파일을 별도 백업하고 배포한다.
- 운영 API, DB 저장, 서비스 상태, 119 PDF 파일 해시까지 검증한다.
