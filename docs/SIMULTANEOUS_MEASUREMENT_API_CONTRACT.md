# 동시 측정 API 계약서 v1

작성일: 2026-07-24  
기본 저장 시각: UTC ISO 8601  
표시 타임존: `Asia/Seoul`

## 공통 규칙

- Collector ingress 인증: `X-Collector-Token`
- 사용자/관리 API 인증: 기존 33번 로그인 세션
- 119 현장 클라이언트 인증: `X-Ict-Device-Token`
- 생성/배치/파일 요청은 `Idempotency-Key` 또는 본문의 고유 ID가 필수다.
- 같은 멱등 키와 같은 본문은 기존 결과를 반환한다.
- 같은 멱등 키와 다른 본문은 `409 idempotency_conflict`를 반환한다.
- 알 수 없는 값은 `null`, 미지원은 `unsupported`, 미실행은 `skipped`다.
- 측정되지 않은 수치를 `0`으로 대체하지 않는다.

오류 응답:

```json
{
  "error": {
    "code": "invalid_session_state",
    "message": "running 상태에서만 일시 정지할 수 있습니다.",
    "details": {},
    "request_id": "uuid"
  }
}
```

## 1. 세션 생성

`POST /api/collectors/:collectorId/measurement-sessions`

```json
{
  "measurement_session_id": "client-generated-uuid",
  "site_id": 10,
  "agent_id": 17,
  "timezone": "Asia/Seoul",
  "requested_duration_seconds": 900,
  "correlation_window_ms": 1000,
  "modules": {
    "wired": true,
    "wireless": true,
    "rf": true,
    "packet_capture": false,
    "system": true
  },
  "sampling": {
    "wired_interval_ms": 1000,
    "wireless_interval_ms": 5000,
    "rf_interval_ms": 3000,
    "system_interval_ms": 5000
  },
  "operator": {
    "name": "현장 작업자",
    "user_id": null
  },
  "notes": ""
}
```

응답 `201` 또는 멱등 재요청 `200`:

```json
{
  "measurement_session_id": "uuid",
  "status": "created",
  "server_time": "2026-07-24T10:00:00.000Z",
  "accepted_modules": ["wired", "wireless", "rf", "system"],
  "config_revision": 1
}
```

검증:

- collector와 site 매핑 불일치: `409 scope_mismatch`
- 같은 collector의 활성 세션 중복: 기본 `409 active_session_exists`
- 관리자 설정으로 동시 세션 수를 늘리기 전에는 활성 세션 1개만 허용

## 2. 세션 상태 변경

`PATCH /api/collectors/:collectorId/measurement-sessions/:sessionId`

```json
{
  "action": "start|pause|resume|stop",
  "client_time": "2026-07-24T10:00:02.000Z",
  "reason": "operator_request"
}
```

응답:

```json
{
  "measurement_session_id": "uuid",
  "status": "running",
  "updated_at": "2026-07-24T10:00:02.050Z"
}
```

## 3. 사전 점검

`POST /api/collectors/:collectorId/measurement-sessions/:sessionId/preflight`

```json
{
  "checked_at": "2026-07-24T10:00:01.000Z",
  "clock": {
    "ntp_state": "synced|degraded|unsynced|unknown",
    "offset_ms": 12.4,
    "server_clock_delta_ms": 18.2,
    "source": "chronyc_tracking"
  },
  "devices": [
    {
      "local_device_id": "tinysa-zs407-400",
      "measurement_type": "rf",
      "model": "tinySA Ultra ZS407",
      "serial_number": null,
      "firmware_version": "v1.4-...",
      "device_path": "/dev/tinysa4",
      "status": "ready",
      "settings": {
        "antenna_profile": "zs407_stock_antenna",
        "calibration_state": "level_calibrated"
      }
    }
  ]
}
```

장비가 제공하지 않는 시리얼 번호는 `null`로 보낸다.

## 4. 모듈 실행 상태

`POST /api/collectors/:collectorId/measurement-sessions/:sessionId/module-runs`

```json
{
  "module_run_id": "uuid",
  "measurement_type": "wireless",
  "status": "running|paused|completed|failed|unsupported|skipped",
  "started_at": "2026-07-24T10:00:02.000Z",
  "ended_at": null,
  "sample_count": 0,
  "source_delay_ms": null,
  "error_code": null,
  "error_message": null,
  "settings": {
    "interface": "wlx001122334455",
    "interval_ms": 5000
  }
}
```

`module_run_id`로 upsert한다.

## 5. 측정 표본 배치

`POST /api/collectors/:collectorId/measurement-sessions/:sessionId/samples`

제한:

- 배치당 최대 1,000개 표본
- 압축 전 최대 5 MiB
- RF 대형 원본은 파일 API 사용

```json
{
  "batch_id": "uuid",
  "schema_version": "metro-measurement-samples-v1",
  "generated_at": "2026-07-24T10:00:10.000Z",
  "samples": [
    {
      "sample_id": "uuid",
      "module_run_id": "uuid",
      "measurement_type": "wireless",
      "sampled_at": "2026-07-24T10:00:09.500Z",
      "timezone": "Asia/Seoul",
      "source_delay_ms": 6.2,
      "status": "success",
      "values": {
        "interface_name": "wlx001122334455",
        "ssid": "example",
        "bssid": "00:11:22:33:44:55",
        "frequency_mhz": 5180,
        "channel": 36,
        "channel_width_mhz": 80,
        "signal_dbm": -54.0,
        "snr_db": null,
        "noise_floor_dbm": null,
        "rx_link_mbps": 866.7,
        "tx_link_mbps": 780.0,
        "retry_rate_pct": null
      },
      "source": "iw_link",
      "error_code": null,
      "error_message": null
    }
  ]
}
```

응답:

```json
{
  "batch_id": "uuid",
  "stored": 1,
  "duplicate": false,
  "received_at": "2026-07-24T10:00:10.080Z",
  "ingest_delay_ms": 80.0
}
```

현재 호환 구현은 기존
`POST /api/collectors/:collectorId/wifi-analysis/batches`를 재사용한다.
연결성, Wi-Fi, RF 각 표본에는 `module_run_id`, `timezone`,
`source_delay_ms`, `sample_status`, `error_code`, `error_message`를 포함하며
33번 적재 시 `ingest_delay_ms`를 계산한다. 구버전 수집기 데이터는 계속
수용하지만 새 필드가 없는 과거값은 `null`로 유지한다.

## 6. 원본 파일

### 메타데이터 등록

`POST /api/collectors/:collectorId/measurement-sessions/:sessionId/files`

```json
{
  "file_id": "uuid",
  "module_run_id": "uuid",
  "file_kind": "rf_raw|rf_image|pcap|photo|log|other",
  "file_name": "rf-20260724T100000Z.json.gz",
  "mime_type": "application/gzip",
  "size_bytes": 1048576,
  "sha256": "64-char-lowercase-hex",
  "sample_started_at": "2026-07-24T10:00:00.000Z",
  "sample_ended_at": "2026-07-24T10:00:30.000Z",
  "local_relative_path": "sessions/uuid/rf/rf-....json.gz"
}
```

응답:

```json
{
  "file_id": "uuid",
  "status": "registered",
  "upload_url": "/api/collectors/17/measurement-sessions/uuid/files/uuid/content",
  "expires_at": "2026-07-25T10:00:00.000Z"
}
```

### 내용 업로드

`PUT /api/collectors/:collectorId/measurement-sessions/:sessionId/files/:fileId/content`

- `Content-Type`: 등록 MIME
- `Content-Length` 필수
- 서버는 수신 후 크기와 SHA-256을 검증한다.
- 부분 업로드는 1차 구현에서 지원하지 않고 재시작 가능한 파일 단위 큐로 처리한다.

## 7. 세션 완료

`POST /api/collectors/:collectorId/measurement-sessions/:sessionId/complete`

```json
{
  "ended_at": "2026-07-24T10:15:02.000Z",
  "status": "completed|partial|failed",
  "module_summary": {
    "wired": "completed",
    "wireless": "completed",
    "rf": "failed",
    "packet_capture": "skipped",
    "system": "completed"
  },
  "queue_summary": {
    "pending_batches": 0,
    "pending_files": 1
  }
}
```

서버는 저장된 모듈 상태와 대조한다. 클라이언트가 `completed`를 보내도 실패 모듈이 있으면 `partial`로 정규화한다.

응답:

```json
{
  "measurement_session_id": "uuid",
  "status": "partial",
  "analysis_job_id": "uuid",
  "report_ready": false
}
```

## 8. 세션과 시간축 조회

`GET /api/measurement-sessions/:sessionId`

응답에는 다음을 포함한다.

- 고객/현장/수집기
- 세션 상태와 시간 동기화
- 장비와 설정
- 모듈별 상태/표본 수/오류
- 파일 무결성 상태
- 분석/보고서 작업 상태

`GET /api/measurement-sessions/:sessionId/timeline?from=...&to=...&resolution_ms=1000&window_ms=1000`

```json
{
  "measurement_session_id": "uuid",
  "timezone": "Asia/Seoul",
  "resolution_ms": 1000,
  "correlation_window_ms": 1000,
  "series": [
    {
      "metric": "wireless.signal_dbm",
      "unit": "dBm",
      "source": "iw_link",
      "points": [
        ["2026-07-24T10:00:09.500Z", -54.0]
      ]
    }
  ],
  "anomaly_windows": []
}
```

현재 시간축 API는 연결성, Wi-Fi, RF 원천 표본과 `correlation_frames`,
모듈별 `coverage`, `clock_warning`을 반환한다. 자료가 없으면 `unknown`,
해당 시간 윈도우에 짝이 없으면 `null`이며 임의의 0을 생성하지 않는다.
기본 시간 윈도우는 세션의 `correlation_window_ms`, 기본값은 1,000ms다.

## 9. 분석

`POST /api/measurement-sessions/:sessionId/analyze`

```json
{
  "from": "2026-07-24T10:00:00.000Z",
  "to": "2026-07-24T10:15:00.000Z",
  "window_ms": 1000,
  "limit": 5000,
  "thresholds": {
    "high_packet_loss_pct": 5,
    "high_latency_ms": 100,
    "high_rf_occupancy_pct": 70
  }
}
```

현재 10단계 구현은 `rule_based` 분석만 실행한다. 같은 세션, 엔진 버전,
임계값, 원천 표본이면 입력 해시로 기존 분석 결과를 반환한다. 임계값은
허용 목록과 범위를 검증하며 임의 필드는 거부한다.

`GET /api/measurement-sessions/:sessionId/analysis`

특정 실행 결과 조회:

`GET /api/measurement-sessions/:sessionId/analysis?run_id=:correlationRunId`

```json
{
  "correlation_run_id": "uuid",
  "measurement_session_id": "uuid",
  "engine_version": "metro-correlation-rules-v1",
  "analysis_method": "rule_based",
  "analysis_status": "completed|insufficient_data",
  "correlation_window_ms": 1000,
  "coverage": {
    "wired": "collected",
    "wireless": "collected",
    "rf": "collected"
  },
  "clock_warning": null,
  "summary": {
    "overall_grade": "warning",
    "overall_grade_label": "경고",
    "finding_count": 1,
    "correlation_frame_count": 120
  },
  "findings": [
    {
      "analysis_method": "rule_based",
      "rule_key": "snr_rf_noise_alignment",
      "grade": "warning",
      "grade_label": "경고",
      "anomaly_started_at": "2026-07-24T10:04:12.000Z",
      "anomaly_ended_at": "2026-07-24T10:04:30.000Z",
      "classification": "rf_interference",
      "confidence": 0.78,
      "interference_pattern": "persistent",
      "related_measurements": [],
      "judgment_basis": [],
      "possible_causes": [],
      "contradictory_evidence": [],
      "missing_data": [],
      "additional_checks": [],
      "recommended_actions": [],
      "remeasurement_conditions": [],
      "evidence_frame_count": 8
    }
  ]
}
```

판정 정책:

- 등급은 `normal`, `caution`, `warning`, `critical`, `unknown`이다.
- 유선·무선·RF 중 하나라도 미수집이거나 시간 동기화 경고가 있으면
  분석 상태를 `insufficient_data`로 기록한다.
- NTP 경고가 있으면 원인 신뢰도를 최대 `0.35`로 제한한다.
- 원천이 부족할 때 정상으로 판정하지 않고 `unknown/판단 보류`로 기록한다.
- `continuous_wave_detected`와 `pulse_detected`는 비 Wi-Fi 간섭을 확정하지
  않으며 다른 근거가 없으면 `non_wifi_rf_interference_candidate`로만 표시한다.
- AI 분석은 11단계에서 별도 저장소와 응답 영역으로 구현한다.

## 10. 119 보고서

`POST /api/nms/measurement-reports`

```json
{
  "measurement_session_id": "uuid",
  "customer_id": 1,
  "site_id": 10,
  "title": "현장 네트워크·RF 동시 측정 보고서",
  "operator_name": "현장 작업자",
  "notes": "",
  "formats": ["html", "pdf", "json", "csv"]
}
```

응답:

```json
{
  "job_id": "uuid",
  "status": "queued"
}
```

`GET /api/nms/measurement-reports/jobs/:jobId`

```json
{
  "job_id": "uuid",
  "status": "queued|running|completed|failed",
  "progress_pct": 70,
  "report_id": null,
  "error_code": null,
  "error_message": null
}
```

`GET /api/nms/measurement-reports/:reportId`

응답에는 생성 파일별 이름, MIME, 크기, SHA-256, 다운로드 URL, 보고서 스냅샷 생성시각을 포함한다.

## 11. 호환성

- 기존 `/measurement-sessions/offline`과 `/wifi-analysis/batches`는 유지한다.
- 신규 Agent는 공통 세션 API를 사용한다.
- 전환 기간에는 기존 배치에도 선택적 `measurement_session_id`를 허용한다.
- `measurement_session_id`가 없는 기존 자료는 독립 측정으로 표시하며 신규 세션에 임의 편입하지 않는다.
- 119의 기존 `/api/nms/collection-reports`는 유지한다.
