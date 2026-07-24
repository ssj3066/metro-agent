# Metro Agent Platform V1

## 결정

V1은 기존 운영 구조를 교체하지 않는다.

- 33 NMS는 중앙 API, PostgreSQL, 이벤트와 운영 데이터의 기준이다.
- 130 Ubuntu 수집기는 기존 heartbeat, 원격진단, Wi-Fi/RF, SNMP와 현장 GUI를 계속 담당한다.
- Metro Agent V1은 130 수집기 안에 추가되는 독립 실행 계층이다.
- 기존 `collectors` ID, 토큰, 고객사, 현장, 장비 연결을 재사용한다.
- 119 ICT Manager와 60 ERP의 기준정보를 Metro Agent가 복제하지 않는다.

## V1 구성

```text
33 network-server
  collector_check_profiles
  collector_check_batches
  collector_check_results
  GET  /api/collectors/:id/metro-agent/config
  POST /api/collectors/:id/metro-agent/check-batches
  GET  /api/metro-agent/check-profiles/:id
  PUT  /api/metro-agent/check-profiles/:id
  GET  /api/metro-agent/check-results

130 metro-agent
  metro-agent-v1/index.js
  metro-agent-v1/plugins/{ping,tcp,http,system}.js
  metro-agent-v1/lib/{queue,transport}.js
  nms-metro-agent-v1.service
  nms-metro-agent-v1.timer
```

## 데이터 계약

모든 결과는 `value`, `unit`, `source`, `observed_at`, `status`,
원천별 `details`, 실행한 `config_revision`을 포함한다. 원천값이 없으면
`null`과 `unavailable`을 사용하고 숫자 `0`으로 대체하지 않는다.
서버 수신시각은 `received_at`으로 별도 저장한다.

각 배치는 UUID `batch_id`를 사용한다. 중앙 DB는
`collector_id + batch_id`를 고유 키로 사용하여 응답 유실 후 재전송도
중복 저장하지 않는다.

## 점검 프로필 예시

관리자 또는 운영자 세션으로 다음 API에 설정한다.

```http
PUT /api/metro-agent/check-profiles/17
Content-Type: application/json
```

```json
{
  "enabled": true,
  "interval_seconds": 60,
  "checks": [
    {
      "key": "gateway",
      "type": "ping",
      "target": "gateway",
      "timeout_ms": 3000,
      "options": { "count": 4 }
    },
    {
      "key": "central_nms",
      "type": "tcp",
      "target": "192.168.1.33:7443",
      "timeout_ms": 5000
    },
    {
      "key": "internet_https",
      "type": "http",
      "target": "https://www.naver.com/",
      "timeout_ms": 10000
    },
    {
      "key": "host",
      "type": "system",
      "timeout_ms": 5000
    }
  ]
}
```

프로필을 수정할 때마다 revision이 증가한다. Agent는 각 결과 배치에
실행한 revision을 기록한다.

## 오프라인 처리

마지막 정상 프로필은
`/var/lib/nms-collector/metro-agent-v1/config.json`에 저장한다.
인터넷이 끊기면 캐시 프로필로 계속 점검하고 배치를 `queue/`에
`0600` 권한으로 저장한다. 연결 복구 시 생성시각 순서대로 전송하며,
프로필이 비활성화됐거나 다음 점검 주기 전이라도 대기 배치는 전송한다.

토큰과 비밀번호는 큐 또는 프로필 캐시에 저장하지 않는다.

## 운영 적용 순서

1. 33번 운영 파일과 DB를 백업한다.
2. `061_add_metro_agent_v1.sql`을 적용한다.
3. 신규 store와 route 파일 및 연결된 서버 파일을 배포한다.
4. 33 API를 재시작하고 health 및 인증 경로를 확인한다.
5. 130번 `/opt/nms-collector`, 환경파일과 systemd unit을 백업한다.
6. Metro Agent V1 파일과 unit을 설치한다.
7. `collector.env`에 `METRO_AGENT_V1_ENABLED=true`를 추가한다.
8. 33번에서 130 수집기 ID에 점검 프로필을 등록한다.
9. timer를 시작하고 결과 DB 적재와 중복 방지를 확인한다.

## 단계별 확장 로드맵

### V1.1 운영 화면

- 수집기별 프로필 편집 UI
- 최신 점검값과 신선도 표시
- 실패, 미수집, 과거값 필터
- 현장 이동 시 이전 현장 결과를 현재값으로 표시하지 않는 scope 처리

### V1.2 이벤트와 장애

- 연속 실패 횟수와 회복 조건
- 중복 경보 억제와 유지보수 시간대
- 점검 결과를 기존 `alert_events`, `issues`와 연결
- 장애 원인 라벨과 사용자 확정 피드백 저장

### V1.3 수집 플러그인

- DNS, traceroute, 서비스 상태, SMART
- SNMP v2c/v3 polling 프로필
- Windows Event Log와 Linux journal
- 플러그인 capability와 버전 호환성 검사

### V1.4 RF와 상관관계

- tinySA 드라이버를 공통 RF 플러그인 계약으로 래핑
- AP 상태와 RF 스윕 시간창 상관분석
- 채널 점유, 간섭 후보, 교정 상태 기반 신뢰도

### V1.5 보안과 배포

- 토큰 순환과 장치 인증서 선택 지원
- 서명된 Agent 업데이트와 rollback
- Docker 개발환경과 CI
- 멀티테넌트 데이터 격리 및 보존 정책

### V2 제품화

- Go 기반 장기 실행 Agent core 검토
- NATS JetStream 기반 대규모 비동기 수집
- React/TypeScript 운영 콘솔
- MinIO 보고서/RF 원본 저장
- 118 LLM evidence pack과 119 점검보고서 자동 연결

Go 전환은 V1 프로토콜과 현장 동작이 안정화된 뒤 진행한다. V1에서
기존 Node.js/Python 수집기를 재작성하지 않는다.
