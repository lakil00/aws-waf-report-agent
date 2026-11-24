# AWS WAF Report Agent

**Strands Agents SDK** + **Amazon Bedrock AgentCore** 기반 멀티에이전트 WAF 보안 운영 시스템.
4개의 전문 에이전트가 협력하여 WAF 로그 분석, 오탐 탐지, 미탐 위협 발견, 권고 검증, 리포트를 매일 자동 생성합니다.

## 아키텍처

```
┌──────────────────────────────────────────────────────────────────┐
│ 컨트롤 플레인 — fire-and-forget + 독립 헬스체크                    │
└──────────────────────────────────────────────────────────────────┘

  EventBridge Scheduler A                       EventBridge Scheduler B
  cron(0 8 * * ? *)   SGT                       cron(15 8 * * ? *)  SGT
  retry_policy.max_retry_attempts = 0           retry_policy.max_retry_attempts = 0
        │                                             │
        │ aws-sdk:lambda:invoke                       │ sync invoke, retries=0
        │ InvocationType=Event  (async)               │
        ▼                                             ▼
  ┌───────────────────────┐                     ┌────────────────────────┐
  │ Lambda "trigger" 60 s │                     │ Lambda "healthcheck"   │
  │ • run_id 생성          │                     │ 60 s, retries=0        │
  │ • S3 PUT 마커          │                     │                        │
  │   {status:"started"}  │                     │ • S3 LIST markers/     │
  │ • lambda.invoke(      │                     │   {today}/             │
  │     "runner",         │                     │ • 각 마커 처리:         │
  │     InvocationType=   │                     │   – status="completed" │
  │     "Event")          │                     │     → silent pass      │
  │ • 즉시 return          │                     │   – status="started"   │
  └──────────┬────────────┘                     │     ∧ age > 12 min     │
             │ async invoke                     │     → SNS 경고 메일     │
             │ event_invoke_config              │       "pipeline hang"  │
             │ .max_retry_attempts = 0          │ • 7일 넘은 마커 삭제    │
             ▼                                  └────────────────────────┘
  ┌────────────────────────────────┐                       ▲
  │ Lambda "runner" 900 s          │                       │
  │ • boto3 Config(               │                       │
  │     retries={max_attempts:1},│                       │
  │     read_timeout=850)         │                       │
  │ • invoke_agent_runtime(sync)  │                       │
  │ • 성공 시:                     │                       │
  │     S3 PUT 마커                │                       │
  │     {status:"completed"}      │                       │
  │ • Lambda timeout 발생 시:      │                       │
  │   마커가 "started" 상태 유지    │                       │
  │   → 헬스체크가 15 분 뒤 감지    │                       │
  └──────────────┬─────────────────┘                       │
                 │ invoke_agent_runtime                     │
                 ▼                                          │
  ┌─────────────────────────────────────────────────────────────────┐
  │ Supervisor Runtime (Claude Sonnet 4.6)                          │
  │ 파이프라인 오케스트레이션, sub-agent 호출, SNS 리포트 발행         │
  │                                                                 │
  │ ★ IDEMPOTENCY GUARD                                             │
  │   SNS publish 직전, S3 PutObject IfNoneMatch:"*" 로 원자적       │
  │   슬롯 클레임: markers/report-sent-{YYYY-MM-DD}.json             │
  │   ├─ PreconditionFailed → 좀비 세션 — publish 스킵               │
  │   └─ 성공 → SNS publish + run_id 마커 "completed" 갱신           │
  └───┬────────┬────────────┬───────────────────────────────────────┘
      │        │            │  invoke_agent_runtime
      ▼        ▼            ▼
  ┌────────┐ ┌──────────┐ ┌──────────┐
  │Analyzer│ │Validator │ │Executor  │
  │Opus 4.6│ │Opus 4.6  │ │Opus 4.6  │
  └───┬────┘ └────┬─────┘ └────┬─────┘
      │           │             │
      └───────────┴─────────────┘
                    │ MCP (Gateway)
                    ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │ AgentCore Gateway (MCP 프로토콜)                                  │
  │ 단일 Lambda target — _tool 필드로 라우팅                          │
  └──────────────────────────────┬──────────────────────────────────┘
                                 ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │ Lambda: waf-report-tools (20개 도구)                             │
  │                                                                 │
  │ 분석:                          관리:                             │
  │ • query_waf_summary          • get_web_acl                     │
  │ • query_top_blocked          • update_web_acl_rules            │
  │ • query_suspicious_patterns  • list_pending_findings (S3)      │
  │ • query_rate_limit_hits      • archive_processed_findings      │
  │ • query_false_positive_signals • current_datetime              │
  │ • scan_bypass_candidates     • check_coverage_gaps             │
  │ • investigate_ip_deep (JA4/UA)                                 │
  │ • query_label_distribution   보강:                              │
  │ • query_bot_intelligence     • enrich_ip_reputation            │
  │ • check_volume_anomaly         (AbuseIPDB + ET blocklist)      │
  │ • query_per_domain           커스텀:                            │
  │ • query_non_terminating_rules • run_custom_waf_query           │
  └─────────────────────────────────────────────────────────────────┘
           │              │              │              │
           ▼              ▼              ▼              ▼
     CloudWatch Logs    WAF v2         SNS        S3 (findings + markers)
```

### 신뢰성 모델 — 모든 재시도 노브를 0으로 두는 이유

파이프라인은 **일 1회** 실행이며 **날짜 기준 idempotent**입니다. 놓친 실행은 다음 날 실행으로 복구되지만, 중복 실행은 리포트를 두 번 발송합니다. 따라서 모든 계층의 재시도를 끄고, exactly-once 발송은 단일 S3 idempotency 클레임으로 보장합니다.

| 계층 | 재시도 설정 | 이유 |
|-----|-------------|-----|
| EventBridge Scheduler A (→ trigger) | `maximum_retry_attempts = 0` | Async fire-and-forget. Lambda invoke 실패해도 다음 날 스케줄이 다시 실행. |
| EventBridge Scheduler B (→ healthcheck) | `maximum_retry_attempts = 0` | 경고 실패는 허용 가능 — 스케줄이 내일 또 발동. |
| Lambda trigger — event invoke config | `maximum_retry_attempts = 0` | Trigger는 60초짜리 기록 작업; 실패하면 파이프라인 안 돌고 healthcheck가 알림. |
| Lambda runner — event invoke config | `maximum_retry_attempts = 0` | Lambda async 기본 재시도는 2회이며, 재시도되면 파이프라인이 한 번 더 시작됨. |
| Lambda runner — boto3 client | `retries={"max_attempts": 1}` | read timeout 후 클라이언트가 재시도하면 두 번째 AgentCore 세션이 시작됨. `max_attempts=1`로 SDK 재시도를 끄고, `read_timeout=850`으로 호출을 Lambda 제한(900초) 안에 둠. |
| Lambda healthcheck — boto3 client | `retries={"max_attempts": 3, "mode": "standard"}` | Healthcheck는 idempotent (read-only S3 + SNS publish 1회); 재시도 안전. |
| Supervisor SNS publish | 원자적 S3 `IfNoneMatch:"*"` 클레임 | AgentCore 세션은 runner Lambda가 종료된 뒤에도 서버 사이드에서 계속 실행되어 발행 단계에 도달할 수 있음. S3 클레임으로 첫 번째 세션만 발행. |

## 에이전트 역할

| 에이전트 | 모델 | 역할 |
|----------|------|------|
| **Supervisor** | Claude Sonnet 4.6 | 파이프라인 오케스트레이션 — sub-agent 순차 호출, SNS로 리포트 직접 발행 (programmatic, exactly once, tools Lambda 경유 없음) |
| **Analyzer** | Claude Opus 4.6 | 하이브리드 분석: programmatic 데이터 수집 (FP 판정, JA4, IP 평판, 도메인별, COUNT 규칙) + LLM은 recommendation만 생성. AgentCore Memory로 일자별 트렌드 (재발 IP, 트래픽 변화, 신규 패턴) 감지 |
| **Validator** | Claude Opus 4.6 | Analyzer recommendation을 애플리케이션 컨텍스트 대비 독립 검증 (spot-check, downstream label deps) → APPROVE / REJECT / MODIFY |
| **Executor** | Claude Opus 4.6 | WAF 룰 변경 제안 (dry_run 모드 — 룰 변경 0건이면 스킵). `allow_waf_write = true`가 아니면 실제 적용은 차단됨 ([안전장치](#안전장치) 참고) |

## 파이프라인 흐름

```
컨트롤 플레인 (fire-and-forget):
────────────────────────────────
T=0:00   EventBridge A가 trigger Lambda 발동 (async, InvocationType=Event)
T=0:00   trigger Lambda:
           - run_id = uuid4()
           - S3 PUT markers/{YYYY-MM-DD}/{run_id}.json  {status:"started", started_at:now}
           - lambda.invoke("waf-report-runner", InvocationType=Event, payload={run_id, ...})
           - return  (Lambda 2초 안에 종료)
T=0:00   runner Lambda 시작 (async) — invoke_agent_runtime(supervisor, sync) 시작

데이터 플레인 (Supervisor 파이프라인, 약 5–10 분):
────────────────────────────────────────────
1. Supervisor가 트리거 수신 (timestamp, run_id 포함)
2. Supervisor → invoke_analyzer
   └─ Analyzer Phase 1 (programmatic): query_waf_summary, query_top_blocked,
      query_false_positive_signals (×9 IP → 판정 사전 분류),
      check_volume_anomaly, scan_bypass_candidates,
      investigate_ip_deep (임계치 초과 후보 자동 실행, JA4/UA/URIs/COUNT 규칙 포함),
      query_bot_intelligence, query_label_distribution,
      query_per_domain, query_non_terminating_rules, enrich_ip_reputation (×5 IP)
   └─ Analyzer Phase 2 (LLM): bypass 위협 평가, COUNT 규칙 승격 후보, recommendation 생성
      (도구 접근 가능하지만 재조회 금지 — 부가가치 분석에만 집중)
   └─ Analyzer Phase 3 (병합): raw data + programmatic 판정이 LLM 출력을 오버라이드
3. Supervisor → list_pending_findings (S3 외부 findings, 예: 펜테스트 결과)
4. Supervisor가 WAF + 외부 findings 병합
5. Supervisor → invoke_validator
   └─ Validator: evidence spot-check, 애플리케이션 안전성 평가, downstream label deps 확인
6. 룰 변경 필요 시: Supervisor → invoke_executor (dry_run 룰 제안 JSON 생성)
   └─ Validator가 0건 승인 시 완전 스킵
7. Supervisor → archive_processed_findings (S3 processed/로 이동)
8. Supervisor → IDEMPOTENCY CLAIM
   S3 PutObject markers/report-sent-{YYYY-MM-DD}.json 를 IfNoneMatch:"*"로
   ├─ PreconditionFailed (SlotAlreadyClaimed) → 로그 남기고 종료 (좀비 세션)
   └─ 성공 → 9단계로 진행
9. Supervisor → 직접 SNS publish (programmatic, exactly once)
10. Supervisor → S3 PUT markers/{YYYY-MM-DD}/{run_id}.json  {status:"completed", message_id, completed_at}
11. runner Lambda 반환; Lambda가 900초에서 죽었으면 마커가 "started"로 남아 healthcheck가 감지

헬스체크 플레인 (독립):
────────────────────
T=0:15   EventBridge B가 healthcheck Lambda 발동 (sync, retries=0)
         healthcheck Lambda:
           - list_objects_v2(prefix="markers/{today}/")
           - 각 마커에 대해:
               * status="completed" → OK
               * status="started" ∧ (now - started_at) > 12 분 → PIPELINE TIMEOUT
                 → SNS publish 경고 (subject: "WAF Pipeline Timeout — {date} — {run_id}")
           - 7일 넘은 마커 삭제
```

## 프로젝트 구조

```
aws-waf-report-agent/
├── agents/                      # AgentCore Runtime 컨테이너 (4개 에이전트)
│   ├── Dockerfile               # 공유 Dockerfile (ARG AGENT_NAME으로 handler 선택)
│   ├── requirements.txt         # strands-agents, bedrock-agentcore, mcp, boto3
│   ├── supervisor/handler.py    # 오케스트레이터 + S3 idempotency 클레임 + SNS publish
│   ├── analyzer/handler.py      # WAF 로그 분석 + recommendation
│   ├── validator/handler.py     # Recommendation 검증
│   └── executor/handler.py      # WAF 룰 적용
├── lambda/
│   ├── trigger_handler.py       # EventBridge A → run_id 생성, runner async 호출
│   ├── runner_handler.py        # trigger가 async로 호출, invoke_agent_runtime sync 실행
│   ├── healthcheck_handler.py   # EventBridge B (T+15분) → 파이프라인 hang 감지 → 경고 메일
│   └── tools_handler.py         # 모든 도구 (Gateway MCP target, 20개 도구)
├── tests/
│   ├── test_tools.py            # 단위 테스트 (84개, 전체 mock — AWS 호출 없음)
│   └── test_e2e_agents.py       # E2E 통합 테스트 (Analyzer, Validator, Control Plane Lambda, Memory)
├── infra/
│   ├── main.tf                  # Terraform (ECR, Runtime, Gateway, Memory, IAM, Scheduler 2개, Lambda 4개: tools + 컨트롤 플레인 3개)
│   ├── variables.tf             # 입력 변수 (healthcheck_schedule_expression + healthcheck_hang_threshold_minutes 추가)
│   ├── terraform.tfvars.example # 설정 예시
│   ├── tool_schemas.json        # Gateway용 MCP 도구 정의 (20개)
│   └── policies/                # Cedar 정책 (에이전트별 최소권한)
├── docs/
│   ├── pipeline-flow.mmd        # Mermaid 파이프라인 다이어그램 소스 (control/data/health 플레인)
│   ├── pipeline-flow.svg        # pipeline-flow.mmd에서 렌더된 SVG
│   ├── ANALYSIS_AGENT_REQUIREMENTS.md    # 분석 에이전트 전체 명세 (EN)
│   └── ANALYSIS_AGENT_REQUIREMENTS_ko.md # 분석 에이전트 전체 명세 (KO)
├── scripts/
│   ├── test_run.sh              # 배포 + 실행 + 검증 (빠른 반복)
│   ├── check_doc_drift.sh       # CI 체크 — README 테스트 수와 pytest 일치, tfvars.example과 variables.tf 일치
│   └── hooks/
│       ├── pre-commit           # Git pre-commit 훅 — 관련 파일 변경 시 check_doc_drift.sh 실행
│       └── install.sh           # scripts/hooks/*를 .git/hooks/에 심볼릭 링크로 설치
├── pyproject.toml               # Python 프로젝트 메타데이터 (개발 의존성: pytest)
├── LICENSE                      # MIT
├── README.md                    # (영문)
└── README.ko.md                 # (한국어)
```

## 빠른 시작

### 사전 요구사항

- Python 3.10+, Docker, Terraform 1.5+
- Bedrock Claude 모델 활성화된 AWS 계정 (us-east-1)
- CloudWatch Logs 로깅이 켜진 WAF Web ACL

### 배포

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
# 편집: web_acl_arn, log_group, abuseipdb_api_key (선택)

terraform init
terraform apply
```

자동 수행 항목:
1. ECR 리포지토리 생성 (4개)
2. ARM64 컨테이너 이미지 빌드 + 푸시 (4개 에이전트)
3. AgentCore Runtime 생성 + 환경변수 설정
4. Gateway + Lambda target + tool schema 생성 (20개 도구)
5. AgentCore Memory 생성 (semantic + episodic, 30일 보존)
6. **EventBridge Scheduler 2개** 생성:
   - `waf-report-daily-scan` — 매일 8AM (`schedule_timezone`, 기본 SGT) → trigger Lambda (async)
   - `waf-report-daily-healthcheck` — 매일 8:15AM (동일 타임존) → healthcheck Lambda
7. **Lambda 3개** 생성: `waf-report-trigger`, `waf-report-runner`, `waf-report-healthcheck`
8. SNS 토픽 + S3 findings/markers 버킷 생성

### 테스트

```bash
# 단위 테스트 (mock — AWS 호출 없음)
source .venv/bin/activate
pytest tests/test_tools.py -v          # 84개 테스트

# E2E 통합 (실제 runtime 호출, 도구 + 메모리 확인)
# web_acl_arn / log_group / region은 infra/terraform.tfvars 또는
# WAF_WEB_ACL_ARN, WAF_LOG_GROUP, AWS_REGION 환경변수에서 읽음
AWS_PROFILE=<your-profile> python tests/test_e2e_agents.py

# 실패 시 자동 배포 + 재시도
AWS_PROFILE=<your-profile> python tests/test_e2e_agents.py --deploy --fix-loop

# 파이프라인 전체 실행 트리거 (fire-and-forget, 2초 안에 반환)
aws lambda invoke --function-name waf-report-trigger \
  --invocation-type Event \
  --profile <your-profile> --region <region> /dev/null

# 헬스체크 수동 실행 — 현재 마커 상태 확인
aws lambda invoke --function-name waf-report-healthcheck \
  --profile <your-profile> --region <region> /tmp/hc.json && cat /tmp/hc.json
```

### 수동 실행

```bash
aws bedrock-agentcore invoke-agent-runtime \
  --agent-runtime-arn "$(terraform -chdir=infra output -raw supervisor_runtime_arn)" \
  --runtime-session-id "test-$(date +%s)-$(openssl rand -hex 12)" \
  --payload '{"lookback_hours":24,"dry_run":true,"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' \
  --content-type application/json \
  --accept application/json \
  --cli-read-timeout 600 \
  --region us-east-1 /dev/stdout
```

## 배포 주의사항

- **컨테이너 이미지 업데이트**: Runtime에 `DEPLOY_VERSION = filesha256("handler.py")` env var 포함 — 코드 변경 시 자동 업데이트.
- **Tool schema 업데이트**: Gateway Target이 `lifecycle { replace_triggered_by = [aws_s3_object.tool_schemas.etag] }` 사용 — 스키마 변경 시 자동 재생성.
- **Supervisor 환경변수**: sub-agent ARN 변경 시 자동 업데이트 (Terraform 처리).
- **invoke_agent_runtime**: raw JSON payload 사용 (base64 아님), 응답은 `resp["response"]` 스트림.
- **Analyzer 역할 분리**: FP 판정은 결정적 (Lambda), 심층 조사는 임계치 기반 (programmatic), LLM은 recommendation 합성에만 집중. 판정 오버라이드에는 `override_reasoning` 필수.
- **직접 SNS publish + S3 idempotency 클레임**: Supervisor가 `boto3.client("sns").publish()`로 직접 발행. Publish 직전에 `markers/report-sent-{date}.json`에 `IfNoneMatch:"*"`로 원자적 `PutObject` — 첫 승자만 publish, 좀비 세션들은 `PreconditionFailed` 받고 조용히 종료.
- **EventBridge fire-and-forget**: Scheduler A가 `aws-sdk:lambda:invoke` 유니버설 타겟 + `InvocationType=Event` 사용 → Lambda 실행 실패(timeout 포함)가 EventBridge 재시도를 유발하지 **않음**. Scheduler A의 `retry_policy.maximum_retry_attempts`도 `0`.
- **Runner 내부 boto3 재시도 금지**: `botocore.config.Config(retries={"max_attempts":1}, read_timeout=850)` — read timeout 후 재시도가 일어나면 단일 Lambda 실행 안에서 두 번째 AgentCore 세션이 시작됨.
- **이메일 포맷**: Supervisor LLM이 구조화된 plaintext 리포트 출력 (JSON 아님). `_clean_for_email()`이 잔여 마크다운 제거 후 SNS publish. 유니코드 구획 헤더 (═══, ▶)로 깔끔한 이메일.

## 설정

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `web_acl_arn` | 모니터링할 WAF Web ACL ARN | (필수) |
| `log_group` | WAF 로그용 CloudWatch log group | (필수) |
| `sns_topic_arn` | 리포트 SNS 토픽 (빈값 = 자동생성) | `""` |
| `schedule_expression` | EventBridge A cron (`schedule_timezone` 기준) | `cron(0 8 * * ? *)` |
| `healthcheck_schedule_expression` | EventBridge B cron (SGT) — Lambda runner timeout 이상 뒤에 발동해야 함 | `cron(15 8 * * ? *)` |
| `healthcheck_hang_threshold_minutes` | 마커 age가 이 값을 넘으면 hang으로 간주 | `12` |
| `schedule_enabled` | 두 스케줄 활성화 여부 | `true` |
| `abuseipdb_api_key` | IP 평판 조회용 AbuseIPDB API 키 (무료: 1000/일) | `""` |
| `region` | AWS 리전 | `us-east-1` |
| `schedule_timezone` | 두 스케줄러의 IANA 타임존. 리포트 하단 문구와 tools Lambda 기본 타임존에도 사용 | `Asia/Singapore` |
| `gateway_policy_mode` | AgentCore Gateway 정책 엔진 모드: `ENFORCE`(Cedar 결정이 강제됨) 또는 `LOG_ONLY` | `ENFORCE` |
| `allow_waf_write` | tools Lambda의 하드 스위치. `false`이면 `update_web_acl_rules`가 dry_run이 아닌 호출을 모두 거부 | `false` |
| `agent_models` | 에이전트별 Bedrock 모델 / inference profile ID (`supervisor`, `analyzer`, `validator`, `executor`) | supervisor Sonnet 4.6, 나머지 Opus 4.6 |
| `detection_thresholds` | 탐지 임계값 덮어쓰기. 예: `{ fp_attacker_block_ratio = 0.8 }` (키 목록은 아래) | `{}` |
| `agent_env_overrides` | 모든 AgentCore runtime에 병합되는 추가 환경변수 (`FP_SIGNAL_MAX_IPS`, `REPUTATION_MAX_IPS`, `DEEP_INVESTIGATION_PCT`, `CONFIDENCE_THRESHOLD` 등) | `{}` |

### 탐지 임계값 조정

판정·이상 탐지 임계값은 `lambda/tools_handler.py`의 `DEFAULT_THRESHOLDS`에 있고, 코드 수정 없이 `detection_thresholds`(tools Lambda의 `WAF_THRESHOLDS`로 전달)로 덮어쓸 수 있습니다. 알 수 없는 키와 숫자가 아닌 값은 무시됩니다.

| 그룹 | 키 |
|------|----|
| FP 판정 | `fp_attacker_block_ratio`, `fp_attacker_min_rules`, `fp_strong_block_ratio`, `fp_strong_min_rules`, `fp_volumetric_peak_rpm`, `fp_low_block_ratio`, `fp_low_max_rules`, `fp_benign_high_conf_ratio`, `fp_allow_block_multiple`, `fp_allow_max_peak_rpm` |
| 허용 트래픽 스캔 | `suspicious_min_requests`, `suspicious_min_uris`, `bypass_uri_diversity`, `bypass_hammer_min_total`, `bypass_hammer_max_uris`, `bypass_datacenter_min_total` |
| 규칙·도메인 | `promotion_min_matches`, `domain_drilldown_block_rate`, `domain_drilldown_count` |
| 트래픽 증감(주 대비) | `volume_moderate_wow`, `volume_significant_wow`, `volume_blocked_wow_max` |

Analyzer 수집 한도(`FP_SIGNAL_MAX_IPS` = 9, `REPUTATION_MAX_IPS` = 5, `DEEP_INVESTIGATION_PCT` = 0.01, `DEEP_INVESTIGATION_MIN` = 20, `DEEP_INVESTIGATION_MAX` = 100)는 runtime 환경변수이며 `agent_env_overrides`로 설정합니다.

## 안전장치

| 통제 | 위치 | 동작 |
|------|------|------|
| 쓰기 스위치 | tools Lambda (`WAF_WRITE_ENABLED`, `allow_waf_write`에서 설정) | 에이전트가 `dry_run`에 무엇을 넘기든 `true`가 아니면 `update_web_acl_rules`가 예외 발생. 기본 `false` |
| 룰 변경 정책 | tools Lambda | 기존 룰은 삭제·수정 불가. 호출당 신규 룰 최대 5개. 신규/변경 룰은 모두 COUNT 전용(`Action: Count`, 룰 그룹은 `OverrideAction: Count`). BLOCK 승격은 수동 작업. lock token은 호출자 값이 아니라 적용 시점에 조회 |
| Cedar 인가 | AgentCore Gateway, `ENFORCE` | 기본 거부. 각 에이전트 runtime 역할은 자기 도구만 호출 가능. 호출자는 assumed-role ARN 기반 `AgentCore::IamEntity`로 매칭(IAM 인증 게이트웨이에는 principal 태그가 없음). `dry_run == false`인 `update_web_acl_rules`는 forbid 규칙으로 차단 |
| 입력 검증 | tools Lambda | IP 인자는 IP 주소로 파싱돼야 하고, 로그에서 온 호스트명은 `[A-Za-z0-9.-]`만 허용한 뒤 Logs Insights 쿼리에 사용. 숫자 인자는 범위 제한 |
| 쿼리 무결성 | tools Lambda | 실패·취소·타임아웃된 Logs Insights 쿼리는 빈 결과 대신 오류를 발생시키고 쿼리를 중단. 타임아웃이 "트래픽 없음"으로 보이지 않음 |
| FP 판정 | tools Lambda | `LIKELY_FP`는 검사한 모든 payload가 정상(공격 키워드 없는 이름/단어)이고 차단율이 `fp_attacker_block_ratio` 미만일 때만 부여. HIGH 신뢰도는 차단율이 `fp_benign_high_conf_ratio` 미만일 때만 |
| 위협 인텔리전스 | tools Lambda | ET 블록리스트는 부분 문자열이 아닌 정확한 IP/CIDR 매칭, S3에 24시간 캐시, 갱신 실패 시 오래된 캐시 사용. 목록을 얻지 못하면 `et_listed`는 `null` |
| 아카이브 보호 | tools Lambda | `archive_processed_findings`는 `findings/pending/` 아래 키만 이동 (`FINDINGS_PENDING_PREFIX` / `FINDINGS_PROCESSED_PREFIX`로 변경 가능) |

## IAM 권한

| 역할 | 권한 |
|------|------|
| Supervisor Runtime | `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`, `bedrock-agentcore:InvokeAgentRuntime` (sub-agent), `bedrock-agentcore:InvokeGateway` (Gateway 경유 도구 호출), `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, `ecr:GetAuthorizationToken`, `s3:GetObject/PutObject/DeleteObject/ListBucket` (findings + markers), `sns:Publish` |
| Sub-agent Runtimes | `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`, `bedrock-agentcore:InvokeGateway`, memory ops (`CreateEvent`, `GetEvent`, `ListEvents`, `RetrieveMemoryRecords`, `ListMemoryRecords`, `StartMemoryExtractionJob`, `ListMemoryExtractionJobs`), `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, `ecr:GetAuthorizationToken` |
| Tools Lambda | `wafv2:GetWebACL/UpdateWebACL`, `logs:StartQuery/GetQueryResults/StopQuery/GetLogEvents/FilterLogEvents`, `logs:DescribeLogGroups`, `s3:GetObject/PutObject/DeleteObject/ListBucket/CopyObject`, `cloudwatch:GetMetricStatistics` |
| Gateway | `lambda:InvokeFunction` (tools Lambda), Cedar policy engine 작업 (`GetPolicyEngine`, `EvaluatePolicy`, `CheckAuthorizePermissions`, `AuthorizeAction`, `PartiallyAuthorizeActions`) |
| Trigger Lambda | `lambda:InvokeFunction` (runner), `s3:PutObject` (markers) |
| Runner Lambda | `bedrock-agentcore:InvokeAgentRuntime` (supervisor만), `s3:PutObject` (markers) |
| Healthcheck Lambda | `s3:ListBucket`, `s3:GetObject`, `s3:DeleteObject` (markers), `sns:Publish` |

> Supervisor는 tools Lambda를 **Gateway를 통해** (`bedrock-agentcore:InvokeGateway`) 호출하며, 직접 호출하지 않음. `lambda:InvokeFunction` 권한은 Gateway 역할에만 부여됨. SNS 발행은 Supervisor가 직접 수행하므로 tools Lambda에는 `sns:Publish` 권한이 필요 없음.

## 비용 추정

### 사용 서비스

| 서비스 | 스택 내 역할 | 과금 모델 |
|--------|-----------|-----------|
| **Amazon Bedrock** | LLM 추론 (Claude 모델) | 토큰당 (input/output) |
| **AgentCore Runtime** | 에이전트 컨테이너 실행 (4개, 각 30초~3분) | $0.0895/vCPU-hour + $0.00945/GB-hour |
| **AgentCore Gateway** | Lambda로의 MCP 도구 라우팅 | $0.005 / 1K invocations |
| **AgentCore Memory** | 세션간 트렌드 저장 | $0.25/1K events + $0.75/1K records/월 + $0.50/1K retrievals |
| **AgentCore Policy** | Cedar 인가 | $0.000025 / auth request |
| **AWS Lambda** | 도구 (20개) + trigger + runner + healthcheck | 요청당 + GB-second |
| **CloudWatch Logs Insights** | WAF 로그 쿼리 (~100 쿼리/실행) | $0.005 / GB scanned per query |
| **Amazon ECR** | 컨테이너 이미지 (4개) | $0.10 / GB-month |
| **Amazon S3** | Tool schema + findings + run markers + ET blocklist 캐시 | ~$0.023 / GB-month |
| **Amazon SNS** | 리포트 + 경고 메일 전송 | $2.00 / 100K emails |
| **EventBridge Scheduler** | 데일리 trigger (A) + healthcheck (B) | $1.00 / 1M invocations |

### Bedrock 모델 가격 (지배적 비용)

| 에이전트 | 모델 | Input (per MTok) | Output (per MTok) | 실행당 예상 |
|----------|------|-----------------|-------------------|--------------|
| Supervisor | Claude Sonnet 4.6 | $3 | $15 | ~$0.11 |
| Analyzer | Claude Opus 4.6 | $5 | $25 | ~$0.15 |
| Validator | Claude Opus 4.6 | $5 | $25 | ~$0.18 |
| Executor | Claude Opus 4.6 | $5 | $25 | ~$0.13 (호출될 때) |
| **Bedrock 총합** | | | | **~$0.44-0.57 / 실행** |

> 주: Analyzer의 programmatic 단계 (~24개 도구 호출)는 Bedrock 토큰을 전혀 쓰지 않음 — 합성 단계만 LLM 호출. Executor는 룰 변경 0건일 때 스킵.

**AgentCore Runtime 계산**: ~5.5 분/실행 × (1 vCPU × $0.0895/hr + 1 GB × $0.00945/hr) / 60 = ~$0.009/실행 × 30 = ~$0.27/월.

**CW Logs Insights 쿼리 분해** (~100 쿼리/실행):
- `query_false_positive_signals`: 8개 서브쿼리 × 9 IP = 72
- `investigate_ip_deep`: 8개 서브쿼리 × ~2개 후보 = 16
- `scan_bypass_candidates`: 3, `query_bot_intelligence`: 4, `query_label_distribution`: 2
- `query_per_domain`: 1-4, `query_non_terminating_rules`: 1
- `query_waf_summary`: 1, `query_top_blocked`: 1
- Validator spot-check: ~2-5 추가

### 월간 비용 (일 1회 실행 = 30회/월)

| 카테고리 | 월간 예상 | 비고 |
|----------|-------------|-------|
| Bedrock LLM 토큰 | **~$14-17** | 3-4 에이전트 × 30 실행 |
| AgentCore Runtime | ~$0.3 | ~5.5 분/실행 × 30 실행 |
| AgentCore Gateway | ~$0.01 | ~600 도구 호출/월 |
| AgentCore Memory | ~$0.03 | ~30 events + 30 records + 30 retrievals/월 |
| CloudWatch Logs Insights | **가변** | ~100 쿼리/실행 × log_volume_GB × $0.005 × 30일 |
| ECR 저장 | ~$0.16 | 4개 이미지 × ~400 MB |
| Lambda / SNS / S3 / EventBridge | ~$0 | 이 사용량은 프리티어 내 |

**CW Logs Insights는 트래픽 종속** — 이것이 가변 비용의 주된 동력:

| 일일 WAF 로그 볼륨 | 실행당 쿼리 | 월간 CW Logs 비용 | 총 월간 |
|---------------------|-------------|---------------------|---------------|
| ~1 MB (본 프로젝트, ~300 req/일) | 100 | **~$0.02** | ~$15 |
| 100 MB (~50K req/일) | 100 | **~$1.5** | ~$16 |
| 1 GB (~500K req/일) | 100 | **~$15** | ~$30 |
| 5 GB (~2.5M req/일) | 100 | **~$75** | ~$90 |

### 적용된 비용 최적화

| 기법 | 절감 효과 |
|-----------|--------|
| Supervisor가 SNS 직접 발행 (별도 reporter 에이전트 없음) | 리포트 발송용 런타임·LLM 토큰 불필요 |
| Supervisor에 Sonnet 4.6 (라우팅만) | Opus 대비 1.7배 저렴 |
| Programmatic 데이터 수집 (Analyzer Phase 1) | 실행당 ~10K 중복 input 토큰 제거 |
| 역할 분리 (LLM 단계 재조회 금지) | Analyzer 토큰 ~30% 절감 |
| 룰 변경 0건일 때 Executor 스킵 | 정상 실행 시 Opus 호출 1회 절감 |
| AgentCore 활성 소비 과금 | 실행 중에만 과금, 유휴 시간 무료 |

## 라이선스

[LICENSE](LICENSE) 참조.
