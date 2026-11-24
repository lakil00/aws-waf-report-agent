# WAF Report Agent — 전체 시스템 명세서

> **목표**: 이 문서만으로 다른 개발자 또는 AI 코딩 에이전트가 멀티 에이전트 WAF 보안 운영 시스템을 처음부터 구현할 수 있는 완전한 명세서.

---

## 1. 아키텍처 개요

### 1.1 시스템 구성

```
컨트롤 플레인 (fire-and-forget + 독립 헬스체크):

  EventBridge Scheduler A (cron 0 8 * * ? *  SGT, retries=0)
      → Lambda "trigger" (60s, retries=0)
          - run_id 생성
          - S3 PUT markers/{date}/{run_id}.json  {status:"started"}
          - lambda.invoke("runner", InvocationType=Event)  (async)
              → Lambda "runner" (900s, boto3 read_timeout=850, retries=0)
                  → invoke_agent_runtime(Supervisor, sync)

  EventBridge Scheduler B (cron 15 8 * * ? *  SGT, retries=0)
      → Lambda "healthcheck" (60s)
          - markers/{today}/ 조회, status="started" ∧ age > 12분이면 경보
          - 7일 넘은 마커 삭제

데이터 플레인 (Supervisor 내부):

  Supervisor Runtime (Claude Sonnet 4.6)
      → Analyzer Runtime (Claude Opus 4.6)
      → list_pending_findings (S3 외부 발견사항, Gateway 경유)
      → Validator Runtime (Claude Opus 4.6)
      → Executor Runtime (Claude Opus 4.6)  [변경 0건이면 스킵]
      → archive_processed_findings
      → ★ S3 IDEMPOTENCY CLAIM
         PutObject markers/report-sent-{date}.json with IfNoneMatch:"*"
         - 성공 → SNS publish (정확히 1회) + run 마커 "completed"
         - PreconditionFailed → 좀비 세션, 조용히 종료
```

### 1.2 에이전트 구성 (4개)

| 에이전트 | 모델 | 역할 | 도구 |
|---------|------|------|------|
| **Supervisor** | Claude Sonnet 4.6 | 파이프라인 오케스트레이션, 리포트 발송 | Gateway MCP (S3/datetime) + 서브에이전트 호출 |
| **Analyzer** | Claude Opus 4.6 | 하이브리드 분석: 프로그래밍 방식 데이터 수집 + LLM 추천 | 읽기/분석 도구 16개 (Cedar 허용; WAF 쓰기, S3 findings 도구 제외) |
| **Validator** | Claude Opus 4.6 | Analyzer 추천사항 독립 검증 | 도구 6개 (Cedar 허용): query_waf_summary, query_top_blocked, run_custom_waf_query, query_false_positive_signals, investigate_ip_deep, current_datetime |
| **Executor** | Claude Opus 4.6 | WAF 규칙 변경 제안 (dry_run 모드) | get_web_acl, update_web_acl_rules, current_datetime |

> **참고**: 별도의 reporter 에이전트는 없음. Supervisor가 파이프라인 완료 후 boto3 SNS로 직접 발송.
>
> **도구 접근은 권고가 아니라 강제됨.** Gateway 정책 엔진은 `ENFORCE` 모드(기본 거부)로 동작. 각 런타임 역할은 `infra/policies/<agent>.cedar.tftpl`에 있는 도구만 호출 가능 (Supervisor: current_datetime, list_pending_findings, archive_processed_findings).

### 1.3 인프라 스택

| 컴포넌트 | 서비스 | 용도 |
|---------|--------|------|
| 에이전트 컨테이너 | Amazon Bedrock AgentCore Runtime (ARM64 Docker) | 에이전트 코드 + SDK 실행 |
| 도구 라우팅 | AgentCore Gateway (MCP 프로토콜) | Lambda로 도구 호출 라우팅 |
| 도구 백엔드 | AWS Lambda (단일 함수, 20개 도구) | WAF 로그 쿼리, 규칙 관리, S3 findings 처리 |
| 로그 쿼리 | CloudWatch Logs Insights | WAF 로그 분석 |
| 메트릭스 | CloudWatch Metrics (AWS/WAFV2) | 볼륨 이상 탐지 |
| 리포트 | Amazon SNS → Email | 일일 리포트 전달 |
| 외부 발견사항 | Amazon S3 (findings 버킷) | 침투테스트 결과, 수동 입력 |
| 트렌드 메모리 | AgentCore Memory (시맨틱 + 에피소딕) | 세션 간 분석 패턴 |
| 인가 | AgentCore Policy (Cedar, `ENFORCE`) | 에이전트별 도구 접근(IAM 역할 매칭) + dry_run이 아닌 쓰기 차단 |
| 스케줄링 | EventBridge Scheduler | 일일 트리거 |
| IaC | Terraform | 전체 인프라 관리 |

---

## 2. 파이프라인 흐름 (상세)

### 2.1 전체 시퀀스

```
컨트롤 플레인 (fire-and-forget)
─────────────────────────────
T=0:00  EventBridge Scheduler A가 "waf-report-daily-scan" 발동
        → aws-sdk:lambda:invoke 유니버설 타겟
        → Lambda "waf-report-trigger" (async, InvocationType=Event)

T=0:00  trigger Lambda:
          run_id = uuid4()
          marker_key = "markers/{YYYY-MM-DD}/{run_id}.json"
          S3 PUT {status:"started", started_at, trigger_request_id}
          lambda.invoke("waf-report-runner", InvocationType=Event, payload={run_id, marker_key, ...})
          return  (Lambda 2초 안에 종료)

T=0:00  runner Lambda 시작 (async):
          boto3 Config(retries={max_attempts:1}, read_timeout=850)
          invoke_agent_runtime(SupervisorArn, sync)  ← 파이프라인 완료까지 블로킹

데이터 플레인 (Supervisor 파이프라인, ~3-10 분)
────────────────────────────────────────────
1. Supervisor가 payload {run_id, marker_key, lookback_hours, dry_run, timestamp} 수신
2. Supervisor LLM이 도구로 오케스트레이션:
   a. current_datetime → 정확한 리포트 타임스탬프
   b. invoke_analyzer(log_group, lookback_hours) → WAF 분석 JSON
   c. list_pending_findings → S3 외부 발견사항
   d. WAF + 외부 findings 병합
   e. invoke_validator(병합된 findings, web_acl_arn) → 검증 결과
   f. 검증자가 규칙 변경 필요 확인 시:
        invoke_executor(검증된 findings, web_acl_arn, dry_run=true)
      아니면: executor 완전 스킵
   g. archive_processed_findings → S3 파일을 processed/로 이동
   h. 출력: 구조화된 plaintext 리포트 (이메일용)
3. Supervisor 코드 (LLM 이후):
   a. _clean_for_email(pipeline_output) → 마크다운 잔존물 제거
   b. 리포트의 `Status:` 줄에서 심각도 감지 (CRITICAL / ACTION_REQUIRED→HIGH / HEALTHY, 기본 INFO)
   c. ★ IDEMPOTENCY CLAIM
      S3 PutObject markers/report-sent-{YYYY-MM-DD}.json 를 IfNoneMatch:"*"로
        - PreconditionFailed (SlotAlreadyClaimed) → run 마커를
          "skipped_duplicate"로 남기고 조용히 종료 (좀비 세션)
        - 성공 → 다음 단계 진행
   d. boto3 SNS publish (정확히 1회, 프로그래밍 방식)
   e. S3 PUT marker_key {status:"completed", message_id, severity}
4. runner Lambda 반환; Lambda가 900초에서 죽었으면 마커가 "started"로 남아
   healthcheck가 감지

헬스체크 플레인 (독립)
──────────────────
T=0:15  EventBridge Scheduler B가 "waf-report-daily-healthcheck" 발동
        → Lambda "waf-report-healthcheck" (sync, retries=0)

        healthcheck Lambda:
          list_objects_v2(prefix="markers/{today}/")
          각 마커에 대해:
            status="completed"          → OK
            status="started" ∧ age >12m → PIPELINE TIMEOUT
                                          → SNS publish 경보
                                          (subject: "WAF Pipeline Timeout — {date} — {run_id}")
          7일 넘은 마커 삭제
```

### 2.2 Analyzer 내부 단계

```
Phase 1: 프로그래밍 방식 데이터 수집 (_collect_raw_data)
├── query_waf_summary → 트래픽 개요
├── query_top_blocked (limit 20) → 상위 차단 IP
├── query_false_positive_signals (×9 IP) → 사전 분류된 판정
├── check_volume_anomaly → 주간 비교
├── scan_bypass_candidates → 의심스러운 허용 트래픽
├── investigate_ip_deep (임계값 초과 후보 자동)
│   └── 포함: JA4, User-Agent, URI, 비종료 규칙
├── query_bot_intelligence → 봇 카테고리, AI 봇, 플래그
├── query_label_distribution → WAF 라벨 집계
├── query_per_domain → Host 헤더 도메인별 분류
├── query_non_terminating_rules → COUNT 규칙 + 다운스트림 의존성
└── enrich_ip_reputation (×5 IP) → AbuseIPDB + ET 블록리스트

Phase 2: LLM 분석 (추천만)
├── Phase 1 데이터 전체를 입력으로 수신 (재쿼리 금지)
├── 바이패스 후보의 위협 수준 평가
├── COUNT→BLOCK 승격 후보 식별
├── 도메인별 공격 집중도 플래그
├── 구체적이고 실행 가능한 추천 생성
└── 구조화된 JSON 반환

Phase 3: 병합 (_merge_with_raw_data)
├── Raw 데이터 값이 LLM 생성 숫자를 무조건 오버라이드
├── Phase 1의 FP 판정이 권위적
├── LLM은 명시적 override_reasoning 필드가 있어야만 판정 오버라이드 가능
└── 최종 출력: raw 데이터 + LLM 추천 병합 JSON
```

### 2.3 데이터 전달 규칙

- Supervisor는 Analyzer 출력을 **원문 그대로** Validator에 전달 (요약 금지)
- Supervisor 최종 출력은 **plaintext 리포트** (JSON 아님) — 이메일 발송용
- Analyzer LLM은 raw 데이터를 수신하며 숫자 변경 금지
- Validator는 Analyzer 주장을 검증하기 위해 스팟체크 쿼리 실행 가능

### 2.4 신뢰성 모델 — 모든 재시도 노브를 0으로 두는 이유

파이프라인은 **일 1회** 실행이며 **날짜 기준 idempotent**입니다. 놓친 실행은 다음 날 실행으로 복구되지만, 중복 실행은 리포트를 두 번 발송합니다. 따라서 모든 계층의 재시도를 끄고, exactly-once 발송은 단일 S3 idempotency 클레임으로 보장합니다.

| 계층 | 재시도 설정 | 이유 |
|-----|-------------|-----|
| EventBridge Scheduler A (→ trigger) | `retry_policy.maximum_retry_attempts = 0` | Async fire-and-forget. Lambda invoke 실패해도 다음 날 스케줄이 다시 실행. |
| EventBridge Scheduler B (→ healthcheck) | `retry_policy.maximum_retry_attempts = 0` | 경보 실패는 허용 가능 — 스케줄이 내일 또 발동. |
| Lambda trigger — event invoke config | `maximum_retry_attempts = 0` | Trigger는 60초짜리 기록 작업; 실패해도 파이프라인이 안 돌 뿐. |
| Lambda runner — event invoke config | `maximum_retry_attempts = 0` | Lambda async 기본 재시도는 2회이며, 재시도되면 파이프라인이 한 번 더 시작됨. |
| Lambda runner — boto3 client | `retries={"max_attempts": 1}`, `read_timeout=850` | read timeout 후 클라이언트가 재시도하면 두 번째 AgentCore 세션이 시작됨. `max_attempts=1`로 SDK 재시도를 끄고, `read_timeout=850`으로 호출을 Lambda 제한(900초) 안에 둠. |
| Lambda healthcheck — boto3 client | `retries={"max_attempts": 3, "mode": "standard"}` | Healthcheck는 idempotent (read-only S3 + SNS 1회); 재시도 안전. |
| Supervisor SNS publish | `markers/report-sent-{date}.json`에 원자적 S3 `IfNoneMatch:"*"` 클레임 | AgentCore 세션은 runner Lambda가 종료된 뒤에도 서버 사이드에서 계속 실행되어 발행 단계에 도달할 수 있음. S3 클레임으로 첫 번째 세션만 발행. |

**Idempotency 클레임 구현** (Supervisor 코드, `sns.publish` 직전):
```python
claim_key = f"markers/report-sent-{date.today().isoformat()}.json"
try:
    s3.put_object(Bucket=findings_bucket, Key=claim_key,
                  Body=claim_body, IfNoneMatch="*")
except s3.exceptions.ClientError as e:
    if e.response["Error"]["Code"] in ("PreconditionFailed", "ConditionalRequestConflict"):
        # 이미 다른 세션이 오늘의 슬롯 확보 — 조용히 종료
        return {"status": "skipped_duplicate", "run_id": run_id}
    raise
# 첫 승자만 여기 도달 — 안전하게 발행
sns.publish(TopicArn=sns_topic, Subject=subject, Message=report_body)
```

healthcheck 경보는 runner Lambda가 죽었고 AgentCore 세션도 멈춘 드문 경우를 잡기 위한 것입니다. 이 시나리오에서 마커가 12분 넘게 "started"로 남으면 경보 메일이 발송되지만, **중복 WAF 리포트는 발송되지 않습니다.**

---

## 3. False Positive 판별

### 3.1 탐지 시그널

| 시그널 | 쿼리 방법 | True Positive 지표 | False Positive 지표 |
|--------|----------|-------------------|-------------------|
| **Block Ratio** | IP의 BLOCK/(BLOCK+ALLOW) | >75% 차단 | <5% 차단 |
| **요청 빈도** | bin(1m) 최대/평균 RPM | >250 req/min | <10 req/min |
| **멀티 규칙 트리거** | IP별 고유 terminatingRuleId 수 | ≥3개 규칙 | 단일 규칙 |
| **매치 디테일** | terminatingRuleMatchDetails 페이로드 | 공격 구문 패턴 | 정상 콘텐츠 |
| **URI 패턴** | 차단 요청 URI 분포 | 공격 경로: /.env, /wp-login | 비즈니스 경로: /api/ |
| **JA4 핑거프린트** | ja4Fingerprint 필드 | 알려진 스캐너 핑거프린트 | 브라우저 핑거프린트 |

### 3.2 결정론적 판정 로직 (Lambda 측)

Lambda `query_false_positive_signals` 도구가 **우선순위 순서**로 적용 (먼저 일치한 규칙이 적용됨). 숫자는 `lambda/tools_handler.py`의 `DEFAULT_THRESHOLDS` 기본값이며, 각각 Terraform `detection_thresholds`로 변경 가능.

| # | 조건 | 판정 | 신뢰도 |
|---|------|------|--------|
| 1 | matchedData 페이로드 중 하나라도 공격 패턴에 일치 (`_ATTACK_PATTERNS`: SQLi, XSS, 경로 탐색, 셸/명령 인젝션, `/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`, `/actuator` 같은 스캐너 경로) | TRUE_POSITIVE | HIGH |
| 2 | 검사한 matchedData 페이로드가 **모두** 정상으로 보이고 AND `block_ratio < fp_attacker_block_ratio` (0.75) | LIKELY_FP | `block_ratio < fp_benign_high_conf_ratio` (0.25)이면 HIGH, 아니면 MEDIUM |
| 3 | `block_ratio > 0.75` AND `rules_triggered >= 3` | TRUE_POSITIVE | HIGH |
| 4 | `block_ratio > 0.90` AND `rules_triggered >= 2` | TRUE_POSITIVE | HIGH |
| 5 | `block_ratio > 0.75` AND `peak_rpm > 250` | TRUE_POSITIVE | MEDIUM |
| 6 | `block_ratio < 0.05` AND `rules_triggered <= 3` | LIKELY_FP | MEDIUM; 차단된 URI가 사이트의 인기 허용 URI에 포함되고 IP 국가가 상위 국가에 포함되면 HIGH |
| 7 | allow:block 비율 > 10 AND `peak_rpm < 10` AND 규칙 정확히 1개 | LIKELY_FP | MEDIUM (같은 인기 URI/상위 국가 조건이면 HIGH) |
| — | 그 외 | UNDETERMINED | LOW |

**"정상으로 보임" (규칙 2)**은 의도적으로 좁게 정의됨: 페이로드가 이름/단어 패턴(`_FP_PATTERNS`: `O'Brien` 같은 아포스트로피 이름, Title Case 이름, 30자 이하의 문자/공백/아포스트로피/하이픈)에 일치하고 AND `_SUSPICIOUS_TOKENS`(`select`, `union`, `admin`, `root`, `script`, `cmd`, `or`, `and` 같은 SQL/셸/XSS 키워드)를 하나도 포함하지 않아야 함. 소문자 단어 하나, IP 리터럴, URL은 공격자가 쉽게 만들 수 있으므로 정상으로 **보지 않음**. 검사한 페이로드 중 공격도 정상도 아닌 것이 하나라도 있으면 규칙 2는 적용되지 않음.

**출력**: `{ip, verdict, confidence, allow_count, block_count, block_ratio, peak_rpm, rules_triggered, match_detail_attack, match_detail_fp, matched_payloads, uri_in_popular_paths, country_in_top_customers}`.

**입력 처리**: `ip`는 Logs Insights 쿼리에 삽입되므로 IPv4/IPv6 주소로 파싱되어야 함 (아니면 호출 실패). 실패·취소·타임아웃된 Logs Insights 쿼리는 빈 결과를 반환하지 않고 오류를 발생시킴.

### 3.3 IP별 서브쿼리 (8개)

```sql
-- 1. 액션 분류 (block_ratio, allow_count, block_count)
filter httpRequest.clientIp = '{ip}'
| stats count(*) as hits by action

-- 2. 최대 RPM
filter httpRequest.clientIp = '{ip}'
| stats count(*) as hits by bin(1m)
| stats max(hits) as peak_rpm, avg(hits) as avg_rpm

-- 3. 트리거된 규칙 (ALLOW 제외)
filter httpRequest.clientIp = '{ip}' and action != 'ALLOW'
| stats count(*) as hits by terminatingRuleId | sort hits desc | limit 10

-- 4. 매치 데이터 추출 (공격/정상 분류)
filter httpRequest.clientIp = '{ip}' and action = 'BLOCK'
  and @message like '"terminatingRuleMatchDetails":[{'
| fields @message | limit 5

-- 5. 차단 URI 분포
filter httpRequest.clientIp = '{ip}' and action = 'BLOCK'
| stats count(*) as hits by httpRequest.uri | sort hits desc | limit 10

-- 6. 사이트 전체 인기 허용 URI (uri_in_popular_paths용)
filter action = 'ALLOW'
| stats count(*) as hits by httpRequest.uri | sort hits desc | limit 20

-- 7. 사이트 전체 상위 국가 (country_in_top_customers용)
stats count(*) as hits by httpRequest.country | sort hits desc | limit 10

-- 8. 이 IP의 국가
filter httpRequest.clientIp = '{ip}'
| stats count(*) as hits by httpRequest.country | limit 1
```

---

## 4. 바이패스 탐지

### 4.1 사전 바이패스 스캔

ALLOW 로그에서 WAF 규칙을 우회하는 악성 트래픽 탐지:

| 카테고리 | 조건 | 해석 |
|---------|------|------|
| **높은 URI 다양성** | ALLOW + unique_uris > 50 (`bypass_uri_diversity`; 정적 자산/검증된 봇 제외) | 크롤러/스크래퍼 |
| **엔드포인트 해머링** | ALLOW + requests > 200 (`bypass_hammer_min_total`) + unique_uris < 10 (`bypass_hammer_max_uris`) | DDoS 또는 무차별 대입 |
| **미분류 데이터센터** | ALLOW + `known_bot_data_center` 라벨, 검증/미검증 봇 아님, requests > 50 (`bypass_datacenter_min_total`) | 호스팅 업체발 자동화 |

정적 자산 제외: 요청 URI에 `\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)` 적용.

`scan_bypass_candidates`는 카테고리당 최대 10개 IP를 반환. Analyzer는 요청 수가 `min(max(허용 트래픽의 1%, 20), 100)`에 도달한 후보에 대해 `investigate_ip_deep`를 실행 (`DEEP_INVESTIGATION_PCT`, `DEEP_INVESTIGATION_MIN`, `DEEP_INVESTIGATION_MAX`).

### 4.2 IP 심층 조사 (investigate_ip_deep)

IP당 8개 서브쿼리 (`ip`는 IP 주소인지 검증됨):

| 분석 항목 | 서브쿼리 |
|----------|---------|
| 빈도 | ALLOW 요청: `stats count(*) by bin(1m)` → peak_rpm, avg_rpm |
| 액션 분류 | `stats count(*) by action` |
| 국가 | `stats count(*) by httpRequest.country` (상위 1개) |
| 봇 라벨 | `bot:category:*` 라벨 → 상위 5개 |
| JA4 핑거프린트 | `stats count(*) by ja4Fingerprint` → 상위 5개 |
| User-Agent | raw 로그에서 파싱한 `user-agent` 헤더 → 상위 5개 |
| 상위 URI | `stats count(*) by httpRequest.uri` → 상위 10개 |
| 비종료 규칙 | `nonTerminatingMatchingRules` 규칙 ID → 상위 10개 |

출력: `{ip, frequency, actions, country, bot_labels, ja4_fingerprints, user_agents, top_uris, non_terminating_rules}`.

### 4.3 볼륨 이상 탐지

CloudWatch Metrics (AWS/WAFV2 네임스페이스) 사용:
- AllowedRequests/BlockedRequests: 이번 주 vs 지난주 비교
- WoW 비율 임계값: 정상(<2x), 보통(2-3x), 이상(>3x) — 기본값(`volume_moderate_wow`, `volume_significant_wow`)이며 `detection_thresholds`로 변경 가능
- ALLOW 급증(> `volume_significant_wow`) + BLOCK 비례하지 않음(< `volume_blocked_wow_max`) → `bypass_suspected`

---

## 5. 라벨 & 봇 인텔리전스

### 5.1 봇 인텔리전스 쿼리 (`query_bot_intelligence`, 4개)

```sql
-- 봇 카테고리 분포 (상위 10개)
filter @message like 'bot:category'
| parse @message /bot:category:(?<category>[^"}\s,]+)/
| stats count(*) as hits by category | sort hits desc | limit 10

-- 검증됨 vs 미검증 비율
filter @message like 'bot-control:bot:'
| stats sum(@message like 'bot:verified') as verified,
        sum(@message like 'bot:unverified') as unverified

-- AI 봇: 이름과 액션
filter @message like 'bot:category:ai'
| parse @message /bot:name:(?<bot_name>[^"}\s,]+)/
| stats count(*) as hits by bot_name, action | sort hits desc

-- AI 봇이 요청한 URI (상위 20개)
filter @message like 'bot:category:ai'
| stats count(*) as hits by httpRequest.uri | sort hits desc | limit 20
```

출력: `{categories_top10, verified_ratio, ai_bot_stats: {bots, top_uris}}`.

### 5.2 라벨 분포 (`query_label_distribution`, 2개)

```sql
-- 공격 규칙 라벨 분포 (차단된 요청)
filter action = 'BLOCK'
| parse @message /awswaf:managed:aws:(?<rule_group>[^:]+):(?<rule_name>[^"}\s,]+)/
| stats count(*) as hits by rule_group, rule_name
| sort hits desc | limit 20

-- Bot Control 시그널 라벨 (의심 지표)
filter @message like 'bot-control:signal:'
| parse @message /signal:(?<signal>[^"}\s,]+)/
| stats count(*) as hits by signal | sort hits desc
```

출력: `{attack_types: [{group, rule, hits}], signals: [{signal, hits}]}`.

---

## 6. 추가 분석 기능

### 6.1 도메인별 분석 (query_per_domain)

멀티 도메인 WebACL에서 Host 헤더를 추출하여 도메인별 트래픽 패턴 식별:

```sql
parse @message /"name":"[Hh]ost","value":"(?<host>[^"]+)"/
| stats count(*) as total,
        sum(action='BLOCK') as blocked,
        sum(action='ALLOW') as allowed
  by host
| sort total desc | limit 20
```

차단율이 10%를 넘는 도메인 최대 3개(`domain_drilldown_block_rate`, `domain_drilldown_count`)에 대해 두 번째 쿼리로 상위 5개 종료 규칙을 반환. Host 헤더는 공격자가 조작할 수 있으므로 드릴다운은 `[A-Za-z0-9.-]`로만 이루어진 호스트명에만 실행.

### 6.2 비종료 규칙 (query_non_terminating_rules)

COUNT 모드 규칙 추적 + 다운스트림 BLOCK 의존성 감지:

```sql
-- WAF 로그의 COUNT 규칙 히트
filter @message like '"nonTerminatingMatchingRules":[{'
| parse @message /nonTerminatingMatchingRules.*?"ruleId":"(?<rule>[^"]+)"/
| stats count(*) as match_count by rule
| sort match_count desc | limit 20
```

**다운스트림 BLOCK 감지**: WebACL 설정을 `get_web_acl`로 가져온 뒤 각 COUNT 규칙에 대해:
- 라벨 생성 여부 확인 (대부분의 관리형 규칙은 라벨 생성)
- 해당 라벨을 scope-down 문에서 소비하는 다운스트림 BLOCK 규칙 존재 여부 확인
- 있으면 → "label_sourced" (COUNT 유지 안전 — 다운스트림이 블로킹 처리)
- 없고 `match_count > promotion_min_matches` (기본 10)이면 → "promotion_candidate" (COUNT인데 아무 조치 없음 = 갭)

### 6.3 IP 평판 강화 (enrich_ip_reputation)

**AbuseIPDB** (REST API, `ABUSEIPDB_API_KEY` 환경변수 필요):
- 무료 티어: 1000회/일
- 반환: abuseConfidenceScore (0-100), isp, totalReports, usageType
- 키 미설정시 graceful degradation (null 반환)

**Emerging Threats 블록리스트** (Proofpoint, API 키 불필요):
- S3 `{findings_bucket}/threat-intel/et-blocklist.txt`에 캐시 (24시간이 지나면 갱신, 갱신 실패 시 오래된 캐시 사용)
- 정확한 IP / CIDR 포함 여부로 판정 (부분 문자열 검색 아님). 목록을 얻지 못하면 `et_listed`는 null

### 6.4 JA4 핑거프린트 분석

- `ja4Fingerprint` 필드로 TLS 클라이언트 특성 식별
- 다수 IP에서 동일 JA4 → 봇넷/분산 스캐너
- `investigate_ip_deep`에서 쿼리: `fields ja4Fingerprint | stats count(*) by ja4Fingerprint`

---

## 7. 도구 인터페이스 명세 (20개)

모든 도구는 단일 Lambda (`waf-report-tools`)에서 실행. Gateway가 MCP 요청의 `_tool` 필드로 라우팅. 리포트 발송(SNS)은 Supervisor가 직접 처리 (Lambda 경유 아님).

**공통 동작**
- `region` 기본값은 Lambda의 `REGION`, `lookback_hours` 기본값은 `LOOKBACK_HOURS` (24)이며 1–720 범위로 제한.
- Logs Insights 쿼리를 실행하는 도구는 별도 표기가 없으면 결과 행을 문자열화된 리스트로 반환. 실패·취소·타임아웃된 쿼리는 MCP 오류(`isError: true`)를 반환하고 쿼리를 중지하며, 빈 결과를 반환하지 않음.
- 에이전트별 도구 접근은 Cedar 정책으로 제한 (§ 1.2 참조).

### 7.1 분석 도구

| 도구 | 인자 | 반환 |
|------|------|------|
| `query_waf_summary` | log_group, lookback_hours, region | `[{total, unique_ips, blocked, allowed, other}]` (1행) |
| `query_top_blocked` | log_group, lookback_hours, region, limit (1–100, 기본 20) | `[{ip, rule, cnt}]` |
| `query_false_positive_signals` | ip, log_group, lookback_hours, region | `{ip, verdict, confidence, allow_count, block_count, block_ratio, peak_rpm, rules_triggered, match_detail_attack, match_detail_fp, matched_payloads, uri_in_popular_paths, country_in_top_customers}` |
| `scan_bypass_candidates` | log_group, lookback_hours, region | `{candidates: [{category, ip, total, unique_uris}], count}` (`unclassified_datacenter` 항목은 `total`만 포함) |
| `investigate_ip_deep` | ip, log_group, lookback_hours, region | `{ip, frequency, actions, country, bot_labels, ja4_fingerprints, user_agents, top_uris, non_terminating_rules}` |
| `query_label_distribution` | log_group, lookback_hours, region | `{attack_types: [{group, rule, hits}], signals: [{signal, hits}]}` |
| `query_bot_intelligence` | log_group, lookback_hours, region | `{categories_top10, verified_ratio, ai_bot_stats: {bots, top_uris}}` |
| `check_volume_anomaly` | web_acl_arn, region | `{wow_allowed, wow_blocked, classification, bypass_suspected}` |
| `query_rate_limit_hits` | log_group, lookback_hours, region | RATE_BASED 종료 규칙의 `[{ip, rule, cnt}]` |
| `query_suspicious_patterns` | log_group, lookback_hours, region | `suspicious_min_requests` / `suspicious_min_uris`를 넘는 ALLOW 트래픽의 `[{ip, cnt, uri_cnt}]` |
| `query_per_domain` | log_group, lookback_hours, region | `{domains: [{domain, total, blocked, allowed, block_rate, top_rules?}], count}` |
| `query_non_terminating_rules` | log_group, web_acl_arn, lookback_hours, region | `{non_terminating_rules: [{rule, match_count, has_downstream_block, downstream_rule, promotion_candidate}], total_count, promotion_candidates, label_sourced}` |
| `enrich_ip_reputation` | ip | `{ip, abuseipdb: {score, total_reports, isp, country, is_tor, usage_type, domain} \| {error} \| null, et_listed: true \| false \| null}` |
| `run_custom_waf_query` | query, log_group, lookback_hours, region | 원시 Logs Insights 행 |

### 7.2 관리 도구

| 도구 | 인자 | 반환 |
|------|------|------|
| `get_web_acl` | web_acl_arn, region | `{rules, lock_token, capacity}` |
| `update_web_acl_rules` | web_acl_arn, rules_json, region, dry_run | `dry_run` 미리보기 또는 `{status: "applied", rule_count}`. `WAF_WRITE_ENABLED=true`가 아니면 거부. `rules_json`은 전체 룰 목록이며, 신규/변경 룰은 COUNT 전용, 기존 룰 삭제·수정 불가, 신규 룰 최대 5개. lock token은 적용 시점에 조회 (`lock_token` 인자는 무시) |
| `check_coverage_gaps` | web_acl_arn, region | `{gaps: [{gap, recommendation}], rules_count}` (Bot Control, rate-based 규칙, Anti-DDoS) |

### 7.3 유틸리티 도구

| 도구 | 인자 | 반환 |
|------|------|------|
| `current_datetime` | timezone (기본: `DEFAULT_TIMEZONE`, Asia/Singapore) | `{datetime, timezone, date, time}` |
| `list_pending_findings` | bucket, prefix (기본 `findings/pending/`) | `{files: [{file, content}], count}`; `.json/.md/.txt` 내용은 20,000자로 잘림, PDF는 표기만. 결과 첫 페이지(최대 1000개 키)만 처리 |
| `archive_processed_findings` | bucket, files_json (키의 JSON 배열) | `{archived: N}`; 키는 pending 접두사 아래여야 하며 `findings/processed/`로 이동 |

---

## 8. 에이전트 시스템 프롬프트

### 8.1 Supervisor

**핵심 동작**:
- `current_datetime` 먼저 호출하여 정확한 타임스탬프 확보
- 서브에이전트를 순서대로 호출: analyzer → validator → executor (조건부)
- Analyzer 출력을 원문 그대로 Validator에 전달 (요약 금지)
- Validator가 0건 규칙 변경 승인시 executor 스킵
- 최종 출력은 **plaintext 리포트** (JSON 아님) — 이메일 발송용

**리포트 템플릿**:
```
═══════════════════════════════════════════
  WAF Daily Security Report
  Date: {날짜}
  Period: Last {lookback_hours} hours
  Status: {HEALTHY / ACTION_REQUIRED / CRITICAL}
═══════════════════════════════════════════

▶ TRAFFIC OVERVIEW
▶ TOP BLOCKED IPs
▶ FALSE POSITIVE ANALYSIS
▶ THREATS & ANOMALIES
▶ VALIDATOR ASSESSMENT
▶ RULE CHANGES
▶ EXTERNAL FINDINGS

───────────────────────────────────────────
  Next run: {내일} {schedule_expression + schedule_timezone 기준 다음 실행 시각}
═══════════════════════════════════════════
```

**LLM 이후 프로그래밍 단계**:
1. `_clean_for_email()` — 마크다운 잔존물 제거 (코드 펜스, 볼드, 헤더)
2. 리포트의 `Status:` 줄에서 심각도 감지 (CRITICAL / ACTION_REQUIRED→HIGH / HEALTHY, 기본 INFO) → 이메일 제목
3. `boto3.client("sns").publish()` — 정확히 1회, LLM 개입 없음

### 8.2 Analyzer

**핵심 동작**:
- Phase 1은 100% 프로그래밍 방식 (LLM 없음) — `_collect_raw_data()` ~24개 도구 순차 호출
- Phase 2 LLM은 모든 raw 데이터를 수신하며 재쿼리 금지
- Phase 2 집중: 바이패스 위협 평가, COUNT 승격, 추천
- Phase 3 `_merge_with_raw_data()` — raw 데이터 권위를 LLM 출력에 강제
- FP 판정(Lambda)이 권위적; LLM 오버라이드는 `override_reasoning` 필수
- AgentCore Memory로 세션 간 트렌드 감지

**도구 호출 예산**: Phase 1에서 ~24회:
- query_waf_summary (1), query_top_blocked (1)
- query_false_positive_signals × 9 IP (9)
- check_volume_anomaly (1), scan_bypass_candidates (1)
- investigate_ip_deep × N 후보 (~2)
- query_bot_intelligence (1), query_label_distribution (1)
- query_per_domain (1), query_non_terminating_rules (1)
- enrich_ip_reputation × 5 IP (5)

### 8.3 Validator

**핵심 동작**:
- Analyzer 출력을 원문으로 수신
- 독립 쿼리(run_custom_waf_query)로 증거 스팟체크
- 애플리케이션 컨텍스트 평가 (차단 경로가 실제 엔드포인트인지)
- COUNT→BLOCK 승격 전 다운스트림 라벨 의존성 확인
- 결정: APPROVE / REJECT / MODIFY / NEEDS_REVIEW
- 신뢰도 임계값 설정 가능 (기본 0.7)
- 광범위한 예외 (path=/*) 절대 승인 불가

### 8.4 Executor

**핵심 동작**:
- 검증된 findings만 수신
- `get_web_acl` 먼저 호출하여 현재 상태 + 용량 확인
- 첫 배포시 절대 BLOCK 모드로 규칙 생성하지 않음 — 항상 COUNT
- 볼륨 공격에는 rate-based 규칙 선호
- dry_run 모드: True이면 변경 제안만 (JSON 출력)
- 출력: `[{type: add|modify|skip, rule_name, reason, mode}]`
- Validator가 0건 승인시 완전히 스킵

---

## 9. 인프라 구현

### 9.1 Terraform 리소스

```hcl
# ECR 저장소 (4개 에이전트)
resource "aws_ecr_repository" "agents" {
  for_each = toset(["supervisor", "analyzer", "validator", "executor"])
}

# Docker 빌드 + 푸시 (handler.py 해시 변경시 트리거)
resource "null_resource" "docker_push" {
  triggers = { code_hash = filesha256("../agents/${each.key}/handler.py") }
}

# AgentCore 런타임 (4개)
resource "aws_bedrockagentcore_agent_runtime" "this" {
  # DEPLOY_VERSION 환경변수로 코드 변경시 컨테이너 갱신 강제
  environment { DEPLOY_VERSION = filesha256("../agents/${each.key}/handler.py") }
}

# AgentCore Gateway + Lambda Target
resource "aws_bedrockagentcore_gateway_target" "lambda" {
  # 스키마 변경시 Target 재생성
  lifecycle { replace_triggered_by = [aws_s3_object.tool_schemas.etag] }
}

# Tools Lambda (단일 함수, 20개 도구, Gateway 경유 호출)
resource "aws_lambda_function" "tools" {
  function_name = "waf-report-tools"
  handler = "tools_handler.handler"
  timeout = 120
  environment {
    FINDINGS_BUCKET, ABUSEIPDB_API_KEY (sensitive), REGION, DEFAULT_TIMEZONE,
    WAF_WRITE_ENABLED (var.allow_waf_write), WAF_THRESHOLDS (var.detection_thresholds)
  }
}

# 컨트롤 플레인 Lambda (추가 3개) — 재시도 잠금은 § 2.4 참조
resource "aws_lambda_function" "trigger" {
  function_name = "waf-report-trigger"
  handler = "trigger_handler.handler"
  timeout = 60
  environment { REGION, FINDINGS_BUCKET, RUNNER_FUNCTION_NAME, LOOKBACK_HOURS, DRY_RUN }
}
resource "aws_lambda_function" "runner" {
  function_name = "waf-report-runner"
  handler = "runner_handler.handler"
  timeout = 900   # boto3 read_timeout = 850 (코드 안)
  environment { REGION, FINDINGS_BUCKET, SUPERVISOR_RUNTIME_ARN, LOOKBACK_HOURS, DRY_RUN }
}
resource "aws_lambda_function" "healthcheck" {
  function_name = "waf-report-healthcheck"
  handler = "healthcheck_handler.handler"
  timeout = 60
  environment { REGION, FINDINGS_BUCKET, SNS_TOPIC_ARN, HANG_THRESHOLD_MINUTES, RUNNER_FUNCTION_NAME }
}

# trigger + runner의 async 재시도 잠금
resource "aws_lambda_function_event_invoke_config" "trigger" {
  function_name = aws_lambda_function.trigger.function_name
  maximum_retry_attempts = 0
  maximum_event_age_in_seconds = 60
}
resource "aws_lambda_function_event_invoke_config" "runner" {
  function_name = aws_lambda_function.runner.function_name
  maximum_retry_attempts = 0
  maximum_event_age_in_seconds = 60
}

# EventBridge Scheduler A (trigger) — retry_policy.max_retry_attempts = 0
resource "aws_scheduler_schedule" "daily_waf_scan" {
  schedule_expression = var.schedule_expression  # cron(0 8 * * ? *) SGT
  target {
    arn = "arn:aws:scheduler:::aws-sdk:lambda:invoke"
    input = jsonencode({ FunctionName = ..., InvocationType = "Event", Payload = "" })
    retry_policy { maximum_retry_attempts = 0 }
  }
}

# EventBridge Scheduler B (healthcheck) — retry_policy.max_retry_attempts = 0
resource "aws_scheduler_schedule" "daily_waf_healthcheck" {
  schedule_expression = var.healthcheck_schedule_expression  # cron(15 8 * * ? *) SGT
  target {
    arn = aws_lambda_function.healthcheck.arn
    retry_policy { maximum_retry_attempts = 0 }
  }
}

# SNS Topic + S3 Findings/Markers 버킷 + Cedar Policy Engine + Memory
```

### 9.2 에이전트별 환경변수

| 에이전트 | 주요 환경변수 |
|---------|------------|
| **Supervisor** | `MODEL_ID`, `REGION`, `GATEWAY_URL`, `ANALYZER_RUNTIME_ARN`, `VALIDATOR_RUNTIME_ARN`, `EXECUTOR_RUNTIME_ARN`, `WEB_ACL_ARN`, `LOG_GROUP`, `SNS_TOPIC_ARN`, `FINDINGS_BUCKET`, `SCHEDULE_EXPRESSION`, `SCHEDULE_TIMEZONE` |
| **Analyzer** | `MODEL_ID`, `REGION`, `GATEWAY_URL`, `WEB_ACL_ARN`, `LOG_GROUP`, `MEMORY_ID`; 선택 `FP_SIGNAL_MAX_IPS` (9), `REPUTATION_MAX_IPS` (5), `DEEP_INVESTIGATION_PCT` (0.01), `DEEP_INVESTIGATION_MIN` (20), `DEEP_INVESTIGATION_MAX` (100) |
| **Validator** | `MODEL_ID`, `REGION`, `GATEWAY_URL`, `WEB_ACL_ARN`, `LOG_GROUP` (필수, 내장 기본값 없음), `CONFIDENCE_THRESHOLD` (0.7) |
| **Executor** | `MODEL_ID`, `REGION`, `GATEWAY_URL`, `WEB_ACL_ARN` |

모든 런타임은 Terraform `agent_env_overrides` 항목도 함께 받음. `REGION`이 없으면 `AWS_REGION` / `AWS_DEFAULT_REGION`을 사용.

### 9.3 IAM 권한

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

### 9.4 Docker 이미지

공유 `Dockerfile` + `ARG AGENT_NAME`:
```dockerfile
FROM --platform=linux/arm64 python:3.11-slim-bookworm
ARG AGENT_NAME
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ${AGENT_NAME}/handler.py .
EXPOSE 8080
CMD ["python", "handler.py"]
```

의존성: `strands-agents`, `bedrock-agentcore`, `mcp`, `boto3`

---

## 10. MCP Gateway 프로토콜

### 10.1 도구 호출 흐름

```
Agent (Strands SDK) → MCPClient → streamable_http → Gateway → Lambda
```

### 10.2 Gateway 라우팅

Lambda가 `_tool` 필드로 디스패치:
```python
def handler(event, context):
    tool_name = event.get("_tool", "")
    if tool_name == "query_waf_summary": return _query_waf_summary(event)
    ...
```

### 10.3 프로그래밍 방식 MCP 호출 (Analyzer Phase 1)

```python
# LLM 밖에서 직접 MCP 호출 (토큰 비용 없음)
result = mcp_client.call_tool_sync(
    tool_use_id=str(uuid.uuid4()),
    name="query_waf_summary",
    arguments={"log_group": log_group, "lookback_hours": 24,
               "region": "us-east-1", "_tool": "query_waf_summary"}
)
# 결과: {"content": [{"type": "text", "text": "{\"total\": 272, ...}"}]}
```

**중요**: 인자에 반드시 `"_tool": tool_name` 포함 — Gateway Lambda가 이 필드로 라우팅.

### 10.4 Lambda 응답 형식

```python
return {"content": [{"type": "text", "text": json.dumps(result)}]}
```

`"type": "text"` 필수 — MCP SDK 검증이 이 필드 없으면 거부.

---

## 11. 이메일 리포트 포맷팅

### 11.1 설계 원칙

- 출력이 이메일(SNS → Email)로 직접 전달
- 일반 이메일 클라이언트는 HTML/Markdown 렌더링 안 함
- Unicode 박스 드로잉 문자 사용 (═, ─, ▶, •)
- 실제 숫자, IP, 규칙명 포함 — 모호한 요약 금지
- 목표 2000-4000자

### 11.2 클린업 함수

```python
def _clean_for_email(text: str) -> str:
    import re
    text = re.sub(r'```[\w]*\n?', '', text)           # 코드 펜스
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)      # **볼드**
    text = re.sub(r'\*(.+?)\*', r'\1', text)           # *이탤릭*
    text = re.sub(r'^#{1,4}\s+', '', text, flags=re.MULTILINE)  # # 헤더
    text = re.sub(r'\n{3,}', '\n\n', text)             # 과도한 빈 줄
    return text.strip()
```

### 11.3 심각도 감지

```python
severity = "INFO"
m = re.search(r"Status\s*:\s*(\w+)", report_body)   # 리포트 헤더 줄에서 추출
if m:
    status = m.group(1).upper()
    if status == "CRITICAL":
        severity = "CRITICAL"
    elif status in ("ACTION_REQUIRED", "HIGH"):
        severity = "HIGH"
    elif status == "HEALTHY":
        severity = "HEALTHY"
# 제목: "WAF Daily Security Report — 2026-06-19 — HEALTHY"  (날짜 = 컨테이너 UTC 날짜)
```

---

## 12. 제약 & 설계 결정

### 성능
- Analyzer Phase 1: ~24개 순차 도구 호출 (CWL 쿼리 1-3초/개)
- 전체 파이프라인: ~3-10분 (Supervisor의 서브에이전트 호출 `read_timeout`: 600초, runner Lambda 상한: 900초)
- FP 분석 9개 IP로 제한 (비용 대비 커버리지 균형)
- IP 평판 5개 IP 제한 (AbuseIPDB 무료: 1000회/일)

### 안전
- 모든 WAF 변경은 dry_run=True. 이중으로 강제: tools Lambda는 `allow_waf_write=true`가 아니면 쓰기를 거부하고, Gateway 정책 엔진(`ENFORCE`)은 `dry_run == false`인 `update_web_acl_rules`를 forbid
- Executor는 0건 변경시 스킵 — Opus 호출 절약
- SNS 접근 게이트: source_agent != "supervisor"이면 Lambda 거부
- 첫 적용시 절대 BLOCK 모드 금지

### 신뢰성
- Fail-fast: traffic_overview 오류/제로시 Analyzer 즉시 중단
- Raw 데이터 권위: LLM이 프로그래밍 수집 숫자 오버라이드 불가
- 판정 오버라이드시 명시적 `override_reasoning` 필수
- 정확히 1회 리포트: 프로그래밍 방식 SNS 발행 (LLM 제어 아님)

### 비용 최적화
- Supervisor는 Sonnet 사용 (저렴, 라우팅 전용)
- 서브에이전트는 Opus 사용 (복잡한 분석/검증)
- Phase 1 프로그래밍 방식은 Bedrock 토큰 0 사용 (~24 호출 무료)
- Supervisor가 SNS 직접 발행 (reporter 에이전트·추가 런타임 없음)
- Executor 스킵으로 클린 런에서 Opus 1회 절약
- 예상: $0.44-0.57/실행, 일 1회 시 ~$15/월

---

## 13. WAF 로그 필드 레퍼런스

```
httpRequest.clientIp         — 클라이언트 IP 주소
httpRequest.uri              — 요청 URI 경로
httpRequest.httpMethod       — HTTP 메서드
httpRequest.country          — GeoIP 국가 코드 (2자)
httpRequest.headers          — 헤더 배열 [{name, value}]
action                       — ALLOW / BLOCK / CAPTCHA / CHALLENGE / COUNT
terminatingRuleId            — 평가를 종료시킨 규칙
terminatingRuleType          — REGULAR / MANAGED_RULE_GROUP / RATE_BASED
terminatingRuleMatchDetails  — 매치 증거 (SQLi/XSS 패턴)
nonTerminatingMatchingRules  — COUNT 모드에서 매치된 규칙 (배열)
labels                       — WAF 라벨 배열 [{name, value}]
ja4Fingerprint               — JA4 TLS 클라이언트 핑거프린트
rateBasedRuleList            — 매치된 rate-based 규칙
```

### CloudWatch Metrics

```
Namespace: AWS/WAFV2
Dimensions: WebACL={name}, Rule={rule}, Region={region}
Metrics: AllowedRequests, BlockedRequests, CountedRequests,
         CaptchaRequests, ChallengeRequests
```

---

## 14. 파일 구조

```
aws-waf-report-agent/
├── agents/
│   ├── Dockerfile               # 공유 (ARG AGENT_NAME)
│   ├── requirements.txt         # strands-agents, bedrock-agentcore, mcp, boto3
│   ├── supervisor/handler.py    # 오케스트레이터 + S3 idempotency 클레임 + 프로그래매틱 SNS + 이메일 클린업
│   ├── analyzer/handler.py      # Phase 1-3 하이브리드 분석
│   ├── validator/handler.py     # 독립 검증
│   └── executor/handler.py      # 규칙 변경 제안
├── lambda/
│   ├── trigger_handler.py       # EventBridge A → run_id 생성, runner async 호출
│   ├── runner_handler.py        # trigger가 async 호출, invoke_agent_runtime sync 실행
│   ├── healthcheck_handler.py   # EventBridge B (T+15분) → hang 마커 감지, 경보 메일, 오래된 마커 삭제
│   └── tools_handler.py         # 전체 20개 도구 (단일 Lambda, Gateway 경유 호출)
├── infra/
│   ├── main.tf                  # 전체 Terraform 리소스 (Scheduler 2개, Lambda 4개, Runtime 4개, Gateway, Memory, IAM, S3, SNS)
│   ├── variables.tf             # 입력 변수 (healthcheck_schedule_expression + healthcheck_hang_threshold_minutes 포함)
│   ├── terraform.tfvars.example # 예제 설정
│   ├── tool_schemas.json        # MCP 도구 정의 (20개)
│   └── policies/                # Cedar 정책 (에이전트별 최소권한)
├── docs/
│   ├── ANALYSIS_AGENT_REQUIREMENTS.md    # 이 문서 (영문)
│   ├── ANALYSIS_AGENT_REQUIREMENTS_ko.md # 이 문서 (한국어)
│   ├── pipeline-flow.mmd                 # Mermaid 소스
│   └── pipeline-flow.svg                 # 렌더링된 다이어그램
├── scripts/
│   ├── test_run.sh              # 배포 + 실행 + 검증 (빠른 반복)
│   ├── check_doc_drift.sh       # CI 체크 — README 테스트 수와 pytest 일치, tfvars.example과 variables.tf 일치, README와 이 spec 문서의 IAM 표 교차 검증
│   └── hooks/
│       ├── pre-commit           # Git pre-commit 훅 — 관련 파일 변경 시 check_doc_drift.sh 실행
│       └── install.sh           # scripts/hooks/*를 .git/hooks/에 심볼릭 링크로 설치
├── tests/
│   ├── test_tools.py            # 단위 테스트 (84개, 전체 mock — AWS 호출 없음)
│   └── test_e2e_agents.py       # E2E 통합 테스트 (Analyzer, Validator, Control Plane Lambda, Memory)
├── pyproject.toml               # 프로젝트 메타데이터 (개발 의존성: pytest)
├── LICENSE                      # MIT
├── README.md                    # 빠른 시작 가이드 (영문)
└── README.ko.md                 # 빠른 시작 가이드 (한국어)
```
