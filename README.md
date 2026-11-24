# AWS WAF Report Agent

Multi-agent WAF security operations system built on **Strands Agents SDK** + **Amazon Bedrock AgentCore**.
4 specialized agents collaborate to analyze WAF logs, detect false positives, identify undetected threats, validate recommendations, and deliver actionable reports daily.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ CONTROL PLANE — fire-and-forget with independent health check    │
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
  │ • generate run_id     │                     │ 60 s, retries=0        │
  │ • S3 PUT marker       │                     │                        │
  │   {status:"started"}  │                     │ • S3 LIST markers/     │
  │ • lambda.invoke(      │                     │   {today}/             │
  │     "runner",         │                     │ • For each marker:     │
  │     InvocationType=   │                     │   – status="completed" │
  │     "Event")          │                     │     → silent pass      │
  │ • return immediately  │                     │   – status="started"   │
  └──────────┬────────────┘                     │     ∧ age > 12 min     │
             │ async invoke                     │     → SNS alert email  │
             │ event_invoke_config              │       "pipeline hang"  │
             │ .max_retry_attempts = 0          │ • purge markers >7d    │
             ▼                                  └────────────────────────┘
  ┌────────────────────────────────┐                       ▲
  │ Lambda "runner" 900 s          │                       │
  │ • boto3 Config(               │                       │
  │     retries={max_attempts:1},│                       │
  │     read_timeout=850)         │                       │
  │ • invoke_agent_runtime(sync)  │                       │
  │ • on completion:               │                       │
  │     S3 PUT marker              │                       │
  │     {status:"completed"}      │                       │
  │ • on Lambda timeout: marker    │                       │
  │   stays "started" — HC picks   │                       │
  │   it up 15 min after trigger   │                       │
  └──────────────┬─────────────────┘                       │
                 │ invoke_agent_runtime                     │
                 ▼                                          │
  ┌─────────────────────────────────────────────────────────────────┐
  │ Supervisor Runtime (Claude Sonnet 4.6)                          │
  │ Orchestrates pipeline, invokes sub-agents, sends report (SNS)   │
  │                                                                 │
  │ ★ IDEMPOTENCY GUARD                                             │
  │   Before SNS publish, atomically CLAIM today's slot via         │
  │   S3 PutObject with IfNoneMatch:"*" on                          │
  │   markers/report-sent-{YYYY-MM-DD}.json                         │
  │   ├─ PreconditionFailed → zombie session — skip publish          │
  │   └─ Success → publish SNS + write run_id marker "completed"     │
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
  │ AgentCore Gateway (MCP protocol)                                │
  │ Single Lambda target — routes by _tool field                    │
  └──────────────────────────────┬──────────────────────────────────┘
                                 ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │ Lambda: waf-report-tools (20 tools)                             │
  │                                                                 │
  │ Analysis:                         Management:                   │
  │ • query_waf_summary               • get_web_acl                 │
  │ • query_top_blocked               • update_web_acl_rules        │
  │ • query_suspicious_patterns       • list_pending_findings (S3)  │
  │ • query_rate_limit_hits           • archive_processed_findings  │
  │ • query_false_positive_signals    • current_datetime            │
  │ • scan_bypass_candidates          • check_coverage_gaps         │
  │ • investigate_ip_deep (JA4/UA)                                  │
  │ • query_label_distribution        Enrichment:                   │
  │ • query_bot_intelligence          • enrich_ip_reputation        │
  │ • check_volume_anomaly              (AbuseIPDB + ET blocklist)  │
  │ • query_per_domain                Custom:                       │
  │ • query_non_terminating_rules     • run_custom_waf_query        │
  └─────────────────────────────────────────────────────────────────┘
           │              │              │              │
           ▼              ▼              ▼              ▼
     CloudWatch Logs    WAF v2         SNS        S3 (findings + markers)
```

### Reliability model — why every retry knob is zero

The pipeline is **daily** and **idempotent by date**. A missed run is recovered by the next day's run; a duplicated run would send the report twice. Every layer therefore turns retries off, and exactly-once delivery is enforced by a single S3 idempotency claim.

| Layer | Retry setting | Why |
|-------|---------------|-----|
| EventBridge Scheduler A (→ trigger) | `maximum_retry_attempts = 0` | Async fire-and-forget. If Lambda invoke fails, next day's schedule will run. |
| EventBridge Scheduler B (→ healthcheck) | `maximum_retry_attempts = 0` | Alert failure is acceptable — schedule fires again tomorrow. |
| Lambda trigger — event invoke config | `maximum_retry_attempts = 0` | Trigger is a 60 s bookkeeping function; if it fails, no pipeline runs, healthcheck alerts. |
| Lambda runner — event invoke config | `maximum_retry_attempts = 0` | Lambda's async default is 2 retries; a retry would start a second pipeline run. |
| Lambda runner — boto3 client | `retries={"max_attempts": 1}` | A client-side retry after a read timeout would start a second AgentCore session. `max_attempts=1` disables SDK retries; `read_timeout=850` keeps the call within the 900 s Lambda limit. |
| Lambda healthcheck — boto3 client | `retries={"max_attempts": 3, "mode": "standard"}` | Healthcheck is idempotent (read-only S3 + single SNS publish); safe to retry. |
| Supervisor SNS publish | atomic S3 `IfNoneMatch:"*"` claim | An AgentCore session keeps running server-side after the runner Lambda ends and can still reach the publish step. The S3 claim lets only the first session publish. |

## Agent Roles

| Agent | Model | Role |
|-------|-------|------|
| **Supervisor** | Claude Sonnet 4.6 | Pipeline orchestration — invokes sub-agents in sequence, publishes the report directly to SNS (programmatic, exactly once; no tools Lambda involved) |
| **Analyzer** | Claude Opus 4.6 | Hybrid analysis: programmatic data collection (FP verdicts, JA4, IP reputation, per-domain, COUNT rules) + LLM synthesizes recommendations only. AgentCore Memory enables day-to-day trend detection (recurring IPs, traffic changes, new patterns) |
| **Validator** | Claude Opus 4.6 | Independently verifies Analyzer recommendations against application context (spot-check queries, downstream label deps) → APPROVE / REJECT / MODIFY |
| **Executor** | Claude Opus 4.6 | Proposes WAF rule changes (dry_run mode — skipped if 0 rule changes needed). Real writes are disabled unless `allow_waf_write = true` (see [Safety Guardrails](#safety-guardrails)) |

## Pipeline Flow

```
Control plane (fire-and-forget):
────────────────────────────────
T=0:00   EventBridge A fires trigger Lambda (async, InvocationType=Event)
T=0:00   trigger Lambda:
           - run_id = uuid4()
           - S3 PUT markers/{YYYY-MM-DD}/{run_id}.json  {status:"started", started_at:now}
           - lambda.invoke("waf-report-runner", InvocationType=Event, payload={run_id, ...})
           - return  (Lambda exits in <2 s)
T=0:00   runner Lambda starts (async) — begins invoke_agent_runtime(supervisor, sync)

Data plane (supervisor pipeline, ~5–10 min):
────────────────────────────────────────────
1. Supervisor receives trigger (with timestamp, run_id)
2. Supervisor → invoke_analyzer
   └─ Analyzer Phase 1 (programmatic): query_waf_summary, query_top_blocked,
      query_false_positive_signals (×9 IPs → verdicts pre-classified),
      check_volume_anomaly, scan_bypass_candidates,
      investigate_ip_deep (auto for candidates > threshold, includes JA4/UA/URIs/COUNT rules),
      query_bot_intelligence, query_label_distribution,
      query_per_domain, query_non_terminating_rules, enrich_ip_reputation (×5 IPs)
   └─ Analyzer Phase 2 (LLM): assess bypass threats, COUNT promotion candidates, generate recommendations
      (tools available but data re-query prohibited — focus on value-add analysis)
   └─ Analyzer Phase 3 (merge): raw data + programmatic verdicts override LLM output
3. Supervisor → list_pending_findings (S3 external findings, e.g., pentest results)
4. Supervisor merges WAF + external findings
5. Supervisor → invoke_validator
   └─ Validator: spot-checks evidence, assesses application safety, checks downstream label deps
6. If rule changes needed: Supervisor → invoke_executor (dry_run produces rule proposal JSON)
   └─ Skipped entirely if validator approves 0 rule changes
7. Supervisor → archive_processed_findings (moves S3 files to processed/)
8. Supervisor → IDEMPOTENCY CLAIM
   S3 PutObject markers/report-sent-{YYYY-MM-DD}.json with IfNoneMatch:"*"
   ├─ PreconditionFailed (SlotAlreadyClaimed) → log & exit (zombie session)
   └─ Success → proceed to step 9
9. Supervisor → direct SNS publish (programmatic, exactly once)
10. Supervisor → S3 PUT markers/{YYYY-MM-DD}/{run_id}.json  {status:"completed", message_id, completed_at}
11. runner Lambda returns; if Lambda died at 900 s, marker stays "started" for healthcheck to catch

Health check plane (independent):
─────────────────────────────────
T=0:15   EventBridge B fires healthcheck Lambda (sync, retries=0)
         healthcheck Lambda:
           - list_objects_v2(prefix="markers/{today}/")
           - For each marker:
               * status="completed" → OK
               * status="started" ∧ (now - started_at) > 12 min → PIPELINE TIMEOUT
                 → SNS publish alert (subject: "WAF Pipeline Timeout — {date} — {run_id}")
           - purge markers older than 7 days
```

## Project Structure

```
aws-waf-report-agent/
├── agents/                      # AgentCore Runtime containers (4 agents)
│   ├── Dockerfile               # Shared Dockerfile (ARG AGENT_NAME selects handler)
│   ├── requirements.txt         # strands-agents, bedrock-agentcore, mcp, boto3
│   ├── supervisor/handler.py    # Orchestrator + S3 idempotency claim + SNS publish
│   ├── analyzer/handler.py      # WAF log analysis + recommendations
│   ├── validator/handler.py     # Recommendation verification
│   └── executor/handler.py      # WAF rule application
├── lambda/
│   ├── trigger_handler.py       # EventBridge A → generates run_id, async-invokes runner
│   ├── runner_handler.py        # Async-invoked by trigger, calls invoke_agent_runtime sync
│   ├── healthcheck_handler.py   # EventBridge B (T+15 min) → detects pipeline hangs → alert email
│   └── tools_handler.py         # All tools (Gateway MCP target, 20 tools)
├── tests/
│   ├── test_tools.py            # Unit tests (84, fully mocked — no AWS calls)
│   └── test_e2e_agents.py       # E2E integration tests (Analyzer, Validator, Control Plane Lambdas, Memory)
├── infra/
│   ├── main.tf                  # Terraform (ECR, Runtimes, Gateway, Memory, IAM, 2 Schedulers, 4 Lambdas: tools + 3 control-plane)
│   ├── variables.tf             # Input variables (adds healthcheck_schedule_expression + healthcheck_hang_threshold_minutes)
│   ├── terraform.tfvars.example # Example config
│   ├── tool_schemas.json        # MCP tool definitions for Gateway (20 tools)
│   └── policies/                # Cedar policies (per-agent least privilege)
├── docs/
│   ├── pipeline-flow.mmd        # Mermaid pipeline diagram source (control + data + health plane)
│   ├── pipeline-flow.svg        # Rendered SVG from pipeline-flow.mmd
│   ├── ANALYSIS_AGENT_REQUIREMENTS.md    # Full analysis spec (EN)
│   └── ANALYSIS_AGENT_REQUIREMENTS_ko.md # Full analysis spec (KO)
├── scripts/
│   ├── test_run.sh              # Deploy + invoke + verify (quick iteration)
│   ├── check_doc_drift.sh       # CI check — test count in README matches pytest, tfvars.example matches variables.tf
│   └── hooks/
│       ├── pre-commit           # Git pre-commit hook — runs check_doc_drift.sh when relevant files change
│       └── install.sh           # Symlinks scripts/hooks/* into .git/hooks/
├── pyproject.toml               # Python project metadata (dev deps: pytest)
├── LICENSE                      # MIT
├── README.md                    # (English)
└── README.ko.md                 # (Korean)
```

## Quick Start

### Prerequisites

- Python 3.10+, Docker, Terraform 1.5+
- AWS account with Bedrock Claude models enabled (us-east-1)
- WAF Web ACL with CloudWatch Logs logging enabled

### Deploy

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
# Edit: web_acl_arn, log_group, abuseipdb_api_key (optional)

terraform init
terraform apply
```

This automatically:
1. Creates ECR repositories (4)
2. Builds + pushes ARM64 container images (4 agents)
3. Creates AgentCore Runtimes with environment variables
4. Creates Gateway + Lambda target with tool schemas (20 tools)
5. Creates AgentCore Memory (semantic + episodic, 30-day retention)
6. Creates **two** EventBridge Schedulers:
   - `waf-report-daily-scan` — daily 8AM (`schedule_timezone`, default SGT) → trigger Lambda (async)
   - `waf-report-daily-healthcheck` — daily 8:15AM (same timezone) → healthcheck Lambda
7. Creates **three** Lambdas: `waf-report-trigger`, `waf-report-runner`, `waf-report-healthcheck`
8. Creates SNS topic + S3 findings/markers bucket

### Test

```bash
# Unit tests (mock — no AWS calls)
source .venv/bin/activate
pytest tests/test_tools.py -v          # 84 tests

# E2E integration (invokes real runtimes, checks tools + memory).
# web_acl_arn / log_group / region are read from infra/terraform.tfvars, or from the
# WAF_WEB_ACL_ARN, WAF_LOG_GROUP and AWS_REGION environment variables.
AWS_PROFILE=<your-profile> python tests/test_e2e_agents.py

# E2E with auto-deploy + retry on failure
AWS_PROFILE=<your-profile> python tests/test_e2e_agents.py --deploy --fix-loop

# Trigger a full pipeline run manually (fire-and-forget, returns in <2 s)
aws lambda invoke --function-name waf-report-trigger \
  --invocation-type Event \
  --profile <your-profile> --region <region> /dev/null

# Force-run healthcheck to see current marker state
aws lambda invoke --function-name waf-report-healthcheck \
  --profile <your-profile> --region <region> /tmp/hc.json && cat /tmp/hc.json
```

### Manual Invoke

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

## Deployment Notes

- **Container image updates**: Runtimes include `DEPLOY_VERSION = filesha256("handler.py")` env var — when code changes, runtime is updated and picks up new image automatically.
- **Tool schema updates**: Gateway Target uses `lifecycle { replace_triggered_by = [aws_s3_object.tool_schemas.etag] }` — schema changes trigger automatic target recreation.
- **Supervisor env vars** auto-update when sub-agent ARNs change (Terraform handles).
- **invoke_agent_runtime** uses raw JSON payload (NOT base64); response is streaming under `resp["response"]`.
- **Analyzer skill separation**: FP verdicts are deterministic (Lambda), deep investigation is threshold-based (programmatic), LLM focuses only on recommendation synthesis. Verdicts require `override_reasoning` to change.
- **Direct SNS publish + S3 idempotency claim**: Supervisor publishes SNS itself via `boto3.client("sns").publish()`. Immediately before publish, it performs an atomic S3 `PutObject` with `IfNoneMatch:"*"` on `markers/report-sent-{date}.json` — the first winner publishes, all zombie sessions get `PreconditionFailed` and exit silently.
- **Fire-and-forget from EventBridge**: Scheduler A uses the `aws-sdk:lambda:invoke` universal target with `InvocationType=Event`, so Lambda execution failures (including timeouts) do **not** trigger EventBridge retries. Scheduler A's `retry_policy.maximum_retry_attempts` is also `0`.
- **No boto3 retries in runner**: `botocore.config.Config(retries={"max_attempts":1}, read_timeout=850)` — a retry after a read timeout would start a second AgentCore session inside one Lambda execution.
- **Email formatting**: Supervisor LLM outputs a structured plaintext report (not JSON). `_clean_for_email()` strips residual markdown before SNS publish. Result is a clean, readable email with Unicode section headers (═══, ▶).

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `web_acl_arn` | WAF Web ACL ARN to monitor | (required) |
| `log_group` | CloudWatch log group for WAF logs | (required) |
| `sns_topic_arn` | SNS topic for reports (empty = auto-create) | `""` |
| `schedule_expression` | EventBridge A cron (evaluated in `schedule_timezone`) | `cron(0 8 * * ? *)` |
| `healthcheck_schedule_expression` | EventBridge B cron (evaluated in `schedule_timezone`) — should fire ≥ Lambda runner timeout after A | `cron(15 8 * * ? *)` |
| `schedule_timezone` | IANA timezone for both schedulers; also shown in the report footer and used as the tools Lambda default timezone | `Asia/Singapore` |
| `healthcheck_hang_threshold_minutes` | Marker age above which healthcheck considers pipeline hung | `12` |
| `schedule_enabled` | Enable/disable both schedules | `true` |
| `abuseipdb_api_key` | AbuseIPDB API key for IP reputation (free: 1000/day) | `""` |
| `region` | AWS region | `us-east-1` |
| `gateway_policy_mode` | AgentCore Gateway policy engine mode: `ENFORCE` (Cedar decisions are binding) or `LOG_ONLY` | `ENFORCE` |
| `allow_waf_write` | Hard switch in the tools Lambda: when `false`, `update_web_acl_rules` refuses every non-dry-run call | `false` |
| `agent_models` | Bedrock model / inference-profile ID per agent (`supervisor`, `analyzer`, `validator`, `executor`) | Sonnet 4.6 (supervisor), Opus 4.6 (others) |
| `detection_thresholds` | Overrides for detection thresholds, e.g. `{ fp_attacker_block_ratio = 0.8 }` (keys: see below) | `{}` |
| `agent_env_overrides` | Extra environment variables merged into every AgentCore runtime (e.g. `FP_SIGNAL_MAX_IPS`, `REPUTATION_MAX_IPS`, `DEEP_INVESTIGATION_PCT`, `CONFIDENCE_THRESHOLD`) | `{}` |

### Tuning detection thresholds

Verdict and anomaly thresholds live in `DEFAULT_THRESHOLDS` in `lambda/tools_handler.py` and can be overridden without code changes via `detection_thresholds` (passed to the tools Lambda as `WAF_THRESHOLDS`). Unknown keys and non-numeric values are ignored.

| Group | Keys |
|-------|------|
| False-positive verdict | `fp_attacker_block_ratio`, `fp_attacker_min_rules`, `fp_strong_block_ratio`, `fp_strong_min_rules`, `fp_volumetric_peak_rpm`, `fp_low_block_ratio`, `fp_low_max_rules`, `fp_benign_high_conf_ratio`, `fp_allow_block_multiple`, `fp_allow_max_peak_rpm` |
| Allowed-traffic scans | `suspicious_min_requests`, `suspicious_min_uris`, `bypass_uri_diversity`, `bypass_hammer_min_total`, `bypass_hammer_max_uris`, `bypass_datacenter_min_total` |
| Rules and domains | `promotion_min_matches`, `domain_drilldown_block_rate`, `domain_drilldown_count` |
| Volume anomaly (week over week) | `volume_moderate_wow`, `volume_significant_wow`, `volume_blocked_wow_max` |

Analyzer collection limits (`FP_SIGNAL_MAX_IPS` = 9, `REPUTATION_MAX_IPS` = 5, `DEEP_INVESTIGATION_PCT` = 0.01, `DEEP_INVESTIGATION_MIN` = 20, `DEEP_INVESTIGATION_MAX` = 100) are runtime environment variables; set them through `agent_env_overrides`.

## Safety Guardrails

| Control | Where | Behavior |
|---------|-------|----------|
| Write switch | tools Lambda (`WAF_WRITE_ENABLED`, from `allow_waf_write`) | `update_web_acl_rules` raises unless `true`, regardless of what an agent passes as `dry_run`. Default `false`. |
| Rule-change policy | tools Lambda | Existing rules cannot be removed or modified. At most 5 new rules per call. Every new or changed rule must be COUNT-only (`Action: Count`, or `OverrideAction: Count` for rule groups). Promoting to BLOCK is a manual action. The lock token is fetched at apply time, not taken from the caller. |
| Cedar authorization | AgentCore Gateway, `ENFORCE` | Default deny. Each agent runtime role may call only its own tools; the policies match the caller as `AgentCore::IamEntity` by assumed-role ARN (IAM-authorized gateways expose no principal tags). A forbid rule blocks `update_web_acl_rules` when `dry_run == false`. |
| Input validation | tools Lambda | IP arguments must parse as IP addresses and hostnames from logs must match `[A-Za-z0-9.-]` before they are used in Logs Insights queries; numeric arguments are clamped. |
| Query integrity | tools Lambda | Failed, cancelled or timed-out Logs Insights queries raise an error (and stop the query) instead of returning empty results, so a timeout never looks like "no traffic". |
| FP verdicts | tools Lambda | `LIKELY_FP` requires every inspected payload to look benign (names/words without attack keywords) and a block ratio below `fp_attacker_block_ratio`; HIGH confidence needs a block ratio below `fp_benign_high_conf_ratio`. |
| Threat intel | tools Lambda | ET blocklist matched by exact IP/CIDR (not substring), cached in S3 for 24 h, stale cache used if refresh fails; `et_listed` is `null` when the list cannot be obtained. |
| Archive guard | tools Lambda | `archive_processed_findings` only moves keys under `findings/pending/` (override: `FINDINGS_PENDING_PREFIX` / `FINDINGS_PROCESSED_PREFIX`). |

## IAM Permissions

| Role | Permissions |
|------|-------------|
| Supervisor Runtime | `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`, `bedrock-agentcore:InvokeAgentRuntime` (sub-agents), `bedrock-agentcore:InvokeGateway` (tools via Gateway), `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, `ecr:GetAuthorizationToken`, `s3:GetObject/PutObject/DeleteObject/ListBucket` (findings + markers), `sns:Publish` |
| Sub-agent Runtimes | `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`, `bedrock-agentcore:InvokeGateway`, memory ops (`CreateEvent`, `GetEvent`, `ListEvents`, `RetrieveMemoryRecords`, `ListMemoryRecords`, `StartMemoryExtractionJob`, `ListMemoryExtractionJobs`), `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, `ecr:GetAuthorizationToken` |
| Tools Lambda | `wafv2:GetWebACL/UpdateWebACL`, `logs:StartQuery/GetQueryResults/StopQuery/GetLogEvents/FilterLogEvents`, `logs:DescribeLogGroups`, `s3:GetObject/PutObject/DeleteObject/ListBucket/CopyObject`, `cloudwatch:GetMetricStatistics` |
| Gateway | `lambda:InvokeFunction` (tools Lambda), Cedar policy engine ops (`GetPolicyEngine`, `EvaluatePolicy`, `CheckAuthorizePermissions`, `AuthorizeAction`, `PartiallyAuthorizeActions`) |
| Trigger Lambda | `lambda:InvokeFunction` (runner), `s3:PutObject` (markers) |
| Runner Lambda | `bedrock-agentcore:InvokeAgentRuntime` (supervisor only), `s3:PutObject` (markers) |
| Healthcheck Lambda | `s3:ListBucket`, `s3:GetObject`, `s3:DeleteObject` (markers), `sns:Publish` |

> Supervisor invokes the tools Lambda **through the Gateway** (`bedrock-agentcore:InvokeGateway`), not directly. Only the Gateway role has `lambda:InvokeFunction` on the tools Lambda. The Supervisor publishes to SNS directly, so the tools Lambda does not need `sns:Publish`.

## Cost Estimate

### AWS Services Used

| Service | Role in Stack | Pricing Model |
|---------|---------------|---------------|
| **Amazon Bedrock** | LLM inference (Claude models) | Per-token (input/output) |
| **AgentCore Runtime** | Agent container execution (4 agents, 30 s–3 min each) | $0.0895/vCPU-hour + $0.00945/GB-hour |
| **AgentCore Gateway** | MCP tool routing to Lambda | $0.005 / 1K invocations |
| **AgentCore Memory** | Cross-session trend storage | $0.25/1K events + $0.75/1K records/month + $0.50/1K retrievals |
| **AgentCore Policy** | Cedar authorization | $0.000025 / auth request |
| **AWS Lambda** | Tools (20 tools) + trigger + runner + healthcheck | Per-request + GB-second |
| **CloudWatch Logs Insights** | WAF log queries (~100 queries/run) | $0.005 / GB scanned per query |
| **Amazon ECR** | Container images (4 agents) | $0.10 / GB-month |
| **Amazon S3** | Tool schemas + findings + run markers + ET blocklist cache | ~$0.023 / GB-month |
| **Amazon SNS** | Report + alert email delivery | $2.00 / 100K emails |
| **EventBridge Scheduler** | Daily trigger (A) + healthcheck (B) | $1.00 / 1M invocations |

### Bedrock Model Pricing (dominant cost)

| Agent | Model | Input (per MTok) | Output (per MTok) | Est. per Run |
|-------|-------|-----------------|-------------------|--------------|
| Supervisor | Claude Sonnet 4.6 | $3 | $15 | ~$0.11 |
| Analyzer | Claude Opus 4.6 | $5 | $25 | ~$0.15 |
| Validator | Claude Opus 4.6 | $5 | $25 | ~$0.18 |
| Executor | Claude Opus 4.6 | $5 | $25 | ~$0.13 (when invoked) |
| **Total Bedrock** | | | | **~$0.44-0.57 / run** |

> Note: Analyzer's programmatic phase (~24 tool calls) uses zero Bedrock tokens — only the synthesis phase invokes the LLM. Executor is skipped when 0 rule changes needed.

**AgentCore Runtime calculation**: ~5.5 min/run × (1 vCPU × $0.0895/hr + 1 GB × $0.00945/hr) / 60 = ~$0.009/run × 30 = ~$0.27/month.

**CW Logs Insights query breakdown** (~100 queries/run):
- `query_false_positive_signals`: 8 sub-queries x 9 IPs = 72
- `investigate_ip_deep`: 8 sub-queries x ~2 candidates = 16
- `scan_bypass_candidates`: 3, `query_bot_intelligence`: 4, `query_label_distribution`: 2
- `query_per_domain`: 1-4, `query_non_terminating_rules`: 1
- `query_waf_summary`: 1, `query_top_blocked`: 1
- Validator spot-checks: ~2-5 additional

### Monthly Cost (1 daily run = 30 runs/month)

| Category | Monthly Est. | Notes |
|----------|-------------|-------|
| Bedrock LLM tokens | **~$14-17** | 3-4 agents x 30 runs |
| AgentCore Runtime | ~$0.3 | ~5.5 min/run x 30 runs |
| AgentCore Gateway | ~$0.01 | ~600 tool invocations/month |
| AgentCore Memory | ~$0.03 | ~30 events + 30 records + 30 retrievals/month |
| CloudWatch Logs Insights | **varies** | ~100 queries/run x log_volume_GB x $0.005 x 30 days |
| ECR storage | ~$0.16 | 4 images x ~400 MB |
| Lambda / SNS / S3 / EventBridge | ~$0 | Within free tier for this usage |

**CW Logs Insights is traffic-dependent** — this is the variable cost driver:

| Daily WAF Log Volume | Queries/Run | Monthly CW Logs Cost | Total Monthly |
|---------------------|-------------|---------------------|---------------|
| ~1 MB (this project, ~300 req/day) | 100 | **~$0.02** | ~$15 |
| 100 MB (~50K req/day) | 100 | **~$1.5** | ~$16 |
| 1 GB (~500K req/day) | 100 | **~$15** | ~$30 |
| 5 GB (~2.5M req/day) | 100 | **~$75** | ~$90 |

### Cost Optimization Applied

| Technique | Saving |
|-----------|--------|
| Supervisor publishes SNS directly (no separate reporter agent) | No extra runtime or LLM tokens for reporting |
| Sonnet 4.6 for Supervisor (routing only) | 1.7x cheaper than Opus |
| Programmatic data collection (Analyzer Phase 1) | Eliminates ~10K redundant input tokens/run |
| Skill separation (no re-query in LLM phase) | ~30% token reduction in Analyzer |
| Executor skip when 0 changes | Saves 1 Opus invocation on clean runs |
| AgentCore active-consumption billing | Pay only during execution, not idle time |

## License

See [LICENSE](LICENSE).
