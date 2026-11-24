# WAF Report Agent — Complete System Specification

> **Goal**: This document is a complete specification that enables any developer (or AI coding agent) to implement the entire multi-agent WAF security operations system from scratch. It defines architecture, agent behavior, tool interfaces, query templates, data flow, and infrastructure.

---

## 1. Architecture Overview

### 1.1 System Components

```
Control plane (fire-and-forget with independent health check):

  EventBridge Scheduler A (cron 0 8 * * ? *  SGT, retries=0)
      → Lambda "trigger" (60s, retries=0)
          - generate run_id
          - S3 PUT markers/{date}/{run_id}.json  {status:"started"}
          - lambda.invoke("runner", InvocationType=Event)  (async)
              → Lambda "runner" (900s, boto3 read_timeout=850, retries=0)
                  → invoke_agent_runtime(Supervisor, sync)

  EventBridge Scheduler B (cron 15 8 * * ? *  SGT, retries=0)
      → Lambda "healthcheck" (60s)
          - list markers/{today}/, alert on status="started" > 12 min
          - purge markers older than 7 days

Data plane (runs inside Supervisor):

  Supervisor Runtime (Claude Sonnet 4.6)
      → Analyzer Runtime (Claude Opus 4.6)
      → list_pending_findings (S3 external findings via Gateway)
      → Validator Runtime (Claude Opus 4.6)
      → Executor Runtime (Claude Opus 4.6)  [skipped if 0 changes]
      → archive_processed_findings
      → ★ S3 IDEMPOTENCY CLAIM
         PutObject markers/report-sent-{date}.json with IfNoneMatch:"*"
         - success → SNS publish (exactly once) + mark run "completed"
         - PreconditionFailed → zombie session, skip publish silently
```

### 1.2 Agent Roster (4 agents)

| Agent | Model | Role | Tools |
|-------|-------|------|-------|
| **Supervisor** | Claude Sonnet 4.6 | Pipeline orchestration, report delivery | Gateway MCP (S3/datetime) + sub-agent invocations |
| **Analyzer** | Claude Opus 4.6 | Hybrid analysis: programmatic data collection + LLM recommendations | 16 read/analysis tools (Cedar-allowed; no WAF write, no S3 findings tools) |
| **Validator** | Claude Opus 4.6 | Independent verification of Analyzer recommendations | 6 tools (Cedar-allowed): query_waf_summary, query_top_blocked, run_custom_waf_query, query_false_positive_signals, investigate_ip_deep, current_datetime |
| **Executor** | Claude Opus 4.6 | WAF rule change proposals (dry_run mode) | get_web_acl, update_web_acl_rules, current_datetime |

> **Note**: There is no separate reporter agent. Supervisor sends the report directly via boto3 SNS after pipeline completion.
>
> **Tool access is enforced, not advisory.** The Gateway policy engine runs in `ENFORCE` mode (default deny). Each runtime role may call only the tools in its `infra/policies/<agent>.cedar.tftpl` (Supervisor: current_datetime, list_pending_findings, archive_processed_findings).

### 1.3 Infrastructure Stack

| Component | Service | Purpose |
|-----------|---------|---------|
| Agent containers | Amazon Bedrock AgentCore Runtime (ARM64 Docker) | Run agent code + SDK |
| Tool routing | AgentCore Gateway (MCP protocol) | Routes tool calls to Lambda |
| Tools backend | AWS Lambda (single function, 20 tools) | Query WAF logs, manage rules, S3 findings |
| Log queries | CloudWatch Logs Insights | WAF log analysis |
| Metrics | CloudWatch Metrics (AWS/WAFV2) | Volume anomaly detection |
| Reports | Amazon SNS → Email | Daily report delivery |
| External findings | Amazon S3 (findings bucket) | Pentest results, manual findings |
| Trend memory | AgentCore Memory (semantic + episodic) | Cross-session analysis patterns |
| Authorization | AgentCore Policy (Cedar, `ENFORCE`) | Per-agent tool access (IAM role match) + block non-dry-run writes |
| Scheduling | EventBridge Scheduler | Daily trigger |
| IaC | Terraform | All infrastructure |

---

## 2. Pipeline Flow (Detailed)

### 2.1 Full Sequence

```
Control plane (fire-and-forget)
──────────────────────────────
T=0:00  EventBridge Scheduler A fires "waf-report-daily-scan"
        → aws-sdk:lambda:invoke universal target
        → Lambda "waf-report-trigger" (async, InvocationType=Event)

T=0:00  trigger Lambda:
          run_id = uuid4()
          marker_key = "markers/{YYYY-MM-DD}/{run_id}.json"
          S3 PUT {status:"started", started_at, trigger_request_id}
          lambda.invoke("waf-report-runner", InvocationType=Event, payload={run_id, marker_key, ...})
          return  (Lambda exits in <2 s)

T=0:00  runner Lambda starts (async):
          boto3 Config(retries={max_attempts:1}, read_timeout=850)
          invoke_agent_runtime(SupervisorArn, sync)  ← blocks until pipeline completes

Data plane (Supervisor pipeline, ~3-10 min)
───────────────────────────────────────────
1. Supervisor receives payload {run_id, marker_key, lookback_hours, dry_run, timestamp}
2. Supervisor LLM orchestrates via tools:
   a. current_datetime → accurate report timestamp
   b. invoke_analyzer(log_group, lookback_hours) → WAF analysis JSON
   c. list_pending_findings → S3 external findings
   d. Merge WAF + external findings
   e. invoke_validator(merged findings, web_acl_arn) → validation results
   f. IF validator confirms rule changes needed:
        invoke_executor(validated findings, web_acl_arn, dry_run=true)
      ELSE: skip executor entirely
   g. archive_processed_findings → move S3 files to processed/
   h. Output: structured plaintext report (email-ready)
3. Supervisor CODE (post-LLM):
   a. _clean_for_email(pipeline_output) → strip markdown artifacts
   b. Detect severity from the report's `Status:` line (CRITICAL / ACTION_REQUIRED→HIGH / HEALTHY, default INFO)
   c. ★ IDEMPOTENCY CLAIM
      S3 PutObject markers/report-sent-{YYYY-MM-DD}.json with IfNoneMatch:"*"
        - PreconditionFailed (SlotAlreadyClaimed) → mark run as
          "skipped_duplicate" and exit silently (zombie session)
        - Success → proceed
   d. boto3 SNS publish (exactly-once, programmatic)
   e. S3 PUT marker_key {status:"completed", message_id, severity}
4. runner Lambda returns; if Lambda died at 900 s, marker stays "started"
   for healthcheck to catch

Health check plane (independent)
────────────────────────────────
T=0:15  EventBridge Scheduler B fires "waf-report-daily-healthcheck"
        → Lambda "waf-report-healthcheck" (sync, retries=0)

        healthcheck Lambda:
          list_objects_v2(prefix="markers/{today}/")
          for each marker:
            status="completed"          → OK
            status="started" ∧ age >12m → PIPELINE TIMEOUT
                                          → SNS publish alert
                                          (subject: "WAF Pipeline Timeout — {date} — {run_id}")
          purge markers older than 7 days
```

### 2.2 Analyzer Internal Phases

```
Phase 1: Programmatic Data Collection (_collect_raw_data)
├── query_waf_summary → traffic_overview
├── query_top_blocked (limit 20) → top blocked IPs
├── query_false_positive_signals (×9 IPs) → pre-classified verdicts
├── check_volume_anomaly → week-over-week comparison
├── scan_bypass_candidates → suspicious allowed traffic
├── investigate_ip_deep (auto for candidates > threshold)
│   └── Includes: JA4, User-Agents, URIs, non-terminating rules
├── query_bot_intelligence → bot categories, AI bots, flags
├── query_label_distribution → WAF label aggregation
├── query_per_domain → Host header breakdown (multi-domain)
├── query_non_terminating_rules → COUNT rules + downstream deps
└── enrich_ip_reputation (×5 IPs) → AbuseIPDB + ET blocklist

Phase 2: LLM Analysis (recommendations only)
├── Receives ALL Phase 1 data as input (NOT allowed to re-query)
├── Assesses bypass threat levels from deep_profile data
├── Identifies COUNT→BLOCK promotion candidates
├── Flags per-domain attack concentration
├── Generates specific, actionable recommendations
└── Returns structured JSON

Phase 3: Merge (_merge_with_raw_data)
├── Raw data values OVERRIDE any LLM-generated numbers
├── FP verdicts from Phase 1 are authoritative
├── LLM can override verdict ONLY with explicit override_reasoning field
└── Final output: merged JSON with raw data + LLM recommendations
```

### 2.3 Data Passing Rules

- Supervisor passes Analyzer output **VERBATIM** to Validator (no summarization)
- Supervisor's final output is a **plaintext report** (not JSON) for email delivery
- Analyzer LLM receives raw data and must NOT modify numbers
- Validator can run spot-check queries to verify Analyzer claims

### 2.4 Reliability Model — Why Every Retry Knob Is Zero

The pipeline is **daily** and **idempotent by date**. A missed run is recovered by the next day's run; a duplicated run would send the report twice. Every layer therefore turns retries off, and exactly-once delivery is enforced by a single S3 idempotency claim.

| Layer | Retry setting | Why |
|-------|---------------|-----|
| EventBridge Scheduler A (→ trigger) | `retry_policy.maximum_retry_attempts = 0` | Async fire-and-forget. If Lambda invoke fails, next day's schedule will run. |
| EventBridge Scheduler B (→ healthcheck) | `retry_policy.maximum_retry_attempts = 0` | Alert failure is acceptable — schedule fires again tomorrow. |
| Lambda trigger — event invoke config | `maximum_retry_attempts = 0` | Trigger is 60 s bookkeeping; if it fails, no pipeline runs, healthcheck alerts silence. |
| Lambda runner — event invoke config | `maximum_retry_attempts = 0` | Lambda's async default is 2 retries; a retry would start a second pipeline run. |
| Lambda runner — boto3 client | `retries={"max_attempts": 1}`, `read_timeout=850` | A client-side retry after a read timeout would start a second AgentCore session. `max_attempts=1` disables SDK retries; `read_timeout=850` keeps the call within the 900 s Lambda limit. |
| Lambda healthcheck — boto3 client | `retries={"max_attempts": 3, "mode": "standard"}` | Healthcheck is idempotent (read-only S3 + single SNS publish); safe to retry. |
| Supervisor SNS publish | atomic S3 `IfNoneMatch:"*"` claim on `markers/report-sent-{date}.json` | An AgentCore session keeps running server-side after the runner Lambda ends and can still reach the publish step. The S3 claim lets only the first session publish. |

**Idempotency claim implementation** (in Supervisor code, immediately before `sns.publish`):
```python
claim_key = f"markers/report-sent-{date.today().isoformat()}.json"
try:
    s3.put_object(Bucket=findings_bucket, Key=claim_key,
                  Body=claim_body, IfNoneMatch="*")
except s3.exceptions.ClientError as e:
    if e.response["Error"]["Code"] in ("PreconditionFailed", "ConditionalRequestConflict"):
        # Another session already claimed today's slot — exit silently
        return {"status": "skipped_duplicate", "run_id": run_id}
    raise
# Only reached by the first winner — safe to publish
sns.publish(TopicArn=sns_topic, Subject=subject, Message=report_body)
```

The healthcheck alert exists to catch the case where BOTH the runner Lambda died AND the AgentCore session got stuck (rare but possible). In that scenario the marker stays "started" past 12 min and an alert email fires, but no duplicate WAF report goes out.

---

## 3. False Positive Classification

### 3.1 Detection Signals

| Signal | Query Method | True Positive Indicator | False Positive Indicator |
|--------|-------------|------------------------|--------------------------|
| **Block Ratio** | IP's BLOCK/(BLOCK+ALLOW) | >75% blocked | <5% blocked |
| **Request Frequency** | bin(1m) peak/avg RPM | >250 req/min | <10 req/min |
| **Multi-rule Trigger** | Distinct terminatingRuleId per IP | ≥3 rules triggered | Single rule only |
| **Match Detail** | terminatingRuleMatchDetails payload | Attack syntax patterns | Normal content |
| **URI Pattern** | Blocked request URI distribution | Attack paths: /.env, /wp-login | Business paths: /api/ |
| **JA4 Fingerprint** | ja4Fingerprint field | Known scanner fingerprint | Browser fingerprint |

### 3.2 Deterministic Verdict Logic (Lambda-side)

The Lambda `query_false_positive_signals` tool applies these rules in **priority order** (first match wins). The numbers are the defaults of `DEFAULT_THRESHOLDS` in `lambda/tools_handler.py`; each can be overridden with Terraform `detection_thresholds`.

| # | Condition | Verdict | Confidence |
|---|-----------|---------|------------|
| 1 | Any matchedData payload matches an attack pattern (`_ATTACK_PATTERNS`: SQLi, XSS, path traversal, shell/command injection, scanner paths such as `/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`, `/actuator`) | TRUE_POSITIVE | HIGH |
| 2 | **Every** inspected matchedData payload looks benign AND `block_ratio < fp_attacker_block_ratio` (0.75) | LIKELY_FP | HIGH if `block_ratio < fp_benign_high_conf_ratio` (0.25), else MEDIUM |
| 3 | `block_ratio > 0.75` AND `rules_triggered >= 3` | TRUE_POSITIVE | HIGH |
| 4 | `block_ratio > 0.90` AND `rules_triggered >= 2` | TRUE_POSITIVE | HIGH |
| 5 | `block_ratio > 0.75` AND `peak_rpm > 250` | TRUE_POSITIVE | MEDIUM |
| 6 | `block_ratio < 0.05` AND `rules_triggered <= 3` | LIKELY_FP | MEDIUM; HIGH if the blocked URIs are among the site's popular allowed URIs and the IP's country is among the top countries |
| 7 | allow:block ratio > 10 AND `peak_rpm < 10` AND exactly 1 rule | LIKELY_FP | MEDIUM (HIGH under the same popular-URI/top-country condition) |
| — | otherwise | UNDETERMINED | LOW |

**"Looks benign" (rule 2)** is deliberately narrow: the payload must match a name/word pattern (`_FP_PATTERNS`: names with an apostrophe such as `O'Brien`, Title Case names, plain letters/spaces/apostrophes/hyphens up to 30 chars) AND contain none of the `_SUSPICIOUS_TOKENS` (SQL/shell/XSS keywords such as `select`, `union`, `admin`, `root`, `script`, `cmd`, `or`, `and`). Single lowercase words, IP literals and URLs are **not** treated as benign because an attacker can produce them trivially. If any inspected payload is neither attack nor benign, rule 2 does not apply.

**Output**: `{ip, verdict, confidence, allow_count, block_count, block_ratio, peak_rpm, rules_triggered, match_detail_attack, match_detail_fp, matched_payloads, uri_in_popular_paths, country_in_top_customers}`.

**Input handling**: `ip` must parse as an IPv4/IPv6 address (otherwise the call fails) because it is interpolated into Logs Insights queries. A Logs Insights query that fails, is cancelled or times out raises an error instead of returning no rows.

### 3.3 Sub-queries per IP (8 queries)

```sql
-- 1. Action breakdown (block_ratio, allow_count, block_count)
filter httpRequest.clientIp = '{ip}'
| stats count(*) as hits by action

-- 2. Peak RPM
filter httpRequest.clientIp = '{ip}'
| stats count(*) as hits by bin(1m)
| stats max(hits) as peak_rpm, avg(hits) as avg_rpm

-- 3. Rules triggered (non-ALLOW)
filter httpRequest.clientIp = '{ip}' and action != 'ALLOW'
| stats count(*) as hits by terminatingRuleId | sort hits desc | limit 10

-- 4. Matched data extraction (attack/benign classification)
filter httpRequest.clientIp = '{ip}' and action = 'BLOCK'
  and @message like '"terminatingRuleMatchDetails":[{'
| fields @message | limit 5

-- 5. Blocked URI distribution
filter httpRequest.clientIp = '{ip}' and action = 'BLOCK'
| stats count(*) as hits by httpRequest.uri | sort hits desc | limit 10

-- 6. Site-wide popular allowed URIs (for uri_in_popular_paths)
filter action = 'ALLOW'
| stats count(*) as hits by httpRequest.uri | sort hits desc | limit 20

-- 7. Site-wide top countries (for country_in_top_customers)
stats count(*) as hits by httpRequest.country | sort hits desc | limit 10

-- 8. This IP's country
filter httpRequest.clientIp = '{ip}'
| stats count(*) as hits by httpRequest.country | limit 1
```

---

## 4. Bypass Detection

### 4.1 Proactive Bypass Scan

Detect malicious traffic in ALLOW logs that evades WAF rules:

| Category | Condition | Interpretation |
|----------|-----------|----------------|
| **High URI Diversity** | ALLOW + unique_uris > 50 (`bypass_uri_diversity`; excl. static assets, excl. verified bots) | Crawler/scraper |
| **Endpoint Hammering** | ALLOW + requests > 200 (`bypass_hammer_min_total`) + unique_uris < 10 (`bypass_hammer_max_uris`) | DDoS or brute force |
| **Unclassified Data Center** | ALLOW + `known_bot_data_center` label, not verified/unverified bot, requests > 50 (`bypass_datacenter_min_total`) | Automation from hosting providers |

Static asset exclusion: `\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)` on the request URI.

`scan_bypass_candidates` returns at most 10 IPs per category. The Analyzer runs `investigate_ip_deep` for candidates whose request count reaches `min(max(1% of allowed traffic, 20), 100)` (`DEEP_INVESTIGATION_PCT`, `DEEP_INVESTIGATION_MIN`, `DEEP_INVESTIGATION_MAX`).

### 4.2 IP Deep Investigation (investigate_ip_deep)

8 sub-queries per IP (`ip` is validated as an IP address):

| Analysis Item | Sub-query |
|---------------|-----------|
| Frequency | ALLOW requests: `stats count(*) by bin(1m)` → peak_rpm, avg_rpm |
| Action breakdown | `stats count(*) by action` |
| Country | `stats count(*) by httpRequest.country` (top 1) |
| Bot labels | `bot:category:*` labels → top 5 |
| JA4 Fingerprint | `stats count(*) by ja4Fingerprint` → top 5 |
| User-Agents | `user-agent` header parsed from the raw log → top 5 |
| Top URIs | `stats count(*) by httpRequest.uri` → top 10 |
| Non-terminating rules | `nonTerminatingMatchingRules` rule IDs → top 10 |

Output: `{ip, frequency, actions, country, bot_labels, ja4_fingerprints, user_agents, top_uris, non_terminating_rules}`.

### 4.3 Volume Anomaly Detection

Uses CloudWatch Metrics (AWS/WAFV2 namespace):
- Compare AllowedRequests and BlockedRequests: this week vs last week
- WoW ratio thresholds: normal (<2x), moderate (2-3x), anomalous (>3x) — defaults (`volume_moderate_wow`, `volume_significant_wow`); override via `detection_thresholds`
- ALLOW spike (> `volume_significant_wow`) without proportional BLOCK spike (< `volume_blocked_wow_max`) → `bypass_suspected`

---

## 5. Label & Bot Intelligence

### 5.1 Bot Intelligence Queries (`query_bot_intelligence`, 4 sub-queries)

```sql
-- Bot category distribution (top 10)
filter @message like 'bot:category'
| parse @message /bot:category:(?<category>[^"}\s,]+)/
| stats count(*) as hits by category | sort hits desc | limit 10

-- Verified vs Unverified ratio
filter @message like 'bot-control:bot:'
| stats sum(@message like 'bot:verified') as verified,
        sum(@message like 'bot:unverified') as unverified

-- AI bots: names and action
filter @message like 'bot:category:ai'
| parse @message /bot:name:(?<bot_name>[^"}\s,]+)/
| stats count(*) as hits by bot_name, action | sort hits desc

-- URIs requested by AI bots (top 20)
filter @message like 'bot:category:ai'
| stats count(*) as hits by httpRequest.uri | sort hits desc | limit 20
```

Output: `{categories_top10, verified_ratio, ai_bot_stats: {bots, top_uris}}`.

### 5.2 Label Distribution (`query_label_distribution`, 2 sub-queries)

```sql
-- Attack rule label distribution (blocked requests)
filter action = 'BLOCK'
| parse @message /awswaf:managed:aws:(?<rule_group>[^:]+):(?<rule_name>[^"}\s,]+)/
| stats count(*) as hits by rule_group, rule_name
| sort hits desc | limit 20

-- Bot Control signal labels (suspicious indicators)
filter @message like 'bot-control:signal:'
| parse @message /signal:(?<signal>[^"}\s,]+)/
| stats count(*) as hits by signal | sort hits desc
```

Output: `{attack_types: [{group, rule, hits}], signals: [{signal, hits}]}`.

---

## 6. Additional Analysis Capabilities

### 6.1 Per-Domain Breakdown (query_per_domain)

For multi-domain WebACLs, extract Host header to identify per-domain traffic patterns:

```sql
parse @message /"name":"[Hh]ost","value":"(?<host>[^"]+)"/
| stats count(*) as total,
        sum(action='BLOCK') as blocked,
        sum(action='ALLOW') as allowed
  by host
| sort total desc | limit 20
```

For up to 3 domains with a block rate above 10% (`domain_drilldown_block_rate`, `domain_drilldown_count`) a second query returns the top 5 terminating rules. The Host header is attacker-controlled, so the drill-down runs only for hostnames made of `[A-Za-z0-9.-]`.

### 6.2 Non-Terminating Rules (query_non_terminating_rules)

Track COUNT-mode rules and detect downstream BLOCK dependencies:

```sql
-- COUNT rule hits from WAF logs
filter @message like '"nonTerminatingMatchingRules":[{'
| parse @message /nonTerminatingMatchingRules.*?"ruleId":"(?<rule>[^"]+)"/
| stats count(*) as match_count by rule
| sort match_count desc | limit 20
```

**Downstream BLOCK detection**: Fetches WebACL config via `get_web_acl`, then for each COUNT rule:
- Check if it produces labels (most managed rules do)
- Check if any downstream BLOCK rule consumes that label in a scope-down statement
- If YES → "label_sourced" (safe to keep as COUNT, downstream handles blocking)
- If NO and `match_count > promotion_min_matches` (default 10) → "promotion_candidate" (COUNT with no downstream action = gap)

### 6.3 IP Reputation Enrichment (enrich_ip_reputation)

Two sources:

**AbuseIPDB** (REST API, requires `ABUSEIPDB_API_KEY` env var):
```
GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90
Headers: Key: {api_key}, Accept: application/json
Returns: abuseConfidenceScore (0-100), isp, domain, usageType, totalReports
```
- Free tier: 1000 checks/day
- Graceful degradation if key not configured (returns null)

**Emerging Threats Blocklist** (Proofpoint, no API key needed):
```
URL: https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
Cache: S3 {findings_bucket}/threat-intel/et-blocklist.txt (refreshed when older than 24 h; stale cache used if refresh fails)
Lookup: exact IP / CIDR membership (never substring); et_listed = null when the list cannot be obtained
```

### 6.4 JA4 Fingerprint Analysis

`ja4Fingerprint` field in WAF logs identifies TLS client characteristics:
- Format: `t{version}{ciphers}_{extensions}_{alpn}` (e.g., `t13d1314h2_f57a...`)
- Same JA4 across many IPs → botnet/distributed scanner
- Known scanner JA4s can be blocklisted
- Queried in `investigate_ip_deep`: `fields ja4Fingerprint | stats count(*) by ja4Fingerprint`

---

## 7. Tool Interface Specification (20 tools)

All tools execute in a single Lambda (`waf-report-tools`). The Gateway routes calls by the `_tool` field in the MCP request. Report sending (SNS) is handled directly by Supervisor, not via Lambda.

**Common behavior**
- `region` defaults to the Lambda's `REGION`; `lookback_hours` defaults to `LOOKBACK_HOURS` (24) and is clamped to 1–720.
- Tools that run Logs Insights queries return the result rows as a stringified list unless noted. A failed, cancelled or timed-out query returns an MCP error (`isError: true`) and the query is stopped; it never returns an empty result.
- Tool access per agent is limited by the Cedar policies (see § 1.2).

### 7.1 Analysis Tools

| Tool | Arguments | Returns |
|------|-----------|---------|
| `query_waf_summary` | log_group, lookback_hours, region | `[{total, unique_ips, blocked, allowed, other}]` (one row) |
| `query_top_blocked` | log_group, lookback_hours, region, limit (1–100, default 20) | `[{ip, rule, cnt}]` |
| `query_false_positive_signals` | ip, log_group, lookback_hours, region | `{ip, verdict, confidence, allow_count, block_count, block_ratio, peak_rpm, rules_triggered, match_detail_attack, match_detail_fp, matched_payloads, uri_in_popular_paths, country_in_top_customers}` |
| `scan_bypass_candidates` | log_group, lookback_hours, region | `{candidates: [{category, ip, total, unique_uris}], count}` (`unclassified_datacenter` entries have `total` only) |
| `investigate_ip_deep` | ip, log_group, lookback_hours, region | `{ip, frequency, actions, country, bot_labels, ja4_fingerprints, user_agents, top_uris, non_terminating_rules}` |
| `query_label_distribution` | log_group, lookback_hours, region | `{attack_types: [{group, rule, hits}], signals: [{signal, hits}]}` |
| `query_bot_intelligence` | log_group, lookback_hours, region | `{categories_top10, verified_ratio, ai_bot_stats: {bots, top_uris}}` |
| `check_volume_anomaly` | web_acl_arn, region | `{wow_allowed, wow_blocked, classification, bypass_suspected}` |
| `query_rate_limit_hits` | log_group, lookback_hours, region | `[{ip, rule, cnt}]` for RATE_BASED terminating rules |
| `query_suspicious_patterns` | log_group, lookback_hours, region | `[{ip, cnt, uri_cnt}]` ALLOW traffic above `suspicious_min_requests` / `suspicious_min_uris` |
| `query_per_domain` | log_group, lookback_hours, region | `{domains: [{domain, total, blocked, allowed, block_rate, top_rules?}], count}` |
| `query_non_terminating_rules` | log_group, web_acl_arn, lookback_hours, region | `{non_terminating_rules: [{rule, match_count, has_downstream_block, downstream_rule, promotion_candidate}], total_count, promotion_candidates, label_sourced}` |
| `enrich_ip_reputation` | ip | `{ip, abuseipdb: {score, total_reports, isp, country, is_tor, usage_type, domain} \| {error} \| null, et_listed: true \| false \| null}` |
| `run_custom_waf_query` | query, log_group, lookback_hours, region | Raw Logs Insights rows |

### 7.2 Management Tools

| Tool | Arguments | Returns |
|------|-----------|---------|
| `get_web_acl` | web_acl_arn, region | `{rules, lock_token, capacity}` |
| `update_web_acl_rules` | web_acl_arn, rules_json, region, dry_run | `dry_run` preview, or `{status: "applied", rule_count}`. Rejected unless `WAF_WRITE_ENABLED=true`; `rules_json` is the complete rule list; new/changed rules must be COUNT-only, existing rules cannot be removed or modified, max 5 new rules; the lock token is fetched at apply time (a `lock_token` argument is ignored) |
| `check_coverage_gaps` | web_acl_arn, region | `{gaps: [{gap, recommendation}], rules_count}` (Bot Control, rate-based rule, Anti-DDoS) |

### 7.3 Utility Tools

| Tool | Arguments | Returns |
|------|-----------|---------|
| `current_datetime` | timezone (default: `DEFAULT_TIMEZONE`, Asia/Singapore) | `{datetime, timezone, date, time}` |
| `list_pending_findings` | bucket, prefix (default `findings/pending/`) | `{files: [{file, content}], count}`; `.json/.md/.txt` content truncated to 20,000 chars, PDFs noted only; first page of results (up to 1000 keys) |
| `archive_processed_findings` | bucket, files_json (JSON array of keys) | `{archived: N}`; keys must be under the pending prefix, they are moved to `findings/processed/` |

---

## 8. Agent System Prompts

### 8.1 Supervisor

**Key behaviors**:
- Calls `current_datetime` first for accurate timestamp
- Invokes sub-agents in sequence: analyzer → validator → executor (conditional)
- Passes analyzer output VERBATIM to validator (never summarizes)
- Skips executor if validator approves 0 rule changes
- Final output is **plaintext email report** (not JSON)

**Report template**:
```
═══════════════════════════════════════════
  WAF Daily Security Report
  Date: {date}
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
  Next run: {tomorrow} {next run time from schedule_expression + schedule_timezone}
═══════════════════════════════════════════
```

**Post-LLM programmatic steps**:
1. `_clean_for_email()` — strip markdown artifacts (code fences, bold, headers)
2. Severity detection from the report's `Status:` line (CRITICAL / ACTION_REQUIRED→HIGH / HEALTHY, default INFO) for the email subject
3. `boto3.client("sns").publish()` — exactly once, no LLM involvement

### 8.2 Analyzer

**Key behaviors**:
- Phase 1 is 100% programmatic (no LLM) — `_collect_raw_data()` calls ~24 tools sequentially
- Phase 2 LLM receives all raw data and is PROHIBITED from re-querying
- Phase 2 focuses on: bypass threat assessment, COUNT promotion, recommendations
- Phase 3 `_merge_with_raw_data()` enforces raw data authority over LLM output
- FP verdicts from Lambda are authoritative; LLM override requires `override_reasoning`
- Uses AgentCore Memory for cross-session trend detection

**Tool call budget**: ~24 calls in Phase 1:
- query_waf_summary (1)
- query_top_blocked (1)
- query_false_positive_signals × 9 IPs (9)
- check_volume_anomaly (1)
- scan_bypass_candidates (1)
- investigate_ip_deep × N candidates (variable, ~2)
- query_bot_intelligence (1)
- query_label_distribution (1)
- query_per_domain (1)
- query_non_terminating_rules (1)
- enrich_ip_reputation × 5 IPs (5)

### 8.3 Validator

**Key behaviors**:
- Receives Analyzer output verbatim
- Spot-checks evidence by running independent queries (run_custom_waf_query)
- Assesses application context (is the blocked path a real endpoint?)
- Checks downstream label dependencies before approving COUNT→BLOCK promotions
- Decisions: APPROVE / REJECT / MODIFY / NEEDS_REVIEW
- Confidence threshold configurable (default 0.7)
- NEVER approves broad exceptions (path=/* is DANGEROUS)

### 8.4 Executor

**Key behaviors**:
- Receives validated findings only
- First calls `get_web_acl` to check current state + capacity
- NEVER creates rules in BLOCK mode on first deploy — always COUNT
- Prefers rate-based rules for volumetric attacks
- Respects dry_run mode: if True, only proposes changes (JSON output)
- Outputs structured actions: `[{type: add|modify|skip, rule_name, reason, mode}]`
- Skipped entirely when validator approves 0 rule changes

---

## 9. Infrastructure Implementation

### 9.1 Terraform Resources

```hcl
# ECR repositories (4 agents)
resource "aws_ecr_repository" "agents" {
  for_each = toset(["supervisor", "analyzer", "validator", "executor"])
}

# Docker build + push (triggered by handler.py hash change)
resource "null_resource" "docker_push" {
  for_each = toset(["supervisor", "analyzer", "validator", "executor"])
  triggers = { code_hash = filesha256("../agents/${each.key}/handler.py") }
}

# AgentCore Runtimes (4)
resource "aws_bedrockagentcore_agent_runtime" "this" {
  for_each = { supervisor, analyzer, validator, executor }
  # DEPLOY_VERSION env var forces container refresh on code change
  environment { DEPLOY_VERSION = filesha256("../agents/${each.key}/handler.py") }
}

# AgentCore Gateway + Lambda Target
resource "aws_bedrockagentcore_gateway" "this" { ... }
resource "aws_bedrockagentcore_gateway_target" "lambda" {
  # Tool schema from S3 — target recreation on schema change
  lifecycle { replace_triggered_by = [aws_s3_object.tool_schemas.etag] }
}

# Tools Lambda (single function, 20 tools, invoked via Gateway)
resource "aws_lambda_function" "tools" {
  function_name = "waf-report-tools"
  handler = "tools_handler.handler"
  timeout = 120
  environment {
    FINDINGS_BUCKET, ABUSEIPDB_API_KEY (sensitive), REGION, DEFAULT_TIMEZONE,
    WAF_WRITE_ENABLED (var.allow_waf_write), WAF_THRESHOLDS (var.detection_thresholds)
  }
}

# Control-plane Lambdas (3 additional Lambdas) — see § 2.4 for retry lockdown
resource "aws_lambda_function" "trigger" {
  function_name = "waf-report-trigger"
  handler = "trigger_handler.handler"
  timeout = 60
  environment { REGION, FINDINGS_BUCKET, RUNNER_FUNCTION_NAME, LOOKBACK_HOURS, DRY_RUN }
}
resource "aws_lambda_function" "runner" {
  function_name = "waf-report-runner"
  handler = "runner_handler.handler"
  timeout = 900   # boto3 read_timeout = 850 (in code)
  environment { REGION, FINDINGS_BUCKET, SUPERVISOR_RUNTIME_ARN, LOOKBACK_HOURS, DRY_RUN }
}
resource "aws_lambda_function" "healthcheck" {
  function_name = "waf-report-healthcheck"
  handler = "healthcheck_handler.handler"
  timeout = 60
  environment { REGION, FINDINGS_BUCKET, SNS_TOPIC_ARN, HANG_THRESHOLD_MINUTES, RUNNER_FUNCTION_NAME }
}

# Async retry lockdown on trigger + runner
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

# SNS Topic + S3 Findings/Markers Bucket + Cedar Policy Engine + Memory
```

### 9.2 Environment Variables per Agent

| Agent | Key Env Vars |
|-------|-------------|
| **Supervisor** | `MODEL_ID`, `REGION`, `GATEWAY_URL`, `ANALYZER_RUNTIME_ARN`, `VALIDATOR_RUNTIME_ARN`, `EXECUTOR_RUNTIME_ARN`, `WEB_ACL_ARN`, `LOG_GROUP`, `SNS_TOPIC_ARN`, `FINDINGS_BUCKET`, `SCHEDULE_EXPRESSION`, `SCHEDULE_TIMEZONE` |
| **Analyzer** | `MODEL_ID`, `REGION`, `GATEWAY_URL`, `WEB_ACL_ARN`, `LOG_GROUP`, `MEMORY_ID`; optional `FP_SIGNAL_MAX_IPS` (9), `REPUTATION_MAX_IPS` (5), `DEEP_INVESTIGATION_PCT` (0.01), `DEEP_INVESTIGATION_MIN` (20), `DEEP_INVESTIGATION_MAX` (100) |
| **Validator** | `MODEL_ID`, `REGION`, `GATEWAY_URL`, `WEB_ACL_ARN`, `LOG_GROUP` (required; no built-in default), `CONFIDENCE_THRESHOLD` (0.7) |
| **Executor** | `MODEL_ID`, `REGION`, `GATEWAY_URL`, `WEB_ACL_ARN` |

Every runtime also receives the entries of Terraform `agent_env_overrides`. `REGION` falls back to `AWS_REGION` / `AWS_DEFAULT_REGION` when unset.

### 9.3 IAM Permissions

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

### 9.4 Docker Image

Shared `Dockerfile` with `ARG AGENT_NAME`:
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

Dependencies: `strands-agents`, `bedrock-agentcore`, `mcp`, `boto3`

---

## 10. MCP Gateway Protocol

### 10.1 Tool Call Flow

```
Agent (Strands SDK) → MCPClient → streamable_http → Gateway → Lambda
```

### 10.2 Gateway Routing

The Lambda receives the full MCP tool call payload. Routing uses the `_tool` field:
```python
# Lambda handler dispatches by _tool field
def handler(event, context):
    tool_name = event.get("_tool", "")
    if tool_name == "query_waf_summary": return _query_waf_summary(event)
    elif tool_name == "query_top_blocked": return _query_top_blocked(event)
    ...
```

### 10.3 Programmatic MCP Calls (Analyzer Phase 1)

```python
# Direct MCP call outside LLM (no token cost)
result = mcp_client.call_tool_sync(
    tool_use_id=str(uuid.uuid4()),
    name="query_waf_summary",
    arguments={"log_group": log_group, "lookback_hours": 24, "region": "us-east-1", "_tool": "query_waf_summary"}
)
# Result: {"content": [{"type": "text", "text": "{\"total\": 272, ...}"}]}
```

**Critical**: Arguments MUST include `"_tool": tool_name` — Gateway Lambda routes by this field.

### 10.4 Lambda Response Format

```python
# Lambda must return MCP-compatible format
return {
    "content": [{"type": "text", "text": json.dumps(result)}]
}
```

The `"type": "text"` field is REQUIRED — MCP SDK validation rejects responses without it.

---

## 11. Email Report Formatting

### 11.1 Design Principles

- Output goes directly to email (SNS → Email subscription)
- Plain email clients don't render HTML or Markdown
- Use Unicode box drawing characters for structure (═, ─, ▶, •)
- Include real numbers, IPs, and rule names — no vague summaries
- Target 2000-4000 characters

### 11.2 Cleanup Function

```python
def _clean_for_email(text: str) -> str:
    """Strip markdown/JSON artifacts from LLM output."""
    import re
    text = re.sub(r'```[\w]*\n?', '', text)           # code fences
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)      # **bold**
    text = re.sub(r'\*(.+?)\*', r'\1', text)           # *italic*
    text = re.sub(r'^#{1,4}\s+', '', text, flags=re.MULTILINE)  # # headers
    text = re.sub(r'\n{3,}', '\n\n', text)             # excess blank lines
    return text.strip()
```

### 11.3 Severity Detection

```python
severity = "INFO"
m = re.search(r"Status\s*:\s*(\w+)", report_body)   # from the report header line
if m:
    status = m.group(1).upper()
    if status == "CRITICAL":
        severity = "CRITICAL"
    elif status in ("ACTION_REQUIRED", "HIGH"):
        severity = "HIGH"
    elif status == "HEALTHY":
        severity = "HEALTHY"
# Subject: "WAF Daily Security Report — 2026-06-19 — HEALTHY"  (date = container UTC date)
```

---

## 12. Constraints & Design Decisions

### Performance
- Analyzer Phase 1: ~24 sequential tool calls (CWL queries take 1-3s each)
- Total pipeline: ~3-10 minutes (Supervisor's sub-agent call `read_timeout`: 600 s; runner Lambda cap: 900 s)
- FP analysis limited to 9 IPs (cost control vs coverage balance)
- IP reputation limited to 5 IPs (AbuseIPDB free tier: 1000/day)

### Safety
- All WAF changes are dry_run=True. Enforced twice: the tools Lambda refuses writes unless `allow_waf_write=true`, and the Gateway policy engine (`ENFORCE`) forbids `update_web_acl_rules` with `dry_run == false`
- Executor skipped when 0 rule changes — saves Opus invocation
- SNS publish is direct from Supervisor runtime (no Lambda indirection, no LLM access)
- Never deploy rules in BLOCK mode on first application

### Reliability
- Fail-fast: if traffic_overview returns error/zero, Analyzer aborts immediately
- Raw data authority: LLM cannot override numbers from programmatic collection
- Verdict override requires explicit `override_reasoning` field
- Exactly-once report: programmatic SNS publish (not LLM-controlled)

### Cost Optimization
- Supervisor uses Sonnet (cheaper, routing-only role)
- Sub-agents use Opus (complex analysis/validation)
- Programmatic Phase 1 uses zero Bedrock tokens (~24 tool calls for free)
- Supervisor publishes SNS directly (no reporter agent, no extra runtime)
- Executor skip saves 1 Opus invocation on clean runs
- Est. $0.44-0.57 per run, ~$15/month at 1 daily run

---

## 13. WAF Log Fields Reference

```
httpRequest.clientIp         — Client IP address
httpRequest.uri              — Request URI path
httpRequest.httpMethod       — HTTP method (GET, POST, etc.)
httpRequest.country          — GeoIP country code (2-letter)
httpRequest.headers          — Array of {name, value} headers
action                       — ALLOW / BLOCK / CAPTCHA / CHALLENGE / COUNT
terminatingRuleId            — Rule that terminated evaluation
terminatingRuleType          — REGULAR / MANAGED_RULE_GROUP / RATE_BASED
terminatingRuleMatchDetails  — Match evidence (SQLi/XSS patterns)
nonTerminatingMatchingRules  — Rules matched in COUNT mode (array)
labels                       — WAF labels array [{name, value}]
ja4Fingerprint               — JA4 TLS client fingerprint
rateBasedRuleList            — Rate-based rules that matched
```

### CloudWatch Metrics

```
Namespace: AWS/WAFV2
Dimensions: WebACL={name}, Rule={rule}, Region={region}
Metrics: AllowedRequests, BlockedRequests, CountedRequests,
         CaptchaRequests, ChallengeRequests
```

---

## 14. File Structure

```
aws-waf-report-agent/
├── agents/
│   ├── Dockerfile               # Shared (ARG AGENT_NAME)
│   ├── requirements.txt         # strands-agents, bedrock-agentcore, mcp, boto3
│   ├── supervisor/handler.py    # Orchestrator + S3 idempotency claim + programmatic SNS + email cleanup
│   ├── analyzer/handler.py      # Phase 1-3 hybrid analysis
│   ├── validator/handler.py     # Independent verification
│   └── executor/handler.py      # Rule change proposals
├── lambda/
│   ├── trigger_handler.py       # EventBridge A → generates run_id, async-invokes runner
│   ├── runner_handler.py        # Async-invoked by trigger, calls invoke_agent_runtime sync
│   ├── healthcheck_handler.py   # EventBridge B (T+15 min) → detects hung markers, emails alerts, purges old markers
│   └── tools_handler.py         # All 20 tools (single Lambda, invoked via Gateway)
├── infra/
│   ├── main.tf                  # All Terraform resources (2 Schedulers, 4 Lambdas, 4 Runtimes, Gateway, Memory, IAM, S3, SNS)
│   ├── variables.tf             # Input variables (includes healthcheck_schedule_expression + healthcheck_hang_threshold_minutes)
│   ├── terraform.tfvars.example # Example config
│   ├── tool_schemas.json        # MCP tool definitions (20 tools)
│   └── policies/                # Cedar policies (per-agent least privilege)
├── docs/
│   ├── ANALYSIS_AGENT_REQUIREMENTS.md    # This file
│   ├── ANALYSIS_AGENT_REQUIREMENTS_ko.md # Korean version
│   ├── pipeline-flow.mmd                 # Mermaid source
│   └── pipeline-flow.svg                 # Rendered diagram
├── scripts/
│   ├── test_run.sh              # Deploy + invoke + verify (quick iteration)
│   ├── check_doc_drift.sh       # CI check — test count in READMEs matches pytest; tfvars.example matches variables.tf; IAM tables cross-check between README and this spec doc
│   └── hooks/
│       ├── pre-commit           # Git pre-commit hook — runs check_doc_drift.sh when relevant files change
│       └── install.sh           # Symlinks scripts/hooks/* into .git/hooks/
├── tests/
│   ├── test_tools.py            # Unit tests (84, fully mocked — no AWS calls)
│   └── test_e2e_agents.py       # E2E integration tests (Analyzer, Validator, Control Plane Lambdas, Memory)
├── pyproject.toml               # Project metadata (dev deps: pytest)
├── LICENSE                      # MIT
├── README.md                    # Quick start guide (English)
└── README.ko.md                 # Quick start guide (Korean)
```
