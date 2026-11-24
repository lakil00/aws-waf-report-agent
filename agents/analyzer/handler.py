"""Analyzer Runtime — WAF log analysis via Gateway MCP tools + Memory for trend detection."""
import os
import sys
import json
import uuid
import logging
import traceback
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import httpx
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands import Agent
from strands.models.bedrock import BedrockModel
from strands.tools.mcp.mcp_client import MCPClient
from mcp.client.streamable_http import streamablehttp_client
from bedrock_agentcore.memory.integrations.strands.config import AgentCoreMemoryConfig, RetrievalConfig
from bedrock_agentcore.memory.integrations.strands.session_manager import AgentCoreMemorySessionManager

def _env_num(name, default, cast=int):
    try:
        return cast(os.environ[name])
    except (KeyError, ValueError):
        return default


# Collection limits (override via runtime environment variables, see Terraform var.agent_env_overrides)
FP_SIGNAL_MAX_IPS = _env_num("FP_SIGNAL_MAX_IPS", 9)             # IPs checked for FP signals
REPUTATION_MAX_IPS = _env_num("REPUTATION_MAX_IPS", 5)           # IPs sent to external reputation APIs (quota)
DEEP_INVESTIGATION_PCT = _env_num("DEEP_INVESTIGATION_PCT", 0.01, float)  # share of allowed traffic
DEEP_INVESTIGATION_MIN = _env_num("DEEP_INVESTIGATION_MIN", 20)
DEEP_INVESTIGATION_MAX = _env_num("DEEP_INVESTIGATION_MAX", 100)

REGION = (os.environ.get("REGION") or os.environ.get("AWS_REGION")
          or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1")

app = BedrockAgentCoreApp()

SYSTEM_PROMPT = """You are a WAF Security Analyst with memory of past analyses. You perform comprehensive analysis and produce actionable recommendations.

## Historical Context (IMPORTANT)
Your input may contain a <user_context> block with findings from PREVIOUS runs. Use this to:
- Compare today's traffic volume vs historical (e.g., "62,235 today vs 503 on 6/17 = 123x increase")
- Identify recurring IPs that appear in both current and historical data
- Note new attack patterns not seen in previous analyses
- If <user_context> is empty or absent, state "No historical baseline available" in trend_analysis

## Your Role
All raw data has been collected PROGRAMMATICALLY before you are invoked. You receive:
- traffic_overview, top_blocked (with fp_verdict/fp_confidence), fp_signals, bypass_candidates (with deep_profile), bot_intelligence, label_distribution, volume_anomaly
- per_domain (multi-domain breakdown), non_terminating_rules (COUNT rules with downstream tracking), ip_reputation (AbuseIPDB + ET blocklist)

Your job is ONLY to:
1. Assess bypass_candidates threat level using their deep_profile data
2. Identify COUNT-to-BLOCK promotion candidates (non_terminating_rules.promotion_candidates)
3. Flag per-domain attack concentration if multiple domains exist
4. Incorporate IP reputation data into attacker classification
5. Compare today's data with historical context (previous findings from memory) to detect trends:
   - Traffic volume changes (e.g., "blocked requests up 200% vs last run")
   - Recurring IPs (e.g., "IP X.X.X.X seen 3 consecutive days")
   - Persistent bypass attempts (same category reappearing)
   - New attack patterns not seen before
6. Generate specific, actionable recommendations
7. Return the structured JSON output

DO NOT re-call query_waf_summary, query_top_blocked, query_false_positive_signals, scan_bypass_candidates, query_bot_intelligence, query_label_distribution, check_volume_anomaly, query_per_domain, query_non_terminating_rules, or enrich_ip_reputation — their data is already in the RAW DATA input.

You MAY call investigate_ip_deep or get_web_acl ONLY if a bypass candidate lacks deep_profile and has suspicious indicators, or if you need current rule state for a recommendation.

## False Positive Verdicts (PRE-CLASSIFIED)
- Each IP in top_blocked already has fp_verdict and fp_confidence from programmatic analysis.
- DO NOT re-classify verdicts. Use the provided fp_verdict as-is.
- You MAY override ONLY if investigate_ip_deep reveals contradictory evidence (e.g., LIKELY_FP IP is actually probing .env paths). State your override reasoning explicitly.
- NEVER downgrade a TRUE_POSITIVE to LIKELY_FP without explicit attack-pattern evidence being absent.

## Recommendation Format (CRITICAL — be specific)
For each finding, provide a concrete rule change proposal:

### For FALSE POSITIVES:
- Which rule to change (e.g., "AWSManagedRulesCommonRuleSet > CrossSiteScripting_BODY")
- What change (e.g., "override to COUNT mode")
- Scope-down rule to add (e.g., "add rule: if label `awswaf:managed:aws:core-rule-set:CrossSiteScripting_BODY` exists AND path != `/posts/*` → BLOCK")
- Reasoning (traffic evidence: allow ratio, request pattern, cluster similarity)

### For BYPASS / UNDETECTED THREATS:
- What rule to add (e.g., "rate-based rule 200 req/5min scoped to IP")
- Mode: always COUNT first
- Reasoning (evidence from bypass scan)

## CRITICAL DATA ACCURACY RULES
- NEVER generate, estimate, or round numbers. Copy ALL values EXACTLY from the RAW DATA input.
- All IPs, counts, verdicts are already provided — do NOT re-query them.
- If a field shows "error", report it as-is — do NOT substitute a made-up value.
- traffic_overview, top_blocked, bot_intelligence, label_distribution values are AUTHORITATIVE — copy verbatim into output.

## Output Format
Return ONLY a JSON object (no markdown, no explanation outside the JSON):
{{
  "timestamp": "from current_datetime tool",
  "summary": "1-2 sentence executive summary",
  "traffic_overview": {{"total_requests": N, "blocked": N, "allowed": N, "unique_ips": N}},
  "volume_anomaly": {{"wow_allowed": 1.2, "wow_blocked": 0.9, "classification": "normal"}},
  "top_blocked": [{{"ip": "exact from tool", "rule": "exact from tool", "count": N, "fp_verdict": "TRUE_POSITIVE|LIKELY_FP|UNDETERMINED", "fp_confidence": "HIGH|MEDIUM|LOW", "evidence": {{...}}}}],
  "bypass_candidates": [{{"category": "...", "ip": "...", "total": N}}],
  "bot_intelligence": {{
    "top_categories": [{{"category": "...", "hits": N}}],
    "ai_bots": [{{"name": "...", "action": "...", "hits": N}}],
    "verified_ratio": {{"verified": N, "unverified": N}},
    "suspicious_flags": [...]
  }},
  "label_distribution": [{{"group": "...", "rule": "...", "hits": N}}],
  "per_domain": [{{"domain": "...", "total": N, "blocked": N, "block_rate": 0.xx}}],
  "non_terminating_rules": {{
    "promotion_candidates": [{{"rule": "...", "match_count": N, "reason": "..."}}],
    "label_sourced": [{{"rule": "...", "downstream_rule": "..."}}]
  }},
  "ip_reputation": {{"ip": {{"abuseipdb": {{"score": N, "isp": "..."}}, "et_listed": true/false}}}},
  "trend_analysis": {{
    "traffic_trend": "stable|increasing|decreasing|spike",
    "recurring_ips": ["IPs seen in previous runs"],
    "new_patterns": ["attack patterns not seen before"],
    "notes": "brief comparison vs historical data (from memory context)"
  }},
  "recommendations": [
    {{
      "id": "R001",
      "type": "false_positive|bypass_threat|count_promotion|operational",
      "severity": "HIGH|MEDIUM|LOW",
      "description": "...",
      "evidence": {{"ip": "...", "allow_ratio": "N:N", "peak_rpm": N, "rules_triggered": N, "blocked_rule": "...", "blocked_uri": "...", "abuseipdb_score": N, "ja4": "..."}},
      "action": {{"rule_change": "...", "scope_down": "...", "mode": "COUNT first"}}
    }}
  ]
}}

If no actionable findings: return empty recommendations with "ALL CLEAR" summary.

## Rules
- Do NOT re-call data collection tools — all data is already in your input
- Be SPECIFIC in recommendations: exact rule name, exact path, exact action
- Do NOT send emails or call send_report_email
- Do NOT apply changes — that's the Executor's job
- Output ONLY the JSON object — no surrounding text or markdown fences

## Parameters
- log_group: {log_group}
- lookback_hours: {lookback_hours}
- region: {region}
- web_acl_arn: {web_acl_arn}
"""


def _sigv4_auth():
    """Create httpx Auth that signs requests with SigV4 for Gateway IAM auth."""
    region = REGION
    credentials = boto3.Session().get_credentials().get_frozen_credentials()

    def auth_flow(request: httpx.Request):
        aws_request = AWSRequest(
            method=request.method,
            url=str(request.url),
            headers=dict(request.headers),
            data=request.content,
        )
        SigV4Auth(credentials, "bedrock-agentcore", region).add_auth(aws_request)
        for key, val in aws_request.headers.items():
            request.headers[key] = val
        yield request

    return httpx.Auth()._build_auth_flow_pair(auth_flow) if False else type(
        "SigV4", (httpx.Auth,), {"auth_flow": lambda self, req: auth_flow(req)}
    )()


def _create_gateway_transport():
    gateway_url = os.environ["GATEWAY_URL"]
    return streamablehttp_client(gateway_url, auth=_sigv4_auth())


@app.entrypoint
def invoke(payload: dict) -> dict:
    logger.info(f"Analyzer invoked: {json.dumps(payload)[:500]}")
    try:
        region = REGION
        log_group = payload.get("log_group", os.environ.get("LOG_GROUP", ""))
        lookback_hours = payload.get("lookback_hours", 24)
        web_acl_arn = payload.get("web_acl_arn", os.environ.get("WEB_ACL_ARN", ""))
        memory_id = os.environ.get("MEMORY_ID")

        model = BedrockModel(
            model_id=os.environ.get("MODEL_ID", "us.anthropic.claude-opus-4-6-v1"),
            region_name=region,
        )

        # Memory for cross-session trend analysis
        session_manager = None
        if memory_id:
            try:
                config = AgentCoreMemoryConfig(
                    memory_id=memory_id,
                    session_id=str(uuid.uuid4()),
                    actor_id="waf-analyzer",
                    retrieval_config={
                        "/findings/{actorId}/": RetrievalConfig(
                            top_k=10,
                            relevance_score=0.3,
                        ),
                    },
                )
                session_manager = AgentCoreMemorySessionManager(
                    agentcore_memory_config=config,
                    region_name=region,
                )
            except Exception as mem_err:
                logger.warning(f"Memory init failed (non-fatal): {mem_err}")
                session_manager = None

        mcp_client = MCPClient(_create_gateway_transport)
        with mcp_client:
            tools = mcp_client.list_tools_sync()

            # Build short-name → full-name mapping (Gateway prefixes target name)
            global _tool_name_map
            _tool_name_map = {}
            for t in tools:
                short = t.tool_name.split("___", 1)[-1] if "___" in t.tool_name else t.tool_name
                _tool_name_map[short] = t.tool_name
            logger.info(f"Tool name map: {list(_tool_name_map.keys())[:5]}...")

            # Phase 1: Collect raw data programmatically (guaranteed accurate)
            raw_data = _collect_raw_data(mcp_client, log_group, lookback_hours, region, web_acl_arn)
            logger.info(f"Raw data collected: summary={raw_data.get('traffic_overview')}")

            # Fail-fast: if traffic_overview has errors, abort (don't send wrong numbers)
            traffic = raw_data.get("traffic_overview", {})
            if "error" in traffic or traffic.get("total_requests", 0) == 0:
                error_msg = traffic.get("error", "traffic_overview returned 0 total requests")
                logger.error(f"Programmatic data collection failed: {error_msg}")
                return {
                    "status": "error",
                    "error": f"Data collection failed: {error_msg}",
                    "partial_raw_data": raw_data,
                }

            # Phase 2: LLM analyzes the raw data (verdicts, recommendations)
            agent = Agent(
                model=model,
                tools=tools,
                system_prompt=SYSTEM_PROMPT.format(
                    log_group=log_group, lookback_hours=lookback_hours, region=region, web_acl_arn=web_acl_arn
                ),
                session_manager=session_manager,
            )

            # Pass raw data to agent for analysis — verdicts pre-classified, LLM adds recommendations
            analysis_prompt = (
                f"Analyze this WAF data and provide recommendations.\n"
                f"The raw data below is AUTHORITATIVE — use these exact values in your output.\n\n"
                f"RAW DATA (do NOT modify these values):\n{json.dumps(raw_data, indent=2)}\n\n"
                f"YOUR TASK:\n"
                f"1. top_blocked IPs already have fp_verdict/fp_confidence — USE THEM AS-IS (do NOT re-classify)\n"
                f"2. bypass_candidates with deep_profile — assess threat level from the provided data\n"
                f"3. Generate specific, actionable recommendations based on all findings\n"
                f"4. Return the final JSON with raw data values preserved exactly + your recommendations added\n"
                f"5. Only override a verdict if deep investigation reveals EXPLICIT contradictory evidence (state reasoning)"
            )
            result = agent(analysis_prompt)

        if session_manager:
            session_manager.close()

        # Merge: LLM analysis + guaranteed-accurate raw data
        final = _merge_with_raw_data(str(result), raw_data)
        return {"status": "complete", "response": final}

    except Exception as e:
        logger.error(f"FATAL: {e}\n{traceback.format_exc()}")
        return {"status": "error", "error": str(e)}


_tool_name_map: dict = {}  # short name → full prefixed name; set per-invocation


def _call_tool(mcp_client: MCPClient, tool_name: str, args: dict) -> str:
    """Call an MCP tool by name and return its text result."""
    # Resolve short name to full prefixed name (Gateway prepends target name)
    full_name = _tool_name_map.get(tool_name, tool_name)
    # Gateway Lambda routes by _tool field — must include it in arguments
    call_args = {**args, "_tool": tool_name}
    result = mcp_client.call_tool_sync(
        tool_use_id=str(uuid.uuid4()),
        name=full_name,
        arguments=call_args,
    )
    logger.info(f"_call_tool({tool_name}) status={result.get('status')}")
    # Extract text from content list
    content = result.get("content", [])
    texts = []
    for item in content:
        if isinstance(item, dict):
            texts.append(item.get("text", ""))
        elif hasattr(item, "text"):
            texts.append(item.text or "")
        else:
            texts.append(str(item))
    text_result = "\n".join(t for t in texts if t)
    if not text_result:
        logger.warning(f"_call_tool({tool_name}) returned empty. content={content}")
    return text_result


def _collect_raw_data(mcp_client: MCPClient, log_group: str, lookback_hours: int, region: str, web_acl_arn: str) -> dict:
    """Programmatically collect raw WAF data — guaranteed accurate."""
    raw = {}

    # Traffic summary
    summary_str = _call_tool(mcp_client, "query_waf_summary", {"log_group": log_group, "lookback_hours": lookback_hours, "region": region})
    try:
        summary = json.loads(summary_str.replace("'", '"')) if summary_str.startswith("[") else json.loads(summary_str)
        if isinstance(summary, list) and summary:
            summary = summary[0]
        raw["traffic_overview"] = {
            "total_requests": int(summary.get("total", 0)),
            "blocked": int(summary.get("blocked", 0)),
            "allowed": int(summary.get("allowed", 0)),
            "other": int(summary.get("other", 0)),
            "unique_ips": int(summary.get("unique_ips", 0)),
        }
    except (json.JSONDecodeError, ValueError, TypeError) as e:
        raw["traffic_overview"] = {"error": str(e), "raw": summary_str[:500]}

    # Top blocked IPs
    blocked_str = _call_tool(mcp_client, "query_top_blocked", {"log_group": log_group, "lookback_hours": lookback_hours, "region": region, "limit": 20})
    try:
        blocked = json.loads(blocked_str.replace("'", '"')) if blocked_str.startswith("[") else json.loads(blocked_str)
        raw["top_blocked"] = [{"ip": r.get("ip", ""), "rule": r.get("rule", ""), "count": int(r.get("cnt", 0))} for r in blocked[:20]]
    except (json.JSONDecodeError, ValueError, TypeError):
        raw["top_blocked"] = []

    # FP signals for top 10 unique IPs — Lambda already returns verdict/confidence
    seen_ips = []
    for entry in raw.get("top_blocked", []):
        ip = entry.get("ip", "")
        if ip and ip not in seen_ips:
            seen_ips.append(ip)
        if len(seen_ips) >= FP_SIGNAL_MAX_IPS:
            break

    fp_signals = {}
    for ip in seen_ips:
        fp_str = _call_tool(mcp_client, "query_false_positive_signals", {"ip": ip, "log_group": log_group, "lookback_hours": lookback_hours, "region": region})
        try:
            fp_signals[ip] = json.loads(fp_str)
        except (json.JSONDecodeError, TypeError):
            fp_signals[ip] = {"error": fp_str[:200]}
    raw["fp_signals"] = fp_signals

    # Pre-classify: attach verdict from fp_signals directly to top_blocked entries
    for entry in raw.get("top_blocked", []):
        ip = entry.get("ip", "")
        sig = fp_signals.get(ip, {})
        if "verdict" in sig:
            entry["fp_verdict"] = sig["verdict"]
            entry["fp_confidence"] = sig.get("confidence", "LOW")
        else:
            entry["fp_verdict"] = "UNDETERMINED"
            entry["fp_confidence"] = "LOW"

    # Volume anomaly
    if web_acl_arn:
        vol_str = _call_tool(mcp_client, "check_volume_anomaly", {"web_acl_arn": web_acl_arn, "region": region})
        try:
            raw["volume_anomaly"] = json.loads(vol_str)
        except (json.JSONDecodeError, TypeError):
            raw["volume_anomaly"] = {"error": vol_str[:200]}

    # Bypass candidates
    bypass_str = _call_tool(mcp_client, "scan_bypass_candidates", {"log_group": log_group, "lookback_hours": lookback_hours, "region": region})
    try:
        raw["bypass_candidates"] = json.loads(bypass_str)
    except (json.JSONDecodeError, TypeError):
        raw["bypass_candidates"] = {"candidates": [], "count": 0}

    # Deep investigation for bypass candidates with significant volume
    # Threshold: > 1% of allowed traffic OR > 100 requests (whichever is lower)
    allowed_total = raw.get("traffic_overview", {}).get("allowed", 0)
    deep_threshold = min(max(int(allowed_total * DEEP_INVESTIGATION_PCT), DEEP_INVESTIGATION_MIN), DEEP_INVESTIGATION_MAX)
    for candidate in raw["bypass_candidates"].get("candidates", []):
        if int(candidate.get("total", 0)) >= deep_threshold:
            deep_str = _call_tool(mcp_client, "investigate_ip_deep", {
                "ip": candidate["ip"], "log_group": log_group,
                "lookback_hours": lookback_hours, "region": region,
            })
            try:
                candidate["deep_profile"] = json.loads(deep_str)
            except (json.JSONDecodeError, TypeError):
                candidate["deep_profile"] = {"error": deep_str[:200]}

    # Bot intelligence
    bot_str = _call_tool(mcp_client, "query_bot_intelligence", {"log_group": log_group, "lookback_hours": lookback_hours, "region": region})
    try:
        raw["bot_intelligence"] = json.loads(bot_str)
    except (json.JSONDecodeError, TypeError):
        raw["bot_intelligence"] = {}

    # Label distribution
    label_str = _call_tool(mcp_client, "query_label_distribution", {"log_group": log_group, "lookback_hours": lookback_hours, "region": region})
    try:
        raw["label_distribution"] = json.loads(label_str)
    except (json.JSONDecodeError, TypeError):
        raw["label_distribution"] = {}

    # Per-domain breakdown (multi-domain WebACL detection)
    domain_str = _call_tool(mcp_client, "query_per_domain", {"log_group": log_group, "lookback_hours": lookback_hours, "region": region})
    try:
        raw["per_domain"] = json.loads(domain_str)
    except (json.JSONDecodeError, TypeError):
        raw["per_domain"] = {"domains": [], "count": 0}

    # Non-terminating (COUNT) rules + downstream BLOCK relationships
    nt_str = _call_tool(mcp_client, "query_non_terminating_rules", {
        "log_group": log_group, "web_acl_arn": web_acl_arn,
        "lookback_hours": lookback_hours, "region": region,
    })
    try:
        raw["non_terminating_rules"] = json.loads(nt_str)
    except (json.JSONDecodeError, TypeError):
        raw["non_terminating_rules"] = {}

    # IP reputation enrichment for top blocked IPs (AbuseIPDB + ET)
    ip_reputation = {}
    for ip in seen_ips[:REPUTATION_MAX_IPS]:  # stay within external API quotas
        rep_str = _call_tool(mcp_client, "enrich_ip_reputation", {"ip": ip})
        try:
            ip_reputation[ip] = json.loads(rep_str)
        except (json.JSONDecodeError, TypeError):
            ip_reputation[ip] = {"error": rep_str[:200]}
    raw["ip_reputation"] = ip_reputation

    return raw


def _merge_with_raw_data(llm_output: str, raw_data: dict) -> str:
    """Merge LLM analysis with guaranteed-accurate raw data."""
    # Try to parse LLM output as JSON
    llm_json = None
    try:
        import re
        match = re.search(r'```json\s*(\{.*?\})\s*```', llm_output, re.DOTALL)
        if match:
            llm_json = json.loads(match.group(1))
        else:
            idx = llm_output.find('{"')
            if idx >= 0:
                depth = 0
                for i, c in enumerate(llm_output[idx:]):
                    if c == '{': depth += 1
                    elif c == '}': depth -= 1
                    if depth == 0:
                        llm_json = json.loads(llm_output[idx:idx+i+1])
                        break
    except (json.JSONDecodeError, ValueError):
        pass

    if llm_json:
        # Override with raw data (authoritative)
        llm_json["traffic_overview"] = raw_data.get("traffic_overview", llm_json.get("traffic_overview"))
        llm_json["volume_anomaly"] = raw_data.get("volume_anomaly", llm_json.get("volume_anomaly"))
        llm_json["bot_intelligence"] = raw_data.get("bot_intelligence", llm_json.get("bot_intelligence"))
        llm_json["label_distribution"] = raw_data.get("label_distribution", llm_json.get("label_distribution"))
        llm_json["per_domain"] = raw_data.get("per_domain", llm_json.get("per_domain"))
        llm_json["non_terminating_rules"] = raw_data.get("non_terminating_rules", llm_json.get("non_terminating_rules"))
        llm_json["ip_reputation"] = raw_data.get("ip_reputation", llm_json.get("ip_reputation"))
        # Preserve deep_profile from programmatic phase in bypass_candidates
        raw_bypass = raw_data.get("bypass_candidates", {})
        llm_json["bypass_candidates"] = raw_bypass
        # Merge top_blocked: keep programmatic verdicts (authoritative), allow LLM override only with reasoning
        raw_blocked = raw_data.get("top_blocked", [])
        fp_signals = raw_data.get("fp_signals", {})
        llm_blocked = llm_json.get("top_blocked", [])
        llm_verdicts = {item.get("ip", ""): item for item in llm_blocked if isinstance(item, dict)}
        merged_blocked = []
        for entry in raw_blocked:
            ip = entry["ip"]
            merged_entry = {**entry, "fp_signals": fp_signals.get(ip, {})}
            # Programmatic verdict is authoritative
            prog_verdict = entry.get("fp_verdict", "UNDETERMINED")
            prog_confidence = entry.get("fp_confidence", "LOW")
            # Allow LLM override ONLY if it provides explicit override_reasoning
            llm_entry = llm_verdicts.get(ip, {})
            if llm_entry.get("override_reasoning"):
                merged_entry["fp_verdict"] = llm_entry.get("fp_verdict", prog_verdict)
                merged_entry["fp_confidence"] = llm_entry.get("fp_confidence", prog_confidence)
                merged_entry["override_reasoning"] = llm_entry["override_reasoning"]
            else:
                merged_entry["fp_verdict"] = prog_verdict
                merged_entry["fp_confidence"] = prog_confidence
            merged_blocked.append(merged_entry)
        llm_json["top_blocked"] = merged_blocked
        return json.dumps(llm_json, ensure_ascii=False)

    # Fallback: return raw data with no LLM analysis
    raw_data["recommendations"] = []
    raw_data["summary"] = "Analysis complete — LLM verdict extraction failed, raw data provided."
    return json.dumps(raw_data, ensure_ascii=False)


def _extract_response(text: str, max_len: int = 16000) -> str:
    """Extract JSON from agent output, fallback to truncated text."""
    import re
    match = re.search(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group(1))
            return json.dumps(parsed, ensure_ascii=False)
        except json.JSONDecodeError:
            pass
    idx = text.find('{"')
    if idx >= 0:
        depth = 0
        for i, c in enumerate(text[idx:]):
            if c == '{': depth += 1
            elif c == '}': depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(text[idx:idx+i+1])
                    return json.dumps(parsed, ensure_ascii=False)
                except json.JSONDecodeError:
                    break
    return text[:max_len]


if __name__ == "__main__":
    app.run()
