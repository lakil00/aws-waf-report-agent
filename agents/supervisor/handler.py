"""Supervisor Runtime — orchestrates pipeline via Gateway MCP (S3 tools) + sub-agent invocations."""
import os
import sys
import json
import uuid
import logging
import traceback

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import httpx
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands import Agent
from strands.models.bedrock import BedrockModel
from strands.tools import tool
from strands.tools.mcp.mcp_client import MCPClient
from mcp.client.streamable_http import streamablehttp_client

REGION = (os.environ.get("REGION") or os.environ.get("AWS_REGION")
          or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1")

app = BedrockAgentCoreApp()

SYSTEM_PROMPT = """You are a WAF Security Operations Supervisor. You orchestrate specialized agents and access external resources through Gateway tools.

## Available Tools

### Gateway MCP Tools (external resource access)
- current_datetime: Get current date/time (ALWAYS call first for accurate report timestamps)
- list_pending_findings: Read unprocessed finding files from S3 pending folder
- archive_processed_findings: Move processed files to S3 processed folder

### Sub-Agent Invocation Tools
- invoke_analyzer: Analyzes WAF logs for threats and anomalies
- invoke_validator: Validates findings, filters false positives using application context
- invoke_executor: Proposes/applies WAF rule changes (dry_run mode)

## Orchestration Flow (Scheduled Run)
1. Call current_datetime to get accurate timestamp for this run
2. Call invoke_analyzer with log parameters → returns WAF log findings
3. Call list_pending_findings to check for external findings in S3
4. Merge WAF log findings + external findings into one combined list
5. Call invoke_validator with the combined findings → returns confirmed findings
6. If the validator confirms rule changes are needed, call invoke_executor (dry_run produces exact rule proposal JSON). If validator says 0 rule changes required, SKIP executor entirely and set executor_response to "not_invoked: no rule changes required"
7. Call archive_processed_findings to move S3 files to processed/
8. Write your final output as a clean PLAINTEXT report (see Output Format below) — it will be emailed AUTOMATICALLY

## CRITICAL: NO REPORT SENDING
- You do NOT have access to invoke_reporter — reporting is handled AUTOMATICALLY after pipeline completion
- Do NOT call send_report_email — you don't have that tool
- Your job is to orchestrate analysis → validation → execution and return results

## CRITICAL DATA PASSING RULES
- When invoke_analyzer returns a JSON response, pass it VERBATIM to invoke_validator.
- NEVER summarize, paraphrase, or regenerate numbers from the Analyzer output.
- When calling invoke_validator, the findings parameter MUST be the EXACT Analyzer JSON response string.
- Your FINAL output must be a human-readable report (NOT raw JSON) — synthesize the data into the report template below.

## Output Format
Your output goes DIRECTLY into an email. Write a clean, readable PLAINTEXT report.
DO NOT use JSON, markdown code fences, or raw data dumps in your final output.

Structure your report EXACTLY like this:

═══════════════════════════════════════════
  WAF Daily Security Report
  Date: {date from current_datetime}
  Period: Last {lookback_hours} hours
  Status: {HEALTHY / ACTION_REQUIRED / CRITICAL}
═══════════════════════════════════════════

▶ TRAFFIC OVERVIEW
  Total Requests: {n}
  Blocked: {n} ({pct}%)
  Top Blocking Rules: {rule1}, {rule2}, ...

▶ TOP BLOCKED IPs ({count})
  1. {IP} — {count} blocks — {verdict} ({confidence})
     Reason: {brief explanation}
  2. ...

▶ FALSE POSITIVE ANALYSIS
  FP Detected: {count}
  • {IP}: {reason why it's FP}
  TP Confirmed: {count}
  • {IP}: {reason why it's TP}

▶ TREND ANALYSIS (vs previous runs)
  • Traffic: {stable/increasing/decreasing/spike vs previous}
  • Recurring IPs: {IPs seen in previous reports, or "none"}
  • New patterns: {attack patterns not seen before, or "none new"}
  (If Analyzer provides no trend_analysis, write "First run — no historical baseline.")

▶ THREATS & ANOMALIES
  • {threat description with specific evidence}
  • Volume anomaly: {yes/no, details}
  • Bot activity: {summary}

▶ VALIDATOR ASSESSMENT
  Approved: {n} recommendations
  Rejected: {n} (reason: ...)
  Modified: {n}

▶ RULE CHANGES
  {Executor output summary OR "None required — WAF posture is healthy."}

▶ EXTERNAL FINDINGS
  {S3 findings summary OR "None pending."}

───────────────────────────────────────────
  Next run: {tomorrow date} {next_run_time}
═══════════════════════════════════════════

FORMATTING RULES:
- NO JSON objects or arrays in the output
- NO markdown (no #, **, ```, etc.)
- Use plain text with Unicode box drawing for structure
- Include real numbers, IPs, and rule names — never say "see above"
- Be concise but specific — aim for 2000-4000 characters total
- If a section has nothing to report, write one line (e.g., "None detected.")

## Rules
- ALWAYS use the current_timestamp provided in the prompt — NEVER invent or guess dates
- Always pass dry_run parameter through to executor
- Never skip validation — even external pentest findings go through validator
- If no WAF findings AND no external findings, set Status to HEALTHY and note "All clear"
"""



def _next_run_label() -> str:
    """Human-readable daily run time derived from the scheduler config (e.g. '08:00 Asia/Singapore')."""
    import re
    expr = os.environ.get("SCHEDULE_EXPRESSION", "")
    tz = os.environ.get("SCHEDULE_TIMEZONE", "UTC")
    m = re.match(r"cron\(\s*(\d+)\s+(\d+)\s", expr)
    if not m:
        return "(next scheduled run)"
    return f"{int(m.group(2)):02d}:{int(m.group(1)):02d} {tz}"


def _invoke_runtime(runtime_arn: str, payload: dict) -> str:
    """Invoke a sub-agent runtime via AgentCore and return response."""
    from botocore.config import Config
    config = Config(read_timeout=600, connect_timeout=10)
    client = boto3.client("bedrock-agentcore", region_name=REGION, config=config)
    session_id = str(uuid.uuid4()) + "-" + "0" * 12  # 33+ chars required
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=runtime_arn,
        runtimeSessionId=session_id,
        payload=json.dumps(payload).encode(),
        contentType="application/json",
        accept="application/json",
    )
    # Response is a streaming body under 'response' key
    body = resp.get("response", b"")
    if hasattr(body, "read"):
        body = body.read()
    return body.decode("utf-8") if isinstance(body, bytes) else str(body)


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

    return type("SigV4", (httpx.Auth,), {"auth_flow": lambda self, req: auth_flow(req)})()


def _create_gateway_transport():
    gateway_url = os.environ["GATEWAY_URL"]
    return streamablehttp_client(gateway_url, auth=_sigv4_auth())


# --- Sub-agent invocation tools (not via Gateway) ---

@tool
def invoke_analyzer(log_group: str, lookback_hours: int = 24, region: str = REGION) -> str:
    """Invoke the Analyzer Agent to scan WAF logs for threats and anomalies."""
    return _invoke_runtime(os.environ["ANALYZER_RUNTIME_ARN"],
                           {"log_group": log_group, "lookback_hours": lookback_hours, "region": region,
                            "web_acl_arn": os.environ.get("WEB_ACL_ARN", "")})


@tool
def invoke_validator(findings: str, web_acl_arn: str = "", region: str = REGION) -> str:
    """Invoke the Validator Agent to filter false positives from findings."""
    return _invoke_runtime(os.environ["VALIDATOR_RUNTIME_ARN"],
                           {"findings": findings, "web_acl_arn": web_acl_arn or os.environ.get("WEB_ACL_ARN", ""), "region": region})


@tool
def invoke_executor(findings: str, web_acl_arn: str = "", dry_run: bool = True, region: str = REGION) -> str:
    """Invoke the Executor Agent to propose/apply WAF rule changes."""
    return _invoke_runtime(os.environ["EXECUTOR_RUNTIME_ARN"],
                           {"findings": findings, "web_acl_arn": web_acl_arn or os.environ.get("WEB_ACL_ARN", ""), "dry_run": dry_run, "region": region})


def _clean_for_email(text: str) -> str:
    """Strip markdown/JSON artifacts from LLM output for clean email delivery."""
    import re
    # Remove markdown code fences
    text = re.sub(r'```[\w]*\n?', '', text)
    # Remove markdown bold/italic
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    # Remove markdown headers (# Header → Header)
    text = re.sub(r'^#{1,4}\s+', '', text, flags=re.MULTILINE)
    # Collapse 3+ blank lines to 2
    text = re.sub(r'\n{3,}', '\n\n', text)
    # Remove leading/trailing whitespace
    return text.strip()


@app.entrypoint
def invoke(payload: dict) -> dict:
    logger.info(f"Supervisor invoked: {json.dumps(payload)[:500]}")
    try:
        model = BedrockModel(
            model_id=os.environ.get("MODEL_ID", "us.anthropic.claude-sonnet-4-6"),
            region_name=REGION,
        )

        mcp_client = MCPClient(_create_gateway_transport)
        with mcp_client:
            gateway_tools = mcp_client.list_tools_sync()

            agent = Agent(
                model=model,
                tools=[invoke_analyzer, invoke_validator, invoke_executor] + gateway_tools,
                system_prompt=SYSTEM_PROMPT.replace("{next_run_time}", _next_run_label()),
            )

            prompt = (
                f"Run scheduled WAF analysis pipeline:\n"
                f"- current_timestamp: {payload.get('timestamp', 'unknown')}\n"
                f"- log_group: {payload.get('log_group', os.environ.get('LOG_GROUP', ''))}\n"
                f"- web_acl_arn: {payload.get('web_acl_arn', os.environ.get('WEB_ACL_ARN', ''))}\n"
                f"- sns_topic_arn: {payload.get('sns_topic_arn', os.environ.get('SNS_TOPIC_ARN', ''))}\n"
                f"- findings_bucket: {payload.get('findings_bucket', os.environ.get('FINDINGS_BUCKET', ''))}\n"
                f"- lookback_hours: {payload.get('lookback_hours', 24)}\n"
                f"- dry_run: {payload.get('dry_run', True)}\n"
                f"- region: {REGION}\n"
            )

            result = agent(prompt)
            pipeline_output = str(result)

        # --- REPORT SEND via SNS (direct, exactly once) ---
        import re
        from datetime import date, datetime, timezone
        logger.info(f"Pipeline complete ({len(pipeline_output)} chars). Preparing SNS report...")

        report_match = re.search(r'(═{3,}.*═{3,})', pipeline_output, re.DOTALL)
        report_body = _clean_for_email(report_match.group(1) if report_match else pipeline_output)[:14000]

        severity = "INFO"
        status_match = re.search(r'Status\s*:\s*(\w+)', report_body)
        if status_match:
            status_val = status_match.group(1).upper()
            if status_val == "CRITICAL":
                severity = "CRITICAL"
            elif status_val in ("ACTION_REQUIRED", "HIGH"):
                severity = "HIGH"
            elif status_val == "HEALTHY":
                severity = "HEALTHY"

        subject = f"WAF Daily Security Report — {date.today().isoformat()} — {severity}"
        sns_topic = payload.get("sns_topic_arn", os.environ.get("SNS_TOPIC_ARN", ""))
        findings_bucket = payload.get("findings_bucket", os.environ.get("FINDINGS_BUCKET", ""))
        region = REGION
        run_id = payload.get("run_id")
        marker_key = payload.get("marker_key")

        # ★ IDEMPOTENCY CLAIM
        # Atomically create today's report-sent marker. If another (zombie)
        # session has already claimed it, PutObject returns PreconditionFailed
        # and we skip SNS publish. This is the final defense against duplicate
        # emails when Lambda/EventBridge/boto retries slip through.
        claim_key = f"markers/report-sent-{date.today().isoformat()}.json"
        claim_body = json.dumps({
            "claimed_by_run_id": run_id,
            "claimed_at": datetime.now(timezone.utc).isoformat(),
        }).encode("utf-8")

        s3_client = boto3.client("s3", region_name=region)
        try:
            s3_client.put_object(
                Bucket=findings_bucket,
                Key=claim_key,
                Body=claim_body,
                ContentType="application/json",
                IfNoneMatch="*",
            )
        except s3_client.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("PreconditionFailed", "ConditionalRequestConflict"):
                logger.warning(
                    f"Idempotency claim rejected — today's report already sent by another session. "
                    f"Skipping SNS publish. run_id={run_id}"
                )
                # Best-effort: leave the run marker as "started" so the healthcheck
                # sees the outcome, or mark it as duplicate for observability.
                if findings_bucket and marker_key:
                    try:
                        s3_client.put_object(
                            Bucket=findings_bucket,
                            Key=marker_key,
                            Body=json.dumps({
                                "run_id": run_id,
                                "status": "skipped_duplicate",
                                "completed_at": datetime.now(timezone.utc).isoformat(),
                                "reason": "slot_already_claimed",
                            }).encode("utf-8"),
                            ContentType="application/json",
                        )
                    except Exception as marker_exc:  # noqa: BLE001
                        logger.warning(f"Duplicate marker update failed (non-fatal): {marker_exc}")
                return {"status": "skipped_duplicate", "run_id": run_id}
            raise

        sns_client = boto3.client("sns", region_name=region)
        resp = sns_client.publish(
            TopicArn=sns_topic,
            Subject=subject[:100],
            Message=report_body,
        )
        msg_id = resp["MessageId"]
        logger.info(f"Report sent via SNS: {msg_id}")

        # Mark this run as completed. Best-effort — a failure here does not
        # affect email delivery; the healthcheck may still see the marker as
        # "started" but the idempotency claim above prevents duplicates.
        if findings_bucket and marker_key:
            try:
                s3_client.put_object(
                    Bucket=findings_bucket,
                    Key=marker_key,
                    Body=json.dumps({
                        "run_id": run_id,
                        "status": "completed",
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "message_id": msg_id,
                        "severity": severity,
                    }).encode("utf-8"),
                    ContentType="application/json",
                )
            except Exception as marker_exc:  # noqa: BLE001
                logger.warning(f"Run marker update failed (non-fatal): {marker_exc}")

        return {"status": "complete", "response": pipeline_output[:14000],
                "report_message_id": msg_id, "run_id": run_id}

    except Exception as e:
        logger.error(f"FATAL: {e}\n{traceback.format_exc()}")
        return {"status": "error", "error": str(e)}


if __name__ == "__main__":
    app.run()
