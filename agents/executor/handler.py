"""Executor Runtime — proposes/applies WAF rule changes via Gateway MCP tools."""
import os
import sys
import json
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
from strands.tools.mcp.mcp_client import MCPClient
from mcp.client.streamable_http import streamablehttp_client

REGION = (os.environ.get("REGION") or os.environ.get("AWS_REGION")
          or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1")

app = BedrockAgentCoreApp()

SYSTEM_PROMPT = """You are a WAF Rule Engineer. You receive validated findings and implement rule changes.

## Principles
1. NEVER create a rule in BLOCK mode on first deploy — always COUNT
2. Prefer rate-based rules for volumetric attacks
3. Prefer IP sets for persistent bad actors (multiple days)
4. Avoid duplicate rules — check existing rules first via get_web_acl
5. Respect dry_run mode: if True, only propose changes without applying
6. NEVER send emails or call send_report_email — reporting is handled by a separate agent

## Workflow
1. Call get_web_acl to see current rules and capacity
2. For each finding, determine: new rule needed? existing rule update? skip?
3. If changes needed and dry_run=False, call update_web_acl_rules
4. If dry_run=True, document what WOULD be changed

## Input Sources
Findings can come from:
- Analyzer → Validator pipeline (confirmed WAF log findings)
- External pentest tools (pre-validated, apply directly)

## Output Format
Return JSON:
{{
  "actions": [
    {{"type": "add|modify|skip", "rule_name": "...", "reason": "...", "mode": "COUNT|BLOCK"}}
  ],
  "dry_run": true/false,
  "summary": "..."
}}

## Parameters
- web_acl_arn: {web_acl_arn}
- region: {region}
- dry_run: {dry_run}
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

    return type("SigV4", (httpx.Auth,), {"auth_flow": lambda self, req: auth_flow(req)})()


def _create_gateway_transport():
    gateway_url = os.environ["GATEWAY_URL"]
    return streamablehttp_client(gateway_url, auth=_sigv4_auth())


@app.entrypoint
def invoke(payload: dict) -> dict:
    logger.info(f"Executor invoked: {json.dumps(payload)[:500]}")
    try:
        region = REGION
        web_acl_arn = payload.get("web_acl_arn", os.environ.get("WEB_ACL_ARN", ""))
        dry_run = payload.get("dry_run", True)
        findings = payload.get("findings", "[]")

        model = BedrockModel(
            model_id=os.environ.get("MODEL_ID", "us.anthropic.claude-opus-4-6-v1"),
            region_name=region,
        )

        mcp_client = MCPClient(_create_gateway_transport)
        with mcp_client:
            tools = mcp_client.list_tools_sync()
            agent = Agent(
                model=model,
                tools=tools,
                system_prompt=SYSTEM_PROMPT.format(
                    web_acl_arn=web_acl_arn, region=region, dry_run=dry_run
                ),
            )
            result = agent(
                f"Process these findings and update WAF rules.\n"
                f"web_acl_arn={web_acl_arn}\n"
                f"dry_run={dry_run}\n"
                f"region={region}\n\n"
                f"Findings:\n{findings}"
            )

        return {"status": "complete", "response": _extract_response(str(result))}

    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"FATAL: {e}\n{tb}")
        return {"status": "error", "error": str(e), "traceback": tb[-2000:]}


def _extract_response(text: str, max_len: int = 16000) -> str:
    """Extract JSON from agent output, fallback to truncated text."""
    import re
    # Try to find JSON block
    match = re.search(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group(1))
            return json.dumps(parsed, ensure_ascii=False)
        except json.JSONDecodeError:
            pass
    # Try raw JSON object
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
