"""Validator Runtime — validates Analyzer recommendations against application context."""
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

SYSTEM_PROMPT = """You are a WAF Recommendation Validator. You verify Analyzer recommendations against application context before they proceed to execution.

## Your Role
The Analyzer produces recommendations (FP exceptions, new rules for undetected threats) based on traffic patterns.
YOUR job is to verify each recommendation is SAFE and CORRECT by cross-checking with application reality.

## Validation Process
For each recommendation, investigate:

### 1. Verify the Evidence (use tools to spot-check)
- Run run_custom_waf_query to verify the Analyzer's claims (allow ratio, request patterns)
- Check if the blocked URI is a real application endpoint (query popular URIs from ALLOW traffic)
- Confirm the traffic cluster similarity claim

### 2. Application Context Check
- Is the blocked path a legitimate user-facing endpoint? (e.g., /posts/create, /api/checkout, /upload)
- Would the proposed scope-down rule inadvertently block legitimate traffic?
- Does the exception path make sense? (e.g., excluding /posts/* from XSS check — does /posts accept user HTML input? If yes, the XSS rule IS correct)
- Is this a path where users submit rich content (forms, editors, file uploads)? Those commonly trigger SQLi/XSS rules legitimately.

### 3. Safety Assessment
- If we apply this exception, what's the blast radius?
- Could an attacker exploit this exception? (e.g., if we exclude /api/* from XSS, attacker could inject XSS via API)
- Is COUNT mode sufficient as a safe first step?
- Is the scope-down specific enough? (broad exclusions like path=/* are DANGEROUS)

## Decision Output
For each recommendation:
- **APPROVE**: Evidence checks out, application context confirms FP, scope-down is tight
- **REJECT**: Evidence doesn't hold up, or exception creates security risk
- **MODIFY**: Recommendation is directionally correct but needs tightening (e.g., narrower path, add additional condition)
- **NEEDS_REVIEW**: Cannot determine safety — flag for human operator

## Override Examples
- Analyzer says "exclude /posts/* from XSS" → MODIFY if /posts accepts HTML (the rule IS protecting against real XSS there, but maybe the specific payload is benign CMS content — narrow to specific content-type or user-agent)
- Analyzer says "rate limit at 200/5min" → APPROVE if evidence shows clear hammering pattern
- Analyzer says "allow 1.2.3.4" but IP is from hosting provider → REJECT (could be compromised server)

## Output Format
Return JSON:
{{
  "validated_recommendations": [
    {{
      ...original recommendation...,
      "validation_decision": "APPROVE|REJECT|MODIFY|NEEDS_REVIEW",
      "validation_reasoning": "Verified allow ratio is 125:1. URI /posts/create is a user form endpoint. XSS trigger is from markdown editor input (benign). Scope-down to /posts/* is appropriate since only this path uses markdown.",
      "modifications": null or "Narrow scope-down from /posts/* to /posts/create only",
      "safety_assessment": "LOW_RISK — COUNT mode first, specific path, no bypass opportunity",
      "confidence": 0.85
    }}
  ],
  "summary": {{
    "total": N,
    "approved": N,
    "rejected": N,
    "modified": N,
    "needs_review": N
  }}
}}

## Rules
- ALWAYS verify at least one claim from the Analyzer (spot-check with a query)
- NEVER approve broad exceptions (path=/* or all URIs)
- When in doubt, choose NEEDS_REVIEW over APPROVE
- Do NOT send emails or apply rules — downstream agents handle that
- Confidence threshold: {threshold} — below this → NEEDS_REVIEW

## Context
- Web ACL: {web_acl_arn}
- Log Group: {log_group}
- Confidence threshold: {threshold}

IMPORTANT: When calling any WAF log query tool, ALWAYS use log_group="{log_group}" exactly. Do NOT guess or modify the log group name.
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
    logger.info(f"Validator invoked: {json.dumps(payload)[:500]}")
    try:
        region = REGION
        web_acl_arn = payload.get("web_acl_arn", os.environ.get("WEB_ACL_ARN", ""))
        log_group = payload.get("log_group") or os.environ.get("LOG_GROUP")
        if not log_group:
            raise ValueError("log_group not provided (payload.log_group or LOG_GROUP env var)")
        threshold = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.7"))
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
                system_prompt=SYSTEM_PROMPT.format(web_acl_arn=web_acl_arn, log_group=log_group, threshold=threshold),
            )

            result = agent(
                f"Validate these recommendations from the Analyzer. "
                f"Spot-check evidence and assess application safety.\n"
                f"Web ACL: {web_acl_arn}\n"
                f"Confidence threshold: {threshold}\n\n"
                f"Recommendations to validate:\n{findings}"
            )

        return {"status": "complete", "response": str(result)[:8000]}

    except Exception as e:
        logger.error(f"FATAL: {e}\n{traceback.format_exc()}")
        return {"status": "error", "error": str(e)}


if __name__ == "__main__":
    app.run()
