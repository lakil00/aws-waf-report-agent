"""Runner Lambda — invoked async by trigger Lambda.

Blocks for the entire supervisor pipeline duration (~5-10 min typical, up to
15 min hard cap). Every retry knob is off:

  - This Lambda's event_invoke_config: max_retry_attempts = 0
  - boto3 client: retries={"max_attempts": 1} (prevents the historical bug
    where read_timeout fired at 540 s and re-invoked AgentCore mid-pipeline,
    starting a second server-side session)
  - read_timeout = 850 (slightly under Lambda's 900 s timeout — Lambda
    kills the container first, so boto3 timeout is never the trigger for
    a retry attempt)

If the pipeline exceeds Lambda's 900 s timeout, this Lambda dies but the
AgentCore session continues server-side. The S3 marker stays at
status="started"; the healthcheck Lambda alerts if it's still there after
the hang threshold. Meanwhile, the supervisor's own idempotency guard
(S3 IfNoneMatch on markers/report-sent-{date}.json) prevents the zombie
session from publishing a duplicate SNS email.
"""

import json
import os
from datetime import datetime, timezone

import boto3
from botocore.config import Config


_AGENTCORE_CFG = Config(
    retries={"max_attempts": 1, "mode": "standard"},
    connect_timeout=10,
    read_timeout=850,
)
_S3_CFG = Config(retries={"max_attempts": 1, "mode": "standard"},
                 connect_timeout=5, read_timeout=10)


def handler(event, context):
    region = os.environ["REGION"]
    findings_bucket = os.environ["FINDINGS_BUCKET"]
    supervisor_arn = os.environ["SUPERVISOR_RUNTIME_ARN"]

    run_id = event.get("run_id")
    marker_key = event.get("marker_key")
    lookback_hours = event.get("lookback_hours", int(os.environ.get("LOOKBACK_HOURS", "24")))
    dry_run = event.get("dry_run", os.environ.get("DRY_RUN", "true").lower() == "true")
    timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())

    if not run_id or not marker_key:
        raise ValueError("runner: missing run_id or marker_key in event payload")

    payload = json.dumps({
        "run_id": run_id,
        "marker_key": marker_key,
        "findings_bucket": findings_bucket,
        "lookback_hours": lookback_hours,
        "dry_run": dry_run,
        "timestamp": timestamp,
    }).encode("utf-8")

    agentcore = boto3.client("bedrock-agentcore", region_name=region, config=_AGENTCORE_CFG)
    session_id = f"{run_id}-{'0' * 12}"  # AgentCore requires ≥33 chars; UUID(36) + suffix is fine

    print(f"runner: invoking supervisor run_id={run_id}")
    resp = agentcore.invoke_agent_runtime(
        agentRuntimeArn=supervisor_arn,
        runtimeSessionId=session_id,
        payload=payload,
        contentType="application/json",
        accept="application/json",
    )
    body = resp["response"].read().decode("utf-8")
    print(f"runner: supervisor returned {len(body)} chars")

    # Best-effort marker update. If the supervisor already updated it to
    # "completed" (which it does after successful SNS publish), overwriting
    # here is fine — it's the same state. If Lambda dies before this line,
    # the healthcheck picks up the still-"started" marker.
    s3 = boto3.client("s3", region_name=region, config=_S3_CFG)
    try:
        completed_marker = {
            "run_id": run_id,
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "runner_request_id": getattr(context, "aws_request_id", "unknown"),
            "response_length": len(body),
        }
        s3.put_object(
            Bucket=findings_bucket,
            Key=marker_key,
            Body=json.dumps(completed_marker).encode("utf-8"),
            ContentType="application/json",
        )
    except Exception as exc:  # noqa: BLE001 — never fail the run over marker bookkeeping
        print(f"runner: marker update failed (non-fatal): {exc}")

    return {
        "statusCode": resp.get("statusCode", 200),
        "run_id": run_id,
        "response_preview": body[:2000],
    }
