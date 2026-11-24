"""Trigger Lambda — invoked async by EventBridge Scheduler A.

Responsibility: bookkeeping only. Generates a run_id, writes an S3 "started"
marker, then async-invokes the runner Lambda. Returns in <2 s.

Every retry knob is off:
  - EventBridge Scheduler A: retry_policy.max_retry_attempts = 0
  - This Lambda's event_invoke_config: max_retry_attempts = 0
  - boto3 clients: retries={"max_attempts": 1}
If this Lambda fails, no pipeline runs, and the healthcheck Lambda (Scheduler B)
will silently pass — because no "started" marker exists for it to alert on.
That is the intended trade-off: a missed run recovers on the next daily cron.
"""

import json
import os
import uuid
from datetime import datetime, timezone

import boto3
from botocore.config import Config

_NO_RETRY = Config(retries={"max_attempts": 1, "mode": "standard"},
                   connect_timeout=5, read_timeout=10)


def handler(event, context):
    region = os.environ["REGION"]
    findings_bucket = os.environ["FINDINGS_BUCKET"]
    runner_function_name = os.environ["RUNNER_FUNCTION_NAME"]

    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    date_key = now.date().isoformat()
    marker_key = f"markers/{date_key}/{run_id}.json"

    marker_body = {
        "run_id": run_id,
        "status": "started",
        "started_at": now.isoformat(),
        "trigger_request_id": getattr(context, "aws_request_id", "unknown"),
    }

    s3 = boto3.client("s3", region_name=region, config=_NO_RETRY)
    s3.put_object(
        Bucket=findings_bucket,
        Key=marker_key,
        Body=json.dumps(marker_body).encode("utf-8"),
        ContentType="application/json",
    )

    payload = json.dumps({
        "run_id": run_id,
        "marker_key": marker_key,
        "lookback_hours": int(os.environ.get("LOOKBACK_HOURS", "24")),
        "dry_run": os.environ.get("DRY_RUN", "true").lower() == "true",
        "timestamp": now.isoformat(),
    }).encode("utf-8")

    lambda_client = boto3.client("lambda", region_name=region, config=_NO_RETRY)
    resp = lambda_client.invoke(
        FunctionName=runner_function_name,
        InvocationType="Event",   # fire-and-forget
        Payload=payload,
    )

    print(f"trigger: run_id={run_id} marker={marker_key} "
          f"invoke_status={resp.get('StatusCode')}")

    return {
        "statusCode": 202,
        "run_id": run_id,
        "marker_key": marker_key,
    }
