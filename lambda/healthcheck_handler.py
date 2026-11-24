"""Healthcheck Lambda — invoked by EventBridge Scheduler B, ~15 min after A.

Independent of the main pipeline. Responsibilities:

  1. Scan today's run markers in S3.
  2. For any marker still at status="started" past the hang threshold,
     publish a single SNS alert email.
  3. Purge markers older than 7 days (housekeeping).

This Lambda is idempotent (read-only S3 + at-most-one SNS publish per hung
run), so boto3 retries are safe. If a marker is genuinely hung, the AgentCore
session may still complete server-side later — the supervisor's own
idempotency claim (S3 IfNoneMatch on markers/report-sent-{date}.json)
guarantees it will not double-publish the daily report.

Alert email is short and factual: date, run_id, age, started_at. It does not
attempt to render the WAF report itself.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config


_CFG = Config(retries={"max_attempts": 3, "mode": "standard"},
              connect_timeout=5, read_timeout=15)

_MARKER_TTL_DAYS = 7


def _parse_started_at(marker_body):
    """Return a timezone-aware datetime for the marker's started_at, or None."""
    raw = marker_body.get("started_at")
    if not raw:
        return None
    try:
        # ISO 8601 with timezone; Python 3.11+ handles 'Z' natively via fromisoformat
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def handler(event, context):
    region = os.environ["REGION"]
    findings_bucket = os.environ["FINDINGS_BUCKET"]
    sns_topic = os.environ["SNS_TOPIC_ARN"]
    hang_threshold_min = int(os.environ.get("HANG_THRESHOLD_MINUTES", "12"))

    s3 = boto3.client("s3", region_name=region, config=_CFG)
    sns = boto3.client("sns", region_name=region, config=_CFG)

    now = datetime.now(timezone.utc)
    today = now.date().isoformat()
    prefix = f"markers/{today}/"

    report = {"date": today, "checked": 0, "completed": 0,
              "hung": [], "purged": 0, "malformed": 0}

    # ─── 1) inspect today's markers ─────────────────────────────────────
    continuation = None
    while True:
        list_kwargs = {"Bucket": findings_bucket, "Prefix": prefix, "MaxKeys": 1000}
        if continuation:
            list_kwargs["ContinuationToken"] = continuation
        resp = s3.list_objects_v2(**list_kwargs)

        for obj in resp.get("Contents", []):
            key = obj["Key"]
            report["checked"] += 1

            try:
                body = json.loads(s3.get_object(Bucket=findings_bucket, Key=key)["Body"].read())
            except Exception:  # noqa: BLE001
                report["malformed"] += 1
                continue

            status = body.get("status")
            if status == "completed":
                report["completed"] += 1
                continue

            if status == "started":
                started_at = _parse_started_at(body)
                if started_at is None:
                    report["malformed"] += 1
                    continue
                age_min = (now - started_at).total_seconds() / 60.0
                if age_min >= hang_threshold_min:
                    run_id = body.get("run_id", "unknown")
                    report["hung"].append({
                        "run_id": run_id,
                        "age_minutes": round(age_min, 1),
                        "started_at": body["started_at"],
                        "marker_key": key,
                    })

        if resp.get("IsTruncated"):
            continuation = resp.get("NextContinuationToken")
        else:
            break

    # ─── 2) send one SNS alert per hung run ─────────────────────────────
    for hung in report["hung"]:
        subject = f"WAF Pipeline Timeout — {today} — {hung['run_id'][:8]}"
        message = (
            f"The WAF report pipeline for {today} did not complete within "
            f"{hang_threshold_min} minutes.\n\n"
            f"run_id       : {hung['run_id']}\n"
            f"marker_key   : s3://{findings_bucket}/{hung['marker_key']}\n"
            f"started_at   : {hung['started_at']}\n"
            f"age (minutes): {hung['age_minutes']}\n\n"
            f"Action items:\n"
            f"  - Inspect AgentCore Supervisor runtime logs for run_id {hung['run_id']}\n"
            f"  - Check runner Lambda CloudWatch Logs (function: {os.environ.get('RUNNER_FUNCTION_NAME', 'waf-report-runner')})\n"
            f"  - The AgentCore session may still complete server-side and\n"
            f"    publish a delayed report; the S3 idempotency claim\n"
            f"    (markers/report-sent-{today}.json) prevents duplicates.\n"
        )
        sns.publish(TopicArn=sns_topic, Subject=subject[:100], Message=message)
        print(f"healthcheck: alerted for run_id={hung['run_id']} "
              f"age={hung['age_minutes']}min")

    # ─── 3) purge markers older than 7 days (across all date prefixes) ──
    cutoff = now - timedelta(days=_MARKER_TTL_DAYS)
    continuation = None
    while True:
        list_kwargs = {"Bucket": findings_bucket, "Prefix": "markers/", "MaxKeys": 1000}
        if continuation:
            list_kwargs["ContinuationToken"] = continuation
        resp = s3.list_objects_v2(**list_kwargs)

        to_delete = [
            {"Key": obj["Key"]}
            for obj in resp.get("Contents", [])
            if obj["LastModified"] < cutoff
        ]
        # delete_objects handles up to 1000 keys per call
        for i in range(0, len(to_delete), 1000):
            batch = to_delete[i:i + 1000]
            s3.delete_objects(Bucket=findings_bucket, Delete={"Objects": batch})
            report["purged"] += len(batch)

        if resp.get("IsTruncated"):
            continuation = resp.get("NextContinuationToken")
        else:
            break

    print(f"healthcheck: {json.dumps(report)}")
    return report
