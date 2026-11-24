#!/bin/bash
# Test run — new fire-and-forget architecture:
#   1. terraform apply
#   2. async-invoke waf-report-trigger  (returns run_id in <2s)
#   3. poll S3 marker markers/{today}/{run_id}.json until status=completed
#   4. verify SNS publish + no duplicates
#
# Usage:  scripts/test_run.sh [--skip-apply]
#
set -euo pipefail

PROFILE="${AWS_PROFILE:?set AWS_PROFILE to the target account profile}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
INFRA_DIR="$ROOT_DIR/infra"

POLL_INTERVAL_SEC=30
POLL_MAX_MINUTES=15
SNS_METRIC_WINDOW_MIN=20

SKIP_APPLY=false
for arg in "$@"; do
  case "$arg" in
    --skip-apply) SKIP_APPLY=true ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. terraform apply
# ---------------------------------------------------------------------------
if ! $SKIP_APPLY; then
  log "=== 1. Terraform apply ==="
  cd "$INFRA_DIR"
  AWS_PROFILE="$PROFILE" terraform apply -auto-approve \
    2>&1 | grep -E "(Apply complete|Error|Plan:|Creating|Destroying|Modifying)" | tail -20
else
  log "=== 1. Skip terraform apply (--skip-apply) ==="
fi

# ---------------------------------------------------------------------------
# 2. Fetch outputs
# ---------------------------------------------------------------------------
cd "$INFRA_DIR"
FINDINGS_BUCKET="$(AWS_PROFILE="$PROFILE" terraform output -raw findings_bucket)"
SNS_TOPIC_ARN="$(AWS_PROFILE="$PROFILE" terraform output -raw sns_topic_arn)"
log "findings_bucket=$FINDINGS_BUCKET"
log "sns_topic_arn=$SNS_TOPIC_ARN"

# Snapshot current SNS publish count so we can detect NEW publishes only
SNS_TOPIC_NAME="$(basename "$SNS_TOPIC_ARN")"
START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# 3. Async-invoke waf-report-trigger
# ---------------------------------------------------------------------------
log "=== 2. Invoking waf-report-trigger (async fire-and-forget) ==="
INVOKE_OUT="/tmp/waf-report-trigger-invoke.json"
aws lambda invoke \
  --function-name waf-report-trigger \
  --invocation-type Event \
  --profile "$PROFILE" --region "$REGION" \
  --payload '{}' \
  "$INVOKE_OUT" >/tmp/waf-report-invoke-meta.json

STATUS_CODE="$(python3 -c "import json,sys; d=json.load(open('/tmp/waf-report-invoke-meta.json')); print(d.get('StatusCode'))")"
if [[ "$STATUS_CODE" != "202" ]]; then
  fail "Trigger async invoke returned StatusCode=$STATUS_CODE (expected 202)"
fi
log "Trigger accepted (StatusCode=202). Waiting for trigger Lambda to write S3 marker..."
sleep 8

# ---------------------------------------------------------------------------
# 4. Discover the run_id from newly-created S3 marker
# ---------------------------------------------------------------------------
TODAY="$(date -u +%Y-%m-%d)"
log "=== 3. Finding today's run marker (markers/$TODAY/) ==="

# Take the marker whose LastModified is >= START_ISO
RUN_MARKER_KEY="$(aws s3api list-objects-v2 \
  --bucket "$FINDINGS_BUCKET" --prefix "markers/$TODAY/" \
  --profile "$PROFILE" --region "$REGION" \
  --query "reverse(sort_by(Contents, &LastModified))[?LastModified >= \`$START_ISO\`] | [0].Key" \
  --output text 2>/dev/null || echo "")"

if [[ -z "$RUN_MARKER_KEY" || "$RUN_MARKER_KEY" == "None" ]]; then
  fail "No new run marker under markers/$TODAY/ since $START_ISO — trigger Lambda may have failed. Check /aws/lambda/waf-report-trigger logs."
fi

RUN_ID="$(basename "$RUN_MARKER_KEY" .json)"
log "run_id=$RUN_ID"
log "marker_key=$RUN_MARKER_KEY"

# ---------------------------------------------------------------------------
# 5. Poll marker until status=completed or timeout
# ---------------------------------------------------------------------------
log "=== 4. Polling marker (interval=${POLL_INTERVAL_SEC}s, max=${POLL_MAX_MINUTES}min) ==="
MAX_ITERATIONS=$(( POLL_MAX_MINUTES * 60 / POLL_INTERVAL_SEC ))
FINAL_STATUS=""
for i in $(seq 1 "$MAX_ITERATIONS"); do
  sleep "$POLL_INTERVAL_SEC"
  MARKER_JSON="$(aws s3 cp "s3://$FINDINGS_BUCKET/$RUN_MARKER_KEY" - \
    --profile "$PROFILE" --region "$REGION" 2>/dev/null || echo '{}')"
  STATUS="$(python3 -c "import json,sys; print(json.loads('''$MARKER_JSON''').get('status', 'unknown'))" 2>/dev/null || echo "parse_error")"
  ELAPSED=$(( i * POLL_INTERVAL_SEC ))
  log "  poll #$i (${ELAPSED}s): status=$STATUS"
  if [[ "$STATUS" == "completed" || "$STATUS" == "skipped_duplicate" ]]; then
    FINAL_STATUS="$STATUS"
    break
  fi
done

if [[ -z "$FINAL_STATUS" ]]; then
  fail "Marker did not reach completed state within ${POLL_MAX_MINUTES} min. Pipeline may be hung. Marker still says: $STATUS"
fi

log "Marker final status: $FINAL_STATUS"

# ---------------------------------------------------------------------------
# 6. Verify report-sent idempotency marker exists
# ---------------------------------------------------------------------------
log "=== 5. Verifying report-sent idempotency marker ==="
CLAIM_KEY="markers/report-sent-$TODAY.json"
if aws s3api head-object --bucket "$FINDINGS_BUCKET" --key "$CLAIM_KEY" \
     --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1; then
  CLAIM_JSON="$(aws s3 cp "s3://$FINDINGS_BUCKET/$CLAIM_KEY" - \
    --profile "$PROFILE" --region "$REGION")"
  log "  [OK] Idempotency claim present: $CLAIM_JSON"
else
  fail "Idempotency claim marker $CLAIM_KEY not found — SNS publish path may not have executed."
fi

# ---------------------------------------------------------------------------
# 7. Verify exactly ONE SNS publish since start
# ---------------------------------------------------------------------------
log "=== 6. Verifying SNS publish count (expect exactly 1) ==="
# CloudWatch SNS metrics have ~30-60s ingestion latency. Wait before querying.
log "  Waiting 90s for CloudWatch metric ingestion..."
sleep 90
END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PUBLISH_COUNT="$(aws cloudwatch get-metric-statistics \
  --namespace AWS/SNS \
  --metric-name NumberOfMessagesPublished \
  --dimensions "Name=TopicName,Value=$SNS_TOPIC_NAME" \
  --start-time "$START_ISO" --end-time "$END_ISO" \
  --period 60 --statistics Sum \
  --profile "$PROFILE" --region "$REGION" \
  --query "sum(Datapoints[].Sum)" --output text 2>/dev/null || echo 0)"
PUBLISH_COUNT_INT="${PUBLISH_COUNT%.*}"
[[ -z "$PUBLISH_COUNT_INT" || "$PUBLISH_COUNT_INT" == "None" ]] && PUBLISH_COUNT_INT=0

log "  SNS publishes in window [$START_ISO, $END_ISO]: $PUBLISH_COUNT_INT"

if [[ "$FINAL_STATUS" == "completed" ]]; then
  if [[ "$PUBLISH_COUNT_INT" -eq 1 ]]; then
    log "  [OK] Exactly 1 SNS publish — idempotency working"
  elif [[ "$PUBLISH_COUNT_INT" -eq 0 ]]; then
    fail "0 SNS publishes but marker says completed — SNS path broken"
  else
    fail "Expected 1 SNS publish, got $PUBLISH_COUNT_INT — DUPLICATE EMAILS RETURNED!"
  fi
elif [[ "$FINAL_STATUS" == "skipped_duplicate" ]]; then
  log "  [OK] Marker=skipped_duplicate → another session already published (expected behavior)"
fi

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
printf '\n%s\n' "==================================================================="
printf 'TEST RUN SUMMARY\n'
printf '%s\n' "==================================================================="
printf '  run_id           : %s\n' "$RUN_ID"
printf '  marker_status    : %s\n' "$FINAL_STATUS"
printf '  idempotency_claim: %s\n' "$CLAIM_KEY (present)"
printf '  sns_publishes    : %s\n' "$PUBLISH_COUNT_INT"
printf '  window           : %s → %s\n' "$START_ISO" "$END_ISO"
printf '%s\n\n' "==================================================================="
log "ALL CHECKS PASSED"
