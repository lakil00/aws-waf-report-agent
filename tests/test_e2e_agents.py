"""E2E integration test for all agents and tool calls.

Usage:
    AWS_PROFILE=<profile> python tests/test_e2e_agents.py [--deploy] [--fix-loop]

Flags:
    --deploy     Run terraform apply before testing
    --fix-loop   Auto-retry on failure (for CI/CD harness)
"""
import boto3
import json
import os
import subprocess
import re
import sys
import time
import uuid
from botocore.config import Config

INFRA_DIR = os.path.join(os.path.dirname(__file__), "..", "infra")


def _tfvar(name, default=None):
    """Read a string value from infra/terraform.tfvars (gitignored), without needing terraform."""
    path = os.path.join(INFRA_DIR, "terraform.tfvars")
    try:
        with open(path) as f:
            for line in f:
                m = re.match(r'\s*' + re.escape(name) + r'\s*=\s*"([^"]*)"', line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return default


# Environment-specific values come from env vars first, then terraform.tfvars.
REGION = os.environ.get("AWS_REGION") or _tfvar("region") or "us-east-1"
PROFILE = os.environ.get("AWS_PROFILE")  # None -> default credential chain
WEB_ACL_ARN = os.environ.get("WAF_WEB_ACL_ARN") or _tfvar("web_acl_arn")
LOG_GROUP = os.environ.get("WAF_LOG_GROUP") or _tfvar("log_group")
if not (WEB_ACL_ARN and LOG_GROUP):
    sys.exit("Set WAF_WEB_ACL_ARN and WAF_LOG_GROUP (or define web_acl_arn/log_group in infra/terraform.tfvars)")

# Expected tools that Analyzer must successfully call
REQUIRED_TOOLS = [
    "query_waf_summary",
    "query_top_blocked",
    "query_false_positive_signals",
    "check_volume_anomaly",
    "scan_bypass_candidates",
    "query_bot_intelligence",
    "query_label_distribution",
    "query_per_domain",
    "query_non_terminating_rules",
]


def run_cmd(cmd, timeout=120):
    """Run shell command and return (returncode, stdout, stderr)."""
    env = os.environ.copy()
    if PROFILE:
        env["AWS_PROFILE"] = PROFILE
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, cwd=INFRA_DIR, env=env)
    return result.returncode, result.stdout, result.stderr


def terraform_deploy():
    """Apply terraform for all agent runtimes."""
    print("[DEPLOY] Running terraform apply for all agents...")
    targets = " ".join([
        '-target=\'null_resource.docker_push["analyzer"]\'',
        '-target=\'null_resource.docker_push["supervisor"]\'',
        '-target=\'null_resource.docker_push["validator"]\'',
        '-target=\'null_resource.docker_push["executor"]\'',
        "-target=aws_bedrockagentcore_agent_runtime.analyzer",
        "-target=aws_bedrockagentcore_agent_runtime.supervisor",
        "-target=aws_bedrockagentcore_agent_runtime.validator",
        "-target=aws_bedrockagentcore_agent_runtime.executor",
    ])
    rc, out, err = run_cmd(f"terraform apply {targets} -auto-approve", timeout=600)
    if rc != 0:
        print(f"[DEPLOY] FAILED:\n{err[-2000:]}")
        return False
    print("[DEPLOY] Success")
    return True


def get_runtime_arns():
    """Get runtime ARNs from terraform output."""
    rc, out, _ = run_cmd("terraform output -json")
    if rc != 0:
        raise RuntimeError("Cannot get terraform outputs")
    outputs = json.loads(out)
    return {
        "analyzer": outputs["analyzer_runtime_arn"]["value"],
        "supervisor": outputs["supervisor_runtime_arn"]["value"],
        "validator": outputs["validator_runtime_arn"]["value"],
        "executor": outputs["executor_runtime_arn"]["value"],
    }


def invoke_runtime(arn, payload, timeout=600):
    """Invoke an AgentCore runtime and return parsed response."""
    config = Config(read_timeout=timeout, connect_timeout=10)
    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    client = session.client("bedrock-agentcore", config=config)

    session_id = str(uuid.uuid4()) + "-" + "0" * 12
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=arn,
        runtimeSessionId=session_id,
        payload=json.dumps(payload).encode(),
        contentType="application/json",
        accept="application/json",
    )
    body = resp.get("response", b"")
    if hasattr(body, "read"):
        body = body.read()
    text = body.decode("utf-8") if isinstance(body, bytes) else str(body)
    return json.loads(text)


def test_analyzer(arns):
    """Test Analyzer: must return complete status with traffic data and trend_analysis."""
    print("\n[TEST] Analyzer runtime...")
    payload = {
        "log_group": LOG_GROUP,
        "lookback_hours": 24,
        "region": REGION,
        "web_acl_arn": WEB_ACL_ARN,
    }

    result = invoke_runtime(arns["analyzer"], payload)
    errors = []

    # Check status
    if result.get("status") != "complete":
        errors.append(f"Status={result.get('status')}, error={result.get('error', 'unknown')}")
        partial = result.get("partial_raw_data", {})
        # Check which tools failed
        for tool in REQUIRED_TOOLS:
            for key, val in partial.items():
                if isinstance(val, dict) and "error" in val and tool in str(val.get("error", "")):
                    errors.append(f"  Tool FAILED: {tool} → {val['error'][:100]}")
        return errors

    # Check response has required fields
    resp = result.get("response", "")
    if "trend_analysis" not in resp:
        errors.append("Missing trend_analysis in response")
    if "traffic_overview" not in resp and "total_requests" not in resp:
        errors.append("Missing traffic data in response")

    # Check partial_raw_data for tool failures
    partial = result.get("partial_raw_data", {})
    if partial:
        for key, val in partial.items():
            if isinstance(val, dict) and "error" in val:
                errors.append(f"Tool error in {key}: {val['error'][:100]}")

    if not errors:
        print(f"  [OK] Analyzer returned complete response ({len(resp)} chars)")
        # Check trend_analysis content
        try:
            idx = resp.find('"trend_analysis"')
            snippet = resp[idx:idx+200] if idx >= 0 else "not found"
            print(f"  [OK] trend_analysis: {snippet[:150]}")
        except Exception:
            pass
    return errors


def test_validator(arns):
    """Test Validator: must accept findings input and return validation."""
    print("\n[TEST] Validator runtime...")
    # Minimal findings payload
    findings = json.dumps({
        "status": "complete",
        "traffic_overview": {"total_requests": 100, "blocked": 50},
        "top_blocked": [{"ip": "1.2.3.4", "rule": "test", "count": 50, "fp_verdict": "TRUE_POSITIVE", "fp_confidence": "HIGH"}],
        "recommendations": [{"action": "block_ip", "target": "1.2.3.4", "reason": "scanner"}],
    })
    payload = {
        "findings": findings,
        "web_acl_arn": WEB_ACL_ARN,
        "region": REGION,
    }

    result = invoke_runtime(arns["validator"], payload, timeout=300)
    errors = []

    if result.get("status") == "error":
        errors.append(f"Validator error: {result.get('error', 'unknown')[:200]}")
    else:
        print(f"  [OK] Validator responded ({len(str(result))} chars)")
    return errors


def test_control_plane_lambdas(arns):
    """Verify all 3 control plane Lambdas exist and have retry lockdown."""
    print("\n[TEST] Control plane Lambdas (trigger + runner + healthcheck)...")
    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    lambda_client = session.client("lambda")
    errors = []

    # (function_name, expected_timeout_s, has_async_config)
    expected = [
        ("waf-report-trigger",     60,  True),
        ("waf-report-runner",      900, True),
        ("waf-report-healthcheck", 60,  False),  # sync-only, no event_invoke_config
    ]

    for fn, expected_timeout, has_async in expected:
        try:
            f = lambda_client.get_function(FunctionName=fn)
            timeout = f["Configuration"]["Timeout"]
            if timeout != expected_timeout:
                errors.append(f"{fn}: timeout {timeout}s != expected {expected_timeout}s")
            if has_async:
                try:
                    cfg = lambda_client.get_function_event_invoke_config(FunctionName=fn)
                    retries = cfg.get("MaximumRetryAttempts")
                    if retries != 0:
                        errors.append(f"{fn}: async retries {retries} != 0 (must be 0)")
                    else:
                        print(f"  [OK] {fn} (timeout={timeout}s, async retries=0)")
                except lambda_client.exceptions.ResourceNotFoundException:
                    errors.append(f"{fn}: event_invoke_config missing — async retries default to 2")
            else:
                print(f"  [OK] {fn} (timeout={timeout}s, sync-only)")
        except lambda_client.exceptions.ResourceNotFoundException:
            errors.append(f"{fn}: Lambda not found")
        except Exception as e:
            errors.append(f"{fn}: {type(e).__name__}: {str(e)[:150]}")

    # Also verify the scheduler is fire-and-forget (retry_policy=0)
    try:
        scheduler_client = session.client("scheduler")
        for name in ("waf-report-daily-scan", "waf-report-daily-healthcheck"):
            sch = scheduler_client.get_schedule(Name=name)
            retry = sch.get("Target", {}).get("RetryPolicy", {}).get("MaximumRetryAttempts")
            if retry != 0:
                errors.append(f"scheduler {name}: retry_policy {retry} != 0")
            else:
                print(f"  [OK] scheduler {name} retry_policy=0")
    except Exception as e:
        errors.append(f"Scheduler check failed: {type(e).__name__}: {str(e)[:150]}")

    return errors


def test_memory_storage():
    """Test that memory records are being stored (check for recent records)."""
    print("\n[TEST] Memory storage...")
    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    client = session.client("bedrock-agentcore")

    records = client.list_memory_records(
        memoryId="waf_report_memory-Rc5MbB3jMe",
        namespace="/findings/waf-analyzer/",
    )
    summaries = records.get("memoryRecordSummaries", [])
    recent = [r for r in summaries if "2026-07-10" in str(r.get("createdAt", ""))]

    errors = []
    if not recent:
        errors.append("No memory records from today — session_manager may not be storing events")
    else:
        print(f"  [OK] {len(recent)} memory record(s) from today")
    return errors


def run_all_tests(arns):
    """Run all tests and return list of (test_name, errors)."""
    results = []
    results.append(("analyzer", test_analyzer(arns)))
    results.append(("validator", test_validator(arns)))
    results.append(("control_plane_lambdas", test_control_plane_lambdas(arns)))
    results.append(("memory_storage", test_memory_storage()))
    return results


def print_summary(results):
    """Print test summary."""
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    all_pass = True
    for name, errors in results:
        if errors:
            all_pass = False
            print(f"  FAIL  {name}")
            for e in errors:
                print(f"        {e}")
        else:
            print(f"  PASS  {name}")
    print("=" * 50)
    return all_pass


def main():
    deploy = "--deploy" in sys.argv
    fix_loop = "--fix-loop" in sys.argv
    max_retries = 3 if fix_loop else 1

    for attempt in range(1, max_retries + 1):
        if attempt > 1:
            print(f"\n{'='*50}\nRETRY {attempt}/{max_retries}\n{'='*50}")

        if deploy or attempt > 1:
            if not terraform_deploy():
                if attempt == max_retries:
                    print("\n[FATAL] Terraform deploy failed after retries")
                    sys.exit(1)
                continue

        arns = get_runtime_arns()
        print(f"Runtime ARNs: {json.dumps({k: v.split('/')[-1] for k, v in arns.items()}, indent=2)}")

        results = run_all_tests(arns)
        all_pass = print_summary(results)

        if all_pass:
            print("\nAll tests PASSED!")
            sys.exit(0)
        elif not fix_loop:
            print("\nTests FAILED. Use --fix-loop to auto-retry with redeploy.")
            sys.exit(1)

        print(f"\nAttempt {attempt} failed, will redeploy and retry...")
        time.sleep(10)

    print(f"\n[FATAL] Still failing after {max_retries} attempts")
    sys.exit(1)


if __name__ == "__main__":
    main()
