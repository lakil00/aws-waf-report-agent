"""Lambda handler for WAF tools — invoked via AgentCore Gateway (MCP)."""
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError

import boto3


# --- Input validation (values reach Logs Insights queries and external URLs) ---

def _validate_ip(value):
    """Return the canonical IP string, or raise ValueError. Blocks query injection."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise ValueError(f"Invalid IP address: {str(value)[:64]!r}") from None


_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def _is_safe_host(value):
    return bool(value) and bool(_HOST_RE.match(str(value)))


def _int_arg(value, default, lo, hi):
    """Coerce to int and clamp to [lo, hi]; fall back to default on bad input."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    return max(lo, min(hi, n))


# --- Configuration (environment-driven; defaults preserve previous behaviour) ---

DEFAULT_REGION = os.environ.get("REGION") or os.environ.get("AWS_REGION") or "us-east-1"
DEFAULT_LOOKBACK_HOURS = _int_arg(os.environ.get("LOOKBACK_HOURS"), 24, 1, 720)
DEFAULT_TIMEZONE = os.environ.get("DEFAULT_TIMEZONE", "Asia/Singapore")
PENDING_PREFIX = os.environ.get("FINDINGS_PENDING_PREFIX", "findings/pending/")
PROCESSED_PREFIX = os.environ.get("FINDINGS_PROCESSED_PREFIX", "findings/processed/")

# Detection thresholds. Override any subset with WAF_THRESHOLDS='{"fp_attacker_block_ratio": 0.8}'
# (set from Terraform var.detection_thresholds). Unknown keys and non-numeric values are ignored.
DEFAULT_THRESHOLDS = {
    # False-positive verdict (per source IP)
    "fp_attacker_block_ratio": 0.75,      # block ratio above which an IP is attacker-like (also FP ceiling)
    "fp_attacker_min_rules": 3,           # ...and at least this many distinct rules triggered
    "fp_strong_block_ratio": 0.90,
    "fp_strong_min_rules": 2,
    "fp_volumetric_peak_rpm": 250,        # peak requests/min for single-rule volumetric attackers
    "fp_low_block_ratio": 0.05,           # below this, an IP is an FP candidate
    "fp_low_max_rules": 3,
    "fp_benign_high_conf_ratio": 0.25,    # benign payload + block ratio under this => HIGH confidence FP
    "fp_allow_block_multiple": 10,        # allowed:blocked ratio for the legacy FP rule
    "fp_allow_max_peak_rpm": 10,
    # Allowed-traffic anomaly scans
    "suspicious_min_requests": 1000,
    "suspicious_min_uris": 50,
    "bypass_uri_diversity": 50,
    "bypass_hammer_min_total": 200,
    "bypass_hammer_max_uris": 10,
    "bypass_datacenter_min_total": 50,
    # Rules / domains
    "promotion_min_matches": 10,
    "domain_drilldown_block_rate": 0.1,
    "domain_drilldown_count": 3,
    # Week-over-week volume anomaly
    "volume_moderate_wow": 2.0,
    "volume_significant_wow": 3.0,
    "volume_blocked_wow_max": 2.0,
}


def _load_thresholds(raw):
    cfg = dict(DEFAULT_THRESHOLDS)
    if not raw:
        return cfg
    try:
        overrides = json.loads(raw)
        if not isinstance(overrides, dict):
            raise ValueError("not an object")
    except ValueError as exc:
        print(f"[WARN] WAF_THRESHOLDS ignored: {exc}")
        return cfg
    for key, val in overrides.items():
        if key in cfg and isinstance(val, (int, float)) and not isinstance(val, bool):
            cfg[key] = val
        else:
            print(f"[WARN] WAF_THRESHOLDS: ignoring {key!r}")
    return cfg


THRESHOLDS = _load_thresholds(os.environ.get("WAF_THRESHOLDS"))


def _region(args):
    return args.get("region") or DEFAULT_REGION


def _lookback(args):
    return _int_arg(args.get("lookback_hours"), DEFAULT_LOOKBACK_HOURS, 1, 720)


def handler(event, context):
    """MCP tool dispatcher — Gateway sends arguments directly with _tool field."""
    import logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.info(f"RAW EVENT: {json.dumps(event)}")

    tool_name = event.get("_tool", "")
    arguments = event

    dispatch = {
        "query_waf_summary": _query_waf_summary,
        "query_top_blocked": _query_top_blocked,
        "query_suspicious_patterns": _query_suspicious_patterns,
        "query_rate_limit_hits": _query_rate_limit_hits,
        "run_custom_waf_query": _run_custom_waf_query,
        "get_web_acl": _get_web_acl,
        "update_web_acl_rules": _update_web_acl_rules,
        "list_pending_findings": _list_pending_findings,
        "archive_processed_findings": _archive_processed_findings,
        "query_false_positive_signals": _query_false_positive_signals,
        "scan_bypass_candidates": _scan_bypass_candidates,
        "investigate_ip_deep": _investigate_ip_deep,
        "query_label_distribution": _query_label_distribution,
        "query_bot_intelligence": _query_bot_intelligence,
        "check_volume_anomaly": _check_volume_anomaly,
        "check_coverage_gaps": _check_coverage_gaps,
        "current_datetime": _current_datetime,
        "query_per_domain": _query_per_domain,
        "query_non_terminating_rules": _query_non_terminating_rules,
        "enrich_ip_reputation": _enrich_ip_reputation,
    }

    fn = dispatch.get(tool_name)
    if not fn:
        return {"content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}], "isError": True}

    try:
        result = fn(arguments)
        return {"content": [{"type": "text", "text": result}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {str(e)}"}], "isError": True}


# --- Query helpers ---

def _current_datetime(args):
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(args.get("timezone", DEFAULT_TIMEZONE))
    now = datetime.now(tz)
    return json.dumps({"datetime": now.isoformat(), "timezone": str(tz), "date": now.strftime("%Y-%m-%d"), "time": now.strftime("%H:%M:%S")})


class QueryError(Exception):
    """Logs Insights query failed, was cancelled, or timed out."""


_QUERY_POLL_ATTEMPTS = 30
_QUERY_POLL_SECONDS = 2


def _run_query(log_group, query, lookback_hours, region):
    client = boto3.client("logs", region_name=region)
    end = int(datetime.now(timezone.utc).timestamp())
    start = end - int(lookback_hours) * 3600
    return str(_run_query_raw(client, log_group, query, start, end))


# --- WAF Log Tools ---

def _query_waf_summary(args):
    return _run_query(args["log_group"], """fields @timestamp, action
| stats count(*) as total, count_distinct(httpRequest.clientIp) as unique_ips, sum(action='BLOCK') as blocked, sum(action='ALLOW') as allowed, sum(action not in ['BLOCK','ALLOW']) as other
| limit 1""", _lookback(args), _region(args))


def _query_top_blocked(args):
    limit = _int_arg(args.get("limit", 20), 20, 1, 100)
    return _run_query(args["log_group"], f"""fields httpRequest.clientIp as ip, terminatingRuleId as rule
| filter action = 'BLOCK'
| stats count(*) as cnt by ip, rule
| sort cnt desc
| limit {limit}""", _lookback(args), _region(args))


def _query_suspicious_patterns(args):
    t = THRESHOLDS
    return _run_query(args["log_group"], f"""fields httpRequest.clientIp as ip, httpRequest.uri as uri, action
| filter action = 'ALLOW'
| stats count(*) as cnt, count_distinct(uri) as uri_cnt by ip
| filter cnt > {int(t["suspicious_min_requests"])} or uri_cnt > {int(t["suspicious_min_uris"])}
| sort cnt desc
| limit 20""", _lookback(args), _region(args))


def _query_rate_limit_hits(args):
    return _run_query(args["log_group"], """fields httpRequest.clientIp as ip, terminatingRuleId as rule
| filter terminatingRuleType = 'RATE_BASED'
| stats count(*) as cnt by ip, rule
| sort cnt desc
| limit 20""", _lookback(args), _region(args))


def _run_custom_waf_query(args):
    return _run_query(args["log_group"], args["query"], _lookback(args), _region(args))


# --- WAF Management Tools ---

def _parse_acl_arn(arn):
    parts = arn.split("/")
    scope = "REGIONAL" if ":regional/" in arn else "CLOUDFRONT"
    return scope, parts[-2], parts[-1]


def _get_web_acl(args):
    scope, name, acl_id = _parse_acl_arn(args["web_acl_arn"])
    client = boto3.client("wafv2", region_name=_region(args))
    resp = client.get_web_acl(Name=name, Scope=scope, Id=acl_id)
    acl = resp["WebACL"]
    return json.dumps({"rules": acl.get("Rules", []), "lock_token": resp["LockToken"], "capacity": acl.get("Capacity")}, default=str)


_MAX_NEW_RULES_PER_CALL = 5


def _writes_enabled():
    """Hard switch, set by Terraform (var.allow_waf_write). Independent of LLM-supplied dry_run."""
    return os.environ.get("WAF_WRITE_ENABLED", "false").lower() == "true"


def _is_count_only(rule):
    """True only if the rule cannot block: Action=Count, or rule-group OverrideAction=Count."""
    if isinstance(rule.get("Action"), dict):
        return set(rule["Action"].keys()) == {"Count"}
    if isinstance(rule.get("OverrideAction"), dict):
        return set(rule["OverrideAction"].keys()) == {"Count"}
    return False


def _canon(rule):
    return json.dumps(rule, sort_keys=True, default=str)


def _validate_rule_update(current_rules, new_rules):
    """Return a list of policy violations (empty list = safe to apply).

    Policy: existing rules are immutable and cannot be removed; at most
    _MAX_NEW_RULES_PER_CALL rules may be added; every added or changed rule
    must be COUNT-only. Promotion to BLOCK is a deliberate human action.
    """
    errors = []
    if not isinstance(new_rules, list) or not all(isinstance(r, dict) for r in new_rules):
        return ["rules_json must be a JSON array of rule objects"]
    names = [r.get("Name") for r in new_rules]
    if len(set(names)) != len(names):
        errors.append("duplicate rule names")
    prios = [r.get("Priority") for r in new_rules]
    if len(set(prios)) != len(prios):
        errors.append("duplicate rule priorities")

    current_by_name = {r["Name"]: r for r in current_rules}
    removed = sorted(set(current_by_name) - set(names))
    if removed:
        errors.append(f"removing existing rules is not allowed: {removed}")

    added = 0
    for r in new_rules:
        name = r.get("Name")
        cur = current_by_name.get(name)
        if cur is not None and _canon(cur) == _canon(r):
            continue  # unchanged
        kind = "modified" if cur is not None else "new"
        if cur is None:
            added += 1
        if not _is_count_only(r):
            errors.append(f"{kind} rule {name!r} must be COUNT-only (Action=Count or OverrideAction=Count)")
    if added > _MAX_NEW_RULES_PER_CALL:
        errors.append(f"too many new rules in one call ({added} > {_MAX_NEW_RULES_PER_CALL})")
    return errors


def _update_web_acl_rules(args):
    if args.get("dry_run", True):
        return json.dumps({"status": "dry_run", "message": "Would update rules"})
    if not _writes_enabled():
        raise PermissionError("WAF writes are disabled (WAF_WRITE_ENABLED != true); only dry_run is allowed")
    scope, name, acl_id = _parse_acl_arn(args["web_acl_arn"])
    client = boto3.client("wafv2", region_name=_region(args))
    try:
        rules = json.loads(args["rules_json"])
    except (TypeError, ValueError, KeyError):
        raise ValueError("rules_json is not valid JSON") from None
    resp = client.get_web_acl(Name=name, Scope=scope, Id=acl_id)
    current = resp["WebACL"]
    errors = _validate_rule_update(current.get("Rules", []), rules)
    if errors:
        raise ValueError("Rule update rejected: " + "; ".join(errors))
    # Always use the lock token fetched just now, not a caller-supplied (possibly stale) one.
    client.update_web_acl(Name=name, Scope=scope, Id=acl_id, LockToken=resp["LockToken"],
                          DefaultAction=current["DefaultAction"], Rules=rules, VisibilityConfig=current["VisibilityConfig"])
    return json.dumps({"status": "applied", "rule_count": len(rules)})


# --- SNS Tool ---


# --- S3 Findings Tools ---

def _list_pending_findings(args):
    """Read all unprocessed finding files from S3 pending folder."""
    s3 = boto3.client("s3", region_name=_region(args))
    bucket = args["bucket"]
    prefix = args.get("prefix", PENDING_PREFIX)

    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    if "Contents" not in resp:
        return json.dumps({"files": [], "count": 0})

    results = []
    for obj in resp["Contents"]:
        key = obj["Key"]
        if not key.endswith((".json", ".md", ".txt", ".pdf")):
            continue
        if key.endswith(".pdf"):
            results.append({"file": key, "content": "[PDF file — noted for review]"})
            continue
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")[:20000]
        results.append({"file": key, "content": body})

    return json.dumps({"files": results, "count": len(results)})


def _archive_processed_findings(args):
    """Move processed files from pending/ to processed/ folder."""
    s3 = boto3.client("s3", region_name=_region(args))
    bucket = args["bucket"]
    files = json.loads(args["files_json"])

    if not isinstance(files, list):
        raise ValueError("files_json must be a JSON array of S3 keys")
    bad = [k for k in files if not (isinstance(k, str) and k.startswith(PENDING_PREFIX))]
    if bad:
        raise ValueError(f"refusing to archive keys outside {PENDING_PREFIX!r}: {bad[:3]}")

    for key in files:
        new_key = PROCESSED_PREFIX + key[len(PENDING_PREFIX):]
        s3.copy_object(Bucket=bucket, CopySource={"Bucket": bucket, "Key": key}, Key=new_key)
        s3.delete_object(Bucket=bucket, Key=key)

    return json.dumps({"archived": len(files)})


# --- Analysis Tools ---


_ATTACK_PATTERNS = [
    r"(?i)'\s*(OR|AND)\s+\d+=\d+", r"(?i)UNION\s+(ALL\s+)?SELECT",
    r"(?i);\s*DROP\s+TABLE", r"(?i)SLEEP\s*\(", r"(?i)BENCHMARK\s*\(",
    r"<script", r"(?i)javascript:", r"(?i)onerror\s*=", r"(?i)onload\s*=",
    r"\.\./\.\./", r"/etc/passwd", r"/proc/self/",
    r"(?i);\s*cat\s+/etc/", r"/bin/sh", r"\|\s*wget", r"\$\(curl",
    r"(?i)eval\s*\(", r"(?i)exec\s*\(", r"(?i)base64_decode\s*\(", r"(?i)system\s*\(",
    r"(?i)/\.env", r"(?i)/\.git", r"(?i)/wp-admin", r"(?i)/xmlrpc\.php",
    r"(?i)/phpmyadmin", r"(?i)/actuator", r"(?i)/solr", r"(?i)/console",
]

# Benign-looking matchedData. Deliberately narrow: single lowercase words, IP literals
# and URLs are NOT here because attackers can trivially produce them.
_FP_PATTERNS = [
    r"^[A-Z][a-z]+'[a-z]+$",                      # O'Brien, O'Reilly
    r"^[A-Z][a-z]+(?:[ -][A-Z][a-z]+){0,3}$",     # Title Case names: "Mary-Ann Smith"
    r"^[A-Za-z][A-Za-z\s'-]{1,29}$",              # plain words/names (guarded by keyword check)
]

# Words that make otherwise name-like text suspicious (SQL/shell/XSS/path tokens).
_SUSPICIOUS_TOKENS = re.compile(
    r"(?i)\b(select|union|insert|update|delete|drop|alter|create|exec|execute|eval|script|alert|"
    r"onerror|onload|sleep|benchmark|waitfor|admin|administrator|root|passwd|shadow|shell|cmd|bash|"
    r"powershell|curl|wget|having|where|from|null|char|concat|information_schema|xp_cmdshell|or|and)\b"
)


def _has_attack_pattern(text):
    return any(re.search(p, text) for p in _ATTACK_PATTERNS)


def _has_fp_pattern(text):
    """True if matchedData looks like ordinary content (names/words) with no attack keywords."""
    t = text.strip()
    if _SUSPICIOUS_TOKENS.search(t):
        return False
    return any(re.search(p, t) for p in _FP_PATTERNS)


def _query_false_positive_signals(args):
    ip = _validate_ip(args["ip"])
    log_group = args["log_group"]
    lookback = _lookback(args)
    region = _region(args)
    client = boto3.client("logs", region_name=region)
    end = int(datetime.now(timezone.utc).timestamp())
    start = end - int(lookback) * 3600

    def q(query): return _run_query_raw(client, log_group, query, start, end)

    ratio_rows = q(f"filter httpRequest.clientIp = '{ip}' | stats count(*) as hits by action")
    actions = {r.get("action", ""): int(r.get("hits", 0)) for r in ratio_rows}
    allow_count, block_count = actions.get("ALLOW", 0), actions.get("BLOCK", 0)

    freq = q(f"filter httpRequest.clientIp = '{ip}' | stats count(*) as hits by bin(1m) | stats max(hits) as peak_rpm, avg(hits) as avg_rpm")
    peak_rpm = float(freq[0].get("peak_rpm", 0)) if freq else 0

    rules = q(f"filter httpRequest.clientIp = '{ip}' and action != 'ALLOW' | stats count(*) as hits by terminatingRuleId | sort hits desc | limit 10")
    rules_triggered = len(rules)

    md_rows = q(f"filter httpRequest.clientIp = '{ip}' and action = 'BLOCK' and @message like '\"terminatingRuleMatchDetails\":[{{' | fields @message | limit 5")
    match_attack = False
    fp_payloads = 0
    matched_payloads = []
    for r in md_rows:
        try:
            rec = json.loads(r.get("@message", ""))
            for d in rec.get("terminatingRuleMatchDetails", []):
                snippet = " ".join(d.get("matchedData", []))
                if not snippet:
                    continue
                matched_payloads.append(snippet[:100])
                if _has_attack_pattern(snippet):
                    match_attack = True
                elif _has_fp_pattern(snippet):
                    fp_payloads += 1
        except (json.JSONDecodeError, TypeError):
            pass

    uri_rows = q(f"filter httpRequest.clientIp = '{ip}' and action = 'BLOCK' | stats count(*) as hits by httpRequest.uri | sort hits desc | limit 10")

    popular = q("filter action = 'ALLOW' | stats count(*) as hits by httpRequest.uri | sort hits desc | limit 20")
    popular_set = {r.get("httpRequest.uri", "") for r in popular}
    blocked_uris = {r.get("httpRequest.uri", "") for r in uri_rows}
    uri_in_popular = bool(blocked_uris & popular_set)

    countries = q("stats count(*) as hits by httpRequest.country | sort hits desc | limit 10")
    top_countries = {r.get("httpRequest.country", "") for r in countries}
    ip_country = q(f"filter httpRequest.clientIp = '{ip}' | stats count(*) as hits by httpRequest.country | limit 1")
    country = ip_country[0].get("httpRequest.country", "") if ip_country else ""
    country_in_top = country in top_countries

    block_ratio = block_count / max(block_count + allow_count, 1)
    t = THRESHOLDS
    # FP only if EVERY inspected payload looks benign (one unclassified payload disqualifies).
    match_fp = bool(matched_payloads) and fp_payloads == len(matched_payloads) and not match_attack

    # Verdict logic (ordered by confidence):
    # 1. matchedData contains attack payload → TP HIGH
    if match_attack:
        verdict, confidence = "TRUE_POSITIVE", "HIGH"
    # 2. ALL matchedData benign AND block ratio not dominant → FP.
    #    HIGH only when blocks are a small minority of this IP's traffic.
    elif match_fp and block_ratio < t["fp_attacker_block_ratio"]:
        verdict, confidence = "LIKELY_FP", ("HIGH" if block_ratio < t["fp_benign_high_conf_ratio"] else "MEDIUM")
    # 3. High block ratio + multiple rules = attacker (regardless of RPM)
    #    - block_ratio > 75% AND 3+ rules triggered = scanner/attacker
    #    - OR block_ratio > 90% AND 2+ rules = very likely attacker
    elif block_ratio > t["fp_attacker_block_ratio"] and rules_triggered >= t["fp_attacker_min_rules"]:
        verdict, confidence = "TRUE_POSITIVE", "HIGH"
    elif block_ratio > t["fp_strong_block_ratio"] and rules_triggered >= t["fp_strong_min_rules"]:
        verdict, confidence = "TRUE_POSITIVE", "HIGH"
    # 4. High block ratio + high RPM (single rule, volumetric)
    elif block_ratio > t["fp_attacker_block_ratio"] and peak_rpm > t["fp_volumetric_peak_rpm"]:
        verdict, confidence = "TRUE_POSITIVE", "MEDIUM"
    # 5. block_ratio < 5% AND rules <= 3 → FP candidate, needs deep dive
    elif block_ratio < t["fp_low_block_ratio"] and rules_triggered <= t["fp_low_max_rules"]:
        verdict, confidence = "LIKELY_FP", "MEDIUM"
        if uri_in_popular and country_in_top:
            confidence = "HIGH"
    # 6. Legacy: high allow ratio + low RPM + single rule
    elif (allow_count > 0 and (allow_count / max(block_count, 1)) > t["fp_allow_block_multiple"]
          and peak_rpm < t["fp_allow_max_peak_rpm"] and rules_triggered == 1):
        verdict, confidence = "LIKELY_FP", "MEDIUM"
        if uri_in_popular and country_in_top:
            confidence = "HIGH"
    else:
        verdict, confidence = "UNDETERMINED", "LOW"

    return json.dumps({"ip": ip, "verdict": verdict, "confidence": confidence,
                       "allow_count": allow_count, "block_count": block_count,
                       "block_ratio": round(block_ratio, 3),
                       "peak_rpm": peak_rpm, "rules_triggered": rules_triggered,
                       "match_detail_attack": match_attack, "match_detail_fp": match_fp,
                       "matched_payloads": matched_payloads[:5],
                       "uri_in_popular_paths": uri_in_popular, "country_in_top_customers": country_in_top})


def _scan_bypass_candidates(args):
    log_group = args["log_group"]
    lookback = _lookback(args)
    region = _region(args)
    client = boto3.client("logs", region_name=region)
    end = int(datetime.now(timezone.utc).timestamp())
    start = end - int(lookback) * 3600

    def q(query): return _run_query_raw(client, log_group, query, start, end)
    candidates = []
    t = THRESHOLDS

    for rows, cat, extra_keys in [
        (q(f"""filter action = 'ALLOW' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ and @message not like 'bot:verified'
| stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris by httpRequest.clientIp
| filter unique_uris > {int(t["bypass_uri_diversity"])} | sort unique_uris desc | limit 10"""), "high_uri_diversity", ["total", "unique_uris"]),
        (q(f"""filter action = 'ALLOW' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ and @message not like 'bot:verified'
| stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris by httpRequest.clientIp
| filter total > {int(t["bypass_hammer_min_total"])} and unique_uris < {int(t["bypass_hammer_max_uris"])} | sort total desc | limit 10"""), "endpoint_hammering", ["total", "unique_uris"]),
        (q(f"""filter action = 'ALLOW' and @message like 'known_bot_data_center' and @message not like 'bot:verified' and @message not like 'bot:unverified'
| stats count(*) as total by httpRequest.clientIp | filter total > {int(t["bypass_datacenter_min_total"])} | sort total desc | limit 10"""), "unclassified_datacenter", ["total"]),
    ]:
        for r in rows:
            entry = {"category": cat, "ip": r.get("httpRequest.clientIp", "")}
            for k in extra_keys:
                entry[k] = int(r.get(k, 0))
            candidates.append(entry)

    return json.dumps({"candidates": candidates, "count": len(candidates)})


def _investigate_ip_deep(args):
    ip = _validate_ip(args["ip"])
    log_group = args["log_group"]
    lookback = _lookback(args)
    region = _region(args)
    client = boto3.client("logs", region_name=region)
    end = int(datetime.now(timezone.utc).timestamp())
    start = end - int(lookback) * 3600

    def q(query): return _run_query_raw(client, log_group, query, start, end)

    freq = q(f"filter httpRequest.clientIp = '{ip}' and action = 'ALLOW' | stats count(*) as hits by bin(1m) | stats max(hits) as peak_rpm, avg(hits) as avg_rpm")
    actions = q(f"filter httpRequest.clientIp = '{ip}' | stats count(*) as hits by action")
    country = q(f"filter httpRequest.clientIp = '{ip}' | stats count(*) as hits by httpRequest.country | limit 1")
    labels = q(f"""filter httpRequest.clientIp = '{ip}' and @message like 'bot-control'
| parse @message /bot:category:(?<cat>[^"}}\\s,]+)/ | stats count(*) as hits by cat | sort hits desc | limit 5""")

    # JA4 fingerprint analysis
    ja4 = q(f"filter httpRequest.clientIp = '{ip}' | stats count(*) as cnt by ja4Fingerprint | sort cnt desc | limit 5")
    ja4_fps = [{"fingerprint": r.get("ja4Fingerprint", ""), "count": int(r.get("cnt", 0))} for r in ja4 if r.get("ja4Fingerprint")]

    # User-Agent distribution (parse by header name — index is unreliable)
    ua = q(f"""filter httpRequest.clientIp = '{ip}'
| parse @message /(?i)\\{{"name":"user-agent","value":"(?<ua>[^"]*)"\\}}/
| stats count(*) as cnt by ua | sort cnt desc | limit 5""")
    user_agents = [{"ua": r.get("ua", ""), "count": int(r.get("cnt", 0))} for r in ua if r.get("ua")]

    # Top URIs hit
    uris = q(f"filter httpRequest.clientIp = '{ip}' | stats count(*) as cnt by httpRequest.uri | sort cnt desc | limit 10")
    top_uris = [{"uri": r.get("httpRequest.uri", ""), "count": int(r.get("cnt", 0))} for r in uris]

    # Non-terminating (COUNT) rules triggered
    count_rules = q(f"""filter httpRequest.clientIp = '{ip}' and @message like '"nonTerminatingMatchingRules":[{{'
| parse @message /nonTerminatingMatchingRules.*?"ruleId":"(?<rule>[^"]+)"/
| stats count(*) as cnt by rule | sort cnt desc | limit 10""")

    return json.dumps({
        "ip": ip,
        "frequency": freq[0] if freq else {},
        "actions": {r.get("action", ""): int(r.get("hits", 0)) for r in actions},
        "country": country[0].get("httpRequest.country", "") if country else "",
        "bot_labels": [{"category": r.get("cat", ""), "hits": int(r.get("hits", 0))} for r in labels],
        "ja4_fingerprints": ja4_fps,
        "user_agents": user_agents,
        "top_uris": top_uris,
        "non_terminating_rules": [{"rule": r.get("rule", ""), "count": int(r.get("cnt", 0))} for r in count_rules],
    })


def _query_label_distribution(args):
    log_group = args["log_group"]
    lookback = _lookback(args)
    region = _region(args)
    client = boto3.client("logs", region_name=region)
    end = int(datetime.now(timezone.utc).timestamp())
    start = end - int(lookback) * 3600

    def q(query): return _run_query_raw(client, log_group, query, start, end)

    attacks = q("""filter action = 'BLOCK'
| parse @message /awswaf:managed:aws:(?<rule_group>[^:]+):(?<rule_name>[^"}}\\s,]+)/
| stats count(*) as hits by rule_group, rule_name | sort hits desc | limit 20""")

    signals = q("""filter @message like 'bot-control:signal:'
| parse @message /signal:(?<signal>[^"}}\\s,]+)/ | stats count(*) as hits by signal | sort hits desc""")

    return json.dumps({
        "attack_types": [{"group": r.get("rule_group", ""), "rule": r.get("rule_name", ""), "hits": int(r.get("hits", 0))} for r in attacks],
        "signals": [{"signal": r.get("signal", ""), "hits": int(r.get("hits", 0))} for r in signals],
    })


def _query_bot_intelligence(args):
    log_group = args["log_group"]
    lookback = _lookback(args)
    region = _region(args)
    client = boto3.client("logs", region_name=region)
    end = int(datetime.now(timezone.utc).timestamp())
    start = end - int(lookback) * 3600

    def q(query): return _run_query_raw(client, log_group, query, start, end)

    categories = q("""filter @message like 'bot:category'
| parse @message /bot:category:(?<category>[^"}}\\s,]+)/ | stats count(*) as hits by category | sort hits desc | limit 10""")

    verification = q("filter @message like 'bot-control:bot:' | stats sum(@message like 'bot:verified') as verified, sum(@message like 'bot:unverified') as unverified")

    ai_bots = q("""filter @message like 'bot:category:ai'
| parse @message /bot:name:(?<bot_name>[^"}}\\s,]+)/ | stats count(*) as hits by bot_name, action | sort hits desc""")

    ai_uris = q("filter @message like 'bot:category:ai' | stats count(*) as hits by httpRequest.uri | sort hits desc | limit 20")

    return json.dumps({
        "categories_top10": [{"category": r.get("category", ""), "hits": int(r.get("hits", 0))} for r in categories],
        "verified_ratio": verification[0] if verification else {},
        "ai_bot_stats": {
            "bots": [{"name": r.get("bot_name", ""), "action": r.get("action", ""), "hits": int(r.get("hits", 0))} for r in ai_bots],
            "top_uris": [{"uri": r.get("httpRequest.uri", ""), "hits": int(r.get("hits", 0))} for r in ai_uris],
        },
    })


def _check_volume_anomaly(args):
    web_acl_arn = args["web_acl_arn"]
    region = _region(args)
    parts = web_acl_arn.split("/")
    webacl_name = parts[-2]
    cw_region = "us-east-1" if "global" in web_acl_arn else region  # CloudFront-scope metrics live in us-east-1
    cw = boto3.client("cloudwatch", region_name=cw_region)

    from datetime import timedelta
    now = datetime.now(timezone.utc)
    tw_start = now - timedelta(days=7)
    lw_start = tw_start - timedelta(days=7)

    def _sum(metric, s, e):
        resp = cw.get_metric_statistics(
            Namespace="AWS/WAFV2", MetricName=metric,
            Dimensions=[{"Name": "WebACL", "Value": webacl_name}, {"Name": "Region", "Value": cw_region}, {"Name": "Rule", "Value": "ALL"}],
            StartTime=s, EndTime=e, Period=7*86400, Statistics=["Sum"])
        pts = resp.get("Datapoints", [])
        return pts[0]["Sum"] if pts else 0

    tw_a, lw_a = _sum("AllowedRequests", tw_start, now), _sum("AllowedRequests", lw_start, tw_start)
    tw_b, lw_b = _sum("BlockedRequests", tw_start, now), _sum("BlockedRequests", lw_start, tw_start)
    wow_a = tw_a / max(lw_a, 1)
    wow_b = tw_b / max(lw_b, 1)

    t = THRESHOLDS
    classification = ("normal" if wow_a < t["volume_moderate_wow"]
                      else ("moderate_increase" if wow_a < t["volume_significant_wow"] else "significant_anomaly"))
    return json.dumps({"wow_allowed": round(wow_a, 2), "wow_blocked": round(wow_b, 2),
                       "classification": classification, "bypass_suspected": wow_a > t["volume_significant_wow"] and wow_b < t["volume_blocked_wow_max"]})


def _check_coverage_gaps(args):
    web_acl_arn = args["web_acl_arn"]
    region = _region(args)
    scope, name, acl_id = _parse_acl_arn(web_acl_arn)
    waf = boto3.client("wafv2", region_name=region)

    resp = waf.get_web_acl(Name=name, Scope=scope, Id=acl_id)
    rules = resp["WebACL"].get("Rules", [])

    has_bot = has_rate = has_ddos = False
    for r in rules:
        stmt = r.get("Statement", {})
        mgr = stmt.get("ManagedRuleGroupStatement", {})
        if mgr.get("Name") == "AWSManagedRulesBotControlRuleSet": has_bot = True
        if mgr.get("Name") == "AWSManagedRulesAntiDDoSRuleSet": has_ddos = True
        if "RateBasedStatement" in stmt: has_rate = True

    gaps = []
    if not has_bot: gaps.append({"gap": "no_bot_control", "recommendation": "Add AWSManagedRulesBotControlRuleSet"})
    if not has_rate: gaps.append({"gap": "no_rate_based_rule", "recommendation": "Add rate-based rule"})
    if not has_ddos: gaps.append({"gap": "no_antiddos", "recommendation": "Add AWSManagedRulesAntiDDoSRuleSet"})
    return json.dumps({"gaps": gaps, "rules_count": len(rules)})


def _query_per_domain(args):
    """Per-domain traffic breakdown for multi-domain WebACLs."""
    log_group = args["log_group"]
    lookback = _lookback(args)
    region = _region(args)
    client = boto3.client("logs", region_name=region)
    end = int(datetime.now(timezone.utc).timestamp())
    start = end - int(lookback) * 3600

    def q(query): return _run_query_raw(client, log_group, query, start, end)

    # Traffic + block rate per domain (Host header)
    domains = q("""parse @message /"name":"[Hh]ost","value":"(?<host>[^"]+)"/
| stats count(*) as total, sum(action='BLOCK') as blocked, sum(action='ALLOW') as allowed by host
| sort total desc | limit 20""")

    result = []
    for r in domains:
        host = r.get("host", "")
        total = int(r.get("total", 0))
        blocked = int(r.get("blocked", 0))
        if not host or total == 0:
            continue
        result.append({
            "domain": host,
            "total": total,
            "blocked": blocked,
            "allowed": int(r.get("allowed", 0)),
            "block_rate": round(blocked / total, 3),
        })

    # Top rules per high-block-rate domain (top 3 domains)
    # Host comes from an attacker-controllable header: only drill down for safe hostnames.
    high_block_domains = [d for d in result if d["block_rate"] > THRESHOLDS["domain_drilldown_block_rate"]
                          and _is_safe_host(d["domain"])][:int(THRESHOLDS["domain_drilldown_count"])]
    for domain in high_block_domains:
        rules = q(f"""parse @message /"name":"[Hh]ost","value":"(?<host>[^"]+)"/
| filter host = '{domain["domain"]}' and action = 'BLOCK'
| stats count(*) as cnt by terminatingRuleId | sort cnt desc | limit 5""")
        domain["top_rules"] = [{"rule": r.get("terminatingRuleId", ""), "count": int(r.get("cnt", 0))} for r in rules]

    return json.dumps({"domains": result, "count": len(result)})


def _query_non_terminating_rules(args):
    """Query COUNT-mode (non-terminating) rules: match counts and downstream BLOCK relationships."""
    log_group = args["log_group"]
    web_acl_arn = args.get("web_acl_arn", "")
    lookback = _lookback(args)
    region = _region(args)
    client = boto3.client("logs", region_name=region)
    end = int(datetime.now(timezone.utc).timestamp())
    start = end - int(lookback) * 3600

    def q(query): return _run_query_raw(client, log_group, query, start, end)

    # All non-terminating rule matches with counts
    nt_rules = q("""filter @message like '"nonTerminatingMatchingRules":[{'
| parse @message /nonTerminatingMatchingRules.*?"ruleId":"(?<rule>[^"]+)"/
| stats count(*) as match_count by rule | sort match_count desc | limit 20""")

    # Check which COUNT-mode labels are used by downstream BLOCK rules
    # by examining WebACL config
    downstream_map = {}
    if web_acl_arn:
        try:
            scope, name, acl_id = _parse_acl_arn(web_acl_arn)
            waf = boto3.client("wafv2", region_name=region)
            resp = waf.get_web_acl(Name=name, Scope=scope, Id=acl_id)
            rules = resp["WebACL"].get("Rules", [])

            def _extract_labels(obj):
                """Recursively find all LabelMatchStatement Key values."""
                labels = []
                if isinstance(obj, dict):
                    if "LabelMatchStatement" in obj:
                        key = obj["LabelMatchStatement"].get("Key", "")
                        if key:
                            labels.append(key)
                    for v in obj.values():
                        labels.extend(_extract_labels(v))
                elif isinstance(obj, list):
                    for item in obj:
                        labels.extend(_extract_labels(item))
                return labels

            for r in rules:
                action = r.get("Action", {})
                if "Block" not in action:
                    continue
                labels_used = _extract_labels(r.get("Statement", {}))
                for label in labels_used:
                    downstream_map[label] = r.get("Name", "unknown")
        except Exception as e:
            print(f"[WARN] Failed to inspect WebACL for downstream labels: {e}")

    # Classify each non-terminating rule
    results = []
    for r in nt_rules:
        rule_name = r.get("rule", "")
        match_count = int(r.get("match_count", 0))
        has_downstream = rule_name in downstream_map or any(rule_name.lower() in k.lower() for k in downstream_map)
        # Resolve downstream rule name (label keys contain the rule name as suffix)
        ds_rule = downstream_map.get(rule_name, "")
        if not ds_rule:
            ds_rule = next((downstream_map[k] for k in downstream_map if rule_name.lower() in k.lower()), "")
        results.append({
            "rule": rule_name,
            "match_count": match_count,
            "has_downstream_block": has_downstream,
            "downstream_rule": ds_rule,
            "promotion_candidate": not has_downstream and match_count > THRESHOLDS["promotion_min_matches"],
        })

    return json.dumps({
        "non_terminating_rules": results,
        "total_count": len(results),
        "promotion_candidates": [r for r in results if r["promotion_candidate"]],
        "label_sourced": [r for r in results if r["has_downstream_block"]],
    })


_ET_URL = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
_ET_CACHE_KEY = "threat-intel/et-blocklist.txt"
_ET_CACHE_MAX_AGE = timedelta(hours=24)


def _parse_blocklist(text):
    """Parse one-IP-or-CIDR-per-line text (with # comments) into network objects."""
    nets = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return nets


def _ip_in_blocklist(ip, nets):
    """Exact IP / CIDR membership (never substring matching)."""
    addr = ipaddress.ip_address(ip)
    return any(n.version == addr.version and addr in n for n in nets)


def _load_et_blocklist(bucket):
    """Return parsed blocklist networks, or None if it cannot be obtained.

    Uses the S3 cache while fresh (<24h), refreshes from upstream when stale,
    and falls back to a stale cache if the refresh fails.
    """
    s3 = boto3.client("s3")
    cached_text, fresh = None, False
    try:
        obj = s3.get_object(Bucket=bucket, Key=_ET_CACHE_KEY)
        cached_text = obj["Body"].read().decode("utf-8")
        modified = obj.get("LastModified")
        fresh = bool(modified) and (datetime.now(timezone.utc) - modified) < _ET_CACHE_MAX_AGE
    except Exception:  # noqa: BLE001 — no cache yet
        pass
    if cached_text is not None and fresh:
        return _parse_blocklist(cached_text)
    try:
        with urlopen(Request(_ET_URL), timeout=10) as resp:
            text = resp.read().decode("utf-8")
        nets = _parse_blocklist(text)
        if nets:
            try:
                s3.put_object(Bucket=bucket, Key=_ET_CACHE_KEY, Body=text.encode(), ContentType="text/plain")
            except Exception:  # noqa: BLE001
                pass
            return nets
    except Exception:  # noqa: BLE001
        pass
    return _parse_blocklist(cached_text) if cached_text else None


def _enrich_ip_reputation(args):
    """Enrich IP with external threat intel: AbuseIPDB + Proofpoint ET blocklist."""
    ip = _validate_ip(args["ip"])
    result = {"ip": ip, "abuseipdb": None, "et_listed": None}

    # AbuseIPDB lookup (if API key configured)
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if api_key:
        try:
            req = Request(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                headers={"Key": api_key, "Accept": "application/json"}
            )
            with urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())["data"]
                result["abuseipdb"] = {
                    "score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "isp": data.get("isp", ""),
                    "country": data.get("countryCode", ""),
                    "is_tor": data.get("isTor", False),
                    "usage_type": data.get("usageType", ""),
                    "domain": data.get("domain", ""),
                }
        except Exception as e:  # noqa: BLE001
            result["abuseipdb"] = {"error": str(e)[:100]}

    # Proofpoint ET blocklist: True/False when checked, None when it could not be obtained.
    bucket = os.environ.get("FINDINGS_BUCKET", "")
    if bucket:
        nets = _load_et_blocklist(bucket)
        if nets is not None:
            result["et_listed"] = _ip_in_blocklist(ip, nets)

    return json.dumps(result)


def _run_query_raw(client, log_group, query, start, end):
    """Execute a Logs Insights query and return parsed rows.

    Raises QueryError on failure/cancel/timeout so callers never mistake an
    incomplete query for "no results" (which would skew verdicts).
    """
    resp = client.start_query(logGroupName=log_group, startTime=start, endTime=end, queryString=query)
    qid = resp["queryId"]
    for _ in range(_QUERY_POLL_ATTEMPTS):
        result = client.get_query_results(queryId=qid)
        status = result["status"]
        if status == "Complete":
            return [{f["field"]: f["value"] for f in row} for row in result.get("results", [])]
        if status in ("Failed", "Cancelled", "Timeout"):
            raise QueryError(f"Logs Insights query {status} (queryId={qid})")
        time.sleep(_QUERY_POLL_SECONDS)
    try:
        client.stop_query(queryId=qid)
    except Exception:  # noqa: BLE001 — best effort, avoid paying for an orphaned query
        pass
    raise QueryError(f"Logs Insights query timed out after {_QUERY_POLL_ATTEMPTS * _QUERY_POLL_SECONDS}s (queryId={qid}); stopped")
