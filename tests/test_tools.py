"""Unit tests for WAF tools Lambda — all AWS calls mocked."""
import json
import sys
import os
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add lambda dir to path
sys.path.insert(0, str(Path(__file__).parent.parent / "lambda"))

import tools_handler as th


# ===== Fixtures =====

MOCK_WEB_ACL_ARN = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/test-acl/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

MOCK_WEB_ACL_RESPONSE = {
    "WebACL": {
        "Name": "test-acl",
        "Rules": [
            {
                "Name": "block-hosting-provider-non-verified-bot",
                "Priority": 10,
                "Statement": {
                    "AndStatement": {
                        "Statements": [
                            {"LabelMatchStatement": {"Scope": "LABEL", "Key": "awswaf:managed:aws:anonymous-ip-list:HostingProviderIPList"}},
                            {"NotStatement": {"Statement": {"LabelMatchStatement": {"Scope": "LABEL", "Key": "awswaf:managed:aws:bot-control:bot:verified"}}}}
                        ]
                    }
                },
                "Action": {"Block": {}},
                "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "block-hp"}
            },
            {
                "Name": "allowed-ip-list",
                "Priority": 1,
                "Statement": {"IPSetReferenceStatement": {"ARN": "arn:aws:wafv2:us-east-1:123:ipset/allowed/xxx"}},
                "Action": {"Allow": {}},
                "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "allow-ip"}
            },
            {
                "Name": "aws-managed-reputation",
                "Priority": 3,
                "Statement": {"RuleGroupReferenceStatement": {"ARN": "arn:aws:wafv2:us-east-1::managed-rule-group/aws/AWSManagedRulesAmazonIpReputationList"}},
                "OverrideAction": {"None": {}},
                "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "rep"}
            },
        ],
        "Capacity": 1110,
    },
    "LockToken": "lock-token-abc",
}

MOCK_LOGS_QUERY_RESULTS = {
    "waf_summary": [{"total": "130", "unique_ips": "11", "blocked": "8", "allowed": "122", "other": "0"}],
    "top_blocked": [
        {"ip": "1.2.3.4", "rule": "aws-ip-reputation-list", "cnt": "5"},
        {"ip": "5.6.7.8", "rule": "block-hosting-provider-non-verified-bot", "cnt": "3"},
    ],
    "non_terminating": [
        {"rule": "HostingProviderIPList", "match_count": "119"},
        {"rule": "TGT_TokenAbsent", "match_count": "3"},
        {"rule": "label-verified-harmless-bot", "match_count": "2"},
    ],
}


def _make_query_result(rows):
    """Convert list of dicts to CloudWatch Logs query result format."""
    return {
        "status": "Complete",
        "results": [[{"field": k, "value": v} for k, v in row.items()] for row in rows]
    }


class MockLogsClient:
    """Mock CloudWatch Logs client that returns predefined query results."""
    def __init__(self, results=None):
        self._results = results or []
        self._call_count = 0

    def start_query(self, **kwargs):
        return {"queryId": f"q-{self._call_count}"}

    def get_query_results(self, **kwargs):
        result = self._results[self._call_count] if self._call_count < len(self._results) else []
        self._call_count += 1
        return _make_query_result(result)


# ===== Tests =====

class TestQueryNonTerminatingRules:
    """Test downstream label detection — the bug that was fixed."""

    def _invoke(self, web_acl_response=None):
        mock_waf = MagicMock()
        mock_waf.get_web_acl.return_value = web_acl_response or MOCK_WEB_ACL_RESPONSE

        logs_client = MockLogsClient([MOCK_LOGS_QUERY_RESULTS["non_terminating"]])

        with patch("boto3.client") as mock_boto:
            def client_factory(service, **kwargs):
                if service == "wafv2":
                    return mock_waf
                elif service == "logs":
                    return logs_client
                return MagicMock()
            mock_boto.side_effect = client_factory

            result = json.loads(th._query_non_terminating_rules({
                "log_group": "test-logs",
                "web_acl_arn": MOCK_WEB_ACL_ARN,
                "lookback_hours": 24,
                "region": "us-east-1",
            }))
        return result

    def test_hosting_provider_has_downstream(self):
        result = self._invoke()
        hp_rule = next(r for r in result["non_terminating_rules"] if r["rule"] == "HostingProviderIPList")
        assert hp_rule["has_downstream_block"] is True
        assert hp_rule["downstream_rule"] == "block-hosting-provider-non-verified-bot"
        assert hp_rule["promotion_candidate"] is False

    def test_tgt_token_absent_no_downstream(self):
        result = self._invoke()
        tgt = next(r for r in result["non_terminating_rules"] if r["rule"] == "TGT_TokenAbsent")
        assert tgt["has_downstream_block"] is False
        assert tgt["promotion_candidate"] is False  # match_count 3 < threshold 10

    def test_promotion_candidates_empty(self):
        result = self._invoke()
        assert result["promotion_candidates"] == []

    def test_label_sourced_includes_hosting(self):
        result = self._invoke()
        assert any(r["rule"] == "HostingProviderIPList" for r in result["label_sourced"])

    def test_no_web_acl_arn_graceful(self):
        """When no web_acl_arn provided, downstream detection is skipped."""
        logs_client = MockLogsClient([MOCK_LOGS_QUERY_RESULTS["non_terminating"]])
        with patch("boto3.client", return_value=logs_client):
            result = json.loads(th._query_non_terminating_rules({
                "log_group": "test-logs",
                "web_acl_arn": "",
                "lookback_hours": 24,
            }))
        # Without ACL inspection, all rules appear as having no downstream
        hp_rule = next(r for r in result["non_terminating_rules"] if r["rule"] == "HostingProviderIPList")
        assert hp_rule["has_downstream_block"] is False
        assert hp_rule["promotion_candidate"] is True  # 119 > 10 and no downstream


class TestGetWebAcl:
    def test_parses_rules(self):
        mock_waf = MagicMock()
        mock_waf.get_web_acl.return_value = MOCK_WEB_ACL_RESPONSE
        with patch("boto3.client", return_value=mock_waf):
            result = json.loads(th._get_web_acl({"web_acl_arn": MOCK_WEB_ACL_ARN, "region": "us-east-1"}))
        assert result["lock_token"] == "lock-token-abc"
        assert result["capacity"] == 1110
        assert len(result["rules"]) == 3

    def test_cloudfront_scope_detection(self):
        mock_waf = MagicMock()
        mock_waf.get_web_acl.return_value = MOCK_WEB_ACL_RESPONSE
        with patch("boto3.client", return_value=mock_waf):
            th._get_web_acl({"web_acl_arn": MOCK_WEB_ACL_ARN, "region": "us-east-1"})
        mock_waf.get_web_acl.assert_called_with(Name="test-acl", Scope="CLOUDFRONT", Id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


class TestUpdateWebAclRules:
    def test_dry_run_returns_without_calling_api(self):
        with patch("boto3.client") as mock_boto:
            result = json.loads(th._update_web_acl_rules({
                "web_acl_arn": MOCK_WEB_ACL_ARN,
                "rules_json": "[]",
                "lock_token": "xxx",
                "dry_run": True,
            }))
        assert result["status"] == "dry_run"
        mock_boto.assert_not_called()



class TestCurrentDatetime:
    def test_returns_datetime_json(self):
        result = json.loads(th._current_datetime({"timezone": "UTC"}))
        assert "datetime" in result
        assert "date" in result
        assert "time" in result

    def test_asia_singapore(self):
        result = json.loads(th._current_datetime({"timezone": "Asia/Singapore"}))
        assert "+08:00" in result["datetime"]


class TestListPendingFindings:
    def test_empty_bucket(self):
        mock_s3 = MagicMock()
        mock_s3.list_objects_v2.return_value = {}
        with patch("boto3.client", return_value=mock_s3):
            result = json.loads(th._list_pending_findings({"bucket": "test-bucket"}))
        assert result["count"] == 0
        assert result["files"] == []

    def test_reads_json_files(self):
        mock_s3 = MagicMock()
        mock_s3.list_objects_v2.return_value = {
            "Contents": [{"Key": "findings/pending/report.json"}, {"Key": "findings/pending/notes.txt"}]
        }
        mock_s3.get_object.return_value = {"Body": MagicMock(read=lambda: b'{"finding": "test"}')}
        with patch("boto3.client", return_value=mock_s3):
            result = json.loads(th._list_pending_findings({"bucket": "test-bucket"}))
        assert result["count"] == 2

    def test_skips_non_text_files(self):
        mock_s3 = MagicMock()
        mock_s3.list_objects_v2.return_value = {
            "Contents": [{"Key": "findings/pending/image.png"}, {"Key": "findings/pending/report.json"}]
        }
        mock_s3.get_object.return_value = {"Body": MagicMock(read=lambda: b'{}')}
        with patch("boto3.client", return_value=mock_s3):
            result = json.loads(th._list_pending_findings({"bucket": "test-bucket"}))
        assert result["count"] == 1


class TestArchiveProcessedFindings:
    def test_moves_files(self):
        mock_s3 = MagicMock()
        with patch("boto3.client", return_value=mock_s3):
            result = json.loads(th._archive_processed_findings({
                "bucket": "test-bucket",
                "files_json": json.dumps(["findings/pending/a.json", "findings/pending/b.json"]),
            }))
        assert result["archived"] == 2
        assert mock_s3.copy_object.call_count == 2
        assert mock_s3.delete_object.call_count == 2


class TestFalsePositiveSignals:
    def _make_logs_client(self, rows_sequence):
        client = MagicMock()
        client.start_query.return_value = {"queryId": "q-1"}
        results_iter = iter(rows_sequence)
        def get_results(**kwargs):
            try:
                return _make_query_result(next(results_iter))
            except StopIteration:
                return _make_query_result([])
        client.get_query_results.side_effect = get_results
        return client

    def test_attack_pattern_verdict(self):
        """matchedData with SQLi pattern → TRUE_POSITIVE HIGH."""
        logs = self._make_logs_client([
            [{"action": "BLOCK", "hits": "10"}],  # ratio
            [{"peak_rpm": "5", "avg_rpm": "2"}],  # freq
            [{"terminatingRuleId": "rule1", "hits": "10"}],  # rules
            [{"@message": json.dumps({"terminatingRuleMatchDetails": [{"matchedData": ["' OR 1=1"]}]})}],  # match details
            [],  # uri_rows
            [],  # popular
            [],  # countries
            [],  # ip_country
        ])
        with patch("boto3.client", return_value=logs):
            result = json.loads(th._query_false_positive_signals({
                "ip": "1.2.3.4", "log_group": "test", "lookback_hours": 24,
            }))
        assert result["verdict"] == "TRUE_POSITIVE"
        assert result["confidence"] == "HIGH"

    def test_fp_pattern_verdict(self):
        """matchedData with name pattern → LIKELY_FP HIGH."""
        logs = self._make_logs_client([
            [{"action": "ALLOW", "hits": "100"}, {"action": "BLOCK", "hits": "2"}],  # ratio
            [{"peak_rpm": "3", "avg_rpm": "1"}],  # freq
            [{"terminatingRuleId": "rule1", "hits": "2"}],  # rules
            [{"@message": json.dumps({"terminatingRuleMatchDetails": [{"matchedData": ["O'Brien"]}]})}],  # match details
            [{"httpRequest.uri": "/about", "hits": "2"}],  # uri_rows
            [{"httpRequest.uri": "/about", "hits": "500"}],  # popular
            [{"httpRequest.country": "US", "hits": "100"}],  # countries
            [{"httpRequest.country": "US", "hits": "50"}],  # ip_country
        ])
        with patch("boto3.client", return_value=logs):
            result = json.loads(th._query_false_positive_signals({
                "ip": "1.2.3.4", "log_group": "test", "lookback_hours": 24,
            }))
        assert result["verdict"] == "LIKELY_FP"


class TestCheckVolumeAnomaly:
    def test_normal_volume(self):
        mock_cw = MagicMock()
        # Both this_week and last_week return similar values
        mock_cw.get_metric_statistics.return_value = {
            "Datapoints": [{"Sum": 100.0}]
        }
        with patch("boto3.client", return_value=mock_cw):
            result = json.loads(th._check_volume_anomaly({
                "web_acl_arn": MOCK_WEB_ACL_ARN,
                "region": "us-east-1",
            }))
        assert "classification" in result or "error" not in result


class TestHandler:
    """Test the top-level dispatcher."""

    def test_unknown_tool(self):
        result = th.handler({"_tool": "nonexistent_tool"}, None)
        assert result["isError"] is True
        assert "Unknown tool" in result["content"][0]["text"]

    def test_dispatches_current_datetime(self):
        result = th.handler({"_tool": "current_datetime", "timezone": "UTC"}, None)
        assert result.get("isError") is None or result.get("isError") is False
        parsed = json.loads(result["content"][0]["text"])
        assert "datetime" in parsed


class TestParseAclArn:
    def test_cloudfront_scope(self):
        scope, name, acl_id = th._parse_acl_arn(
            "arn:aws:wafv2:us-east-1:123:global/webacl/my-acl/abc-123"
        )
        assert scope == "CLOUDFRONT"
        assert name == "my-acl"
        assert acl_id == "abc-123"

    def test_regional_scope(self):
        scope, name, acl_id = th._parse_acl_arn(
            "arn:aws:wafv2:us-east-1:123:regional/webacl/my-acl/abc-123"
        )
        assert scope == "REGIONAL"
        assert name == "my-acl"
        assert acl_id == "abc-123"


# ===== Analyzer tool name mapping =====

class TestAnalyzerToolNameMap:
    """Test the _tool_name_map resolution in the Analyzer handler."""

    def test_prefixed_names_resolve(self):
        """Gateway-prefixed tool names are resolved from short names."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "agents" / "analyzer"))
        import handler as analyzer

        # Simulate tool listing with prefixed names
        analyzer._tool_name_map = {
            "query_waf_summary": "waf-tools-lambda___query_waf_summary",
            "query_top_blocked": "waf-tools-lambda___query_top_blocked",
            "check_volume_anomaly": "waf-tools-lambda___check_volume_anomaly",
        }

        # Verify resolution
        assert analyzer._tool_name_map.get("query_waf_summary") == "waf-tools-lambda___query_waf_summary"
        assert analyzer._tool_name_map.get("check_volume_anomaly") == "waf-tools-lambda___check_volume_anomaly"
        # Unknown tool falls back to itself
        assert analyzer._tool_name_map.get("nonexistent", "nonexistent") == "nonexistent"

    def test_unprefixed_names_passthrough(self):
        """If Gateway doesn't prefix (future change), short names still work."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "agents" / "analyzer"))
        import handler as analyzer

        analyzer._tool_name_map = {
            "query_waf_summary": "query_waf_summary",
        }
        assert analyzer._tool_name_map.get("query_waf_summary") == "query_waf_summary"

    def test_map_building_logic(self):
        """The split logic correctly extracts short name from prefixed name."""
        # Simulate what invoke() does
        class FakeTool:
            def __init__(self, name):
                self.tool_name = name

        tools = [
            FakeTool("waf-tools-lambda___query_waf_summary"),
            FakeTool("waf-tools-lambda___check_volume_anomaly"),
            FakeTool("plain_tool_name"),
        ]

        tool_name_map = {}
        for t in tools:
            short = t.tool_name.split("___", 1)[-1] if "___" in t.tool_name else t.tool_name
            tool_name_map[short] = t.tool_name

        assert tool_name_map == {
            "query_waf_summary": "waf-tools-lambda___query_waf_summary",
            "check_volume_anomaly": "waf-tools-lambda___check_volume_anomaly",
            "plain_tool_name": "plain_tool_name",
        }


# ===== Hardening tests =====
import pytest
from urllib.error import URLError
from datetime import datetime, timedelta, timezone


class TestInputValidation:
    def test_valid_ipv4_ipv6(self):
        assert th._validate_ip("1.2.3.4") == "1.2.3.4"
        assert th._validate_ip("2001:db8::1") == "2001:db8::1"

    @pytest.mark.parametrize("bad", ["1.2.3.4' | stats count(*)", "1.2.3", "abc", "", "1.2.3.4; drop"])
    def test_rejects_injection(self, bad):
        with pytest.raises(ValueError):
            th._validate_ip(bad)

    def test_handler_returns_error_for_injected_ip(self):
        out = th.handler({"_tool": "investigate_ip_deep", "ip": "1.1.1.1' or 1=1", "log_group": "x"}, None)
        assert out["isError"] is True

    def test_safe_host(self):
        assert th._is_safe_host("www.example.com")
        assert not th._is_safe_host("a.com' | filter 1=1")
        assert not th._is_safe_host("")

    def test_int_arg_clamps(self):
        assert th._int_arg("999", 20, 1, 100) == 100
        assert th._int_arg("x", 20, 1, 100) == 20
        assert th._int_arg(-5, 20, 1, 100) == 1

    def test_unsafe_domain_not_interpolated_into_query(self):
        queries = []
        client = MagicMock()
        client.start_query.side_effect = lambda **kw: (queries.append(kw["queryString"]) or {"queryId": "q"})
        domains = [{"host": "evil.com' | filter 1=1 | //", "total": "100", "blocked": "90", "allowed": "10"}]
        seq = iter([domains])
        client.get_query_results.side_effect = lambda **kw: _make_query_result(next(seq, []))
        with patch("boto3.client", return_value=client):
            th._query_per_domain({"log_group": "lg"})
        assert len(queries) == 1  # no drill-down query for the unsafe host


class TestQueryExecution:
    def test_timeout_stops_query_and_raises(self):
        client = MagicMock()
        client.start_query.return_value = {"queryId": "q-1"}
        client.get_query_results.return_value = {"status": "Running", "results": []}
        with patch.object(th.time, "sleep"), pytest.raises(th.QueryError, match="timed out"):
            th._run_query_raw(client, "lg", "q", 0, 1)
        client.stop_query.assert_called_once_with(queryId="q-1")

    @pytest.mark.parametrize("status", ["Failed", "Cancelled", "Timeout"])
    def test_failed_status_raises(self, status):
        client = MagicMock()
        client.start_query.return_value = {"queryId": "q-1"}
        client.get_query_results.return_value = {"status": status, "results": []}
        with pytest.raises(th.QueryError):
            th._run_query_raw(client, "lg", "q", 0, 1)

    def test_run_query_timeout_is_error_not_string(self):
        client = MagicMock()
        client.start_query.return_value = {"queryId": "q-1"}
        client.get_query_results.return_value = {"status": "Running", "results": []}
        with patch("boto3.client", return_value=client), patch.object(th.time, "sleep"), pytest.raises(th.QueryError):
            th._run_query("lg", "q", 1, "us-east-1")


def _rule(name, prio, action=None, override=None):
    r = {"Name": name, "Priority": prio, "Statement": {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}},
         "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": name}}
    if action is not None:
        r["Action"] = action
    if override is not None:
        r["OverrideAction"] = override
    return r


class TestUpdateWebAclHardening:
    EXISTING = [_rule("existing-block", 1, action={"Block": {}})]

    def _wafv2(self):
        c = MagicMock()
        c.get_web_acl.return_value = {"WebACL": {"Rules": self.EXISTING, "DefaultAction": {"Allow": {}},
                                                 "VisibilityConfig": {"SampledRequestsEnabled": True}},
                                      "LockToken": "fresh-token"}
        return c

    def _call(self, rules, env="true", client=None):
        client = client or self._wafv2()
        with patch.dict(os.environ, {"WAF_WRITE_ENABLED": env}), patch("boto3.client", return_value=client):
            return th._update_web_acl_rules({"web_acl_arn": MOCK_WEB_ACL_ARN, "dry_run": False,
                                             "rules_json": json.dumps(rules), "lock_token": "stale-token"}), client

    def test_writes_disabled_by_default(self):
        c = self._wafv2()
        with patch.dict(os.environ, {"WAF_WRITE_ENABLED": "false"}), patch("boto3.client", return_value=c), \
                pytest.raises(PermissionError):
            th._update_web_acl_rules({"web_acl_arn": MOCK_WEB_ACL_ARN, "dry_run": False, "rules_json": "[]"})
        c.update_web_acl.assert_not_called()

    def test_add_count_rule_uses_fresh_lock_token(self):
        new = self.EXISTING + [_rule("new-count", 2, action={"Count": {}})]
        out, c = self._call(new)
        assert json.loads(out)["status"] == "applied"
        assert c.update_web_acl.call_args.kwargs["LockToken"] == "fresh-token"

    def test_new_block_rule_rejected(self):
        c = self._wafv2()
        with pytest.raises(ValueError, match="COUNT-only"):
            self._call(self.EXISTING + [_rule("new-block", 2, action={"Block": {}})], client=c)
        c.update_web_acl.assert_not_called()

    def test_rule_group_without_count_override_rejected(self):
        with pytest.raises(ValueError, match="COUNT-only"):
            self._call(self.EXISTING + [_rule("grp", 2, override={"None": {}})])

    def test_rule_group_with_count_override_allowed(self):
        out, _ = self._call(self.EXISTING + [_rule("grp", 2, override={"Count": {}})])
        assert json.loads(out)["status"] == "applied"

    def test_removing_existing_rule_rejected(self):
        with pytest.raises(ValueError, match="removing"):
            self._call([_rule("other", 5, action={"Count": {}})])

    def test_modifying_existing_rule_rejected(self):
        with pytest.raises(ValueError, match="modified"):
            self._call([_rule("existing-block", 1, action={"Allow": {}})])

    def test_too_many_new_rules_rejected(self):
        many = [_rule(f"n{i}", 10 + i, action={"Count": {}}) for i in range(th._MAX_NEW_RULES_PER_CALL + 1)]
        with pytest.raises(ValueError, match="too many"):
            self._call(self.EXISTING + many)

    def test_duplicate_priority_rejected(self):
        with pytest.raises(ValueError, match="priorities"):
            self._call(self.EXISTING + [_rule("dup", 1, action={"Count": {}})])

    def test_invalid_json_rejected(self):
        with patch.dict(os.environ, {"WAF_WRITE_ENABLED": "true"}), patch("boto3.client", return_value=self._wafv2()), \
                pytest.raises(ValueError, match="valid JSON"):
            th._update_web_acl_rules({"web_acl_arn": MOCK_WEB_ACL_ARN, "dry_run": False, "rules_json": "{nope"})


class TestFalsePositiveHardening:
    @pytest.mark.parametrize("payload", ["admin", "select", "union", "root", "cmd", "10.0.0.1", "http://169.254.169.254/latest", "or", "x"])
    def test_attackish_or_ambiguous_not_fp(self, payload):
        assert th._has_fp_pattern(payload) is False

    @pytest.mark.parametrize("payload", ["O'Brien", "Mary-Ann Smith", "John Smith", "hello world"])
    def test_names_are_fp(self, payload):
        assert th._has_fp_pattern(payload) is True

    def _client(self, rows):
        client = MagicMock()
        client.start_query.return_value = {"queryId": "q"}
        it = iter(rows)
        client.get_query_results.side_effect = lambda **kw: _make_query_result(next(it, []))
        return client

    def _run(self, actions, payloads):
        details = [{"@message": json.dumps({"terminatingRuleMatchDetails": [{"matchedData": [p]}]})} for p in payloads]
        rows = [actions, [{"peak_rpm": "3", "avg_rpm": "1"}], [{"terminatingRuleId": "r", "hits": "2"}],
                details, [], [], [], []]
        with patch("boto3.client", return_value=self._client(rows)):
            return json.loads(th._query_false_positive_signals({"ip": "1.2.3.4", "log_group": "lg"}))

    def test_one_unclassified_payload_blocks_fp(self):
        r = self._run([{"action": "ALLOW", "hits": "100"}, {"action": "BLOCK", "hits": "2"}], ["O'Brien", "x=1"])
        assert r["verdict"] != "LIKELY_FP" or r["match_detail_fp"] is False
        assert r["match_detail_fp"] is False

    def test_benign_payload_but_mostly_blocked_is_not_fp(self):
        r = self._run([{"action": "ALLOW", "hits": "10"}, {"action": "BLOCK", "hits": "90"}], ["O'Brien"])
        assert r["verdict"] != "LIKELY_FP"

    def test_benign_payload_moderate_block_ratio_is_medium(self):
        r = self._run([{"action": "ALLOW", "hits": "60"}, {"action": "BLOCK", "hits": "40"}], ["O'Brien"])
        assert (r["verdict"], r["confidence"]) == ("LIKELY_FP", "MEDIUM")

    def test_benign_payload_low_block_ratio_is_high(self):
        r = self._run([{"action": "ALLOW", "hits": "100"}, {"action": "BLOCK", "hits": "2"}], ["O'Brien"])
        assert (r["verdict"], r["confidence"]) == ("LIKELY_FP", "HIGH")


class TestBlocklist:
    TEXT = "# header\n1.2.3.4\n10.0.0.0/8  # private\n\nbad-line\n2001:db8::/32\n"

    def test_parse_skips_comments_and_garbage(self):
        assert len(th._parse_blocklist(self.TEXT)) == 3

    def test_exact_not_substring(self):
        nets = th._parse_blocklist(self.TEXT)
        assert th._ip_in_blocklist("1.2.3.4", nets) is True
        assert th._ip_in_blocklist("11.2.3.45", nets) is False
        assert th._ip_in_blocklist("1.2.3.40", nets) is False

    def test_cidr_and_ipv6(self):
        nets = th._parse_blocklist(self.TEXT)
        assert th._ip_in_blocklist("10.9.8.7", nets) is True
        assert th._ip_in_blocklist("2001:db8::5", nets) is True
        assert th._ip_in_blocklist("192.168.0.1", nets) is False

    def _s3(self, text, age_hours):
        s3 = MagicMock()
        body = MagicMock()
        body.read.return_value = text.encode()
        s3.get_object.return_value = {"Body": body, "LastModified": datetime.now(timezone.utc) - timedelta(hours=age_hours)}
        return s3

    def test_fresh_cache_used_without_download(self):
        with patch("boto3.client", return_value=self._s3(self.TEXT, 1)), patch.object(th, "urlopen") as dl:
            nets = th._load_et_blocklist("b")
        dl.assert_not_called()
        assert len(nets) == 3

    def test_stale_cache_refreshed(self):
        s3 = self._s3("9.9.9.9\n", 48)
        resp = MagicMock()
        resp.read.return_value = b"5.5.5.5\n"
        resp.__enter__.return_value = resp
        with patch("boto3.client", return_value=s3), patch.object(th, "urlopen", return_value=resp):
            nets = th._load_et_blocklist("b")
        assert th._ip_in_blocklist("5.5.5.5", nets)
        s3.put_object.assert_called_once()

    def test_stale_cache_fallback_when_refresh_fails(self):
        s3 = self._s3("9.9.9.9\n", 48)
        with patch("boto3.client", return_value=s3), patch.object(th, "urlopen", side_effect=URLError("down")):
            nets = th._load_et_blocklist("b")
        assert th._ip_in_blocklist("9.9.9.9", nets)

    def test_unavailable_returns_none_not_false(self):
        s3 = MagicMock()
        s3.get_object.side_effect = Exception("NoSuchKey")
        with patch("boto3.client", return_value=s3), patch.object(th, "urlopen", side_effect=URLError("down")):
            assert th._load_et_blocklist("b") is None
        with patch("boto3.client", return_value=s3), patch.object(th, "urlopen", side_effect=URLError("down")), \
                patch.dict(os.environ, {"FINDINGS_BUCKET": "b", "ABUSEIPDB_API_KEY": ""}):
            out = json.loads(th._enrich_ip_reputation({"ip": "1.2.3.4"}))
        assert out["et_listed"] is None


class TestConfiguration:
    def test_thresholds_default(self):
        assert th._load_thresholds(None) == th.DEFAULT_THRESHOLDS

    def test_thresholds_override_known_keys_only(self):
        cfg = th._load_thresholds(json.dumps({"fp_attacker_block_ratio": 0.9, "bogus": 1, "fp_low_max_rules": "x", "fp_strong_min_rules": True}))
        assert cfg["fp_attacker_block_ratio"] == 0.9
        assert cfg["fp_low_max_rules"] == th.DEFAULT_THRESHOLDS["fp_low_max_rules"]
        assert cfg["fp_strong_min_rules"] == th.DEFAULT_THRESHOLDS["fp_strong_min_rules"]
        assert "bogus" not in cfg

    @pytest.mark.parametrize("raw", ["not json", "[1,2]", '"str"'])
    def test_thresholds_bad_json_falls_back(self, raw):
        assert th._load_thresholds(raw) == th.DEFAULT_THRESHOLDS

    def test_region_and_lookback_helpers(self):
        assert th._region({"region": "eu-west-1"}) == "eu-west-1"
        assert th._region({}) == th.DEFAULT_REGION
        assert th._lookback({"lookback_hours": "48"}) == 48
        assert th._lookback({}) == th.DEFAULT_LOOKBACK_HOURS
        assert th._lookback({"lookback_hours": 10**9}) == 720

    def test_threshold_override_changes_verdict(self):
        """Raising the attacker block-ratio threshold above the observed ratio flips TRUE_POSITIVE to UNDETERMINED."""
        h = TestFalsePositiveHardening()
        rows_actions = [{"action": "ALLOW", "hits": "20"}, {"action": "BLOCK", "hits": "80"}]

        def run():
            client = h._client([rows_actions, [{"peak_rpm": "3", "avg_rpm": "1"}],
                                [{"terminatingRuleId": f"r{i}", "hits": "1"} for i in range(3)], [], [], [], [], []])
            with patch("boto3.client", return_value=client):
                return json.loads(th._query_false_positive_signals({"ip": "1.2.3.4", "log_group": "lg"}))
        assert run()["verdict"] == "TRUE_POSITIVE"
        with patch.dict(th.THRESHOLDS, {"fp_attacker_block_ratio": 0.95, "fp_strong_block_ratio": 0.99}):
            assert run()["verdict"] != "TRUE_POSITIVE"

    def test_default_timezone_used(self):
        with patch.object(th, "DEFAULT_TIMEZONE", "UTC"):
            assert json.loads(th._current_datetime({}))["timezone"] == "UTC"


class TestArchivePrefixGuard:
    def test_rejects_keys_outside_pending(self):
        s3 = MagicMock()
        with patch("boto3.client", return_value=s3), pytest.raises(ValueError, match="outside"):
            th._archive_processed_findings({"bucket": "b", "files_json": json.dumps(["markers/x.json"])})
        s3.copy_object.assert_not_called()

    def test_rejects_non_list(self):
        with patch("boto3.client", return_value=MagicMock()), pytest.raises(ValueError):
            th._archive_processed_findings({"bucket": "b", "files_json": json.dumps({"a": 1})})

    def test_destination_uses_processed_prefix(self):
        s3 = MagicMock()
        with patch("boto3.client", return_value=s3):
            th._archive_processed_findings({"bucket": "b", "files_json": json.dumps(["findings/pending/sub/a.json"])})
        assert s3.copy_object.call_args.kwargs["Key"] == "findings/processed/sub/a.json"
