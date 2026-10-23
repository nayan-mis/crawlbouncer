"""
Tests for app/middleware/waf.py and app/security/waf_rules.py
Every rule is tested with a payload that SHOULD trigger it
and a clean request that should NOT trigger it.
"""
import pytest
from app.middleware.waf import waf, WAFEngine
from app.security.waf_rules import RULES, RULE_MAP


# ─────────────────────────────────────────────────────────────────
# SQL INJECTION
# ─────────────────────────────────────────────────────────────────

class TestSQLInjection:

    def test_union_select_blocked(self):
        r = waf.check(query_string="id=1 UNION SELECT username,password FROM users")
        assert r.blocked
        assert r.rule.id == "SQLi-001"

    def test_union_all_select_blocked(self):
        r = waf.check(query_string="id=1 UNION ALL SELECT 1,2,3")
        assert r.blocked

    def test_boolean_injection_blocked(self):
        r = waf.check(query_string="id=1' OR '1'='1")
        assert r.blocked
        assert r.rule.id == "SQLi-002"

    def test_drop_table_blocked(self):
        r = waf.check(query_string="id=1; DROP TABLE users")
        assert r.blocked
        assert r.rule.id == "SQLi-003"

    def test_sleep_based_blocked(self):
        r = waf.check(query_string="id=1; SLEEP(5)")
        assert r.blocked
        assert r.rule.id == "SQLi-004"

    def test_clean_sql_query_passes(self):
        r = waf.check(query_string="search=hello+world&page=1")
        assert not r.blocked

    def test_normal_id_param_passes(self):
        r = waf.check(query_string="id=42&category=news")
        assert not r.blocked


# ─────────────────────────────────────────────────────────────────
# CROSS-SITE SCRIPTING (XSS)
# ─────────────────────────────────────────────────────────────────

class TestXSS:

    def test_script_tag_blocked(self):
        r = waf.check(query_string="q=<script>alert(1)</script>")
        assert r.blocked
        assert r.rule.id == "XSS-001"

    def test_script_tag_with_space_blocked(self):
        r = waf.check(query_string='q=<script src="evil.js">')
        assert r.blocked

    def test_javascript_protocol_blocked(self):
        r = waf.check(query_string="url=javascript:alert(document.cookie)")
        assert r.blocked
        assert r.rule.id == "XSS-002"

    def test_onclick_handler_blocked(self):
        r = waf.check(body='<div onclick="stealCookies()">click me</div>')
        assert r.blocked
        assert r.rule.id == "XSS-003"

    def test_onerror_handler_blocked(self):
        r = waf.check(body='<img src=x onerror=alert(1)>')
        assert r.blocked

    def test_clean_html_passes(self):
        r = waf.check(body="<p>This is a normal paragraph.</p>")
        assert not r.blocked

    def test_search_query_passes(self):
        r = waf.check(query_string="q=how+to+learn+python")
        assert not r.blocked


# ─────────────────────────────────────────────────────────────────
# PATH TRAVERSAL
# ─────────────────────────────────────────────────────────────────

class TestPathTraversal:

    def test_unix_traversal_blocked(self):
        r = waf.check(path="/images/../../../etc/passwd")
        assert r.blocked
        assert r.rule.id == "PT-001"

    def test_encoded_traversal_blocked(self):
        r = waf.check(path="/files/..%2F..%2Fetc%2Fpasswd")
        assert r.blocked

    def test_etc_passwd_blocked(self):
        r = waf.check(path="/etc/passwd")
        assert r.blocked
        assert r.rule.id == "PT-002"

    def test_proc_self_blocked(self):
        r = waf.check(path="/proc/self/environ")
        assert r.blocked

    def test_normal_path_passes(self):
        r = waf.check(path="/article/how-to-use-python")
        assert not r.blocked

    def test_deep_normal_path_passes(self):
        r = waf.check(path="/blog/2026/07/my-article-title")
        assert not r.blocked


# ─────────────────────────────────────────────────────────────────
# COMMAND INJECTION
# ─────────────────────────────────────────────────────────────────

class TestCommandInjection:

    def test_semicolon_cat_blocked(self):
        r = waf.check(query_string="file=report.txt; cat /etc/passwd")
        assert r.blocked
        assert r.rule.id == "CMDi-001"

    def test_pipe_id_blocked(self):
        r = waf.check(query_string="cmd=ls | id")
        assert r.blocked

    def test_backtick_blocked(self):
        r = waf.check(query_string="name=`whoami`")
        assert r.blocked
        assert r.rule.id == "CMDi-002"

    def test_dollar_subshell_blocked(self):
        r = waf.check(query_string="x=$(id)")
        assert r.blocked

    def test_normal_filename_passes(self):
        r = waf.check(query_string="file=annual-report-2026.pdf")
        assert not r.blocked


# ─────────────────────────────────────────────────────────────────
# SSRF
# ─────────────────────────────────────────────────────────────────

class TestSSRF:

    def test_internal_ip_blocked(self):
        r = waf.check(query_string="url=http://192.168.1.1/admin")
        assert r.blocked
        assert r.rule.id == "SSRF-001"

    def test_localhost_blocked(self):
        r = waf.check(query_string="callback=http://127.0.0.1:8080/secret")
        assert r.blocked

    def test_aws_metadata_blocked(self):
        r = waf.check(query_string="url=http://169.254.169.254/latest/meta-data/")
        assert r.blocked
        assert r.rule.id == "SSRF-002"

    def test_public_url_passes(self):
        r = waf.check(query_string="url=https://example.com/page")
        assert not r.blocked


# ─────────────────────────────────────────────────────────────────
# SENSITIVE FILES
# ─────────────────────────────────────────────────────────────────

class TestSensitiveFiles:

    def test_env_file_blocked(self):
        r = waf.check(path="/.env")
        assert r.blocked

    def test_git_config_blocked(self):
        r = waf.check(path="/.git/config")
        assert r.blocked

    def test_htpasswd_blocked(self):
        r = waf.check(path="/.htpasswd")
        assert r.blocked

    def test_sql_dump_blocked(self):
        r = waf.check(path="/backup.sql")
        assert r.blocked

    def test_normal_files_pass(self):
        for path in ["/style.css", "/app.js", "/logo.png", "/sitemap.xml"]:
            r = waf.check(path=path)
            assert not r.blocked, f"Should not block: {path}"


# ─────────────────────────────────────────────────────────────────
# NULL BYTE
# ─────────────────────────────────────────────────────────────────

def test_null_byte_blocked():
    r = waf.check(path="/index.php%00.jpg")
    assert r.blocked
    assert r.rule.id == "NULL-001"


# ─────────────────────────────────────────────────────────────────
# XXE
# ─────────────────────────────────────────────────────────────────

def test_xxe_blocked():
    payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    r = waf.check(body=payload)
    assert r.blocked
    assert r.rule.id == "XXE-001"


# ─────────────────────────────────────────────────────────────────
# RULE REGISTRY
# ─────────────────────────────────────────────────────────────────

def test_twenty_rules_exist():
    assert len(RULES) == 20, f"Expected 20 WAF rules, got {len(RULES)}"

def test_all_rules_have_unique_ids():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids)), "Duplicate rule IDs detected"

def test_all_rules_have_valid_severity():
    valid = {"critical", "high", "medium", "low"}
    for rule in RULES:
        assert rule.severity in valid, f"Rule {rule.id} has invalid severity: {rule.severity}"

def test_all_rules_have_valid_action():
    valid = {"block", "log"}
    for rule in RULES:
        assert rule.action in valid, f"Rule {rule.id} has invalid action: {rule.action}"

def test_rule_map_matches_rules():
    for rule in RULES:
        assert rule.id in RULE_MAP

def test_waf_result_blocked_is_false_for_clean_request():
    r = waf.check(path="/article/python-tutorial", query_string="page=1")
    assert not r.blocked
    assert r.rule is None
    assert r.matched_value == ""


# ─────────────────────────────────────────────────────────────────
# MULTIPLE ATTACK VECTORS IN ONE REQUEST
# ─────────────────────────────────────────────────────────────────

def test_first_matching_rule_returned():
    """WAF returns the first matching rule, not all matches."""
    r = waf.check(
        path="/../../etc/passwd",
        query_string="id=1 UNION SELECT * FROM users"
    )
    assert r.blocked
    assert r.rule is not None         # some rule fired
    assert r.matched_value != ""


# ─────────────────────────────────────────────────────────────────
# BODY CHECKS
# ─────────────────────────────────────────────────────────────────

def test_body_check_works():
    r = waf.check(body="'; DROP TABLE publishers; --")
    assert r.blocked
    assert r.location in ("body", "query", "path")

def test_large_body_capped():
    """WAF should not hang or OOM on very large bodies."""
    big_body = "a" * 100_000
    r = waf.check(body=big_body)
    assert not r.blocked          # no attack, should pass cleanly
