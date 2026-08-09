"""Unit tests for SentinelScan v2."""

import json
import os
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from sentinelscan.analyzers.base import BaseAnalyzer, Finding
from sentinelscan.analyzers.cookies import CookiesAnalyzer
from sentinelscan.analyzers.cors import CorsAnalyzer
from sentinelscan.analyzers.crawler import CrawlerAnalyzer
from sentinelscan.analyzers.cve_fingerprint import CveFingerprintAnalyzer
from sentinelscan.analyzers.dns import DnsAnalyzer
from sentinelscan.analyzers.headers import REQUIRED_HEADERS, HeadersAnalyzer
from sentinelscan.analyzers.owasp import OwaspAnalyzer
from sentinelscan.analyzers.ports import COMMON_PORTS, PortsAnalyzer
from sentinelscan.analyzers.ssl_tls import SslTlsAnalyzer
from sentinelscan.analyzers.subdomains import SubdomainsAnalyzer
from sentinelscan.cli import (
    EXIT_ERROR,
    EXIT_GATE_TRIPPED,
    EXIT_OK,
    TIMING_PROFILES,
    _expand_target,
    build_parser,
    main,
    maybe_show_disclaimer,
    parse_headers,
    resolve_targets,
    run_doctor,
)
from sentinelscan.config_file import load_profile
from sentinelscan.plugins import load_plugins
from sentinelscan.reporters.html_reporter import HtmlReporter
from sentinelscan.reporters.json_reporter import JsonReporter
from sentinelscan.reporters.sarif_reporter import SarifReporter
from sentinelscan.reporters.text_reporter import TextReporter
from sentinelscan.scanner import Scanner
from sentinelscan.updater import update_signatures

# Every main() call in this suite must not touch the real ~/.config/sentinelscan/
# (including on CI runners). TestDisclaimer below explicitly overrides this to
# test the real behavior.
os.environ["SENTINELSCAN_SKIP_DISCLAIMER"] = "1"


class _FakeNXDOMAIN(Exception):
    pass


class _FakeRdata:
    def __init__(self, text):
        self._text = text

    def __str__(self):
        return self._text


def _make_ctx(headers=None, cookies=None, url="https://example.com", status=200):
    response = MagicMock()
    response.headers = headers or {}
    response.cookies = cookies or []
    response.status_code = status
    response.url = url
    response.text = ""
    return {
        "target": "example.com",
        "url": url,
        "response": response,
        "session": MagicMock(),
        "timeout": 5,
        "verbose": False,
    }


class TestFindingSanitization(unittest.TestCase):
    """Finding fields must never carry raw control/escape bytes into a report.

    Findings routinely embed content pulled straight from a scanned target
    (banners, headers, crawled URLs). Printing that unsanitized to a terminal
    would let a malicious target inject ANSI escape sequences -- e.g. to hide
    other findings in the same report. See base.py's Finding.__init__.
    """

    def test_escape_sequences_stripped_from_all_fields(self):
        finding = Finding(
            title="t\x1b[2Ktitle",
            description="d\x1b[31mdescription",
            severity="high",
            remediation="r\x1b]0;pwned\x07emediation",
            reference="https://example.com/\x1b[Href",
            evidence="e\x07vidence",
        )
        data = finding.to_dict()
        for field in ("title", "description", "remediation", "reference", "evidence"):
            self.assertNotIn("\x1b", data[field])
            self.assertNotIn("\x07", data[field])

    def test_normal_text_passes_through_unchanged(self):
        finding = Finding(
            title="Missing Header: X-Frame-Options",
            description="Clickjacking risk.",
            severity="medium",
            evidence="X-Frame-Options: absent",
        )
        data = finding.to_dict()
        self.assertEqual(data["title"], "Missing Header: X-Frame-Options")
        self.assertEqual(data["evidence"], "X-Frame-Options: absent")


class TestHeadersAnalyzer(unittest.TestCase):

    def test_missing_all_security_headers(self):
        ctx = _make_ctx(headers={})
        analyzer = HeadersAnalyzer(ctx)
        result = analyzer.run()
        findings = result["findings"]
        severities = {f["severity"] for f in findings}
        titles = [f["title"] for f in findings]
        self.assertIn("high", severities)
        self.assertTrue(any("Content-Security-Policy" in t for t in titles))
        self.assertTrue(any("Strict-Transport-Security" in t for t in titles))

    def test_all_security_headers_present(self):
        ctx = _make_ctx(
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=()",
            }
        )
        analyzer = HeadersAnalyzer(ctx)
        result = analyzer.run()
        missing = result.get("headers_missing", [])
        self.assertEqual(missing, [])

    def test_weak_csp_detected(self):
        ctx = _make_ctx(headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
        analyzer = HeadersAnalyzer(ctx)
        result = analyzer.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("unsafe-inline" in t for t in titles))

    def test_server_header_info_disclosure(self):
        ctx = _make_ctx(headers={"Server": "Apache/2.4.51 (Ubuntu)"})
        analyzer = HeadersAnalyzer(ctx)
        result = analyzer.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Server" in t for t in titles))

    def test_hsts_short_max_age(self):
        ctx = _make_ctx(headers={"Strict-Transport-Security": "max-age=3600"})
        analyzer = HeadersAnalyzer(ctx)
        result = analyzer.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("HSTS max-age Too Short" in t for t in titles))


class TestCorsAnalyzer(unittest.TestCase):

    def test_wildcard_origin(self):
        ctx = _make_ctx()
        mock_response = MagicMock()
        mock_response.headers = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "false"}
        ctx["session"].get.return_value = mock_response
        analyzer = CorsAnalyzer(ctx)
        result = analyzer.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Wildcard" in t for t in titles))

    def test_origin_reflection(self):
        ctx = _make_ctx()
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
        }
        ctx["session"].get.return_value = mock_response
        analyzer = CorsAnalyzer(ctx)
        result = analyzer.run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Reflection" in t for t in titles))


class TestCookiesAnalyzer(unittest.TestCase):

    def _ctx_with_set_cookie(self, raw_values):
        response = MagicMock()
        response.raw.headers.getlist.return_value = raw_values
        return {
            "target": "example.com",
            "url": "https://example.com",
            "response": response,
            "session": MagicMock(),
            "timeout": 5,
            "verbose": False,
        }

    def test_no_cookies_found(self):
        ctx = self._ctx_with_set_cookie([])
        result = CookiesAnalyzer(ctx).run()
        self.assertEqual(result["total_cookies"], 0)
        titles = [f["title"] for f in result["findings"]]
        self.assertIn("No Cookies Detected", titles)

    def test_missing_secure_and_httponly(self):
        ctx = self._ctx_with_set_cookie(["sessionid=abc123; Path=/"])
        result = CookiesAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Missing Secure Flag" in t for t in titles))
        self.assertTrue(any("Missing HttpOnly Flag" in t for t in titles))
        self.assertTrue(any("Missing SameSite Attribute" in t for t in titles))
        # session-like cookie name should escalate severity to high
        secure_finding = next(f for f in result["findings"] if "Secure Flag" in f["title"])
        self.assertEqual(secure_finding["severity"], "high")

    def test_samesite_none_without_secure_is_flagged(self):
        ctx = self._ctx_with_set_cookie(["theme=dark; Path=/; SameSite=None"])
        result = CookiesAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("SameSite=None Without Secure" in t for t in titles))

    def test_fully_secure_cookie_has_no_flag_findings(self):
        ctx = self._ctx_with_set_cookie(["sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"])
        result = CookiesAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertFalse(any("Missing" in t for t in titles))

    def test_multiple_set_cookie_headers_all_parsed(self):
        ctx = self._ctx_with_set_cookie(
            [
                "a=1; Path=/; Secure; HttpOnly; SameSite=Strict",
                "b=2; Path=/; Secure; HttpOnly; SameSite=Strict",
            ]
        )
        result = CookiesAnalyzer(ctx).run()
        self.assertEqual(result["total_cookies"], 2)

    def test_falls_back_to_merged_header_when_raw_unavailable(self):
        response = MagicMock()
        response.raw = None
        response.headers = {"Set-Cookie": "plain=1; Path=/"}
        ctx = {
            "target": "example.com",
            "url": "https://example.com",
            "response": response,
            "session": MagicMock(),
            "timeout": 5,
            "verbose": False,
        }
        result = CookiesAnalyzer(ctx).run()
        self.assertEqual(result["total_cookies"], 1)


class TestCliFollowRedirects(unittest.TestCase):

    def test_follow_redirects_default_true(self):
        args = build_parser().parse_args(["example.com"])
        self.assertTrue(args.follow_redirects)

    def test_no_follow_redirects_sets_false(self):
        args = build_parser().parse_args(["example.com", "--no-follow-redirects"])
        self.assertFalse(args.follow_redirects)

    def test_explicit_follow_redirects_sets_true(self):
        args = build_parser().parse_args(["example.com", "--follow-redirects"])
        self.assertTrue(args.follow_redirects)


class TestJsonReporter(unittest.TestCase):

    def _sample_results(self):
        return {
            "example.com": {
                "__meta__": {
                    "target": "example.com",
                    "url": "https://example.com",
                    "risk_score": 30,
                    "risk_grade": "C",
                    "status_code": 200,
                    "final_url": "https://example.com",
                    "scanned_modules": ["headers"],
                },
                "headers": {
                    "findings": [
                        {
                            "title": "Missing Header: Content-Security-Policy",
                            "description": "CSP missing",
                            "severity": "high",
                            "remediation": "Add CSP",
                            "reference": "",
                            "evidence": "",
                        }
                    ],
                    "headers_present": [],
                    "headers_missing": ["Content-Security-Policy"],
                    "total_headers": 3,
                    "_elapsed_ms": 45,
                },
            }
        }

    def test_json_output_is_valid(self):
        reporter = JsonReporter()
        output = reporter.render(self._sample_results())
        parsed = json.loads(output)
        self.assertIn("targets", parsed)
        self.assertIn("summary", parsed)
        self.assertEqual(parsed["summary"]["total_findings"], 1)
        self.assertEqual(parsed["summary"]["by_severity"]["high"], 1)

    def test_severity_filter(self):
        reporter = JsonReporter(severity_filter=["critical"])
        output = reporter.render(self._sample_results())
        parsed = json.loads(output)
        self.assertEqual(parsed["summary"]["total_findings"], 0)


class TestTextReporter(unittest.TestCase):

    def test_text_output_contains_target(self):
        results = {
            "example.com": {
                "__meta__": {
                    "target": "example.com",
                    "url": "https://example.com",
                    "risk_score": 0,
                    "risk_grade": "A+",
                    "status_code": 200,
                    "final_url": "https://example.com",
                    "scanned_modules": ["headers"],
                },
                "headers": {"findings": [], "_elapsed_ms": 10},
            }
        }
        reporter = TextReporter(no_color=True)
        output = reporter.render(results)
        self.assertIn("EXAMPLE.COM", output.upper())
        self.assertIn("A+", output)


class TestHtmlReporter(unittest.TestCase):

    def test_html_output_is_valid(self):
        results = {
            "example.com": {
                "__meta__": {
                    "target": "example.com",
                    "url": "https://example.com",
                    "risk_score": 20,
                    "risk_grade": "B",
                    "status_code": 200,
                    "final_url": "https://example.com",
                    "scanned_modules": ["headers"],
                },
                "headers": {
                    "findings": [
                        {
                            "title": "Missing Header: X-Frame-Options",
                            "description": "Clickjacking risk",
                            "severity": "medium",
                            "remediation": "Add X-Frame-Options",
                            "reference": "",
                            "evidence": "",
                        }
                    ],
                    "_elapsed_ms": 12,
                },
            }
        }
        reporter = HtmlReporter()
        output = reporter.render(results)
        self.assertIn("<!DOCTYPE html>", output)
        self.assertIn("SENTINELSCAN", output)
        self.assertIn("X-Frame-Options", output)
        self.assertIn("medium", output.lower())


class TestSarifReporter(unittest.TestCase):

    def _sample_results(self):
        return {
            "example.com": {
                "__meta__": {
                    "risk_score": 20,
                    "risk_grade": "B",
                    "final_url": "https://example.com",
                },
                "headers": {
                    "findings": [
                        {
                            "title": "Missing Header: X-Frame-Options",
                            "description": "Clickjacking risk",
                            "severity": "medium",
                            "remediation": "Add X-Frame-Options",
                            "reference": "",
                            "evidence": "",
                        },
                        {
                            "title": "Missing Header: Content-Security-Policy",
                            "description": "XSS risk",
                            "severity": "high",
                            "remediation": "Add a CSP",
                            "reference": "",
                            "evidence": "",
                        },
                    ],
                    "_elapsed_ms": 12,
                },
            }
        }

    def test_output_is_valid_sarif_json(self):
        output = SarifReporter().render(self._sample_results())
        parsed = json.loads(output)
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertEqual(len(parsed["runs"]), 1)
        run = parsed["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "SentinelScan")
        self.assertEqual(len(run["results"]), 2)

    def test_findings_grouped_under_shared_rule_by_title_prefix(self):
        output = SarifReporter().render(self._sample_results())
        run = json.loads(output)["runs"][0]
        # Both findings share the "Missing Header" prefix -> one rule, two results
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "headers/missing-header")

    def test_severity_maps_to_sarif_level(self):
        run = json.loads(SarifReporter().render(self._sample_results()))["runs"][0]
        levels = {r["properties"]["severity"]: r["level"] for r in run["results"]}
        self.assertEqual(levels["high"], "error")
        self.assertEqual(levels["medium"], "warning")

    def test_severity_filter_excludes_findings(self):
        output = SarifReporter(severity_filter=["high"]).render(self._sample_results())
        run = json.loads(output)["runs"][0]
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(run["results"][0]["properties"]["severity"], "high")

    def test_result_location_uses_target_url(self):
        run = json.loads(SarifReporter().render(self._sample_results()))["runs"][0]
        uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "https://example.com")


class TestSslTlsAnalyzer(unittest.TestCase):

    def _make_ctx(self, url="https://example.com"):
        return {
            "target": "example.com",
            "url": url,
            "response": None,
            "session": MagicMock(),
            "timeout": 5,
            "verbose": False,
        }

    def _mock_tls(self, version="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), not_after_days=200):
        import datetime as dt

        not_after_dt = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=not_after_days)
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Test CA"),),),
            "notAfter": not_after_dt.strftime("%b %d %H:%M:%S %Y GMT"),
            "notBefore": "Jan 01 00:00:00 2024 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        ssock = MagicMock()
        ssock.version.return_value = version
        ssock.cipher.return_value = cipher
        ssock.getpeercert.return_value = cert
        ssock.__enter__.return_value = ssock
        ssock.__exit__.return_value = False

        wrap_ctx = MagicMock()
        wrap_ctx.wrap_socket.return_value = ssock

        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.__exit__.return_value = False
        return wrap_ctx, sock

    @patch("sentinelscan.analyzers.ssl_tls.ssl.create_default_context")
    @patch("sentinelscan.analyzers.ssl_tls.socket.create_connection")
    def test_strong_protocol_cipher_and_valid_cert(self, mock_conn, mock_ctx):
        wrap_ctx, sock = self._mock_tls()
        mock_conn.return_value = sock
        mock_ctx.return_value = wrap_ctx
        result = SslTlsAnalyzer(self._make_ctx()).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Strong TLS Protocol" in t for t in titles))
        self.assertTrue(any("Strong Cipher Suite" in t for t in titles))
        self.assertTrue(any("Certificate Valid" in t for t in titles))

    @patch("sentinelscan.analyzers.ssl_tls.ssl.create_default_context")
    @patch("sentinelscan.analyzers.ssl_tls.socket.create_connection")
    def test_weak_protocol_flagged_critical(self, mock_conn, mock_ctx):
        wrap_ctx, sock = self._mock_tls(version="TLSv1.1")
        mock_conn.return_value = sock
        mock_ctx.return_value = wrap_ctx
        result = SslTlsAnalyzer(self._make_ctx()).run()
        weak = [f for f in result["findings"] if "Weak TLS Protocol" in f["title"]]
        self.assertTrue(weak)
        self.assertEqual(weak[0]["severity"], "critical")

    @patch("sentinelscan.analyzers.ssl_tls.ssl.create_default_context")
    @patch("sentinelscan.analyzers.ssl_tls.socket.create_connection")
    def test_weak_cipher_flagged_high(self, mock_conn, mock_ctx):
        wrap_ctx, sock = self._mock_tls(cipher=("ECDHE-RSA-RC4-SHA", "TLSv1.2", 128))
        mock_conn.return_value = sock
        mock_ctx.return_value = wrap_ctx
        result = SslTlsAnalyzer(self._make_ctx()).run()
        weak = [f for f in result["findings"] if "Weak Cipher Suite" in f["title"]]
        self.assertTrue(weak)
        self.assertEqual(weak[0]["severity"], "high")

    @patch("sentinelscan.analyzers.ssl_tls.ssl.create_default_context")
    @patch("sentinelscan.analyzers.ssl_tls.socket.create_connection")
    def test_cert_expiring_very_soon_flagged_critical(self, mock_conn, mock_ctx):
        wrap_ctx, sock = self._mock_tls(not_after_days=5)
        mock_conn.return_value = sock
        mock_ctx.return_value = wrap_ctx
        result = SslTlsAnalyzer(self._make_ctx()).run()
        crit = [f for f in result["findings"] if "Expiring Very Soon" in f["title"]]
        self.assertTrue(crit)
        self.assertEqual(crit[0]["severity"], "critical")

    @patch("sentinelscan.analyzers.ssl_tls.ssl.create_default_context")
    @patch("sentinelscan.analyzers.ssl_tls.socket.create_connection")
    def test_expired_cert_flagged_critical(self, mock_conn, mock_ctx):
        wrap_ctx, sock = self._mock_tls(not_after_days=-10)
        mock_conn.return_value = sock
        mock_ctx.return_value = wrap_ctx
        result = SslTlsAnalyzer(self._make_ctx()).run()
        crit = [f for f in result["findings"] if f["title"] == "Certificate Expired"]
        self.assertTrue(crit)
        self.assertEqual(crit[0]["severity"], "critical")

    def test_custom_port_parsed_from_url(self):
        from urllib.parse import urlsplit

        analyzer = SslTlsAnalyzer(self._make_ctx(url="https://example.com:8443"))
        parsed = urlsplit(analyzer.url)
        self.assertEqual(parsed.port, 8443)

    @patch("sentinelscan.analyzers.ssl_tls.socket.create_connection", side_effect=ConnectionRefusedError())
    def test_connection_refused_flagged_critical(self, mock_conn):
        result = SslTlsAnalyzer(self._make_ctx()).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("TLS Not Available" in t for t in titles))

    @patch("sentinelscan.analyzers.ssl_tls.ssl.create_default_context")
    @patch("sentinelscan.analyzers.ssl_tls.socket.create_connection")
    def test_cert_verification_error_flagged_critical(self, mock_conn, mock_ctx):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.__exit__.return_value = False
        mock_conn.return_value = sock
        wrap_ctx = MagicMock()
        wrap_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("cert verify failed")
        mock_ctx.return_value = wrap_ctx
        result = SslTlsAnalyzer(self._make_ctx()).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Certificate Verification Failed" in t for t in titles))


class TestOwaspAnalyzer(unittest.TestCase):

    def _make_ctx(self, body="", headers=None):
        response = MagicMock()
        response.text = body
        response.headers = headers or {}
        return {
            "target": "example.com",
            "url": "https://example.com",
            "response": response,
            "session": MagicMock(),
            "timeout": 5,
            "verbose": False,
        }

    def test_exposed_git_config_flagged_critical(self):
        ctx = self._make_ctx()

        def fake_get(url, **kwargs):
            r = MagicMock()
            r.status_code = 200 if url.endswith("/.git/config") else 404
            return r

        ctx["session"].get.side_effect = fake_get
        result = OwaspAnalyzer(ctx).run()
        crit = [f for f in result["findings"] if ".git/config" in f["title"]]
        self.assertTrue(crit)
        self.assertEqual(crit[0]["severity"], "critical")

    def test_sql_error_pattern_detected(self):
        ctx = self._make_ctx(body="You have a syntax error in your SQL query near line 1")
        ctx["session"].get.return_value = MagicMock(status_code=404)
        result = OwaspAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("SQL Error Disclosure" in t for t in titles))

    def test_directory_listing_detected(self):
        ctx = self._make_ctx()

        def fake_get(url, **kwargs):
            r = MagicMock()
            if "nonexistent-path-xyz123" in url:
                r.status_code = 200
                r.text = "Index of /uploads\nParent Directory"
            else:
                r.status_code = 404
                r.text = ""
            return r

        ctx["session"].get.side_effect = fake_get
        result = OwaspAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Directory Listing Enabled" in t for t in titles))

    def test_server_version_disclosure(self):
        ctx = self._make_ctx(headers={"Server": "nginx/1.18.0"})
        ctx["session"].get.return_value = MagicMock(status_code=404)
        result = OwaspAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Server Version Disclosure" in t for t in titles))

    def test_mixed_content_detected(self):
        ctx = self._make_ctx(body='<img src="http://insecure.example.com/x.png">')
        ctx["session"].get.return_value = MagicMock(status_code=404)
        result = OwaspAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Mixed Content" in t for t in titles))


class TestPortsAnalyzer(unittest.TestCase):

    def _make_ctx(self):
        return {
            "target": "example.com",
            "url": "https://example.com",
            "response": None,
            "session": MagicMock(),
            "timeout": 3,
            "verbose": False,
        }

    @patch("sentinelscan.analyzers.ports._probe_port")
    def test_risky_port_open_flagged_critical(self, mock_probe):
        mock_probe.side_effect = lambda host, port, timeout: (port == 6379, "")
        result = PortsAnalyzer(self._make_ctx()).run()
        crit = [f for f in result["findings"] if "6379" in f["title"]]
        self.assertTrue(crit)
        self.assertEqual(crit[0]["severity"], "critical")

    @patch("sentinelscan.analyzers.ports._probe_port")
    def test_safe_port_open_flagged_info(self, mock_probe):
        mock_probe.side_effect = lambda host, port, timeout: (port == 443, "")
        result = PortsAnalyzer(self._make_ctx()).run()
        info = [f for f in result["findings"] if "443" in f["title"]]
        self.assertTrue(info)
        self.assertEqual(info[0]["severity"], "info")

    @patch("sentinelscan.analyzers.ports._probe_port", return_value=(False, ""))
    def test_all_closed_reports_no_open_ports(self, mock_probe):
        result = PortsAnalyzer(self._make_ctx()).run()
        self.assertEqual(result["open_ports"], [])
        self.assertEqual(result["closed_count"], len(COMMON_PORTS))

    @patch("sentinelscan.analyzers.ports._probe_port")
    def test_banner_included_in_open_port_and_finding_evidence(self, mock_probe):
        mock_probe.side_effect = lambda host, port, timeout: (
            (True, "SSH-2.0-OpenSSH_8.9") if port == 22 else (False, "")
        )
        result = PortsAnalyzer(self._make_ctx()).run()
        ssh_port = next(p for p in result["open_ports"] if p["port"] == 22)
        self.assertEqual(ssh_port["banner"], "SSH-2.0-OpenSSH_8.9")
        finding = next(f for f in result["findings"] if "22/SSH" in f["title"])
        self.assertIn("SSH-2.0-OpenSSH_8.9", finding["evidence"])

    @patch("sentinelscan.analyzers.ports._probe_port")
    def test_malicious_banner_escape_sequences_stripped(self, mock_probe):
        # A malicious/compromised service could send ANSI escape sequences in its
        # banner to manipulate the terminal of anyone who scans it and views a
        # text report (e.g. hiding other findings). Both the Finding fields and
        # the raw open_ports metadata must come out clean.
        malicious = "SSH-2.0-\x1b[2K\x1b[1AOpenSSH_8.9\x1b]0;pwned\x07"
        mock_probe.side_effect = lambda host, port, timeout: ((True, malicious) if port == 22 else (False, ""))
        result = PortsAnalyzer(self._make_ctx()).run()

        ssh_port = next(p for p in result["open_ports"] if p["port"] == 22)
        self.assertNotIn("\x1b", ssh_port["banner"])

        finding = next(f for f in result["findings"] if "22/SSH" in f["title"])
        self.assertNotIn("\x1b", finding["evidence"])
        self.assertNotIn("\x1b", finding["description"])
        self.assertNotIn("\x07", finding["evidence"])
        # The harmless surrounding content should survive.
        self.assertIn("OpenSSH_8.9", finding["evidence"])


class TestCveFingerprintAnalyzer(unittest.TestCase):

    def _make_ctx(self, headers):
        response = MagicMock(status_code=200)
        response.headers = headers
        return {
            "target": "example.com",
            "url": "https://example.com",
            "response": response,
            "session": MagicMock(),
            "timeout": 5,
            "verbose": False,
        }

    def test_known_vulnerable_version_flagged(self):
        ctx = self._make_ctx({"Server": "nginx/1.16.0"})
        result = CveFingerprintAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("CVE-2019-9511" in t for t in titles))
        self.assertEqual(result["detected"], [{"product": "nginx", "version": "1.16.0"}])

    def test_patched_version_not_flagged_as_vulnerable(self):
        ctx = self._make_ctx({"Server": "nginx/1.25.3"})
        result = CveFingerprintAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertFalse(any("CVE-" in t for t in titles))
        self.assertTrue(any("No Known CVEs" in t for t in titles))

    def test_no_recognizable_header_reports_info(self):
        ctx = self._make_ctx({})
        result = CveFingerprintAnalyzer(ctx).run()
        self.assertEqual(result["detected"], [])
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("No Fingerprintable" in t for t in titles))

    def test_apache_path_traversal_cve_detected(self):
        ctx = self._make_ctx({"Server": "Apache/2.4.49 (Unix)"})
        result = CveFingerprintAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("CVE-2021-41773" in t for t in titles))


class TestExitCodes(unittest.TestCase):

    def test_exit_code_constants_have_expected_values(self):
        # These are a documented contract (USAGE.md, man page) -- values must not drift silently.
        self.assertEqual(EXIT_OK, 0)
        self.assertEqual(EXIT_ERROR, 1)
        self.assertEqual(EXIT_GATE_TRIPPED, 2)


class TestDoctor(unittest.TestCase):

    def test_doctor_runs_and_reports_python_version(self):
        with patch("sentinelscan.cli.logger") as mock_logger:
            code = run_doctor()
        self.assertIn(code, (EXIT_OK, EXIT_ERROR))
        self.assertTrue(mock_logger.info.called)

    def test_doctor_flag_wired_through_cli(self):
        code = main(["--doctor", "--no-color"])
        self.assertIn(code, (EXIT_OK, EXIT_ERROR))


class TestDisclaimer(unittest.TestCase):

    def test_shown_once_then_suppressed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            marker = Path(tmpdir) / ".disclaimer_shown"
            with (
                patch("sentinelscan.cli.DISCLAIMER_MARKER", marker),
                patch.dict(os.environ, {"SENTINELSCAN_SKIP_DISCLAIMER": ""}),
            ):
                with patch("sentinelscan.cli.logger") as mock_logger:
                    maybe_show_disclaimer()
                self.assertTrue(marker.exists())
                self.assertTrue(mock_logger.warning.called)

                mock_logger.reset_mock()
                maybe_show_disclaimer()
                mock_logger.warning.assert_not_called()

    def test_skip_env_var_suppresses_entirely(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            marker = Path(tmpdir) / ".disclaimer_shown"
            with (
                patch("sentinelscan.cli.DISCLAIMER_MARKER", marker),
                patch.dict(os.environ, {"SENTINELSCAN_SKIP_DISCLAIMER": "1"}),
            ):
                with patch("sentinelscan.cli.logger") as mock_logger:
                    maybe_show_disclaimer()
                mock_logger.warning.assert_not_called()
                self.assertFalse(marker.exists())


class TestMainEntryPoint(unittest.TestCase):
    """Regression coverage for `python -m sentinelscan` as a real subprocess.

    main()'s return value is meaningless unless something actually calls
    sys.exit() with it. Calling main() in-process can't catch a bug in that
    glue code (__main__.py) -- only a real subprocess invocation can.
    """

    def test_exit_code_propagates_through_python_dash_m(self):
        import subprocess
        import sys as _sys

        result = subprocess.run(
            [_sys.executable, "-m", "sentinelscan", "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0)

    def test_nonzero_exit_code_propagates_through_python_dash_m(self):
        import subprocess
        import sys as _sys

        result = subprocess.run(
            [_sys.executable, "-m", "sentinelscan", "example.com", "-m", "totally_bogus_module", "--no-color"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 1)


class TestConfigProfile(unittest.TestCase):

    def _write_toml(self, tmpdir, filename, content):
        path = Path(tmpdir) / filename
        path.write_text(content, encoding="utf-8")
        return path

    def test_no_profile_requested_returns_empty(self):
        self.assertEqual(load_profile(), {})

    def test_missing_named_profile_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_profile(name="does-not-exist-xyz")

    def test_missing_explicit_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_profile(path="/nonexistent/path/profile.toml")

    def test_loads_valid_profile_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_toml(
                tmpdir,
                "prod.toml",
                'modules = ["headers", "ssl_tls"]\nformat = "json"\ntiming = 4\nretries = 5\n',
            )
            data = load_profile(path=path)
        self.assertEqual(data["modules"], ["headers", "ssl_tls"])
        self.assertEqual(data["format"], "json")
        self.assertEqual(data["timing"], 4)
        self.assertEqual(data["retries"], 5)

    def test_unknown_field_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_toml(tmpdir, "bad.toml", "exit_on_critical = true\n")
            with self.assertRaises(ValueError):
                load_profile(path=path)

    def test_named_profile_resolved_under_config_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profiles_dir = Path(tmpdir) / "profiles"
            profiles_dir.mkdir()
            (profiles_dir / "myprofile.toml").write_text('format = "sarif"\n', encoding="utf-8")
            with patch("sentinelscan.config_file.DEFAULT_CONFIG_DIR", Path(tmpdir)):
                data = load_profile(name="myprofile")
        self.assertEqual(data["format"], "sarif")

    def test_cli_flag_overrides_profile_value(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_toml(tmpdir, "p.toml", 'format = "json"\ntiming = 5\n')
            fake = {"headers": {"findings": []}, "__meta__": {"risk_score": 0}}
            with patch("sentinelscan.cli.Scanner") as MockScanner:
                MockScanner.return_value.scan.return_value = fake
                with patch("sentinelscan.cli.print"):
                    main(["example.com", "--profile-file", str(path), "-f", "html", "--no-color"])
                _, kwargs = MockScanner.call_args
                # timing=5 came from the profile (unset on CLI) -> its timeout applies
                self.assertEqual(kwargs["timeout"], TIMING_PROFILES[5]["timeout"])

    def test_profile_value_used_when_cli_flag_absent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_toml(tmpdir, "p.toml", 'retries = 9\nuser_agent = "CustomAgent/1.0"\n')
            fake = {"headers": {"findings": []}, "__meta__": {"risk_score": 0}}
            with patch("sentinelscan.cli.Scanner") as MockScanner:
                MockScanner.return_value.scan.return_value = fake
                with patch("sentinelscan.cli.print"):
                    main(["example.com", "--profile-file", str(path), "--no-color"])
                _, kwargs = MockScanner.call_args
                self.assertEqual(kwargs["retries"], 9)
                self.assertEqual(kwargs["user_agent"], "CustomAgent/1.0")

    def test_builtin_default_used_when_neither_cli_nor_profile_set(self):
        fake = {"headers": {"findings": []}, "__meta__": {"risk_score": 0}}
        with patch("sentinelscan.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan.return_value = fake
            with patch("sentinelscan.cli.print"):
                main(["example.com", "--no-color"])
            _, kwargs = MockScanner.call_args
            self.assertEqual(kwargs["retries"], 2)
            self.assertEqual(kwargs["user_agent"], "SentinelScan/2.0 (Security Scanner)")

    def test_invalid_profile_format_value_errors_cleanly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_toml(tmpdir, "bad.toml", 'format = "yaml"\n')
            code = main(["example.com", "--profile-file", str(path), "--no-color"])
        self.assertEqual(code, EXIT_ERROR)

    def test_missing_profile_file_errors_cleanly(self):
        code = main(["example.com", "--profile-file", "/no/such/file.toml", "--no-color"])
        self.assertEqual(code, EXIT_ERROR)


class TestUpdater(unittest.TestCase):

    def test_successful_update_writes_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_path = Path(tmpdir) / "cve_signatures.json"
            fake_data = {"nginx": [{"max_version": "1.0.0", "cve": "CVE-0000-0000", "severity": "low"}]}
            mock_session = MagicMock()
            mock_session.get.return_value = MagicMock(status_code=200, text=json.dumps(fake_data))
            with patch("sentinelscan.updater.USER_SIGNATURES_PATH", target_path):
                success, message = update_signatures(mock_session, url="https://example.com/sigs.json")
            self.assertTrue(success)
            self.assertTrue(target_path.exists())
            with open(target_path) as fh:
                self.assertEqual(json.load(fh), fake_data)

    def test_non_200_status_fails_cleanly(self):
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(status_code=404, text="")
        success, message = update_signatures(mock_session, url="https://example.com/missing.json")
        self.assertFalse(success)
        self.assertIn("404", message)

    def test_invalid_json_fails_cleanly(self):
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(status_code=200, text="not json")
        success, message = update_signatures(mock_session, url="https://example.com/sigs.json")
        self.assertFalse(success)

    def test_network_error_fails_cleanly(self):
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError("down")
        success, message = update_signatures(mock_session, url="https://example.com/sigs.json")
        self.assertFalse(success)

    def test_update_db_flag_wired_through_cli(self):
        with patch("sentinelscan.cli.update_signatures", return_value=(True, "ok")) as mock_update:
            code = main(["--update-db", "--no-color"])
        self.assertEqual(code, 0)
        mock_update.assert_called_once()


class TestCrawlerAnalyzer(unittest.TestCase):

    def _make_ctx(self, response, max_pages=15):
        return {
            "target": "example.com",
            "url": "https://example.com/",
            "response": response,
            "session": MagicMock(),
            "timeout": 5,
            "verbose": False,
            "crawl_max_pages": max_pages,
        }

    def _full_headers(self):
        return dict.fromkeys(REQUIRED_HEADERS, "x")

    def test_single_page_produces_no_finding(self):
        homepage = MagicMock(status_code=200, headers=self._full_headers(), text="<html></html>")
        result = CrawlerAnalyzer(self._make_ctx(homepage)).run()
        self.assertEqual(result["pages_crawled"], 1)
        self.assertEqual(result["findings"], [])

    def test_single_page_missing_headers_does_not_claim_inconsistency(self):
        # A lone page with missing headers isn't "inconsistent" -- there's nothing to compare
        # against, and the `headers` module already reports missing headers on its own.
        homepage = MagicMock(status_code=200, headers={}, text="<html></html>")
        result = CrawlerAnalyzer(self._make_ctx(homepage)).run()
        self.assertEqual(result["pages_crawled"], 1)
        self.assertEqual(result["findings"], [])

    def test_follows_same_origin_link_and_flags_inconsistency(self):
        homepage = MagicMock(status_code=200, headers=self._full_headers(), text='<a href="/about">About</a>')
        about_page = MagicMock(status_code=200, headers={}, text="")
        ctx = self._make_ctx(homepage)
        ctx["session"].get.return_value = about_page
        result = CrawlerAnalyzer(ctx).run()
        self.assertEqual(result["pages_crawled"], 2)
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Inconsistent Security Headers" in t for t in titles))

    def test_consistent_headers_across_pages_flagged_info(self):
        full = self._full_headers()
        homepage = MagicMock(status_code=200, headers=full, text='<a href="/about">About</a>')
        about_page = MagicMock(status_code=200, headers=full, text="")
        ctx = self._make_ctx(homepage)
        ctx["session"].get.return_value = about_page
        result = CrawlerAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Consistent Security Headers" in t for t in titles))

    def test_external_links_not_followed(self):
        homepage = MagicMock(
            status_code=200, headers=self._full_headers(), text='<a href="https://other.com/page">Ext</a>'
        )
        ctx = self._make_ctx(homepage)
        result = CrawlerAnalyzer(ctx).run()
        self.assertEqual(result["pages_crawled"], 1)
        ctx["session"].get.assert_not_called()

    def test_max_pages_respected(self):
        links = "".join(f'<a href="/page{i}">p{i}</a>' for i in range(10))
        homepage = MagicMock(status_code=200, headers=self._full_headers(), text=links)
        other_page = MagicMock(status_code=200, headers=self._full_headers(), text="")
        ctx = self._make_ctx(homepage, max_pages=3)
        ctx["session"].get.return_value = other_page
        result = CrawlerAnalyzer(ctx).run()
        self.assertEqual(result["pages_crawled"], 3)

    def test_fetch_failure_skipped_gracefully(self):
        homepage = MagicMock(status_code=200, headers=self._full_headers(), text='<a href="/broken">x</a>')
        ctx = self._make_ctx(homepage)
        ctx["session"].get.side_effect = requests.exceptions.ConnectionError("down")
        result = CrawlerAnalyzer(ctx).run()
        self.assertEqual(result["pages_crawled"], 1)

    def test_malicious_link_escape_sequences_stripped_from_evidence(self):
        # A crafted href containing raw escape bytes could otherwise carry them
        # through urljoin into a Finding's evidence, unsanitized, when printed.
        malicious_href = "/\x1b[2Jpath"
        homepage = MagicMock(
            status_code=200,
            headers=self._full_headers(),
            text=f'<a href="{malicious_href}">x</a>',
        )
        about_page = MagicMock(status_code=200, headers={}, text="")
        ctx = self._make_ctx(homepage)
        ctx["session"].get.return_value = about_page
        result = CrawlerAnalyzer(ctx).run()
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Inconsistent Security Headers" in t for t in titles))
        finding = next(f for f in result["findings"] if "Inconsistent Security Headers" in f["title"])
        self.assertNotIn("\x1b", finding["evidence"])


class TestSubdomainsAnalyzer(unittest.TestCase):

    def _make_ctx(self):
        return {
            "target": "example.com",
            "url": "https://example.com",
            "response": None,
            "session": MagicMock(),
            "timeout": 5,
            "verbose": False,
        }

    def test_discovers_and_dedupes_subdomains(self):
        ctx = self._make_ctx()
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps(
            [
                {"name_value": "www.example.com\nmail.example.com"},
                {"name_value": "mail.example.com"},  # duplicate
                {"name_value": "*.dev.example.com"},  # wildcard, should be stripped
            ]
        )
        ctx["session"].get.return_value = mock_resp
        result = SubdomainsAnalyzer(ctx).run()
        self.assertEqual(result["total_found"], 3)
        self.assertIn("mail.example.com", result["subdomains"])
        self.assertIn("dev.example.com", result["subdomains"])
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Subdomains Discovered" in t for t in titles))

    def test_no_results_reports_info_finding(self):
        ctx = self._make_ctx()
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = "[]"
        ctx["session"].get.return_value = mock_resp
        result = SubdomainsAnalyzer(ctx).run()
        self.assertEqual(result["total_found"], 0)
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("No Subdomains Found" in t for t in titles))

    def test_network_failure_handled_gracefully(self):
        ctx = self._make_ctx()
        ctx["session"].get.side_effect = requests.exceptions.ConnectionError("unreachable")
        result = SubdomainsAnalyzer(ctx).run()
        self.assertEqual(result["subdomains"], [])
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Unavailable" in t for t in titles))

    def test_malformed_json_treated_as_no_results(self):
        ctx = self._make_ctx()
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = "not json"
        ctx["session"].get.return_value = mock_resp
        result = SubdomainsAnalyzer(ctx).run()
        self.assertEqual(result["subdomains"], [])

    def test_www_prefix_stripped_for_base_domain_search(self):
        ctx = self._make_ctx()
        ctx["target"] = "www.example.com"
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = "[]"
        ctx["session"].get.return_value = mock_resp
        SubdomainsAnalyzer(ctx).run()
        called_url = ctx["session"].get.call_args[0][0]
        self.assertIn("example.com", called_url)
        self.assertNotIn("www.example.com", called_url)


class TestDnsAnalyzer(unittest.TestCase):

    def _make_ctx(self):
        return {
            "target": "example.com",
            "url": "https://example.com",
            "response": None,
            "session": MagicMock(),
            "timeout": 5,
            "verbose": False,
        }

    @patch("sentinelscan.analyzers.dns.DNS_AVAILABLE", False)
    @patch("sentinelscan.analyzers.dns.socket.gethostbyname", return_value="93.184.216.34")
    def test_resolution_success_without_dnspython(self, mock_resolve):
        result = DnsAnalyzer(self._make_ctx()).run()
        self.assertEqual(result["ip"], "93.184.216.34")
        titles = [f["title"] for f in result["findings"]]
        self.assertIn("DNS Resolution Successful", titles)
        self.assertIn("Advanced DNS Checks Skipped", titles)

    @patch("sentinelscan.analyzers.dns.socket.gethostbyname", side_effect=socket.gaierror("not found"))
    def test_resolution_failure_flagged_high(self, mock_resolve):
        result = DnsAnalyzer(self._make_ctx()).run()
        failed = [f for f in result["findings"] if f["title"] == "DNS Resolution Failed"]
        self.assertTrue(failed)
        self.assertEqual(failed[0]["severity"], "high")

    @patch("sentinelscan.analyzers.dns.socket.gethostbyname", return_value="93.184.216.34")
    def test_spf_plus_all_flagged_critical(self, mock_resolve):
        fake_resolver_instance = MagicMock()

        def fake_resolve(name, rtype):
            if name == "example.com" and rtype == "TXT":
                return [_FakeRdata('"v=spf1 +all"')]
            if name == "_dmarc.example.com" and rtype == "TXT":
                raise _FakeNXDOMAIN()
            raise Exception("no data")

        fake_resolver_instance.resolve.side_effect = fake_resolve
        fake_dns_module = MagicMock()
        fake_dns_module.resolver.Resolver.return_value = fake_resolver_instance
        fake_dns_module.resolver.NXDOMAIN = _FakeNXDOMAIN

        with (
            patch("sentinelscan.analyzers.dns.DNS_AVAILABLE", True),
            patch("sentinelscan.analyzers.dns.dns", fake_dns_module, create=True),
        ):
            result = DnsAnalyzer(self._make_ctx()).run()

        crit = [f for f in result["findings"] if "+all" in f["title"]]
        self.assertTrue(crit)
        self.assertEqual(crit[0]["severity"], "critical")
        missing_dmarc = [f for f in result["findings"] if f["title"] == "DMARC Record Missing"]
        self.assertTrue(missing_dmarc)

    @patch("sentinelscan.analyzers.dns.socket.gethostbyname", return_value="93.184.216.34")
    def test_dmarc_reject_policy_flagged_info(self, mock_resolve):
        fake_resolver_instance = MagicMock()

        def fake_resolve(name, rtype):
            if name == "example.com" and rtype == "TXT":
                return [_FakeRdata('"v=spf1 -all"')]
            if name == "_dmarc.example.com" and rtype == "TXT":
                return [_FakeRdata('"v=DMARC1; p=reject"')]
            raise Exception("no data")

        fake_resolver_instance.resolve.side_effect = fake_resolve
        fake_dns_module = MagicMock()
        fake_dns_module.resolver.Resolver.return_value = fake_resolver_instance
        fake_dns_module.resolver.NXDOMAIN = _FakeNXDOMAIN

        with (
            patch("sentinelscan.analyzers.dns.DNS_AVAILABLE", True),
            patch("sentinelscan.analyzers.dns.dns", fake_dns_module, create=True),
        ):
            result = DnsAnalyzer(self._make_ctx()).run()

        titles = [f["title"] for f in result["findings"]]
        self.assertIn("DMARC Policy: Reject (Strongest)", titles)
        self.assertIn("SPF: Hard Fail Configured", titles)


class TestScanner(unittest.TestCase):

    def test_extra_headers_applied_to_session(self):
        scanner = Scanner(extra_headers={"Authorization": "Bearer TOKEN", "Cookie": "session=abc"})
        self.assertEqual(scanner.session.headers["Authorization"], "Bearer TOKEN")
        self.assertEqual(scanner.session.headers["Cookie"], "session=abc")

    def test_grade_boundaries(self):
        cases = [
            (0, "A+"),
            (5, "A"),
            (10, "A"),
            (11, "B"),
            (25, "B"),
            (26, "C"),
            (50, "C"),
            (51, "D"),
            (80, "D"),
            (81, "F"),
        ]
        for score, expected in cases:
            self.assertEqual(Scanner._grade(score), expected)

    def test_scan_aggregates_risk_score_and_grade(self):
        scanner = Scanner()
        fake_response = MagicMock(status_code=200, url="https://example.com")
        scanner.session = MagicMock()
        scanner.session.get.return_value = fake_response

        class FakeAnalyzer:
            name = "fake"

            def __init__(self, ctx):
                pass

            def run(self):
                return {"module": "fake", "findings": [{"severity": "critical"}, {"severity": "medium"}]}

        with patch.dict("sentinelscan.scanner.MODULE_MAP", {"fake": FakeAnalyzer}, clear=True):
            results = scanner.scan("example.com", modules=["fake"])

        self.assertEqual(results["__meta__"]["risk_score"], 50)
        self.assertEqual(results["__meta__"]["risk_grade"], "C")

    def test_scan_handles_connection_error(self):
        scanner = Scanner()
        scanner.session = MagicMock()
        scanner.session.get.side_effect = requests.exceptions.ConnectionError("refused")
        results = scanner.scan("example.com", modules=["headers"])
        self.assertIn("__error__", results)

    def test_scan_handles_analyzer_exception_gracefully(self):
        scanner = Scanner()
        fake_response = MagicMock(status_code=200, url="https://example.com")
        scanner.session = MagicMock()
        scanner.session.get.return_value = fake_response

        class BrokenAnalyzer:
            name = "broken"

            def __init__(self, ctx):
                pass

            def run(self):
                raise RuntimeError("boom")

        with patch.dict("sentinelscan.scanner.MODULE_MAP", {"broken": BrokenAnalyzer}, clear=True):
            results = scanner.scan("example.com", modules=["broken"])

        self.assertEqual(results["broken"]["findings"], [])
        self.assertIn("error", results["broken"])


class TestCliExitCodes(unittest.TestCase):

    def _run(self, argv, fake_target_results):
        with patch("sentinelscan.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan.return_value = fake_target_results
            return main(argv)

    def test_no_target_returns_zero(self):
        self.assertEqual(main([]), 0)

    def test_exit_zero_when_no_gate_tripped(self):
        fake = {"headers": {"findings": [{"severity": "low", "title": "Low finding"}]}, "__meta__": {"risk_score": 5}}
        code = self._run(["example.com", "--no-color"], fake)
        self.assertEqual(code, 0)

    def test_exit_two_on_critical_with_flag(self):
        findings = [{"severity": "critical", "title": "Critical finding"}]
        fake = {"headers": {"findings": findings}, "__meta__": {"risk_score": 40}}
        code = self._run(["example.com", "--no-color", "--exit-on-critical"], fake)
        self.assertEqual(code, 2)

    def test_exit_two_on_score_threshold_exceeded(self):
        findings = [{"severity": "medium", "title": "Medium finding"}]
        fake = {"headers": {"findings": findings}, "__meta__": {"risk_score": 60}}
        code = self._run(["example.com", "--no-color", "--score-threshold", "50"], fake)
        self.assertEqual(code, 2)

    def test_critical_without_flag_does_not_trip_gate(self):
        findings = [{"severity": "critical", "title": "Critical finding"}]
        fake = {"headers": {"findings": findings}, "__meta__": {"risk_score": 40}}
        code = self._run(["example.com", "--no-color"], fake)
        self.assertEqual(code, 0)

    def test_multiple_targets_report_in_input_order(self):
        fake = {"headers": {"findings": []}, "__meta__": {"risk_score": 0}}
        with patch("sentinelscan.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan.return_value = fake
            with patch("sentinelscan.cli.print"):
                code = main(["z.example.com", "a.example.com", "m.example.com", "--no-color"])
        self.assertEqual(code, 0)

    def test_report_output_is_isolated_from_status_logging_on_stdout(self):
        import io
        from contextlib import redirect_stderr, redirect_stdout

        fake = {
            "headers": {"findings": []},
            "__meta__": {
                "risk_score": 0,
                "risk_grade": "A+",
                "status_code": 200,
                "final_url": "https://example.com",
                "scanned_modules": ["headers"],
            },
        }
        stdout_buf, stderr_buf = io.StringIO(), io.StringIO()
        with patch("sentinelscan.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan.return_value = fake
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                main(["example.com", "-f", "json"])

        # stdout must be pure, parseable JSON with no banner/status text mixed in
        json.loads(stdout_buf.getvalue())
        self.assertIn("SCANNING", stderr_buf.getvalue().upper())


class TestResolveTargets(unittest.TestCase):

    def test_cidr_expands_to_usable_hosts(self):
        self.assertEqual(_expand_target("10.0.0.0/30"), ["10.0.0.1", "10.0.0.2"])

    def test_single_host_cidr_returns_one_address(self):
        self.assertEqual(_expand_target("10.0.0.5/32"), ["10.0.0.5"])

    def test_hostname_passes_through_unchanged(self):
        self.assertEqual(_expand_target("example.com"), ["example.com"])

    def test_oversized_cidr_raises_value_error(self):
        with self.assertRaises(ValueError):
            _expand_target("10.0.0.0/16")

    def test_input_list_file_reads_targets_and_skips_comments(self):
        import os
        import tempfile

        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write("# comment\nexample.com\n\n10.0.0.0/30\n")
            targets = resolve_targets([], path)
        finally:
            os.remove(path)
        self.assertEqual(targets, ["example.com", "10.0.0.1", "10.0.0.2"])

    def test_deduplicates_while_preserving_order(self):
        targets = resolve_targets(["b.com", "a.com", "b.com"], None)
        self.assertEqual(targets, ["b.com", "a.com"])


class TestTimingProfiles(unittest.TestCase):

    def test_all_six_profiles_defined_with_required_keys(self):
        for level in range(6):
            profile = TIMING_PROFILES[level]
            for key in ("name", "timeout", "target_workers", "module_workers", "port_workers"):
                self.assertIn(key, profile)

    def test_profiles_get_faster_and_more_parallel_as_level_increases(self):
        for level in range(5):
            self.assertGreaterEqual(TIMING_PROFILES[level]["timeout"], TIMING_PROFILES[level + 1]["timeout"])
            self.assertLessEqual(TIMING_PROFILES[level]["module_workers"], TIMING_PROFILES[level + 1]["module_workers"])

    def test_default_timing_is_normal(self):
        # Raw parser default is None -- resolved to BUILTIN_DEFAULTS["timing"] (3) inside
        # main() so --profile can supply a value in between. This confirms the resolved
        # behavior via main(), not the raw parser default.
        fake = {"headers": {"findings": []}, "__meta__": {"risk_score": 0}}
        with patch("sentinelscan.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan.return_value = fake
            with patch("sentinelscan.cli.print"):
                main(["example.com", "--no-color"])
            _, kwargs = MockScanner.call_args
            self.assertEqual(kwargs["timeout"], TIMING_PROFILES[3]["timeout"])

        args = build_parser().parse_args(["example.com"])
        self.assertIsNone(args.timing)
        self.assertIsNone(args.timeout)

    def test_explicit_timeout_overrides_timing_profile(self):
        fake = {"headers": {"findings": []}, "__meta__": {"risk_score": 0}}
        with patch("sentinelscan.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan.return_value = fake
            with patch("sentinelscan.cli.print"):
                main(["example.com", "-T", "5", "--timeout", "42", "--no-color"])
            _, kwargs = MockScanner.call_args
            self.assertEqual(kwargs["timeout"], 42)

    def test_timing_profile_supplies_timeout_when_unset(self):
        fake = {"headers": {"findings": []}, "__meta__": {"risk_score": 0}}
        with patch("sentinelscan.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan.return_value = fake
            with patch("sentinelscan.cli.print"):
                main(["example.com", "-T", "0", "--no-color"])
            _, kwargs = MockScanner.call_args
            self.assertEqual(kwargs["timeout"], TIMING_PROFILES[0]["timeout"])


class TestAuthHeaders(unittest.TestCase):

    def test_parse_single_header(self):
        self.assertEqual(parse_headers(["Authorization: Bearer TOKEN"]), {"Authorization": "Bearer TOKEN"})

    def test_parse_multiple_headers(self):
        headers = parse_headers(["X-Api-Key: abc", "X-Foo: bar"])
        self.assertEqual(headers, {"X-Api-Key": "abc", "X-Foo": "bar"})

    def test_value_with_colon_preserved(self):
        headers = parse_headers(["Authorization: Bearer token:with:colons"])
        self.assertEqual(headers["Authorization"], "Bearer token:with:colons")

    def test_malformed_header_raises(self):
        with self.assertRaises(ValueError):
            parse_headers(["not-a-valid-header"])

    def test_header_and_cookie_flags_reach_scanner(self):
        fake = {"headers": {"findings": []}, "__meta__": {"risk_score": 0}}
        with patch("sentinelscan.cli.Scanner") as MockScanner:
            MockScanner.return_value.scan.return_value = fake
            with patch("sentinelscan.cli.print"):
                main(
                    [
                        "example.com",
                        "--no-color",
                        "-H",
                        "Authorization: Bearer TOKEN",
                        "--cookie",
                        "session=abc123",
                    ]
                )
            _, kwargs = MockScanner.call_args
            self.assertEqual(
                kwargs["extra_headers"],
                {"Authorization": "Bearer TOKEN", "Cookie": "session=abc123"},
            )

    def test_malformed_header_exits_with_error_code(self):
        code = main(["example.com", "-H", "garbage", "--no-color"])
        self.assertEqual(code, 1)


class TestPlugins(unittest.TestCase):

    def _write_plugin(self, tmpdir, filename, content):
        path = os.path.join(tmpdir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_missing_directory_returns_empty(self):
        self.assertEqual(load_plugins("/nonexistent/plugin/dir/xyz"), {})

    def test_loads_valid_plugin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_plugin(
                tmpdir,
                "mycheck.py",
                "from sentinelscan.analyzers.base import BaseAnalyzer\n"
                "class MyCheckAnalyzer(BaseAnalyzer):\n"
                "    name = 'mycheck'\n"
                "    def analyze(self):\n"
                "        self.add_finding(title='t', description='d', severity='info')\n"
                "        return {}\n"
                "ANALYZER = MyCheckAnalyzer\n",
            )
            modules = load_plugins(tmpdir)
        self.assertIn("mycheck", modules)
        self.assertTrue(issubclass(modules["mycheck"], BaseAnalyzer))

    def test_plugin_without_analyzer_attribute_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_plugin(tmpdir, "broken.py", "x = 1\n")
            modules = load_plugins(tmpdir)
        self.assertEqual(modules, {})

    def test_plugin_with_non_analyzer_subclass_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_plugin(tmpdir, "broken.py", "class NotAnAnalyzer:\n    pass\nANALYZER = NotAnAnalyzer\n")
            modules = load_plugins(tmpdir)
        self.assertEqual(modules, {})

    def test_plugin_with_syntax_error_is_skipped_not_raised(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_plugin(tmpdir, "broken.py", "def bad(:\n")
            modules = load_plugins(tmpdir)
        self.assertEqual(modules, {})

    def test_underscore_prefixed_files_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_plugin(
                tmpdir,
                "_helper.py",
                "from sentinelscan.analyzers.base import BaseAnalyzer\n"
                "class X(BaseAnalyzer):\n"
                "    name = 'x'\n"
                "    def analyze(self):\n"
                "        return {}\n"
                "ANALYZER = X\n",
            )
            modules = load_plugins(tmpdir)
        self.assertEqual(modules, {})

    def test_plugin_runs_through_cli_and_is_selectable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_plugin(
                tmpdir,
                "mycheck.py",
                "from sentinelscan.analyzers.base import BaseAnalyzer\n"
                "class MyCheckAnalyzer(BaseAnalyzer):\n"
                "    name = 'mycheck'\n"
                "    def analyze(self):\n"
                "        self.add_finding(title='Plugin Finding', description='d', severity='info')\n"
                "        return {}\n"
                "ANALYZER = MyCheckAnalyzer\n",
            )
            fake = {
                "mycheck": {"findings": [{"severity": "info", "title": "Plugin Finding"}]},
                "__meta__": {"risk_score": 1},
            }
            with patch("sentinelscan.cli.Scanner") as MockScanner:
                MockScanner.return_value.scan.return_value = fake
                with patch("sentinelscan.cli.print"):
                    code = main(["example.com", "-m", "mycheck", "--plugin-dir", tmpdir, "--no-color"])
            self.assertEqual(code, 0)
            _, kwargs = MockScanner.call_args
            self.assertIn("mycheck", kwargs["module_map"])

    def test_unknown_module_returns_error_exit_code(self):
        code = main(["example.com", "-m", "totally_bogus_module", "--no-color", "--no-plugins"])
        self.assertEqual(code, 1)

    def test_no_plugins_flag_disables_loading(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_plugin(
                tmpdir,
                "mycheck.py",
                "from sentinelscan.analyzers.base import BaseAnalyzer\n"
                "class MyCheckAnalyzer(BaseAnalyzer):\n"
                "    name = 'mycheck'\n"
                "    def analyze(self):\n"
                "        return {}\n"
                "ANALYZER = MyCheckAnalyzer\n",
            )
            code = main(["example.com", "-m", "mycheck", "--plugin-dir", tmpdir, "--no-plugins", "--no-color"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
