"""Unit tests for SentinelScan v2."""

import json
import unittest
from unittest.mock import MagicMock, patch

from sentinelscan.analyzers.headers import HeadersAnalyzer
from sentinelscan.analyzers.cookies import CookiesAnalyzer
from sentinelscan.analyzers.cors import CorsAnalyzer
from sentinelscan.reporters.json_reporter import JsonReporter
from sentinelscan.reporters.text_reporter import TextReporter
from sentinelscan.reporters.html_reporter import HtmlReporter


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
        ctx = _make_ctx(headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        })
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
                }
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
                "headers": {"findings": [], "_elapsed_ms": 10}
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
                }
            }
        }
        reporter = HtmlReporter()
        output = reporter.render(results)
        self.assertIn("<!DOCTYPE html>", output)
        self.assertIn("SENTINELSCAN", output)
        self.assertIn("X-Frame-Options", output)
        self.assertIn("medium", output.lower())


if __name__ == "__main__":
    unittest.main()
