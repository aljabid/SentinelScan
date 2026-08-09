"""Core scanner orchestrator – dispatches modules and aggregates results."""

from __future__ import annotations

import concurrent.futures
import logging
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sentinelscan.analyzers.cookies import CookiesAnalyzer
from sentinelscan.analyzers.cors import CorsAnalyzer
from sentinelscan.analyzers.crawler import CrawlerAnalyzer
from sentinelscan.analyzers.cve_fingerprint import CveFingerprintAnalyzer
from sentinelscan.analyzers.dns import DnsAnalyzer
from sentinelscan.analyzers.headers import HeadersAnalyzer
from sentinelscan.analyzers.owasp import OwaspAnalyzer
from sentinelscan.analyzers.ports import PortsAnalyzer
from sentinelscan.analyzers.ssl_tls import SslTlsAnalyzer
from sentinelscan.analyzers.subdomains import SubdomainsAnalyzer

SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 1}

MODULE_MAP: dict[str, type[Any]] = {
    "headers": HeadersAnalyzer,
    "ssl_tls": SslTlsAnalyzer,
    "owasp": OwaspAnalyzer,
    "cookies": CookiesAnalyzer,
    "cors": CorsAnalyzer,
    "dns": DnsAnalyzer,
    "ports": PortsAnalyzer,
    "subdomains": SubdomainsAnalyzer,
    "crawler": CrawlerAnalyzer,
    "cve_fingerprint": CveFingerprintAnalyzer,
}

logger = logging.getLogger("sentinelscan.scanner")


def _run_module(module_name: str, cls: type[Any], ctx: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    t0 = time.monotonic()
    try:
        analyzer = cls(ctx)
        module_result = analyzer.run()
    except Exception as exc:
        logger.debug("Module %s raised: %s", module_name, exc)
        module_result = {"findings": [], "error": str(exc)}
    module_result["_elapsed_ms"] = int((time.monotonic() - t0) * 1000)
    return module_name, module_result


class Scanner:
    def __init__(
        self,
        timeout: int = 10,
        retries: int = 2,
        user_agent: str = "SentinelScan/2.0",
        follow_redirects: bool = True,
        verbose: bool = False,
        module_workers: int = 4,
        port_workers: int = 20,
        extra_headers: dict[str, str] | None = None,
        module_map: dict[str, type[Any]] | None = None,
        crawl_max_pages: int = 15,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.verbose = verbose
        self.module_workers = max(1, module_workers)
        self.port_workers = max(1, port_workers)
        self.extra_headers = extra_headers or {}
        self.module_map = module_map if module_map is not None else MODULE_MAP
        self.crawl_max_pages = max(1, crawl_max_pages)
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=self.retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": self.user_agent})
        if self.extra_headers:
            session.headers.update(self.extra_headers)
        return session

    def _resolve_url(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            return f"https://{target}"
        return target

    def scan(self, target: str, modules: list[str]) -> dict[str, Any]:
        url = self._resolve_url(target)
        results: dict[str, Any] = {}
        risk_score = 0

        # Fetch base HTTP response once and share
        http_response = None
        try:
            http_response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=True,
            )
        except requests.exceptions.SSLError:
            try:
                http_response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    verify=False,
                )
            except Exception as exc:
                results["__error__"] = str(exc)
                return results
        except Exception as exc:
            results["__error__"] = str(exc)
            return results

        ctx = {
            "target": target,
            "url": url,
            "response": http_response,
            "session": self.session,
            "timeout": self.timeout,
            "verbose": self.verbose,
            "port_concurrency": self.port_workers,
            "crawl_max_pages": self.crawl_max_pages,
        }

        valid_modules = [(name, self.module_map[name]) for name in modules if name in self.module_map]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.module_workers) as executor:
            futures = [executor.submit(_run_module, name, cls, ctx) for name, cls in valid_modules]
            for future in concurrent.futures.as_completed(futures):
                module_name, module_result = future.result()

                # Accumulate risk score
                for finding in module_result.get("findings", []):
                    risk_score += SEVERITY_WEIGHTS.get(finding.get("severity", "info"), 1)

                results[module_name] = module_result

        results["__meta__"] = {
            "target": target,
            "url": url,
            "risk_score": risk_score,
            "risk_grade": self._grade(risk_score),
            "status_code": http_response.status_code if http_response else None,
            "final_url": http_response.url if http_response else url,
            "scanned_modules": modules,
        }
        return results

    @staticmethod
    def _grade(score: int) -> str:
        if score == 0:
            return "A+"
        if score <= 10:
            return "A"
        if score <= 25:
            return "B"
        if score <= 50:
            return "C"
        if score <= 80:
            return "D"
        return "F"
