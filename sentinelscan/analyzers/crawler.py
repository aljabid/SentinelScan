"""Crawler Analyzer – checks security-header consistency across multiple same-origin pages."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from sentinelscan.analyzers.base import BaseAnalyzer
from sentinelscan.analyzers.headers import REQUIRED_HEADERS

DEFAULT_MAX_PAGES = 15
_LINK_PATTERN = re.compile(r'href=["\']([^"\'#][^"\']*)["\']', re.IGNORECASE)


class CrawlerAnalyzer(BaseAnalyzer):
    name = "crawler"

    def analyze(self) -> dict[str, Any]:
        if self.response is None:
            return {"error": "No HTTP response available"}

        max_pages = self.ctx.get("crawl_max_pages", DEFAULT_MAX_PAGES)
        base_netloc = urlsplit(self.url).netloc

        visited: set[str] = set()
        to_visit: list[str] = [self.url]
        pages_checked: list[str] = []
        inconsistent: dict[str, list[str]] = {}

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                resp = (
                    self.response
                    if url == self.url
                    else self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                )
            except Exception as exc:
                self.log.debug("Crawl fetch failed for %s: %s", url, exc)
                continue

            if resp is None or resp.status_code >= 400:
                continue

            pages_checked.append(url)
            present = {k.lower() for k in resp.headers}
            missing = [h for h in REQUIRED_HEADERS if h.lower() not in present]
            if missing:
                inconsistent[url] = missing

            if len(visited) < max_pages:
                try:
                    body = resp.text[:100000]
                except Exception:
                    body = ""
                for match in _LINK_PATTERN.findall(body):
                    link = urljoin(url, match)
                    parsed_link = urlsplit(link)
                    if parsed_link.netloc == base_netloc and parsed_link.scheme in ("http", "https"):
                        clean_link = parsed_link._replace(fragment="").geturl()
                        if clean_link not in visited:
                            to_visit.append(clean_link)

        # Inconsistency is only a meaningful concept once there's more than one page to compare.
        # A single page missing headers is already reported by the `headers` module.
        if len(pages_checked) > 1:
            if inconsistent:
                sample_url, sample_missing = next(iter(inconsistent.items()))
                self.add_finding(
                    title=f"Inconsistent Security Headers Across {len(inconsistent)} Page(s)",
                    description=(
                        f"Checked {len(pages_checked)} page(s) on this site; {len(inconsistent)} are "
                        "missing security headers present elsewhere."
                    ),
                    severity="medium",
                    remediation=(
                        "Apply security headers consistently site-wide (e.g. at the reverse "
                        "proxy/CDN level) instead of only on the homepage."
                    ),
                    evidence=f"{sample_url} missing: {', '.join(sample_missing)}",
                )
            else:
                self.add_finding(
                    title="Consistent Security Headers Across Crawled Pages",
                    description=f"All {len(pages_checked)} crawled pages had consistent security headers.",
                    severity="info",
                )

        return {"pages_crawled": len(pages_checked), "pages": pages_checked, "max_pages": max_pages}
