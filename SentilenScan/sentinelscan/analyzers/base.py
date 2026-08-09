"""Base class for all analyzers."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any


def _sanitize(text: str) -> str:
    """Strip non-printable/control characters (incl. ANSI/terminal escape sequences).

    Findings often embed content pulled straight from a scanned target (port
    banners, crawled URLs, response headers). Printing that unsanitized to a
    terminal (TextReporter) would let a malicious target inject escape
    sequences into the user's terminal -- e.g. to hide other findings in the
    same report. Every Finding field is sanitized here, once, centrally, so no
    analyzer has to remember to do it.
    """
    return "".join(c if c.isprintable() else " " for c in text)


class Finding:
    """Represents a single security finding."""

    def __init__(
        self,
        title: str,
        description: str,
        severity: str,
        remediation: str = "",
        reference: str = "",
        evidence: str = "",
    ) -> None:
        self.title = _sanitize(title)
        self.description = _sanitize(description)
        self.severity = severity  # critical | high | medium | low | info
        self.remediation = _sanitize(remediation)
        self.reference = _sanitize(reference)
        self.evidence = _sanitize(evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "remediation": self.remediation,
            "reference": self.reference,
            "evidence": self.evidence,
        }


class BaseAnalyzer(ABC):
    """All analyzers inherit from this base class."""

    name: str = "base"

    def __init__(self, ctx: dict[str, Any]) -> None:
        self.ctx = ctx
        self.target = ctx["target"]
        self.url = ctx["url"]
        self.response: Any = ctx.get("response")
        self.session: Any = ctx.get("session")
        self.timeout = ctx.get("timeout", 10)
        self.verbose = ctx.get("verbose", False)
        self.log = logging.getLogger(f"sentinelscan.analyzers.{self.name}")
        self._findings: list[Finding] = []

    def add_finding(
        self,
        title: str,
        description: str,
        severity: str,
        remediation: str = "",
        reference: str = "",
        evidence: str = "",
    ) -> None:
        self._findings.append(Finding(title, description, severity, remediation, reference, evidence))

    @abstractmethod
    def analyze(self) -> dict[str, Any]:
        """Perform the analysis and return extra metadata."""

    def run(self) -> dict[str, Any]:
        extra = self.analyze()
        result = {
            "module": self.name,
            "findings": [f.to_dict() for f in self._findings],
        }
        result.update(extra)
        return result
