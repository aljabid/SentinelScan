"""Base class for all analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List


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
        self.title = title
        self.description = description
        self.severity = severity  # critical | high | medium | low | info
        self.remediation = remediation
        self.reference = reference
        self.evidence = evidence

    def to_dict(self) -> Dict[str, Any]:
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

    def __init__(self, ctx: Dict[str, Any]) -> None:
        self.ctx = ctx
        self.target = ctx["target"]
        self.url = ctx["url"]
        self.response = ctx.get("response")
        self.session = ctx.get("session")
        self.timeout = ctx.get("timeout", 10)
        self.verbose = ctx.get("verbose", False)
        self._findings: List[Finding] = []

    def add_finding(
        self,
        title: str,
        description: str,
        severity: str,
        remediation: str = "",
        reference: str = "",
        evidence: str = "",
    ) -> None:
        self._findings.append(
            Finding(title, description, severity, remediation, reference, evidence)
        )

    @abstractmethod
    def analyze(self) -> Dict[str, Any]:
        """Perform the analysis and return extra metadata."""

    def run(self) -> Dict[str, Any]:
        extra = self.analyze()
        result = {
            "module": self.name,
            "findings": [f.to_dict() for f in self._findings],
        }
        result.update(extra)
        return result
