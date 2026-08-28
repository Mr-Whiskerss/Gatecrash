"""Check base class and registry."""
from __future__ import annotations

import threading
from typing import Dict, Iterable, List, Optional, Type

from ..models import Endpoint, Finding

REGISTRY: Dict[str, Type["Check"]] = {}


def register(cls: Type["Check"]) -> Type["Check"]:
    if not cls.id:
        raise ValueError(f"{cls.__name__} has no id")
    REGISTRY[cls.id] = cls
    return cls


class Check:
    """Base class for all checks.

    Subclasses implement either `run` (per endpoint) or `run_once` (per scan).
    """

    id: str = ""
    name: str = ""
    description: str = ""
    severity: str = "medium"
    owasp: Optional[str] = None
    cwe: Optional[str] = None
    passive: bool = False            # True = analyses existing traffic, sends nothing
    profiles: tuple = ("safe", "aggressive")
    per_endpoint: bool = True
    #: cap on how many endpoints this check will touch (None = no cap)
    max_endpoints: Optional[int] = None

    def __init__(self, ctx):
        self.ctx = ctx
        self._used = 0
        self._budget_lock = threading.Lock()

    # -- overridables -----------------------------------------------------

    def applies(self, endpoint: Endpoint) -> bool:
        return True

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        return []

    def run_once(self) -> Iterable[Finding]:
        return []

    # -- helpers ----------------------------------------------------------

    def budget_ok(self) -> bool:
        if self.max_endpoints is None:
            return True
        with self._budget_lock:
            return self._used < self.max_endpoints

    def spend(self) -> None:
        with self._budget_lock:
            self._used += 1

    def finding(self, endpoint: Optional[Endpoint], title: str, description: str,
                exchanges: List, *, severity: Optional[str] = None,
                confidence: str = "probable", evidence_summary: str = "",
                remediation: str = "", detail: Optional[dict] = None,
                url: str = "") -> Finding:
        if not url:
            if endpoint is not None:
                url = endpoint.url
            else:
                url = next((e.url for e in exchanges if e is not None and e.url), "")
        return Finding(
            check_id=self.id,
            title=title,
            severity=severity or self.severity,
            confidence=confidence,
            endpoint=endpoint.signature if endpoint else "(scan-wide)",
            url=url,
            description=description,
            evidence_summary=evidence_summary,
            remediation=remediation or self.default_remediation(),
            owasp=self.owasp,
            cwe=self.cwe,
            exchanges=exchanges,
            detail=detail or {},
        )

    def default_remediation(self) -> str:
        return ""
