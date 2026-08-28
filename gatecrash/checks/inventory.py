"""API9 - Improper Inventory Management, and the API4 depth checks."""
from __future__ import annotations

import json
import re
import time
from typing import Iterable, List, Optional
from urllib.parse import parse_qsl, urlsplit

from ..engine import body_similarity, looks_authorised
from ..models import Endpoint, Finding
from .base import Check, register

VERSION_RE = re.compile(r"/(v|version[-_]?)(\d{1,2})(?:\.(\d{1,2}))?(?=/|$)", re.I)

NONPROD_MARKERS = re.compile(
    r"\b(staging|stage|dev|development|test|testing|qa|uat|sandbox|preprod|pre-prod|demo)\b",
    re.I)


@register
class ShadowApiVersions(Check):
    """Older API versions usually stop getting patched but keep serving traffic."""

    id = "inventory.api_versions"
    name = "Older or undocumented API version still live"
    severity = "high"
    owasp = "API9"
    cwe = "CWE-1059"
    profiles = ("safe", "aggressive")
    per_endpoint = False

    def default_remediation(self) -> str:
        return ("Maintain an inventory of every deployed API version and retire old ones on a "
                "schedule. While a deprecated version is still reachable it must receive the "
                "same authorisation, validation and patching as the current one.")

    def run_once(self) -> Iterable[Finding]:
        seen_prefixes = {}
        for endpoint, baseline in self.ctx.baseline_pairs():
            if not looks_authorised(baseline):
                continue
            match = VERSION_RE.search(endpoint.path)
            if not match:
                continue
            key = (endpoint.host, match.group(0), endpoint.path)
            seen_prefixes.setdefault(key, (endpoint, baseline, match))

        out: List[Finding] = []
        probed_versions = set()

        for (host, marker, _path), (endpoint, baseline, match) in list(seen_prefixes.items())[:6]:
            current = int(match.group(2))
            prefix, suffix = match.group(1), match.group(0)
            for candidate in range(max(current - 3, 0), current):
                replacement = f"/{prefix}{candidate}"
                if suffix.endswith("/"):
                    replacement += "/"
                probe_url = endpoint.url.replace(suffix, replacement, 1)
                if (host, probe_url) in probed_versions:
                    continue
                probed_versions.add((host, probe_url))

                probe = self.ctx.replay(
                    endpoint.clone(url=probe_url), self.ctx.primary,
                    note=f"inventory probe - version {suffix.strip('/')} downgraded to "
                         f"{replacement.strip('/')}")
                if not looks_authorised(probe) or not probe.response_body:
                    continue

                similarity = body_similarity(baseline.response_body or "",
                                             probe.response_body or "")
                out.append(self.finding(
                    endpoint.clone(url=probe_url),
                    f"Superseded API version `{replacement.strip('/')}` is still serving traffic",
                    f"The collection documents `{suffix.strip('/')}`, but "
                    f"`{replacement.strip('/')}` also answered with HTTP {probe.status} and "
                    f"{probe.body_bytes} bytes ({similarity:.0%} similar to the current "
                    f"version's response). Superseded versions are typically excluded from "
                    f"security review and patching while remaining fully reachable, and often "
                    f"predate the authorisation fixes applied to the current version. Retest "
                    f"every authorisation finding in this report against this older version "
                    f"as well.",
                    [baseline, probe],
                    confidence="firm", url=probe_url,
                    evidence_summary=f"{replacement.strip('/')} -> HTTP {probe.status}, "
                                     f"{probe.body_bytes} bytes",
                    detail={"documented_version": suffix.strip('/'),
                            "live_older_version": replacement.strip('/'),
                            "similarity": round(similarity, 3)},
                ))
        return out


@register
class NonProductionLeak(Check):
    """Is a non-production build answering on the host under test?"""

    id = "inventory.environment"
    name = "Non-production environment indicators"
    severity = "medium"
    owasp = "API9"
    cwe = "CWE-1059"
    passive = True
    per_endpoint = False
    profiles = ("passive", "safe", "aggressive")

    HEADERS = ("x-environment", "x-env", "x-app-env", "x-release", "x-version",
               "x-deployment", "x-served-by", "x-vercel-deployment-url")

    def default_remediation(self) -> str:
        return ("Do not expose environment identifiers to clients, and ensure non-production "
                "deployments are not reachable from the internet or are behind access control.")

    def run_once(self) -> Iterable[Finding]:
        hits = []
        for endpoint, ex in self.ctx.baseline_pairs():
            if ex is None or ex.status is None:
                continue
            headers = {k.lower(): v for k, v in ex.response_headers.items()}
            for name in self.HEADERS:
                value = headers.get(name)
                if value and NONPROD_MARKERS.search(value):
                    hits.append((endpoint, ex, f"header `{name}: {value}`"))
                    break
            else:
                host_match = NONPROD_MARKERS.search(endpoint.host)
                if host_match:
                    hits.append((endpoint, ex, f"hostname contains `{host_match.group(0)}`"))
        if not hits:
            return []
        endpoint, ex, why = hits[0]
        paths = sorted({e.signature for e, _, _ in hits})
        return [self.finding(
            None,
            "Target appears to be a non-production environment",
            f"{why}. Non-production deployments routinely carry debug settings, seeded data, "
            f"weaker credentials and relaxed authorisation. If this is intentional for the "
            f"engagement, note it - findings here do not automatically apply to production, "
            f"and production may have issues this environment does not.",
            [ex], confidence="probable", url=endpoint.url,
            evidence_summary=f"{why} across {len(paths)} endpoint(s)",
            detail={"indicator": why, "affected_endpoints": paths},
        )]


@register
class RequestSizeLimits(Check):
    """API4 - does the server accept an arbitrarily large request?"""

    id = "misconfig.payload_limits"
    name = "No request size limit enforced"
    severity = "medium"
    owasp = "API4"
    cwe = "CWE-770"
    profiles = ("aggressive",)
    max_endpoints = 6

    def default_remediation(self) -> str:
        return ("Set a maximum request body and URL length at the gateway and reject anything "
                "larger with HTTP 413/414 before it reaches application code.")

    def applies(self, endpoint: Endpoint) -> bool:
        # Query-parameter inflation only: growing a POST body would write an
        # oversized record into the client's database.
        return endpoint.method == "GET" and bool(urlsplit(endpoint.url).query)

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not self.budget_ok() or not looks_authorised(baseline):
            return []
        self.spend()
        size_kb = int(self.ctx.config.get("max_payload_kb", 64))
        pairs = parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True)
        if not pairs:
            return []
        name = pairs[0][0]
        probe = self.ctx.replay(
            endpoint.with_query_param(name, "A" * (size_kb * 1024)), self.ctx.primary,
            note=f"request size probe - `{name}` inflated to {size_kb}KB")
        if probe.error or probe.status is None:
            return []
        if probe.status in (413, 414, 400, 431):
            return []
        if not looks_authorised(probe):
            return []
        return [self.finding(
            endpoint,
            f"{size_kb}KB parameter accepted without a size limit",
            f"`{endpoint.method} {endpoint.path}` accepted a {size_kb}KB value in the `{name}` "
            f"parameter and returned HTTP {probe.status} rather than 413 or 414. Without a "
            f"size ceiling, request handling, logging and any downstream parsing scale with "
            f"whatever the client sends, which is a cheap way to exhaust memory, fill logs or "
            f"drive up per-request cost.",
            [baseline, probe], confidence="firm",
            evidence_summary=f"{size_kb}KB `{name}` -> HTTP {probe.status} "
                             f"in {probe.elapsed_ms:.0f}ms",
            detail={"parameter": name, "payload_kb": size_kb, "status": probe.status},
        )]


@register
class ExpensiveQuery(Check):
    """API4 - can the client make the server do disproportionate work?"""

    id = "misconfig.expensive_query"
    name = "Client can force a disproportionately expensive query"
    severity = "medium"
    owasp = "API4"
    cwe = "CWE-770"
    profiles = ("aggressive",)
    max_endpoints = 8

    WILDCARDS = ("*", "%", ".*", "%25", "a%")
    SEARCH_HINTS = ("q", "query", "search", "filter", "term", "keyword", "name", "text",
                    "find", "match", "where", "sort", "order", "expand", "include", "fields")

    def default_remediation(self) -> str:
        return ("Reject leading-wildcard and unbounded search patterns, enforce a query "
                "timeout and result ceiling, and require an indexed predicate on any "
                "collection endpoint.")

    def _search_params(self, endpoint: Endpoint) -> List[str]:
        return [name for name, _ in parse_qsl(urlsplit(endpoint.url).query,
                                              keep_blank_values=True)
                if any(h == name.lower() or h in name.lower() for h in self.SEARCH_HINTS)]

    def applies(self, endpoint: Endpoint) -> bool:
        return endpoint.method == "GET" and bool(self._search_params(endpoint))

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not self.budget_ok() or not looks_authorised(baseline):
            return []
        self.spend()
        name = self._search_params(endpoint)[0]
        base_ms = max(baseline.elapsed_ms, 1.0)

        for wildcard in self.WILDCARDS:
            probe = self.ctx.replay(endpoint.with_query_param(name, wildcard),
                                    self.ctx.primary,
                                    note=f"expensive query probe - `{name}={wildcard}`")
            if probe.error or not looks_authorised(probe):
                continue
            slower = probe.elapsed_ms / base_ms
            bigger = (probe.body_bytes or 0) / max(baseline.body_bytes or 1, 1)
            if (slower >= 5 and probe.elapsed_ms > 1000) or bigger >= 10:
                return [self.finding(
                    endpoint,
                    f"Unbounded wildcard search accepted on `{name}`",
                    f"`{name}={wildcard}` took {probe.elapsed_ms:.0f}ms and returned "
                    f"{probe.body_bytes} bytes, against a {base_ms:.0f}ms / "
                    f"{baseline.body_bytes} byte baseline - {slower:.1f}x slower and "
                    f"{bigger:.1f}x larger. A single client request drives disproportionate "
                    f"server work, so a handful of concurrent requests can saturate the "
                    f"database without any volumetric attack.",
                    [baseline, probe], confidence="probable",
                    evidence_summary=f"`{name}={wildcard}`: {probe.elapsed_ms:.0f}ms / "
                                     f"{probe.body_bytes}B vs baseline {base_ms:.0f}ms / "
                                     f"{baseline.body_bytes}B",
                    detail={"parameter": name, "payload": wildcard,
                            "slowdown": round(slower, 2), "size_ratio": round(bigger, 2)},
                )]
        return []
