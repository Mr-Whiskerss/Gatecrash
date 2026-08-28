"""Security misconfiguration and resource consumption checks."""
from __future__ import annotations

import json
import logging
import time
from typing import Iterable, List, Optional

from ..engine import looks_authorised
from ..models import Endpoint, Finding
from .base import Check, register

PROBE_ORIGIN = "https://gatecrash-probe.example"

log = logging.getLogger("gatecrash")


@register
class CorsMisconfiguration(Check):
    id = "misconfig.cors"
    name = "Cross-Origin Resource Sharing misconfiguration"
    severity = "high"
    owasp = "API8"
    cwe = "CWE-942"
    profiles = ("safe", "aggressive")
    per_endpoint = False

    def default_remediation(self) -> str:
        return ("Match `Origin` against a static allow-list and echo only exact matches. Never "
                "reflect an arbitrary origin, never return `null`, and never combine "
                "`Access-Control-Allow-Origin: *` with `Allow-Credentials: true`.")

    def run_once(self) -> Iterable[Finding]:
        out: List[Finding] = []
        seen_hosts = set()
        for endpoint, baseline in self.ctx.baseline_pairs():
            if endpoint.host in seen_hosts:
                continue
            if not looks_authorised(baseline):
                continue
            seen_hosts.add(endpoint.host)

            target_host = endpoint.host.split(":")[0]
            probes = [
                ("arbitrary origin", PROBE_ORIGIN),
                ("null origin", "null"),
                ("suffix-matching bypass", f"https://{target_host}.gatecrash-probe.example"),
                ("prefix-matching bypass", f"https://gatecrash-probe-{target_host}"),
            ]
            for label, origin in probes:
                ex = self.ctx.replay(endpoint, self.ctx.primary,
                                     headers={"Origin": origin},
                                     note=f"CORS probe - {label}: Origin: {origin}")
                headers = {k.lower(): v for k, v in ex.response_headers.items()}
                acao = headers.get("access-control-allow-origin")
                acac = (headers.get("access-control-allow-credentials") or "").lower() == "true"
                if not acao:
                    continue

                reflected = acao.strip() == origin
                wildcard = acao.strip() == "*"

                if reflected and acac:
                    out.append(self.finding(
                        endpoint,
                        f"CORS reflects an attacker-controlled origin with credentials ({label})",
                        f"The server echoed `Access-Control-Allow-Origin: {acao}` together with "
                        f"`Access-Control-Allow-Credentials: true` for the origin `{origin}`. Any "
                        f"web page an authenticated user visits can therefore read this endpoint's "
                        f"responses with the user's cookies attached - a full cross-origin data "
                        f"theft primitive.",
                        [ex], severity="high", confidence="firm",
                        evidence_summary=f"Origin: {origin} -> ACAO: {acao}, ACAC: true",
                        detail={"origin": origin, "acao": acao, "credentials": True},
                    ))
                    break
                if reflected and origin != "null":
                    out.append(self.finding(
                        endpoint,
                        f"CORS reflects an arbitrary origin ({label})",
                        f"`Access-Control-Allow-Origin` was set to `{acao}` for the supplied "
                        f"origin `{origin}`. Credentials are not allowed, so the immediate impact "
                        f"is limited, but any endpoint that authorises by IP, network position or "
                        f"a non-cookie mechanism is readable cross-origin.",
                        [ex], severity="medium", confidence="firm",
                        evidence_summary=f"Origin: {origin} -> ACAO: {acao}",
                    ))
                    break
                if wildcard and acac:
                    out.append(self.finding(
                        endpoint,
                        "CORS wildcard combined with credentials",
                        "`Access-Control-Allow-Origin: *` was returned alongside "
                        "`Access-Control-Allow-Credentials: true`. Browsers reject this "
                        "combination, but non-browser clients and some proxies do not, and it "
                        "signals that the CORS policy is not deliberately scoped.",
                        [ex], severity="medium", confidence="firm",
                        evidence_summary=f"ACAO: * with ACAC: true",
                    ))
                    break
        return out


@register
class MethodEnumeration(Check):
    id = "misconfig.methods"
    name = "Unexpected HTTP methods enabled"
    severity = "low"
    owasp = "API8"
    cwe = "CWE-16"
    profiles = ("safe", "aggressive")
    max_endpoints = 20

    def default_remediation(self) -> str:
        return ("Restrict each route to the verbs it implements and disable TRACE at the "
                "web server or gateway.")

    def applies(self, endpoint: Endpoint) -> bool:
        return True

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not self.budget_ok():
            return []
        self.spend()
        out = []

        options = self.ctx.replay(endpoint.clone(method="OPTIONS", body=None),
                                  self.ctx.primary, note="OPTIONS method discovery")
        allow = options.response_headers.get("Allow") or options.response_headers.get("allow")
        if allow:
            methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
            risky = methods & {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
            if risky:
                out.append(self.finding(
                    endpoint,
                    f"Endpoint advertises {', '.join(sorted(risky))}",
                    f"`OPTIONS {endpoint.path}` advertised `Allow: {allow}`. The state-changing "
                    f"verbs listed here were not exercised by this scan (they are gated behind "
                    f"`--allow-destructive`), so confirm manually whether they are authorised "
                    f"to the same standard as the documented verbs.",
                    [options], severity="info", confidence="firm",
                    evidence_summary=f"Allow: {allow}",
                    detail={"allow": sorted(methods)},
                ))

        trace = self.ctx.replay(endpoint.clone(method="TRACE", body=None), self.ctx.primary,
                                headers={"X-Gatecrash-Probe": "trace-reflection"},
                                note="TRACE method probe (cross-site tracing)")
        if trace.status == 200 and "trace-reflection" in (trace.response_body or ""):
            out.append(self.finding(
                endpoint,
                "TRACE method enabled and reflecting request headers",
                "The server answered `TRACE` with HTTP 200 and echoed the request headers back. "
                "Combined with any script execution context this enables Cross-Site Tracing, "
                "reading headers the client cannot otherwise access (including HttpOnly cookies).",
                [trace], severity="medium", confidence="firm",
                evidence_summary="TRACE returned 200 with the probe header reflected",
            ))
        return out


@register
class RateLimiting(Check):
    id = "misconfig.rate_limit"
    name = "No rate limiting on sensitive endpoint"
    severity = "medium"
    owasp = "API4"
    cwe = "CWE-770"
    profiles = ("safe", "aggressive")
    per_endpoint = False

    SENSITIVE_HINTS = ("login", "signin", "sign-in", "auth", "token", "otp", "verify",
                       "password", "reset", "forgot", "sms")

    #: Bursting one of these would create 25 real records, charges or messages.
    #: A state-changing endpoint is only ever burst if it is an authentication
    #: endpoint, and never if it looks like it creates or sends something.
    NEVER_BURST = ("order", "payment", "charge", "invoice", "checkout", "purchase",
                   "subscribe", "subscription", "refund", "transfer", "payout",
                   "invite", "notify", "notification", "message", "send", "mail",
                   "sms", "webhook", "publish", "upload", "import", "export",
                   "signup", "sign-up", "register", "provision", "deploy", "ticket")

    def default_remediation(self) -> str:
        return ("Rate limit per identity and per source address at the gateway, with a stricter "
                "budget on authentication and messaging endpoints, and return HTTP 429 with "
                "`Retry-After`.")

    def _eligible(self, endpoint: Endpoint) -> bool:
        """Is it safe to send this endpoint 25 times in a row?

        Read-only endpoints always are. A state-changing endpoint only is when it
        is an authentication endpoint - bursting anything that creates a record or
        sends a message would do 25x real damage to a client's system.
        """
        path = endpoint.path.lower()
        if endpoint.method in ("GET", "HEAD"):
            return True
        if any(h in path for h in self.NEVER_BURST):
            return False
        return any(h in path for h in self.SENSITIVE_HINTS)

    def _pick(self) -> Optional[tuple]:
        candidates = []
        skipped_writes = []
        for endpoint, baseline in self.ctx.baseline_pairs():
            if baseline is None or baseline.error:
                continue
            if not self._eligible(endpoint):
                if endpoint.method not in ("GET", "HEAD"):
                    skipped_writes.append(endpoint.signature)
                continue
            path = endpoint.path.lower()
            score = 0
            if any(h in path for h in self.SENSITIVE_HINTS):
                score += 10
            if endpoint.method in ("GET", "HEAD"):
                score += 1
            candidates.append((score, endpoint, baseline))
        if skipped_writes:
            log.info("rate-limit probe: not bursting %d state-changing endpoint(s) - %s",
                     len(skipped_writes), ", ".join(sorted(set(skipped_writes))[:5]))
        if not candidates:
            log.info("rate-limit probe: no endpoint was safe to burst, check skipped")
            return None
        candidates.sort(key=lambda c: -c[0])
        return candidates[0][1], candidates[0][2]

    def run_once(self) -> Iterable[Finding]:
        burst = self.ctx.config.get("rate_limit_burst", 0)
        if not burst:
            return []
        picked = self._pick()
        if not picked:
            return []
        endpoint, baseline = picked

        statuses = []
        exchanges = []
        started = time.monotonic()
        for i in range(burst):
            ex = self.ctx.replay(endpoint, self.ctx.primary,
                                 note=f"rate limit burst {i + 1}/{burst}")
            statuses.append(ex.status)
            if i in (0, burst - 1):
                exchanges.append(ex)
        elapsed = time.monotonic() - started
        throttled = sum(1 for s in statuses if s in (429, 503))
        served = sum(1 for s in statuses if s and 200 <= s < 400)

        if throttled == 0 and served >= burst * 0.9:
            sensitive = any(h in endpoint.path.lower() for h in self.SENSITIVE_HINTS)
            return [self.finding(
                endpoint,
                "No rate limiting observed" + (" on an authentication endpoint" if sensitive else ""),
                f"{burst} consecutive requests to `{endpoint.method} {endpoint.path}` were all "
                f"served in {elapsed:.1f}s with no HTTP 429 or 503 and no `Retry-After` or "
                f"`X-RateLimit-*` headers. "
                + ("This endpoint handles authentication or account recovery, so the absence of "
                   "throttling permits credential stuffing, OTP brute force and account "
                   "enumeration at scale."
                   if sensitive else
                   "Without a request budget the API is exposed to scraping and to cost-driven "
                   "denial of service.")
                + "\n\nNote: an upstream WAF or edge rate limiter may apply at volumes higher "
                  "than this probe used.",
                exchanges,
                severity="high" if sensitive else "medium",
                confidence="probable",
                evidence_summary=f"{served}/{burst} requests served in {elapsed:.1f}s, "
                                 f"0 throttled",
                detail={"burst": burst, "served": served, "throttled": throttled,
                        "elapsed_seconds": round(elapsed, 2)},
            )]
        return []


@register
class UnrestrictedResourceConsumption(Check):
    id = "misconfig.pagination"
    name = "Pagination limits not enforced"
    severity = "medium"
    owasp = "API4"
    cwe = "CWE-770"
    profiles = ("safe", "aggressive")
    max_endpoints = 10

    PARAMS = ("limit", "per_page", "perPage", "page_size", "pageSize", "count", "size", "take")

    def default_remediation(self) -> str:
        return ("Clamp page size server-side to a maximum regardless of the value supplied, and "
                "reject non-numeric or negative values.")

    def applies(self, endpoint: Endpoint) -> bool:
        return endpoint.method == "GET"

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not self.budget_ok() or not looks_authorised(baseline):
            return []
        try:
            data = json.loads(baseline.response_body or "")
        except (ValueError, TypeError):
            return []
        items = data if isinstance(data, list) else next(
            (v for v in data.values() if isinstance(v, list) and len(v) >= 3), None) \
            if isinstance(data, dict) else None
        if not items or len(items) < 3:
            return []
        self.spend()

        for param in self.PARAMS:
            ex = self.ctx.replay(endpoint.with_query_param(param, "10000"), self.ctx.primary,
                                 note=f"pagination probe: {param}=10000")
            if not looks_authorised(ex):
                continue

            # A very large response gets truncated before it reaches us, which is
            # itself the strongest possible evidence that the limit is unclamped.
            if ex.truncated and ex.body_bytes > max(baseline.body_bytes * 5, 100_000):
                return [self.finding(
                    endpoint,
                    f"Client controls page size without an upper bound (`{param}`)",
                    f"`{endpoint.method} {endpoint.path}` returned {baseline.body_bytes} bytes "
                    f"by default but {ex.body_bytes} bytes when called with `{param}=10000`. The "
                    f"server honours the client's page size unclamped, so a single request can "
                    f"force an unbounded database read and response serialisation - a cheap "
                    f"denial of service and an efficient bulk-extraction primitive.",
                    [baseline, ex], confidence="firm",
                    evidence_summary=f"default {baseline.body_bytes} bytes -> {param}=10000 "
                                     f"returned {ex.body_bytes} bytes "
                                     f"({ex.body_bytes / max(baseline.body_bytes, 1):.0f}x)",
                    detail={"parameter": param, "default_bytes": baseline.body_bytes,
                            "probe_bytes": ex.body_bytes},
                )]
            try:
                probe_data = json.loads(ex.response_body or "")
            except (ValueError, TypeError):
                continue
            probe_items = probe_data if isinstance(probe_data, list) else next(
                (v for v in probe_data.values() if isinstance(v, list)), None) \
                if isinstance(probe_data, dict) else None
            if probe_items is None:
                continue
            if len(probe_items) > len(items) * 2 and len(probe_items) > 50:
                return [self.finding(
                    endpoint,
                    f"Client controls page size without an upper bound (`{param}`)",
                    f"`{endpoint.method} {endpoint.path}` returned {len(items)} records by "
                    f"default but {len(probe_items)} when called with `{param}=10000`. The server "
                    f"honours the client's page size unclamped, so a single request can force an "
                    f"unbounded database read and response serialisation - a cheap denial of "
                    f"service and an efficient bulk-extraction primitive.",
                    [baseline, ex], confidence="firm",
                    evidence_summary=f"default {len(items)} items -> {param}=10000 returned "
                                     f"{len(probe_items)} items ({ex.body_bytes} bytes)",
                    detail={"parameter": param, "default_items": len(items),
                            "probe_items": len(probe_items)},
                )]
        return []


@register
class DebugSurface(Check):
    id = "misconfig.debug_surface"
    name = "Debug or management interface exposed"
    severity = "high"
    owasp = "API9"
    cwe = "CWE-489"
    profiles = ("aggressive",)
    per_endpoint = False

    PATHS = [
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
        "/debug/pprof/", "/swagger-ui/index.html", "/swagger.json", "/openapi.json",
        "/v2/api-docs", "/v3/api-docs", "/.env", "/graphql", "/graphiql",
        "/api-docs", "/metrics", "/server-status", "/console", "/_profiler",
    ]

    def default_remediation(self) -> str:
        return ("Remove or authenticate management, profiling and schema endpoints in every "
                "internet-facing environment, and bind them to a private interface.")

    def run_once(self) -> Iterable[Finding]:
        hosts = {}
        for endpoint, _ in self.ctx.baseline_pairs():
            hosts.setdefault(f"{endpoint.scheme}://{endpoint.host}", endpoint)
        out = []
        for base, sample in list(hosts.items())[:3]:
            for path in self.PATHS:
                probe = sample.clone(url=base + path, method="GET", body=None,
                                     headers={}, name=f"GET {path}")
                ex = self.ctx.replay(probe, self.ctx.primary,
                                     note=f"management surface probe: {path}")
                if ex.status != 200 or not ex.response_body:
                    continue
                body = ex.response_body[:2000].lower()
                if "<html" in body and "swagger" not in body and "graphiql" not in body:
                    continue
                severity = "critical" if path in ("/.env", "/actuator/env",
                                                  "/actuator/heapdump") else "high"
                out.append(self.finding(
                    probe,
                    f"Exposed management endpoint: `{path}`",
                    f"`GET {path}` returned HTTP 200 with {ex.body_bytes} bytes. Endpoints of "
                    f"this kind expose configuration, environment variables, memory dumps or the "
                    f"complete API schema, and are frequently the fastest route from external "
                    f"access to credentials.",
                    [ex], severity=severity, confidence="firm", url=base + path,
                    evidence_summary=f"GET {path} -> HTTP 200, {ex.body_bytes} bytes",
                ))
        return out
