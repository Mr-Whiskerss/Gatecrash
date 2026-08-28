"""Passive checks - analyse responses we already have, send nothing extra."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable, List

from ..models import Endpoint, Finding
from .base import Check, register

# --------------------------------------------------------------------------
# Signature tables
# --------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("AWS secret access key", re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\"?\s*[:=]\s*\"?[A-Za-z0-9/+=]{40}"), "critical"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}"), "high"),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), "critical"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "critical"),
    ("Bcrypt password hash", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"), "high"),
    ("Password field in response", re.compile(r"(?i)\"(?:password|passwd|pwd|password_hash|secret)\"\s*:\s*\"[^\"]{3,}\""), "high"),
    ("Database connection string", re.compile(r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s\"'<>]{6,}"), "high"),
    ("Bearer/JWT in response body", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}"), "medium"),
]

PII_PATTERNS = [
    ("Email addresses", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), 3),
    ("US SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 1),
    ("Payment card number", re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{2,4}\b"), 1),
    ("Phone numbers", re.compile(r"(?<![\d.])(?:\+\d{1,3}[ \-]?)?(?:\(\d{3}\)|\d{3})[ \-]\d{3}[ \-]\d{4}(?![\d.])"), 3),
]

ERROR_SIGNATURES = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)|File \"/[^\"]+\", line \d+")),
    ("Werkzeug/Flask debugger", re.compile(r"(?i)werkzeug\s+debugger|The debugger caught an exception")),
    ("Django debug page", re.compile(r"(?i)DJANGO_SETTINGS_MODULE|django\.core\.exceptions")),
    ("Java stack trace", re.compile(r"\bat (?:java|javax|jakarta|org\.springframework|com\.sun)\.[\w.$]+\(")),
    (".NET stack trace", re.compile(r"System\.(?:NullReference|InvalidOperation|Data\.SqlClient)\w*Exception")),
    ("PHP error", re.compile(r"(?i)(?:Fatal error|Warning|Notice):.+ in .+ on line \d+|PDOException")),
    ("Node.js stack trace", re.compile(r"\bat [\w.$<>\[\] ]+ \(?/[\w./\-]*node_modules/")),
    ("Ruby stack trace", re.compile(r"\.rb:\d+:in `")),
    ("Go panic", re.compile(r"panic: .+\n\ngoroutine \d+")),
    ("SQL error message", re.compile(r"(?i)SQLSTATE\[|ORA-\d{5}|You have an error in your SQL syntax|unclosed quotation mark|SQLite3::|psql:|PG::\w+Error|MySqlException")),
]

PATH_DISCLOSURE = re.compile(
    r"(?:/(?:home|var/www|usr/local|opt|srv|Users)/[\w./\-]{3,}|[A-Za-z]:\\\\?(?:Users|inetpub|wwwroot)\\[\w.\\\-]{3,})")

INTERNAL_HOST = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|(?:[\w\-]+\.)?(?:internal|local|corp|lan|intranet))\b")

VERSIONED_BANNER = re.compile(r"\d+\.\d+(?:\.\d+)?")


def _luhn(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not 12 <= len(digits) <= 19:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _snippet(text: str, match: re.Match, width: int = 90) -> str:
    start = max(0, match.start() - width // 2)
    end = min(len(text), match.end() + width // 2)
    return ("..." if start else "") + text[start:end].replace("\n", " ") + ("..." if end < len(text) else "")


def _redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return value[:keep] + "***"
    return f"{value[:keep]}***{value[-keep:]} ({len(value)} chars)"


# --------------------------------------------------------------------------

@register
class SecretExposure(Check):
    id = "passive.secrets"
    name = "Credentials or secrets in API response"
    severity = "high"
    owasp = "API3"
    cwe = "CWE-200"
    passive = True
    profiles = ("passive", "safe", "aggressive")

    def default_remediation(self) -> str:
        return ("Strip secrets and password material from API serialisers. Return only the "
                "fields the consumer needs, and rotate any credential exposed here.")

    # A token-issuing endpoint is *supposed* to return a token.
    TOKEN_ISSUERS = ("login", "signin", "sign-in", "token", "oauth", "authorize",
                     "authorise", "session", "refresh", "register", "signup")

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not baseline or not baseline.response_body:
            return []
        body = baseline.response_body
        issuer = any(hint in endpoint.path.lower() for hint in self.TOKEN_ISSUERS)
        out: List[Finding] = []
        for label, pattern, severity in SECRET_PATTERNS:
            if issuer and label == "Bearer/JWT in response body":
                continue
            match = pattern.search(body)
            if not match:
                continue
            out.append(self.finding(
                endpoint,
                f"{label} exposed in response",
                f"The response to `{endpoint.method} {endpoint.path}` contains what looks like "
                f"{label.lower()}. Anything returned here is visible to every client that can "
                f"reach this endpoint, and will sit in proxy logs, browser caches and mobile "
                f"app storage.",
                [baseline],
                severity=severity,
                confidence="firm" if severity in ("critical", "high") else "probable",
                evidence_summary=f"{label} matched in HTTP {baseline.status} body: "
                                 f"{_snippet(body, match)}",
                detail={"pattern": label, "status": baseline.status},
            ))
        return out


@register
class PiiExposure(Check):
    id = "passive.pii"
    name = "Personal data returned in bulk"
    severity = "medium"
    owasp = "API3"
    cwe = "CWE-359"
    passive = True
    profiles = ("passive", "safe", "aggressive")

    def default_remediation(self) -> str:
        return ("Apply object property level authorisation: return personal data only to "
                "principals entitled to it, and only the fields required for the use case.")

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not baseline or not baseline.response_body or baseline.status != 200:
            return []
        body = baseline.response_body
        out = []
        for label, pattern, threshold in PII_PATTERNS:
            matches = pattern.findall(body)
            if label == "Payment card number":
                matches = [m for m in matches if _luhn(m)]
            unique = sorted(set(matches))
            if len(unique) < threshold:
                continue
            severity = "high" if label in ("US SSN", "Payment card number") else "medium"
            out.append(self.finding(
                endpoint,
                f"{label} returned by API ({len(unique)} distinct values)",
                f"`{endpoint.method} {endpoint.path}` returned {len(unique)} distinct values "
                f"matching {label.lower()}. Bulk personal data in a single response is a "
                f"strong indicator of missing property-level authorisation or a missing "
                f"pagination/field-selection boundary.",
                [baseline],
                severity=severity,
                confidence="probable",
                evidence_summary=f"{len(unique)} distinct values, e.g. "
                                 + ", ".join(_redact(u) for u in unique[:3]),
                detail={"count": len(unique), "kind": label},
            ))
        return out


@register
class VerboseErrors(Check):
    id = "passive.verbose_errors"
    name = "Stack trace or internal error detail returned"
    severity = "medium"
    owasp = "API8"
    cwe = "CWE-209"
    passive = True
    profiles = ("passive", "safe", "aggressive")

    def default_remediation(self) -> str:
        return ("Return a generic error body with a correlation ID and log the detail "
                "server-side. Disable debug mode in every deployed environment.")

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not baseline or not baseline.response_body:
            return []
        body = baseline.response_body
        out = []
        for label, pattern in ERROR_SIGNATURES:
            match = pattern.search(body)
            if not match:
                continue
            severity = "high" if "SQL" in label else "medium"
            out.append(self.finding(
                endpoint,
                f"{label} disclosed in response",
                f"`{endpoint.method} {endpoint.path}` returned HTTP {baseline.status} carrying "
                f"a {label.lower()}. This hands an attacker the framework, version, file layout "
                f"and often the query structure behind the endpoint, which materially shortens "
                f"the path to a working injection or deserialisation payload.",
                [baseline],
                severity=severity,
                confidence="firm",
                evidence_summary=f"HTTP {baseline.status}: {_snippet(body, match, 140)}",
                detail={"signature": label},
            ))
            break
        pmatch = PATH_DISCLOSURE.search(body)
        if pmatch:
            out.append(self.finding(
                endpoint,
                "Server filesystem path disclosed",
                f"The response reveals a server-side filesystem path, exposing the deployment "
                f"layout and the account the service runs under.",
                [baseline],
                severity="low",
                confidence="firm",
                evidence_summary=_snippet(body, pmatch),
            ))
        return out


@register
class SecurityHeaders(Check):
    id = "passive.headers"
    name = "Response header hardening"
    severity = "low"
    owasp = "API8"
    cwe = "CWE-693"
    passive = True
    per_endpoint = False
    profiles = ("passive", "safe", "aggressive")

    def default_remediation(self) -> str:
        return ("Set the missing headers at the gateway so every route inherits them: "
                "`Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, "
                "`Cache-Control: no-store` on authenticated data, and suppress version banners.")

    def run_once(self) -> Iterable[Finding]:
        issues = defaultdict(list)          # (label, severity, why) -> [exchange]
        for endpoint, ex in self.ctx.baseline_pairs():
            if not ex or ex.status is None or ex.error:
                continue
            headers = {k.lower(): v for k, v in ex.response_headers.items()}

            if endpoint.scheme == "https" and "strict-transport-security" not in headers:
                issues[("Missing Strict-Transport-Security", "low",
                        "TLS-only enforcement is not signalled, so a client that first "
                        "connects over http:// can be downgraded.")].append((endpoint, ex))
            if headers.get("x-content-type-options", "").lower() != "nosniff":
                issues[("Missing X-Content-Type-Options: nosniff", "low",
                        "Browsers may MIME-sniff a JSON response into HTML or script, "
                        "which turns reflected content into stored XSS.")].append((endpoint, ex))

            ctype = headers.get("content-type", "")
            body = (ex.response_body or "").lstrip()
            if body.startswith(("{", "[")) and "json" not in ctype.lower() and ctype:
                issues[("JSON body served with a non-JSON Content-Type", "medium",
                        f"The body parses as JSON but is labelled `{ctype}`. If it is "
                        f"rendered as HTML, attacker-controlled values in it execute.")].append((endpoint, ex))

            for banner in ("server", "x-powered-by", "x-aspnet-version",
                           "x-aspnetmvc-version", "x-generator"):
                value = headers.get(banner)
                if value and VERSIONED_BANNER.search(value):
                    issues[(f"Software version disclosed in `{banner.title()}` header", "info",
                            "The exact product version lets an attacker look up known CVEs "
                            "without probing the service.")].append((endpoint, ex))

            cache = headers.get("cache-control", "").lower()
            authed = any(k.lower() in ("authorization", "cookie") for k in ex.request_headers)
            if authed and ex.status == 200 and ("no-store" not in cache):
                issues[("Authenticated response is cacheable", "low",
                        "Without `Cache-Control: no-store`, private responses can be retained "
                        "by shared caches and browser disk cache.")].append((endpoint, ex))

        out = []
        for (label, severity, why), pairs in issues.items():
            samples = pairs[:3]
            paths = sorted({p[0].signature for p in pairs})
            out.append(self.finding(
                None, label,
                f"{why}\n\nAffected on {len(paths)} endpoint(s).",
                [p[1] for p in samples],
                severity=severity,
                confidence="firm",
                url=samples[0][0].url,
                evidence_summary=f"{len(paths)} endpoints, e.g. " + ", ".join(paths[:5]),
                detail={"affected_endpoints": paths},
            ))
        return out


@register
class InsecureTransport(Check):
    id = "passive.transport"
    name = "Endpoint reachable over cleartext HTTP"
    severity = "high"
    owasp = "API8"
    cwe = "CWE-319"
    passive = True
    per_endpoint = False
    profiles = ("passive", "safe", "aggressive")

    def default_remediation(self) -> str:
        return "Terminate only TLS, redirect http:// to https:// and set HSTS with a long max-age."

    def run_once(self) -> Iterable[Finding]:
        http_pairs = [(ep, ex) for ep, ex in self.ctx.baseline_pairs()
                      if ep.scheme == "http" and ex and ex.status is not None]
        if not http_pairs:
            return []
        paths = sorted({ep.signature for ep, _ in http_pairs})
        return [self.finding(
            None, "API served over cleartext HTTP",
            f"{len(paths)} endpoint(s) answered over plain HTTP. Bearer tokens, API keys and "
            f"session cookies sent to these endpoints are readable and modifiable by anyone on "
            f"the network path.",
            [ex for _, ex in http_pairs[:3]],
            confidence="firm",
            url=http_pairs[0][0].url,
            evidence_summary=f"{len(paths)} cleartext endpoints, e.g. " + ", ".join(paths[:5]),
            detail={"affected_endpoints": paths},
        )]


@register
class InternalHostLeak(Check):
    id = "passive.internal_hosts"
    name = "Internal hostname or RFC1918 address disclosed"
    severity = "low"
    owasp = "API8"
    cwe = "CWE-200"
    passive = True
    profiles = ("passive", "safe", "aggressive")

    def default_remediation(self) -> str:
        return ("Rewrite internal addresses at the edge and avoid echoing upstream service "
                "locations in headers or error bodies.")

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not baseline:
            return []
        haystacks = [("body", baseline.response_body or "")]
        haystacks += [(f"header {k}", v) for k, v in baseline.response_headers.items()
                      if k.lower() in ("location", "x-backend", "x-upstream", "via",
                                       "x-served-by", "x-forwarded-host")]
        for where, text in haystacks:
            match = INTERNAL_HOST.search(text)
            if match and not match.group(0).endswith(("0.0", "0.1")):
                return [self.finding(
                    endpoint,
                    "Internal network address disclosed",
                    f"`{endpoint.method} {endpoint.path}` leaked an internal address in the "
                    f"{where}. This maps the internal topology and gives an SSRF or pivot "
                    f"attempt a concrete target.",
                    [baseline],
                    confidence="probable",
                    evidence_summary=f"{where}: {_snippet(text, match)}",
                )]
        return []
