"""Core data model: endpoints, HTTP exchanges (evidence) and findings."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit


# --------------------------------------------------------------------------
# Taxonomy
# --------------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_SCORE = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# OWASP API Security Top 10 (2023)
OWASP_API_2023 = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

DESTRUCTIVE_METHODS = {"DELETE", "PUT", "PATCH"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

#: When True, credential header values are masked wherever evidence is rendered.
#: Set once from the CLI (--redact) before reports are written.
REDACT_CREDENTIALS = False

_REDACTED_HEADERS = frozenset({
    "authorization", "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token",
    "x-session-token", "x-csrf-token", "cookie", "set-cookie", "x-amz-security-token",
})


def set_redaction(enabled: bool) -> None:
    global REDACT_CREDENTIALS
    REDACT_CREDENTIALS = bool(enabled)


def _mask(name: str, value: str) -> str:
    if not REDACT_CREDENTIALS or name.lower() not in _REDACTED_HEADERS:
        return value
    scheme, _, rest = value.partition(" ")
    if rest and scheme.lower() in ("bearer", "basic", "token", "digest"):
        return f"{scheme} [redacted: {len(rest)} chars]"
    return f"[redacted: {len(value)} chars]"


# --------------------------------------------------------------------------
# Endpoint
# --------------------------------------------------------------------------

_PATH_PARAM_RE = re.compile(r"\{([^}/]+)\}|:([A-Za-z_][A-Za-z0-9_]*)")
_ID_LIKE_RE = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{24}|[0-9a-fA-F]{32})$"
)


@dataclass
class Endpoint:
    """One request template discovered from a collection / spec / URL."""

    method: str
    url: str                                   # concrete URL, variables resolved
    name: str = ""
    path_template: str = ""                    # e.g. /users/{id}
    headers: Dict[str, str] = field(default_factory=dict)
    query: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    content_type: Optional[str] = None
    source: str = ""                           # which file it came from
    auth_hint: Optional[str] = None            # 'bearer', 'apikey', 'basic', None
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        if not self.path_template:
            self.path_template = urlsplit(self.url).path or "/"
        if not self.name:
            self.name = f"{self.method} {self.path_template}"

    # -- helpers ----------------------------------------------------------

    @property
    def host(self) -> str:
        return urlsplit(self.url).netloc.lower()

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme.lower()

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    @property
    def signature(self) -> str:
        """Stable identity used for dedup: METHOD + normalised path."""
        return f"{self.method} {normalise_path(self.path)}"

    @property
    def json_body(self) -> Optional[Any]:
        if not self.body:
            return None
        ct = (self.content_type or "").lower()
        if "json" not in ct and not self.body.lstrip().startswith(("{", "[")):
            return None
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None

    def id_segments(self) -> List[tuple]:
        """Return [(index, value)] for path segments that look like object IDs."""
        out = []
        segs = self.path.strip("/").split("/")
        for i, seg in enumerate(segs):
            if seg and _ID_LIKE_RE.match(seg):
                out.append((i, seg))
        return out

    def with_path_segment(self, index: int, value: str) -> str:
        """Return this endpoint's URL with path segment `index` replaced."""
        parts = urlsplit(self.url)
        segs = parts.path.strip("/").split("/")
        if index >= len(segs):
            return self.url
        segs[index] = str(value)
        new_path = "/" + "/".join(segs)
        if parts.path.endswith("/") and not new_path.endswith("/"):
            new_path += "/"
        return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))

    def with_query_param(self, name: str, value: str) -> "Endpoint":
        """Return a clone with `name` **replaced** in the query string.

        Appending a second copy of a parameter is not equivalent: most servers read
        the first occurrence, so an appended probe payload is silently ignored and
        the check reports nothing. Always replace.
        """
        from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit
        parts = urlsplit(self.url)
        pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                 if k != name]
        pairs.append((name, value))
        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in pairs)
        return self.clone(url=urlunsplit(
            (parts.scheme, parts.netloc, parts.path, query, parts.fragment)))

    def clone(self, **overrides) -> "Endpoint":
        data = {
            "method": self.method, "url": self.url, "name": self.name,
            "path_template": self.path_template, "headers": dict(self.headers),
            "query": dict(self.query), "body": self.body,
            "content_type": self.content_type, "source": self.source,
            "auth_hint": self.auth_hint, "tags": list(self.tags),
        }
        data.update(overrides)
        return Endpoint(**data)


def normalise_path(path: str) -> str:
    """Collapse ID-looking segments so /users/1 and /users/2 dedup together."""
    segs = []
    for seg in path.strip("/").split("/"):
        if seg and _ID_LIKE_RE.match(seg):
            segs.append("{id}")
        else:
            segs.append(seg)
    return "/" + "/".join(segs)


def path_params(template: str) -> List[str]:
    names = []
    for m in _PATH_PARAM_RE.finditer(template or ""):
        names.append(m.group(1) or m.group(2))
    return names


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------

@dataclass
class Exchange:
    """A single request/response pair kept verbatim as evidence."""

    id: str
    identity: str
    method: str
    url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    status: Optional[int] = None
    reason: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    elapsed_ms: float = 0.0
    body_bytes: int = 0
    error: Optional[str] = None
    truncated: bool = False
    note: str = ""

    @staticmethod
    def new_id() -> str:
        return uuid.uuid4().hex[:12]

    def raw_request(self) -> str:
        parts = urlsplit(self.url)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        lines = [f"{self.method} {target} HTTP/1.1", f"Host: {parts.netloc}"]
        for k, v in self.request_headers.items():
            if k.lower() == "host":
                continue
            lines.append(f"{k}: {_mask(k, v)}")
        out = "\r\n".join(lines) + "\r\n\r\n"
        if self.request_body:
            out += self.request_body
        return out

    def raw_response(self) -> str:
        if self.error:
            return f"<transport error> {self.error}"
        lines = [f"HTTP/1.1 {self.status} {self.reason}".rstrip()]
        for k, v in self.response_headers.items():
            lines.append(f"{k}: {_mask(k, v)}")
        out = "\r\n".join(lines) + "\r\n\r\n" + (self.response_body or "")
        if self.truncated:
            out += "\n\n[... response truncated by gatecrash ...]"
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "identity": self.identity, "method": self.method,
            "url": self.url, "status": self.status, "elapsed_ms": round(self.elapsed_ms, 1),
            "body_bytes": self.body_bytes, "error": self.error, "note": self.note,
            "request": self.raw_request(), "response": self.raw_response(),
        }


# --------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------

@dataclass
class Finding:
    check_id: str
    title: str
    severity: str                  # critical|high|medium|low|info
    confidence: str                # firm|probable|tentative
    endpoint: str                  # "GET /users/{id}"
    url: str
    description: str
    evidence_summary: str = ""
    remediation: str = ""
    owasp: Optional[str] = None    # e.g. "API1"
    cwe: Optional[str] = None      # e.g. "CWE-639"
    exchanges: List[Exchange] = field(default_factory=list)
    detail: Dict[str, Any] = field(default_factory=dict)

    @property
    def owasp_label(self) -> str:
        if not self.owasp:
            return ""
        return f"{self.owasp}:2023 {OWASP_API_2023.get(self.owasp, '')}".strip()

    @property
    def dedup_key(self) -> str:
        raw = f"{self.check_id}|{self.endpoint}|{self.evidence_summary[:120]}"
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def sort_key(self) -> tuple:
        conf = {"firm": 0, "probable": 1, "tentative": 2}.get(self.confidence, 3)
        return (SEVERITY_SCORE.get(self.severity, 99), conf, self.endpoint)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.dedup_key,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "endpoint": self.endpoint,
            "url": self.url,
            "owasp": self.owasp_label or None,
            "cwe": self.cwe,
            "description": self.description,
            "evidence_summary": self.evidence_summary,
            "remediation": self.remediation,
            "detail": self.detail,
            "evidence": [e.to_dict() for e in self.exchanges],
        }
