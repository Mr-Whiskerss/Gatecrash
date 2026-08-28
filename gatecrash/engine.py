"""HTTP engine: scope enforcement, rate limiting, evidence capture."""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import requests
import urllib3

from .models import DESTRUCTIVE_METHODS, Exchange

log = logging.getLogger("gatecrash")


#: Headers that carry a caller's identity. When an identity profile supplies its own,
#: these must not be inherited from the collection - otherwise every cross-user check
#: would silently re-test the same user.
CREDENTIAL_HEADERS = frozenset({
    "authorization", "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token",
    "x-session-token", "x-csrf-token", "cookie", "x-amz-security-token",
})


class ScopeError(Exception):
    """Raised when a check tries to touch a host outside the agreed scope."""


class DestructiveBlocked(Exception):
    """Raised when a check tries a state-changing request without opt-in."""


# --------------------------------------------------------------------------

#: Comparable privilege levels. Function level authorisation can only be tested by
#: walking *downward* from a higher-privilege identity to a lower one, so roles need
#: an ordering rather than just a label. Override per identity with `privilege: N`.
ROLE_RANK = {
    "anonymous": 0, "guest": 0, "public": 0,
    "user": 1, "member": 1, "customer": 1, "basic": 1,
    "staff": 2, "manager": 2, "moderator": 2, "support": 2,
    "admin": 3, "administrator": 3, "owner": 3,
    "superadmin": 4, "superuser": 4, "root": 4,
}


@dataclass
class Identity:
    """A tester persona: credentials plus (optionally) objects it owns."""

    name: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    query: Dict[str, str] = field(default_factory=dict)
    owns: List[str] = field(default_factory=list)   # object IDs this identity legitimately owns
    role: str = "user"                              # user|admin|anonymous
    description: str = ""
    #: True when the credentials were lifted out of the collection rather than
    #: configured by the tester - they must not override per-endpoint headers.
    adopted: bool = False
    #: Explicit privilege level, overriding whatever `role` would imply.
    privilege: Optional[int] = None

    @property
    def is_anonymous(self) -> bool:
        return self.role == "anonymous" or (not self.headers and not self.cookies and not self.query)

    @property
    def rank(self) -> int:
        """Comparable privilege level; higher means more privileged."""
        if self.privilege is not None:
            return int(self.privilege)
        if self.is_anonymous:
            return 0
        return ROLE_RANK.get(self.role.lower(), 1)

    def bearer_token(self) -> Optional[str]:
        for k, v in self.headers.items():
            if k.lower() == "authorization" and v.lower().startswith("bearer "):
                return v[7:].strip()
        return None


ANONYMOUS = Identity(name="anonymous", role="anonymous",
                     description="No credentials supplied at all.")


# --------------------------------------------------------------------------

class RateLimiter:
    """Simple token-bucket-ish limiter: at most `rps` requests per second."""

    def __init__(self, rps: float):
        self.min_interval = 1.0 / rps if rps and rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._next = max(now, self._next) + self.min_interval


# --------------------------------------------------------------------------

@dataclass
class EngineConfig:
    scope_hosts: List[str] = field(default_factory=list)
    timeout: float = 15.0
    rps: float = 8.0
    max_body: int = 200_000
    verify_tls: bool = True
    proxy: Optional[str] = None
    user_agent: str = "gatecrash/1.0 (authorised security testing)"
    allow_destructive: bool = False
    extra_headers: Dict[str, str] = field(default_factory=dict)
    max_requests: int = 20_000


class Engine:
    """Wraps requests with scope guards, throttling and full evidence capture."""

    def __init__(self, config: EngineConfig):
        self.config = config
        self.limiter = RateLimiter(config.rps)
        self.exchanges: List[Exchange] = []
        self._lock = threading.Lock()
        self._count = 0
        self._local = threading.local()
        if not config.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # -- scope ------------------------------------------------------------

    def in_scope(self, url: str) -> bool:
        host = urlsplit(url).netloc.lower()
        host_only = host.split("@")[-1].split(":")[0]
        for allowed in self.config.scope_hosts:
            a = allowed.lower().strip()
            if a.startswith("*."):
                if host_only == a[2:] or host_only.endswith("." + a[2:]):
                    return True
            elif host_only == a or host == a:
                return True
        return False

    # -- session ----------------------------------------------------------

    def _session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            s.trust_env = False
            if self.config.proxy:
                s.proxies = {"http": self.config.proxy, "https": self.config.proxy}
            self._local.session = s
        return s

    @property
    def request_count(self) -> int:
        return self._count

    # -- the one place a request is made ----------------------------------

    def send(
        self,
        method: str,
        url: str,
        identity: Identity,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,
        note: str = "",
        allow_redirects: bool = False,
        strip_auth: bool = False,
    ) -> Exchange:
        method = method.upper()

        if not self.in_scope(url):
            raise ScopeError(f"{url} is outside the declared scope {self.config.scope_hosts}")
        if method in DESTRUCTIVE_METHODS and not self.config.allow_destructive:
            raise DestructiveBlocked(f"{method} blocked (re-run with --allow-destructive)")
        with self._lock:
            if self._count >= self.config.max_requests:
                raise ScopeError("request budget exhausted (--max-requests)")
            self._count += 1

        final_headers: Dict[str, str] = {"User-Agent": self.config.user_agent,
                                         "Accept": "*/*"}
        final_headers.update(self.config.extra_headers)
        if not strip_auth:
            final_headers.update(identity.headers)
        final_headers.update(headers or {})
        if strip_auth:
            for k in [k for k in final_headers if k.lower() in
                      ("authorization", "x-api-key", "api-key", "x-auth-token", "cookie")]:
                final_headers.pop(k)

        merged_params = dict(identity.query)
        merged_params.update(params or {})

        cookies = {} if strip_auth else dict(identity.cookies)

        ex = Exchange(
            id=Exchange.new_id(), identity=identity.name, method=method, url=url,
            request_headers=final_headers, request_body=body, note=note,
        )
        if merged_params:
            joined = "&".join(f"{k}={v}" for k, v in merged_params.items())
            ex.url = url + ("&" if "?" in url else "?") + joined
        if cookies:
            ex.request_headers = dict(final_headers)
            ex.request_headers.setdefault(
                "Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))

        self.limiter.acquire()
        started = time.monotonic()
        try:
            resp = self._session().request(
                method, url, headers=final_headers, data=body.encode() if body else None,
                params=merged_params or None, cookies=cookies or None,
                timeout=self.config.timeout, allow_redirects=allow_redirects,
                verify=self.config.verify_tls,
            )
            ex.elapsed_ms = (time.monotonic() - started) * 1000
            ex.status = resp.status_code
            ex.reason = resp.reason or ""
            ex.response_headers = dict(resp.headers)
            raw = resp.content or b""
            ex.body_bytes = len(raw)
            if len(raw) > self.config.max_body:
                raw = raw[: self.config.max_body]
                ex.truncated = True
            ex.response_body = raw.decode(resp.encoding or "utf-8", errors="replace")
            ex.url = resp.url
        except requests.RequestException as exc:
            ex.elapsed_ms = (time.monotonic() - started) * 1000
            ex.error = f"{type(exc).__name__}: {exc}"
            log.debug("request failed %s %s: %s", method, url, exc)

        with self._lock:
            self.exchanges.append(ex)
        return ex


# --------------------------------------------------------------------------
# Response comparison helpers used by the authz checks
# --------------------------------------------------------------------------

def body_similarity(a: str, b: str, cap: int = 4000) -> float:
    """0..1 similarity of two response bodies."""
    if a is None or b is None:
        return 0.0
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a[:cap], b[:cap]).ratio()


def looks_authorised(ex: Exchange) -> bool:
    """A response that plausibly served real data rather than a denial."""
    if ex.error or ex.status is None:
        return False
    if ex.status in (401, 403, 404, 405, 407, 429):
        return False
    if ex.status >= 500:
        return False
    if ex.status >= 400:
        return False
    body = (ex.response_body or "").lower()
    denial_markers = ("unauthori", "forbidden", "access denied", "not permitted",
                      "invalid token", "permission denied", "must be logged in")
    if len(body) < 400 and any(m in body for m in denial_markers):
        return False
    return True


def is_denial(ex: Exchange) -> bool:
    return ex.status in (401, 403) if ex.status else False
