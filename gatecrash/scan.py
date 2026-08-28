"""Scan orchestration: baseline pass, check execution, finding aggregation."""
from __future__ import annotations

import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import checks as check_registry
from .engine import (ANONYMOUS, CREDENTIAL_HEADERS, DestructiveBlocked, Engine,
                     EngineConfig, Identity, ScopeError)
from .models import Endpoint, Exchange, Finding

log = logging.getLogger("gatecrash")


# --------------------------------------------------------------------------
# Identity configuration
# --------------------------------------------------------------------------

def load_identities(path: Optional[str], cli_header: Optional[List[str]] = None,
                    cli_token: Optional[str] = None) -> Tuple[List[Identity], List[str]]:
    """Return (identities, extra_scope_hosts)."""
    identities: List[Identity] = []
    scope: List[str] = []

    if path:
        try:
            import yaml
        except ImportError as exc:                       # pragma: no cover
            raise SystemExit("PyYAML is required for identity files: pip install pyyaml") from exc
        if not os.path.exists(path):
            raise SystemExit(f"identity file not found: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        scope = [str(h) for h in (data.get("scope") or [])]
        for entry in data.get("identities", []) or []:
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            name = str(entry["name"])
            headers = {str(k): _expand(str(v), f"'{name}' header {k}")
                       for k, v in (entry.get("headers") or {}).items()}
            identities.append(Identity(
                name=name,
                headers=headers,
                cookies={str(k): _expand(str(v), f"'{name}' cookie {k}")
                         for k, v in (entry.get("cookies") or {}).items()},
                query={str(k): _expand(str(v), f"'{name}' query {k}")
                       for k, v in (entry.get("query") or {}).items()},
                owns=[str(o) for o in (entry.get("owns") or [])],
                role=str(entry.get("role", "user")),
                description=str(entry.get("description", "")),
                privilege=(int(entry["privilege"]) if entry.get("privilege") is not None
                           else None),
            ))
        primary_name = data.get("primary")
        if primary_name:
            identities.sort(key=lambda i: i.name != primary_name)

    cli_headers: Dict[str, str] = {}
    for raw in cli_header or []:
        if ":" not in raw:
            raise SystemExit(f"--header expects 'Name: value', got {raw!r}")
        key, _, value = raw.partition(":")
        cli_headers[key.strip()] = value.strip()
    if cli_token:
        cli_headers["Authorization"] = cli_token if cli_token.lower().startswith(
            ("bearer ", "basic ", "token ")) else f"Bearer {cli_token}"
    if cli_headers:
        identities.insert(0, Identity(name="cli", headers=cli_headers,
                                      description="credentials supplied on the command line"))

    if not identities:
        identities = [Identity(name="collection",
                               description="whatever credentials the collection itself carries")]
    if not any(i.is_anonymous for i in identities):
        identities.append(ANONYMOUS)
    return identities, scope


def adopt_collection_credentials(identities: List[Identity],
                                 endpoints: List[Endpoint]) -> List[Identity]:
    """If the tester configured no credentials, borrow the collection's own.

    Without this, a scan driven purely by a Postman collection would have an
    identity with no token, so the JWT checks would have nothing to analyse and
    the credential-stripping comparison would have nothing to strip.
    """
    primary = next((i for i in identities if i.role != "anonymous"), None)
    if primary is None or primary.headers or primary.cookies or primary.query:
        return identities

    counts: Dict[Tuple[str, str], int] = {}
    for endpoint in endpoints:
        for key, value in endpoint.headers.items():
            if key.lower() in CREDENTIAL_HEADERS and value and "{{" not in value:
                counts[(key, value)] = counts.get((key, value), 0) + 1
    if not counts:
        return identities

    (key, value), _ = max(counts.items(), key=lambda kv: kv[1])
    primary.headers[key] = value
    primary.adopted = True
    primary.description = f"credentials adopted from the collection's own `{key}` header"
    log.info("No identity credentials supplied - adopted `%s` from the collection. "
             "Supply -i identities.yaml with two users to enable the authorisation checks.",
             key)
    return identities


_UNRESOLVED_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


def _expand(value: str, where: str = "") -> str:
    """Allow ${ENV_VAR} in identity files so tokens stay out of the repo.

    An unset variable is fatal rather than silently passed through. Sending the
    literal string `${ADMIN_TOKEN}` as a bearer token produces 401s that look
    exactly like correctly enforced authorisation, so the scan would report a
    misconfigured run as a clean bill of health.
    """
    expanded = os.path.expandvars(value)
    leftover = _UNRESOLVED_VAR.search(expanded)
    if leftover and "$" in expanded:
        raise SystemExit(
            f"identity{' ' + where if where else ''}: environment variable "
            f"${{{leftover.group(1)}}} is not set, so the credential would be sent "
            f"literally as {expanded!r}.\n"
            f"Every request from this identity would fail authentication, and the "
            f"resulting 401s are indistinguishable from correctly enforced access "
            f"control - the scan would look clean when nothing was actually tested.\n"
            f"Export it first:  export {leftover.group(1)}='<token>'")
    return expanded


# --------------------------------------------------------------------------

@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    exchanges: List[Exchange] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class ScanContext:
    """Everything a check needs, plus the request helper it must go through."""

    def __init__(self, engine: Engine, endpoints: List[Endpoint],
                 identities: List[Identity], config: Dict[str, Any]):
        self.engine = engine
        self.endpoints = endpoints
        self.identities = identities
        self.config = config
        self.baselines: Dict[int, Optional[Exchange]] = {}
        self.errors: List[str] = []
        self._lock = threading.Lock()

    # -- identity ---------------------------------------------------------

    @property
    def primary(self) -> Identity:
        for identity in self.identities:
            if not identity.is_anonymous:
                return identity
        return self.identities[0]

    def exchange_for_identity(self, identity: Identity) -> Optional[Exchange]:
        for ex in self.engine.exchanges:
            if ex.identity == identity.name and ex.status is not None:
                return ex
        return None

    # -- baselines --------------------------------------------------------

    def baseline_pairs(self) -> List[Tuple[Endpoint, Optional[Exchange]]]:
        return [(self.endpoints[i], ex) for i, ex in sorted(self.baselines.items())
                if ex is not None]

    # -- the single request helper checks use -----------------------------

    def replay(self, endpoint: Endpoint, identity: Identity, *,
               headers: Optional[Dict[str, str]] = None,
               params: Optional[Dict[str, str]] = None,
               body: Optional[str] = None,
               strip_auth: bool = False,
               note: str = "") -> Exchange:
        merged = dict(endpoint.headers)
        # An identity's credentials must win over whatever the collection baked in,
        # or a cross-user replay would keep re-sending the collection's own token.
        if not identity.adopted and (identity.headers or identity.cookies or identity.query):
            explicit = {k.lower() for k in (headers or {})}
            for key in [k for k in merged
                        if k.lower() in CREDENTIAL_HEADERS and k.lower() not in explicit]:
                merged.pop(key)
        merged.update(headers or {})
        try:
            return self.engine.send(
                endpoint.method, endpoint.url, identity,
                headers=merged, body=body if body is not None else endpoint.body,
                params=params, note=note, strip_auth=strip_auth,
            )
        except (ScopeError, DestructiveBlocked) as exc:
            with self._lock:
                self.errors.append(f"{endpoint.method} {endpoint.url}: {exc}")
            return Exchange(id=Exchange.new_id(), identity=identity.name,
                            method=endpoint.method, url=endpoint.url,
                            request_headers=merged, request_body=endpoint.body,
                            error=str(exc), note=note)


# --------------------------------------------------------------------------

def run_scan(endpoints: List[Endpoint], identities: List[Identity],
             engine_config: EngineConfig, *, profile: str = "safe",
             only: Optional[List[str]] = None, skip: Optional[List[str]] = None,
             workers: int = 6, config: Optional[Dict[str, Any]] = None,
             progress=None) -> ScanResult:
    engine = Engine(engine_config)
    ctx = ScanContext(engine, endpoints, identities, config or {})

    in_scope = [ep for ep in endpoints if engine.in_scope(ep.url)]
    dropped = len(endpoints) - len(in_scope)
    if dropped:
        log.warning("%d endpoint(s) dropped as out of scope (%s)",
                    dropped, ", ".join(engine_config.scope_hosts))
    ctx.endpoints = in_scope

    safe_only = (config or {}).get("safe_methods_only")
    if safe_only:
        ctx.endpoints = [ep for ep in ctx.endpoints if ep.method in ("GET", "HEAD", "OPTIONS")]

    if not ctx.endpoints:
        raise SystemExit(
            f"every endpoint was filtered out before testing: {dropped} were outside the "
            f"scope {engine_config.scope_hosts}"
            + (" and --safe-methods-only removed the rest" if safe_only else "")
            + ". Nothing was sent. Check --scope / --target.")

    # ---- 1. baseline pass -------------------------------------------------
    def baseline(index: int) -> None:
        endpoint = ctx.endpoints[index]
        ex = ctx.replay(endpoint, ctx.primary, note="baseline request from collection")
        ctx.baselines[index] = ex
        if progress:
            progress("baseline", endpoint, ex)

    log.info("Baselining %d endpoint(s) as identity '%s'", len(ctx.endpoints), ctx.primary.name)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(baseline, range(len(ctx.endpoints))))

    # ---- 2. checks --------------------------------------------------------
    classes = check_registry.select(profile, only=only, skip=skip)
    instances = [cls(ctx) for cls in classes]
    log.info("Running %d check(s) at profile '%s'", len(instances), profile)

    findings: List[Finding] = []
    findings_lock = threading.Lock()

    def run_endpoint_check(args) -> None:
        check, index = args
        endpoint = ctx.endpoints[index]
        base = ctx.baselines.get(index)
        try:
            if not check.applies(endpoint):
                return
            produced = list(check.run(endpoint, base) or [])
        except Exception as exc:                                   # noqa: BLE001
            log.debug("check %s failed on %s: %s", check.id, endpoint.url, exc, exc_info=True)
            with findings_lock:
                ctx.errors.append(f"{check.id} on {endpoint.method} {endpoint.path}: {exc}")
            return
        if produced:
            with findings_lock:
                findings.extend(produced)
        if progress:
            progress("check", endpoint, check)

    tasks = [(check, i) for check in instances if check.per_endpoint
             for i in range(len(ctx.endpoints))]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(run_endpoint_check, tasks))

    for check in instances:
        if check.per_endpoint:
            continue
        try:
            findings.extend(list(check.run_once() or []))
        except Exception as exc:                                   # noqa: BLE001
            log.debug("check %s failed: %s", check.id, exc, exc_info=True)
            ctx.errors.append(f"{check.id}: {exc}")
        if progress:
            progress("check", None, check)

    # ---- 3. aggregate -----------------------------------------------------
    unique: Dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.dedup_key, finding)
    ordered = sorted(unique.values(), key=lambda f: f.sort_key)

    counts: Dict[str, int] = {}
    for finding in ordered:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    return ScanResult(
        findings=ordered,
        endpoints=ctx.endpoints,
        exchanges=engine.exchanges,
        errors=ctx.errors,
        stats={
            "endpoints_tested": len(ctx.endpoints),
            "endpoints_dropped_out_of_scope": dropped,
            "requests_sent": engine.request_count,
            "checks_run": len(instances),
            "profile": profile,
            "identities": [i.name for i in identities],
            "primary_identity": ctx.primary.name,
            "severity_counts": counts,
            "scope": engine_config.scope_hosts,
        },
    )
