"""Authentication and authorisation checks - the high-value ones on an API test."""
from __future__ import annotations

import json
from typing import Dict, Iterable, List, Optional

from ..engine import body_similarity, is_denial, looks_authorised
from ..models import Endpoint, Finding
from .base import Check, register

# Paths that are meant to be reachable without credentials - excluded from the
# "authentication not enforced" check so a login route is not reported as a bypass.
PUBLIC_HINTS = ("login", "signin", "sign-in", "signup", "sign-up", "register",
                "logout", "token", "oauth", "authorize", "authorise", "callback",
                "forgot", "reset-password", "password/reset", "verify-email",
                "health", "healthz", "livez", "readyz", "ping", "status", "version",
                "public", "docs", "swagger", "openapi", "robots.txt", "favicon",
                ".well-known", "captcha", "csrf")

# Endpoints that serve the *caller's own* data. Every role is meant to reach these,
# so a lower-privilege identity succeeding is correct behaviour, not a BFLA finding.
SELF_SCOPED_HINTS = ("/me", "/myself", "/self", "/whoami", "/profile", "/account",
                     "/session", "/current", "/my/", "/mine", "/dashboard", "/home",
                     "/preferences", "/notifications/unread", "/token/refresh")

ADMIN_HINTS = ("admin", "administrator", "manage", "management", "internal", "console",
               "backoffice", "back-office", "superuser", "sudo", "root", "config",
               "settings/system", "audit", "impersonat", "debug", "metrics", "actuator",
               "role", "permission", "entitlement", "billing", "invoice", "payout")


def _shape(body: str) -> str:
    """Structural fingerprint of a JSON body: keys and types, not values."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return ""

    def walk(node, depth=0):
        if depth > 4:
            return "..."
        if isinstance(node, dict):
            return "{" + ",".join(f"{k}:{walk(v, depth + 1)}" for k, v in sorted(node.items())) + "}"
        if isinstance(node, list):
            return "[" + (walk(node[0], depth + 1) if node else "") + "]"
        return type(node).__name__

    return walk(data)


def _same_resource(a, b) -> tuple:
    """(is_same, why) for two exchanges that both returned data."""
    if not a or not b or a.status is None or b.status is None:
        return False, ""
    body_a, body_b = a.response_body or "", b.response_body or ""
    if body_a and body_a == body_b:
        return True, "byte-identical response bodies"
    ratio = body_similarity(body_a, body_b)
    if ratio >= 0.95:
        return True, f"response bodies {ratio:.0%} similar"
    shape_a, shape_b = _shape(body_a), _shape(body_b)
    if shape_a and shape_a == shape_b and len(shape_a) > 12 and ratio > 0.4:
        return True, f"identical JSON structure ({ratio:.0%} content similarity)"
    return False, f"bodies only {ratio:.0%} similar"


# --------------------------------------------------------------------------

@register
class BrokenAuthentication(Check):
    id = "auth.missing_enforcement"
    name = "Endpoint serves data without valid credentials"
    severity = "critical"
    owasp = "API2"
    cwe = "CWE-306"
    profiles = ("safe", "aggressive")

    def default_remediation(self) -> str:
        return ("Enforce authentication in middleware that runs before routing, defaulting to "
                "deny. Verify the token signature, issuer, audience and expiry on every "
                "request rather than checking only for the header's presence.")

    CRED_HEADERS = ("authorization", "x-api-key", "api-key", "x-auth-token",
                    "x-access-token", "cookie", "x-session-token")

    def _declares_auth(self, endpoint: Endpoint) -> bool:
        if endpoint.auth_hint:
            return True
        return any(k.lower() in self.CRED_HEADERS for k in endpoint.headers)

    def applies(self, endpoint: Endpoint) -> bool:
        path = endpoint.path.lower()
        if any(hint in path for hint in PUBLIC_HINTS):
            return False
        if self._declares_auth(endpoint):
            return True
        # Collections built from a URL list carry no auth metadata at all; in that
        # case fall back to testing everything that is not obviously public.
        return not any(self._declares_auth(e) for e in self.ctx.endpoints)

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        identity = self.ctx.primary
        if identity.is_anonymous:
            return []
        if not looks_authorised(baseline):
            return []
        if not (identity.headers or identity.cookies or identity.query):
            return []

        out: List[Finding] = []

        stripped = self.ctx.replay(endpoint, identity, strip_auth=True,
                                   note="credentials removed entirely")
        same, why = _same_resource(baseline, stripped)
        if looks_authorised(stripped) and same:
            out.append(self.finding(
                endpoint,
                "Authentication not enforced - endpoint served the same data with no credentials",
                f"`{endpoint.method} {endpoint.path}` returned HTTP {baseline.status} for the "
                f"authenticated identity `{identity.name}`, and returned HTTP {stripped.status} "
                f"with the credentials removed entirely ({why}). Any unauthenticated party who "
                f"can reach this host can read this data.",
                [baseline, stripped],
                confidence="firm",
                evidence_summary=f"authenticated HTTP {baseline.status} vs unauthenticated "
                                 f"HTTP {stripped.status}; {why}",
                detail={"comparison": why},
            ))
            return out

        # Credentials required - but is the token actually validated?
        token = identity.bearer_token()
        if token:
            forged = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhcGlzZWMtaW52YWxpZCJ9.aW52YWxpZA"
            tampered = self.ctx.replay(
                endpoint, identity,
                headers={"Authorization": f"Bearer {forged}"},
                note="Authorization replaced with a syntactically valid but unsigned token")
        else:
            tampered = self.ctx.replay(
                endpoint, identity,
                headers={k: "gatecrash-invalid-value" for k in identity.headers
                         if k.lower() in ("x-api-key", "api-key", "x-auth-token", "authorization")},
                note="credential header replaced with an invalid value")

        same, why = _same_resource(baseline, tampered)
        if looks_authorised(tampered) and same:
            out.append(self.finding(
                endpoint,
                "Credential is not validated - an invalid token was accepted",
                f"`{endpoint.method} {endpoint.path}` rejected the request when the credential "
                f"header was absent, but accepted an obviously invalid credential and returned "
                f"HTTP {tampered.status} ({why}). The service is checking that a credential is "
                f"present, not that it is genuine, so any attacker can forge one.",
                [baseline, tampered],
                confidence="firm",
                evidence_summary=f"invalid credential accepted: HTTP {tampered.status}; {why}",
            ))
        return out


@register
class BrokenObjectLevelAuth(Check):
    id = "authz.bola"
    name = "Broken Object Level Authorization (BOLA/IDOR)"
    severity = "critical"
    owasp = "API1"
    cwe = "CWE-639"
    profiles = ("safe", "aggressive")

    def default_remediation(self) -> str:
        return ("Authorise every object access against the identity in the token - never trust "
                "an identifier from the path, query or body. Use a central policy layer, and "
                "prefer unguessable identifiers as defence in depth (not as the control).")

    def _owner_of(self, object_id: str):
        """Which declared identity actually owns this object, if any."""
        for identity in self.ctx.identities:
            if object_id in identity.owns:
                return identity
        return None

    def applies(self, endpoint: Endpoint) -> bool:
        return bool(endpoint.id_segments()) and len(self.ctx.identities) > 1

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not looks_authorised(baseline):
            return []
        segments = endpoint.id_segments()
        if not segments:
            return []
        out: List[Finding] = []

        # The identity that legitimately owns the object in the URL is not necessarily
        # the one we baselined as. Attributing the object to the baseline caller
        # produces nonsense like "userA can read an object belonging to admin" when
        # the object is in fact userA's own.
        _idx, object_in_url = segments[-1]
        declared_owner = self._owner_of(object_in_url)
        owner = declared_owner or self.ctx.primary

        # Compare against the *owner's* view of the object, not the baseline
        # caller's, or the evidence will not say what the finding claims.
        if declared_owner and declared_owner.name != self.ctx.primary.name:
            baseline = self.ctx.replay(
                endpoint, declared_owner,
                note=f"object `{object_in_url}` fetched as its declared owner "
                     f"'{declared_owner.name}' to establish the legitimate response")
            if not looks_authorised(baseline):
                return []

        for other in self.ctx.identities:
            if other.name == owner.name or other.is_anonymous:
                continue
            # The object is this identity's own property - reaching it is correct.
            if object_in_url in other.owns:
                continue
            # A more privileged caller reading a subordinate's object is the
            # designed behaviour of an admin role, not a broken object check.
            if other.rank > owner.rank:
                continue

            # 1. Same object, different caller's credentials.
            replay = self.ctx.replay(
                endpoint, other,
                note=f"object owned by '{owner.name}' requested with '{other.name}' credentials")
            same, why = _same_resource(baseline, replay)
            if looks_authorised(replay) and same:
                index, value = segments[-1]
                owned = value in owner.owns
                out.append(self.finding(
                    endpoint,
                    f"BOLA: '{other.name}' can read an object belonging to '{owner.name}'",
                    f"`{endpoint.method} {endpoint.path}` addresses object `{value}`. Requested "
                    f"with `{owner.name}`'s credentials it returned HTTP {baseline.status}; "
                    f"requested with a different user's credentials (`{other.name}`) it returned "
                    f"HTTP {replay.status} with {why}. The service resolves the object from the "
                    f"URL without checking that the caller is entitled to it."
                    + ("" if owned else "\n\nConfirm object ownership manually - the identity "
                                        "config did not declare which objects belong to whom."),
                    [baseline, replay],
                    confidence="firm" if owned else "probable",
                    evidence_summary=f"object `{value}`: owner HTTP {baseline.status}, "
                                     f"other user HTTP {replay.status}; {why}",
                    detail={"object_id": value, "owner": owner.name,
                            "attacker": other.name, "declared_ownership": owned},
                ))
                continue

            # 2. Swap in an object the *other* identity owns, using the owner's credentials.
            if other.owns:
                index, _ = segments[-1]
                victim_id = str(other.owns[0])
                url = endpoint.with_path_segment(index, victim_id)
                probe = self.ctx.replay(
                    endpoint.clone(url=url), owner,
                    note=f"object {victim_id} owned by '{other.name}' requested as '{owner.name}'")
                if looks_authorised(probe) and probe.status == baseline.status:
                    ratio = body_similarity(baseline.response_body or "",
                                            probe.response_body or "")
                    shape_match = _shape(baseline.response_body or "") == \
                        _shape(probe.response_body or "")
                    if shape_match and ratio < 0.999:
                        out.append(self.finding(
                            endpoint,
                            f"BOLA: '{owner.name}' can read object `{victim_id}` owned by "
                            f"'{other.name}'",
                            f"Substituting `{other.name}`'s declared object id `{victim_id}` into "
                            f"`{endpoint.path_template or endpoint.path}` and calling it as "
                            f"`{owner.name}` returned HTTP {probe.status} with a populated "
                            f"resource of the same shape as the caller's own object. The "
                            f"identifier alone grants access.",
                            [baseline, probe],
                            confidence="firm",
                            url=url,
                            evidence_summary=f"cross-tenant object `{victim_id}` returned "
                                             f"HTTP {probe.status} ({len(probe.response_body)} bytes)",
                            detail={"object_id": victim_id, "owner": other.name,
                                    "attacker": owner.name},
                        ))
        return out


@register
class ObjectIdEnumeration(Check):
    id = "authz.id_enumeration"
    name = "Sequential object identifiers are enumerable"
    severity = "medium"
    owasp = "API1"
    cwe = "CWE-639"
    profiles = ("aggressive",)
    max_endpoints = 15

    def default_remediation(self) -> str:
        return ("Authorise per object, and return an indistinguishable 404 for objects the "
                "caller may not see so existence itself is not leaked.")

    def applies(self, endpoint: Endpoint) -> bool:
        return endpoint.method in ("GET", "HEAD") and any(
            seg.isdigit() for _, seg in endpoint.id_segments())

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not looks_authorised(baseline) or not self.budget_ok():
            return []
        # An administrator reading many objects is the point of an administrator.
        if self.ctx.primary.rank >= 2:
            return []
        numeric = [(i, s) for i, s in endpoint.id_segments() if s.isdigit()]
        if not numeric:
            return []
        self.spend()
        index, value = numeric[-1]
        base_id = int(value)
        hits, probes = [], []
        for candidate in (base_id + 1, base_id + 2, max(base_id - 1, 0), base_id + 1000):
            if candidate == base_id:
                continue
            url = endpoint.with_path_segment(index, str(candidate))
            ex = self.ctx.replay(endpoint.clone(url=url), self.ctx.primary,
                                 note=f"sequential id probe: {value} -> {candidate}")
            probes.append(ex)
            if looks_authorised(ex) and _shape(ex.response_body or "") == \
                    _shape(baseline.response_body or "") and ex.response_body:
                hits.append((candidate, ex))

        if len(hits) >= 2:
            return [self.finding(
                endpoint,
                "Sequential identifiers return other objects to the same caller",
                f"`{endpoint.path_template or endpoint.path}` uses a sequential numeric "
                f"identifier. Walking it from `{value}` returned populated, same-shaped "
                f"resources for {', '.join(str(c) for c, _ in hits)}. If those objects are not "
                f"all owned by `{self.ctx.primary.name}`, this is a directly exploitable BOLA; "
                f"either way the identifier space is trivially enumerable.",
                [baseline] + [ex for _, ex in hits[:2]],
                confidence="tentative",
                evidence_summary=f"ids {', '.join(str(c) for c, _ in hits)} each returned "
                                 f"HTTP 200 with the same JSON shape as id {value}",
                detail={"base_id": base_id, "hit_ids": [c for c, _ in hits]},
            )]
        return []


@register
class BrokenFunctionLevelAuth(Check):
    """API5 - can a lower-privilege caller invoke a higher-privilege function?

    Authorisation intent cannot be inferred from a URL. The reliable signal is a
    *privilege gradient*: if the tester declares an identity more privileged than
    another, every endpoint the privileged one can reach is a candidate, and any
    of them the lower one can also reach is a finding. Path keywords are used only
    to raise severity - never to decide what gets tested.

    Without a privilege gradient the check degrades to keyword mode and says so,
    because silently testing nothing would make a clean report meaningless.
    """

    id = "authz.bfla"
    name = "Broken Function Level Authorization"
    severity = "high"
    owasp = "API5"
    cwe = "CWE-285"
    profiles = ("safe", "aggressive")

    def default_remediation(self) -> str:
        return ("Deny by default and grant per route based on the caller's role, checked "
                "server-side in middleware. Administrative routes should live behind an "
                "explicit authorisation policy, not merely an unlinked or unguessable path.")

    # -- targeting --------------------------------------------------------

    def _lower_identities(self) -> List:
        """Identities strictly less privileged than the caller we baseline as."""
        return [i for i in self.ctx.identities
                if i.rank < self.ctx.primary.rank and i.name != self.ctx.primary.name]

    def _gradient_available(self) -> bool:
        return bool(self._lower_identities())

    #: Aggregated per identity rather than per endpoint. An API with no role checks
    #: anywhere is one systemic defect, not forty findings - and a report that says
    #: it forty times buries everything else.
    per_endpoint = False

    def _targets(self, endpoint: Endpoint) -> bool:
        if len(self.ctx.identities) < 2:
            return False
        # BOLA already replays cross-identity for object-addressed routes; testing
        # them here too would double the traffic and double-report the same bug.
        if endpoint.id_segments():
            return False
        # "Show me my own profile" is supposed to work for every role.
        path = endpoint.path.lower().rstrip("/")
        if any(path.endswith(h.rstrip("/")) or h in path + "/"
               for h in SELF_SCOPED_HINTS):
            return False
        # Deliberately public routes (login, health, docs) are reachable by design.
        if any(hint in path for hint in PUBLIC_HINTS):
            return False
        if self._gradient_available():
            return True
        # No gradient declared: fall back to the keyword heuristic so the check still
        # does something, and warn about the coverage gap via authz.bfla_coverage.
        return any(hint in endpoint.path.lower() for hint in ADMIN_HINTS)

    def run_once(self) -> Iterable[Finding]:
        gradient = self._gradient_available()
        candidates = [i for i in (self._lower_identities() if gradient else self.ctx.identities)
                      if i.name != self.ctx.primary.name and not i.is_anonymous
                      and i.rank <= self.ctx.primary.rank]
        if not candidates:
            return []

        # identity name -> [(endpoint, baseline, replay, why, keyword_match)]
        breaches: Dict[str, List[tuple]] = {}

        for endpoint, baseline in self.ctx.baseline_pairs():
            if not self._targets(endpoint) or not looks_authorised(baseline):
                continue
            keyword_match = any(hint in endpoint.path.lower() for hint in ADMIN_HINTS)
            for other in candidates:
                replay = self.ctx.replay(
                    endpoint, other,
                    note=f"function reachable as '{self.ctx.primary.name}' "
                         f"(privilege {self.ctx.primary.rank}) - retried as '{other.name}' "
                         f"(privilege {other.rank})")
                if not looks_authorised(replay):
                    continue
                same, why = _same_resource(baseline, replay)
                if not same:
                    continue
                # Same JSON *shape* but different content usually means the endpoint
                # legitimately serves per-caller data to both roles. Only treat that
                # as a finding when the route is also named like a privileged one.
                identical = body_similarity(baseline.response_body or "",
                                            replay.response_body or "") >= 0.95
                if not identical and not keyword_match:
                    continue
                breaches.setdefault(other.name, []).append(
                    (endpoint, baseline, replay, why, keyword_match, identical))

        out: List[Finding] = []
        for name, rows in breaches.items():
            other = next(i for i in candidates if i.name == name)
            # A route named like an admin route is evidence of intent. One that is
            # not could equally be a function both roles are meant to call, and a
            # scanner cannot read the product's intent - so they are reported
            # separately, at the confidence each actually deserves.
            named = [r for r in rows if r[4]]
            unnamed = [r for r in rows if not r[4]]

            def listing(group):
                text = "\n".join(
                    f"- `{ep.method} {ep.path}`"
                    + ("  — identical response to both identities" if ident
                       else "  — same structure, per-caller values")
                    for ep, _b, _r, _w, _kw, ident in group[:20])
                if len(group) > 20:
                    text += f"\n- … and {len(group) - 20} more"
                return text

            gradient_note = (
                f"`{name}` is declared at privilege {other.rank}, below "
                f"`{self.ctx.primary.name}` at privilege {self.ctx.primary.rank}."
                if gradient else
                "No privilege gradient was declared, so these were selected because the path "
                "looks administrative - confirm the two identities really do have different "
                "entitlements before reporting.")

            if named:
                out.append(self.finding(
                    None,
                    f"BFLA: '{name}' can invoke {len(named)} administrative function(s) "
                    f"intended for '{self.ctx.primary.name}'",
                    f"{gradient_note} Each route below is named like a privileged function and "
                    f"returned substantially the same response to both identities, so it "
                    f"authenticates the caller but never checks what the caller is entitled "
                    f"to do.\n\n{listing(named)}\n\n"
                    "Evidence below shows the first three, each as the privileged baseline "
                    "followed by the same request made as the lower-privileged identity.",
                    [ex for row in named[:3] for ex in (row[1], row[2])],
                    severity="critical" if gradient else "high",
                    confidence="firm" if gradient else "probable",
                    url=named[0][0].url,
                    evidence_summary=f"{name} (privilege {other.rank}) reached {len(named)} "
                                     f"administrative endpoint(s) intended for "
                                     f"{self.ctx.primary.name} (privilege "
                                     f"{self.ctx.primary.rank})",
                    detail={"identity": name, "role": other.role,
                            "identity_privilege": other.rank,
                            "baseline_privilege": self.ctx.primary.rank,
                            "endpoints": [r[0].signature for r in named],
                            "mode": "privilege-gradient" if gradient else "keyword-heuristic"},
                ))

            if unnamed and gradient:
                out.append(self.finding(
                    None,
                    f"{len(unnamed)} function(s) reachable by both '{self.ctx.primary.name}' "
                    f"and lower-privileged '{name}' - confirm intent",
                    f"{gradient_note} The routes below were reachable by both identities and "
                    f"returned substantially the same response. Unlike the administrative "
                    f"routes reported separately, nothing in the path indicates whether these "
                    f"are *meant* to be role-restricted - many APIs correctly expose the same "
                    f"function to every role.\n\n{listing(unnamed)}\n\n"
                    f"**This is a list to check against the product's intended permissions "
                    f"model, not a proven vulnerability.** Any route here that should have "
                    f"been admin-only is a genuine API5 finding; the rest are correct "
                    f"behaviour and should be dismissed.",
                    [ex for row in unnamed[:3] for ex in (row[1], row[2])],
                    severity="medium",
                    confidence="tentative",
                    url=unnamed[0][0].url,
                    remediation="Confirm the intended permission for each route before "
                                "reporting. " + self.default_remediation(),
                    evidence_summary=f"{len(unnamed)} route(s) reachable by both "
                                     f"{self.ctx.primary.name} (privilege "
                                     f"{self.ctx.primary.rank}) and {name} "
                                     f"(privilege {other.rank})",
                    detail={"identity": name, "role": other.role,
                            "endpoints": [r[0].signature for r in unnamed],
                            "requires_intent_confirmation": True},
                ))
        return out


@register
class FunctionLevelAuthCoverage(Check):
    """Tells the tester when API5 coverage is degraded, instead of silently under-testing."""

    id = "authz.bfla_coverage"
    name = "Function level authorisation coverage notice"
    severity = "info"
    owasp = "API5"
    passive = True
    per_endpoint = False
    profiles = ("passive", "safe", "aggressive")

    def run_once(self) -> Iterable[Finding]:
        identities = self.ctx.identities
        ranks = sorted({i.rank for i in identities if not i.is_anonymous})
        if len(ranks) >= 2:
            return []
        named = ", ".join(f"`{i.name}` (privilege {i.rank})" for i in identities)
        return [self.finding(
            None,
            "API5 coverage is limited - no higher-privilege identity was supplied",
            "Broken Function Level Authorization is only testable by walking downward from a "
            "more privileged caller to a less privileged one. This scan ran with "
            f"{named}, which contains no privilege gradient, so the check fell back to "
            "flagging routes whose *path* looks administrative.\n\n"
            "Routes that are privileged but not named like it were not tested. To close the "
            "gap, add an admin identity to the identity file:\n\n"
            "```yaml\n"
            "  - name: admin\n"
            "    role: admin          # or: privilege: 3\n"
            "    headers:\n"
            "      Authorization: \"Bearer ${ADMIN_TOKEN}\"\n"
            "```\n\n"
            "and set `primary: admin` so the scan baselines as the privileged caller.",
            [],
            confidence="firm",
            evidence_summary="no identity ranked above another; BFLA ran in keyword-heuristic mode",
            remediation="Not a vulnerability - a note on this scan's coverage.",
            detail={"identities": {i.name: i.rank for i in identities}},
        )]


@register
class MassAssignment(Check):
    id = "authz.mass_assignment"
    name = "Mass assignment of privileged properties"
    severity = "high"
    owasp = "API3"
    cwe = "CWE-915"
    profiles = ("safe", "aggressive")
    max_endpoints = 25

    INJECTED = {
        "role": "admin", "isAdmin": True, "is_admin": True, "admin": True,
        "is_superuser": True, "verified": True, "isVerified": True,
        "email_verified": True, "status": "active", "balance": 999999,
        "credit": 999999, "permissions": ["admin"], "account_type": "premium",
        "is_active": True, "approved": True,
    }

    def default_remediation(self) -> str:
        return ("Bind request bodies to an explicit allow-list DTO per endpoint. Never pass a "
                "parsed body straight into an ORM model or `Object.assign` on an entity.")

    def applies(self, endpoint: Endpoint) -> bool:
        return endpoint.method in ("POST", "PUT", "PATCH") and \
            isinstance(endpoint.json_body, dict)

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not self.budget_ok():
            return []
        original = endpoint.json_body
        if not isinstance(original, dict):
            return []
        self.spend()

        payload = dict(original)
        injected = {k: v for k, v in self.INJECTED.items() if k not in original}
        if not injected:
            return []
        payload.update(injected)
        body = json.dumps(payload)

        probe = self.ctx.replay(
            endpoint.clone(body=body), self.ctx.primary,
            headers={"Content-Type": "application/json"},
            note="request body extended with privileged properties")

        if not looks_authorised(probe):
            return []

        try:
            response = json.loads(probe.response_body or "")
        except (ValueError, TypeError):
            return []

        reflected = _find_reflected(response, injected)
        if not reflected:
            return []

        pairs = ", ".join(f"`{k}` = {json.dumps(v)}" for k, v in reflected.items())
        return [self.finding(
            endpoint,
            f"Mass assignment accepted: {', '.join('`%s`' % k for k in reflected)}",
            f"`{endpoint.method} {endpoint.path}` accepted properties that were not part of the "
            f"documented request body and echoed them back on the persisted object: {pairs}. The "
            f"handler binds the whole request body to the underlying model, so a client can set "
            f"server-controlled fields such as role, verification state or balance.",
            [baseline, probe] if baseline else [probe],
            confidence="firm",
            evidence_summary=f"injected {pairs} - reflected in HTTP {probe.status} response",
            detail={"injected": injected, "reflected": reflected},
        )]


def _find_reflected(node, injected: dict, depth: int = 0) -> dict:
    """Return the injected key/value pairs that came back in the response."""
    found = {}
    if depth > 5:
        return found
    if isinstance(node, dict):
        for key, value in node.items():
            if key in injected and _loosely_equal(value, injected[key]):
                found[key] = value
            else:
                found.update(_find_reflected(value, injected, depth + 1))
    elif isinstance(node, list):
        for item in node[:20]:
            found.update(_find_reflected(item, injected, depth + 1))
    return found


def _loosely_equal(a, b) -> bool:
    if a == b:
        return True
    if isinstance(b, bool):
        return a in (b, str(b).lower(), int(b))
    return str(a).lower() == str(b).lower()
