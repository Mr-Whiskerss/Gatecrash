"""API6 and API10.

Neither category is provable by a scanner, and pretending otherwise produces
confident nonsense. Both checks here do what a tool honestly can: identify the
attack surface precisely, record which controls were and were not observed, and
hand the tester a specific manual checklist. They are deliberately reported at
low severity with tentative confidence.
"""
from __future__ import annotations

import json
import re
from typing import Dict, Iterable, List, Tuple
from urllib.parse import parse_qsl, urlsplit

from ..engine import looks_authorised
from ..models import Endpoint, Finding
from .base import Check, register
from .ssrf import URL_PARAM_HINTS, _candidate_params

# Business flows that are worth money or reputation when automated at scale.
FLOW_HINTS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("purchase or payment", ("checkout", "purchase", "buy", "order", "cart", "payment",
                             "pay", "charge", "billing", "subscribe", "subscription")),
    ("booking or reservation", ("book", "booking", "reserve", "reservation", "seat",
                                "slot", "appointment", "schedule", "ticket")),
    ("promotion or credit", ("coupon", "promo", "voucher", "discount", "redeem", "claim",
                             "reward", "points", "referral", "credit", "gift")),
    ("account creation", ("register", "signup", "sign-up", "account/create", "onboard")),
    ("invitation or messaging", ("invite", "invitation", "message", "notify", "email",
                                 "sms", "share", "send")),
    ("transfer or withdrawal", ("transfer", "withdraw", "payout", "remit", "send-money")),
    ("voting or rating", ("vote", "rating", "rate", "review", "like", "poll", "survey")),
    ("application or submission", ("apply", "application", "submit", "bid", "offer",
                                   "enroll", "enrol", "waitlist")),
)

# Header and field names that indicate an anti-automation control exists.
RATE_LIMIT_HEADERS = ("x-ratelimit-limit", "x-ratelimit-remaining", "ratelimit-limit",
                      "ratelimit-remaining", "retry-after", "x-rate-limit-limit")
IDEMPOTENCY_HEADERS = ("idempotency-key", "x-idempotency-key", "x-request-id",
                       "x-correlation-id")
HUMAN_CHECK_FIELDS = re.compile(
    r"(captcha|recaptcha|hcaptcha|turnstile|challenge|otp|mfa|2fa|totp|confirmation_code"
    r"|verification_code|nonce|csrf)", re.I)

EXTERNAL_URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+\.[A-Za-z]{2,})(?::\d+)?(?:/[^\s\"'<>]*)?")

# Hosts that appear in almost every response and say nothing about integrations.
BORING_HOSTS = re.compile(
    r"(schema\.org|w3\.org|example\.(com|org|net)|localhost|json-schema\.org"
    r"|swagger\.io|opensource\.org|apache\.org|github\.io|jsonapi\.org)$", re.I)


def _endpoint_exists(ex) -> bool:
    """Is this route actually implemented here?

    Deliberately weaker than `looks_authorised`: a 500 from a checkout handler or a
    502 from a failed outbound fetch still proves the route exists and has the
    surface we are inventorying. Only "not here" answers are excluded.
    """
    if ex is None or ex.error or ex.status is None:
        return False
    return ex.status not in (404, 405, 501, 502) or bool(ex.response_body)


def _flow_kind(endpoint: Endpoint) -> str:
    path = endpoint.path.lower()
    for label, hints in FLOW_HINTS:
        if any(h in path for h in hints):
            return label
    return ""


@register
class SensitiveBusinessFlows(Check):
    id = "bizflow.sensitive_flows"
    name = "Sensitive business flow without observable anti-automation"
    severity = "low"
    owasp = "API6"
    cwe = "CWE-799"
    passive = True
    per_endpoint = False
    profiles = ("passive", "safe", "aggressive")

    def default_remediation(self) -> str:
        return ("Decide per flow what abuse at scale would cost, then apply proportionate "
                "controls: device fingerprinting, human verification on first use, per-account "
                "and per-payment-instrument velocity limits, idempotency keys on anything that "
                "moves money, and monitoring that alerts on unusual flow-completion rates. "
                "Rate limiting by IP alone is not sufficient.")

    def run_once(self) -> Iterable[Finding]:
        flows: List[Tuple[Endpoint, object, str, Dict[str, bool]]] = []
        for endpoint, ex in self.ctx.baseline_pairs():
            kind = _flow_kind(endpoint)
            if not kind:
                continue
            if endpoint.method in ("GET", "HEAD", "OPTIONS") and "vote" not in endpoint.path.lower():
                continue                     # reads are not the abusable half of a flow
            if not _endpoint_exists(ex):
                continue                     # 404/405 - the flow does not exist here
            headers = {k.lower(): v for k, v in (ex.response_headers or {}).items()}
            request_blob = json.dumps(endpoint.headers) + (endpoint.body or "") + endpoint.url
            controls = {
                "rate limit headers": any(h in headers for h in RATE_LIMIT_HEADERS),
                "idempotency key": any(h in {k.lower() for k in endpoint.headers}
                                       for h in IDEMPOTENCY_HEADERS),
                "human verification field": bool(HUMAN_CHECK_FIELDS.search(request_blob)),
            }
            flows.append((endpoint, ex, kind, controls))

        if not flows:
            return []

        lines = []
        for endpoint, _ex, kind, controls in flows:
            present = [name for name, ok in controls.items() if ok]
            missing = [name for name, ok in controls.items() if not ok]
            lines.append(
                f"- `{endpoint.method} {endpoint.path}` — {kind}\n"
                f"    observed: {', '.join(present) if present else 'no anti-automation signals'}"
                f"{'; not observed: ' + ', '.join(missing) if missing else ''}")

        unprotected = [f for f in flows if not any(f[3].values())]
        severity = "medium" if unprotected else "low"

        return [self.finding(
            None,
            f"{len(flows)} sensitive business flow(s) identified for manual abuse testing",
            "Unrestricted Access to Sensitive Business Flows cannot be proven by a scanner: "
            "whether automating a flow causes harm depends on what the business loses when it "
            "happens ten thousand times, which is not visible from the wire. This check "
            "therefore identifies the flows and records which anti-automation controls were "
            "observable in the traffic — it does not attempt to abuse them, and the absence of "
            "a control here is an observation, not a proven vulnerability.\n\n"
            + "\n".join(lines) +
            "\n\n**Manual tests to run against each flow above:**\n"
            "1. Complete the flow once by hand and capture the full request sequence, including "
            "any steps the collection omits.\n"
            "2. Replay it with a fresh identity and no browser: does it complete without human "
            "interaction?\n"
            "3. Run it concurrently against the same object — do stock counts, seat allocations "
            "or balances go negative (a race the sequential checks in this tool cannot find)?\n"
            "4. Automate it at a realistic attacker rate and establish the per-attempt cost to "
            "the attacker versus the loss to the business.\n"
            "5. Check whether limits are enforced per account, per payment instrument and per "
            "device, or only per IP address.",
            [f[1] for f in flows[:3]],
            severity=severity,
            confidence="tentative",
            evidence_summary=f"{len(flows)} flow(s) identified; {len(unprotected)} with no "
                             f"observable anti-automation control",
            detail={"flows": [{"endpoint": e.signature, "kind": k, "controls": c}
                              for e, _x, k, c in flows]},
        )]


@register
class ThirdPartyConsumption(Check):
    id = "consumption.third_party"
    name = "Third-party integration surface"
    severity = "info"
    owasp = "API10"
    cwe = "CWE-1104"
    passive = True
    per_endpoint = False
    profiles = ("passive", "safe", "aggressive")

    def default_remediation(self) -> str:
        return ("Treat every third-party response as untrusted input: validate it against a "
                "schema before use, enforce TLS certificate verification, do not follow "
                "redirects blindly, apply timeouts and size caps, and allow-list the hosts the "
                "service is permitted to call.")

    def run_once(self) -> Iterable[Finding]:
        target_hosts = {e.host.split(":")[0] for e, _ in self.ctx.baseline_pairs()}
        external: Dict[str, List[str]] = {}
        url_params: List[str] = []
        redirects: List[Tuple[str, str]] = []
        samples = []

        for endpoint, ex in self.ctx.baseline_pairs():
            if not _endpoint_exists(ex):
                continue                     # an endpoint that 404s has no surface
            if _candidate_params(endpoint):
                names = ", ".join(n for _l, n, _v in _candidate_params(endpoint))
                url_params.append(f"`{endpoint.method} {endpoint.path}` ({names})")

            location = (ex.response_headers.get("Location")
                        or ex.response_headers.get("location") or "")
            if location.startswith("http"):
                host = urlsplit(location).netloc.split(":")[0]
                if host and host not in target_hosts:
                    redirects.append((endpoint.signature, location))

            for match in EXTERNAL_URL_RE.finditer((ex.response_body or "")[:20000]):
                host = match.group(1).lower()
                if host in target_hosts or BORING_HOSTS.search(host):
                    continue
                if any(host.endswith("." + t) or t.endswith("." + host) for t in target_hosts):
                    continue
                external.setdefault(host, []).append(endpoint.signature)
                if len(samples) < 3 and ex not in samples:
                    samples.append(ex)

        if not external and not url_params and not redirects:
            return []

        sections = []
        if external:
            top = sorted(external.items(), key=lambda kv: -len(kv[1]))[:12]
            sections.append(
                "**External hosts referenced in responses** — each is a dependency whose data "
                "the API or its clients consume:\n"
                + "\n".join(f"- `{host}` (in {len(set(eps))} endpoint response(s))"
                            for host, eps in top))
        if url_params:
            sections.append(
                "**Parameters that appear to carry a URL the server fetches** — these are the "
                "concrete points where third-party data enters:\n"
                + "\n".join(f"- {p}" for p in url_params[:12]))
        if redirects:
            sections.append(
                "**Redirects to external hosts:**\n"
                + "\n".join(f"- `{sig}` → `{loc}`" for sig, loc in redirects[:8]))

        return [self.finding(
            None,
            f"Third-party consumption surface: {len(external)} external host(s), "
            f"{len(url_params)} URL-bearing parameter(s)",
            "Unsafe Consumption of APIs is about how this service handles data it receives "
            "*from* other services, which is not observable from the client side — a scanner "
            "cannot see whether the upstream response is schema-validated, whether TLS is "
            "verified, or whether redirects are followed. This is an inventory of the "
            "integration surface so the review can be directed at it.\n\n"
            + "\n\n".join(sections) +
            "\n\n**What to check for each integration:**\n"
            "1. Is the third-party response validated against a schema, or trusted and passed "
            "through to the database or the client?\n"
            "2. Is TLS certificate verification enabled on the outbound call?\n"
            "3. Are redirects from the third party followed, and is the destination re-checked "
            "against the allow-list after each hop?\n"
            "4. Are timeouts and response size caps set, so a slow or huge upstream response "
            "cannot exhaust this service?\n"
            "5. If the integration is compromised or its domain lapses, what does it get to "
            "write into this system?\n\n"
            "See also any `ssrf.injection` findings in this report — they share the same "
            "injection points.",
            samples,
            confidence="tentative",
            evidence_summary=f"{len(external)} external host(s), {len(url_params)} "
                             f"URL-bearing parameter(s), {len(redirects)} external redirect(s)",
            detail={"external_hosts": {h: sorted(set(e)) for h, e in external.items()},
                    "url_parameters": url_params, "external_redirects": redirects},
        )]
