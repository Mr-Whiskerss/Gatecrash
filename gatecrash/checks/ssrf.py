"""API7 - Server Side Request Forgery, and the open-redirect family next to it."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from ..engine import looks_authorised
from ..models import Endpoint, Finding
from .base import Check, register

# Parameter names that usually carry a URL the server will fetch.
URL_PARAM_HINTS = (
    "url", "uri", "link", "src", "source", "target", "dest", "destination",
    "callback", "webhook", "hook", "endpoint", "host", "domain", "site",
    "feed", "rss", "image", "img", "avatar", "photo", "logo", "thumbnail",
    "document", "doc", "file", "path", "load", "fetch", "proxy", "forward",
    "resource", "remote", "upstream", "origin", "import", "ingest", "preview",
)

REDIRECT_PARAM_HINTS = (
    "redirect", "redirect_uri", "redirect_url", "return", "return_to", "returnurl",
    "next", "continue", "goto", "back", "callback_url", "success_url", "cancel_url",
)

URL_VALUE_RE = re.compile(r"^\s*(?:https?|ftp|gopher|file)://", re.I)

# Probe targets. Each is (label, payload, [signatures that prove the fetch happened]).
SSRF_PROBES: List[Tuple[str, str, Tuple[str, ...]]] = [
    ("AWS instance metadata (IMDSv1)",
     "http://169.254.169.254/latest/meta-data/",
     ("ami-id", "instance-id", "iam/", "hostname", "local-ipv4", "security-credentials")),
    ("GCP instance metadata",
     "http://metadata.google.internal/computeMetadata/v1/instance/",
     ("computeMetadata", "service-accounts", "machine-type", "zone")),
    ("Azure instance metadata",
     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     ("compute", "azEnvironment", "vmId", "subscriptionId")),
    ("Loopback HTTP service",
     "http://127.0.0.1/",
     ()),
    ("Loopback via IPv6",
     "http://[::1]/",
     ()),
    ("Local file scheme",
     "file:///etc/passwd",
     ("root:x:0:0", "daemon:x:", "/bin/bash", "nobody:")),
]

#: Control target - routable nowhere, so a response that differs from this one is
#: evidence the server treated the other payloads differently.
CONTROL_TARGET = "http://192.0.2.123/"          # TEST-NET-1, RFC 5737

METADATA_MARKERS = re.compile(
    r"(ami-id|instance-id|iam/security-credentials|computeMetadata|azEnvironment"
    r"|accessKeyId|SecretAccessKey|root:x:0:0)", re.I)

FETCH_ERROR_MARKERS = re.compile(
    r"(connection refused|econnrefused|connect timeout|etimedout|no route to host"
    r"|name or service not known|enotfound|getaddrinfo|failed to fetch|curl error"
    r"|unable to connect|invalid url|url fetch|proxy error|socket hang up)", re.I)


def _body_fields(endpoint: Endpoint) -> Dict[str, Any]:
    body = endpoint.json_body
    return body if isinstance(body, dict) else {}


def _candidate_params(endpoint: Endpoint) -> List[Tuple[str, str, str]]:
    """Return [(location, name, current_value)] worth injecting a URL into."""
    found: List[Tuple[str, str, str]] = []

    for name, value in parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True):
        if _looks_urlish(name, value):
            found.append(("query", name, value))

    for name, value in _body_fields(endpoint).items():
        if isinstance(value, (str, int)) and _looks_urlish(name, str(value)):
            found.append(("body", name, str(value)))

    return found


def _looks_urlish(name: str, value: str) -> bool:
    lowered = name.lower()
    if any(hint == lowered or hint in lowered for hint in URL_PARAM_HINTS):
        return True
    return bool(URL_VALUE_RE.match(value or ""))


def _with_query_param(endpoint: Endpoint, name: str, value: str) -> Endpoint:
    return endpoint.with_query_param(name, value)


def _with_body_field(endpoint: Endpoint, name: str, value: str) -> Endpoint:
    body = dict(_body_fields(endpoint))
    body[name] = value
    return endpoint.clone(body=json.dumps(body))


# --------------------------------------------------------------------------

@register
class ServerSideRequestForgery(Check):
    id = "ssrf.injection"
    name = "Server Side Request Forgery"
    severity = "critical"
    owasp = "API7"
    cwe = "CWE-918"
    profiles = ("safe", "aggressive")
    max_endpoints = 12

    def default_remediation(self) -> str:
        return ("Do not fetch client-supplied URLs. Where the feature requires it, resolve the "
                "hostname first and reject any address in a private, loopback, link-local or "
                "metadata range (re-checking after every redirect), allow-list the schemes and "
                "destination hosts, and make the outbound call from an egress-restricted "
                "network path with IMDSv2 enforced.")

    def applies(self, endpoint: Endpoint) -> bool:
        return bool(_candidate_params(endpoint))

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not self.budget_ok() or baseline is None or baseline.error:
            return []
        candidates = _candidate_params(endpoint)
        if not candidates:
            return []
        self.spend()

        oast = self.ctx.config.get("oast_domain")
        out: List[Finding] = []

        for location, name, _original in candidates[:3]:
            build = _with_query_param if location == "query" else _with_body_field

            control = self.ctx.replay(
                build(endpoint, name, CONTROL_TARGET), self.ctx.primary,
                note=f"SSRF control - `{name}` set to an unroutable address "
                     f"({CONTROL_TARGET}); everything else is compared against this")

            # Send every probe before judging. A blind differential on an early
            # payload must never pre-empt firm proof available from a later one.
            results = []
            for label, payload, signatures in SSRF_PROBES:
                probe = self.ctx.replay(
                    build(endpoint, name, payload), self.ctx.primary,
                    note=f"SSRF probe - `{name}` set to {payload} ({label})")
                if probe.error:
                    continue
                body = probe.response_body or ""
                hit = METADATA_MARKERS.search(body) or next(
                    (s for s in signatures if s and s.lower() in body.lower()), None)
                results.append((label, payload, probe, hit))

            confirmed = [r for r in results if r[3]]
            for label, payload, probe, hit in confirmed[:1]:
                    marker = hit.group(0) if hasattr(hit, "group") else hit
                    out.append(self.finding(
                        endpoint,
                        f"SSRF: `{name}` fetched {label} and returned its contents",
                        f"Setting the `{name}` {location} parameter to `{payload}` produced a "
                        f"response containing `{marker}` - content that only exists on the "
                        f"server's own side of the network. The API fetches client-supplied "
                        f"URLs with no destination restriction, so an attacker can read cloud "
                        f"credentials, reach internal-only services and pivot into the private "
                        f"network from the internet.",
                        [control, probe], confidence="firm",
                        evidence_summary=f"{name}={payload} -> HTTP {probe.status} containing "
                                         f"`{marker}`",
                        detail={"parameter": name, "location": location, "payload": payload,
                                "marker": marker},
                    ))
            if confirmed:
                return out            # firm proof for this parameter; stop here

            # 2. Nothing came back to us - fall back to differential behaviour.
            for label, payload, probe, _hit in results:
                if self._materially_different(control, probe):
                    body = probe.response_body or ""
                    fetch_error = FETCH_ERROR_MARKERS.search(body)
                    out.append(self.finding(
                        endpoint,
                        f"Possible SSRF: `{name}` is fetched server-side",
                        f"`{name}={payload}` produced a materially different response "
                        f"(HTTP {probe.status}, {probe.body_bytes} bytes, "
                        f"{probe.elapsed_ms:.0f}ms) from the unroutable control "
                        f"(HTTP {control.status}, {control.body_bytes} bytes, "
                        f"{control.elapsed_ms:.0f}ms). "
                        + (f"The response carries a network-level error "
                           f"(`{fetch_error.group(0)}`), which confirms the server attempted "
                           f"the connection on the client's behalf. "
                           if fetch_error else "")
                        + "The contents were not reflected back, so this is blind - confirm "
                          "with an out-of-band callback (`--oast-domain`) or by timing "
                          "an open versus closed internal port.",
                        [control, probe],
                        severity="high", confidence="probable",
                        evidence_summary=f"{name}={payload}: HTTP {probe.status}/"
                                         f"{probe.body_bytes}B vs control HTTP "
                                         f"{control.status}/{control.body_bytes}B",
                        detail={"parameter": name, "location": location, "payload": payload},
                    ))
                    break

            # 3. Out-of-band, when the tester supplied a collaborator domain.
            if oast:
                token = f"{self.ctx.config.get('oast_token', 'gatecrash')}-{abs(hash(name)) % 10000}"
                callback = f"http://{token}.{oast}/"
                probe = self.ctx.replay(
                    build(endpoint, name, callback), self.ctx.primary,
                    note=f"SSRF out-of-band probe - `{name}` set to {callback}")
                out.append(self.finding(
                    endpoint,
                    f"SSRF out-of-band probe sent via `{name}` - check your collaborator",
                    f"An out-of-band payload was delivered to the `{name}` {location} "
                    f"parameter pointing at `{callback}`. gatecrash cannot observe your "
                    f"collaborator, so this is not a finding on its own: check for a DNS or "
                    f"HTTP interaction from the target's egress address. An interaction "
                    f"confirms blind SSRF; no interaction after a few minutes suggests the "
                    f"parameter is not fetched.",
                    [probe], severity="info", confidence="tentative",
                    evidence_summary=f"payload {callback} delivered; awaiting out-of-band "
                                     f"confirmation",
                    remediation="Confirm before reporting - see the SSRF remediation guidance.",
                    detail={"parameter": name, "callback": callback},
                ))
        return out

    @staticmethod
    def _materially_different(control, probe) -> bool:
        if control.error or probe.error or control.status is None or probe.status is None:
            return False
        if control.status != probe.status:
            return True
        size_delta = abs((probe.body_bytes or 0) - (control.body_bytes or 0))
        if size_delta > max(64, 0.25 * max(control.body_bytes or 1, 1)):
            return True
        # A control pointing nowhere should be the *slowest* thing we send. If a probe
        # is dramatically faster, the server reached something.
        if control.elapsed_ms > 1500 and probe.elapsed_ms < control.elapsed_ms / 3:
            return True
        return False


@register
class OpenRedirect(Check):
    id = "misconfig.open_redirect"
    name = "Unvalidated redirect to an attacker-controlled host"
    severity = "medium"
    owasp = "API8"
    cwe = "CWE-601"
    profiles = ("safe", "aggressive")
    max_endpoints = 15

    EVIL = "https://gatecrash-probe.example/redirected"

    def default_remediation(self) -> str:
        return ("Validate redirect targets against a server-side allow-list of paths or hosts. "
                "Prefer relative paths, or map an opaque key to a destination rather than "
                "accepting the destination itself.")

    def _redirect_params(self, endpoint: Endpoint) -> List[Tuple[str, str]]:
        found = []
        for name, _v in parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True):
            if any(h in name.lower() for h in REDIRECT_PARAM_HINTS):
                found.append(("query", name))
        for name in _body_fields(endpoint):
            if any(h in name.lower() for h in REDIRECT_PARAM_HINTS):
                found.append(("body", name))
        return found

    def applies(self, endpoint: Endpoint) -> bool:
        return bool(self._redirect_params(endpoint))

    def run(self, endpoint: Endpoint, baseline) -> Iterable[Finding]:
        if not self.budget_ok():
            return []
        self.spend()
        out = []
        for location, name in self._redirect_params(endpoint)[:3]:
            build = _with_query_param if location == "query" else _with_body_field
            probe = self.ctx.replay(build(endpoint, name, self.EVIL), self.ctx.primary,
                                    note=f"open redirect probe - `{name}` set to {self.EVIL}")
            location_header = (probe.response_headers.get("Location")
                               or probe.response_headers.get("location") or "")
            if probe.status in (301, 302, 303, 307, 308) and \
                    location_header.startswith("https://gatecrash-probe.example"):
                out.append(self.finding(
                    endpoint,
                    f"Open redirect via `{name}`",
                    f"`{name}={self.EVIL}` produced HTTP {probe.status} with "
                    f"`Location: {location_header}`. The destination is not validated, so the "
                    f"endpoint can be used to lend the client's domain to a phishing page, and "
                    f"in OAuth flows to leak authorisation codes or tokens to an "
                    f"attacker-controlled host.",
                    [probe], confidence="firm",
                    evidence_summary=f"{name}={self.EVIL} -> HTTP {probe.status}, "
                                     f"Location: {location_header}",
                    detail={"parameter": name, "location_header": location_header},
                ))
        return out
