"""Postman collection v2.0 / v2.1 loader (with environment + variable support)."""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from ..models import Endpoint

log = logging.getLogger("gatecrash")

_VAR_RE = re.compile(r"\{\{([^{}]+)\}\}")


# --------------------------------------------------------------------------

def collect_variables(collection: Dict[str, Any],
                      environment: Optional[Dict[str, Any]] = None,
                      overrides: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Merge collection variables, environment values and CLI overrides."""
    variables: Dict[str, str] = {}
    for var in collection.get("variable", []) or []:
        if isinstance(var, dict) and var.get("key") is not None:
            variables[str(var["key"])] = str(var.get("value", ""))
    if environment:
        values = environment.get("values", environment.get("variable", [])) or []
        for var in values:
            if not isinstance(var, dict):
                continue
            if var.get("enabled") is False:
                continue
            key = var.get("key")
            if key is not None:
                variables[str(key)] = str(var.get("value", ""))
    if overrides:
        variables.update({str(k): str(v) for k, v in overrides.items()})
    return variables


def substitute(text: Optional[str], variables: Dict[str, str],
               unresolved: Optional[set] = None) -> Optional[str]:
    """Replace {{var}} placeholders; record any that could not be resolved."""
    if not text:
        return text

    def repl(match: re.Match) -> str:
        name = match.group(1).strip()
        if name in variables:
            return variables[name]
        if unresolved is not None:
            unresolved.add(name)
        # keep something URL-safe so the request is still sendable
        return _placeholder_for(name)

    prev = None
    out = text
    for _ in range(5):                       # variables may reference variables
        prev, out = out, _VAR_RE.sub(repl, out)
        if out == prev:
            break
    return out


def _placeholder_for(name: str) -> str:
    lowered = name.lower()
    if any(k in lowered for k in ("id", "uuid", "guid")):
        return "1"
    if "token" in lowered or "key" in lowered or "secret" in lowered:
        return "PLACEHOLDER"
    if "url" in lowered or "host" in lowered or "base" in lowered:
        return ""
    return "test"


# --------------------------------------------------------------------------

def _url_to_string(url: Any, variables: Dict[str, str], unresolved: set) -> str:
    if isinstance(url, str):
        return substitute(url, variables, unresolved) or ""
    if not isinstance(url, dict):
        return ""
    raw = url.get("raw")
    if raw:
        return substitute(raw, variables, unresolved) or ""
    protocol = url.get("protocol") or "https"
    host = url.get("host") or []
    if isinstance(host, list):
        host = ".".join(str(h) for h in host)
    path = url.get("path") or []
    if isinstance(path, list):
        path = "/".join(str(p) for p in path)
    built = f"{protocol}://{host}/{str(path).lstrip('/')}"
    query = url.get("query") or []
    pairs = [f"{q.get('key')}={q.get('value', '')}" for q in query
             if isinstance(q, dict) and q.get("disabled") is not True and q.get("key")]
    if pairs:
        built += "?" + "&".join(pairs)
    return substitute(built, variables, unresolved) or ""


def _headers(request: Dict[str, Any], variables: Dict[str, str],
             unresolved: set) -> Dict[str, str]:
    out: Dict[str, str] = {}
    raw = request.get("header") or []
    if isinstance(raw, str):
        for line in raw.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                out[k.strip()] = substitute(v.strip(), variables, unresolved) or ""
        return out
    for h in raw:
        if not isinstance(h, dict) or h.get("disabled"):
            continue
        key = h.get("key")
        if key:
            out[str(key)] = substitute(str(h.get("value", "")), variables, unresolved) or ""
    return out


def _body(request: Dict[str, Any], variables: Dict[str, str],
          unresolved: set) -> tuple:
    body = request.get("body") or {}
    if not isinstance(body, dict):
        return None, None
    mode = body.get("mode")
    if mode == "raw":
        raw = substitute(body.get("raw"), variables, unresolved)
        lang = ((body.get("options") or {}).get("raw") or {}).get("language", "")
        ctype = "application/json" if lang == "json" or _looks_json(raw) else "text/plain"
        return raw, ctype
    if mode == "urlencoded":
        pairs = [f"{p.get('key')}={substitute(str(p.get('value', '')), variables, unresolved)}"
                 for p in body.get("urlencoded", []) or []
                 if isinstance(p, dict) and not p.get("disabled") and p.get("key")]
        return "&".join(pairs), "application/x-www-form-urlencoded"
    if mode == "formdata":
        pairs = [f"{p.get('key')}={substitute(str(p.get('value', '')), variables, unresolved)}"
                 for p in body.get("formdata", []) or []
                 if isinstance(p, dict) and not p.get("disabled")
                 and p.get("type") != "file" and p.get("key")]
        return "&".join(pairs), "application/x-www-form-urlencoded"
    if mode == "graphql":
        gql = body.get("graphql") or {}
        payload = json.dumps({"query": gql.get("query", ""),
                              "variables": gql.get("variables", {})})
        return substitute(payload, variables, unresolved), "application/json"
    return None, None


def _looks_json(raw: Optional[str]) -> bool:
    return bool(raw) and raw.lstrip().startswith(("{", "["))


def _auth_hint(node: Dict[str, Any]) -> Optional[str]:
    auth = node.get("auth")
    if isinstance(auth, dict) and auth.get("type"):
        return str(auth["type"]).lower()
    return None


# --------------------------------------------------------------------------

def load(path: str, environment_path: Optional[str] = None,
         overrides: Optional[Dict[str, str]] = None) -> List[Endpoint]:
    with open(path, "r", encoding="utf-8-sig") as fh:
        collection = json.load(fh)

    environment = None
    if environment_path:
        with open(environment_path, "r", encoding="utf-8-sig") as fh:
            environment = json.load(fh)

    variables = collect_variables(collection, environment, overrides)
    unresolved: set = set()
    endpoints: List[Endpoint] = []

    def walk(items: List[Any], trail: List[str], inherited_auth: Optional[str]) -> None:
        for item in items or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", ""))
            auth = _auth_hint(item) or inherited_auth
            if "item" in item:
                walk(item["item"], trail + [name], auth)
                continue
            request = item.get("request")
            if isinstance(request, str):
                request = {"method": "GET", "url": request}
            if not isinstance(request, dict):
                continue
            url = _url_to_string(request.get("url"), variables, unresolved)
            if not url or "://" not in url:
                log.debug("skipping item with unusable URL: %s (%r)", name, url)
                continue
            body, ctype = _body(request, variables, unresolved)
            headers = _headers(request, variables, unresolved)
            if ctype and not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = ctype
            endpoints.append(Endpoint(
                method=str(request.get("method", "GET")),
                url=url,
                name=" / ".join([p for p in trail + [name] if p]) or name,
                headers=headers,
                body=body,
                content_type=ctype or headers.get("Content-Type"),
                source=path,
                auth_hint=_auth_hint(request) or auth,
            ))

    walk(collection.get("item", []), [], _auth_hint(collection))

    if unresolved:
        log.warning("Postman variables with no value (placeholders substituted): %s",
                    ", ".join(sorted(unresolved)))
    return endpoints
