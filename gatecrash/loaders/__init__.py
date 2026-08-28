"""Collection loaders: normalise anything into a list of Endpoints."""
from __future__ import annotations

import json
import logging
import os
from typing import Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from ..models import Endpoint
from . import openapi as openapi_loader
from . import postman as postman_loader

log = logging.getLogger("gatecrash")

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def load_raw_list(path: str, target: Optional[str] = None) -> List[Endpoint]:
    """One endpoint per line: `GET https://api/x`, `POST /x`, or bare URL/path."""
    endpoints: List[Endpoint] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if parts[0].upper() in HTTP_METHODS and len(parts) > 1:
                method, rest = parts[0].upper(), parts[1].strip()
            else:
                method, rest = "GET", line
            if "://" not in rest:
                if not target:
                    log.warning("%s:%d relative path needs --target: %s", path, lineno, rest)
                    continue
                rest = target.rstrip("/") + "/" + rest.lstrip("/")
            endpoints.append(Endpoint(method=method, url=rest, source=path))
    return endpoints


def detect_kind(path: str) -> str:
    lowered = path.lower()
    if lowered.endswith((".yaml", ".yml")):
        return "openapi"
    if lowered.endswith(".txt") or lowered.endswith(".list"):
        return "rawlist"
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            head = fh.read(8192)
        data = json.loads(head) if head.strip().startswith("{") else None
    except (ValueError, OSError):
        data = None
    if isinstance(data, dict):
        if "info" in data and "item" in data:
            return "postman"
        if "openapi" in data or "swagger" in data:
            return "openapi"
    # Fall back to a full parse before giving up
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            full = json.load(fh)
        if isinstance(full, dict):
            if "item" in full:
                return "postman"
            if "paths" in full:
                return "openapi"
    except (ValueError, OSError):
        pass
    return "rawlist"


def rebase(endpoints: List[Endpoint], target: str) -> List[Endpoint]:
    """Point every endpoint at `target`'s scheme+host, keeping paths/queries."""
    tparts = urlsplit(target if "://" in target else "https://" + target)
    base_path = tparts.path.rstrip("/")
    out = []
    for ep in endpoints:
        parts = urlsplit(ep.url)
        path = parts.path
        if base_path and not path.startswith(base_path):
            path = base_path + path
        out.append(ep.clone(url=urlunsplit(
            (tparts.scheme, tparts.netloc, path, parts.query, ""))))
    return out


def dedupe(endpoints: List[Endpoint]) -> List[Endpoint]:
    seen = set()
    out = []
    for ep in endpoints:
        key = (ep.method, ep.url, (ep.body or "")[:200])
        if key in seen:
            continue
        seen.add(key)
        out.append(ep)
    return out


def load_any(path: str, target: Optional[str] = None,
             environment: Optional[str] = None,
             overrides: Optional[Dict[str, str]] = None) -> List[Endpoint]:
    if not os.path.exists(path):
        raise SystemExit(f"input file not found: {path}")
    kind = detect_kind(path)
    log.info("Loading %s as %s", path, kind)
    if kind == "postman":
        endpoints = postman_loader.load(path, environment, overrides)
    elif kind == "openapi":
        endpoints = openapi_loader.load(path, target, overrides)
    else:
        endpoints = load_raw_list(path, target)
    if target and kind != "openapi":
        endpoints = rebase(endpoints, target)
    return dedupe(endpoints)
