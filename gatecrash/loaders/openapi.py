"""OpenAPI 3.x / Swagger 2.0 loader (JSON or YAML)."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from ..models import Endpoint

log = logging.getLogger("gatecrash")

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def _read(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8-sig") as fh:
        text = fh.read()
    try:
        return json.loads(text)
    except ValueError:
        try:
            import yaml
        except ImportError as exc:                       # pragma: no cover
            raise SystemExit("PyYAML is required to read YAML specs: pip install pyyaml") from exc
        return yaml.safe_load(text)


def _resolve(spec: Dict[str, Any], node: Any, depth: int = 0) -> Any:
    """Resolve local $refs (best effort, cycle-safe)."""
    if depth > 12 or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        target: Any = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(target, dict) and part in target:
                target = target[part]
            else:
                return {}
        return _resolve(spec, target, depth + 1)
    return node


def _base_urls(spec: Dict[str, Any], target: Optional[str]) -> List[str]:
    if target:
        return [target.rstrip("/") + "/"]
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        out = []
        for srv in servers:
            url = srv.get("url", "") if isinstance(srv, dict) else str(srv)
            for name, var in (srv.get("variables", {}) if isinstance(srv, dict) else {}).items():
                default = var.get("default") if isinstance(var, dict) else None
                if default is not None:
                    url = url.replace("{%s}" % name, str(default))
            if url:
                out.append(url.rstrip("/") + "/")
        if out:
            return out[:1]
    # Swagger 2.0
    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        base = spec.get("basePath", "") or ""
        return [f"{scheme}://{host}{base}".rstrip("/") + "/"]
    return []


def _example_for(schema: Dict[str, Any], name: str = "") -> Any:
    schema = schema or {}
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    if "examples" in schema and isinstance(schema["examples"], list) and schema["examples"]:
        return schema["examples"][0]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    stype = schema.get("type")
    if stype == "integer" or stype == "number":
        return 1
    if stype == "boolean":
        return True
    if stype == "array":
        return [_example_for(schema.get("items", {}) or {}, name)]
    if stype == "object" or "properties" in schema:
        return {k: _example_for(v or {}, k)
                for k, v in (schema.get("properties") or {}).items()}
    fmt = (schema.get("format") or "").lower()
    lname = name.lower()
    if fmt == "uuid":
        return "00000000-0000-4000-8000-000000000000"
    if fmt in ("date-time", "date"):
        return "2024-01-01T00:00:00Z"
    if fmt == "email" or "email" in lname:
        return "gatecrash-probe@example.com"
    if "id" in lname:
        return "1"
    return "gatecrash"


def _build_body(spec: Dict[str, Any], operation: Dict[str, Any]) -> tuple:
    rb = _resolve(spec, operation.get("requestBody") or {})
    content = rb.get("content") or {}
    for ctype in ("application/json", "application/vnd.api+json", "text/json"):
        if ctype in content:
            media = content[ctype] or {}
            if "example" in media:
                return json.dumps(media["example"]), ctype
            examples = media.get("examples") or {}
            if examples:
                first = next(iter(examples.values()))
                if isinstance(first, dict) and "value" in first:
                    return json.dumps(first["value"]), ctype
            schema = _resolve(spec, media.get("schema") or {})
            return json.dumps(_example_for(schema), default=str), ctype
    if "application/x-www-form-urlencoded" in content:
        schema = _resolve(spec, (content["application/x-www-form-urlencoded"] or {}).get("schema") or {})
        example = _example_for(schema)
        if isinstance(example, dict):
            return "&".join(f"{k}={v}" for k, v in example.items()), \
                "application/x-www-form-urlencoded"
    # Swagger 2.0 body parameter
    for param in operation.get("parameters", []) or []:
        param = _resolve(spec, param)
        if param.get("in") == "body":
            schema = _resolve(spec, param.get("schema") or {})
            return json.dumps(_example_for(schema), default=str), "application/json"
    return None, None


def load(path: str, target: Optional[str] = None,
         overrides: Optional[Dict[str, str]] = None) -> List[Endpoint]:
    spec = _read(path)
    if not isinstance(spec, dict):
        raise SystemExit(f"{path} does not look like an OpenAPI/Swagger document")

    bases = _base_urls(spec, target)
    if not bases:
        raise SystemExit(
            f"{path} declares no server URL - pass --target https://api.example.com")
    base = bases[0]
    overrides = overrides or {}
    endpoints: List[Endpoint] = []

    for raw_path, path_item in (spec.get("paths") or {}).items():
        path_item = _resolve(spec, path_item or {})
        shared_params = path_item.get("parameters", []) or []
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            params = [_resolve(spec, p) for p in (shared_params + (operation.get("parameters") or []))]

            concrete = raw_path
            query: Dict[str, str] = {}
            headers: Dict[str, str] = {}
            for param in params:
                pname = param.get("name")
                if not pname:
                    continue
                schema = _resolve(spec, param.get("schema") or {})
                value = overrides.get(pname, param.get("example",
                                                       _example_for(schema, pname)))
                where = param.get("in")
                if where == "path":
                    concrete = concrete.replace("{%s}" % pname, str(value))
                elif where == "query" and (param.get("required") or "id" in pname.lower()):
                    query[pname] = str(value)
                elif where == "header" and param.get("required"):
                    headers[pname] = str(value)

            url = urljoin(base, concrete.lstrip("/"))
            if query:
                url += ("&" if "?" in url else "?") + "&".join(
                    f"{k}={v}" for k, v in query.items())

            body, ctype = _build_body(spec, operation)
            if ctype:
                headers.setdefault("Content-Type", ctype)

            security = operation.get("security", spec.get("security"))
            endpoints.append(Endpoint(
                method=method.upper(),
                url=url,
                name=operation.get("operationId") or operation.get("summary")
                or f"{method.upper()} {raw_path}",
                path_template=raw_path,
                headers=headers,
                body=body,
                content_type=ctype,
                source=path,
                auth_hint="declared" if security else None,
                tags=[str(t) for t in (operation.get("tags") or [])],
            ))

    log.info("Loaded %d operations from %s", len(endpoints), path)
    return endpoints
