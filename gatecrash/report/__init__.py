"""Reporters."""
from __future__ import annotations

import datetime as _dt
import json
import os
from typing import Dict, List

from ..models import Finding
from . import html as html_report
from . import markdown as md_report


def write_json(path: str, findings: List[Finding], stats: Dict, target: str,
               errors: List[str] = None) -> None:
    payload = {
        "tool": "gatecrash",
        "version": "1.1.0",
        "generated": _dt.datetime.now().astimezone().isoformat(),
        "target": target,
        "stats": stats,
        "errors": errors or [],
        "findings": [f.to_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)


def write_html(path: str, findings: List[Finding], stats: Dict, target: str,
               errors: List[str] = None) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_report.render(findings, stats, target, errors))


def write_markdown(path: str, findings: List[Finding], stats: Dict, target: str,
                   errors: List[str] = None) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(md_report.render(findings, stats, target, errors))


def write_all(outdir: str, findings: List[Finding], stats: Dict, target: str,
              errors: List[str] = None, formats=("html", "json", "md")) -> List[str]:
    os.makedirs(outdir, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    written = []
    if "html" in formats:
        p = os.path.join(outdir, f"gatecrash-{stamp}.html")
        write_html(p, findings, stats, target, errors)
        written.append(p)
    if "json" in formats:
        p = os.path.join(outdir, f"gatecrash-{stamp}.json")
        write_json(p, findings, stats, target, errors)
        written.append(p)
    if "md" in formats:
        p = os.path.join(outdir, f"gatecrash-{stamp}.md")
        write_markdown(p, findings, stats, target, errors)
        written.append(p)
    return written
