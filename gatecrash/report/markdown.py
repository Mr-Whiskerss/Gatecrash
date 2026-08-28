"""Markdown report - drops straight into engagement notes."""
from __future__ import annotations

import datetime as _dt
from typing import Dict, List

from ..models import SEVERITY_ORDER, Finding

ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟩", "info": "⬜"}


def _fence(text: str, limit: int = 4000) -> str:
    text = text or ""
    if len(text) > limit:
        text = text[:limit] + "\n[... truncated ...]"
    return "```http\n" + text.replace("```", "`​``") + "\n```"


def render(findings: List[Finding], stats: Dict, target: str,
           errors: List[str] = None, evidence_limit: int = 2500) -> str:
    generated = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [
        f"# API security assessment — {target}",
        "",
        f"_Generated {generated} by gatecrash (profile: {stats.get('profile')})._",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in SEVERITY_ORDER:
        lines.append(f"| {ICON[sev]} {sev.title()} | {counts.get(sev, 0)} |")
    lines += [
        "",
        f"- **Scope:** {', '.join(stats.get('scope', [])) or 'n/a'}",
        f"- **Endpoints tested:** {stats.get('endpoints_tested', 0)}",
        f"- **Requests sent:** {stats.get('requests_sent', 0)}",
        f"- **Checks run:** {stats.get('checks_run', 0)}",
        f"- **Identities:** {', '.join(stats.get('identities', []))} "
        f"(primary: `{stats.get('primary_identity', '')}`)",
        "",
    ]

    if not findings:
        lines += ["## Findings", "", "No findings were produced at this profile.", ""]
    else:
        lines += ["## Findings", ""]
        for sev in SEVERITY_ORDER:
            group = [f for f in findings if f.severity == sev]
            if not group:
                continue
            lines += [f"### {ICON[sev]} {sev.title()} ({len(group)})", ""]
            for i, f in enumerate(group, 1):
                lines += [
                    f"#### {sev[0].upper()}{i}. {f.title}",
                    "",
                    f"- **Endpoint:** `{f.endpoint}`",
                    f"- **URL:** {f.url}",
                    f"- **Confidence:** {f.confidence}",
                    f"- **Check:** `{f.check_id}`"
                    + (f" · **{f.owasp_label}**" if f.owasp else "")
                    + (f" · {f.cwe}" if f.cwe else ""),
                    "",
                    f.description,
                    "",
                    f"**Evidence** — {f.evidence_summary}",
                    "",
                ]
                for ex in f.exchanges:
                    if ex is None:
                        continue
                    header = (f"<summary>{ex.method} {ex.url} — as <code>{ex.identity}</code>"
                              f" → HTTP {ex.status}"
                              + (f" — {ex.note}" if ex.note else "") + "</summary>")
                    lines += [
                        "<details>", header, "",
                        _fence(ex.raw_request(), evidence_limit),
                        _fence(ex.raw_response(), evidence_limit),
                        "</details>", "",
                    ]
                lines += [f"**Remediation:** {f.remediation}", "", "---", ""]

    if errors:
        lines += ["## Skipped / errored", ""]
        lines += [f"- `{e}`" for e in errors[:40]]
        if len(errors) > 40:
            lines.append(f"- … and {len(errors) - 40} more")
        lines.append("")

    lines += [
        "## Caveats",
        "",
        "Findings marked *tentative* or *probable* infer authorisation intent from response "
        "similarity and require manual confirmation before being reported to a client. "
        "Absence of a finding is not evidence of absence — this scan only exercised the "
        "endpoints supplied in the collection.",
        "",
    ]
    return "\n".join(lines)
