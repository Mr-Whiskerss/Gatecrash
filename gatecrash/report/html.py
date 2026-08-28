"""Self-contained HTML report."""
from __future__ import annotations

import datetime as _dt
import html
import json
import re
from typing import Dict, List

from ..models import SEVERITY_ORDER, Finding

CSS = """
*{box-sizing:border-box}
:root{
  --bg:#0e1116;--panel:#161b22;--panel2:#1c2230;--line:#2a3140;--fg:#e6edf3;
  --muted:#8b949e;--accent:#58a6ff;
  --critical:#ff4d4f;--high:#ff8a3d;--medium:#ffc53d;--low:#4ec9b0;--info:#6e8bb3;
}
body{margin:0;background:var(--bg);color:var(--fg);
  font:14px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
code,pre{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 80px}
header h1{margin:0 0 4px;font-size:24px;letter-spacing:-.01em}
header .sub{color:var(--muted);font-size:13px}
.meta{display:flex;flex-wrap:wrap;gap:10px;margin:18px 0 6px}
.meta div{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:9px 13px;font-size:12px}
.meta b{display:block;font-size:16px;font-weight:600;margin-top:2px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--line);border-left-width:4px;
  border-radius:8px;padding:12px 14px;cursor:pointer;user-select:none}
.card.off{opacity:.35}
.card .n{font-size:26px;font-weight:650;line-height:1.1}
.card .l{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.card.critical{border-left-color:var(--critical)} .card.critical .n{color:var(--critical)}
.card.high{border-left-color:var(--high)} .card.high .n{color:var(--high)}
.card.medium{border-left-color:var(--medium)} .card.medium .n{color:var(--medium)}
.card.low{border-left-color:var(--low)} .card.low .n{color:var(--low)}
.card.info{border-left-color:var(--info)} .card.info .n{color:var(--info)}
.toolbar{display:flex;gap:10px;align-items:center;margin:14px 0 20px;flex-wrap:wrap}
input[type=search]{flex:1;min-width:220px;background:var(--panel);border:1px solid var(--line);
  color:var(--fg);border-radius:8px;padding:9px 12px;font-size:13px}
.f{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:12px;
  overflow:hidden}
.f.hidden{display:none}
.fh{display:flex;gap:12px;align-items:flex-start;padding:14px 16px;cursor:pointer}
.fh:hover{background:var(--panel2)}
.sev{flex:none;font-size:10px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;
  padding:4px 8px;border-radius:5px;margin-top:2px;color:#0e1116}
.sev.critical{background:var(--critical)} .sev.high{background:var(--high)}
.sev.medium{background:var(--medium)} .sev.low{background:var(--low)}
.sev.info{background:var(--info);color:#e6edf3}
.ft{flex:1;min-width:0}
.ft h3{margin:0 0 5px;font-size:15px;font-weight:600}
.tags{display:flex;flex-wrap:wrap;gap:6px;font-size:11px;color:var(--muted)}
.tag{background:var(--panel2);border:1px solid var(--line);border-radius:20px;padding:2px 9px}
.tag.ep{font-family:ui-monospace,monospace;color:var(--accent)}
.chev{color:var(--muted);flex:none;font-size:12px;margin-top:4px}
.fb{display:none;padding:0 16px 18px;border-top:1px solid var(--line)}
.f.open .fb{display:block}
.fb h4{font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
  margin:18px 0 7px}
.fb p{margin:0 0 10px;white-space:pre-wrap}
.fb code{background:var(--panel2);padding:1px 5px;border-radius:4px;font-size:12.5px}
.ev{border:1px solid var(--line);border-radius:8px;margin-bottom:10px;overflow:hidden}
.evh{background:var(--panel2);padding:8px 12px;font-size:12px;display:flex;gap:10px;
  align-items:center;flex-wrap:wrap}
.evh .m{font-family:ui-monospace,monospace;font-weight:600;color:var(--accent)}
.evh .st{font-family:ui-monospace,monospace}
.evh .id{margin-left:auto;color:var(--muted);font-family:ui-monospace,monospace;font-size:11px}
.note{color:var(--medium);font-style:italic}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--line)}
@media(max-width:820px){.pair{grid-template-columns:1fr}}
.pane{background:#0b0e13;padding:10px 12px;overflow:auto;max-height:360px}
.pane .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
  margin-bottom:6px}
pre{margin:0;white-space:pre-wrap;word-break:break-word;font-size:12px;line-height:1.5}
.rem{background:rgba(78,201,176,.07);border-left:3px solid var(--low);padding:10px 14px;
  border-radius:0 6px 6px 0}
footer{color:var(--muted);font-size:12px;margin-top:34px;border-top:1px solid var(--line);
  padding-top:16px}
.warn{background:rgba(255,197,61,.08);border:1px solid rgba(255,197,61,.3);color:#ffd77a;
  border-radius:8px;padding:12px 14px;font-size:12.5px;margin:16px 0}
.empty{text-align:center;color:var(--muted);padding:60px 20px}
"""

JS = """
function toggle(el){el.parentElement.classList.toggle('open');}
const state={sev:new Set(%SEVS%),q:''};
function apply(){
  document.querySelectorAll('.f').forEach(f=>{
    const okSev=state.sev.has(f.dataset.sev);
    const okQ=!state.q||f.dataset.search.includes(state.q);
    f.classList.toggle('hidden',!(okSev&&okQ));
  });
  const shown=document.querySelectorAll('.f:not(.hidden)').length;
  document.getElementById('empty').style.display=shown?'none':'block';
  document.getElementById('shown').textContent=shown;
}
document.querySelectorAll('.card').forEach(c=>c.addEventListener('click',()=>{
  const s=c.dataset.sev;
  if(state.sev.has(s)){state.sev.delete(s);c.classList.add('off');}
  else{state.sev.add(s);c.classList.remove('off');}
  apply();
}));
document.getElementById('q').addEventListener('input',e=>{
  state.q=e.target.value.toLowerCase();apply();
});
document.getElementById('expand').addEventListener('click',()=>{
  const anyClosed=[...document.querySelectorAll('.f:not(.hidden)')].some(f=>!f.classList.contains('open'));
  document.querySelectorAll('.f:not(.hidden)').forEach(f=>f.classList.toggle('open',anyClosed));
});
apply();
"""


def _e(text) -> str:
    return html.escape(str(text if text is not None else ""))


def _md_inline(text: str) -> str:
    """Escape, then honour `code` spans and ``` fenced blocks from check text."""
    out = _e(text)
    out = re.sub(r"```(?:json|http|text)?\n?(.*?)```",
                 lambda m: f"<pre class=\"pane\">{m.group(1)}</pre>", out, flags=re.S)
    out = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", out)
    return out


def _render_evidence(exchanges) -> str:
    blocks = []
    for ex in exchanges:
        if ex is None:
            continue
        status = f"HTTP {ex.status}" if ex.status is not None else "no response"
        blocks.append(f"""
      <div class="ev">
        <div class="evh">
          <span class="m">{_e(ex.method)}</span>
          <span class="st">{_e(status)}</span>
          <span>as <b>{_e(ex.identity)}</b></span>
          <span>{_e(round(ex.elapsed_ms))} ms</span>
          <span>{_e(ex.body_bytes)} bytes</span>
          {f'<span class="note">{_e(ex.note)}</span>' if ex.note else ''}
          <span class="id">#{_e(ex.id)}</span>
        </div>
        <div class="pair">
          <div class="pane"><div class="lbl">Request</div><pre>{_e(ex.raw_request())}</pre></div>
          <div class="pane"><div class="lbl">Response</div><pre>{_e(ex.raw_response())}</pre></div>
        </div>
      </div>""")
    return "".join(blocks)


def render(findings: List[Finding], stats: Dict, target: str,
           errors: List[str] = None) -> str:
    generated = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    cards = "".join(
        f"""<div class="card {s}" data-sev="{s}"><div class="n">{counts.get(s, 0)}</div>
        <div class="l">{s}</div></div>""" for s in SEVERITY_ORDER)

    meta = "".join(f"""<div>{_e(label)}<b>{_e(value)}</b></div>""" for label, value in [
        ("Target", target),
        ("Endpoints tested", stats.get("endpoints_tested", 0)),
        ("Requests sent", stats.get("requests_sent", 0)),
        ("Checks run", stats.get("checks_run", 0)),
        ("Profile", stats.get("profile", "")),
        ("Identities", ", ".join(stats.get("identities", []))),
    ])

    items = []
    for f in findings:
        search = " ".join([f.title, f.endpoint, f.description, f.check_id,
                           f.owasp_label or "", f.cwe or ""]).lower()
        tags = [f'<span class="tag ep">{_e(f.endpoint)}</span>',
                f'<span class="tag">{_e(f.confidence)} confidence</span>',
                f'<span class="tag">{_e(f.check_id)}</span>']
        if f.owasp:
            tags.append(f'<span class="tag">{_e(f.owasp_label)}</span>')
        if f.cwe:
            tags.append(f'<span class="tag">{_e(f.cwe)}</span>')
        items.append(f"""
    <div class="f" data-sev="{f.severity}" data-search="{_e(search)}">
      <div class="fh" onclick="toggle(this)">
        <span class="sev {f.severity}">{f.severity}</span>
        <div class="ft">
          <h3>{_md_inline(f.title)}</h3>
          <div class="tags">{''.join(tags)}</div>
        </div>
        <span class="chev">&#9662;</span>
      </div>
      <div class="fb">
        <h4>Description</h4>
        <p>{_md_inline(f.description)}</p>
        <h4>Evidence &mdash; {_e(f.evidence_summary)}</h4>
        {_render_evidence(f.exchanges)}
        <h4>Remediation</h4>
        <div class="rem">{_md_inline(f.remediation)}</div>
      </div>
    </div>""")

    warn = ""
    if errors:
        shown = "".join(f"<li>{_e(e)}</li>" for e in errors[:12])
        more = f"<li>&hellip; and {len(errors) - 12} more</li>" if len(errors) > 12 else ""
        warn = (f'<div class="warn"><b>{len(errors)} request(s) or check(s) were skipped '
                f'or errored</b><ul>{shown}{more}</ul></div>')

    js = JS.replace("%SEVS%", json.dumps(SEVERITY_ORDER))

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>API security findings &mdash; {_e(target)}</title>
<style>{CSS}</style></head><body><div class="wrap">
<header>
  <h1>API security assessment</h1>
  <div class="sub">{_e(target)} &middot; generated {generated} &middot; gatecrash</div>
</header>
<div class="meta">{meta}</div>
<div class="cards">{cards}</div>
{warn}
<div class="toolbar">
  <input id="q" type="search" placeholder="Filter findings by title, endpoint, CWE, check id&hellip;">
  <button id="expand" class="card" style="cursor:pointer">Expand / collapse</button>
  <span style="color:var(--muted);font-size:12px"><b id="shown">0</b> shown</span>
</div>
{''.join(items) if items else ''}
<div id="empty" class="empty" style="display:none">No findings match the current filter.</div>
<footer>
  Every finding above is reproducible from the raw request/response pairs recorded with it.
  Findings marked <b>tentative</b> or <b>probable</b> need manual confirmation before they go
  in a client report &mdash; the scanner infers authorisation intent from response similarity,
  which it cannot always get right.<br><br>
  Scope: {_e(', '.join(stats.get('scope', [])))} &middot;
  Primary identity: {_e(stats.get('primary_identity', ''))}
</footer>
</div><script>{js}</script></body></html>"""
