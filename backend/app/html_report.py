"""
html_report.py — render an incident report as a styled, self-contained HTML
document.

Takes the same structured dict that report_generator.generate_report() builds
and produces a single HTML file (no external assets, no network) an analyst can
open, filter, and share. Complements the Markdown report rather than replacing
it.

Design intent: this is a forensic/IR deliverable for analysts, not a marketing
page. Dark, dense, information-first; severity is the organising signal and
carries the only saturated colour. Monospace for evidence/IOCs so artefacts
line up and read like the console output they came from. Two layers — an
executive view (summary + metrics + MITRE shape) and a technical view (every
finding, filterable) — toggled in place so one file serves both the CISO and
the responder.
"""
from __future__ import annotations

import html
from app.evidence_format import why_it_matters, evidence_fields
import json


# ── palette / tokens ────────────────────────────────────────────────────────
# Severity is the spine of the whole document, so it owns the saturated hues;
# everything structural stays in cool slate greys so the colour means "danger",
# not "decoration".
SEV_COLORS = {
    "critical": "#ff4d4d",
    "high": "#ff8c42",
    "medium": "#ffd23f",
    "low": "#4da3ff",
    "info": "#7a8699",
}


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def _safe_json(obj) -> str:
    """json.dumps, then neutralise characters that could break out of or
    confuse a <script> block (<, >, &, and the U+2028/2029 line separators
    that are valid JSON but illegal in JS string literals)."""
    s = json.dumps(obj, ensure_ascii=False)
    return (s.replace("<", "\\u003c").replace(">", "\\u003e")
             .replace("&", "\\u0026")
             .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _sev(sev: str) -> str:
    return str(sev or "info").lower()


def generate_html(report: dict) -> str:
    """Render the report dict as a standalone HTML string."""
    meta = report.get("metadata", {})
    summ = report.get("executive_summary", {})
    metrics = summ.get("key_metrics", {})
    findings = report.get("detection_findings", [])
    iocs = report.get("iocs", [])
    techniques = report.get("mitre_techniques", [])
    timeline = report.get("timeline", [])
    recommendations = report.get("recommendations", [])
    gaps = report.get("knowledge_gaps", [])
    narrative = report.get("attack_narrative", {})
    mitre_cov = report.get("mitre_coverage", {})

    sev_label = _sev(meta.get("severity", "info"))
    sev_color = SEV_COLORS.get(sev_label, SEV_COLORS["info"])

    # Serialise findings for the client-side filter. Keep only what the UI shows.
    # json.dumps escapes for JSON but NOT for HTML, so a finding title like
    # "</script>" could break out of the <script> block. Escaping '<' (and '&')
    # to unicode escapes keeps the JSON valid and inert inside <script>.
    findings_json = _safe_json([
        {
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": _sev(f.get("severity")),
            "category": f.get("category", "uncategorised"),
            "description": f.get("description", ""),
            "mitre": f.get("mitre", ""),
            "occurrences": f.get("occurrences", 1),
            "score": f.get("score", 0),
            "why": why_it_matters(f),
            "evidence": [
                {"label": lbl, "value": val, "raw": raw}
                for lbl, val, raw in evidence_fields(f)
            ],
        }
        for f in findings
    ])

    return _TEMPLATE.format(
        title=_esc(meta.get("title", "Incident Report")),
        report_id=_esc(meta.get("report_id", "")),
        generated=_esc(meta.get("generated_at", "")),
        status=_esc(meta.get("status", "")),
        analyzed_by=_esc(meta.get("analyzed_by", "")),
        confidence=_esc(meta.get("confidence", "N/A")),
        engine=_esc(meta.get("engine_version", "")),
        sev_label=sev_label.upper(),
        sev_color=sev_color,
        sev_desc=_esc(meta.get("severity_description", "")),
        bottom_line=_esc(summ.get("bottom_line", "")),
        summary=_esc(summ.get("summary", "")),
        confidence_expl=_esc(summ.get("confidence_explanation", "")),
        metrics_html=_render_metrics(metrics),
        mitre_html=_render_mitre(mitre_cov, techniques),
        narrative_html=_render_narrative(narrative),
        ioc_html=_render_iocs(iocs),
        timeline_html=_render_timeline(timeline),
        recs_html=_render_recs(recommendations),
        gaps_html=_render_gaps(gaps),
        sev_colors_json=_safe_json(SEV_COLORS),
        findings_json=findings_json,
        finding_count=len(findings),
    )


def _render_metrics(m: dict) -> str:
    cells = [
        ("Unique findings", m.get("unique_findings", 0), None),
        ("Total occurrences", m.get("total_occurrences", 0), None),
        ("Critical", m.get("critical", 0), "critical"),
        ("High", m.get("high", 0), "high"),
        ("Medium", m.get("medium", 0), "medium"),
        ("IOCs", m.get("iocs", 0), None),
        ("MITRE tactics", m.get("mitre_tactics", 0), None),
        ("MITRE techniques", m.get("mitre_techniques", 0), None),
        ("Attack chains", m.get("attack_chains", 0), None),
    ]
    out = []
    for label, value, sev in cells:
        color = f"color:{SEV_COLORS[sev]}" if sev else ""
        out.append(
            f'<div class="metric"><div class="metric-v" style="{color}">{_esc(value)}</div>'
            f'<div class="metric-l">{_esc(label)}</div></div>'
        )
    return "".join(out)


def _render_mitre(cov: dict, techniques: list) -> str:
    tactics = cov.get("by_tactic", []) if isinstance(cov, dict) else []
    if not tactics and not techniques:
        return '<p class="empty">No MITRE ATT&CK techniques mapped.</p>'
    # Tactic columns, each listing its techniques as chips — reads like an
    # ATT&CK matrix row without pulling the full framework in.
    cols = []
    for t in tactics:
        tname = _esc(t.get("tactic", "")) if isinstance(t, dict) else _esc(t)
        count = t.get("total_detections", "") if isinstance(t, dict) else ""
        cols.append(
            f'<div class="tactic"><div class="tactic-h">{tname}'
            f'<span class="tactic-n">{_esc(count)}</span></div></div>'
        )
    chips = "".join(
        f'<span class="chip"><b>{_esc(t.get("id",""))}</b> {_esc(t.get("name",""))}'
        f'<i>{_esc(t.get("confidence",""))}</i></span>'
        for t in techniques
    )
    return (
        f'<div class="tactic-row">{"".join(cols)}</div>'
        f'<div class="chips">{chips}</div>'
    )


def _render_narrative(n: dict) -> str:
    if not n:
        return ""
    text = n.get("attack_narrative", "") if isinstance(n, dict) else str(n)
    if not text:
        return ""
    paras = "".join(f"<p>{_esc(p)}</p>" for p in str(text).split("\n\n") if p.strip())
    return f'<section class="block"><h2>Attack narrative</h2>{paras}</section>'


def _render_iocs(iocs: list) -> str:
    if not iocs:
        return '<p class="empty">No indicators of compromise extracted.</p>'
    rows = []
    for i in iocs:
        mal = i.get("malicious")
        badge = ('<span class="mal yes">malicious</span>' if mal
                 else '<span class="mal no">unconfirmed</span>')
        rows.append(
            f'<tr><td class="mono">{_esc(i.get("type",""))}</td>'
            f'<td class="mono val">{_esc(i.get("value",""))}</td>'
            f'<td>{badge}</td><td>{_esc(i.get("confidence",""))}</td>'
            f'<td>{_esc(i.get("context",""))}</td></tr>'
        )
    return (
        '<table class="grid"><thead><tr><th>Type</th><th>Value</th>'
        '<th>Verdict</th><th>Conf.</th><th>Context</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _render_timeline(tl: list) -> str:
    if not tl:
        return '<p class="empty">No timeline events reconstructed.</p>'
    items = []
    for ev in tl:
        items.append(
            f'<li><span class="ts mono">{_esc(ev.get("timestamp",""))}</span>'
            f'<div class="ev"><b>{_esc(ev.get("event",""))}</b>'
            f'<span class="src">{_esc(ev.get("source",""))}</span>'
            f'<p>{_esc(ev.get("significance",""))}</p></div></li>'
        )
    return f'<ul class="timeline">{"".join(items)}</ul>'


def _render_recs(recs: list) -> str:
    if not recs:
        return ""
    items = "".join(f"<li>{_esc(r)}</li>" for r in recs)
    return f'<section class="block"><h2>Recommended actions</h2><ol class="recs">{items}</ol></section>'


def _render_gaps(gaps: list) -> str:
    if not gaps:
        return ""
    items = []
    for g in gaps:
        q = g.get("question", g) if isinstance(g, dict) else g
        pri = g.get("priority", "") if isinstance(g, dict) else ""
        items.append(f'<li><span class="pri {(_esc(pri) or "med").lower()}">{_esc(pri)}</span>{_esc(q)}</li>')
    return f'<section class="block"><h2>Open questions</h2><ul class="gaps">{"".join(items)}</ul></section>'


# ── template ────────────────────────────────────────────────────────────────
# One file, no external requests. CSS variables keyed off severity so the whole
# document re-tints from the headline severity.
_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{report_id} — {title}</title>
<style>
  :root {{
    --bg:#0d1117; --panel:#161b22; --panel2:#1c2230; --line:#2a3140;
    --ink:#e6edf3; --ink-dim:#8b97a7; --accent:{sev_color};
    --mono:'SF Mono',ui-monospace,'Cascadia Code','Roboto Mono',Menlo,monospace;
    --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font-family:var(--sans); line-height:1.55; font-size:15px; }}
  a {{ color:var(--accent); }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:0 24px 80px; }}

  /* header: severity is the thesis — a thick rule in the headline hue */
  header.top {{ border-top:5px solid var(--accent); background:var(--panel);
    padding:32px 24px; margin-bottom:8px; }}
  header.top .inner {{ max-width:1100px; margin:0 auto; }}
  .eyebrow {{ font-family:var(--mono); font-size:12px; letter-spacing:.14em;
    text-transform:uppercase; color:var(--ink-dim); }}
  h1 {{ font-size:30px; margin:6px 0 14px; font-weight:650; letter-spacing:-.01em; }}
  .sev-tag {{ display:inline-block; font-family:var(--mono); font-weight:700;
    font-size:13px; letter-spacing:.08em; color:#0d1117; background:var(--accent);
    padding:4px 12px; border-radius:4px; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:18px; margin-top:16px;
    font-size:13px; color:var(--ink-dim); font-family:var(--mono); }}
  .meta b {{ color:var(--ink); font-weight:600; }}

  /* layer toggle */
  .layers {{ display:flex; gap:4px; margin:24px 0 8px; background:var(--panel2);
    padding:4px; border-radius:8px; width:fit-content; }}
  .layers button {{ font-family:var(--sans); font-size:14px; font-weight:550;
    color:var(--ink-dim); background:transparent; border:0; padding:8px 18px;
    border-radius:6px; cursor:pointer; }}
  .layers button.on {{ background:var(--accent); color:#0d1117; }}

  section.block {{ background:var(--panel); border:1px solid var(--line);
    border-radius:10px; padding:24px; margin:16px 0; }}
  h2 {{ font-size:13px; font-family:var(--mono); letter-spacing:.1em;
    text-transform:uppercase; color:var(--ink-dim); margin:0 0 16px;
    font-weight:600; }}
  .bottom-line {{ font-size:18px; line-height:1.5; font-weight:550; }}
  .summary {{ color:var(--ink); }}
  .conf-expl {{ color:var(--ink-dim); font-style:italic; font-size:14px;
    border-left:2px solid var(--line); padding-left:14px; margin-top:14px; }}

  /* metrics */
  .metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
    gap:1px; background:var(--line); border:1px solid var(--line);
    border-radius:10px; overflow:hidden; }}
  .metric {{ background:var(--panel); padding:18px 16px; text-align:center; }}
  .metric-v {{ font-size:28px; font-weight:700; font-family:var(--mono); }}
  .metric-l {{ font-size:11px; color:var(--ink-dim); text-transform:uppercase;
    letter-spacing:.08em; margin-top:4px; }}

  /* MITRE */
  .tactic-row {{ display:flex; flex-wrap:wrap; gap:8px; margin-bottom:16px; }}
  .tactic {{ flex:1; min-width:130px; background:var(--panel2);
    border:1px solid var(--line); border-radius:8px; padding:12px; }}
  .tactic-h {{ font-size:13px; font-weight:600; display:flex;
    justify-content:space-between; align-items:center; }}
  .tactic-n {{ font-family:var(--mono); color:var(--accent); font-size:13px; }}
  .chips {{ display:flex; flex-wrap:wrap; gap:6px; }}
  .chip {{ font-size:12px; background:var(--panel2); border:1px solid var(--line);
    border-radius:20px; padding:4px 12px; font-family:var(--mono); }}
  .chip b {{ color:var(--accent); }}
  .chip i {{ color:var(--ink-dim); font-style:normal; margin-left:6px; }}

  /* findings */
  .filters {{ display:flex; flex-wrap:wrap; gap:8px; align-items:center;
    margin-bottom:16px; }}
  .filters input {{ flex:1; min-width:200px; background:var(--bg);
    border:1px solid var(--line); border-radius:8px; color:var(--ink);
    padding:9px 12px; font-family:var(--mono); font-size:13px; }}
  .fbtn {{ font-family:var(--mono); font-size:12px; padding:6px 12px;
    border-radius:20px; border:1px solid var(--line); background:var(--panel2);
    color:var(--ink-dim); cursor:pointer; }}
  .fbtn.on {{ color:#0d1117; font-weight:700; }}
  .finding {{ border:1px solid var(--line); border-left:3px solid var(--sev);
    border-radius:8px; padding:14px 16px; margin-bottom:8px; background:var(--panel2); }}
  .finding-h {{ display:flex; gap:10px; align-items:baseline; }}
  .fid {{ font-family:var(--mono); font-size:12px; color:var(--ink-dim); }}
  .ftitle {{ font-weight:600; flex:1; }}
  .fsev {{ font-family:var(--mono); font-size:11px; font-weight:700;
    text-transform:uppercase; color:var(--sev); }}
  .fmeta {{ font-family:var(--mono); font-size:12px; color:var(--ink-dim);
    margin-top:6px; display:flex; gap:14px; flex-wrap:wrap; }}
  .fdesc {{ font-size:13px; color:var(--ink); margin-top:8px; }}
  /* why-it-matters: a quiet callout that explains the "so what" */
  .fwhy {{ font-size:13px; color:var(--ink); margin-top:10px;
    padding:8px 12px; border-radius:6px; background:var(--panel);
    border-left:2px solid var(--sev); line-height:1.5; }}
  .fwhy-l {{ display:block; font-family:var(--mono); font-size:10px;
    text-transform:uppercase; letter-spacing:.06em; color:var(--ink-dim);
    margin-bottom:3px; }}
  /* evidence as a definition list: label left, value right, aligned */
  .fev {{ margin:10px 0 0; display:grid; grid-template-columns:max-content 1fr;
    gap:4px 14px; font-size:12.5px; }}
  .fev dt {{ font-family:var(--mono); font-size:11px; color:var(--ink-dim);
    text-transform:uppercase; letter-spacing:.04em; }}
  .fev dd {{ margin:0; font-family:var(--mono); color:var(--accent);
    word-break:break-all; }}
  /* raw bytes behind a toggle */
  .fraw {{ margin-top:8px; }}
  .fraw-t {{ font-family:var(--mono); font-size:11px; cursor:pointer;
    background:none; border:none; color:var(--ink-dim); padding:2px 0; }}
  .fraw-t:hover {{ color:var(--ink); }}
  .fraw-b {{ display:none; margin:6px 0 0; padding:10px; border-radius:6px;
    background:var(--bg); border:1px solid var(--line); font-family:var(--mono);
    font-size:11px; color:var(--ink-dim); white-space:pre-wrap;
    word-break:break-all; max-height:200px; overflow:auto; }}
  .fraw-b.open {{ display:block; }}

  /* tables / timeline / lists */
  table.grid {{ width:100%; border-collapse:collapse; font-size:13px; }}
  .grid th {{ text-align:left; font-family:var(--mono); font-size:11px;
    text-transform:uppercase; letter-spacing:.06em; color:var(--ink-dim);
    border-bottom:1px solid var(--line); padding:8px 10px; }}
  .grid td {{ border-bottom:1px solid var(--line); padding:9px 10px;
    vertical-align:top; }}
  .mono {{ font-family:var(--mono); }}
  .val {{ color:var(--accent); word-break:break-all; }}
  .mal {{ font-family:var(--mono); font-size:11px; padding:2px 8px;
    border-radius:4px; font-weight:700; }}
  .mal.yes {{ background:rgba(255,77,77,.15); color:#ff4d4d; }}
  .mal.no {{ background:rgba(122,134,153,.15); color:var(--ink-dim); }}
  .timeline {{ list-style:none; margin:0; padding:0; }}
  .timeline li {{ display:flex; gap:16px; padding:10px 0;
    border-bottom:1px solid var(--line); }}
  .ts {{ font-size:12px; color:var(--accent); white-space:nowrap; min-width:160px; }}
  .ev b {{ display:block; }}
  .ev .src {{ font-family:var(--mono); font-size:11px; color:var(--ink-dim); }}
  .ev p {{ margin:4px 0 0; font-size:13px; color:var(--ink-dim); }}
  ol.recs li, ul.gaps li {{ margin-bottom:10px; }}
  ul.gaps {{ list-style:none; padding:0; }}
  .pri {{ font-family:var(--mono); font-size:10px; text-transform:uppercase;
    padding:2px 7px; border-radius:4px; margin-right:10px; background:var(--panel2);
    color:var(--ink-dim); }}
  .pri.high {{ background:rgba(255,77,77,.15); color:#ff4d4d; }}
  .empty {{ color:var(--ink-dim); font-style:italic; }}
  .layer {{ display:none; }}
  .layer.on {{ display:block; }}
  footer {{ text-align:center; color:var(--ink-dim); font-family:var(--mono);
    font-size:12px; padding:30px; }}
  @media print {{ .layers,.filters {{ display:none; }} .layer {{ display:block !important; }} body {{ background:#fff; color:#000; }} }}
</style></head>
<body>
<header class="top"><div class="inner">
  <div class="eyebrow">{report_id} · Incident Response Report</div>
  <h1>{title}</h1>
  <span class="sev-tag">{sev_label}</span>
  <span style="color:var(--ink-dim);font-size:13px;margin-left:10px;">{sev_desc}</span>
  <div class="meta">
    <span><b>Status</b> {status}</span>
    <span><b>Analyzed by</b> {analyzed_by}</span>
    <span><b>Confidence</b> {confidence}</span>
    <span><b>Engine</b> {engine}</span>
    <span><b>Generated</b> {generated}</span>
  </div>
</div></header>

<div class="wrap">
  <div class="layers">
    <button class="on" onclick="setLayer('exec',this)">Executive</button>
    <button onclick="setLayer('tech',this)">Technical</button>
  </div>

  <!-- EXECUTIVE LAYER -->
  <div class="layer on" id="layer-exec">
    <section class="block">
      <h2>Bottom line</h2>
      <p class="bottom-line">{bottom_line}</p>
      <p class="summary">{summary}</p>
      <p class="conf-expl">{confidence_expl}</p>
    </section>
    <section class="block"><h2>At a glance</h2><div class="metrics">{metrics_html}</div></section>
    {narrative_html}
    <section class="block"><h2>MITRE ATT&CK coverage</h2>{mitre_html}</section>
    {recs_html}
    {gaps_html}
  </div>

  <!-- TECHNICAL LAYER -->
  <div class="layer" id="layer-tech">
    <section class="block">
      <h2>Findings ({finding_count})</h2>
      <div class="filters">
        <input id="q" placeholder="filter by text, id, category, MITRE…" oninput="renderFindings()">
        <button class="fbtn on" data-sev="all" onclick="toggleSev(this)">all</button>
        <button class="fbtn" data-sev="critical" onclick="toggleSev(this)">critical</button>
        <button class="fbtn" data-sev="high" onclick="toggleSev(this)">high</button>
        <button class="fbtn" data-sev="medium" onclick="toggleSev(this)">medium</button>
        <button class="fbtn" data-sev="low" onclick="toggleSev(this)">low</button>
        <button class="fbtn" data-sev="info" onclick="toggleSev(this)">info</button>
      </div>
      <div id="findings"></div>
    </section>
    <section class="block"><h2>Indicators of compromise</h2>{ioc_html}</section>
    <section class="block"><h2>Attack timeline</h2>{timeline_html}</section>
  </div>
</div>

<footer>Generated by IR Platform · {report_id}</footer>

<script>
  const SEV = {sev_colors_json};
  const FINDINGS = {findings_json};
  let activeSev = "all";

  function setLayer(which, btn) {{
    document.querySelectorAll('.layers button').forEach(b=>b.classList.remove('on'));
    btn.classList.add('on');
    document.getElementById('layer-exec').classList.toggle('on', which==='exec');
    document.getElementById('layer-tech').classList.toggle('on', which==='tech');
    if (which==='tech') renderFindings();
  }}
  function toggleSev(btn) {{
    document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('on'));
    btn.classList.add('on');
    activeSev = btn.dataset.sev;
    renderFindings();
  }}
  function renderFindings() {{
    const q = (document.getElementById('q').value||'').toLowerCase();
    const host = document.getElementById('findings');
    const rows = FINDINGS.filter(f => {{
      if (activeSev!=='all' && f.severity!==activeSev) return false;
      if (!q) return true;
      return (f.id+' '+f.title+' '+f.category+' '+f.mitre+' '+f.description).toLowerCase().includes(q);
    }});
    if (!rows.length) {{ host.innerHTML = '<p class="empty">No findings match this filter.</p>'; return; }}
    host.innerHTML = rows.map((f, i) => {{
      const c = SEV[f.severity] || SEV.info;
      const occ = f.occurrences>1 ? `×${{f.occurrences}}` : '';
      const mitre = f.mitre ? `<span>MITRE ${{f.mitre}}</span>` : '';
      const why = f.why ? `<div class="fwhy"><span class="fwhy-l">Why it matters</span>${{f.why}}</div>` : '';
      // Evidence: normal fields inline, raw/binary behind a toggle.
      const ev = f.evidence || [];
      const normal = ev.filter(e => !e.raw);
      const raw = ev.filter(e => e.raw);
      let evHtml = '';
      if (normal.length) {{
        evHtml += '<dl class="fev">' + normal.map(e =>
          `<dt>${{e.label}}</dt><dd>${{e.value}}</dd>`).join('') + '</dl>';
      }}
      if (raw.length) {{
        const rid = 'raw'+i;
        evHtml += raw.map(e =>
          `<div class="fraw">
             <button class="fraw-t" onclick="document.getElementById('${{rid}}').classList.toggle('open')">
               ▸ ${{e.label}} (raw bytes)
             </button>
             <pre id="${{rid}}" class="fraw-b">${{e.value}}</pre>
           </div>`).join('');
      }}
      return `<div class="finding" style="--sev:${{c}}">
        <div class="finding-h">
          <span class="fid">${{f.id}}</span>
          <span class="ftitle">${{f.title}}</span>
          <span class="fsev" style="--sev:${{c}}">${{f.severity}}</span>
        </div>
        <div class="fmeta"><span>${{f.category}}</span>${{mitre}}<span>${{occ}}</span><span>score ${{f.score}}</span></div>
        ${{why}}
        <div class="fdesc">${{f.description||''}}</div>
        ${{evHtml}}
      </div>`;
    }}).join('');
  }}
</script>
</body></html>"""
