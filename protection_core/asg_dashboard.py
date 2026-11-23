#!/usr/bin/env python3
"""
ASG local dashboard — one self-contained HTML page summarising every scan.

    python asg_dashboard.py            # writes ~/.asg-security-guardian/dashboard.html
    python asg_dashboard.py --open     # ...and opens it in the default browser

Built from the JSON reports in <state>/reports. No network, no external assets, no
JavaScript data injection: every value coming from a scanned target (paths, evidence)
is HTML-escaped on the server side, because that text is untrusted.
Home-directory prefixes are shown as "~" so screenshots do not leak user names.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import webbrowser
from datetime import datetime
from pathlib import Path

STATE = Path(os.environ.get("ASG_STATE", str(Path.home() / ".asg-security-guardian"))).expanduser()
STRONG_IDS = {"SECRET", "AI001", "AI002", "PIPE001", "PS001", "PS002", "CRED001", "PERS001", "ARCHIVE001"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "INCONCLUSIVE": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
MAX_SCANS = 300
MAX_FINDINGS_SHOWN = 40

TEXT = {
    "pt": {
        "title": "ASG Security Guardian", "subtitle": "Análises automáticas do que o seu agente baixou",
        "scans": "Análises", "review": "Revisar antes de usar", "attention": "Com indicadores",
        "clean": "Sem indicadores", "inconclusive": "Inconclusivas", "search": "Filtrar por nome, origem ou regra…",
        "all": "Todas", "when": "Quando", "what": "Alvo", "verdict": "Veredito", "counts": "Achados",
        "v_review": "REVISAR", "v_inconclusive": "INCONCLUSIVO", "v_attention": "INDICADORES", "v_clean": "SEM INDICADORES",
        "files": "arquivos", "report": "Relatório completo (Markdown)", "none": "Nenhuma análise ainda. Clone um repositório com o Claude Code ou o Codex e ela aparece aqui.",
        "note": "Triagem heurística e estática. Um achado não prova malware; um resultado limpo não garante segurança.",
        "more": "achados adicionais no relatório", "generated": "Gerado em",
        "src": "Origem", "trigger_hook": "automática", "trigger_manual": "manual",
    },
    "en": {
        "title": "ASG Security Guardian", "subtitle": "Automatic scans of what your agent downloaded",
        "scans": "Scans", "review": "Review before use", "attention": "With indicators",
        "clean": "No indicators", "inconclusive": "Inconclusive", "search": "Filter by name, source or rule…",
        "all": "All", "when": "When", "what": "Target", "verdict": "Verdict", "counts": "Findings",
        "v_review": "REVIEW", "v_inconclusive": "INCONCLUSIVE", "v_attention": "INDICATORS", "v_clean": "NO INDICATORS",
        "files": "files", "report": "Full report (Markdown)", "none": "No scans yet. Clone a repository with Claude Code or Codex and it shows up here.",
        "note": "Static heuristic triage. A finding is not proof of malware; a clean result is not a safety guarantee.",
        "more": "more findings in the report", "generated": "Generated",
        "src": "Source", "trigger_hook": "automatic", "trigger_manual": "manual",
    },
}


def _lang(state: Path) -> str:
    try:
        value = json.loads((state / "config.json").read_text(encoding="utf-8")).get("lang", "pt")
    except Exception:
        value = "pt"
    return value if value in TEXT else "en"


def _tilde(p: str) -> str:
    home = str(Path.home())
    for variant in (home, home.replace("\\", "/")):
        if p.lower().startswith(variant.lower()):
            return "~" + p[len(variant):]
    return p


def verdict(report: dict) -> str:
    counts = report.get("counts", {})
    findings = report.get("findings", [])
    if counts.get("INCONCLUSIVE"):
        return "inconclusive"
    if any(f["id"] in STRONG_IDS and f["severity"] in {"CRITICAL", "HIGH"} for f in findings):
        return "review"
    if any(f["severity"] not in {"INFO", "LOW"} for f in findings):
        return "attention"
    return "clean"


def load_reports(state: Path) -> list[dict]:
    out = []
    files = sorted((state / "reports").glob("asg-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for jp in files[:MAX_SCANS]:
        try:
            r = json.loads(jp.read_text(encoding="utf-8"))
        except Exception:
            continue
        r["_json"] = str(jp)
        r["_md"] = str(jp.with_suffix(".md"))
        out.append(r)
    return out


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b1f24;--muted:#5b6470;--line:#e3e6ea;--accent:#2f6feb;
--crit:#b42318;--crit-bg:#fdecea;--high:#c4320a;--high-bg:#fff1e7;--med:#8a6100;--med-bg:#fff8e1;
--ok:#1a7f37;--ok-bg:#e8f5ec;--inc:#6941c6;--inc-bg:#f1ecfd;--chip:#eef1f4}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--ink:#e6e9ee;--muted:#9aa4b2;--line:#2a313a;
--accent:#6ea8ff;--crit:#ff8a80;--crit-bg:#3a1714;--high:#ffab70;--high-bg:#3a2210;--med:#f2cc60;--med-bg:#332a0e;
--ok:#6fdd8b;--ok-bg:#12301c;--inc:#b69cff;--inc-bg:#261c43;--chip:#222831}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:28px 16px 48px}
header{display:flex;align-items:center;gap:14px;margin-bottom:6px}
.logo{width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,#2f6feb,#7c3aed);display:grid;place-items:center;color:#fff;font-weight:700}
h1{font-size:22px;margin:0}.sub{color:var(--muted);margin:0 0 20px}
.kpis{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:18px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.kpi b{display:block;font-size:26px;line-height:1.1}.kpi span{color:var(--muted);font-size:12px}
.kpi.review b{color:var(--crit)}.kpi.attention b{color:var(--med)}.kpi.clean b{color:var(--ok)}.kpi.inconclusive b{color:var(--inc)}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.bar input{flex:1;min-width:220px;padding:9px 12px;border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--ink)}
.bar button{padding:8px 12px;border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer}
.bar button.on{border-color:var(--accent);color:var(--accent);font-weight:600}
.scan{background:var(--card);border:1px solid var(--line);border-radius:12px;margin-bottom:10px;overflow:hidden}
.scan summary{list-style:none;display:grid;grid-template-columns:150px 1fr 150px 230px;gap:12px;align-items:center;padding:12px 16px;cursor:pointer}
.scan summary::-webkit-details-marker{display:none}
.when{color:var(--muted);font-size:12px}.what b{display:block;word-break:break-all}.what small{color:var(--muted);word-break:break-all}
.badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.02em}
.b-review{background:var(--crit-bg);color:var(--crit)}.b-attention{background:var(--med-bg);color:var(--med)}
.b-clean{background:var(--ok-bg);color:var(--ok)}.b-inconclusive{background:var(--inc-bg);color:var(--inc)}
.chips{display:flex;gap:6px;flex-wrap:wrap}.chip{background:var(--chip);border-radius:6px;padding:2px 7px;font-size:12px}
.chip.c{color:var(--crit)}.chip.h{color:var(--high)}.chip.m{color:var(--med)}.chip.i{color:var(--inc)}
.body{border-top:1px solid var(--line);padding:10px 16px 14px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px}td code{font:12px/1.4 ui-monospace,Consolas,monospace;word-break:break-all}
.sev{font-weight:700;font-size:11px}.s-CRITICAL{color:var(--crit)}.s-HIGH{color:var(--high)}.s-MEDIUM{color:var(--med)}.s-INCONCLUSIVE{color:var(--inc)}.s-LOW,.s-INFO{color:var(--muted)}
.links{margin-top:10px;font-size:12px}.links a{color:var(--accent)}
.empty{background:var(--card);border:1px dashed var(--line);border-radius:12px;padding:32px;text-align:center;color:var(--muted)}
footer{margin-top:22px;color:var(--muted);font-size:12px}
@media (max-width:760px){.kpis{grid-template-columns:repeat(2,1fr)}.scan summary{grid-template-columns:1fr}.when{order:3}}
"""

JS = """
const q=document.getElementById('q');let mode='all';
function apply(){const t=q.value.toLowerCase();document.querySelectorAll('.scan').forEach(e=>{
const okMode=mode==='all'||e.dataset.v===mode;const okText=!t||e.dataset.s.includes(t);e.style.display=okMode&&okText?'':'none'})}
q.addEventListener('input',apply);
document.querySelectorAll('.bar button').forEach(b=>b.addEventListener('click',()=>{
document.querySelectorAll('.bar button').forEach(x=>x.classList.remove('on'));b.classList.add('on');mode=b.dataset.m;apply()}));
"""


def render(reports: list[dict], lang: str) -> str:
    T = TEXT[lang]
    e = html.escape
    verdicts = [verdict(r) for r in reports]
    count = {k: verdicts.count(k) for k in ("review", "attention", "clean", "inconclusive")}
    parts = [f"<!doctype html><html lang='{'pt-BR' if lang == 'pt' else 'en'}'><head><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width,initial-scale=1'>",
             "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'\">",
             f"<title>ASG Dashboard</title><style>{CSS}</style></head><body><div class='wrap'>",
             f"<header><div class='logo'>A</div><div><h1>{T['title']}</h1></div></header><p class='sub'>{T['subtitle']}</p>",
             "<div class='kpis'>",
             f"<div class='kpi'><b>{len(reports)}</b><span>{T['scans']}</span></div>",
             f"<div class='kpi review'><b>{count['review']}</b><span>{T['review']}</span></div>",
             f"<div class='kpi attention'><b>{count['attention']}</b><span>{T['attention']}</span></div>",
             f"<div class='kpi clean'><b>{count['clean']}</b><span>{T['clean']}</span></div>",
             f"<div class='kpi inconclusive'><b>{count['inconclusive']}</b><span>{T['inconclusive']}</span></div></div>",
             f"<div class='bar'><input id='q' placeholder='{e(T['search'])}'>",
             f"<button class='on' data-m='all'>{T['all']}</button><button data-m='review'>{T['review']}</button>",
             f"<button data-m='attention'>{T['attention']}</button><button data-m='clean'>{T['clean']}</button></div>"]
    if not reports:
        parts.append(f"<div class='empty'>{T['none']}</div>")
    vlabel = {"review": T["v_review"], "attention": T["v_attention"], "clean": T["v_clean"], "inconclusive": T["v_inconclusive"]}
    for r, v in zip(reports, verdicts):
        counts = r.get("counts", {})
        when = r.get("created_at", "")[:19].replace("T", " ")
        target = _tilde(r.get("target", ""))
        name = Path(target.replace("\\", "/")).name or target
        source = r.get("source") or ""
        trig = T["trigger_hook"] if str(r.get("trigger", "")).endswith("hook") else T["trigger_manual"]
        findings = sorted(r.get("findings", []), key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["id"]))
        search = " ".join([name, target, source] + sorted({f["id"] for f in findings})).lower()
        chips = "".join(f"<span class='chip {cls}'>{k} {counts.get(k, 0)}</span>"
                        for k, cls in (("CRITICAL", "c"), ("HIGH", "h"), ("MEDIUM", "m"), ("INCONCLUSIVE", "i")) if counts.get(k))
        chips = chips or f"<span class='chip'>0</span>"
        parts.append(f"<details class='scan' data-v='{v}' data-s='{e(search)}'><summary>"
                     f"<div class='when'>{e(when)} UTC<br>{e(trig)}</div>"
                     f"<div class='what'><b>{e(name)}</b><small>{e(source or target)}</small></div>"
                     f"<div><span class='badge b-{v}'>{vlabel[v]}</span><div class='when'>{r.get('files_inventoried', 0)} {T['files']}</div></div>"
                     f"<div class='chips'>{chips}</div></summary><div class='body'>")
        shown = [f for f in findings if f["severity"] != "INFO"][:MAX_FINDINGS_SHOWN]
        if shown:
            parts.append("<table><tr><th>Sev</th><th>ID</th><th>Regra</th><th>Local</th><th>Evidência</th></tr>" if lang == "pt"
                         else "<table><tr><th>Sev</th><th>ID</th><th>Rule</th><th>Location</th><th>Evidence</th></tr>")
            for f in shown:
                loc = f"{f['path']}:{f['line']}" if f.get("line") else f["path"]
                parts.append(f"<tr><td class='sev s-{e(f['severity'])}'>{e(f['severity'])}</td><td>{e(f['id'])}</td>"
                             f"<td>{e(f['title'])}</td><td><code>{e(_tilde(loc))}</code></td><td><code>{e(str(f.get('evidence', ''))[:160])}</code></td></tr>")
            parts.append("</table>")
            extra = len([f for f in findings if f["severity"] != "INFO"]) - len(shown)
            if extra > 0:
                parts.append(f"<p class='when'>+{extra} {T['more']}</p>")
        md = Path(r["_md"])
        parts.append(f"<div class='links'><a href='{e(md.as_uri())}'>{T['report']}</a> · <code>{e(_tilde(str(md)))}</code></div></div></details>")
    parts.append(f"<footer>{T['note']}<br>{T['generated']} {datetime.now().strftime('%Y-%m-%d %H:%M')}</footer>")
    parts.append(f"</div><script>{JS}</script></body></html>")
    return "".join(parts)


def build(state: Path = STATE) -> Path:
    state.mkdir(parents=True, exist_ok=True)
    out = state / "dashboard.html"
    out.write_text(render(load_reports(state), _lang(state)), encoding="utf-8")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the ASG local dashboard")
    ap.add_argument("--state", default=str(STATE))
    ap.add_argument("--open", action="store_true", help="open in the default browser")
    args = ap.parse_args()
    out = build(Path(args.state).expanduser())
    print(f"Dashboard: {out}")
    if args.open:
        webbrowser.open(out.as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
