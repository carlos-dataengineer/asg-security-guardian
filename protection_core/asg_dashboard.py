#!/usr/bin/env python3
"""
ASG local dashboard — one self-contained HTML page with two tabs:
  * Scans:   every static scan (automatic or manual) with verdict and findings;
  * Actions: the audit ledger as a timeline — installs blocked or confirmed, installs that ran
             after confirmation, automatic scans, quarantine proposals/copies, integrity checks —
             plus the hash-chain status of the ledger.

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
import importlib.util
import json
import os
import re
import webbrowser
from datetime import datetime
from pathlib import Path

STATE = Path(os.environ.get("ASG_STATE", str(Path.home() / ".asg-security-guardian"))).expanduser()
STRONG_IDS = {"SECRET", "AI001", "AI002", "PIPE001", "PS001", "PS002", "CRED001", "PERS001", "ARCHIVE001"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "INCONCLUSIVE": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
MAX_SCANS = 300
MAX_FINDINGS_SHOWN = 40
MAX_EVENTS = 500

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
        "tab_scans": "Análises", "tab_actions": "Ações", "a_blocked": "Instalações bloqueadas",
        "a_asked": "Confirmações pedidas", "a_ran": "Executadas após confirmação", "a_review": "Marcadas para revisão",
        "a_quarantine": "Cópias para quarentena", "a_integrity": "Alterações de integridade",
        "chain_ok": "Auditoria íntegra", "chain_bad": "AUDITORIA ALTERADA", "events": "eventos", "forks": "gravação(ões) simultânea(s), sem perda",
        "a_search": "Filtrar por comando, pasta ou tipo…", "a_none": "Nenhuma ação registrada ainda.",
        "f_block": "Bloqueios", "f_ask": "Confirmações", "f_scan": "Análises", "f_quarantine": "Quarentena", "f_integrity": "Integridade",
        "e_deny": "Instalação bloqueada", "e_ask": "Confirmação solicitada ao usuário", "e_ran": "Instalação executada após confirmação",
        "e_scan": "Análise automática", "e_mscan": "Análise manual", "e_baseline": "Baseline criado", "e_check": "Verificação de integridade",
        "e_proposed": "Quarentena proposta", "e_executed": "Cópia para quarentena executada",
        "e_denied": "Aprovação negada ou cancelada", "e_expired": "Proposta expirada", "e_stale": "Proposta rejeitada: alvo alterado",
        "changes": "alteração(ões)", "files_n": "arquivos", "actions_note": "Registro local encadeado por hashes (audit.jsonl). Comandos com credenciais são gravados já redigidos.",
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
        "tab_scans": "Scans", "tab_actions": "Actions", "a_blocked": "Installs blocked",
        "a_asked": "Confirmations asked", "a_ran": "Ran after confirmation", "a_review": "Flagged for review",
        "a_quarantine": "Quarantine copies", "a_integrity": "Integrity changes",
        "chain_ok": "Audit ledger intact", "chain_bad": "AUDIT LEDGER ALTERED", "events": "events", "forks": "simultaneous write(s), nothing lost",
        "a_search": "Filter by command, folder or type…", "a_none": "No actions recorded yet.",
        "f_block": "Blocks", "f_ask": "Confirmations", "f_scan": "Scans", "f_quarantine": "Quarantine", "f_integrity": "Integrity",
        "e_deny": "Install blocked", "e_ask": "Confirmation requested from the user", "e_ran": "Install ran after confirmation",
        "e_scan": "Automatic scan", "e_mscan": "Manual scan", "e_baseline": "Baseline created", "e_check": "Integrity check",
        "e_proposed": "Quarantine proposed", "e_executed": "Quarantine copy executed",
        "e_denied": "Approval denied or cancelled", "e_expired": "Proposal expired", "e_stale": "Proposal rejected: target changed",
        "changes": "changes", "files_n": "files", "actions_note": "Local hash-chained ledger (audit.jsonl). Commands containing credentials are stored redacted.",
    },
}


def _lang(state: Path) -> str:
    try:
        value = json.loads((state / "config.json").read_text(encoding="utf-8")).get("lang", "pt")
    except Exception:
        value = "pt"
    return value if value in TEXT else "en"


def _tilde(text: str) -> str:
    """Show the home folder (short or long Windows form, any slash) as ~."""
    home = Path.home()
    variants = set()
    forms = [str(home), str(home.resolve())]
    if os.name == "nt":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(1024)
            if ctypes.windll.kernel32.GetShortPathNameW(str(home), buf, 1024):
                forms.append(buf.value)
        except Exception:
            pass
    for h in forms:
        variants.update({h, h.replace("\\", "/")})
    for v in sorted(variants, key=len, reverse=True):
        text = re.sub(re.escape(v), "~", text, flags=re.IGNORECASE)
    return text


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
.tabs{display:flex;gap:6px;border-bottom:1px solid var(--line);margin:4px 0 18px}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;padding:10px 14px;color:var(--muted);font-size:14px;cursor:pointer}
.tabs button.on{color:var(--ink);border-color:var(--accent);font-weight:600}
.tab{display:none}.tab.on{display:block}
.chain{display:inline-block;margin:-6px 0 14px;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:600}
.chain.ok{background:var(--ok-bg);color:var(--ok)}.chain.bad{background:var(--crit-bg);color:var(--crit)}
.kpis.six{grid-template-columns:repeat(6,minmax(0,1fr))}
.kpi.block b{color:var(--crit)}.kpi.ask b{color:var(--high)}.kpi.ran b{color:var(--med)}.kpi.quar b{color:var(--accent)}
.ev{display:grid;grid-template-columns:150px 210px 1fr;gap:12px;align-items:start;background:var(--card);border:1px solid var(--line);
border-left:4px solid var(--line);border-radius:10px;padding:10px 14px;margin-bottom:8px}
.ev.k-crit{border-left-color:var(--crit)}.ev.k-high{border-left-color:var(--high)}.ev.k-med{border-left-color:var(--med)}
.ev.k-ok{border-left-color:var(--ok)}.ev.k-inc{border-left-color:var(--inc)}.ev.k-acc{border-left-color:var(--accent)}
.ev b{font-size:13px}.ev .det{font-size:13px;word-break:break-word}.ev .det code{font:12px/1.4 ui-monospace,Consolas,monospace;background:var(--chip);padding:1px 5px;border-radius:5px}
.tag{display:inline-block;font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:6px;padding:0 6px;margin-left:6px}
@media (max-width:760px){.kpis.six{grid-template-columns:repeat(2,1fr)}.ev{grid-template-columns:1fr}}
@media (max-width:760px){.kpis{grid-template-columns:repeat(2,1fr)}.scan summary{grid-template-columns:1fr}.when{order:3}}
"""

JS = """
function filt(barId,inputId,sel,attr){const q=document.getElementById(inputId);let mode='all';
function apply(){const t=q.value.toLowerCase();document.querySelectorAll(sel).forEach(e=>{
const okMode=mode==='all'||e.dataset[attr]===mode;const okText=!t||e.dataset.s.includes(t);e.style.display=okMode&&okText?'':'none'})}
q.addEventListener('input',apply);
document.querySelectorAll('#'+barId+' button').forEach(b=>b.addEventListener('click',()=>{
document.querySelectorAll('#'+barId+' button').forEach(x=>x.classList.remove('on'));b.classList.add('on');mode=b.dataset.m;apply()}))}
filt('sbar','q','.scan','v');filt('abar','qa','.ev','c');
function show(id){document.querySelectorAll('.tabs button').forEach(b=>b.classList.toggle('on',b.dataset.t===id));
document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('on',t.id===id));try{location.hash=id}catch(e){}}
document.querySelectorAll('.tabs button').forEach(b=>b.addEventListener('click',()=>show(b.dataset.t)));
if(location.hash==='#actions')show('actions');
"""


def load_events(state: Path) -> list[dict]:
    log = state / "audit.jsonl"
    if not log.exists():
        return []
    events = []
    for raw in log.read_text(encoding="utf-8", errors="replace").splitlines()[-MAX_EVENTS:]:
        try:
            events.append(json.loads(raw))
        except Exception:
            continue
    return list(reversed(events))


def chain_status(state: Path) -> dict | None:
    try:
        spec = importlib.util.spec_from_file_location("asg_local_dash", Path(__file__).with_name("asg_local.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.verify_audit(state)
    except Exception:
        return None


def describe(ev: dict, T: dict) -> tuple[str, str, str, str]:
    """(category, colour key, title, detail html) for one audit event. All values escaped here."""
    e = html.escape
    kind = ev.get("type", "")
    client = ev.get("client")
    tag = f"<span class='tag'>{e(str(client))}</span>" if client else ""
    if kind == "install_gate":
        deny = ev.get("decision") == "deny"
        return ("block" if deny else "ask", "crit" if deny else "high", (T["e_deny"] if deny else T["e_ask"]) + tag,
                f"{e(ev.get('what', ''))}<br><code>{e(ev.get('command', ''))}</code>")
    if kind == "install_ran":
        return ("ask", "med", T["e_ran"] + tag, f"{e(ev.get('what', ''))}<br><code>{e(ev.get('command', ''))}</code>")
    if kind in ("auto_scan", "manual_scan"):
        v = ev.get("verdict") or "attention"
        colour = {"review": "crit", "inconclusive": "inc", "attention": "med", "clean": "ok"}.get(v, "med")
        counts = ev.get("counts", {})
        chips = " · ".join(f"{k} {counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "INCONCLUSIVE") if counts.get(k)) or "0"
        label = {"review": T["v_review"], "inconclusive": T["v_inconclusive"], "attention": T["v_attention"], "clean": T["v_clean"]}.get(v, v)
        name = T["e_scan"] if kind == "auto_scan" else T["e_mscan"]
        return ("scan", colour, f"{name} — {e(label)}" + tag,
                f"<code>{e(_tilde(str(ev.get('source', ''))))}</code> → <code>{e(_tilde(str(ev.get('target', ''))))}</code><br>{e(chips)}")
    if kind == "baseline_created":
        return ("integrity", "acc", T["e_baseline"], f"<code>{e(_tilde(str(ev.get('root', ''))))}</code> · {e(str(ev.get('file_count', 0)))} {T['files_n']}")
    if kind == "integrity_check":
        n = int(ev.get("changes", 0) or 0)
        return ("integrity", "med" if n else "ok", T["e_check"], f"<code>{e(_tilde(str(ev.get('root', ''))))}</code> · {n} {T['changes']}")
    if kind == "action_proposed":
        return ("quarantine", "acc", T["e_proposed"], f"ID <code>{e(str(ev.get('request_id', '')))}</code> · SHA-256 <code>{e(str(ev.get('source_sha256', ''))[:16])}…</code>")
    if kind == "action_executed":
        return ("quarantine", "acc", T["e_executed"], f"ID <code>{e(str(ev.get('request_id', '')))}</code> → <code>{e(_tilde(str(ev.get('destination', ''))))}</code>")
    labels = {"approval_denied_or_cancelled": T["e_denied"], "approval_expired": T["e_expired"], "approval_rejected_stale_target": T["e_stale"]}
    if kind in labels:
        return ("quarantine", "med", labels[kind], f"ID <code>{e(str(ev.get('request_id', '')))}</code>")
    return ("other", "", e(kind or "?"), "")


def render_actions(events: list[dict], chain: dict | None, T: dict) -> str:
    e = html.escape
    kinds = [(ev.get("type"), ev.get("decision"), ev.get("verdict"), int(ev.get("changes", 0) or 0)) for ev in events]
    k = {
        "block": sum(1 for t, d, _, _ in kinds if t == "install_gate" and d == "deny"),
        "ask": sum(1 for t, d, _, _ in kinds if t == "install_gate" and d == "ask"),
        "ran": sum(1 for t, *_ in kinds if t == "install_ran"),
        "review": sum(1 for t, _, v, _ in kinds if t in ("auto_scan", "manual_scan") and v in ("review", "inconclusive")),
        "quar": sum(1 for t, *_ in kinds if t == "action_executed"),
        "integ": sum(1 for t, _, _, c in kinds if t == "integrity_check" and c > 0),
    }
    out = []
    if chain is not None:
        cls, label = ("ok", T["chain_ok"]) if chain.get("valid") else ("bad", T["chain_bad"])
        forks = f" · {chain['forks']} {T['forks']}" if chain.get("valid") and chain.get("forks") else ""
        out.append(f"<div class='chain {cls}'>{'✔' if cls == 'ok' else '✖'} {label} · {chain.get('events', 0)} {T['events']}{forks}</div>")
    out.append("<div class='kpis six'>"
               f"<div class='kpi block'><b>{k['block']}</b><span>{T['a_blocked']}</span></div>"
               f"<div class='kpi ask'><b>{k['ask']}</b><span>{T['a_asked']}</span></div>"
               f"<div class='kpi ran'><b>{k['ran']}</b><span>{T['a_ran']}</span></div>"
               f"<div class='kpi review'><b>{k['review']}</b><span>{T['a_review']}</span></div>"
               f"<div class='kpi quar'><b>{k['quar']}</b><span>{T['a_quarantine']}</span></div>"
               f"<div class='kpi attention'><b>{k['integ']}</b><span>{T['a_integrity']}</span></div></div>")
    out.append(f"<div class='bar' id='abar'><input id='qa' placeholder='{e(T['a_search'])}'>"
               f"<button class='on' data-m='all'>{T['all']}</button><button data-m='block'>{T['f_block']}</button>"
               f"<button data-m='ask'>{T['f_ask']}</button><button data-m='scan'>{T['f_scan']}</button>"
               f"<button data-m='quarantine'>{T['f_quarantine']}</button><button data-m='integrity'>{T['f_integrity']}</button></div>")
    if not events:
        out.append(f"<div class='empty'>{T['a_none']}</div>")
    for ev in events:
        cat, colour, title, detail = describe(ev, T)
        when = str(ev.get("timestamp", ""))[:19].replace("T", " ")
        search = " ".join(str(ev.get(x, "")) for x in ("type", "what", "command", "source", "target", "root", "client", "verdict", "decision"))
        out.append(f"<div class='ev k-{colour}' data-c='{cat}' data-s='{e(_tilde(search).lower())}'>"
                   f"<div class='when'>{e(when)} UTC</div><div><b>{title}</b></div><div class='det'>{detail}</div></div>")
    out.append(f"<p class='when'>{T['actions_note']}</p>")
    return "".join(out)


def render(reports: list[dict], lang: str, events: list[dict] | None = None, chain: dict | None = None) -> str:
    T = TEXT[lang]
    e = html.escape
    verdicts = [verdict(r) for r in reports]
    count = {k: verdicts.count(k) for k in ("review", "attention", "clean", "inconclusive")}
    parts = [f"<!doctype html><html lang='{'pt-BR' if lang == 'pt' else 'en'}'><head><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width,initial-scale=1'>",
             "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'\">",
             f"<title>ASG Dashboard</title><style>{CSS}</style></head><body><div class='wrap'>",
             f"<header><div class='logo'>A</div><div><h1>{T['title']}</h1></div></header><p class='sub'>{T['subtitle']}</p>",
             f"<nav class='tabs'><button class='on' data-t='scans'>{T['tab_scans']} ({len(reports)})</button>"
             f"<button data-t='actions'>{T['tab_actions']} ({len(events or [])})</button></nav>",
             "<section class='tab on' id='scans'><div class='kpis'>",
             f"<div class='kpi'><b>{len(reports)}</b><span>{T['scans']}</span></div>",
             f"<div class='kpi review'><b>{count['review']}</b><span>{T['review']}</span></div>",
             f"<div class='kpi attention'><b>{count['attention']}</b><span>{T['attention']}</span></div>",
             f"<div class='kpi clean'><b>{count['clean']}</b><span>{T['clean']}</span></div>",
             f"<div class='kpi inconclusive'><b>{count['inconclusive']}</b><span>{T['inconclusive']}</span></div></div>",
             f"<div class='bar' id='sbar'><input id='q' placeholder='{e(T['search'])}'>",
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
    parts.append("</section><section class='tab' id='actions'>")
    parts.append(render_actions(events or [], chain, T))
    parts.append("</section>")
    parts.append(f"<footer>{T['note']}<br>{T['generated']} {datetime.now().strftime('%Y-%m-%d %H:%M')}</footer>")
    parts.append(f"</div><script>{JS}</script></body></html>")
    return "".join(parts)


def build(state: Path = STATE) -> Path:
    state.mkdir(parents=True, exist_ok=True)
    out = state / "dashboard.html"
    out.write_text(render(load_reports(state), _lang(state), load_events(state), chain_status(state)), encoding="utf-8")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the ASG local dashboard")
    ap.add_argument("--state", default=str(STATE))
    ap.add_argument("--open", action="store_true", help="open in the default browser")
    ap.add_argument("--actions", action="store_true", help="open directly on the Actions tab")
    args = ap.parse_args()
    out = build(Path(args.state).expanduser())
    print(f"Dashboard: {out}")
    if args.open or args.actions:
        webbrowser.open(out.as_uri() + ("#actions" if args.actions else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
