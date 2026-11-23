#!/usr/bin/env python3
"""
ASG Protection Core — read-only static triage MVP.
Cross-platform Python 3.10+. Does not execute target code or extract archives.
Heuristic findings are not malware verdicts.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, sys, time, zipfile, tarfile
from pathlib import Path
from datetime import datetime, timezone

VERSION = "0.4.0"
MAX_FILES_DEFAULT = 50000
MAX_FILE = 2 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_MEMBER = 10 * 1024 * 1024
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules"}
TEXT_EXTS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh",
    ".ps1", ".psm1", ".bat", ".cmd", ".php", ".rb", ".go", ".rs", ".java",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".yaml", ".yml", ".json", ".toml",
    ".ini", ".cfg", ".conf", ".xml", ".md", ".txt", ".html", ".htm", ".sql",
    ".dockerfile", ".tf", ".properties", ".gradle", ".lock", ".env.example"
}
SECRET_PATTERNS = [
    ("AWS access key-like value", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic token assignment", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("GitHub token-like value", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
]
RULES = [
    ("EXEC001", "HIGH", r"(?i)\b(?:eval|exec)\s*\(", "Dynamic code execution primitive"),
    ("PROC001", "MEDIUM", r"(?i)\b(?:subprocess\.(?:Popen|run|call)|os\.system|child_process\.exec|spawn)\s*\(", "Process or command execution primitive"),
    ("NET001", "MEDIUM", r"(?i)(?:\brequests\.(?:get|post|put)\b|\burllib\.request\b|\bfetch\s*\(|\baxios(?:\.(?:get|post))?\s*\(|\bhttps?\.(?:get|request)\s*\(|\brequire\(\s*['\"]https?['\"]\s*\)|\bcurl\b|\bwget\b|\bInvoke-WebRequest\b|\bNew-Object\s+Net\.WebClient\b)", "Network access or remote content retrieval"),
    ("PERS001", "HIGH", r"(?i)(?:RunOnce|CurrentVersion\\Run|systemctl\s+enable|crontab|LaunchAgents|LaunchDaemons)", "Possible persistence-related configuration or command"),
    ("PRIV001", "HIGH", r"(?i)(?:sudo\s+|runas\s+|chmod\s+[ugo]*s|setuid|privilege|administrator)", "Privilege-related operation or reference"),
    ("OBF001", "MEDIUM", r"(?i)(?:base64\.b64(?:de|en)code|frombase64string|tobase64string|atob\s*\(|btoa\s*\(|toString\(\s*['\"]base64['\"]\s*\)|(?:\\x[0-9a-f]{2}){4,})", "Encoding or obfuscation-related construct"),
    ("PIPE001", "HIGH", r"(?i)(?:curl|wget).{0,120}\|\s*(?:sh|bash)", "Remote content piped to a shell"),
    ("AI001", "HIGH", r"(?i)(?:\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|prompts)|\breveal\s+(?:your\s+|the\s+)?(?:system\s+prompt|hidden\s+instructions|secrets)|\bexfiltrate\s+(?:the\s+|all\s+|any\s+)?(?:data|secrets|credentials|tokens|files|keys)\s+to\b|\bsend\s+(?:the\s+|all\s+|any\s+|your\s+)?(?:credentials|secrets|tokens|api\s+keys|passwords|\.env)\s+to\b|\b(?:disable|turn\s+off|bypass)\s+(?:the\s+)?(?:antivirus|defender|security\s+(?:checks|hooks|controls|scanner)|permission\s+prompts))", "Instruction that may attempt prompt injection or unauthorized data handling"),
    ("CI001", "MEDIUM", r"(?i)(?:pull_request_target|permissions:\s*write-all|secrets\.[A-Z_]+)", "CI/CD permission or secret usage requiring review"),
    ("PS001", "HIGH", r"(?i)(?:\bInvoke-Expression\b|\biex\s*[\(\$]|-EncodedCommand\b|\s-enc\s+[A-Za-z0-9+/=]{20,}|DownloadString\s*\(|DownloadFile\s*\()", "PowerShell dynamic execution or download primitive"),
    ("PS002", "HIGH", r"(?i)(?:Set-MpPreference\s+-Disable|Add-MpPreference\s+-ExclusionPath|Set-ExecutionPolicy\s+(?:Bypass|Unrestricted))", "Security control weakening (Defender exclusion / execution policy bypass)"),
    ("CRED001", "HIGH", r"(?i)(?:\.ssh[/\\]id_|\.aws[/\\]credentials|Login Data|\\Cookies\b|\.claude[/\\]\.credentials|\.git-credentials|wallet\.dat)", "Reference to credential or browser secret store"),
    ("PKG001", "MEDIUM", r'(?i)"(?:preinstall|postinstall|install|prepare)"\s*:\s*"', "npm lifecycle script runs automatically on install"),
    ("PKG002", "MEDIUM", r"(?i)\b(?:cmdclass\s*=|setup_requires\s*=)", "Python packaging hook that can run code at install/build time"),
]

# File-level rules: the mere presence of these files matters for Claude Code / AI tooling.
AGENT_CONFIG_FILES = {
    ".mcp.json": ("AI003", "MEDIUM", "Project MCP server configuration",
                  "Review every MCP server command before approving it; MCP servers run as local processes with your permissions."),
    "claude.md": ("AI004", "INFO", "Agent instruction file (CLAUDE.md)",
                  "Read as untrusted text: it is loaded into Claude's context when the folder is opened."),
    "agents.md": ("AI004", "INFO", "Agent instruction file (AGENTS.md)",
                  "Read as untrusted text before letting an agent work in this folder."),
}
# In documentation the code-pattern rules usually describe, rather than perform, behaviour.
# They stay visible but one level lower. AI001/SECRET keep full severity: prompt injection
# and leaked secrets live precisely in text files.
DOC_EXTS = {".md", ".markdown", ".rst", ".txt", ".adoc"}
DOC_KEEP_SEVERITY = {"AI001", "SECRET"}
DOWNGRADE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW", "INFO": "INFO"}
HOOK_KEY = re.compile(r'"(?:hooks|statusLine|apiKeyHelper|awsAuthRefresh|awsCredentialExport|otelHeadersHelper)"\s*:')
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def is_text_candidate(p: Path) -> bool:
    return p.suffix.lower() in TEXT_EXTS or p.name.lower() in {
        "dockerfile", "makefile", "procfile", "gemfile", "rakefile",
        "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
        "requirements.txt", "pyproject.toml", "poetry.lock", "pipfile",
        "cargo.toml", "go.mod", "go.sum", "pom.xml", "build.gradle",
        "gradlew", "composer.json", "gemfile.lock", "justfile"
    } or p.name.startswith(".env")

def finding(fid, severity, confidence, path, line, title, evidence, recommendation):
    return {
        "id": fid, "severity": severity, "confidence": confidence,
        "path": str(path), "line": line, "title": title,
        "evidence": evidence, "recommendation": recommendation
    }

def scan_text(path_label: str, data: bytes):
    findings = []
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return findings
    is_doc = Path(path_label).suffix.lower() in DOC_EXTS
    for n, line in enumerate(text.splitlines(), 1):
        # Redact before evaluating any other rule: a second heuristic on the same
        # source line must never leak a credential through its evidence excerpt.
        redacted_line = line
        for secret_title, rx in SECRET_PATTERNS:
            if rx.search(line):
                findings.append(finding("SECRET", "CRITICAL", "medium", path_label, n,
                    secret_title, "[REDACTED: possible secret value present]",
                    "Treat as potentially exposed; verify locally without copying the value, then rotate/revoke if genuine."))
                redacted_line = rx.sub("[REDACTED]", redacted_line)
        for fid, sev, pattern, title in RULES:
            if re.search(pattern, line):
                if is_doc and fid not in DOC_KEEP_SEVERITY:
                    sev = DOWNGRADE[sev]
                    title = title + " (mentioned in documentation)"
                excerpt = redacted_line.strip()
                if len(excerpt) > 180: excerpt = excerpt[:177] + "..."
                findings.append(finding(fid, sev, "low" if sev in ("MEDIUM", "LOW", "INFO") else "medium",
                    path_label, n, title, excerpt,
                    "Review surrounding code and execution context. This heuristic is not proof of malicious behavior."))
    return findings

def agent_config_findings(rel: str, data):
    """Findings tied to Claude Code / agent configuration files inside the target."""
    out = []
    norm = "/" + rel.replace("\\", "/")
    lnorm = norm.lower()
    name = lnorm.rsplit("/", 1)[-1]
    if name in AGENT_CONFIG_FILES:
        fid, sev, title, rec = AGENT_CONFIG_FILES[name]
        out.append(finding(fid, sev, "high", rel, None, title, name, rec))
    if "/.claude/" in lnorm and name.startswith("settings") and name.endswith(".json"):
        text = (data or b"").decode("utf-8", errors="replace")
        if HOOK_KEY.search(text):
            out.append(finding("AI002", "HIGH", "high", rel, None,
                "Claude Code project settings define commands (hooks/helpers)",
                "settings file declares hooks, statusLine or credential helpers",
                "These commands run automatically when Claude Code works in this folder. Read them line by line before trusting the folder."))
        else:
            out.append(finding("AI002", "MEDIUM", "high", rel, None,
                "Claude Code project settings present", name,
                "Check permissions/allow rules before trusting the folder."))
    if any(seg in lnorm for seg in ("/.claude/skills/", "/.claude/commands/", "/.claude/agents/")) and name.endswith(".md"):
        out.append(finding("AI005", "INFO", "high", rel, None,
            "Claude Code skill/command/agent definition", name,
            "Treat as untrusted instructions; review allowed-tools and any embedded commands."))
    return out

def tar_findings(path: Path):
    out = []
    try:
        with tarfile.open(path, "r:*") as t:
            for i, m in enumerate(t):
                if i >= MAX_ARCHIVE_MEMBERS:
                    out.append(finding("ARCHIVE004", "INCONCLUSIVE", "high", str(path), None,
                        "Archive member limit reached", f">{MAX_ARCHIVE_MEMBERS} members",
                        "Remaining members were not inspected."))
                    break
                normalized = m.name.replace("\\", "/")
                if normalized.startswith("/") or ".." in normalized.split("/"):
                    out.append(finding("ARCHIVE001", "HIGH", "high", str(path), None,
                        "Unsafe archive member path", m.name[:180],
                        "Do not extract this archive on the host; inspect in an isolated tool."))
                if m.issym() or m.islnk():
                    out.append(finding("ARCHIVE005", "MEDIUM", "high", str(path), None,
                        "Link member inside archive", f"{m.name[:120]} -> {str(m.linkname)[:60]}",
                        "Links can point outside the extraction folder. Extract only with a safe filter."))
                if m.size > MAX_ARCHIVE_MEMBER:
                    out.append(finding("ARCHIVE002", "MEDIUM", "high", str(path), None,
                        "Oversized archive member", f"{m.name}: {m.size} bytes",
                        "Inspect with strict resource limits."))
    except Exception as e:
        out.append(finding("ARCHIVEERR", "INCONCLUSIVE", "high", str(path), None,
            "Archive inspection failed", type(e).__name__,
            "Do not treat this artifact as cleared; inspect with an updated isolated parser."))
    return out

def archive_findings(path: Path):
    out = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                infos = z.infolist()[:MAX_ARCHIVE_MEMBERS]
                for info in infos:
                    name = info.filename
                    normalized = name.replace("\\", "/")
                    if normalized.startswith("/") or ".." in normalized.split("/"):
                        out.append(finding("ARCHIVE001", "HIGH", "high", str(path), None,
                            "Unsafe archive member path", name[:180],
                            "Do not extract this archive on the host; inspect in an isolated tool."))
                    if info.file_size > MAX_ARCHIVE_MEMBER:
                        out.append(finding("ARCHIVE002", "MEDIUM", "high", str(path), None,
                            "Oversized archive member", f"{name}: {info.file_size} bytes",
                            "Inspect with strict resource limits."))
                    if info.filename.lower().endswith((".zip", ".tar", ".gz", ".7z")):
                        out.append(finding("ARCHIVE003", "INFO", "medium", str(path), None,
                            "Nested archive reference", name[:180],
                            "Nested archive content was not recursively inspected by this MVP."))
    except Exception as e:
        out.append(finding("ARCHIVEERR", "INCONCLUSIVE", "high", str(path), None,
            "Archive inspection failed", type(e).__name__,
            "Do not treat this artifact as cleared; inspect with an updated isolated parser."))
    return out

def walk_target(target: Path):
    if target.is_file():
        yield target
        return
    for base, dirs, files in os.walk(target, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(base) / d).is_symlink()]
        for name in files:
            p = Path(base) / name
            if p.is_symlink():
                continue
            yield p

def scan(target: Path, max_files: int = MAX_FILES_DEFAULT):
    start = time.time()
    inventory, findings, skipped = [], [], []
    truncated = False
    for p in walk_target(target):
        if len(inventory) >= max_files:
            truncated = True
            break
        try:
            st = p.stat()
            rel = str(p.relative_to(target)) if target.is_dir() else p.name
            item = {"path": rel, "size": st.st_size, "sha256": sha256_file(p)}
            inventory.append(item)
            if st.st_size > MAX_FILE:
                findings.extend(agent_config_findings(rel, None))
                skipped.append({"path": rel, "reason": "file exceeds static text limit"})
                continue
            low = p.name.lower()
            if low.endswith((".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz")):
                findings.extend(tar_findings(p))
                continue
            if zipfile.is_zipfile(p):
                findings.extend(archive_findings(p))
                continue
            if is_text_candidate(p):
                data = p.read_bytes()
                findings.extend(agent_config_findings(rel, data))
                findings.extend(scan_text(rel, data))
            elif p.suffix.lower() in {".exe", ".dll", ".so", ".dylib", ".bin", ".dat"}:
                findings.append(finding("BINARY001", "INFO", "high", rel, None,
                    "Binary artifact present", f"{p.suffix or 'unknown'}; static binary analysis not included",
                    "Analyze with a dedicated binary-analysis engine in an isolated environment."))
        except (PermissionError, OSError) as e:
            skipped.append({"path": str(p), "reason": type(e).__name__})
    if truncated:
        findings.append(finding("COVERAGE001", "INCONCLUSIVE", "high", str(target), None,
            "File limit reached; scan is partial", f"stopped after {max_files} files",
            "Re-run with a higher --max-files value before trusting this target."))
    counts = {}
    for f in findings: counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "product": "ASG Protection Core", "version": VERSION,
        "scan_id": hashlib.sha256((str(target.resolve()) + str(time.time_ns())).encode()).hexdigest()[:16],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target.resolve()), "mode": "read-only-static",
        "execution_performed": False, "network_access_performed": False,
        "files_inventoried": len(inventory), "files_skipped": len(skipped), "truncated": truncated,
        "coverage_note": "Heuristic static triage only. No code execution, full SCA resolution, sandboxing, runtime telemetry, or complete binary analysis.",
        "counts": counts, "inventory": inventory, "skipped": skipped, "findings": findings,
        "duration_seconds": round(time.time() - start, 3)
    }

def markdown_report(r):
    lines = [
        "# ASG Security Investigation Report", "",
        f"- **Scan ID:** `{r['scan_id']}`",
        f"- **Target:** `{r['target']}`",
        f"- **Date:** {r['created_at']}",
        f"- **Mode:** `{r['mode']}`",
        f"- **Files inventoried:** {r['files_inventoried']}",
        f"- **Files skipped:** {r['files_skipped']}",
        f"- **Code executed:** No",
        f"- **Network access:** No", "",
        "> This is a heuristic static triage report, not a guarantee of safety. A pattern match is not proof of malware.", "",
        "## Summary", ""
    ]
    for k in ("CRITICAL","HIGH","MEDIUM","LOW","INFO","INCONCLUSIVE"):
        lines.append(f"- {k}: {r['counts'].get(k,0)}")
    lines += ["", "## Findings", ""]
    if not r["findings"]:
        lines.append("No indicators detected within the checks performed. This does not prove the target is safe.")
    for f in r["findings"]:
        loc = f":{f['line']}" if f["line"] else ""
        lines += [
            f"### {f['id']} — {f['severity']} — {f['title']}",
            f"- **Location:** `{f['path']}{loc}`",
            f"- **Confidence:** {f['confidence']}",
            f"- **Evidence:** `{f['evidence']}`",
            f"- **Recommendation:** {f['recommendation']}", ""
        ]
    lines += ["## Limitations", "", r["coverage_note"], "",
              "## User decision", "",
              "No files were modified, deleted, quarantined, installed, or executed. Review findings and explicitly approve any proposed remediation."]
    return "\n".join(lines) + "\n"

def write_reports(report, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"asg-{report['scan_id']}.json"
    md_path = out / f"asg-{report['scan_id']}.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(markdown_report(report), encoding="utf-8")
    return json_path, md_path

def main():
    ap = argparse.ArgumentParser(description="ASG read-only static triage MVP")
    ap.add_argument("target", help="File or directory to inspect")
    ap.add_argument("--out", default="asg-reports", help="Output directory (default: ./asg-reports)")
    ap.add_argument("--max-files", type=int, default=MAX_FILES_DEFAULT, help="Stop after N files (scan is then marked INCONCLUSIVE)")
    args = ap.parse_args()
    target = Path(args.target).expanduser()
    if not target.exists():
        print("ERROR: target does not exist", file=sys.stderr); return 2
    if target.is_symlink():
        print("ERROR: target is a symlink; choose the real path explicitly", file=sys.stderr); return 2
    report = scan(target, args.max_files)
    json_path, md_path = write_reports(report, Path(args.out).expanduser())
    print(f"ASG scan complete: {report['scan_id']}")
    print(f"Files inventoried: {report['files_inventoried']}; findings: {len(report['findings'])}")
    print(f"JSON: {json_path.resolve()}")
    print(f"Markdown: {md_path.resolve()}")
    print("No target code was executed. No target files were modified.")
    print("IMPORTANT: heuristic triage only; review findings and limitations.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
