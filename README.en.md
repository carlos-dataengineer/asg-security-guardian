<div align="center">

# 🛡️ ASG Security Guardian

**Your AI agent just downloaded a GitHub repository? ASG scans it before anything is installed or run.**

Automatic, local, read-only protection for **Claude Code** and **OpenAI Codex**.

[Português](README.md) · [Install](#install-in-one-command) · [How it works](#how-it-works) · [Screens](#screens) · [Shortcuts](#shortcuts-and-commands)

<img src="docs/images/claude-hook.png" alt="Claude Code stopping before installing a repository with strong indicators" width="900">

</div>

## Why

Coding agents clone repositories, install packages and run scripts for you. A repository can ship things you
won't notice at a glance: `.claude/settings.json` hooks that run by themselves, prompt injection inside a skill
or README, `curl … | sh` in a setup script, an npm `postinstall` that sends environment data out, or an
`.mcp.json` starting a server with access to your disk.

ASG sits **between download and use**. As soon as the agent fetches something from GitHub, ASG runs a static
scan (it never executes anything) and shows you the verdict. When it finds strong indicators, it tells the agent
to **stop and ask you** first.

> **Status: defensive prototype 0.4.** Heuristic triage, not an antivirus or EDR. A finding is not proof of
> malware, and a clean result is not a guarantee.

## Install in one command

Requires **Python 3.10+** and **git**. Claude Code and/or Codex are detected automatically.

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/carlos-dataengineer/asg-security-guardian/main/install.ps1 | iex
```

```bash
# macOS / Linux / WSL   (add `sh -s -- --lang en` for English messages)
curl -fsSL https://raw.githubusercontent.com/carlos-dataengineer/asg-security-guardian/main/install.sh | sh -s -- --lang en
```

Review-first alternative: `git clone … && cd asg-security-guardian && python install.py --lang en`.
See [INSTALL.md](INSTALL.md) for every option (`--target claude|codex|all`, `--add-to-path`, `--no-hooks`,
`--uninstall`).

### Generated automatically on install

| Item | Claude Code | Codex |
|---|---|---|
| Skill `asg-security-guardian` | `~/.claude/skills/` → `/asg-security-guardian` | `~/.agents/skills/` → `$asg-security-guardian` |
| After-download hook (`PostToolUse`) | scans every clone/download | scans every clone/download |
| Before-install hook (`PreToolUse`) | direct GitHub install → **asks you** | direct GitHub install → **denies and explains** |
| Session hook (`SessionStart`) | scans new/changed plugins and skills | scans new/changed skills |
| `asg` command, local `dashboard.html`, first scan of existing extensions | ✓ | ✓ |

Existing hooks and settings are kept, and a backup is written before any change. Afterwards, restart the
agent. **In Codex, run `/hooks` once to trust the ASG hooks.** Then check everything with `asg doctor`.

## How it works

| When | Trigger | ASG |
|---|---|---|
| Before a command | `pip install git+…`, `npm i github:…`, `npx github:…`, `curl \| sh`, `irm \| iex`, `go install`, `cargo install --git` | Claude Code: asks you. Codex: denies and tells the agent to clone first |
| After a download | `git clone`, `gh repo clone`, `git submodule add`, `gh release download`, `curl -o`, `wget`, `Invoke-WebRequest -OutFile` | Scans and shows a one-line verdict. Strong indicators make the agent stop and ask |
| Session start | startup / resume | Scans plugins, marketplaces and skills that are new or changed |
| On demand | `/asg-security-guardian`, `$asg-security-guardian`, `asg scan` | Guided investigation. No action is taken without your approval |

Verdicts: **REVIEW** (strong indicators), **INCONCLUSIVE** (scan incomplete or core modified), **INDICATORS**
(heuristic signals only), **NO INDICATORS** (nothing found by the checks; not a safety guarantee).

## Screens

<img src="docs/images/codex-hook.png" alt="Codex: direct install denied, clone scanned" width="880">

<img src="docs/images/dashboard.png" alt="ASG dashboard" width="880">

**Actions tab** (`asg dashboard --actions`, or `asg log` in the terminal). Every ASG decision is written to a local
hash-chained audit ledger, and this tab shows it as a timeline:
- installs blocked (Codex);
- confirmations asked (Claude Code) and installs that ran after you approved;
- automatic and manual scans with their verdicts;
- quarantine proposals and copies;
- baselines and integrity changes.

It also shows whether the ledger is still intact. Commands containing credentials are stored redacted.

<img src="docs/images/dashboard-actions.png" alt="ASG dashboard, Actions tab" width="880">

<sub>Synthetic demo repositories. ASG text is real tool output; agent replies are illustrative.</sub>

## Shortcuts and commands

| | |
|---|---|
| `/asg-security-guardian …` (Claude) · `$asg-security-guardian …` (Codex) | guided investigation |
| `asg scan PATH` | static scan, report and dashboard refresh |
| `asg dashboard --open` / `--actions` | open the dashboard (Scans / Actions tab) |
| `asg log [--limit N]` | timeline of blocks, confirmations, scans and quarantine |
| `asg doctor` | installation and integrity check |
| `asg baseline PATH` / `asg check PATH` / `asg watch PATH` | file-integrity snapshot, compare and watch |
| `asg propose-quarantine FILE` → `asg approve ID` | copy-only quarantine (you type `APPROVE ID`) |
| `asg verify-audit` · `asg uninstall` | audit chain check · remove |

## Privacy and limits

ASG is fully local, with no network access and no telemetry, and works read-only. Secret values are never stored.
The installed core is integrity-checked (a modified core reports INCONCLUSIVE), and home folders appear as `~`
in messages.

Limits:
- Static heuristics only, so expect false positives (ASG's own source code triggers its rules) and false negatives.
- Only commands run through the agent's shell tool are seen.
- Codex hooks cannot "ask" and must be trusted once with `/hooks`.

The rule table, FAQ and details are in the [Portuguese README](README.md).

## Contributing · Security · License

[CONTRIBUTING.md](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) ·
[private vulnerability report](https://github.com/carlos-dataengineer/asg-security-guardian/security/advisories/new) ·
[MIT](LICENSE)
