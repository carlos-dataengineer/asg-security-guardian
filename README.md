# ASG Security Guardian

Local-first defensive security toolkit for investigating untrusted projects, agent Skills, MCP integrations, plugins, and files before use.

> **Status: experimental prototype — MVP 0.2.** ASG is not an antivirus, EDR, malware-removal product, or production endpoint protection system. A clean report does not prove that a project is safe.

## Purpose

ASG combines:
1. **ASG Security Guardian Skill** — structured investigation, evidence-based explanation, and explicit user authorization before proposed actions.
2. **ASG Local Protection Core** — local Python utilities for static triage, integrity baselines, per-action approval records, copy-only quarantine, and a local audit ledger.

**Core principle:** Claude investigates and recommends; the Protection Core validates requests, performs only specifically authorized operations, and records evidence. A Skill alone is not a security boundary; deterministic host controls are required for enforcement.

## MVP 0.2 capabilities

- File inventory and SHA-256 hashing.
- Heuristic indicators for process execution, networking, persistence, privilege, obfuscation, prompt injection, and possible secrets.
- Secret-value redaction in reports.
- Limited ZIP metadata checks; archives are not extracted.
- Integrity baseline and polling comparison for added, modified, and removed files.
- Single-use approval bound to exact action, target, and hash; expires after 15 minutes.
- Copy-only quarantine; original remains unchanged.
- Local JSONL hash-chain audit ledger with integrity verification.
- Local-only defaults; no cloud upload or remote threat-intelligence calls.

## Architecture

```text
Untrusted project / Skill / MCP / plugin / files
                    |
                    v
         ASG Security Guardian Skill
       investigation, evidence, explanation
                    |
                    v
          ASG Local Protection Core
      scanner | integrity | approval | audit
                    |
          explicit user approval
                    |
                    v
       narrowly scoped local operation
          (quarantine copies only)
```

## Security defaults

- Read-only investigation by default.
- Untrusted code execution and untrusted network access denied.
- No automatic remediation.
- User approval required for every supported action.
- Approval is single-use and bound to an exact target and SHA-256.
- Cloud upload disabled; secret values are not intentionally stored.
- Fail-closed behavior for supported approval-controlled operations.

## Requirements and platforms

- Python 3.10+.
- Windows, Linux, and macOS are target platforms; native endpoint sensors are not implemented in this MVP.
- Claude Code with custom Skills support for Skill integration.
- Core scripts have no third-party runtime dependencies; pytest is needed for tests.

## Installation

### Windows PowerShell

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

For project-local Skill installation:

```powershell
.\install.ps1 -Project
```

### Linux / macOS

```bash
chmod +x ./install.sh
./install.sh
```

For project-local Skill installation:

```bash
./install.sh --project
```

Installers copy the Skill and local Protection Core, and create a command wrapper under `~/.asg/bin` or `%USERPROFILE%\.asg\bin`. They do not install services, execute scanned content, configure firewall rules, or change OS security settings. Add the wrapper directory to PATH manually if desired.

## Usage

### Static scan

```bash
# Windows
py -3 protection_core/asg_guard.py "C:\\path\\to\\project" --out ".\\asg-reports"

# Linux / macOS
python3 protection_core/asg_guard.py "/path/to/project" --out ./asg-reports
```

### Local Protection Core

```bash
python3 protection_core/asg_local.py --help
python3 protection_core/asg_local.py baseline /path/to/project
python3 protection_core/asg_local.py check /path/to/project
python3 protection_core/asg_local.py watch /path/to/project --interval 10
python3 protection_core/asg_local.py propose-quarantine /path/to/suspicious-file
python3 protection_core/asg_local.py approve REQUEST_ID
python3 protection_core/asg_local.py verify-audit
```

On Windows, use `py -3` instead of `python3` where appropriate. Default local state directory: `~/.asg-security-guardian`.

## Tests

```bash
python -m pip install pytest
python -m pytest -v
```

The current baseline suite contains seven unit tests using synthetic fixtures. Passing tests are not an independent security audit and do not establish malware-detection accuracy. The GitHub Actions workflow is configured for Windows, Linux, and macOS; verify its results after publication.

## Limitations

- Heuristics can produce false positives and false negatives; an indicator is not proof of malware.
- No complete AST, taint, or data-flow analysis.
- No complete SCA, SBOM, or provenance verification.
- ZIP inspection is metadata-only; no extraction or comprehensive nested archive analysis.
- No full PE/ELF/Mach-O reverse engineering.
- No real-time process, kernel, or network monitoring.
- No firewall enforcement, credential/session telemetry, or sandbox.
- Polling detects integrity changes; it does not prevent them.
- The audit chain is tamper-evident, not immutable against a privileged local administrator.
- Quarantine copies a file; it does not disable or delete the original.

See [Architecture](docs/ARCHITECTURE.md), [Local Core 0.2](docs/LOCAL_CORE_0.2.md), [Installation](INSTALL.md), and [Security Policy](SECURITY.md).

## Roadmap

1. Harden parsers and inventory edge cases.
2. Add tested SAST, SCA, SBOM, provenance, and VEX adapters.
3. Add signed, versioned detection rules.
4. Build isolated sandbox workers.
5. Implement signed native sensors for Windows, Linux, and macOS.
6. Add egress enforcement and credential-access telemetry.
7. Build a robust approval interface and policy engine.
8. Add incident response and verified recovery.
9. Conduct independent penetration testing and false-negative evaluation.

## Contributing

Contributions should include tests, documented threat assumptions, and explicit safety boundaries. Do not submit live malware, credentials, private keys, or personal data.

## License

No open-source license has been selected yet. Until a license is added, standard copyright applies; reuse, redistribution, and derivative-work permissions are not granted. A public GitHub repository without a license is publicly viewable but is not automatically open source.
