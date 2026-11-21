# ASG Security Guardian — Architecture and Implementation Plan

## 1. Product boundary

**Claude Skill:** investigation workflow, evidence interpretation, user communication, action proposals.
**Protection Core:** deterministic local scanner, policy engine, evidence store, approval ledger, and OS adapters.
**OS sensors:** separately installed and privileged only where necessary; never bundled as unreviewed scripts.

Claude must not be the sole enforcement point. A compromised prompt or malicious repository can influence model reasoning; deterministic controls must live outside the model context.

## 2. Trust zones

1. Untrusted zone: repositories, packages, Skills, MCP servers, archives, binaries.
2. Analysis zone: unprivileged static analyzers and parsers with strict resource limits.
3. Control zone: policy, approvals, identity and configuration.
4. Evidence zone: append-only reports and hashes.
5. Runtime zone: disposable sandbox and optional host sensors.

No untrusted artifact may write to control or evidence zones.

## 3. Cross-platform strategy

| Platform | Initial support | Later runtime controls |
|---|---|---|
| Windows 10/11 | Python static scanner | Windows Event Log/ETW, Defender integration where supported, AppContainer/Windows Sandbox or Hyper-V isolation, Windows Firewall policy |
| Linux | Python static scanner | audit/eBPF-based telemetry where available, namespaces/seccomp, cgroups, Landlock, nftables |
| macOS | Python static scanner | Endpoint Security framework via signed/notarized native component, App Sandbox/VM isolation, PF/network controls where supported |

Do not promise identical enforcement on all operating systems. Each adapter requires platform-specific testing, signing, permissions and compatibility review.

## 4. Core services

- Intake: accepts local paths and explicitly approved repository snapshots.
- Inventory: records files, sizes, types, hashes and symlink boundaries.
- Static analysis: runs deterministic rules and external analyzers through adapters.
- SCA/SBOM: resolves dependency metadata without executing package lifecycle scripts.
- AI inspection: parses Skill instructions, MCP manifests and referenced documents as untrusted text.
- Sandbox manager: starts disposable isolated environments; no real credentials.
- Runtime telemetry: process tree, file access, privilege changes and network events.
- Risk engine: aggregates evidence with confidence and coverage.
- Policy engine: deterministic allow/deny/restrict decisions.
- Approval manager: binds approval to one exact action, target hash and expiry.
- Evidence store: append-only records, redaction and integrity hashes.
- Reporting: human-readable and machine-readable reports.

## 5. Consent contract

An approval record must contain:
- user identity or local operator identity;
- exact target and SHA-256;
- exact action;
- parameters and destination;
- stated impact and reversibility;
- timestamp and expiry;
- explicit affirmative response;
- result and verification.

Approval to scan never implies approval to execute, install, upload, delete, quarantine, modify, or revoke credentials.

## 6. MVP implementation

Included:
- Claude Skill package.
- Python 3.10+ static scanner.
- File inventory and SHA-256.
- Heuristic indicators for dynamic execution, process creation, network access, persistence, privilege operations, obfuscation, prompt injection and secret-like values.
- ZIP metadata checks for unsafe paths and oversized members.
- JSON and Markdown reports.
- Redaction of matched secret values.
- No execution, extraction, network, or remediation.

## 7. Production gates

Do not call the product endpoint protection until:
- static engine coverage is measured against curated datasets;
- parser fuzzing and resource-exhaustion tests pass;
- false-positive/false-negative rates are published;
- sandbox escape assumptions are reviewed;
- OS sensors are signed and tested;
- policy tampering is prevented;
- update channel is authenticated and rollback-tested;
- incident response and recovery are tested;
- independent security assessment is completed.

## 8. Next implementation increments

### Increment A — scanner hardening
- Unit tests and fuzzing.
- Better archive handling with strict limits.
- AST-based language parsers.
- Secret detector tests with synthetic fixtures.
- Ruleset versioning and signatures.

### Increment B — software supply chain
- CycloneDX/SPDX SBOM.
- OSV and NVD adapters.
- Lockfile parsers.
- Git provenance and attestation checks.
- Typosquatting and maintainer-change signals.

### Increment C — isolated execution
- Firecracker/gVisor/Kata on supported Linux infrastructure.
- Windows Sandbox/Hyper-V worker.
- macOS VM worker.
- No host credentials; network denied by default.

### Increment D — runtime and host protection
- Separate signed native sensor per OS.
- Process ancestry and file/network event collection.
- User approval UI.
- Firewall/egress policy integration.
- Tamper protection and health monitoring.

### Increment E — Claude integration
- Read-only command wrapper.
- Deterministic PreToolUse hook to prevent execution of unreviewed targets where practical.
- Narrow permissions and managed settings for organizations.
- Optional MCP only after independent review.

## 9. Threat model for ASG itself

Threats include malicious archives, parser exploits, symlink/path traversal, decompression bombs, resource exhaustion, malicious rulesets, forged reports, approval replay, policy tampering, compromised updates, and unauthorized access to evidence.

Controls include unprivileged parsing, strict limits, immutable originals, hash-bound approvals, signed updates, separation of duties, audit logs, and fail-closed behavior.


## 10. Selected deployment: local-only, approve every action

The selected configuration is:
- Local installation on each machine.
- No mandatory cloud control plane.
- No automatic upload of source, reports, samples or indicators.
- Every action requires a one-time, target-bound user approval.
- No standing approval and no autonomous remediation.

### Local components

- Claude Code Skill: investigation and explanation.
- Python Protection Core: static analysis and approval workflow.
- Local state directory: `~/.asg-security-guardian`.
- Local reports: JSON and Markdown.
- Audit ledger: append-only JSONL with hash chaining.
- Quarantine: copy-only MVP, preserving original file.

### Approval transaction

1. Generate a proposal with exact action, target path, SHA-256, destination and expiry.
2. Present the proposal and consequences to the user.
3. Require exact interactive confirmation.
4. Re-check target hash immediately before action.
5. Execute only the single approved operation.
6. Verify output hash.
7. Record result in audit ledger.
8. Never reuse the approval for another target or action.

### Explicitly not implemented in 0.2

- Real-time file-system prevention.
- Process termination.
- Firewall or network blocking.
- Credential-store monitoring.
- Kernel or endpoint sensors.
- Automatic deletion.
- Remote administration or cloud sync.

These are deferred to OS-specific signed components and must be built and validated separately.
