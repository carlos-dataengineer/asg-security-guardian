# ASG Security Guardian 0.2 — Local Protection Core

## Deployment decision

- Deployment: local-only.
- Authorization: every action requires an individual approval.
- Cloud upload: disabled.
- Automatic remediation: disabled.
- Untrusted code execution: denied.
- Untrusted network access: denied.

## New components

### Local Integrity Monitor
Creates a user-requested baseline of file hashes and compares later snapshots. It reports additions, modifications and removals. Polling mode is detection-only: it does not prevent writes, stop processes or restore files.

### Approval Manager
Creates one-time proposals bound to:
- one exact action;
- one exact source path;
- one exact SHA-256;
- one exact destination;
- a short expiry;
- an explicit confirmation phrase.

A stale target invalidates the proposal. Approval to scan is never approval to remediate.

### Quarantine MVP
Supports only a verified copy into a local quarantine folder. It does not delete or move the original. The copy is hash-verified. Deletion, process termination, firewall changes, permission changes and credential revocation are intentionally not implemented.

### Audit ledger
Stores local JSONL events with a SHA-256 hash chain. This detects accidental or unsophisticated edits, but is not equivalent to hardware-backed or WORM storage. A local administrator can still alter the file and recompute the chain. Production requires OS-protected storage and signed checkpoints.

## Commands

Initialize a baseline:
```bash
python protection_core/asg_local.py baseline /path/to/project
```

Check changes:
```bash
python protection_core/asg_local.py check /path/to/project
```

Poll for changes (Ctrl+C to stop):
```bash
python protection_core/asg_local.py watch /path/to/project --interval 10
```

Propose a quarantine copy (no action occurs):
```bash
python protection_core/asg_local.py propose-quarantine /path/to/suspicious-file
```

Approve a specific pending proposal:
```bash
python protection_core/asg_local.py approve REQUEST_ID
```
The terminal then displays the exact action and requires typing `APPROVE REQUEST_ID`. This is a local CLI confirmation, not a cryptographic identity proof.

Verify audit chain:
```bash
python protection_core/asg_local.py verify-audit
```

Default state directory: `~/.asg-security-guardian`. Use `--state` to select another local directory.

## Important limits

The monitor is a polling integrity checker, not real-time endpoint protection. It cannot reliably observe file reads, credential-store access, process injection, memory activity or network exfiltration. It does not block ransomware or malicious process execution. Do not market this release as antivirus/EDR.

## Next platform-specific work

- Windows: signed service/sensor, ETW or supported endpoint telemetry, Windows Firewall integration, least-privilege service account, secure ACLs.
- Linux: audit/eBPF telemetry where supported, fanotify/inotify for file events, namespaces/seccomp/cgroups for sandbox workers, nftables integration.
- macOS: signed/notarized Endpoint Security client, TCC-aware design, sandbox/VM workers and supported network controls.

Each native sensor requires separate implementation, signing, compatibility testing and review. The portable Python core must not pretend to provide kernel-level protection.
