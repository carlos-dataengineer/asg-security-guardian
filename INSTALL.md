# Installation guide

The installer copies the Claude Code Skill and a self-contained copy of the local Protection Core into the user's home directory, then creates a command wrapper. It does not register a background service, install kernel drivers, alter firewall settings, or enable automatic remediation.

## Windows

Open PowerShell in the extracted repository folder:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\\install.ps1
```

Project-local Skill installation:

```powershell
.\\install.ps1 -Project
```

## Linux and macOS

```bash
chmod +x ./install.sh
./install.sh
```

Project-local Skill installation:

```bash
./install.sh --project
```

The local core is copied to `~/.asg/app` (or `%USERPROFILE%\\.asg\\app` on Windows). The command wrapper is placed in `~/.asg/bin` (or `%USERPROFILE%\\.asg\\bin`). Add the bin directory to your PATH manually if desired.

## Verify

```bash
python3 ~/.asg/app/protection_core/asg_guard.py --help
python3 ~/.asg/app/protection_core/asg_local.py --help
```

Windows:

```powershell
py -3 "$HOME\\.asg\\app\\protection_core\\asg_guard.py" --help
py -3 "$HOME\\.asg\\app\\protection_core\\asg_local.py" --help
```

## Uninstall

Remove the installed Skill directory, `~/.asg/app`, and the `~/.asg/bin/asg` launcher (or corresponding `%USERPROFILE%` paths on Windows). The `~/.asg-security-guardian` state/audit directory is intentionally left untouched. Review and back up local state before manually deleting it.
