# ASG Security Guardian — one-command installer (Windows PowerShell 5.1+ / PowerShell 7).
#
#   From a clone:   .\install.ps1 [-Target claude|codex|all] [-Lang en] [-AddToPath]
#   One command:    irm https://raw.githubusercontent.com/carlos-dataengineer/asg-security-guardian/main/install.ps1 | iex
#
# Piped mode clones the repository (git required) into %USERPROFILE%\.asg-security-guardian\src and runs install.py.
# Read this file before piping it to a shell — that is exactly the habit ASG asks you to keep.
param(
    [ValidateSet("auto", "claude", "codex", "all")][string]$Target = "auto",
    [ValidateSet("pt", "en")][string]$Lang = "pt",
    [switch]$AddToPath,
    [switch]$NoHooks,
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"

$RepoUrl = if ($env:ASG_REPO) { $env:ASG_REPO } else { "https://github.com/carlos-dataengineer/asg-security-guardian.git" }
$Ref = if ($env:ASG_REF) { $env:ASG_REF } else { "main" }
$StateDir = if ($env:ASG_STATE) { $env:ASG_STATE } else { Join-Path $HOME ".asg-security-guardian" }
$Src = Join-Path $StateDir "src"

# Find Python 3.10+
$Py = $null; $PyArgs = @()
foreach ($cand in @(@("py", "-3"), @("python"), @("python3"))) {
    if (Get-Command $cand[0] -ErrorAction SilentlyContinue) {
        $extra = @(); if ($cand.Count -gt 1) { $extra = $cand[1..($cand.Count - 1)] }
        & $cand[0] @extra -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) { $Py = $cand[0]; $PyArgs = $extra; break }
    }
}
if (-not $Py) { throw "ASG: Python 3.10+ is required (https://www.python.org/downloads/)." }

$InstallArgs = @("--target", $Target, "--lang", $Lang)
if ($AddToPath) { $InstallArgs += "--add-to-path" }
if ($NoHooks) { $InstallArgs += "--no-hooks" }
if ($Uninstall) { $InstallArgs = @("--uninstall") }

$Here = if ($PSScriptRoot) { $PSScriptRoot } else { $null }
if ($Here -and (Test-Path (Join-Path $Here "install.py"))) {
    & $Py @PyArgs (Join-Path $Here "install.py") @InstallArgs
    exit $LASTEXITCODE
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "ASG: git is required for the one-command install (https://git-scm.com/download/win)." }
if (Test-Path (Join-Path $Src ".git")) {
    Write-Host "ASG: updating $Src ($Ref)"
    git -C $Src fetch --depth 1 origin $Ref; if ($LASTEXITCODE -ne 0) { throw "git fetch failed" }
    git -C $Src checkout -q FETCH_HEAD
} else {
    Write-Host "ASG: downloading $RepoUrl ($Ref) -> $Src"
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    git clone -q --depth 1 --branch $Ref $RepoUrl $Src; if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
}
& $Py @PyArgs (Join-Path $Src "install.py") @InstallArgs
