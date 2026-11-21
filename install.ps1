[CmdletBinding()]
param([switch]$Project)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

$PythonCmd = $null
$PythonArgs = @()
if (Get-Command py -ErrorAction SilentlyContinue) {
    $PythonCmd = "py"; $PythonArgs = @("-3")
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonCmd = "python"
} else {
    throw "Python 3.10+ não encontrado. Instale em https://www.python.org/downloads/."
}
& $PythonCmd @PythonArgs --version
if ($LASTEXITCODE -ne 0) { throw "Falha ao verificar Python." }
& $PythonCmd @PythonArgs -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)"
if ($LASTEXITCODE -ne 0) { throw "Python 3.10 ou superior é obrigatório." }

$SkillSource = Join-Path $Root ".claude\skills\asg-security-guardian"
if (-not (Test-Path $SkillSource)) { throw "Skill não encontrada: $SkillSource" }
if ($Project) {
    $SkillDestination = Join-Path (Get-Location) ".claude\skills\asg-security-guardian"
} else {
    $ClaudeHome = if ($env:CLAUDE_CONFIG_DIR) { $env:CLAUDE_CONFIG_DIR } else { Join-Path $HOME ".claude" }
    $SkillDestination = Join-Path $ClaudeHome "skills\asg-security-guardian"
}
$App = Join-Path $HOME ".asg\app"
$Bin = Join-Path $HOME ".asg\bin"
if (Test-Path $SkillDestination) { throw "Skill já existe: $SkillDestination. Faça backup/remova manualmente antes de reinstalar." }
if (Test-Path $App) { throw "Aplicação já existe: $App. Faça backup/remova manualmente antes de reinstalar." }

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $SkillDestination), $App, $Bin | Out-Null
Copy-Item -Recurse -LiteralPath $SkillSource -Destination $SkillDestination
New-Item -ItemType Directory -Force -Path (Join-Path $App "protection_core") | Out-Null
Copy-Item (Join-Path $Root "protection_core\*.py") (Join-Path $App "protection_core")
Copy-Item -Recurse (Join-Path $Root "config") $App

$Launcher = Join-Path $Bin "asg.ps1"
$PythonExe = (Get-Command $PythonCmd).Source
$PythonArgsText = ($PythonArgs | ForEach-Object { "'$_'" }) -join ","
@"
`$ErrorActionPreference = 'Stop'
`$AsgRoot = '$($App.Replace("'","''"))'
`$PythonExe = '$($PythonExe.Replace("'","''"))'
`$PythonArgs = @($PythonArgsText)
if (`$args.Count -lt 1) { Write-Host 'Uso: asg.ps1 <scan|baseline|check|watch|propose-quarantine|approve|verify-audit> [argumentos]'; exit 2 }
`$Command = `$args[0]
`$Rest = @()
if (`$args.Count -gt 1) { `$Rest = `$args[1..(`$args.Count - 1)] }
switch (`$Command) {
  'scan' { & `$PythonExe @PythonArgs (Join-Path `$AsgRoot 'protection_core\asg_guard.py') @Rest }
  {`$_ -in 'baseline','check','watch','propose-quarantine','approve','verify-audit'} { & `$PythonExe @PythonArgs (Join-Path `$AsgRoot 'protection_core\asg_local.py') `$Command @Rest }
  default { Write-Error "Comando desconhecido: `$Command"; exit 2 }
}
exit `$LASTEXITCODE
"@ | Set-Content -Encoding UTF8 $Launcher

Write-Host "ASG instalado."
Write-Host "Skill: $SkillDestination"
Write-Host "Core:  $App"
Write-Host "CLI:   $Launcher"
Write-Host "Adicione $Bin ao PATH para chamar 'asg.ps1' de qualquer pasta."
