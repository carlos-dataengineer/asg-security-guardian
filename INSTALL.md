# Guia de instalação

## Requisitos

- Python **3.10+** (`python --version`)
- **git** (só para a instalação em um comando)
- Claude Code e/ou OpenAI Codex instalados (o instalador detecta os dois)

## Opção 1 — um comando

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/carlos-dataengineer/asg-security-guardian/main/install.ps1 | iex
```

**macOS / Linux / WSL / Git Bash:**

```bash
curl -fsSL https://raw.githubusercontent.com/carlos-dataengineer/asg-security-guardian/main/install.sh | sh
```

O script clona o repositório em `~/.asg-security-guardian/src` e executa `install.py`. Rode esses comandos **você
mesmo, no seu terminal**: se pedir para o Claude Code ou o Codex rodá-los depois do ASG instalado, o próprio ASG vai
pedir confirmação (Claude) ou bloquear (Codex), porque é exatamente o padrão "baixar e executar sem analisar".

## Opção 2 — revisar antes de instalar (recomendado para quem é cuidadoso)

```bash
git clone https://github.com/carlos-dataengineer/asg-security-guardian.git
cd asg-security-guardian
# leia install.py e protection_core/ antes de continuar
python install.py
```

## Opções do instalador

| `install.py` | `install.ps1` | Efeito |
|---|---|---|
| `--target auto` (padrão) | `-Target auto` | instala para os agentes encontrados (`~/.claude`, `~/.codex` ou comandos no PATH) |
| `--target claude` / `codex` / `all` | `-Target claude` … | escolhe os agentes |
| `--lang en` | `-Lang en` | mensagens em inglês (padrão: português) |
| `--add-to-path` | `-AddToPath` | coloca `~/.asg-security-guardian/bin` no PATH do usuário |
| `--no-hooks` | `-NoHooks` | só Skill, comando e painel, sem hooks automáticos |
| `--uninstall` | `-Uninstall` | remove tudo, exceto relatórios e auditoria |

Com `install.sh`, passe as opções de `install.py` depois de `sh -s --`, por exemplo:
`curl -fsSL …/install.sh | sh -s -- --target codex --lang en`.

Variáveis de ambiente: `ASG_STATE` (pasta de estado), `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `ASG_REF` (branch/tag
usado pelo instalador de um comando), `ASG_HOOK_MAX_FILES`.

## O que é criado

| Local | Conteúdo |
|---|---|
| `~/.asg-security-guardian/app/` | Core instalado + `manifest.json` (SHA-256 de cada arquivo) |
| `~/.asg-security-guardian/bin/` | comando `asg` (`asg.cmd` no Windows) |
| `~/.asg-security-guardian/reports/` | relatórios JSON e Markdown |
| `~/.asg-security-guardian/dashboard.html` | painel local |
| `~/.asg-security-guardian/audit.jsonl` | ledger de auditoria com cadeia de hashes |
| `~/.claude/skills/asg-security-guardian/` | Skill do Claude Code |
| `~/.claude/settings.json` | hooks `PreToolUse`, `PostToolUse`, `SessionStart` (backup `.asg-backup-*` ao lado) |
| `~/.agents/skills/asg-security-guardian/` | Skill do Codex |
| `~/.codex/hooks.json` | hooks do Codex (backup `.asg-backup-*` ao lado) |

Hooks que você já tinha são preservados. Reinstalar é seguro: as entradas do ASG são substituídas, não duplicadas.

## Depois de instalar

- **Claude Code:** reinicie (ou abra uma nova sessão).
- **Codex:** reinicie e rode **`/hooks`** uma vez para **confiar** nos hooks do ASG. O Codex ignora hooks novos até
  que sejam aprovados.
- Confira com `asg doctor`.

## Atualizar

Rode o mesmo comando de instalação de novo (ou `git pull && python install.py` no clone).

## Desinstalar

```bash
asg uninstall          # ou: python install.py --uninstall
```

Remove hooks, Skills, Core e comando. Relatórios, painel e auditoria ficam em `~/.asg-security-guardian/` para
consulta; apague a pasta manualmente se quiser.
