# Histórico de versões

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto usa [SemVer](https://semver.org/lang/pt-BR/).

## 0.3.0 — proteção automática para Claude Code e Codex

### Adicionado
- **Hooks automáticos** (`protection_core/asg_hook.py`) para **Claude Code** e **OpenAI Codex**:
  - depois de `git clone`, `gh repo clone`, `gh release download`, `git submodule add`, `curl -o/-O`, `wget`
    e `Invoke-WebRequest -OutFile`, o conteúdo baixado é analisado e o veredito vai para você e para o agente;
  - instalação direta do GitHub (`pip install git+…`, `npm i github:…`, `npx github:…`, `curl … | sh`, `irm … | iex`,
    `go install`, `cargo install --git`) pede confirmação no Claude Code e é bloqueada com explicação no Codex
    (hooks do Codex não suportam "ask");
  - plugins, marketplaces e skills novos ou alterados são analisados ao abrir a sessão.
- **Instalação em um comando** (`install.ps1` / `install.sh`), com detecção automática de Claude Code e Codex.
  A instalação gera automaticamente: Skill nos dois agentes, hooks, comando `asg`, painel `dashboard.html` e a
  primeira análise das extensões já instaladas.
- **Comando `asg`**: `scan`, `dashboard`, `doctor`, `baseline`, `check`, `watch`, `propose-quarantine`, `approve`,
  `verify-audit`, `uninstall`, `version`.
- **Painel local** (`asg dashboard --open`) com todas as análises, filtros e busca; sem rede e com escape de todo
  conteúdo vindo do alvo.
- Manifesto SHA-256 do Core instalado: se os arquivos forem alterados, o hook responde INCONCLUSIVO.
- Regras novas: AI002–AI005 (settings/hooks do Claude, MCP, CLAUDE.md/AGENTS.md, skills), PS001/PS002, CRED001,
  PKG001/PKG002; verificação de metadados TAR; limite de arquivos com achado INCONCLUSIVE.
- Templates de issue/PR, CODEOWNERS, Dependabot, `.editorconfig`, `.gitattributes`, `pyproject.toml`,
  Código de Conduta e teste de fumaça do instalador no CI (Windows, macOS, Linux).

### Corrigido
- NET001 não detectava `fetch(...)`, `requests.get(...)` e similares por causa de um `\b` final na expressão.
- AI001 disparava em textos defensivos ("detectar exfiltração"); agora procura frases imperativas.

### Alterado
- Em documentação (`.md`, `.txt`, `.rst`) as regras de código caem um nível de severidade e são marcadas como
  "mentioned in documentation"; AI001 e SECRET mantêm a severidade.
- Mensagens dos hooks e do painel mostram a pasta pessoal como `~` (sem expor nome de usuário).
- Instalação passa a usar `~/.asg-security-guardian/` (app, bin, relatórios, auditoria). A opção `--project`
  dos instaladores antigos foi removida.

## 0.2.1 — publicação do código-fonte

- Publicação da Skill, Protection Core, política local, instaladores e testes.
- Atualização da documentação para refletir os arquivos realmente disponíveis.
- Correção para evitar que uma regra heurística secundária exponha um valor de segredo presente na mesma linha de código.
- Inclusão de teste de regressão para a redação de segredos.
- Licença MIT.

## 0.2.0 — protótipo local

- Baseline e comparação de integridade por polling.
- Aprovação específica, de uso único e com validade limitada.
- Quarentena por cópia, preservando o original.
- Ledger de auditoria local com encadeamento SHA-256.
