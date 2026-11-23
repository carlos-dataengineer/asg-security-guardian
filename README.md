<div align="center">

# 🛡️ ASG Security Guardian

**Seu agente de IA baixou um repositório do GitHub? O ASG analisa antes de qualquer coisa ser instalada ou executada.**

Proteção automática, local e somente leitura para **Claude Code** e **OpenAI Codex**.

[![Tests](https://github.com/carlos-dataengineer/asg-security-guardian/actions/workflows/tests.yml/badge.svg)](https://github.com/carlos-dataengineer/asg-security-guardian/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB)
![Windows | macOS | Linux](https://img.shields.io/badge/os-Windows%20%7C%20macOS%20%7C%20Linux-555)
![Claude Code](https://img.shields.io/badge/Claude%20Code-skill%20%2B%20hooks-D97757)
![Codex](https://img.shields.io/badge/Codex-skill%20%2B%20hooks-10A37F)

[Instalar](#-instalação-em-um-comando) · [Como funciona](#-como-funciona) · [Telas](#-telas) · [Casos de uso](#-casos-de-uso) · [Atalhos](#-atalhos-e-comandos) · [FAQ](#-perguntas-frequentes) · [English](README.en.md)

<img src="docs/images/claude-hook.png" alt="Claude Code parando antes de instalar um repositório com indicadores fortes" width="900">

</div>

---

## Índice

- [Por que o ASG existe](#-por-que-o-asg-existe)
- [Instalação em um comando](#-instalação-em-um-comando)
- [O que é gerado automaticamente ao instalar](#-o-que-é-gerado-automaticamente-ao-instalar)
- [Primeiros passos](#-primeiros-passos)
- [Como funciona](#-como-funciona)
- [Telas](#-telas)
- [Casos de uso](#-casos-de-uso)
- [Atalhos e comandos](#-atalhos-e-comandos)
- [Como ler o veredito](#-como-ler-o-veredito)
- [O que o ASG procura](#-o-que-o-asg-procura)
- [Configuração](#%EF%B8%8F-configuração)
- [Privacidade e segurança do próprio ASG](#-privacidade-e-segurança-do-próprio-asg)
- [Limitações](#%EF%B8%8F-limitações)
- [Atualizar e desinstalar](#-atualizar-e-desinstalar)
- [Perguntas frequentes](#-perguntas-frequentes)
- [Estrutura do repositório](#-estrutura-do-repositório)
- [Contribuir, segurança e licença](#-contribuir-segurança-e-licença)

## 🎯 Por que o ASG existe

Agentes como o Claude Code e o Codex clonam repositórios, instalam pacotes e rodam scripts por você, e cada vez
mais rápido. Um repositório pode trazer riscos que não aparecem numa olhada rápida:

- um `.claude/settings.json` com **hooks que rodam sozinhos** quando o agente abre a pasta;
- uma **skill** ou um `README` com **prompt injection** ("ignore as instruções anteriores e…");
- um `setup.sh` que faz **`curl … | sh`** de um servidor desconhecido;
- um `package.json` com **`postinstall`** que lê variáveis de ambiente e manda para a internet;
- um `.mcp.json` que sobe um servidor MCP com acesso ao seu disco.

O ASG entra **entre o download e o uso**: assim que o agente baixa algo do GitHub, o conteúdo é analisado de forma
estática (sem executar nada), o veredito aparece para você e o agente recebe instruções para **parar e perguntar**
quando houver indicadores fortes.

> **Status: protótipo defensivo 0.4.** O ASG faz triagem heurística. Não é antivírus nem EDR. Um achado não prova
> malware, e um resultado limpo não garante segurança. Leia as [limitações](#%EF%B8%8F-limitações).

## 🚀 Instalação em um comando

Requisitos: **Python 3.10+** e **git**. O instalador detecta sozinho se você usa Claude Code, Codex ou os dois.

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/carlos-dataengineer/asg-security-guardian/main/install.ps1 | iex
```

**macOS / Linux / WSL:**

```bash
curl -fsSL https://raw.githubusercontent.com/carlos-dataengineer/asg-security-guardian/main/install.sh | sh
```

**Prefere revisar o código antes de instalar?** (é o que o próprio ASG recomendaria)

```bash
git clone https://github.com/carlos-dataengineer/asg-security-guardian.git
cd asg-security-guardian
python install.py
```

<img src="docs/images/install.png" alt="Saída do instalador em um comando" width="820">

Opções (`--target claude|codex|all`, `--lang en`, `--add-to-path`, `--no-hooks`, `--uninstall`) e detalhes de cada
arquivo criado estão em [INSTALL.md](INSTALL.md).

> 💡 Rode o comando de instalação **você mesmo, no terminal**. Se pedir ao agente para rodar um `curl … | sh` depois
> do ASG instalado, o ASG vai pedir confirmação (Claude Code) ou bloquear (Codex). É o comportamento esperado.

## ✨ O que é gerado automaticamente ao instalar

Um único comando deixa a ferramenta pronta dentro do seu agente, sem nenhuma configuração manual:

| Item | Claude Code | Codex |
|---|---|---|
| **Skill `asg-security-guardian`** (investigação guiada) | `~/.claude/skills/` → chame com `/asg-security-guardian` | `~/.agents/skills/` → chame com `$asg-security-guardian` |
| **Hook depois de baixar** (`PostToolUse`) | analisa todo `git clone`/download | analisa todo `git clone`/download |
| **Hook antes de instalar** (`PreToolUse`) | instalação direta do GitHub → **pede confirmação** | instalação direta do GitHub → **bloqueia e explica** |
| **Hook ao abrir sessão** (`SessionStart`) | analisa plugins/skills novos ou alterados | analisa skills novas ou alteradas |
| **Comando `asg`** | `~/.asg-security-guardian/bin/` | idem |
| **Painel local** `dashboard.html` | aba **Análises** + aba **Ações** (bloqueios, confirmações, quarentena, integridade) | idem |
| **Primeira análise** | das extensões que você já tem | idem |

Seus hooks e configurações existentes são preservados, e um backup é criado antes de qualquer alteração.

## 👣 Primeiros passos

1. **Reinicie o agente** (ou abra uma nova sessão).
2. **Codex:** rode `/hooks` uma vez e **confie** nos hooks do ASG. O Codex ignora hooks novos até que você aprove.
3. Confira a instalação:
   ```bash
   asg doctor
   ```
   <img src="docs/images/doctor.png" alt="asg doctor" width="560">
4. Teste: peça ao agente *"clone https://github.com/octocat/Hello-World"* e veja o veredito do ASG aparecer.
5. Abra o painel: `asg dashboard --open`.

> Se `asg` não for reconhecido, use o caminho completo (`~/.asg-security-guardian/bin/asg`, ou `asg.cmd` no
> Windows) ou reinstale com `--add-to-path`.

## 🔍 Como funciona

```mermaid
flowchart LR
    U["Você"] -->|"pede"| AG["Claude Code / Codex"]
    AG -->|"git clone, curl -o, gh repo clone…"| GH[("GitHub")]
    AG -.->|"PreToolUse: pip install git+, curl | sh"| ASK{"ASG<br/>confirma / bloqueia"}
    GH --> DL["pasta ou arquivo baixado"]
    DL -->|"PostToolUse"| SCAN["ASG Protection Core<br/>análise estática<br/>sem rede · sem executar"]
    SCAN --> V{"Veredito"}
    V -->|"REVISAR / INCONCLUSIVO"| STOP["agente para e pergunta"]
    V -->|"indicadores / sem indicadores"| CTX["agente recebe o resumo"]
    SCAN --> R[("~/.asg-security-guardian<br/>relatórios · painel · auditoria")]
    STOP --> U
    CTX --> U
```

| Momento | Gatilho | O que o ASG faz |
|---|---|---|
| **Antes** de rodar o comando | `pip/uv install git+…`, `npm/pnpm/yarn add github:…`, `npx github:…`, `curl/wget … \| sh`, `irm/iwr … \| iex`, `go install github.com/…`, `cargo install --git` | Claude Code: pede sua confirmação. Codex: nega e orienta o agente a clonar primeiro. |
| **Depois** de baixar | `git clone`, `gh repo clone`, `git submodule add`, `gh release download`, `curl -o/-O`, `wget`, `Invoke-WebRequest -OutFile` | Analisa o que chegou e mostra o veredito em uma linha. O agente recebe os achados e as regras de conduta. Com indicadores fortes, o agente é instruído a parar e perguntar. |
| **Ao abrir** uma sessão | início ou retomada | Analisa plugins, marketplaces e skills novos ou alterados desde a última sessão. |
| **Quando você pedir** | `/asg-security-guardian`, `$asg-security-guardian`, `asg scan` | Investigação guiada pela Skill, com relatório em 11 seções e nenhuma ação sem sua aprovação. |

**Princípio central:** o agente investiga e recomenda; **você decide**; o Core verifica, aplica só o que foi
autorizado e registra evidências.

## 🖼️ Telas

**Claude Code: um repositório com indicadores fortes é clonado**

<img src="docs/images/claude-hook.png" alt="Hook do ASG no Claude Code" width="880">

**Codex: instalação direta do GitHub bloqueada, clone analisado**

<img src="docs/images/codex-hook.png" alt="Hook do ASG no Codex" width="880">

**Painel local (`asg dashboard --open`)**

<img src="docs/images/dashboard.png" alt="Painel do ASG com três análises" width="880">

**Painel de ações: o que foi bloqueado, confirmado e colocado em quarentena (`asg dashboard --actions`)**

Cada decisão do ASG fica num registro de auditoria local encadeado por hashes. A aba **Ações** mostra a linha do
tempo, os totais e se o registro continua íntegro:

| Evento | Quando aparece |
|---|---|
| 🟥 **Instalação bloqueada** | o Codex tentou instalar/executar algo direto do GitHub e o ASG negou |
| 🟧 **Confirmação solicitada** | o Claude Code tentou o mesmo e o ASG pediu sua confirmação |
| 🟨 **Instalação executada após confirmação** | você aprovou e o comando rodou |
| 🔎 **Análise automática / manual** | cada clone, download ou `asg scan`, com o veredito |
| 🧪 **Quarentena proposta / executada / negada** | o fluxo de aprovação da cópia para quarentena |
| 🧷 **Baseline / verificação de integridade** | fotos de hashes e alterações detectadas |

<img src="docs/images/dashboard-actions.png" alt="Aba Ações do painel do ASG" width="880">

A mesma linha do tempo no terminal, com `asg log`:

<img src="docs/images/log.png" alt="asg log" width="880">

Comandos com credenciais (`https://usuario:token@…`, `TOKEN=…`, cabeçalhos `Authorization`) são gravados já
**redigidos**. O painel avisa em destaque se o registro de auditoria tiver sido alterado.

<sub>As telas usam repositórios de demonstração sintéticos (`example/...`). O texto do ASG é a saída real da
ferramenta; as respostas dos agentes são ilustrativas.</sub>

## 💼 Casos de uso

**1. "Achei um repositório legal, instala pra mim."**
Você pede ao agente para clonar e instalar uma ferramenta. O ASG analisa o clone; se houver `postinstall`, rede,
ofuscação ou hooks do Claude, o agente mostra os achados **antes** do `npm install`.

**2. Skills e plugins de terceiros.**
Antes de copiar uma skill para `~/.claude/skills` ou `~/.agents/skills`, o ASG procura prompt injection, comandos
embutidos e configurações que rodam sozinhas. Plugins instalados pelo menu são analisados na sessão seguinte.

**3. Servidores MCP.**
Um repositório com `.mcp.json` é sinalizado (AI003): você revisa qual comando o servidor executa antes de aprovar.

**4. "O README manda rodar `curl … | bash`."**
O padrão é bloqueado/perguntado. O caminho seguro vira: clonar, deixar o ASG analisar, ler o script e só então
rodar a partir da pasta local.

**5. Releases e arquivos compactados.**
`gh release download` ou `curl -o pacote.zip`: o ASG inspeciona metadados de ZIP/TAR (caminhos `../`, links,
membros gigantes) **sem extrair**.

**6. Investigação sob demanda.**
`/asg-security-guardian investigue ~/Downloads/projeto-x` (Claude) ou `$asg-security-guardian …` (Codex): o
agente conduz a investigação em fases (escopo, inventário, análise, dependências, risco, relatório) e só propõe
ações uma de cada vez.

**7. Acompanhar mudanças numa pasta.**
`asg baseline` + `asg check` mostram arquivos adicionados, alterados e removidos, útil depois de atualizar uma
dependência ou um plugin.

**8. Auditar o que o agente tentou fazer.**
No fim do dia, `asg dashboard --actions` (ou `asg log`) mostra quais instalações foram bloqueadas, quais você
aprovou, quais repositórios foram marcados para revisão e se o registro de auditoria continua íntegro.

## ⌨️ Atalhos e comandos

**Dentro do agente**

| Ação | Claude Code | Codex |
|---|---|---|
| Chamar a Skill | `/asg-security-guardian` | `$asg-security-guardian` ou `/skills` |
| Investigar uma pasta | `/asg-security-guardian analise ~/Downloads/x` | `$asg-security-guardian analise ~/Downloads/x` |
| Ver/confiar nos hooks | `/hooks` | `/hooks` (obrigatório uma vez) |
| Pedido em linguagem natural | "Antes de instalar, roda o ASG e me explica os achados" | idem |

**No terminal**

| Comando | O que faz |
|---|---|
| `asg scan CAMINHO` | análise estática (relatório JSON + Markdown e painel atualizado) |
| `asg dashboard --open` | abre o painel (aba Análises) |
| `asg dashboard --actions` | abre o painel direto na aba Ações |
| `asg log [--limit N] [--type TIPO]` | linha do tempo de bloqueios, confirmações, análises e quarentena no terminal |
| `asg doctor` | verifica instalação, integridade, Skills e hooks |
| `asg baseline CAMINHO` / `asg check CAMINHO` | foto dos hashes / comparação com a foto |
| `asg watch CAMINHO --interval 10` | acompanha mudanças por polling (só detecta) |
| `asg propose-quarantine ARQUIVO` | propõe uma cópia para quarentena (nada muda ainda) |
| `asg approve ID` | você digita `APPROVE ID` para confirmar a cópia |
| `asg verify-audit` | confere a cadeia de hashes da auditoria |
| `asg version` · `asg uninstall` | versão · remove a instalação |

**Arquivos úteis**

| Caminho | Conteúdo |
|---|---|
| `~/.asg-security-guardian/dashboard.html` | painel |
| `~/.asg-security-guardian/reports/` | relatórios `asg-<id>.md` e `.json` |
| `~/.asg-security-guardian/audit.jsonl` | auditoria encadeada |
| `~/.asg-security-guardian/config.json` | idioma (`"lang": "pt" \| "en"`) |

## 🚦 Como ler o veredito

| Veredito | Significado | O que o agente faz |
|---|---|---|
| **REVISAR ANTES DE USAR** | há indicadores fortes: segredo exposto, prompt injection, hooks do Claude no projeto, `curl \| sh`, download-e-execução em PowerShell, enfraquecimento do Defender, acesso a credenciais, persistência ou caminho perigoso em arquivo compactado | para e pede sua decisão |
| **INCONCLUSIVO** | a análise não terminou (limite de arquivos, falha de leitura ou Core alterado) | trata como não verificado |
| **INDICADORES** | sinais heurísticos sem indicador forte (rede, processos, `postinstall`, base64…) | segue com cautela e mostra o resumo |
| **SEM INDICADORES** | nada encontrado nas verificações feitas | segue; **não é garantia de segurança** |

Severidades: `CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`, e `INCONCLUSIVE` para cobertura insuficiente.

## 🔎 O que o ASG procura

| ID | Severidade | O quê |
|---|---|---|
| SECRET | CRITICAL | valor parecido com segredo (o valor **nunca** é guardado nem exibido) |
| AI001 | HIGH | frases de prompt injection ou de exfiltração ("ignore all previous instructions", "send the tokens to…") |
| AI002 | HIGH / MEDIUM | `.claude/settings*.json` no projeto (HIGH se define hooks ou helpers) |
| AI003 · AI004 · AI005 | MEDIUM · INFO | `.mcp.json` · `CLAUDE.md`/`AGENTS.md` · skills/commands/agents |
| PIPE001 · PS001 · PS002 | HIGH | `curl \| sh` · `IEX`/`DownloadString`/`-EncodedCommand` · exclusão do Defender, `ExecutionPolicy Bypass` |
| EXEC001 · PROC001 · NET001 · OBF001 | HIGH/MEDIUM | `eval`/`exec` · processos · rede · base64/ofuscação |
| PERS001 · PRIV001 · CRED001 | HIGH | persistência · privilégios · arquivos de credenciais e cookies |
| PKG001 · PKG002 · CI001 | MEDIUM | `postinstall`/`preinstall` · hooks de build Python · segredos e permissões em CI |
| ARCHIVE001–005 | HIGH…INFO | ZIP/TAR com `../`, links, membros enormes ou aninhados |
| BINARY001 | INFO | binário presente (não analisado) |
| COVERAGE001 · ARCHIVEERR | INCONCLUSIVE | análise parcial ou falha do parser |

Em documentação (`.md`, `.txt`, `.rst`), as regras de código caem um nível e são marcadas *"mentioned in
documentation"*. Prompt injection e segredos mantêm a severidade, porque é justamente em texto que eles aparecem.

## ⚙️ Configuração

| Ajuste | Onde | Padrão |
|---|---|---|
| Idioma das mensagens | `--lang en` na instalação ou `~/.asg-security-guardian/config.json` | `pt` |
| Pasta de estado | variável `ASG_STATE` | `~/.asg-security-guardian` |
| Máximo de arquivos por análise automática | variável `ASG_HOOK_MAX_FILES` | `20000` |
| Pasta do Claude / do Codex | `CLAUDE_CONFIG_DIR` / `CODEX_HOME` | `~/.claude` / `~/.codex` |
| Somente Skill, sem hooks | `--no-hooks` | hooks ativos |

## 🔒 Privacidade e segurança do próprio ASG

- **100% local:** nenhuma chamada de rede, nenhuma telemetria, nenhum upload.
- **Somente leitura:** não executa, importa, instala nem extrai o conteúdo analisado; não segue symlinks.
- **Segredos redigidos:** o valor nunca vai para relatório, painel ou mensagem, nem quando outra regra aponta a mesma linha.
- **Integridade:** o Core instalado tem um manifesto SHA-256. Se for alterado, o hook responde INCONCLUSIVO em vez de "limpo".
- **Sem autoridade do alvo:** nada dentro do projeto analisado consegue suprimir achados nem mudar a política.
- **Aprovação por ação:** a quarentena exige `APPROVE <ID>` digitado por você; o agente não consegue aprovar sozinho.
- **Mensagens com `~`:** a pasta pessoal aparece como `~`, para não expor seu nome de usuário em transcrições.
- **Falha aberta, mas honesta:** se o ASG der erro, seu trabalho continua, mas a mensagem diz INCONCLUSIVO.

## ⚠️ Limitações

- Heurísticas estáticas: não há AST, fluxo de dados, SCA/SBOM nem análise de binários. Espere falsos positivos
  (o próprio código-fonte do ASG dispara regras, porque contém os padrões que procura) e falsos negativos.
- Só vê o que passa pela ferramenta de shell do agente. Downloads pelo navegador, pela busca web do agente ou
  por outros programas não são vistos. Plugins instalados pelo menu `/plugin` são analisados na sessão seguinte.
- A leitura dos comandos é best-effort: variáveis, aliases ou scripts que clonam internamente podem escapar.
- No Codex, `PreToolUse` não suporta "perguntar"; por isso o ASG nega e explica. Os hooks precisam ser
  confiados uma vez via `/hooks`.
- Hooks são uma proteção para o agente, não uma barreira contra um atacante com acesso à máquina.

## 🔄 Atualizar e desinstalar

```bash
# atualizar: rode o mesmo comando de instalação (ou, no clone:)
git pull && python install.py

# desinstalar (mantém relatórios e auditoria)
asg uninstall
```

## ❓ Perguntas frequentes

<details><summary><b>O ASG deixa meu agente mais lento?</b></summary>

Não para comandos comuns: o hook só faz trabalho quando o comando é um download ou uma instalação do GitHub.
A análise de um repositório típico leva de frações de segundo a poucos segundos.
</details>

<details><summary><b>Recebi "REVISAR" num projeto conhecido e confiável. É malware?</b></summary>

Provavelmente não. Ferramentas de segurança, instaladores e projetos que documentam ataques disparam as
regras. Abra o relatório, veja o contexto de cada achado e decida. Se for um falso positivo claro, abra uma
[issue de falso positivo](https://github.com/carlos-dataengineer/asg-security-guardian/issues/new/choose).
</details>

<details><summary><b>Onde vejo o que o ASG bloqueou?</b></summary>

Na aba **Ações** do painel (`asg dashboard --actions`) ou no terminal com `asg log`. Os eventos ficam em
`~/.asg-security-guardian/audit.jsonl`, encadeados por hashes. Se alguém editar o arquivo, o painel mostra
**AUDITORIA ALTERADA**. Ressalva: um administrador local ainda consegue reescrever o arquivo inteiro e
recalcular a cadeia; não é armazenamento imutável.
</details>

<details><summary><b>Funciona sem o Claude Code ou o Codex?</b></summary>

Sim: `asg scan`, `asg dashboard` e os comandos de baseline/quarentena funcionam sozinhos no terminal.
</details>

<details><summary><b>Por que o Codex bloqueia em vez de perguntar?</b></summary>

A especificação de hooks do Codex ainda não suporta `permissionDecision: "ask"`. Ao bloquear, o ASG explica ao
agente o caminho seguro (clonar → analisar → mostrar → instalar da pasta local, com sua aprovação).
</details>

<details><summary><b>O ASG altera meus arquivos ou minhas configurações?</b></summary>

Só os da instalação: Skills, hooks (com backup `*.asg-backup-*` ao lado) e a pasta `~/.asg-security-guardian`.
Ele nunca altera, move nem apaga o conteúdo analisado.
</details>

<details><summary><b>Posso usar só a Skill, sem hooks?</b></summary>

Sim: `python install.py --no-hooks`.
</details>

## 🗂️ Estrutura do repositório

```
.claude/skills/asg-security-guardian/SKILL.md   Skill (Claude Code e Codex)
protection_core/
  asg_guard.py       scanner estático e relatórios
  asg_hook.py        hooks PreToolUse / PostToolUse / SessionStart
  asg_local.py       baseline, quarentena por cópia, auditoria
  asg_dashboard.py   painel HTML local (Análises + Ações)
  asg_cli.py         comando `asg`
install.py           instalador (Claude Code + Codex)
install.ps1 / .sh    instalação em um comando
config/policy.json   política local
docs/                arquitetura, guia de uso, telas
tests/               testes com fixtures sintéticas
```

Documentação: [INSTALL.md](INSTALL.md) · [docs/COMO-USAR.md](docs/COMO-USAR.md) · [docs/ARQUITETURA.md](docs/ARQUITETURA.md) · [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · [docs/LOCAL_CORE_0.2.md](docs/LOCAL_CORE_0.2.md) · [CHANGELOG.md](CHANGELOG.md)

## 🤝 Contribuir, segurança e licença

- Contribuições são bem-vindas: veja [CONTRIBUTING.md](CONTRIBUTING.md) e o [Código de Conduta](CODE_OF_CONDUCT.md).
- Encontrou uma vulnerabilidade? **Não abra issue pública**: use o [relato privado](https://github.com/carlos-dataengineer/asg-security-guardian/security/advisories/new) ([SECURITY.md](SECURITY.md)).
- Licença [MIT](LICENSE).
