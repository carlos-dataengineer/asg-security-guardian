# Como contribuir

Obrigado pelo interesse em contribuir com o ASG Security Guardian.

## Ambiente de desenvolvimento

```bash
git clone https://github.com/<seu-usuario>/asg-security-guardian.git
cd asg-security-guardian
python -m pip install pytest      # opcional: há também tests/run_tests.py, sem dependências
python -m pytest -q
```

O projeto usa somente a biblioteca padrão do Python 3.10+. Não adicione dependências de terceiros ao Core.

Para testar o instalador **sem mexer na sua instalação real**, aponte `HOME`/`USERPROFILE` para uma pasta
temporária:

```bash
export HOME=/tmp/asg-home USERPROFILE=/tmp/asg-home   # Windows (Git Bash) funciona igual
mkdir -p "$HOME/.claude" "$HOME/.codex"
python install.py --target all
python "$HOME/.asg-security-guardian/app/asg_cli.py" doctor
```

## Estrutura

| Caminho | Papel |
|---|---|
| `protection_core/asg_guard.py` | scanner estático (regras, inventário, relatórios) |
| `protection_core/asg_hook.py` | hooks do Claude Code e do Codex |
| `protection_core/asg_local.py` | baseline, quarentena por cópia, ledger de auditoria |
| `protection_core/asg_dashboard.py` | painel HTML local |
| `protection_core/asg_cli.py` | comando `asg` |
| `install.py`, `install.sh`, `install.ps1` | instalação/desinstalação |
| `.claude/skills/asg-security-guardian/` | Skill (usada pelo Claude Code e pelo Codex) |
| `tests/` | testes com fixtures sintéticas |

## Como enviar uma contribuição

1. Faça um fork do repositório e crie uma branch.
2. Faça mudanças pequenas e explique o motivo.
3. Inclua ou atualize testes quando alterar comportamento. Mudou uma regra? Adicione um caso positivo **e** um negativo.
4. Execute `python -m pytest -q`.
5. Atualize `CHANGELOG.md` e a documentação.
6. Abra um Pull Request descrevendo problema, solução, riscos e como testou.

## Regras de segurança

- Não envie malware real, credenciais, tokens, chaves privadas ou dados pessoais. Use apenas exemplos sintéticos.
- Não adicione execução automática de conteúdo analisado.
- Não introduza upload, telemetria remota ou chamadas de rede sem discussão e aprovação explícita.
- Nenhum arquivo do projeto analisado pode suprimir achados ou alterar a política (não aceitamos "comentários de ignorar" lidos do alvo).
- Preserve o princípio de autorização individual antes de qualquer operação que altere o sistema.
- Documente limitações, falsos positivos esperados e riscos novos.

## Revisão e versão oficial

Qualquer pessoa pode criar forks e manter versões independentes. Pull Requests são propostas, não autorização para
alterar diretamente a versão oficial. O mantenedor revisa as contribuições e decide se serão integradas.

A licença MIT permite reutilização nos termos do arquivo [LICENSE](LICENSE), mas não concede a terceiros permissão de
escrita no repositório oficial nem direito de representar suas versões como releases oficiais do ASG.

Ao participar, você concorda com o [Código de Conduta](CODE_OF_CONDUCT.md).
