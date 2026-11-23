## O que muda / What changes

<!-- Problema, solução e riscos. Problem, solution and risks. -->

## Como testei / How I tested

- [ ] `python -m pytest -q` (ou `python tests/run_tests.py`)
- [ ] Testei o instalador em uma pasta descartável (`HOME`/`USERPROFILE` temporários) quando mexi em `install.py`

## Checklist

- [ ] Nenhum segredo, malware real ou dado pessoal nos arquivos ou fixtures (apenas exemplos sintéticos)
- [ ] O ASG continua sem executar o conteúdo analisado e sem acesso à rede
- [ ] Nenhuma ação que altera o sistema foi adicionada sem aprovação individual do usuário
- [ ] Documentação e `CHANGELOG.md` atualizados quando o comportamento mudou
