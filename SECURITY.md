# Política de segurança / Security Policy

## Situação do projeto

O ASG Security Guardian é um **protótipo defensivo experimental**. Não é antivírus, EDR, removedor de malware
nem controle de segurança de produção. Um relatório limpo não prova que um projeto é seguro.

ASG Security Guardian is an experimental defensive prototype, not an antivirus or EDR.

## Versões com suporte

| Versão | Suporte |
|---|---|
| 0.3.x | ✅ correções de segurança |
| < 0.3 | ❌ atualize com o instalador |

## Como reportar uma vulnerabilidade

Use o **relato privado de vulnerabilidades do GitHub**:
<https://github.com/carlos-dataengineer/asg-security-guardian/security/advisories/new>

Não abra issue pública com detalhes de exploração, credenciais, chaves privadas, dados pessoais ou amostras de
malware. Inclua: versão (`asg version`), sistema operacional, agente (Claude Code/Codex), passos mínimos e impacto.
Resposta inicial esperada em até 7 dias.

Exemplos do que é relevante: um jeito de o conteúdo analisado executar código durante a análise; um caminho que
faça o hook relatar "sem indicadores" quando a análise falhou; vazamento de segredo em relatório; um repositório
capaz de alterar a política do ASG, os relatórios ou o ledger de auditoria; bypass do manifesto de integridade.

## Testes seguros

- Teste somente em sistemas e arquivos seus ou com autorização explícita.
- Use fixtures sintéticas e ambientes descartáveis; não execute código não confiável.
- Trate os achados heurísticos como pistas que exigem validação humana.

## Limites de escopo

O protótipo não oferece monitoramento de kernel, bloqueio de processos, controle de rede, sandbox, análise
completa de dependências nem detecção garantida de malware. Os hooks são uma proteção para agentes de IA, não
uma barreira contra um atacante determinado com acesso à máquina.
