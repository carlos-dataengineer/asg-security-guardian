# Como contribuir

Obrigado pelo interesse em contribuir com o ASG Security Guardian.

## Como enviar uma contribuição

1. Faça um fork do repositório.
2. Crie uma branch para sua alteração.
3. Faça mudanças pequenas e explique o motivo.
4. Inclua ou atualize testes quando alterar comportamento.
5. Execute `python -m pytest -q`.
6. Abra um Pull Request descrevendo o problema, a solução, os riscos e como testou.

## Regras de segurança

- Não envie malware real, credenciais, tokens, chaves privadas ou dados pessoais.
- Use somente exemplos sintéticos e arquivos de teste inofensivos.
- Não adicione execução automática de conteúdo analisado.
- Não introduza upload, telemetria remota ou chamadas de rede sem discussão e aprovação explícita.
- Preserve o princípio de autorização individual antes de qualquer operação que altere o sistema.
- Documente limitações, falsos positivos esperados e riscos novos.

## Revisão e versão oficial

Qualquer pessoa pode criar forks e manter versões independentes. Pull Requests são propostas, não autorização para alterar diretamente a versão oficial. O mantenedor revisa as contribuições e decide se serão integradas. Não faça commits diretos na branch principal; use seu fork e um Pull Request.

A licença MIT permite reutilização nos termos do arquivo [LICENSE](LICENSE), mas não concede a terceiros permissão de escrita no repositório oficial nem direito de representar suas versões como releases oficiais do ASG.
