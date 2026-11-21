# Security Policy

## Project status
ASG Security Guardian is an experimental defensive prototype. It is not an antivirus, EDR, malware-removal utility, or production endpoint security control.

## Reporting a vulnerability
Do not publish exploit details, credentials, private keys, personal data, or malware samples in a public issue. Until a private vulnerability-reporting channel is configured, contact the repository maintainer through the GitHub profile and request a private disclosure channel.

## Safe testing
- Test only on systems and files you own or are explicitly authorized to assess.
- Do not run untrusted code as part of testing.
- Use synthetic fixtures and isolated disposable environments.
- Preserve original evidence; current quarantine copies files and does not delete originals.
- Treat heuristic findings as leads requiring human validation.

## Scope limitations
The current prototype does not provide kernel-level monitoring, process blocking, network enforcement, sandboxing, complete dependency analysis, or guaranteed malware detection. A clean scan is not proof that a project is safe.
