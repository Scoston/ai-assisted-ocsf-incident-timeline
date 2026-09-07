# Security policy

Use the latest reviewed release for fixes. Older releases retain evidence compatibility where documented, but this project does not promise a separate long-term support branch or response SLA.

Do not put customer evidence, credentials, private keys or exploit details in public issues. Report vulnerabilities using the repository's **Security → Report a vulnerability** private reporting channel when enabled. If that channel is unavailable, contact the repository owner through an established private channel and ask for a secure reporting method before sharing details. Repository administrators must enable private vulnerability reporting and own triage.

Include the affected version, minimal synthetic reproduction, expected/actual behavior and impact. Keep testing within systems you are authorized to assess. Ordinary bugs with synthetic fixtures can use issues/PRs.

See [threat model](docs/THREAT_MODEL.md), [deployment](docs/DEPLOYMENT.md) and [enterprise acceptance](docs/ENTERPRISE_READINESS.md). Dependency/security workflows provide findings; repository administrators must review alerts, enforce branch rules and operate the patch process.
