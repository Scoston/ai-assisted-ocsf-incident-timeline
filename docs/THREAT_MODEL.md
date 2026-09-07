# Threat model

Assets: original evidence bytes, provenance, collector cursors/watermarks, signing keys and trust, case authorization, provider credentials, AI requests/results/budgets and publication receipts.

| Threat | Controls | Remaining boundary |
| --- | --- | --- |
| Malicious source records or paths | Strict readers, canonical bundle membership, schema validation, no source execution, safe CSV, no unsafe HTML | Sandboxed resource limits and trusted host/filesystem are required |
| Artifact substitution | Full-file hashes, independent manifest pins, optional Ed25519 trust; required signatures in shared viewer | Signer compromise, misleading source content and untrusted timestamps need separate investigation |
| Cross-case data access | OIDC issuer/subject authorization, fixed case mapping, expiry checks, signed/pinned evidence, read-only view | OS access, reverse proxy, session revocation and policy deployment are platform responsibilities |
| Partial collection or data loss | Durable page-before-cursor commits, bounded retries, no blind POST retries, pagination/cap checks, health and verified snapshots | Source retention, excluded log categories and delayed delivery remain explicit collection gaps |
| Resource exhaustion | Response/document/line limits, ingestion counters, bounded AI context and calls | Host CPU/memory/disk quotas, scheduler deadlines and ingress rate limits |
| Credential or evidence egress | Explicit provider endpoints, no redirects, minimized opt-in AI, separate ledger, sanitized monitoring errors | Secret manager, network allowlists, permitted regions and model output review |
| AI prompt injection or fabricated conclusions | Untrusted-data instructions, no tools/actions, strict response/citation validation, human review | Model conclusions can still be wrong; citations are not proof of faithfulness |
| Supply-chain compromise | Hash locks, pinned Actions/base image, advisory scans, CodeQL, reviewed PRs, build provenance | Admin-enforced protection, upstream reviews, OS scanning and timely patching |

Trust the operating system, interpreter, deployed package, configured IdP and administrative policy. Do not assume that a collector's source label verifies its tenant, that hashes prove source authenticity, or that one local SQLite ledger enforces a budget across independent hosts. No automated containment or destructive response is implemented.
