# Enterprise readiness assessment — 0.12.0

Current release: see the [0.12 follow-up review](GAP_REVIEW.md) for rolling recovery, source inventories, AI ledger recovery and developer infrastructure evidence. The project now provides 19 collectors, 27 parsers and nine notebooks. The controls and production acceptance owners below continue to apply.

Initial assessment baseline: `c69f1ba` (0.10.0), 7 September 2026. This release implements an enterprise deployment baseline for a read-only incident evidence tool. Production acceptance still depends on tenant permissions, identity configuration, durable storage, operating ownership and live source validation. It is not a certification, completeness guarantee or multi-tenant SaaS service.

## Findings and implemented controls

| Finding at baseline | Improvement in 0.11.0 | Verification |
| --- | --- | --- |
| Shared viewer accepted arbitrary filesystem paths without authentication | OIDC mode, issuer/subject allowlist, explicit case assignments, identity expiry checks, pinned case manifests and required trusted signatures; local mode requires a loopback bind | Authorized signed case, unknown user/tenant, expired identity, cross-case denial and missing signature tests |
| Published evidence inherited ambient filesystem permissions | Private POSIX output directories/files, private ledger creation before SQLite opens it, symlink rejection for private storage, bounded input copying | Permission and symlink regression tests |
| Manifest JSON accepted duplicate keys and weak size types; special files could block hashing | Strict bounded JSON, integer lengths, required metadata/provenance, canonical paths, rejection of symlinks/FIFOs/special files, bounded member enumeration | Adversarial manifests and FIFO tests; historical demo verification |
| Offline ingestion lacked aggregate resource budgets | Configurable input bytes, input count, expanded records, emitted events and IOC cardinality limits, with no partial publication on breach | Every limit exercised, including quarantine mode |
| Collector recovery required manual SQLite/file manipulation | `timeline-ops backup/restore`, consistent SQLite snapshot plus committed blobs, independent snapshot pin, publication inventory, non-overwriting restore | Interrupted-window resume, completed replay, corrupt/extra/symlink files, missing/tampered published evidence |
| Operators lacked machine-readable collection health | Read-only JSON and Prometheus output, per-source acquisition age, pending runs, watermark lag, deep blob/bundle verification and explicit exit codes | Read-only checks, stale/missing state, metrics without raw source IDs |
| An interrupted acquisition could resume under another parser version | Parser version stored with new run checkpoints; incomplete mismatches and unknown legacy versions stop before API access | Upgrade failure tests and existing completed replay suite |
| Databricks processing staged SQLite beside Volume output | Normalize/export on driver-local disk; sequential Files API uploads with manifests last, bounded conflict verification and partial-upload recovery | Fake SDK normalization/export tests and existing Spark/Delta gate; live Volume validation still required |
| Dependencies and Actions changed without a pinned deployment baseline | Hash-locked Python 3.12 runtime/build dependencies, pinned Actions and container base digest, Dependabot, dependency audit/SBOM, CodeQL, unprivileged offline container CI, main-build attestations | CI gates, dependency scans, wheel/resource verification |
| Operating procedures and release responsibilities were missing | Security policy, code ownership, PR template, deployment/operations guides, recovery notebook and importable main ruleset | Repository review and documented live acceptance evidence |

The existing 18 collectors, 25 parser contracts, nine pinned OCSF classes, Tines stories, Databricks publication, signatures and AI budgets remain part of the regression suite. Source completeness is reported separately from drained pagination. Unmapped OCSF records retain explicit rejection receipts.

## Acceptance boundaries and ownership

| Control | Required production evidence | Owner |
| --- | --- | --- |
| GitHub branch protection | Import `deploy/github-main-ruleset.json`; assign a second reviewer; verify required check names and CodeQL alerts; prohibit direct pushes | Repository administrator |
| Identity and case separation | Real OIDC login/logout, wrong tenant, unassigned case, expired identity, revoked signer; TLS proxy reachable only through approved routes | IAM and application owner |
| Source acquisition | Verify each tenant/account/project, API scopes, enabled feeds, retention, time basis, pagination and late delivery against provider exports | Detection engineering/source owners |
| Recovery and availability | Restore state, published bundles and independent pins on replacement infrastructure; stop the original writer; measure recovery time and data loss | Platform operations/evidence custodian |
| Data governance | Encryption/KMS, approved regions, immutable evidence storage, retention and legal-hold decisions, least privilege and access-log retention | Data governance and security |
| Databricks/Tines | Production service principals, fixed job policy, Volume grants, signer trust, replay/partial failure and committed-view checks | Automation and data platform owners |
| AI egress | Approved provider/data scope, minimized requests, durable ledger, case-budget enforcement and independently reviewed task quality | AI security and incident response |
| Capacity and support | Representative incident workload, disk quotas, collector lag thresholds, patch owner, alert delivery and support escalation | Service owner |

The connected GitHub App excludes administration access. Main was unprotected during this assessment. The supplied ruleset is a concrete admin deliverable; adding it to git does **not** enable protection. No tenant credentials, identity provider, KMS policy, WORM retention policy or external scheduler was configured by this release.

## Deployment scope

Use one active writer per collector state directory on durable local POSIX storage. SQLite state is not a shared multi-host coordination service. Preserve fixed collection boundaries until a batch completes before advancing the scheduler's requested end time. Keep all real state/evidence and keys out of git. For HA, use a fenced active/passive process with tested storage recovery; active/active distributed scheduling and a centralized multi-host AI budget service are outside this architecture.

The shared UI only reads authorized signed evidence. It does not grant collection, signing, AI, publishing or case administration capabilities. Those privileges belong to separate OS/service identities. A user with filesystem access as the service account can bypass application controls; protect the host, deployment policy and signer trust independently.

## Token use and model routing

Collection, normalization, verification, recovery, OCSF mapping, grouping and cost preview require **zero model tokens**. Retain the existing single-call routes: `gpt-5.6-luna` for summarize, `gpt-5.6-terra` for correlate and explicitly requested `gpt-6-astra` review. Never call a model per event or automatically escalate. The harness caps input/output, preserves successful cache entries and keeps uncertain reservations charged. See [AI policy](AI_HARNESS.md) for current configurable IDs, price assumptions and quality limits.

Read [deployment](DEPLOYMENT.md), [operations](OPERATIONS.md), [threat model](THREAT_MODEL.md) and [validation](VALIDATION.md) before production acceptance.
