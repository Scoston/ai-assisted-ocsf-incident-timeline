# Changelog

## 0.13.0 — 2026-09-07

- Added a native Plaso backend covering all 59 parsers, 186 parser plugins and 4 cookie helpers at source revision 00fcc6e7f95a0, including VMware ESXi added after the latest release.
- Added source/image/storage ingestion, split-image companion handling, immutable source/dependency pins, runtime census validation, resource limits and isolated offline processing.
- Preserve acquired originals, Plaso storage, JSONL, commands, logs, source stat inventory and receipts; block missing plugins, export count mismatches and incomplete sessions/warnings unless explicitly allowed.
- Added the versioned `plaso_event` importer for JSONL, dynamic CSV and l2tcsv, including semantic-time rejection and detailed artifact provenance. Existing parser event IDs remain unchanged. OCSF mapping version 1.3.0 retains historical verification.
- Added the complete format catalog/table, operating guide, tenth Jupyter notebook, contract regressions, upstream native parser suite and real artifact/image/storage round-trip CI gate. Native processing uses zero model tokens.

## 0.12.0 — 2026-09-07

- Fixed interrupted partial rolling windows when subsequent invocations extend their end time; serialized schema migrations and conservative legacy-window adoption.
- Added clock-relative scheduling with settling delay, systemd examples and expected-source inventories/health metrics.
- Added read-only AI usage reporting and pinned SQLite-aware backup/restore retaining failed/pending charges and cached results; tightened provider token-usage validation.
- Added GitHub organization audit collector and Kubernetes audit parser, bringing coverage to 19 collector types and 27 parser contracts; OCSF mappings advance to 1.2.0 with historical verification.
- Added a ninth offline Jupyter notebook, source fixtures, regression tests, upgrade guidance and a follow-up enterprise assessment.

## 0.11.0 — 2026-09-07

- Added an enterprise readiness assessment, threat model, operating/recovery procedures, deployment baseline, security policy and administrator ruleset.
- Added `timeline-ops` health/Prometheus output and pinned, consistent checkpoint backup/restore, plus an eighth Jupyter recovery notebook.
- Added shared-viewer OIDC authentication, issuer/subject case authorization, identity expiry checks, required pinned signatures and access auditing. Local mode requires a loopback bind.
- Hardened manifests against duplicate keys, noncanonical paths, special files, invalid sizes and missing provenance; fixed nested manifest attachments being omitted from hashes.
- Added aggregate ingestion limits, private evidence/ledger files and durable local publication; incomplete collector checkpoints now bind their parser version.
- Moved Databricks normalization/OCSF SQLite staging to local disk and published Volume artifacts through sequential, resumable Files API uploads with manifests last.
- Added hash-locked runtime/build dependencies, pinned Actions/base image, Dependabot, advisory audits/SBOMs, CodeQL, unprivileged offline container verification and main-build provenance attestations.
- No paid model calls or new per-event AI processing; collector/parser/OCSF identity versions remain unchanged.

## 0.10.0 — 2026-09-07

- Evaluated enterprise incident coverage and added 14 collectors: Entra audit, M365 audit feeds, Defender alerts/hunting, Okta, Azure Activity/Monitor Logs, GCP Audit, Workspace audit, GuardDuty, Security Hub CSPM, CloudWatch Logs, Falcon alerts and Splunk.
- Added explicit source clocks, header pagination, durable list/detail and async-search checkpoints, bounded fixed queries and partial/truncated-result rejection. Late mailbox events and alert updates retain native event timestamps. Collection still consumes zero model tokens.
- Added four parsers, complete Workspace child-event expansion, native GuardDuty SDK projections and source-UTC M365 handling. M365/GuardDuty parser identities advance to 2.1.0; new OCSF mappings use 1.1.0 with historical export verification retained.
- Added eight Azure Monitor table choices including workload/noninteractive sign-ins, 14 Defender hunting tables, source-specific configuration examples, enterprise coverage/incident recipes, permissions/retention guidance and a seventh offline Jupyter notebook.
- Expanded API-contract, recovery, truncation, source-boundary and OCSF regression coverage. Live enterprise tenant acceptance remains external to the synthetic test suite.

## 0.9.0 — 2026-09-07

- Added detached Ed25519 signatures for exact evidence/OCSF manifests, encrypted key generation and strictly parsed signer policies with required independent hashes.
- Added versioned trust creation, key addition, scope restriction, verification-only retirement and revocation; no trusted timestamp or automatic signer identity is asserted.
- Added `timeline-sign`, required-signature flags for bundle/export verification, signed sidecar upload and fixed Databricks deployment policy.
- Added verification before Spark writes and before publication markers, insert-only signature receipts, and repeated source-trust checks in the OCSF task. Tines forwards the existing reference contract; signer policy stays in the deployment.
- Moved all deployed tasks to positional wheel entry points so job parameter pushdown cannot replace configured policy, export mode or inspection destination; retained interactive analyst notebooks.
- Added a sixth offline Jupyter notebook, signed real-Delta replay/revocation coverage, operational documentation and final roadmap reconciliation.

## 0.8.0 — 2026-09-07

- Added isolated synthetic scale benchmarks with exact source hashes, hardware/resource limits, runtime, peak RSS, source/artifact sizes, AI coverage and token upper bounds.
- Added parser and IOC truth fixtures, published measured results and a source-bound analyst-review scorer with separate claim precision/recall and citation faithfulness. No paid model evaluation is represented by the handwritten fixtures.
- The quality probe identified missing IPv6 extraction; added validated unscoped IPv6 candidates and stable IPv4-mapped formatting, with before/after diagnostic results.
- Added `timeline-evaluate`, an offline evaluation notebook, regression cases, CI smoke workloads and guidance for deploying/evaluating model routes.

## 0.7.0 — 2026-09-07

- Added Tines audit, Entra sign-in, regional CloudTrail event-history and Databricks system audit collectors with fixed read-only queries and credential references.
- Persist raw pages and record projections before cursor advancement; resume interruptions, enforce budgets, detect paging cycles/truncation and pin completed bundles.
- Added `collect` and `collect-until`, overlapping windows, atomic watermarks, raw response attachments, configuration examples and source coverage/operations documentation. Collection uses zero model tokens.
- Corrected native Tines `request_ip` mapping; only that parser advances to version 2.1.0. New manifests record each input parser version.
- Added 15 collection regression cases and the collection dependency extra.

## 0.6.0 — 2026-09-07

- Added deterministic core OCSF 1.3.0 export and verification for nine classes, with complete pinned JSON Schemas generated from the official catalog and reproducible generator/source hashes.
- Added required-field mappings, native OCSF validation, strict failure or explicit quarantine, source binding, provenance receipts and duplicate-reference detection. Export uses zero model tokens.
- Added `timeline export-ocsf` and `timeline verify-ocsf`, a fourth offline Jupyter notebook, and a separate export manifest.
- Added optional Databricks OCSF export job task, insert-only Delta events/rejections and a final publication marker/view; documented Tines strict failure and partial-success implications.
- Added OCSF regression coverage, expanded the real Delta replay gate and packaged schema/license verification. Existing 0.5 timeline and parser identities remain compatible.

## 0.5.0 — 2026-09-07

- Reorganized the nested demo into an installable package with an explicit CLI and dependency extras.
- Added raw evidence snapshots, bundle integrity checks, deterministic ordering, duplicate receipts, quarantine, CSV formula neutralization and optional Parquet export.
- Expanded source support from three parsers to 21 documented contracts; corrected class mapping and strict timestamp handling; retained every CrowdStrike behavior.
- Added dedicated Tines publish/monitor and run-inspection stories, plus deployment and operational implications documentation.
- Added Databricks Volume upload/download, repeat-safe Jobs submission/status, insert-only Delta publication, committed timeline view and deployment bundle.
- Added three Jupyter notebooks and two Databricks source notebooks.
- Added a token-bounded AI harness with explicit Luna/Terra/Astra task routes, durable budgets, validated citations, cache and analysis receipts.
- Replaced unsafe source-data HTML rendering with a read-only Streamlit viewer that checks bundle integrity.
- Added regression, notebook, packaging and Spark/Delta CI gates.

Breaking changes: package import paths, explicit CLI inputs, strict time zones, event identity, class mapping and manifest format. See `UPGRADING.md`.
