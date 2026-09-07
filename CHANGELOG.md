# Changelog

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
