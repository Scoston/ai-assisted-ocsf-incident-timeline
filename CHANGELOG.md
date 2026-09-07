# Changelog

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
