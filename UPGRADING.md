# Upgrading

## From 0.7 to 0.8

The offline evaluator adds no runtime dependencies or model calls. Event IDs and parser versions are unchanged. Re-ingestion can add normalized IPv6 candidates to `extracted_iocs.json`, changing artifact and bundle hashes; old bundles remain verifiable. IPv6 zone identifiers are outside the candidate contract. Review the [published measurements and scoring rules](docs/EVALUATION.md).

## From 0.6 to 0.7

Install `.[collection,databricks]` to collect all four supported APIs. Keep collector state on a durable local filesystem separate from bundle output; preserve it when upgrading. The initial collector state format is 1.0.0.

Only the Tines audit parser changes to 2.1.0 to include native `request_ip`; re-ingesting Tines records intentionally produces new event IDs. Other parser identities remain 2.0.0. New manifest inputs include parser versions, so re-ingestion may produce a different bundle ID; historical bundles still verify without rewriting. Overlapping windows retain repeated receipts across bundles, so use event IDs when querying across collections. See [collection operations](docs/COLLECTION.md).

## From 0.5 to 0.6

Reinstall the package and redeploy the Databricks bundle to obtain the optional OCSF task. Existing evidence bundles, timeline fields, parser versions and event identities remain compatible. OCSF export writes to a separate new directory; it does not rewrite an existing bundle or convert project Parquet in place.

`ocsf_enabled=false` preserves ordinary job behavior. Enable it and configure `ocsf_export_root` to require pinned OCSF publication. Strict mode is the default; `ocsf_quarantine=true` permits partial exports whose rejected counts require review. See [OCSF migration and deployment](docs/OCSF_EXPORT.md).

Remove older wheel files from your local `dist/` directory before deploying a newly built wheel with the bundle's `dist/*.whl` artifact pattern.

## From the nested 0.4 demo

Use a clean checkout or remove the old editable installation before installing the root package:

```bash
python -m pip uninstall forensic-timeline-ai-demo
python -m pip install -e '.[dev,ai,databricks,notebooks,ui]'
```

| Old path or behavior | Replacement |
| --- | --- |
| `forensic_timeline_ai_repo/forensic_timeline_ai_repo/build/` | Repository root |
| `src.timeline_demo...` imports | `timeline_demo...` imports |
| `python -m src.timeline_demo.run_real_pipeline` with implicit sample paths | `timeline ingest` with explicit inputs, case ID and output directory |
| `streamlit_timeline_ui/app/app.py` | `streamlit_timeline_ui/app.py` |
| `data/raw/` | `examples/raw/` for shipped samples; use external evidence locations for real cases |
| Tracked bytecode, egg-info and generated build files | Removed; rebuilt locally and ignored by Git |
| Implicit UTC for missing zones | Explicit `--assume-timezone`, recorded in the output |
| Static manifest with `verified_evidence: true` | Version 2 artifact hashes and `timeline verify` |
| Automatic full-timeline AI call when a key exists | Explicit `timeline analyze --allow-ai` with task policy and durable ledger |
| `.env` implicitly loaded by the old runner | Process environment or your approved secret manager; no automatic `.env` loading |
| Windows PyInstaller demo packaging | Source installation and Streamlit launch; the stale executable build is retired |

Old generated bundles are not silently converted or declared verified. Re-ingest the original source exports into a new directory. Event identity, class mappings, time handling and manifest format changed, so do not combine old and new rows as if they were the same schema.

The three original parser function names remain as wrappers for callers using `timeline_demo.parsers.*`. The legacy `generate_ai_enrichment` helper returns a skipped result directing callers to the bounded harness.
