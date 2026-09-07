# Upgrade from the nested 0.4 demo

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
