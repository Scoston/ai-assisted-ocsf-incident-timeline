# AI-assisted OCSF incident timeline

Build an investigation timeline from cloud, identity, endpoint, network and forensic exports. Preserve source files, normalize timestamps, retain parser provenance, verify artifact hashes, and add optional AI interpretation for human review.

**Version 0.7.0:** an installable Python package, 21 parser contracts, two dedicated Tines stories, Databricks Volume/Jobs/Delta integration, four Jupyter notebooks, a token-bounded AI harness, a schema-validated OCSF 1.3.0 export, and four checkpointed collectors. The offline pipeline and OCSF export require no API key and consume **zero model tokens**.

The timeline uses an **OCSF-aligned analytical profile**. The separate `export-ocsf` command emits validated core OCSF events for nine pinned classes; missing required fields are rejected explicitly. File integrity checks do not prove source authenticity, complete collection, accurate clocks, or legal admissibility. AI analysis is stored separately and cannot establish those properties.

## Start locally

Python 3.10+:

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev,ai,databricks,notebooks,ui]'
```

Run the bundled synthetic case; use a new output directory for each bundle:

```bash
timeline ingest --case-id demo-001 --input cloudtrail=examples/raw/aws/cloudtrail_real_sample.json --input entra_signin=examples/raw/entra/entra_signin_real_sample.jsonl --input crowdstrike_detection=examples/raw/edr/crowdstrike_detection_real_sample.json --output output/demo-001 --parquet
timeline verify output/demo-001
timeline export-ocsf output/demo-001 --output output/demo-001-ocsf
timeline verify-ocsf output/demo-001-ocsf --bundle output/demo-001
timeline parsers
```

The case produces five events. This is a sample count, not an alert-capacity benchmark. JSONL/CSV/Parquet readers stream records; SQLite handles timeline sorting and deduplication. Raw evidence storage, IOC cardinality, file size and runtime resources still limit a run. JSON documents and Windows XML exports have a 32 MiB limit; line-oriented records have a 4 MiB limit.

```bash
jupyter lab notebooks/
streamlit run streamlit_timeline_ui/app.py
```

The viewer starts with a verified example bundle. Select a newly generated bundle in its sidebar. It displays an explicit event limit and verifies hashes before presenting the timeline.

## Integrations and analysis

| Need | Implemented path | Guide |
| --- | --- | --- |
| Continuous collection | Fixed windows, durable pages/cursors and overlapping catch-up batches for four sources | [Collection setup and coverage](docs/COLLECTION.md) |
| Tines orchestration | Importable publish/monitor and run-inspection stories; asynchronous receipts, bounded polling and stable Databricks idempotency keys | [Tines implementation and operational implications](integrations/tines/README.md) |
| Databricks | Upload/download verified bundles through Unity Catalog Volumes; submit/poll Jobs; publish insert-only Delta tables and committed views | [Databricks setup and acceptance](integrations/databricks/README.md) |
| Jupyter | Offline investigation, Databricks round trip, AI harness and pinned OCSF export notebooks | [Notebooks](notebooks/README.md) |
| OCSF interoperability | Nine complete core class validators, strict/quarantine export, source binding and optional Databricks job task | [OCSF mappings, validation and deployment](docs/OCSF_EXPORT.md) |
| AI task harness | Optional single-call tasks, compact evidence groups, citations, durable case budgets and cache | [AI harness and model policy](docs/AI_HARNESS.md) |
| Parsers | 21 named contracts with fixtures; JSON/JSONL/gzip/CSV/TSV/Parquet, exported Windows XML, RFC 5424 and VPC text readers | [Parser coverage and limits](docs/PARSERS.md) |
| Review and improvement plan | Original findings, implemented work, acceptance requirements and next milestones | [Repository review and plan](docs/REVIEW_AND_PLAN.md) |

Preview AI cost boundaries without sending a request:

```bash
timeline analyze output/demo-001 --task summarize
```

After configuring `OPENAI_API_KEY` in your process environment and authorizing the minimized data for that provider:

```bash
timeline analyze output/demo-001 --task summarize --allow-ai --ledger analysis/usage.sqlite --output analysis/summary.json
```

The default routes are `gpt-5.6-luna` for summarization, `gpt-5.6-terra` for correlation and `gpt-6-astra` for explicitly requested critical review. Routing, reasoning effort and budgets are configurable. No automatic escalation or per-event model calls occur. These choices follow the [official model catalog](https://developers.openai.com/api/docs/models); evaluate quality on your own cases before enabling a route.

## Evidence bundle

Each bundle contains source snapshots under `evidence/`, ordered `timeline.jsonl`, presentation-safe `timeline.csv`, `receipts.jsonl`, `quarantine.jsonl`, extracted indicators, and a manifest covering every artifact. Add `--parquet` for a columnar analytical export. Raw file SHA-256 and deterministic record SHA-256 have different meanings; see [evidence design](docs/ARCHITECTURE.md).

By default, invalid records fail the run without exposing a partial bundle. `--quarantine` retains the source and an error receipt for each rejected record; malformed whole documents still fail. Missing time zones require an explicit `--assume-timezone UTC` or another IANA zone. The assumption is recorded.

## Development and verification

```bash
python -m pip install -e '.[dev,ai,databricks,collection]'
ruff check src tests scripts streamlit_timeline_ui integrations/databricks
pytest -q
python scripts/check_notebooks.py --kernel
python -m build
```

GitHub Actions tests Python 3.10/3.12, executes the notebooks, builds the distribution, and runs a separate real Spark/Delta replay gate. Tenant credentials are not used in CI. See [validation record](docs/VALIDATION.md) for results and live acceptance steps.

Upgrading from the nested 0.4 demo? Read [UPGRADING.md](UPGRADING.md). The original training catalogs and demo material remain in `catalogs/` and `docs/legacy_demo_guide.md`; catalogs describe investigation coverage and are not executable parsers.
