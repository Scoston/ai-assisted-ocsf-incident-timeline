# AI-assisted OCSF incident timeline

Build an investigation timeline from cloud, identity, endpoint, network, forensic exports and native artifacts. Preserve source files, normalize timestamps, retain parser provenance, verify artifact hashes, and add optional AI interpretation for human review.

**Version 0.14.0:** every AI analysis now has [evidence chunk IDs, complete audit export, zero-token evidence checks and mandatory human approval](docs/AI_EVIDENCE_AND_REVIEW.md). The project retains complete pinned log2timeline/Plaso coverage through a native backend: **59 parsers, 186 parser plugins and 4 cookie plugins**, with an auditable [format inventory and ingestion guide](docs/PLASO.md). The package now has 28 import/parser contracts, 19 checkpointed collector types and eleven Jupyter notebooks, alongside dedicated Tines stories, Databricks Volume/Jobs/Delta integration, signed manifests and a token-bounded AI harness. Native parsing, offline ingestion and OCSF export consume **zero model tokens**.

The timeline uses an **OCSF-aligned analytical profile**. The separate `export-ocsf` command emits validated core OCSF events for nine pinned classes; missing required fields are rejected explicitly. File integrity checks do not prove source authenticity, complete collection, accurate clocks, or legal admissibility. AI analysis is stored separately and cannot establish those properties.

Start with the [enterprise readiness assessment](docs/ENTERPRISE_READINESS.md) for implemented controls and the tenant, identity, storage and administrator acceptance work required before production use.

## Watch the feature demo

[![Watch the v0.13.0 feature demo](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/releases/download/demo-v0.13.0/timeline-v0.13.0-demo-poster.png)](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/releases/download/demo-v0.13.0/timeline-v0.13.0-demo.mp4)

**[Watch or download the narrated 1080p video](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/releases/download/demo-v0.13.0/timeline-v0.13.0-demo.mp4)** — approximately eight minutes, with captions and 20 chapters. It covers the viewer, evidence verification, collectors, Plaso, OCSF, signatures, Tines, Databricks, Jupyter, AI routing and budgets, recovery, and shared deployment. See the [chapter guide and transcript](docs/DEMO.md). The tour uses synthetic evidence and labels cloud configuration walkthroughs and simulated providers explicitly. It records v0.13.0; the new v0.14.0 approval workflow is demonstrated in [notebook 11](notebooks/11_ai_evidence_and_human_review.ipynb).

## Start locally

Python 3.10+:

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev,ai,databricks,collection,signing,notebooks,ui]'
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

Local viewer mode requires a loopback bind and starts with a verified example bundle. Shared mode requires OIDC, explicit case assignments, pinned manifests and trusted signatures; see [deployment](docs/DEPLOYMENT.md). Select a newly generated bundle in its sidebar. It displays an explicit event limit and verifies hashes before presenting the timeline.

## Integrations and analysis

| Need | Implemented path | Guide |
| --- | --- | --- |
| Enterprise operations | Health/Prometheus, consistent checkpoint backup/restore and parser upgrade boundaries | [Operations](docs/OPERATIONS.md) |
| Shared access and deployment | OIDC case authorization, locked dependencies, container, advisory scans and build provenance | [Deployment](docs/DEPLOYMENT.md) |
| Signed evidence | Detached bundle/export signatures, pinned signer policy, rotation/revocation and optional Databricks enforcement | [Signer setup and operating limits](docs/SIGNING.md) |
| Continuous collection | Fixed windows, durable pages/cursors and overlapping catch-up batches for 19 collector types | [Collection setup and coverage](docs/COLLECTION.md) |
| Tines orchestration | Importable publish/monitor and run-inspection stories; asynchronous receipts, bounded polling and stable Databricks idempotency keys | [Tines implementation and operational implications](integrations/tines/README.md) |
| Databricks | Upload/download verified bundles through Unity Catalog Volumes; submit/poll Jobs; publish insert-only Delta tables and committed views | [Databricks setup and acceptance](integrations/databricks/README.md) |
| Jupyter | Offline investigation, Databricks round trip, AI harness, OCSF export, evaluation, signer lifecycle and enterprise collection notebooks | [Notebooks](notebooks/README.md) |
| OCSF interoperability | Nine complete core class validators, strict/quarantine export, source binding and optional Databricks job task | [OCSF mappings, validation and deployment](docs/OCSF_EXPORT.md) |
| Evaluation | Reproducible runtime/RSS/coverage benchmarks, parser/IOC truth fixtures and analyst-label scorer | [Measurements and evaluation](docs/EVALUATION.md) |
| AI task harness | Optional single-call tasks, compact evidence groups, citations, durable case budgets and cache | [AI harness and model policy](docs/AI_HARNESS.md) |
| Native forensic artifacts | Complete pinned Plaso parser collection, artifact/image/storage ingestion, runtime coverage checks and retained evidence | [Native setup and every format](docs/PLASO.md) |
| Parsers | 28 named contracts with fixtures; JSON/JSONL/gzip/CSV/TSV/Parquet, exported Windows XML, RFC 5424 and VPC text readers | [Parser coverage and limits](docs/PARSERS.md) |
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

Detached signatures remain outside the bundle. Enable required-signature verification where signer authorization is needed; ordinary hash verification remains available.

Each bundle contains source snapshots under `evidence/`, ordered `timeline.jsonl`, presentation-safe `timeline.csv`, `receipts.jsonl`, `quarantine.jsonl`, extracted indicators, and a manifest covering every artifact. Add `--parquet` for a columnar analytical export. Raw file SHA-256 and deterministic record SHA-256 have different meanings; see [evidence design](docs/ARCHITECTURE.md).

By default, invalid records fail the run without exposing a partial bundle. `--quarantine` retains the source and an error receipt for each rejected record; malformed whole documents still fail. Missing time zones require an explicit `--assume-timezone UTC` or another IANA zone. The assumption is recorded.

## Development and verification

```bash
python -m pip install -e '.[dev,ai,databricks,collection,signing]'
ruff check src tests scripts streamlit_timeline_ui integrations/databricks integrations/plaso
pytest -q
python scripts/check_notebooks.py --kernel
python -m build
```

GitHub Actions tests Python 3.10/3.12, executes all ten notebooks, builds the distribution, runs real Spark/Delta replay and native Plaso validation, audits dependencies, runs CodeQL and exercises the installed wheel in an unprivileged offline container. Successful main builds attest the distribution. Tenant credentials are not used in CI. See [validation record](docs/VALIDATION.md) for results and live acceptance steps.

Upgrading from the nested 0.4 demo? Read [UPGRADING.md](UPGRADING.md). The original training catalogs and demo material remain in `catalogs/` and `docs/legacy_demo_guide.md`; catalogs describe investigation coverage and are not executable parsers.
