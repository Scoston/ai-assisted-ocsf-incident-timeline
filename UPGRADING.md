# Upgrading

## From 0.11 to 0.12

Stop and fence old collector processes and take a verified backup before upgrading. State migration now runs in one serialized transaction and adds a pending window end and hashed policy contract. Do not run old and new binaries against the same migrated state. One matching pre-upgrade rolling window is adopted automatically, including a published window whose watermark commit was interrupted. Multiple conflicting legacy windows fail closed: retain both states/bundles, reconcile their reports, and start an explicitly inventoried replacement acquisition instead of editing SQLite. Pending parser-version checks still apply.

Keep the original source configuration, initial start, case prefix, output root and window policy. `--end now` uses a default five-minute settling delay; adjust `--settling-seconds` for source delivery. The first resumed invocation finishes the frozen partial window before planning another. Do not shrink the end past that pending boundary.

Existing parsers and evidence IDs are unchanged. GitHub/Kubernetes parsers start at 1.0.0; OCSF mapping advances to 1.2.0 while historical 1.0.0/1.1.0 exports remain verifiable. Re-export into a new directory and redeploy the current wheel for new mappings. Update monitoring with an expected-source inventory. AI ledger recovery is additive and preserves old charges/cache rows; restore into a new directory and keep the original writer fenced. See [operations](docs/OPERATIONS.md) and [follow-up review](docs/GAP_REVIEW.md).

## From 0.10 to 0.11

Read [enterprise readiness](docs/ENTERPRISE_READINESS.md), [deployment](docs/DEPLOYMENT.md) and [operations](docs/OPERATIONS.md). Finish active windows with the old release before upgrading. The state schema adds a nullable parser version: new runs bind it; incomplete legacy/changed-version runs with committed pages fail before network access. Completed old runs remain replayable. Back up state and published evidence before migration; do not roll a migrated active state back by editing SQLite.

Offline ingestion now has explicit aggregate budgets and rejects direct `/Volumes/` output. Use the updated Databricks normalization/OCSF adapters, which stage locally and upload manifests last. Redeploy the wheel and job configuration; the OCSF task now declares the Databricks SDK dependency. Give the driver adequate local disk space.

Manifest 2.0, parser versions and OCSF mapping versions are unchanged. Existing well-formed bundles verify; previously accepted duplicate JSON keys, invalid lengths, noncanonical paths or special files are rejected. Preserve rejected originals rather than rewriting evidence to bypass checks.

Local viewer mode requires a loopback bind; shared access requires the new OIDC/pinned-policy setup. Generated POSIX files are private to their owner. Provision deliberate service/group access through your platform instead of relying on ambient world-readable permissions. The deployment lock is specifically Linux/Python 3.12.

## From 0.9 to 0.10

Reinstall the package with `.[collection,databricks]` for the expanded collectors. Copy the new source examples and scope one configuration to each account/region, table, feed or application. Existing four-source collection reports and checkpoints remain compatible. New reports add a source-specific `window_basis`; late delivered or updated evidence can have a timeline timestamp outside that collection window.

M365 and GuardDuty parsers change to 2.1.0 for source UTC semantics and native remote IP fields. Their re-ingested event IDs intentionally change; preserve existing evidence and reconcile versions when querying across old/new bundles. Four additional parsers start at 1.0.0. OCSF export mapping advances to 1.1.0; historical 1.0.0 exports still verify. Re-export into a new directory and redeploy the current wheel when adopting new Databricks mappings. Remove obsolete wheel files before deployment with a `dist/*.whl` pattern.

No new live collector is activated during upgrade. See [enterprise coverage](docs/COLLECTOR_COVERAGE.md) and [API/authentication contracts](docs/ENTERPRISE_APIS.md) for supported formats, query caps, permissions and live acceptance.

## From 0.8 to 0.9

Install `.[signing]` for local signature operations and reinstall the wheel for the new CLI. Existing bundles and parser/event identities remain unchanged; signatures are detached. Unsigned verification/publication defaults remain compatible. Configure `require_signature=true` plus the fixed sidecar root, trust policy path and independent pin when deploying a required-signature Databricks job. Redeploy both the job definition and wheel; uploading a signature alone does not enable enforcement. The deployed export/inspection tasks now use positional wheel entry points to avoid notebook parameter overrides. Interactive notebooks remain available for analyst use.

Signed publications add the insert-only `signature_verifications` table. Revocation blocks new checks under the updated policy, while historical receipts and published data remain retained. Update consumers to the current policy and pin through your controlled deployment process. See [signing and rotation](docs/SIGNING.md).

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
