# Databricks integration

This implementation connects exported evidence, Unity Catalog Volumes, Databricks Jobs, Delta tables and Jupyter. It includes SDK upload/download and job controls, a deployable job definition, raw-source normalization and published-timeline inspection notebooks. It does not automatically enable workspace services or grant access.

## Prerequisites

- An existing Unity Catalog enabled workspace and supported cluster (Runtime 15.4 LTS or newer for Volume access and the included Python workflow).
- An approved catalog, schema and Volume for the evidence bundles. Keep raw evidence retention separate from analytic table retention.
- Databricks CLI and SDK unified authentication, preferably an OAuth profile. SDK calls use `WorkspaceClient()`; the example environment file lists configuration names without secrets.
- The job principal needs `USE CATALOG`, `USE SCHEMA`, the appropriate Volume read/write permissions and destination table/view creation permissions. Precreate objects and reduce privileges as required by your operating model. The Tines identity should only be able to run/inspect the designated job.

## Install and deploy

From the repository root:

```bash
python -m pip install -e '.[dev,databricks]'
python -m build --wheel
databricks auth login --host https://YOUR-WORKSPACE --profile timeline-dev
databricks bundle validate -t dev --profile timeline-dev --var cluster_id=YOUR_CLUSTER,catalog=YOUR_CATALOG,schema=incident_timelines
databricks bundle deploy -t dev --profile timeline-dev --var cluster_id=YOUR_CLUSTER,catalog=YOUR_CATALOG,schema=incident_timelines
```

Set `DATABRICKS_CONFIG_PROFILE=timeline-dev` for SDK commands using that profile. The root `databricks.yml` builds and attaches the wheel, defines `publish_timeline`, limits concurrent runs to one, and retries deterministic publication tasks twice. Notebook/wheel task syntax follows [Databricks' bundle task documentation](https://docs.databricks.com/aws/en/dev-tools/bundles/job-task-types).

The first task requires a Volume bundle path and pinned manifest SHA-256, verifies it, and publishes the tables. The optional `export_and_publish_ocsf` task runs next. The final inspection wheel task rechecks configured signer policy and the committed timeline count. The separate interactive inspection notebook displays at most 200 events for an analyst. These tasks invoke no AI model.

OCSF publication is disabled by default. Enable it with bundle variables `ocsf_enabled=true,ocsf_export_root=/Volumes/main/incident_timelines/evidence/ocsf,ocsf_quarantine=false`, in addition to your existing cluster/catalog/schema variables. This adds a strict, schema-validated export for nine pinned OCSF 1.3.0 classes. Configure a separate writable derived-output directory; see [OCSF setup, replay and partial-publication semantics](../../docs/OCSF_EXPORT.md). Remove older local wheels before deploying through `dist/*.whl`.

## End-to-end flow

```bash
# Build locally using the README's timeline ingest command, then upload.
timeline databricks-upload output/demo-001 --volume-root /Volumes/main/incident_timelines/evidence/bundles

# Use the remote_bundle returned above and the deployed job ID.
timeline databricks-submit output/demo-001 --remote-bundle /Volumes/main/incident_timelines/evidence/bundles/BUNDLE_ID --job-id 12345

# Use the returned run_id; this is a single status lookup.
timeline databricks-status 98765

# Download to a new local directory; use the independently recorded manifest hash.
timeline databricks-download --remote-bundle /Volumes/main/incident_timelines/evidence/bundles/BUNDLE_ID --manifest-sha256 MANIFEST_SHA256 --output output/restored-demo
timeline verify output/restored-demo --manifest-sha256 MANIFEST_SHA256
```

Upload creates directories and writes the manifest last. It never overwrites remote evidence. On an already-existing file, the adapter downloads and compares bytes by SHA-256; conflicting content fails. Job submission uses a 64-character deterministic idempotency token. Databricks documents these replay semantics in the [Jobs SDK reference](https://databricks-sdk-py.readthedocs.io/en/latest/workspace/jobs/jobs.html).

The CLI prints the manifest anchor in its submission/Tines request contract. You can also obtain it locally:

```bash
python -c "from timeline_demo.parsers.common import file_hash; print(file_hash('output/demo-001/audit_manifest.json'))"
```

## Delta tables and query behavior

| Object | Contents / key |
| --- | --- |
| `evidence_files` | Original source file hashes, sizes, Volume paths and acquisition metadata per case/bundle |
| `timeline_events` | Normalized fields and full `record_json`; case/bundle/event identity key |
| `ingestion_receipts` | Source and record references, including duplicate occurrences |
| `quarantine` | Rejected-record references and reasons |
| `analysis` | Validated AI response and receipt, with `human_review_required=true`; separate from evidence |
| `published_bundles` | Manifest and publication marker inserted after all evidence tables |
| `published_timeline` | Events joined to committed bundle markers; default analyst read surface |
| `ocsf_events` / `ocsf_rejections` | Optional core OCSF records and rejected-event receipts keyed by case/bundle/export/timeline-event identity |
| `published_ocsf_exports` / `published_ocsf` | Optional export-manifest marker with counts, and accepted events joined to completed export markers |

Writes use insert-only `MERGE` clauses, explicit schemas and deduplication, following [Delta merge semantics](https://docs.databricks.com/aws/en/delta/merge). There is no update/delete clause. `delta.appendOnly=true` reinforces the table's write behavior. This is not a claim of immutable/WORM storage; administrators, retention settings and object-store access remain material controls.

Always filter both `case_id` and `bundle_id` when comparing row counts or reviewing a specific investigation snapshot. Different bundles intentionally retain separate copies of an event. Use the committed view for normal reads; staging tables may include rows from an incomplete attempt.

For OCSF, also filter `export_id`. Strict OCSF failures make the job fail after the ordinary timeline may already have been published. `ocsf_quarantine=true` allows a successful partial export; inspect the marker's rejected count before declaring OCSF coverage complete. Empty accepted exports still have a marker and rejection records.

## Source data already in Databricks

Import `normalize_sources.py` into the workspace, attach the project wheel, and configure:

```json
[
  {"parser":"databricks_audit","path":"/Volumes/main/incident_timelines/evidence/raw/audit.jsonl"},
  {"parser":"cloudtrail","path":"/Volumes/main/incident_timelines/evidence/raw/cloudtrail.json"}
]
```

Set `case_id`, a new `output_bundle` Volume directory and, only when the source requires it, an explicit time-zone assumption. Export `system.access.audit` with documented timestamps before ingesting it; preserve the query, source table/version, collection window and original export as collection records. Naive exported Spark timestamps require an explicit source-time-zone decision.

The normalization notebook runs the shared pipeline on the driver. It is suitable for bounded investigation exports; it is not a distributed Auto Loader implementation. Large continuous lakehouse ingestion, cursor management and upstream source collection need separate scale and completeness validation.

## Optional AI in notebooks

Use `notebooks/03_ai_harness.ipynb` for planning or explicit analysis. Install the `ai` extra, retrieve secrets through the approved scope and choose a durable transactional ledger location. Publish a completed result separately with `publish_analysis(spark, result, catalog, schema)`. No paid AI calls run inside the deployed publication job.

## Live acceptance

Validate/deploy against your workspace, run the synthetic case, compare count and hashes, replay the same request, interrupt a publication stage and retry, deny a required permission, and alter one copied artifact. Confirm that failed attempts do not appear as completed cases and that restoring a bundle requires its pinned manifest hash.

SDK tests and local contract validation are included. They do not establish your workspace permissions, billing settings, storage durability or live notebook compatibility. The repository's GitHub CI separately exercises a local Spark/Delta runtime; live Databricks acceptance requires your configured workspace.

## Required signer verification

Version 0.9.0 adds signed sidecar upload, verification before writes and final publication, and insert-only `signature_verifications` receipts. Configure `require_signature`, `signature_root`, `trust_store_path` and `trust_store_sha256` as deployment variables; they are not incoming job parameters. The OCSF task verifies the source signer but does not automatically sign its derived output. Historical receipts remain historical after revocation. [Exact setup, rotation and signed-export publication](../../docs/SIGNING.md).
