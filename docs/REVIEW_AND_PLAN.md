# Repository review and implementation plan

Reviewed baseline: `d8e8169e1c5bb175bc8c5218f005f6f2a9a563d3` on 2026-09-07. Scope is `Scoston/ai-assisted-ocsf-incident-timeline`; the separate AI-DFIR project is not changed.

## Review findings

| Finding in the baseline | Consequence | Implemented correction |
| --- | --- | --- |
| Source and build outputs nested under `forensic_timeline_ai_repo/forensic_timeline_ai_repo/build` | Installation and UI paths were unreliable; bytecode and packaging output were tracked | Root `pyproject.toml`, `src/` package, CLI, ignore rules and migration guide |
| Three source parsers, one test | Major integration sources were unsupported | Registry with 21 named contracts, synthetic fixtures and positive/negative regression coverage |
| Naive timestamps assumed UTC; fabricated 0.99 temporal confidence | Analysts could mistake an assumption for source precision | Reject missing zones unless explicitly supplied; record source timestamp, offset and assumption |
| CloudTrail, Entra and detection class IDs did not match the intended OCSF classes | Downstream interpretation could be wrong | Versioned class mapping and explicit OCSF-aligned profile boundary |
| CrowdStrike retained only the first behavior | A detection could lose relevant activities | Preserve each behavior with a unique event identity and shared source provenance |
| Manifest asserted verified evidence without validating file hashes | UI displayed trust that the implementation had not checked | Archive bytes, hash all bundle artifacts, verify before display, AI and publication |
| AI received the full pretty-printed timeline with no output cap or durable budget | Repeated analysis could waste tokens; invalid output was accepted | Explicit task routes, compact groups, schema/citation checks, output caps, durable reservations and cache |
| No Tines, Databricks or notebook implementations | Workflow and lakehouse deployment were undefined | Dedicated story exports, SDK adapter, deployable job bundle, Delta publication and notebooks |
| Source strings interpolated into unsafe HTML in the UI | Untrusted logs could inject display content | Native Streamlit text, tables and JSON rendering |

## Completed implementation work

1. Package and CLI migration; preserve original source samples, catalogs and historical material.
2. Strict, deterministic ingestion with raw snapshots, UTC ordering, duplicate receipts, quarantine and portable integrity verification.
3. Parser contracts for the documented hybrid-cloud/DFIR integration scope, including upstream Plaso export ingestion.
4. Tines publish-and-monitor and independent run-inspection stories; configuration, authentication, retries, retention and human-review implications documented.
5. Databricks SDK Volume upload/download, pinned manifest verification, repeat-safe job submission, status lookup, insert-only Delta publication, final publication marker, and an inspection notebook task.
6. Three executable Jupyter examples, including optional live Databricks and AI cells disabled by default.
7. AI harness with model/task routing, no hidden retries, durable per-case token/call budget, conservative input bounds, minimized evidence, schema/citation validation, audit receipts and cache.
8. Updated user, operator, architecture, model-selection, parser, migration and validation documentation; CI and packaging gates.

## Deployment acceptance that depends on the operator environment

These are explicit acceptance steps, not claims of completed production deployment:

- Import both stories into the intended Tines tenant; configure resources and credentials; test the expressions with your action runtime; run success, failure, timeout and replay cases before enabling them.
- Provide a Databricks OAuth profile, UC catalog/schema/Volume and cluster; validate/deploy `databricks.yml`; verify grants, retention and object-store controls.
- Run a synthetic live round trip and compare downloaded bundle hashes and Delta row counts. Test denied permissions, altered bundles and interrupted publication.
- Confirm model access and data-processing requirements. Run a small reviewed evaluation set before enabling paid analysis. Model output quality has not been measured by the offline test doubles.

## Next milestones

| Priority | Enhancement | Acceptance evidence |
| --- | --- | --- |
| 1 | Tenant acceptance and organization-specific parser fixtures | Sanitized representative exports pass source/record/field-level review; live workflow evidence recorded |
| 2 | Full pinned OCSF schema export | Upstream schema validation passes for each advertised class; mapping deviations documented |
| 3 | Continuous collection and checkpoints | Source-specific pagination/cursors, collection windows, throttling and replay tested; no silent gaps |
| 4 | Scale and quality evaluation | Published hardware/dataset limits, peak memory/runtime, precision/recall and citation faithfulness measurements |
| 5 | Signed manifests and external trust anchors | Explicit signer trust, key rotation and revocation; independent audit/retention controls |

The existing artifact-family and top-50 SaaS catalogs remain descriptive references. Implementing a catalog entry requires a source contract and representative test data; the project does not claim those entries are all parsers.
