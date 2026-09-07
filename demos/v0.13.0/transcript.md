# v0.13.0 narrated feature demo

Synthetic narration (Kokoro af_sarah); synthetic evidence only.


## 00:00:00 — Follow the evidence

Welcome to the AI-assisted OCSF incident timeline, version zero point thirteen. This tour follows an investigation from source evidence to a verified timeline and optional analysis. Everything shown uses synthetic evidence. Cloud integrations are configuration walkthroughs.


## 00:00:19 — Start with source evidence

First, ingest the bundled CloudTrail, Entra sign-in, and CrowdStrike examples. The command produces five ordered events, preserves three source files, and writes JSON lines, CSV, and Parquet. Parsing and normalization happen locally and use zero model tokens.


## 00:00:38 — Explore the investigation

Open the verified bundle in the Streamlit viewer. The banner reports file integrity, while the counters show events, quarantined records, and duplicates. Filter the displayed timeline by source, then inspect the underlying event. The viewer shows its display limit explicitly, so a partial view stays visible to the analyst.


## 00:00:58 — Trace every event

Each event keeps its original timestamp, parser version, evidence path, and record and file hashes. Acquisition receipts connect the timeline back to its inputs. Extracted addresses, domains, and hashes are investigative candidates. Their presence alone is not a threat verdict.


## 00:01:16 — Detect altered evidence

Verification checks the bundle before it is used. Here, adding one newline to a temporary copy of the timeline causes verification to fail. Strict ingestion rejects invalid records. Explicit quarantine mode retains rejected records and their error receipts for review. File hashes verify integrity; they do not establish source authenticity.


## 00:01:40 — Collect across the enterprise

Nineteen collector types cover cloud, identity, endpoint, collaboration, and enterprise search systems. They preserve native responses and checkpoint committed pages. Rolling collection adds overlapping windows, settling time, and durable watermarks. An expected-source inventory helps flag missing feeds. Tenant permissions and retention still determine what can be acquired.


## 00:02:04 — Include developer incidents

Developer investigations now include GitHub enterprise audit and Kubernetes audit evidence. These synthetic examples preserve a repository action and a denied request to list secrets. The same timeline, source verification, OCSF export, and bounded analysis workflow applies.


## 00:02:24 — Bring native artifacts into scope

The native backend includes the complete pinned Plaso registration inventory: fifty-nine parsers, one hundred eighty-six parser plugins, and four cookie plugins. The inventory records upstream source paths and formats for audit. These are registrations, not two hundred forty-nine independent log types or live collectors.


## 00:02:46 — Preserve the forensic context

Native ingestion accepts acquired artifacts, disk images, embedded archives, and compatible Plaso storage files. It uses a pinned, isolated backend and retains source snapshots, runtime inventory, and processing receipts. The recorded release validation processed fourteen thousand nine hundred ninety-one source records, with three explicitly quarantined. A separate disk-image and embedded-archive check produced thirty-seven events.


## 00:03:14 — Export validated OCSF

The analytical timeline uses an OCSF-aligned profile. A separate export command validates core OCSF version one point three against nine pinned event classes. Our five sample events export and verify successfully. Missing required fields fail strict export or appear in explicit rejection receipts when quarantine is enabled.


## 00:03:38 — Control who can sign

Detached Ed25519 signatures add authorized signer verification with independently pinned trust policies. This local run signs a bundle, retires the key to verification-only status, and then revokes it. Retirement preserves verification. Revocation blocks it. The source bundle remains unchanged.


## 00:04:00 — Orchestrate with Tines

Two dedicated Tines stories handle publishing and monitoring, plus run inspection. The publish story validates the bundle contract, submits a Databricks job, and polls within a defined limit. Stable idempotency keys and asynchronous receipts support retries and operator follow-up. Import and configure these disabled templates in your tenant before enabling them.


## 00:04:24 — Publish into Databricks

The Databricks integration uploads verified bundles to Unity Catalog Volumes, with the manifest published last. Jobs verify the bundle before publishing insert-only Delta records. Publication markers and committed views make completed data explicit, while repeat submissions use stable identifiers. Download and inspection commands support a verified round trip. Workspace grants and live acceptance remain deployment steps.


## 00:04:52 — Investigate in Jupyter

Ten Jupyter notebooks walk through the same workflows with executable Python. They cover offline investigation, Databricks, AI budgets, OCSF, evaluation, signatures, collection, recovery, developer incidents, and Plaso. Network and paid-model examples are disabled by default. Start locally, then explicitly enable the connections your investigation needs.


## 00:05:17 — Choose a model by task

The repository routes summarization to GPT five point six Luna, correlation to GPT five point six Terra, and explicitly requested critical review to GPT six Astra. Each route has its own input and output budget. These are configurable defaults. Validate model quality on analyst-reviewed cases before deployment.


## 00:05:40 — Spend tokens deliberately

A plain analyze command only prepares a plan. It sends no model request. The plan reports covered and omitted events before dispatch. Compact groups, bounded outputs, durable case budgets, and cached results control usage. The cache contract demonstration uses an offline test double. Repeating the same request consumes zero additional tokens, and evidence remains separate from interpretation.


## 00:06:06 — Recover interrupted collection

Operational commands inspect source health, backlog, committed pages, and published bundles, and expose Prometheus metrics. In this demonstration, a page budget pauses collection before publication. We back up the checkpoint, restore it using an independent hash pin, and fetch only the remaining page. The restored acquisition completes and its verified health report is healthy.


## 00:06:31 — Deploy with explicit access

Local viewing requires a loopback bind. Shared deployment adds OpenID Connect, explicit case assignments, pinned manifests, required trusted signatures, and access auditing. The repository also includes deployment guidance, dependency locks, and an unprivileged container. Configure and test identity, case access, storage, and recovery in your environment before production use.


## 00:06:56 — Keep the claims measurable

Release validation includes the project tests, real notebook kernels, Spark and Delta replay, upstream Plaso tests, dependency audits, and CodeQL. The published synthetic benchmark ingested one hundred thousand unique events in about twenty seconds on its recorded host. That measurement is not a universal capacity guarantee. Live collection completeness and model quality need case-specific acceptance.


## 00:07:23 — Run your first verified case

Start with the README, run the synthetic case, and open the first notebook. Use the integration guides and enterprise readiness assessment to plan your deployment. Collect the evidence. Verify the timeline. Apply bounded analysis when it helps, and keep the analyst in control.
