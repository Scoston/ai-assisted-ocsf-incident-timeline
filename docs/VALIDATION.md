# Validation record

## 0.13 native forensic release

Feature baseline: `274fa8d037badafffbbf467b4d1ebd780a1166d9`, 7 September 2026. [PR #15](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/pull/15) and [main CI run 34160916880](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/actions/runs/34160916880) record the completed release gates: 864 project tests, ten real Jupyter notebooks, separately gated Spark/Delta replay, native Plaso validation, dependency/container checks, CodeQL and main distribution attestations. The upstream parser suite passed 637 tests with no skips.

Native fixture ingestion processed 14,991 source records into 14,988 timeline events and three explicit quarantined records with source evidence preserved. The disk-image and embedded-archive fixture produced 37 events with no quarantine. Storage re-import preserved event identities. These fixture results do not establish complete recognition of arbitrary artifacts or complete tenant acquisition.

The [new demo](DEMO.md) reproduces offline ingestion, OCSF export, integrity failure, signer lifecycle, AI planning/cache contracts, and checkpoint recovery with synthetic evidence. Its recorded native results refer to the release run above. Cloud tenant, identity-provider, and paid-model connections are not represented as live demonstrations.

## 0.12 follow-up release

Baseline: `d9e88310e5df53dd4f1a54221b678265970e7f5d`, 7 September 2026. Local regression: **313 passed**, one separately gated real Delta test; all **nine notebooks** execute offline. New regressions exercise rolling/migration recovery, source inventory, AI WAL/cache/reservation restoration, malformed usage and GitHub/Kubernetes source contracts. [Synthetic diagnostics](../benchmarks/results/2026-09-07-gap-review-quality.json) report 54/54 timestamp/class assertions across 27 parser fixtures; this is not incident/model accuracy. The existing CI gates execute Python 3.10/3.12, real Jupyter, signed Delta, container/dependency/security checks and main-build attestations. See this release PR for the exact CI result. No live tenant/OIDC/scheduler deployment or paid model invocation was performed.

## 0.11 enterprise release

- Baseline: `c69f1ba`, 7 September 2026. Local regression: 275 passed, one separately gated real Delta test; all eight notebooks execute offline. CI also executes real notebook kernels, Python 3.10/3.12 and Spark/Delta.
- Added malformed-manifest/special-file/permissions/resource-limit checks, checkpoint version boundaries, read-only health, interrupted and completed snapshot recovery, altered snapshot rejection, OIDC principal/expiry/cross-case denial and required trusted evidence.
- Databricks SDK doubles verify local normalization, manifest-last uploads, recovery of partial OCSF uploads and conflict rejection. Live driver disk, OAuth/UC grants and Volume operations remain acceptance requirements.
- Both hash-locked runtime and build dependency scans found no known vulnerabilities on 7 September 2026. CI repeats audits and produces CycloneDX inventories. Advisory results are time-specific.
- Container build/runtime and CodeQL gates run in GitHub Actions; Docker and live OIDC transport are not available in the local workspace. Main-build attestations run only after merge and successful gates.
- Source/provider/model quality and tenant completeness remain unverified by these synthetic tests. No paid model calls were made. The new [enterprise assessment](ENTERPRISE_READINESS.md) assigns production acceptance ownership.

Implementation date: 2026-09-07. Baseline: `d8e8169e1c5bb175bc8c5218f005f6f2a9a563d3`.

## Local verification

- Version 0.10.0 regression suite: 234 passed, including 53 new enterprise cases and the original collection/signing/evaluation gates; one real Spark/Delta test is separately gated by `TIMELINE_TEST_DELTA=1`.
- Collection: interruption/resume, cursor cycles, timestamp boundaries, watermark advancement, page/record/byte limits, raw page integrity, HTTP throttling/redirects, SDK pagination and SQL result truncation checked with test doubles. Live permissions, source retention and late-arrival coverage remain acceptance steps.
- Enterprise collection: all 14 new types, eight Azure Monitor tables, source-clock handling, native M365 UTC, SDK request-shape validation, header pagination, async resume, missing detail IDs, changed totals, query caps/partial results, network endpoints, nested Workspace events, historical OCSF mappings and malformed rows checked offline. Source-specific API/authentication and live acceptance limits are recorded in [ENTERPRISE_APIS.md](ENTERPRISE_APIS.md).
- Evaluation: six fresh-process synthetic workloads (1,000/10,000/100,000 events, repeated/diverse), fixture diagnostics, scorer denominator/duplicate/support checks and source/label binding. Exact results and limits are in [EVALUATION.md](EVALUATION.md).
- Signing: encryption, deterministic signatures, artifact/policy/key/kind substitution, trusted-policy pins, source-bound OCSF, rotation, revocation, exclusive writes, permissions, required verification, upload replay/conflicts and deployment policy boundaries checked.
- Original synthetic demo: five events ingested, exported and verified successfully.
- All 25 parser fixtures: UTC conversion, deterministic identity and class/profile behavior checked.
- Negative inputs: ambiguous timestamps, DST fold/gap, invalid JSON, duplicate keys, non-finite numbers, malformed CSV/XML paths, quarantine, artifact tampering and directory traversal checked.
- AI harness: offline planning, bounded requests, task routing, durable reservations, concurrency, case isolation, cache hits, failed/incomplete output, invented citations and no evidence mutation checked with test doubles. No paid model requests were made.
- SDK adapter: upload, repeat upload, pinned download, job parameter/idempotency contract and status behavior checked with test doubles and the installed Databricks SDK types.
- Tines: export graph/index/resource/credential boundaries checked. Tenant import and expression evaluation remain deployment acceptance steps.
- OCSF: all nine pinned class validators, mapped source contracts, nested constraints, class/activity/type consistency, version/profile rejection, missing required fields, deterministic output, quarantine accounting, source binding, rehashed-invalid exports, duplicate references and symlink boundaries checked. The original five-event bundle exports five validated core events without changing its manifest.
- Schema generation: exact official catalog hash and `ocsf-json-schema==1.2.0` reproduce all nine packaged definitions. Runtime schema checks use no network or generator dependency. Schema and notice inclusion are checked inside the built wheel.
- Jupyter: all code cells in all seven notebooks executed successfully in offline mode. Local kernel startup was blocked by the workspace's socket restrictions, so real Jupyter transport execution is included in GitHub Actions.
- Python source lint and distribution build checked. GitHub Actions also performs these checks on Python 3.10 and 3.12.

## Runtime CI

The `Validate timeline integrations` workflow executes the seven notebooks through Jupyter and runs a real Spark 3.5.3 / Delta 3.2.1 insert/replay test on an Ubuntu runner with Java 17. Version 0.9.0 extends that gate to signed source/OCSF publications, repeat verification receipts, configured inspection and denial after key revocation, while retaining OCSF events, empty rejection tables, stable event keys and final export markers. Consult the workflow run associated with the merged commit for the authoritative result; a local test-double pass is not a substitute for this gate.

The preceding 0.5.0 implementation passed Python 3.10/3.12, real Jupyter kernels and Delta in [GitHub Actions run 34131970448](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/actions/runs/34131970448). This is historical evidence; new changes require their own green run.

Local Spark startup could not retrieve its default Maven dependency in this environment, and the same workspace blocks local socket binding. The hosted runtime test is therefore required before merging the implementation.

## Live services not exercised

No Tines tenant, Databricks workspace/cluster/Volume credentials, or OpenAI API key were configured in this implementation environment. The code and deployable artifacts are provided, but production integration and model quality have not been claimed as verified.

Before enabling live workflows, complete the acceptance cases in the Tines and Databricks guides and evaluate model output against analyst-reviewed incidents. Record workspace/runtime versions, job/story IDs, source export formats, expected hashes/counts, actual provider usage and observed failure behavior.

## Completed milestone CI evidence

- 0.7.0: [run 34140270470](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/actions/runs/34140270470), Python 3.10/3.12, real Jupyter and Delta all passed before PR #3 merged.
- 0.8.0: [run 34141192293](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/actions/runs/34141192293), Python 3.10/3.12, real Jupyter, evaluation smoke workloads and Delta all passed before PR #4 merged.
- 0.9.0: [run 34143093485](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/actions/runs/34143093485), Python 3.10/3.12, six real Jupyter notebooks and signed Delta replay/revocation passed before PR #5 merged.
- 0.10.0: the PR #6 workflow is the required gate for enterprise collectors and the seventh notebook. Historical green runs do not validate this change.
