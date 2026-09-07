# Validation record

Implementation date: 2026-09-07. Baseline: `d8e8169e1c5bb175bc8c5218f005f6f2a9a563d3`.

## Local verification

- Version 0.8.0 regression suite: 146 passed, including 16 evaluation/IPv6, 15 collection and 44 OCSF cases; one real Spark/Delta test is separately gated by `TIMELINE_TEST_DELTA=1`.
- Collection: interruption/resume, cursor cycles, timestamp boundaries, watermark advancement, page/record/byte limits, raw page integrity, HTTP throttling/redirects, SDK pagination and SQL result truncation checked with test doubles. Live permissions, source retention and late-arrival coverage remain acceptance steps.
- Evaluation: six fresh-process synthetic workloads (1,000/10,000/100,000 events, repeated/diverse), fixture diagnostics, scorer denominator/duplicate/support checks and source/label binding. Exact results and limits are in [EVALUATION.md](EVALUATION.md).
- Original synthetic demo: five events ingested, exported and verified successfully.
- All 21 parser fixtures: UTC conversion, deterministic identity and class/profile behavior checked.
- Negative inputs: ambiguous timestamps, DST fold/gap, invalid JSON, duplicate keys, non-finite numbers, malformed CSV/XML paths, quarantine, artifact tampering and directory traversal checked.
- AI harness: offline planning, bounded requests, task routing, durable reservations, concurrency, case isolation, cache hits, failed/incomplete output, invented citations and no evidence mutation checked with test doubles. No paid model requests were made.
- SDK adapter: upload, repeat upload, pinned download, job parameter/idempotency contract and status behavior checked with test doubles and the installed Databricks SDK types.
- Tines: export graph/index/resource/credential boundaries checked. Tenant import and expression evaluation remain deployment acceptance steps.
- OCSF: all nine pinned class validators, mapped source contracts, nested constraints, class/activity/type consistency, version/profile rejection, missing required fields, deterministic output, quarantine accounting, source binding, rehashed-invalid exports, duplicate references and symlink boundaries checked. The original five-event bundle exports five validated core events without changing its manifest.
- Schema generation: exact official catalog hash and `ocsf-json-schema==1.2.0` reproduce all nine packaged definitions. Runtime schema checks use no network or generator dependency. Schema and notice inclusion are checked inside the built wheel.
- Jupyter: all code cells in all five notebooks executed successfully in offline mode. Local kernel startup was blocked by the workspace's socket restrictions, so real Jupyter transport execution is included in GitHub Actions.
- Python source lint and distribution build checked. GitHub Actions also performs these checks on Python 3.10 and 3.12.

## Runtime CI

The `Validate timeline integrations` workflow executes the five notebooks through Jupyter and runs a real Spark 3.5.3 / Delta 3.2.1 insert/replay test on an Ubuntu runner with Java 17. Version 0.6.0 extends that gate to OCSF events, empty rejection tables, stable event keys and final export markers. Consult the workflow run associated with the merged commit for the authoritative result; a local test-double pass is not a substitute for this gate.

The preceding 0.5.0 implementation passed Python 3.10/3.12, real Jupyter kernels and Delta in [GitHub Actions run 34131970448](https://github.com/Scoston/ai-assisted-ocsf-incident-timeline/actions/runs/34131970448). This is historical evidence; new changes require their own green run.

Local Spark startup could not retrieve its default Maven dependency in this environment, and the same workspace blocks local socket binding. The hosted runtime test is therefore required before merging the implementation.

## Live services not exercised

No Tines tenant, Databricks workspace/cluster/Volume credentials, or OpenAI API key were configured in this implementation environment. The code and deployable artifacts are provided, but production integration and model quality have not been claimed as verified.

Before enabling live workflows, complete the acceptance cases in the Tines and Databricks guides and evaluate model output against analyst-reviewed incidents. Record workspace/runtime versions, job/story IDs, source export formats, expected hashes/counts, actual provider usage and observed failure behavior.
