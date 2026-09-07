# Validation record

Implementation date: 2026-09-07. Baseline: `d8e8169e1c5bb175bc8c5218f005f6f2a9a563d3`.

## Local verification

- Regression suite: 71 passed; one real Spark/Delta test is separately gated by `TIMELINE_TEST_DELTA=1`.
- Original synthetic demo: five events ingested, exported and verified successfully.
- All 21 parser fixtures: UTC conversion, deterministic identity and class/profile behavior checked.
- Negative inputs: ambiguous timestamps, DST fold/gap, invalid JSON, duplicate keys, non-finite numbers, malformed CSV/XML paths, quarantine, artifact tampering and directory traversal checked.
- AI harness: offline planning, bounded requests, task routing, durable reservations, concurrency, case isolation, cache hits, failed/incomplete output, invented citations and no evidence mutation checked with test doubles. No paid model requests were made.
- SDK adapter: upload, repeat upload, pinned download, job parameter/idempotency contract and status behavior checked with test doubles and the installed Databricks SDK types.
- Tines: export graph/index/resource/credential boundaries checked. Tenant import and expression evaluation remain deployment acceptance steps.
- Jupyter: all code cells in all three notebooks executed successfully in offline mode. Local kernel startup was blocked by the workspace's socket restrictions, so real Jupyter transport execution is included in GitHub Actions.
- Python source lint and distribution build checked. GitHub Actions also performs these checks on Python 3.10 and 3.12.

## Runtime CI

The `Validate timeline integrations` workflow executes the three notebooks through Jupyter and runs a real Spark 3.5.3 / Delta 3.2.1 insert/replay test on an Ubuntu runner with Java 17. Consult the workflow run associated with the merged commit for the authoritative result; a local test-double pass is not a substitute for this gate.

Local Spark startup could not retrieve its default Maven dependency in this environment, and the same workspace blocks local socket binding. The hosted runtime test is therefore required before merging the implementation.

## Live services not exercised

No Tines tenant, Databricks workspace/cluster/Volume credentials, or OpenAI API key were configured in this implementation environment. The code and deployable artifacts are provided, but production integration and model quality have not been claimed as verified.

Before enabling live workflows, complete the acceptance cases in the Tines and Databricks guides and evaluate model output against analyst-reviewed incidents. Record workspace/runtime versions, job/story IDs, source export formats, expected hashes/counts, actual provider usage and observed failure behavior.
