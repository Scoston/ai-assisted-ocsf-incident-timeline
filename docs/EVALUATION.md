# Reproducible scale and quality evaluation

Version 0.8.0 provides measured synthetic workloads and an offline scorer for saved, analyst-reviewed model output. Evaluation uses zero model tokens. Live model quality remains unmeasured until reviewed provider outputs are supplied.

## Reproduce

```bash
python scripts/benchmark.py --output scale.json
python scripts/evaluate_quality.py --output quality.json
```

Use a new output path. Benchmark defaults are 1,000/10,000/100,000 unique CloudTrail-shaped JSONL events, two shapes and one repetition. Each workload runs in a fresh, sequential process. Input order is reversed; every tenth event is duplicated. The harness checks deduplication/counts and IPv4 candidate precision/recall. `--repeats 3` repeats measurements; `--sizes` and `--shapes` narrow the workload. No performance threshold is imposed on shared CI runners.

`repeated` has four action/IP groups; `diverse` has a distinct action and IP per event, up to the documented synthetic address range. The generator is deterministic and capped at one million unique events. Raw dataset hashes, exact Python/resource/script file hashes, base commit, dirty-worktree flag and environment details accompany results. Source hashes identify measured code even when the measurement precedes its commit. Generated evidence is temporary and removed after each measurement; results retain reproducibility metadata.

OCSF export and source-bound verification are measured only at 1,000 events by default; larger sizes report null. Set `--ocsf-max-events` explicitly for a larger OCSF experiment. A workload timeout is 900 seconds. Parquet, network collectors, Databricks, Tines and provider latency are outside this benchmark.

## Measured results — 2026-09-07

The [final machine-readable report](../benchmarks/results/2026-09-07-scale-ipv6.json) records Python 3.12.13 on Linux x86-64, an AMD EPYC 9V74 host, nine visible logical CPUs, an eight-CPU cgroup quota and a 20 GiB memory limit. Each worker is a single Python process. Peak RSS uses `resource.getrusage(RUSAGE_SELF)` and includes imports, generation, ingestion, verification, AI planning and any measured OCSF work; it is not ingestion-only memory. Storage cache state was not controlled. These are single observations, not confidence intervals or production capacity guarantees.

| Shape | Unique events | Ingest seconds | Peak process MiB | AI covered events | Input token upper bound |
| --- | ---: | ---: | ---: | ---: | ---: |
| repeated | 1,000 | 0.179 | 28.1 | 1,000 | 3,771 |
| repeated | 10,000 | 1.934 | 25.8 | 10,000 | 3,777 |
| repeated | 100,000 | 20.987 | 26.1 | 100,000 | 3,783 |
| diverse | 1,000 | 0.193 | 28.1 | 11 | 5,774 |
| diverse | 10,000 | 2.117 | 27.2 | 11 | 5,776 |
| diverse | 100,000 | 19.713 | 43.3 | 11 | 5,778 |

At 100,000 unique events, the input contains 110,000 records and roughly 25–26 MB of JSONL; final bundles are roughly 217–221 MB. SQLite temporary space and transient peak disk usage were not measured. IOC sets grow with candidate cardinality, explaining why bounded sorting does not imply constant process memory. Source-format limits remain in force; these results concern short JSONL records, not a giant JSON document or arbitrary forensic export.

The repeated workload represents all event counts through four groups, but supplies only first/last examples for each group. The distinct-action workload includes 11 events and omits the rest under the default summarization budget. This is a deliberate resource boundary, not complete semantic coverage. A low request size alone does not demonstrate good analysis. Review coverage and use narrower investigation windows or targeted source exports before requesting interpretation. The upper bound counts serialized request bytes plus framing; it is not actual provider-token usage. All benchmark model usage is zero.

The [initial measurement](../benchmarks/results/2026-09-07-scale.json) predates the IPv6 fix. It is retained with its own exact source hashes. Timing differences between these single runs are not statistically established performance effects.

## Deterministic quality probes

The [parser truth file](../benchmarks/parser_truth.json) now binds 28 minimal synthetic source fixtures to 56 expected class/time fields. All 56 pass in the [0.13.0 probe](../benchmarks/results/2026-09-07-plaso-quality.json). Native Plaso compatibility is separately checked by the [upstream parser and native integration CI tests](PLASO.md). Historical result files retain their original 21-fixture hashes; they are not re-labeled as new measurements. This confirms those field contracts and does not measure every parser field, representative tenant accuracy or full OCSF conformance; the separate OCSF test suite covers the pinned core schemas.

The IOC probe has six labelled candidates across three deliberately small cases. [Before correction](../benchmarks/results/2026-09-07-quality.json), five were found: precision 1.0, recall 0.8333, with the IPv6 address missed. [After correction](../benchmarks/results/2026-09-07-quality-ipv6.json), all six are found with no false positives in this fixture. Added regressions exercise mapped/compressed IPv6, invalid addresses, timestamps, bracketed URLs and excluded zone identifiers. These tiny diagnostic scores are not threat-detection accuracy; domain-like strings and hash-shaped strings remain candidates requiring context.

## Score analyst-reviewed findings

```bash
timeline-evaluate --analysis benchmarks/synthetic_analysis.json --bundle examples/demo_bundle --labels benchmarks/synthetic_review.json --output scored-review.json
```

The example is handwritten and deliberately includes an unsupported claim and a duplicate. It is explicitly marked `synthetic-handwritten-fixture`; it is not an output from Luna, Terra or Astra. Its citation references are all valid, while its finding-level support score is 2/3, claim precision 1/3 and claim recall 1/2. This demonstrates that an existing citation does not establish support for an interpretation.

For real evaluation, retain the harness output and immutable source bundle. Have an analyst write independent expected claim IDs and adjudicate every finding using the label structure in `benchmarks/synthetic_review.json`. Bind labels to the bundle ID and `sha256_of_text(compact_json(analysis['analysis']))`; include a reviewer label. The label is attribution supplied by the operator, not authenticated reviewer identity. Resolve disagreements using a second reviewer and preserve both original judgments in your audit system.

| Metric | Definition and limit |
| --- | --- |
| Claim precision | Distinct matched reference claims / output findings; repeated claims receive credit once |
| Claim recall | Distinct matched reference claims / expected claims; depends on reference-set completeness |
| Citation reference validity | Accepted analyses have schema-valid citations resolving to events in the supplied bundle; invalid analyses fail evaluation |
| Citation faithfulness | Findings judged supported by their citations / findings; requires complete analyst judgments |
| Empty denominator | Null, never automatically perfect |

Each finding matches at most one atomic reference claim. Split compound claims in the evaluation protocol or document the limitation. Matching correctness and citation support are distinct judgments. This scorer covers findings; summary and next-step text, omitted evidence, causal reasoning and operational harm need separate review. It does not authenticate a saved provider receipt. An analysis with forged model metadata is not evidence of provider performance.

For each configured route (`summarize`, `correlate`, `review`), use the same reviewed case set and frozen prompt/policy version. Record model ID, observed input/output usage, omissions, refusal/error rate, latency and analyst disagreement. Use actual provider usage to compare cost. Enable the smallest route meeting your case-specific quality threshold; no route should be promoted because of the synthetic scorer's demonstration scores. See [model policy and budgets](AI_HARNESS.md).

The [evaluation notebook](../notebooks/05_evaluation.ipynb) walks through coverage and the scorer without any provider request.

## Evidence-gated analyses in 0.14.0

The legacy `timeline-evaluate` fixtures and schema remain readable for historical finding-level comparisons. They do not confer approval on a saved analysis. New actions use exact observation witnesses and a separate hypothesis protocol; `timeline-ai inspect` exposes the per-claim verifier result and `timeline-ai review` records the human assessment. Do not describe field-equality pass rates as semantic accuracy. The new test suite deliberately shows that a valid but irrelevant citation still needs human adjudication and cannot authorize publication on its own. Use representative source-bound human labels before selecting more expensive routes. See [research, tests and workflow](AI_EVIDENCE_AND_REVIEW.md).
