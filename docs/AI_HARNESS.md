# AI harness, task routing and token control

The default workflow uses no model. Parsing, timestamp conversion, hashes, validation, ordering, deduplication, IOC extraction, Tines orchestration and Databricks publication are deterministic.

## Models by task

Selection reviewed against the [official model catalog](https://developers.openai.com/api/docs/models) on 2026-09-07. The catalog describes Luna for cost-sensitive workloads, Terra for a balance of capability and cost, and Astra for complex reasoning. The assignments below are project design choices, not measured comparative quality results.

| Task | Default model | Reasoning | Max input bound | Max output tokens | Dispatch |
| --- | --- | --- | ---: | ---: | --- |
| Parse, normalize, validate, hash, sort, deduplicate, extract IOCs | None | None | 0 | 0 | Always deterministic |
| Tines routing, Databricks writes, notebook data inspection | None | None | 0 | 0 | Always deterministic |
| `summarize`: observed activity and investigation pivots | `gpt-5.6-luna` | `none` | 6,000 | 700 | Explicit AI call |
| `correlate`: cross-source relationships and competing hypotheses | `gpt-5.6-terra` | `low` | 7,000 | 1,200 | Explicit AI call |
| `review`: evidence sufficiency, attribution gaps and alternatives | `gpt-6-astra` | `low` | 7,000 | 1,500 | Explicit AI call |

The authoritative configuration is [`model_policy.json`](../src/timeline_demo/resources/model_policy.json). A single shared ledger enforces **24,000 tokens and three calls per case** by default. Multiple ledgers are independent budgets; use one durable ledger per deployment and do not reset it to retry a case. CLI overrides use `--policy path/to/policy.json`. Model access depends on your API account.

The configured standard input/output rates per million tokens are $0.20/$1.20 for Luna, $2/$12 for Terra, and $10/$50 for Astra. At the configured caps, approximate request ceilings are $0.00204, $0.0284 and $0.145 respectively, before taxes or future pricing changes. The harness enforces token/call budgets, not dollar budgets. Confirm current rates in the [official pricing documentation](https://developers.openai.com/api/docs/pricing).

## Token-saving behavior

- No model call per alert or event; no automatic multi-agent loop, model fallback or escalation.
- Group by source, activity, status and severity. Send first/last representative examples with short `e1`-style references. Report counts and omitted coverage.
- Prioritize high-severity groups, then chronology. Default group inventory is capped at 1,000; input packing applies a separate request bound. Omitted groups may contain important evidence, so limited coverage is visible in every receipt.
- Exclude raw files, record hashes, metadata and full user/asset/IP identities from the request. Use case-specific pseudonyms. Activity text gets basic redaction and truncation; this does not guarantee removal of sensitive data.
- Send compact JSON with a small output schema. Count all request content, including schema and instructions.
- Use a conservative UTF-8 byte bound plus 256 framing tokens, rather than assuming four characters per token. Provider usage is recorded and checked against the reservation. This bound trades some usable context for predictable limits; it is not exact tokenizer measurement.
- Cap model output, including reasoning tokens where applicable. [OpenAI documents output-token limits and reasoning usage](https://developers.openai.com/api/docs/guides/reasoning).
- Cache successful results by case, bundle, task, model, full policy, prompt version, minimized request and reference mapping. Unchanged cache hits consume zero new model tokens.

## Execution and audit

```bash
# Local plan only: shows model, coverage and token reservations.
timeline analyze output/demo-001 --task summarize

# Explicit paid call, with the ledger outside the evidence bundle.
timeline analyze output/demo-001 --task summarize --allow-ai --ledger analysis/usage.sqlite --output analysis/summary.json

# Run these only when needed; there is no automatic escalation.
timeline analyze output/demo-001 --task correlate --allow-ai --ledger analysis/usage.sqlite --output analysis/correlation.json
timeline analyze output/demo-001 --task review --allow-ai --ledger analysis/usage.sqlite --output analysis/review.json
```

Provide `OPENAI_API_KEY` through your process environment or secret manager. In Databricks, use the approved secret scope and a protected persistent ledger location that supports SQLite locking. Do not place a shared SQLite ledger on object-store/FUSE storage with uncertain locking semantics. For multiple hosts, use a single serialized harness service or implement a transactional central budget store before enabling concurrent dispatch.

The ledger reserves a call and its maximum tokens in a transaction **before** dispatch. A second concurrent request for the same key either receives the cached result or an explicit pending/failed status; it cannot dispatch another copy. API retries are disabled. A timeout retains the reservation because the provider may have processed the request. A response with known usage is charged even if it fails validation. Failed or pending requests require investigation; they do not automatically retry or switch models.

Requests use the Responses API, `store=false`, no model tools and [strict structured output](https://developers.openai.com/api/docs/guides/structured-outputs). The response must complete, satisfy the local schema and cite only provided references. Refusals, incomplete responses, invalid JSON and invented references fail closed. The evidence bundle is verified again after a successful model response.

The receipt records case/bundle identity, request hash, prompt/policy versions, task/model, input/output usage, selected coverage, evidence-reference mapping and provider response ID. The ledger also retains the minimized request and provider response for reconstruction. Treat that database as sensitive; configure access, retention and backup appropriately. `store=false` is not a guarantee of zero provider retention; verify your organization's approved API data controls.

AI results always require human review. Schema validation proves structure, not truth. A citation can be syntactically valid while its interpretation is wrong. ATT&CK hypotheses or containment decisions need supporting evidence and analyst judgment; the model is given no containment tool or delegated production authority.

## Quality evaluation

Offline tests establish budget, cache, concurrency, citation and failure behavior. They use test doubles and **do not measure model accuracy**. Build a reviewed set of representative incidents with expected evidence references, known ambiguity, benign alternatives and prompt-injection text. Measure unsupported-claim rate, citation support, omitted-critical-event rate, reviewer acceptance, actual tokens and cost. Enable a more expensive route only when that evaluation shows a useful improvement.

## Measured coverage and output evaluation

The synthetic scale suite shows why token limits require explicit coverage: four repeated action groups can represent 100,000 event counts with a small request, while distinct actions cause most events to be omitted. Group counts do not mean the model saw every underlying record. Inspect `coverage` before using an interpretation. High-cardinality sources need a narrower investigation window or a targeted source export; no automatic extra model calls are made. Use the source-bound analyst scorer to measure claim precision/recall and citation faithfulness on saved outputs. See [actual measurements and review protocol](EVALUATION.md).

## Durable usage operations

Use `timeline-ops ledger-usage`, `ledger-backup` and `ledger-restore` for read-only accounting and verified SQLite-aware recovery. Unknown reservations remain charged, and completed cached analyses still avoid a new call. Restore only with original writers fenced and dispatch history reconciled. See [commands and recovery boundaries](OPERATIONS.md#ai-usage-and-recovery).
