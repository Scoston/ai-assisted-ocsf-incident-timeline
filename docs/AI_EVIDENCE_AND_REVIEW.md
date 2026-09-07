# AI evidence, verification and human review

Version 0.14.0 adds a mandatory evidence and human-review gate for every incident-analysis task. `summarize`, `correlate`, `review`, captured external AI, the viewer, Databricks publication and the Tines handoff use the same action record. The retired legacy enricher still cannot dispatch a model. Parsing, chunking, verification, review, audit export and orchestration use **zero model tokens**.

## Research and design decisions

Research reviewed 7 September 2026:

- **NIST AI 600-1**, §2.2 and action MS-2.5-003, describes confabulation and recommends checking sources and citations during evaluation and monitoring. Its provenance discussion motivates retaining input lineage and output history. This project implements those ideas with source pins, reconstructable chunks, review records and adversarial tests; this is not a NIST certification. [NIST Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf).
- **OWASP** recommends separating untrusted data from instructions, validating outputs, restricting tool privileges, monitoring interactions and using human controls. It also explains that an LLM guardrail can itself be attacked and adds cost. The project therefore uses deterministic checks and explicit human decisions, with no model tools or automatic second-model judge. [OWASP prompt-injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).
- **Anthropic** recommends admitting uncertainty, grounding claims in source quotations and verifying citations, while stating that these techniques cannot eliminate hallucinations. Here, exact field/value witnesses replace loose quotations for factual observations; unrestricted interpretation remains a hypothesis requiring human assessment. [Anthropic hallucination guidance](https://platform.claude.com/docs/en/test-and-evaluate/strengthen-guardrails/reduce-hallucinations).

The restricted observation format and separate approval gate are this project's engineering choices. No comparative model-accuracy result or zero-hallucination guarantee is claimed.

## What is recorded

| Record | Contents and purpose |
| --- | --- |
| Action ID | SHA-256 of case, bundle, source manifest pin, task, prompt version, complete policy, exact request and chunk mapping; external captures additionally bind their declared origin and response hash |
| Acquired logs | The verified bundle contains every acquired original file, collection/parser receipts, quarantine, timeline and duplicate accounting. An audit package copies the complete bundle, including data omitted from model context |
| Event chunk ID | `event-` plus SHA-256 of bundle ID and canonical normalized event; every timeline event has an ID, even when omitted from context |
| Group chunk ID | `chunk-` plus SHA-256 of bundle ID, exact minimized group payload, original grouping key and ordered membership digest of every group event |
| Short context references | `c1` identifies a group and resolves to its full chunk ID; `e1` identifies a representative event and resolves to its event UUID. Short aliases save tokens; full hashes stay in the local receipt |
| Source locators | Event UUID, source file and record hashes, evidence path, record index, child index, parser/version and timeline position |
| Request and response | Exact SDK request parameters, system prompt, minimized context, output schema, model/settings, provider-returned response object and usage; raw originals are not sent automatically |
| Verification | Verifier version, claim IDs, checked field/value witnesses, chunk IDs, error codes, structural pass/fail and explicit semantic-review requirement |
| Human decision | Current candidate hash, reviewer principal, pinned policy hash, decision, reason, coverage acknowledgment and claim-by-claim evidence assessment |
| Action history | UTC time, planning, reservation, dispatch denial, captured response, metering, verification/failure, cache access, review/evidence inspection, human decisions, approved reads and publication/handoff events |

The raw provider response is archived **before** usage or output validation. Malformed usage, refusals, incomplete responses and invalid output remain inspectable. Unknown usage retains the reservation. Exceptions record their class, not potentially secret-bearing exception messages. A transport failure can only record the failure metadata; no response exists to archive.

These records capture observable inputs, outputs and evidence references. They do not expose unavailable private model reasoning, prove which internal feature caused a prediction, prove that all enterprise logs were collected, or establish the authenticity of an acquired log.

## Verification before presentation

The model returns [`evidence_analysis.schema.json`](../src/timeline_demo/resources/evidence_analysis.schema.json):

```json
{
  "observations": [{"chunk_ref": "c1", "field": "count", "value": "1"}],
  "hypotheses": [],
  "abstain": false
}
```

Observations must copy an exact nonempty field value from a supplied chunk. Supported fields are source, activity, status, severity, count, first/last time and the two representative examples' time/actor/asset/IP fields. Counts use decimal strings. Alias values remain aliases; the application does not silently turn them into attributed identities.

The verifier rejects invented or unsupplied chunks, mismatched values, unsupported fields, duplicate observations, missing observations without abstention, contradictory abstention, invalid/duplicate-key JSON, and extra fields such as a model-authored approval or uncited summary. Incomplete/refused responses and proposed tool calls are blocked. The source bundle is verified again after the response and whenever an action is opened for review or publication.

Only fixed application templates construct factual summary text. There is no independent free-text model summary to evade citation checks. Hypotheses require exact evidence witnesses, an alternative explanation and a proposed investigation step. The verifier can check those witnesses, **but cannot determine whether they entail the prose**. A valid count citation does not prove exfiltration or attribution. Each hypothesis remains unapproved until a human judges its interpretation, alternative and next step against the cited originals.

`Harness.run()` returns a receipt and verification report without candidate prose. Failed checks quarantine the candidate. `inspect()` opens an explicitly labeled human-review workspace; it is not the accepted analyst summary. `approved()` is the normal presentation gate and requires a current authorized approval. The viewer renders text/JSON without model HTML or executable actions. The CLI `show`, Databricks publisher and Tines handoff all reload the protected ledger rather than trusting caller-provided `approved` flags.

## Human review workflow

Install the package, then plan or explicitly dispatch:

```bash
timeline analyze output/case-001 --ledger analysis/usage.sqlite
timeline analyze output/case-001 --ledger analysis/usage.sqlite --allow-ai --output analysis/receipt.json
```

Record the `action_id` from the receipt. Planning also writes an audit event but sends no request. `prepare()` remains a pure local preview helper and does not dispatch or write an audit event.

An administrator creates a protected policy from [`ai-review-policy.example.json`](../deploy/ai-review-policy.example.json), assigns exact case IDs and records the SHA-256 independently. CLI identity comes from the operating-system UID (`local:uid:1000`, for example), never from a `--reviewer` name. The policy can require the initiator and reviewer to differ. The shared viewer derives `oidc:` plus SHA-256 of canonical `[issuer, subject]` from validated, unexpired Streamlit OIDC claims; it does not accept identity from the decision JSON. A trusted custom service may pass its authenticated principal to `run(principal=...)` and `review(principal=...)`. Do not expose those Python arguments as unauthenticated request fields.

```bash
timeline-ai inspect output/case-001 --ledger analysis/usage.sqlite --action ACTION_ID --output analysis/review-workspace.json
timeline-ai review-template output/case-001 --ledger analysis/usage.sqlite --action ACTION_ID --output analysis/human-decision.json
timeline-ai chunk output/case-001 --ledger analysis/usage.sqlite --action ACTION_ID --chunk-id CHUNK_ID --offset 0 --limit 100
```

The template defaults to no approval. A **human** edits it after inspecting the cited source records:

- Choose `approve`, `reject` or `request_changes`, and explain the decision.
- Keep the exact `result_sha256` and cited chunk IDs.
- Acknowledge grouping, omitted events, quarantine and collection scope.
- Assess every observation as `supported` and every accepted hypothesis as `plausible_hypothesis`; provide a rationale for each. A hypothesis assessment covers its alternative and proposed step too. Unsupported claims cannot be approved. Reject/request changes instead.

```bash
timeline-ai review output/case-001 --ledger analysis/usage.sqlite --action ACTION_ID --input analysis/human-decision.json --review-policy /etc/timeline/ai-review.json --review-policy-sha256 POLICY_SHA256
timeline-ai show output/case-001 --ledger analysis/usage.sqlite --action ACTION_ID --review-policy /etc/timeline/ai-review.json --review-policy-sha256 POLICY_SHA256 --output analysis/accepted.json
```

Approval binds the candidate, evidence, verifier and policy. Changed evidence, a changed policy pin, an unauthorized reviewer, a later rejection/request-changes or altered call records blocks subsequent presentation. Cached calls do not approve anything or erase review history. A later decision can revoke an earlier approval. No command edits a cached candidate in place or automatically retries a failed call. For revisions, preserve the prior action and have an operator explicitly choose a revised task/context or a separately captured output within budget; do not reset the ledger to bypass limits.

Use [`11_ai_evidence_and_human_review.ipynb`](../notebooks/11_ai_evidence_and_human_review.ipynb) for an executable synthetic walkthrough. It never calls a provider or automatically records human approval.

## Other AI providers and actions

The single dispatch interface is `Harness.run()`. A trusted provider adapter can implement `responses.create(**request)` and return an object with `model_dump(mode="json")`, containing a completed status, provider ID, input/output usage and either `output_text` or Responses-style output messages. The harness logs its submitted normalized request and returned object. If an adapter transforms the wire request, it must also retain its exact provider request/response in the returned audit object; transport authenticity remains the adapter's responsibility. Provider credentials belong in its secret configuration, not those audit objects. The adapter must not perform extra unbudgeted model calls, retries or tool actions.

For an already captured output:

```bash
timeline-ai request output/case-001 --ledger analysis/usage.sqlite --output analysis/prepared.json
# Assemble provider, exact prepared request and captured response in external.json.
timeline-ai import output/case-001 --ledger analysis/usage.sqlite --input analysis/external.json
```

The import requires the exact prepared context and output protocol. Imported origin and usage are **self-reported**, not authenticated proof of what another service saw or spent. The import still consumes a case call, checks the declared token limits, records the response and enforces the same human-review gate. It cannot retroactively control a call made outside this tool. Unknown or mismatched contexts must not be passed off as verified harness actions. The retired `generate_ai_enrichment` entry point remains non-dispatching. No unrestricted agent/tool executor is introduced.

## Full audit export and recovery

```bash
timeline-ai export output/case-001 --ledger analysis/usage.sqlite --action ACTION_ID --output analysis/audit-case-001
timeline-ai verify-export analysis/audit-case-001 --manifest-sha256 INDEPENDENTLY_RECORDED_SHA256
timeline-ops ledger-backup --ledger analysis/usage.sqlite --output backup/ai-001
timeline-ops ledger-restore --snapshot backup/ai-001 --snapshot-sha256 SNAPSHOT_SHA256 --output analysis/restored
```

`action.json` contains the exact identity and stored call; `audit.jsonl` contains that action's hash chain; `chunks.jsonl` indexes **all** normalized events; `evidence_bundle/` retains all original files and receipts. The export verifier reconstructs chunks and requests against the bundled source, verifies stored output checks and checks every file and event locator. Planned and failed actions are exportable too. An export's integrity status is not a new human approval.

SQLite writes call state and corresponding audit events transactionally. Audit update/delete triggers prevent ordinary accidental edits. The reader checks the action chain and the latest recorded call hash before trusting a result. Store export manifest pins or audit heads outside the writable host, using your protected case store or WORM logging service. A local hash chain **cannot** detect a complete history rewrite or rollback if an attacker can replace all copies and independent pins. Protect the ledger, policy, host, backups and authenticated service; SQLite is not an independent identity or authorization server.

Backup/restore copies all audit events and decisions through SQLite's snapshot API, including WAL commits. Historical pre-0.14 usage remains charged and restorable, but old analyses remain unreviewed. Fence original writers and reconcile dispatch history before recovery. A restored snapshot cannot know about later approvals, revocations or provider calls; do not resume publication until those histories are reconciled.

## Publication and deployment

Databricks `publish_analysis` now requires `bundle`, `ledger`, `review_policy` and `review_policy_sha256` keyword arguments. It rechecks the approved result and writes an append-only `analysis_releases` record keyed by case, bundle, action and review hash. Replay cannot replace a previous review version. Legacy `analysis` rows are not promoted. Remove analyst access to old unreviewed rows as part of deployment migration.

The Tines `approved_handoff` helper produces only a current approval receipt, chunk IDs and a deterministic idempotency key. It makes no HTTP call. Use it inside an authenticated, case-authorized service before delivering a story event; never trust an inbound webhook's approval flag. Tines orchestration and review polling need no model. [Tines integration details](../integrations/tines/README.md).

Published Delta rows, exported JSON and delivered browser content are **historical snapshots**. A later local revocation does not recall those copies. Live analyst applications must call `approved()` again before presenting a result, and downstream operators must reconcile revocations before using stored releases. No raw-table permission can substitute for that gate.

For the optional shared viewer, pin the additional `ai` paths in each case's viewer policy: `ledger`, `review_policy`, `review_policy_sha256`. Grant the service write access only to its AI audit ledger; keep evidence, signature trust and policies read-only. Never mount provider credentials or signer keys into the viewer. Only case-authorized humans listed in the pinned review policy see the draft workspace; ordinary case readers see only accepted output. Read [deployment](DEPLOYMENT.md) and [threat model](THREAT_MODEL.md).

## Validation and limits

Automated tests cover forged/mismatched chunks, counts/times/status/actor contradictions, missing and duplicate claims, uncited summary and approval injection, valid but irrelevant citations, per-claim adjudication, stale approvals, separation of duties, revoked decisions, cross-case substitution, external captures, malformed usage, cache/audit tampering, backup/restore, complete chunk exports and Databricks/Tines gates. The real Spark/Delta CI gate exercises approved publication and replay. Tests use synthetic providers and reviewer fixtures; they do not measure model accuracy, live tenant identity configuration or the correctness of a human judgment.

Keep the existing bounded routes: Luna for summarize, Terra for correlate, Astra only for explicitly requested critical review. The same local verifier applies to all three, costs zero tokens and never escalates automatically. A more expensive model is not an authority to approve another model. Evaluate representative incidents and human citation-faithfulness judgments before changing route defaults. See [task limits and model policy](AI_HARNESS.md).
