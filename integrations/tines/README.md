# Dedicated Tines stories and operational implications

Two exported stories live in [`stories/`](stories/):

| Story | Behavior |
| --- | --- |
| `publish_and_monitor.json` | Receive an evidence-bundle reference; validate required fields; submit the configured Databricks job with a stable idempotency token; poll every 30 seconds up to 60 retries; emit success, job failure, submission failure, poll failure or timeout receipts |
| `inspect_run.json` | Read the status of an existing run after an interruption or timeout; does not submit another job |

Exports use the structure in [Tines' story import documentation](https://www.tines.com/stories/docs/api/stories/import/). All actions are disabled initially. Regenerate them with `python scripts/build_tines_stories.py`. Graph and boundary checks run in CI; import acceptance and formula evaluation must be checked in your tenant.

## Setup

1. Deploy the Databricks job following [the Databricks guide](../databricks/README.md).
2. Create a Tines resource `databricks_host` containing your approved HTTPS workspace origin without a trailing slash. Incoming events cannot choose this host.
3. Create a numeric resource `timeline_job_id` containing the deployed job ID. The incoming event cannot choose arbitrary jobs.
4. Create the `databricks_token` credential for the scoped job-running identity. Use your supported Tines credential/OAuth refresh workflow; do not place real tokens in the story JSON.
5. Import each JSON story into the intended team. Assign a fresh secret to each webhook and verify its access-control setting. Configure headers to remain included, because the story reads `receive_bundle.body`.
6. Review the graph, formula evaluation and resources in a test tenant. Enable all actions only after synthetic acceptance tests. Configure Tines action-failure monitoring so transport-level failures also reach your normal operational queue.

The webhook acknowledges receipt with HTTP 202. That response does not mean validation, publication or analysis has completed. Terminal story receipts carry the actual outcome.

## Payload and producer

First create and verify a local bundle, then upload it to your allowed Unity Catalog Volume:

```bash
timeline databricks-upload output/demo-001 --volume-root /Volumes/main/incident_timelines/evidence/bundles
```

Use the returned directory as `--remote-bundle`; generate the body to send to Tines:

```bash
timeline tines-request output/demo-001 --remote-bundle /Volumes/main/incident_timelines/evidence/bundles/BUNDLE_ID --job-id 12345
```

The body contains `contract_version`, `case_id`, `bundle_id`, `bundle_path`, `manifest_sha256` and `idempotency_key`. It carries references and integrity anchors, not raw event arrays or AI prompts. The deployed job verifies the independently supplied manifest hash and rejects unsafe Volume paths before publication.

Tines supports secret, team and tenant webhook authentication and signed requests; configure the mechanism appropriate for the producer using the [official webhook guide](https://www.tines.com/stories/docs/actions/types/webhook/). Restrict the job identity to the intended evidence Volume and destination schema. A valid payload does not override those permissions.

## Dedicated operational implications

| Concern | Implementation or deployment requirement |
| --- | --- |
| Replay / duplicate submissions | The producer derives a stable token from job ID and manifest digest. Databricks returns the existing run for repeated submissions with that token. Keep it unchanged after network ambiguity. |
| Retry cost | Polling calls no language model. Polls wait 30 seconds and stop after 60 retries. The Databricks job has its own timeout; a story timeout is not cancellation. |
| Secret expiry / HTTP errors | Explicit submission and polling failure receipts; action-level monitoring handles transport failures that emit no event. Refresh credentials before retrying. |
| Incomplete publication | The job inserts a publication marker last; analysts read the committed view. A failed stage is safe to rerun against the same bundle. |
| OCSF completion | The optional Databricks OCSF task is disabled by default. If enabled in strict mode, rejected OCSF records make the job fail; the earlier timeline publication may remain committed. With `ocsf_quarantine=true`, success may be partial. The current story receipt carries job status, so inspect OCSF task output or `published_ocsf_exports` counts and route rejections for review. See the [OCSF guide](../../docs/OCSF_EXPORT.md). |
| Reused IDs or altered bundles | Source content contributes to event identity. A supplied manifest hash must match before a job accepts a bundle. |
| Untrusted data / prompt injection | Stories send reference fields only. They do not execute payload-selected code, SQL, hosts, models or containment actions. |
| Data residency and retention | Raw evidence stays in the configured Volume; story events still contain case IDs, paths and run metadata. The export requests a one-day event retention window; verify tenant policy, monitoring retention and case-record requirements. |
| Human review | A successful job emits `human_review_required: true`. It is a review cue, not an authenticated approval decision. Connect it to your approved case/review workflow. No automatic containment or case closure is implemented. |
| Scale | Large logs belong in the evidence store. Pass bundle references into Tines. Monitor the delay queue and concurrency limits; the [Tines delay guide](https://www.tines.com/stories/docs/actions/types/event-transformation/delay/) documents queue behavior. |
| Poll interruption | Use the inspect-existing-run story with `{"run_id": 123}`. Inspect the existing run before requesting another job. |

## Acceptance cases

Exercise a valid synthetic bundle, duplicate payload, modified manifest, missing required field, unauthorized Volume path, expired credential, failed job, active job beyond the polling cap and interrupted polling. Confirm no success receipt appears for failure paths. Compare the published count to the manifest and download/verify the original bundle. Verify source evidence and AI findings remain separate in the case workflow.

No live Tines tenant import or execution was performed during repository implementation. Credential placeholders and all disabled flags are intentional deployment requirements.
