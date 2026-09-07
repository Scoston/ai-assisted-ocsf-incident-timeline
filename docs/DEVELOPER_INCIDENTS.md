# Repository and Kubernetes incident coverage

Version 0.12 adds `github_audit` and `kubernetes_audit` parser contracts, both version 1.0.0. They map to OCSF API Activity (6003), with source actions and raw evidence retained. Normalization does not classify an action as malicious.

## GitHub organization audit

Copy [github-audit.json](../examples/collectors/github-audit.json), replace `organization` and `source_id`, and supply `GITHUB_AUDIT_TOKEN` through approved credential delivery. The collector reads `GET /orgs/{organization}/audit-log` on `https://api.github.com`, pins API version `2026-03-10`, requests both Git and web events, and follows validated same-origin, same-path next links. It requests ascending, second-resolution date ranges and applies the exact half-open millisecond interval locally. Raw page bodies and excluded counts remain in the collection bundle.

The [GitHub endpoint contract](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization) requires an organization owner for user credentials; classic tokens use `read:audit_log`, and supported fine-grained/App tokens need organization Administration read permission. Confirm plan availability, SSO authorization and actual visibility in the target organization. The endpoint documents 1,750 queries per hour per user/IP. This adapter spaces pages by 2.1 seconds; shared credentials or other clients need a coordinated limit. A 403 fails the page without advancing; bounded 429 handling defers long delays to the scheduler.

The parser uses `@timestamp` or `created_at` as UTC epoch milliseconds, `_document_id` for the source ID, `actor` as the initiating identity, and repository/organization as the asset. Optional `actor_ip` is preserved. No success result is inferred from the presence of an action.

Repository policy changes, credential authorization, membership changes and recorded Git operations can support supply-chain and source-code theft investigations. Git events have short retention and exclude some operations initiated through browser/API workflows; reconcile them with other evidence. See [GitHub audit search, exports and REST limits](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization). Pagination exhaustion is not proof of historical completeness.

This collector does not read personal security logs, enterprise-wide audit endpoints, GHES or GHE.com hosts. Use separately reviewed contracts for those environments. It makes no repository or organization changes.

## Kubernetes API audit

Use a native `audit.k8s.io/v1` `Event`, JSONL audit file, or an `EventList` JSON export. A Kubernetes resource, ordinary cluster Event or a watch response is a different contract. [The Kubernetes audit schema](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/) distinguishes the request identity, optional impersonated identity, audit stage, request time and stage time.

The parser requires the audit ID, supported stage/level, verb, user and both timestamps. Timeline ordering uses `stageTimestamp`; the original request timestamp remains in raw evidence. Multiple stages of one request share a source audit ID and retain separate deterministic event identities. `user.username` remains the authenticated actor; `impersonatedUser` is retained separately in the original record. Numeric response codes map to success for 200–399, failure for 400–599, otherwise unknown. The first claimed source IP is recorded without claiming it is a verified client address.

Use [CloudWatch configuration](../examples/collectors/cloudwatch-kubernetes.json) for a dedicated audit log group/stream feed, or [Splunk configuration](../examples/collectors/splunk-kubernetes.json) for a dedicated audit sourcetype. Each transported JSON message must contain one audit object. If an EKS group also contains authenticator/controller logs, export or route its audit streams into a dedicated source first; mixed records deliberately fail parsing. Offline example:

```bash
timeline ingest --input kubernetes_audit=apiserver-audit.jsonl --case-id cluster-001 --output output/cluster-001
timeline export-ocsf output/cluster-001 --output output/cluster-001-ocsf
```

Audit collection depends on an existing file or webhook backend and configured retention. There is no historical Kubernetes API audit-list endpoint. Enabling the backend is an administrator task. Audit policy controls whether request/response bodies are captured; those bodies can contain credentials or Secrets. Preserve and protect existing evidence, and choose future logging policy through your platform's governance. See [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/).

## Tenant acceptance

Compare a closed collection interval with the provider's export. Exercise pagination, denied access, missing permissions, timestamp edges, multiple stages and delayed delivery. Confirm repository/org and cluster identity independently. Validate the resulting bundle and strict OCSF export, preserve quarantine/rejection receipts if used, then pass bundle references and pins through the existing Tines/Databricks workflows. The [ninth notebook](../notebooks/09_developer_incidents.ipynb) demonstrates the local flow with synthetic data and no network calls.
