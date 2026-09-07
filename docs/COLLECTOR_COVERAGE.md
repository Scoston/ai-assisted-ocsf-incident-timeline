# Enterprise collector assessment and rollout

Reviewed against version 0.9.0 on 2026-09-07. The four original collectors had durable paging and evidence receipts, but covered only Entra sign-ins, regional CloudTrail management history, Tines audit and Databricks audit. They could not independently reconstruct mailbox compromise, endpoint execution, directory persistence or most network activity.

Version 0.13.0 provides **19 collector types**, **28 import/parser contracts**, and [complete pinned native Plaso parser coverage](PLASO.md). GitHub organization audit collection and Kubernetes audit parsing extend the identity, cloud, endpoint, mail and SIEM coverage. Choose the sources present in your organization. This is an incident-response coverage assessment, not a claim that every enterprise owns these products or that their APIs expose every event.

## Coverage decisions

| Investigation need | Sources to enable | Evidence and remaining boundary |
| --- | --- | --- |
| Account takeover and identity persistence | Entra sign-ins and directory audit; Okta; Azure Monitor sign-in tables | Authentication, app consent and administrative changes. Collect interactive, noninteractive, service-principal and managed-identity tables separately when forwarded to Azure Monitor. AD/DC logs require forwarding or export. |
| Mailbox compromise, phishing and data sharing | M365 Exchange/SharePoint/General/DLP feeds; Defender email/URL tables; Workspace login/admin/token/drive | Audit operations, sharing, tokens and message/attachment/URL metadata. This does not download mailbox contents or attachments. |
| Ransomware and lateral movement | Defender alerts and hunting device tables; Falcon alerts; Azure SecurityEvent/WindowsEvent or Splunk Windows exports | Alert context and process/network/file/logon evidence. Falcon alerts are findings, not FDR or a complete process history. |
| Cloud credential abuse | CloudTrail, GuardDuty, Security Hub CSPM, Azure Activity, GCP Audit | Management operations and updated findings. Repeat account/region/project configurations; delegated views depend on actual access. Disabled auditing and unretained history cannot be recovered automatically. |
| Exfiltration, command-and-control and remote access | CloudWatch VPC/JSON/syslog; Splunk selected index/sourcetype; Azure CommonSecurityLog/Syslog | Existing firewall, VPN, DNS and proxy evidence in supported formats. Generic syslog retains vendor text without inferring action semantics. |
| Automation and lakehouse abuse | Existing Tines and Databricks audit collectors | Story/platform operations, correlated with identity and cloud evidence. |

Collection, parsing, deduplication, verification and OCSF export use **zero model tokens**. The existing AI harness receives a bounded evidence selection, uses its configured task/model routes and reports omitted coverage. No collector invokes a model.

## Select an incident-specific collection set

| Incident | Start with | Add when indicated |
| --- | --- | --- |
| Microsoft mailbox compromise | Entra sign-ins/audit, M365 `Audit.Exchange` | SharePoint/General/DLP feeds; Defender `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `UrlClickEvents`; noninteractive sign-ins |
| Endpoint ransomware | Defender process/file/network/logon tables and alerts, or Falcon alerts with endpoint exports | Windows/Sysmon, DC authentication, VPN/firewall, affected cloud accounts and backup audit exports |
| Cloud credential abuse | CloudTrail/GuardDuty/Security Hub, Azure Activity/Entra audit, or GCP Audit | Workload-identity sign-ins, enabled data-access logs, network and Databricks audit |
| OAuth/SaaS takeover | Entra audit or Okta, M365 General, or Workspace login/admin/token | Workspace Drive, endpoint telemetry and relevant SaaS audit exports |

Use one configuration per tenant/account/region/project, application/content type, table or central-log source. Set a descriptive `source_id`; it is a label, not proof of the authenticated identity. Copy [configuration examples](../examples/collectors/) and replace identifiers. Never put access tokens in JSON. Querying warehouses and SIEMs can incur provider charges even when model tokens are zero.

## Formats and normalization

- Direct APIs feed their declared parser. GuardDuty SDK fields use botocore's wire-name model; the decoded SDK response is archived separately.
- Defender and Azure Monitor rows use `{"table":"TableName","record":{...}}`. The table identifies the schema explicitly. HTTP attachments preserve original column arrays/dynamic strings; projected record hashes describe a separate representation.
- Workspace expands every `events[]` item with a child index and distinct timeline identity. Children retain the same source-record hash.
- CloudWatch and Splunk require `parser` and `format`. JSON means exactly one source object per message. Text supports RFC 5424 or default 14-field VPC records. Mixed sourcetypes, arbitrary vendor text, arrays within messages, native EVTX and packets need a deliberate export/conversion step. Exported Windows XML is supported offline.
- Raw evidence remains available for unmapped classes. Email, URL-click, registry and generic device events do not acquire an invented OCSF class. Strict OCSF export rejects unsupported/sparse events; quarantine writes exact rejection receipts.

See [parser contracts](PARSERS.md), [APIs and permissions](COLLECTION.md), and [OCSF boundaries](OCSF_EXPORT.md).

## Rollout and acceptance

1. Inventory identity providers, endpoints, mail platforms, cloud accounts and central logs. Enable needed source-side forwarding/auditing through your existing administration process; collectors never enable it themselves.
2. Grant the applicable read scopes and obtain correctly scoped tokens through existing identity tooling. SDK sources use the role/profile chain. Refresh expiring tokens externally and resume the checkpoint.
3. Collect a representative closed window into source-specific state/output. Compare source UI/export counts and records, including UTC boundaries, nested events, updated findings and late delivery. Missing permissions/licensing can restrict visibility without an API error.
4. Exercise interruption, expired-token and expired-cursor cases. Preserve failed state. Validate raw hashes and field mappings, then establish lag, overlap and backfill policies per source.
5. Publish the verified bundle through Databricks and Tines. Pass its reference and manifest pin; retain collector credentials/state on the collector host. Drained pagination is an acquisition result; OCSF can still reject records, and Tines must honor existing failure/partial-result handling.

Offline regressions and the seventh notebook exercise synthetic contracts. CI adds Python 3.10/3.12, real Jupyter and signed Delta publication/replay. **Live tenant acceptance has not been performed:** enterprise collector credentials and representative private incident logs were unavailable.

## Organization-specific gaps

This release does not install endpoint agents, scrape arbitrary SaaS consoles, acquire disks/memory/packets, implement every firewall/VPN dialect or replace vendor retention. Direct Falcon FDR, SentinelOne, Elastic, Salesforce audit and long-term object-store acquisition are candidates when the organization's inventory requires them. Use a matching parser for structured exports, or add a reviewed contract and representative fixtures first. These are explicit gaps, not advertised placeholder collectors.

## Developer infrastructure incidents

Repository/credential or supply-chain incidents can use `github_audit`; Kubernetes API abuse and cluster authorization investigations can use `kubernetes_audit` through dedicated CloudWatch/Splunk sources or offline exports. Neither is a disk/runtime/packet collector. See [contracts, source restrictions and acceptance](DEVELOPER_INCIDENTS.md).
