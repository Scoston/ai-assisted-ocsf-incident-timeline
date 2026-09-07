# Parser contracts and coverage

All parsers use version `2.0.0` and the `timeline-ocsf-aligned-2.0` analytical profile. Select a parser explicitly with `--input PARSER=PATH`; the pipeline does not ask an LLM to infer a schema.

The mappings reference classes in the [OCSF 1.3.0 schema](https://github.com/ocsf/ocsf-schema/tree/v1.3.0). They select a class, not a complete upstream event schema. Unmapped generic events retain `ocsf_class_uid=0` and `metadata.ocsf_mapping_status=unmapped`; the tool does not label arbitrary log entries as process activity.

Version 0.6.0 adds a separate [schema-validated OCSF export](OCSF_EXPORT.md) for all nine mapped core classes. It reads the archived source fields and validates complete emitted events against pinned definitions. A parser can accept a sparse record into the timeline while OCSF export rejects it for missing required objects. Native OCSF export accepts only validated 1.3.0 core events in the advertised classes; project Parquet is still an analytical timeline format.

| Parser | Supported source contract | Time field / numeric unit | Class selection |
| --- | --- | --- | --- |
| `cloudtrail` | CloudTrail record, `Records` envelope, or EventBridge `detail` | `eventTime`, zoned ISO | API Activity 6003 |
| `guardduty` | GuardDuty finding / `findings` export | `updatedAt` or `createdAt`, ISO | Detection Finding 2004 |
| `securityhub` | AWS ASFF finding / `Findings` envelope | `UpdatedAt` or `CreatedAt`, ISO | Detection Finding 2004 |
| `vpc_flow` | Default 14-field AWS flow text or equivalent field-name JSON | `start`, seconds | Network Activity 4001 |
| `entra_signin` | Graph sign-in / `value` wrapper; documented Log Analytics aliases | `createdDateTime`, `CreatedDateTime`, `TimeGenerated`, ISO | Authentication 3002 |
| `entra_audit` | Graph directory audit / `value` | `activityDateTime` or `TimeGenerated`, ISO | API Activity 6003 |
| `azure_activity` | Azure Activity export | `eventTimestamp`, `TimeGenerated`, `time`, ISO | API Activity 6003 |
| `m365_audit` | Unified Audit record or embedded JSON `AuditData` | `CreationTime`, ISO | API Activity 6003 |
| `defender_alert` | Microsoft Graph/Defender alert export | `createdDateTime`, `alertCreationTime`, `firstActivityDateTime`, ISO | Detection Finding 2004 |
| `crowdstrike_detection` | Falcon detection resource with `behaviors[]`; one event per behavior | Behavior timestamp, then detection timestamp, ISO | Detection Finding 2004 |
| `gcp_audit` | Cloud Logging AuditLog entry with `protoPayload` | `timestamp` or `receiveTimestamp`, ISO | API Activity 6003 |
| `okta` | System Log event | `published`, ISO | Authentication 3002 for authentication/session/MFA events; API Activity 6003 otherwise |
| `windows_event` | Normalized JSON export or Windows Event XML export | `TimeCreated.SystemTime` and documented JSON aliases, ISO | Logon-related IDs 3002; 4688 process 1007; 1102 event-log 1008; others unmapped |
| `syslog` | RFC 5424 version 1 text or equivalent structured JSON | Zoned RFC 5424 timestamp | Unmapped; message retained in original source |
| `zeek` | JSON connection, DNS and HTTP logs with `_path` | `ts`, seconds | Conn 4001, DNS 4003, HTTP 4002; other explicit paths unmapped |
| `suricata` | EVE JSON | `timestamp`, ISO | Alert 2004, flow/netflow 4001, DNS 4003, HTTP 4002; other types unmapped |
| `plaso` | psort JSONL or CSV with `datetime` or `timestamp` and a message/data type | `datetime` ISO or `timestamp` microseconds | `fs:` records 1001; others unmapped |
| `ocsf` | OCSF JSON/JSONL/Parquet with `class_uid` and time; project Parquet `record_json` envelope | `time` milliseconds or `time_utc` ISO | Preserve positive source class; re-ingestion records new source provenance |
| `tines_audit` | Tines audit record export | `created_at` or `timestamp`, ISO | API Activity 6003 |
| `databricks_audit` | Workspace audit JSON or exported `system.access.audit` rows | `event_time` ISO or `timestamp` milliseconds | API Activity 6003 |
| `ai_agent` | Project audit contract: timestamp, action/tool, agent ID, event ID, resource/status | `timestamp`, zoned ISO | API Activity 6003 |
| `defender_hunting` | Explicit `table` plus `record` from one of 14 supported hunting tables | `record.Timestamp`, ISO | Process 1007, network 4001, logon 3002, file 1001, identity/cloud API 6003; email/URL/registry/generic-device tables unmapped |
| `azure_log_analytics` | Explicit `table` plus `record`, eight supported tables | `record.TimeGenerated`, ISO | Selected Windows event classes, sign-ins 3002, CommonSecurityLog with endpoints 4001; Syslog/other Windows IDs unmapped |
| `google_workspace` | Admin Reports activity with `id`, `actor`, `events[]`; every event expanded | `id.time`, ISO | Login 3002; admin/token/drive 6003 |
| `crowdstrike_alert` | Falcon alerts v2 entity (separate from legacy detection/behavior exports) | `timestamp`, then `created_timestamp`, ISO | Detection Finding 2004 |

Version 0.10.0 supplies 25 parser contracts. New parsers start at 1.0.0. M365 and GuardDuty advance to 2.1.0: suffix-free M365 `CreationTime` is explicitly UTC under the source contract, and GuardDuty captures native `ipAddressV4` fields. Re-ingesting these two sources changes event identities; retained bundles are not rewritten. New OCSF mappings are version `ocsf-export-1.1.0` and retain verification support for 1.0.0 exports.

For query exports use `{"table":"DeviceProcessEvents","record":{...}}` or `{"table":"SecurityEvent","record":{...}}` per row; raw Results/columns/rows arrays are not guessed into a table. See [allowed tables and source clocks](ENTERPRISE_APIS.md). Collection archives both the native API body and projected parser records. A mapped class alone does not guarantee all required OCSF fields exist.

The exact field aliases are centralized in `src/timeline_demo/parsers/registry.py`. Every listed parser has a synthetic fixture in `examples/parser_samples.json` and a regression test. These fixtures establish the advertised shape; they do not establish compatibility with every vendor SKU, API revision or export option.

## Containers and reader rules

JSON documents support arrays, single objects and `Records`, `records`, `value`, `resources`, `Findings`, `findings` or `items` arrays. JSONL records stream one object per line. CSV/TSV are supported where the source contract is flat. Gzip wraps text formats. Parquet reads in batches and requires the `parquet` extra; native nested fields remain available to the parser.

Windows XML is an **exported Event XML document**, not a native `.evtx` reader. DTD/entity declarations are rejected. RFC 3164 timestamps without a year/time zone are not accepted as RFC 5424. Custom VPC Flow field orders, non-JSON Zeek TSV logs, Falcon FDR, binary Plaso storage, browser SQLite files and memory images require their own source export/conversion step.

Malformed record objects and timestamps fail by default. `--quarantine` records per-record failures and retains the original source. Malformed whole JSON/XML documents fail the batch. Source-specific numeric units are explicit; the tool does not guess seconds versus milliseconds from magnitude.

## Plaso and broad forensic artifact coverage

Use upstream Plaso/log2timeline to parse disk, file-system, browser, registry and native event-log artifacts, then export its event records for this pipeline. Consult the [official psort documentation](https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html) for supported output modules in your installed Plaso version. Preserve original artifacts, the `.plaso` storage file, tool version, parser selection, time-zone assumptions and export commands in the acquisition record.

For example, with an installed psort version that exposes `json_line`:

```bash
psort.py -o json_line -w events.jsonl collection.plaso
timeline ingest --case-id case-001 --input plaso=events.jsonl --output output/case-001
```

Confirm the output module and timestamp fields in your installed version with `psort.py -h`; this repository does not bundle Plaso or claim to reimplement all upstream parsers. CSV exports need `datetime` or `timestamp` fields; legacy l2tcsv split date/time columns need an explicit conversion before ingestion.

## Adding a source

Define the supported export shape and time semantics, add a registry mapping or dedicated reader when needed, preserve the archived raw source, and add representative positive, malformed and multi-record fixtures. Do not substitute the current time, invent a time zone, suppress unknown fields in the source evidence, or treat an artifact catalog entry as implemented code.

## IOC candidate extraction

The separate deterministic extractor supports validated unscoped IPv4/IPv6 literals, domain-like strings, URLs, emails and SHA-256-shaped strings. IPv6 values use compressed notation; IPv4-mapped IPv6 uses a dotted IPv4 suffix consistently across supported Python versions. Zone identifiers, defanging, URL punctuation repair, IDN normalization and threat classification are outside this contract. Candidate presence does not make an address malicious. [Synthetic precision/recall probes](EVALUATION.md) are intentionally small and do not establish production detection quality.
