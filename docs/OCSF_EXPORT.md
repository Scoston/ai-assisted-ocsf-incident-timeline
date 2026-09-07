# Pinned OCSF export

Version 0.6.0 adds a separate, deterministic export of core OCSF 1.3.0 events. The existing `timeline.jsonl` remains the project analytical profile, with its original event identities and evidence references. Exporting does not modify an evidence bundle, call a model or fetch a schema over the network.

Version 0.10.0 adds mapping version `ocsf-export-1.1.0` for the new enterprise parsers; 1.0.0 exports remain verifiable. Query-row wrappers and Workspace child references remain source-bound. Email/URL/registry/generic telemetry and sparse records may stay unmapped or fail required-field validation; review quarantine counts before publication.

## Use the export

```bash
timeline export-ocsf examples/demo_bundle --output output/demo-ocsf
timeline verify-ocsf output/demo-ocsf --bundle examples/demo_bundle
```

The five-event demo exports five valid events. Use `--manifest-sha256 SOURCE_MANIFEST_SHA256` on `export-ocsf` to pin the source independently. On `verify-ocsf`, the same option pins **the export manifest**, while `--bundle` verifies the source manifest pin recorded inside it and checks every event's provenance against the timeline.

Strict mode fails if any timeline event cannot satisfy the schema. The final output directory is created only on success. To retain a partial export and explicit rejection receipts:

```bash
timeline export-ocsf output/case-001 --output output/case-001-ocsf --quarantine
```

| Artifact | Contract |
| --- | --- |
| `ocsf.jsonl` | Schema-validated events in the source timeline's order; no duplicate timeline event references |
| `rejections.jsonl` | One receipt per rejected timeline event, including parser, original file/record/child reference and reason |
| `export_manifest.json` | SHA-256 and size of both artifacts, source bundle/manifest binding, schema-lock pin, mapping version and exact coverage counts |

`exported_events + rejected_events = source_events`. These are **deduplicated timeline events**. The source bundle's `receipts.jsonl` continues to record every ingestion occurrence. Source records already quarantined during ingestion never became timeline events and remain accounted for in the source manifest; they are not counted again by this export. Export rejects never remove the original evidence or its timeline row.

Each accepted event includes `unmapped.timeline_export`, linking its derived OCSF fields to the original file hash, deterministic record hash, parser version, record index, child index and timeline event UUID. Native OCSF retains its original metadata and other fields; a pre-existing `unmapped.timeline_export` field causes rejection to avoid overwriting source content.

## Exact schema scope and provenance

The version is deliberately pinned to **1.3.0**, matching the project's existing class reference. This is not a claim that 1.3.0 is the newest OCSF release. Nine complete JSON Schema definitions, including their referenced objects and required/conditional field constraints, ship inside the wheel. No optional profiles or extensions are enabled. Other classes, other versions and declared profiles/extensions are rejected.

The inputs and generator are recorded in [`schema-lock.json`](../src/timeline_demo/resources/ocsf/1.3.0/schema-lock.json):

- Official catalog: [OCSF 1.3.0 export](https://schema.ocsf.io/1.3.0/export/schema), SHA-256 `6ccff0f70b6216abc8f82be3756a9a167662a535c64a6a60df111b0db363e3e2`.
- Schema reference: [upstream tag v1.3.0](https://github.com/ocsf/ocsf-schema/tree/v1.3.0), commit `c8bde8c4cc7e93bb4a36e873623bbe099da22fb5`.
- Conversion: [`ocsf-json-schema` 1.2.0](https://github.com/nsmithuk/ocsf-json-schema), a third-party generator, using the downloaded official catalog and `profiles=[]`. It generates Draft 2020-12 definitions with embedded references, including `at_least_one` and `just_one` constraints. This is local validation against generated definitions, not an OCSF certification or a live call to the schema server.
- Runtime: `jsonschema` validates every field and nested object; additional checks enforce the version, empty profile/extension scope, and `type_uid = class_uid * 100 + activity_id`. Resource hashes are checked before loading. External schema references are forbidden.

Apache-2.0 license and notice files for the schema are bundled with the generated definitions. The generator is a development tool; it is not a runtime dependency. To reproduce the packaged bytes:

```bash
python -m pip install ocsf-json-schema==1.2.0
curl --fail --output /tmp/ocsf-1.3.0.json https://schema.ocsf.io/1.3.0/export/schema
python scripts/build_ocsf_schemas.py /tmp/ocsf-1.3.0.json --check
```

The script rejects catalog or generator drift. If the official endpoint changes serialization, retain or obtain the exact reviewed catalog bytes before reproducing. A schema upgrade requires a reviewed lock update and mapping/fixture validation; the application never follows an upstream update automatically.

## Mappings and explicit limits

| Class | Source contracts | Required mapping and limitations |
| --- | --- | --- |
| 6003 API Activity | CloudTrail, Entra audit, Azure activity, M365, GCP audit, non-authentication Okta, Tines audit, Databricks audit, AI audit | Source operation, actor and source endpoint required. CRUD activity remains Unknown (0) when no reviewed vendor mapping exists; operation and original status remain available. A non-IP endpoint label remains a name. |
| 3002 Authentication | Entra sign-in, authentication Okta, Windows 4624/4625/4634/4648 | User plus service or destination required. Entra sign-in and known session start/end map to Logon/Logoff. Windows 4624/4625 explicitly map success/failure. Other outcomes are not inferred. |
| 2004 Detection Finding | GuardDuty, Security Hub, Defender, CrowdStrike, Suricata alerts | Source finding ID and title required. Suricata signature IDs identify rules, so its finding UID is explicitly derived from the source event identity. Detection lifecycle remains Unknown; each CrowdStrike behavior retains its own event reference. |
| 4001 Network Activity | VPC flow, Zeek connection, Suricata flow/netflow | Destination endpoint required; available source/destination ports are typed and range checked. An ACCEPT/REJECT label is not treated as a connection lifecycle. |
| 4002 HTTP Activity | Zeek HTTP, Suricata HTTP | Destination, source method and response status required. Standard method IDs are mapped; other methods use Other (99) with the source method name. Request/response payload bodies remain archived. |
| 4003 DNS Activity | Zeek DNS, Suricata DNS | A source query name is required by this exporter. Combined sensor records do not establish a single traffic direction; activity remains Unknown. Answer enrichment is not synthesized. |
| 1007 Process Activity | Windows 4688 | Source computer, subject user and new PID required; hex PIDs supported. Launch maps to activity 1. Device type remains Unknown. |
| 1008 Event Log Activity | Windows 1102 | Source log/channel required; Clear maps to activity 1. |
| 1001 File System Activity | Plaso `fs:` exports | Source host, actor and filename required. File/device type and unreviewed activity remain Unknown. Sparse filesystem exports may require quarantine. |

Native OCSF input for these nine classes is validated and preserved. An OCSF-aligned project Parquet row does not become a full OCSF event merely by being read through the `ocsf` parser. Generic syslog, unmapped Windows events, other Plaso event families and other unsupported class mappings receive rejection receipts when quarantine is enabled. Parser success alone does not establish OCSF export readiness.

## Databricks and Tines

The deployed job includes `export_and_publish_ocsf`, after the ordinary timeline publication and before final inspection. It is disabled by default for compatibility. To enable strict export, include these variables in your existing bundle validation/deployment command:

```text
ocsf_enabled=true,ocsf_export_root=/Volumes/main/incident_timelines/evidence/ocsf,ocsf_quarantine=false
```

The job identity needs write access to this separate derived-output directory. It creates a deterministic directory from bundle identity and mapping version, verifies an existing export on replay, and rejects a previous partial export in strict mode. The Tines request format and model token budget do not change.

On a cluster with the project wheel, the equivalent Python API is:

```python
from timeline_demo.ocsf import export_bundle
from timeline_demo.integrations.databricks import publish_ocsf_export

source = '/Volumes/main/incident_timelines/evidence/bundles/BUNDLE_ID'
destination = '/Volumes/main/incident_timelines/evidence/ocsf/NEW_EXPORT'
report = export_bundle(source, destination, manifest_sha256=SOURCE_MANIFEST_SHA256)
published = publish_ocsf_export(spark, destination, source, 'main', 'incident_timelines')
```

`ocsf_events` and `ocsf_rejections` use case/bundle/export/timeline-event keys. `published_ocsf_exports` is inserted last, after verification; `published_ocsf` joins accepted events to that marker. Filter by `export_id` as well as case and bundle. Replays do not insert duplicate events. Markers retain rejection counts, including when an export contains no accepted events.

With strict export enabled, an OCSF failure makes the Databricks job fail and follows the existing Tines failure path. The earlier timeline publication may already be committed; job failure does not roll it back. With `ocsf_quarantine=true`, job success can mean a partial OCSF export. The current Tines success receipt does not include OCSF counts: retrieve the task output or query the export marker and route nonzero rejections for review before treating the export as complete. With OCSF disabled, success describes ordinary timeline publication only.

The fourth Jupyter notebook demonstrates offline export, schema inspection, source binding and rejection receipts. Real Spark/Delta insert/replay is a CI gate. Live tenant grants and job execution remain operator acceptance steps.

## Trust and capacity

Hashes detect alteration relative to a trusted pin; unsigned manifests can be replaced alongside artifacts. Store independent pins and apply your evidence retention controls. Schema validity and source linkage do not establish source authenticity or the truth of an interpretation. Verification with `--bundle` checks the timeline reference, time and class; it does not independently prove the semantic meaning of every vendor field.

Source scans and event joins use disk-backed SQLite, and export validation accounts for event identities on disk. There are no per-event model calls and no extra AI context. Export consumes local storage/CPU and Databricks compute when enabled. No large-case throughput or memory benchmark is claimed.
