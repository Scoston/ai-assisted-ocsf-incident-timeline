# Complete log2timeline / Plaso coverage

Version 0.13.0 adds a native backend for **all 59 parsers, 186 parser plugins and 4 cookie helper plugins** registered in upstream revision [`00fcc6e7f95a0`](https://github.com/log2timeline/plaso/tree/00fcc6e7f95a002c85464f0dfd193396bd7d86d3), reviewed 7 September 2026. This includes the ESXi parser added after the 20260720 release. The [complete format table](PLASO_COVERAGE.md) lists every registration and its source. The [machine-readable catalog](../src/timeline_demo/resources/plaso_catalog.json) ships in the Python wheel; `timeline plaso-parsers` prints it offline.

This closes the gap between the previous export-only importer and native log2timeline processing. The implementation runs Plaso's actual parser collection. It does not replace its native libraries with approximate Python field mappings. The 249 upstream registrations are separate from this project's **28 import/parser contracts** and **19 live API collector types**.

## Acquire and process native artifacts

Use a Linux or WSL host with a local Docker engine and acquired, stable evidence. Build the optional backend once from this repository:

```bash
docker build --tag timeline-plaso:20260720-00fcc6e integrations/plaso
timeline plaso-ingest --source /cases/acquired --work /cases/work-001 --output /cases/bundle-001 --case-id case-001 --timezone UTC --year 2026
timeline verify /cases/bundle-001
```

The source can be an acquired file, supported disk image or directory of artifacts. This covers native EVTX/EVT, registry hives, MFT/USN, prefetch, shortcuts/jump lists, browser databases and caches, SQLite/ESE/OLE/plist artifacts, macOS/iOS/Android data, systemd journals, syslog, application/server/security logs and every other registered format in the table. Exact file versions, compression/image support and parser behavior are those of the pinned Plaso/dfVFS stack. Unsupported or encrypted sources still require acquisition/decryption using appropriate tools; memory analysis is not provided by Plaso's parser inventory.

All top-level parsers are explicitly selected, enabling their plugins instead of allowing an automatic operating-system preset to narrow coverage. Partitions and VSS stores use `all`. `--timezone` defaults to UTC and is recorded; `--year` is an optional initial year for logs without one. Both are investigator assumptions, not corrections proven from evidence. For split disk images or formats that need companion files, acquire all segments together and use `--entry-point image.E01` within a source directory. Never submit only the first segment.

The image pins an official [Plaso dependency image](https://plaso.readthedocs.io/en/latest/sources/user/Installing-with-docker.html) by digest and overlays a source archive verified by SHA-256. Hash-pinned [dfVFS 20260731](https://github.com/log2timeline/dfvfs/tree/20260731) and [dfDateTime 20260730](https://github.com/log2timeline/dfdatetime/tree/20260730) wheels satisfy the newer source requirements; their versions are checked in the runtime census and recorded in the catalog. Building needs network access. Processing resolves one locally installed immutable image ID, uses `--pull=never` and disables container networking. No API key or LLM is involved: **zero model tokens**. The backend runs with the invoking Linux UID/GID, a read-only root and source mount, dropped capabilities, no new privileges, a temporary filesystem and CPU/RAM/PID budgets. Prefer an unprivileged dedicated acquisition account; Docker daemon access itself is privileged. Do not mount the Docker socket into the shared viewer or Databricks job.

Before processing, the backend reports its actual registered parsers/plugins and hashes of every parser source file. A missing plugin, different source hash or version mismatch blocks ingestion. A tag pointing to an incompatible local image cannot silently reduce coverage.

## Existing storage and exports

Import a compatible `.plaso` storage file without modifying it:

```bash
timeline plaso-ingest --source /cases/collection.plaso --storage-file --work /cases/import-work --output /cases/import-bundle --case-id case-001
```

The pinned storage reader supports the upstream 20260516 storage schema. Older storage must be exported using a compatible original Plaso installation; the bridge never upgrades the evidentiary original in place.

JSONL, dynamic CSV and legacy 17-column `l2tcsv` exports can also be ingested directly without Docker:

```bash
psort.py --include-all -o json_line -w events.jsonl collection.plaso
timeline ingest --input plaso_event=events.jsonl --output output/plaso-case --case-id case-001
timeline ingest --input plaso_event=legacy.csv --assume-timezone America/Chicago --output output/legacy-case --case-id legacy-001
```

`plaso_event` accepts upstream integer microsecond `timestamp`, zoned `datetime`/`Datetime`, and l2tcsv's `date,time,timezone` fields. l2tcsv dates are month/day/year; ambiguous timezone abbreviations require an explicit IANA assumption. DST folds/gaps, invalid dates and semantic timestamps such as `NotSet` are rejected rather than assigned a fabricated timeline position. With quarantine enabled the original export and reject receipt remain available. Numeric time units are never inferred from magnitude.

The old `plaso` 2.0.0 contract and its event identities remain unchanged. New `plaso_event` starts at 1.0.0. The new importer retains parser chain, data type, timestamp description, artifact path and full microsecond integer provenance. Native nested path specifications, arbitrary source fields and serialized dfdatetime values stay in archived JSONL. `.plaso` stores can contain additional data absent from JSON exports, so native ingestion also archives the storage file.

## Evidence, completeness and limits

Native ingestion takes a private content snapshot, records file SHA-256, original size/mode/mtime/ctime and paths, then archives originals by content hash. It retains the storage, complete JSONL export, pinned catalog, actual backend census, executed argument arrays, private stdout/stderr, source inventory and extraction receipt inside the verified bundle. The work directory is retained for investigation; failures write `failure.json` and do not publish a bundle. Use new work/output directories on retry.

**Host file metadata from the staged copy is not original acquisition metadata.** Copying preserves atime/mtime but cannot preserve ctime/birth time or all filesystem context. `metadata.plaso.host_filestat` flags OS-backed filestat records; the receipt identifies this basis. The separate source inventory records original host stat observations. For evidentiary filesystem timestamps, process a properly acquired disk image: internal image metadata is not rewritten by staging. Collect inactive files or a consistent snapshot; a before/after stat check does not make copying a live database atomic.

Upstream extraction, preprocessing, recovery, timelining and analysis warnings, aborted sessions or incomplete session markers block publication by default. Review work logs before retrying with `--allow-partial`; this option also quarantines records that cannot be normalized. Receipts retain warning counters, and the result reports partial status. `psort --include-all` disables export deduplication, and the exported record count must equal the native storage event count even in partial mode. The pipeline can coalesce identical normalized events while retaining every occurrence in receipts and raw evidence.

Successful processing proves neither full acquisition nor that every byte is recognized. An unknown format can yield only generic file metadata, and a parser may not detect every unsupported variant. Inspect data types, parser chains, warnings and expected-source coverage; `source_completeness_proven` remains false. Generic artifact records are retained with OCSF class 0. Only source-supported file activity mappings claim class 1001; strict OCSF export continues to reject missing required fields. Native parser coverage does not imply a complete OCSF schema mapping for every Plaso event family.

| Budget | Default / behavior |
| --- | --- |
| Acquired bytes / files | 10 GiB / 10,000 regular files; links and special files rejected |
| Directory entries | Twice the file budget; includes directories |
| Backend work bytes | 20 GiB, checked while running; this is a monitored limit, not a filesystem quota |
| Phase timeout / memory | 3,600 seconds / 4,096 MiB; 2 CPUs and 256 PIDs |
| Container temporary space | 256 MiB |
| Each stdout/stderr | 8 MiB |
| Pipeline records / events | 1,000,000 / 2,000,000 |
| Total ingested bytes | 10 GiB including JSONL and archived attachments |

Expose changes through `timeline plaso-ingest --help`; plan disk capacity for source snapshot, native storage, JSONL, work files and final archived copies. A phase that exceeds its budget is stopped, and the work remains incomplete. Use filesystem quotas for a hard disk limit. Never treat a limit failure as a complete case. No source or model credentials are passed to the container.

## Tines, Databricks, notebooks and AI

Run native extraction on a dedicated acquisition host. Upload the resulting verified bundle through the existing Databricks Volume integration, then use the existing publish/monitor and inspection Tines stories. Tines does not need raw disk images in webhook payloads; pass bundle paths, hashes and idempotency keys using the existing contracts. Delta ingestion retains event provenance and the archived artifacts. Review storage quotas for the larger native evidence attachments. See [Databricks](../integrations/databricks/README.md) and [Tines operational implications](../integrations/tines/README.md).

The [Plaso Jupyter notebook](../notebooks/10_plaso_coverage.ipynb) explores the catalog and a synthetic export offline, with an explicit optional native run. Existing AI summarization/correlation/review routes apply after verified ingestion. There is no per-artifact model invocation, parser selection prompt or automatic model escalation; see [task/model budgets](AI_HARNESS.md).

## Validation and updating upstream

Local regression tests cover all 249 registered parser identities and 285 data types declared in parser source through the export contract. These synthetic tests establish importer behavior, not native binary compatibility. CI additionally runs the pinned upstream parser test suite with required fixture presence, then processes representative real upstream EVTX, registry, shortcut, prefetch, browser SQLite/plist, systemd, compressed syslog and ESXi fixtures plus a disk image. It checks the runtime census, event family presence, counts, bundle integrity and read-only `.plaso` re-import. CI retains summary reports, including upstream skip reasons, instead of republishing realistic fixture evidence.

The `plaso` CI job is a required gate in the supplied main-branch ruleset and a dependency of main-build provenance attestation. Tenant acceptance still needs organization-specific artifacts and expected event/clock checks. The complete inventory means all pinned registrations are available; it does not claim every historic format variant has a passing end-to-end fixture.

To review a new upstream revision, update the source commit/archive checksum and approved dependency image digest, regenerate the catalog/table and inspect additions/removals. In a checkout of the currently pinned source, verify reproducibility with:

```bash
python scripts/build_plaso_catalog.py /path/to/plaso-checkout --check
```

Run the upstream suite and native integration job before accepting a new pin. Do not bypass a mismatch by editing a saved evidence receipt or mutating an existing bundle. Primary references: [parser/plugin guide](https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html), [log2timeline usage](https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html), [psort usage](https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html). The published supported-formats page is historical; registered source code and the runtime census are the coverage authority for this release.
