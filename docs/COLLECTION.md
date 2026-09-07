# Checkpointed collection

Version 0.12.0 supplies 19 bounded collector types and 27 parser contracts. A parser does not imply a live collector. Collection, ingestion and verification use zero model tokens. Start with the [enterprise coverage assessment](COLLECTOR_COVERAGE.md).

## Source contracts

| Configuration | API and captured scope | Authentication and acceptance |
| --- | --- | --- |
| `examples/collectors/tines-audit.json` | Tines tenant audit operations; date filters, page links, total-count consistency | Tenant audit access; bearer token in `TINES_API_TOKEN`; verify pagination behavior in your tenant |
| `examples/collectors/entra-signins.json` | Microsoft Graph v1.0 sign-ins in the global cloud; time filter and opaque next links | `AuditLog.Read.All`, required role/license/retention; access token in `GRAPH_ACCESS_TOKEN` |
| `examples/collectors/cloudtrail.json` | CloudTrail LookupEvents management event history in one account/region, last 90 days | Standard boto3 profile/role chain; `cloudtrail:LookupEvents`; repeat separately for each region/account |
| `examples/collectors/databricks-audit.json` | Fixed parameterized query of `system.access.audit` through one SQL warehouse | Databricks SDK unified authentication; warehouse use and table/catalog/schema read grants |

Tines exposes `before`/`after` filters and paginated audit operations. The implementation requests a one-second boundary overlap and applies the exact window locally. It records `request_ip` with parser 2.1.0. The source may change during paging; changed reported totals fail the run. [Tines audit API](https://www.tines.com/stories/docs/api/audit-logs/list/).

Graph returns at most 1,000 sign-ins per page and only retained records. This collector does not cover sovereign clouds, directory audit, every workload identity event, or omitted Conditional Access fields. [Microsoft sign-in API](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0).

CloudTrail's event-history endpoint is region-scoped, limited to 90 days and two requests per second. This is not an S3 trail/data-event collector. SDK responses are serialized after decoding, so their attachments are not original HTTP wire bytes. [AWS LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html).

Databricks uses `INLINE` JSON results, typed time parameters, async status polling and ordered result chunks. Truncation, changed schema, missing rows or expired statements fail explicitly. SQL execution may incur warehouse charges. An ambiguous submission failure is not automatically retried; rerunning can create another read-only statement. [Statement Execution API](https://docs.databricks.com/api/statement-execution/v1/execute-statement).

## Install and collect a fixed window

The four original contracts above remain supported. The enterprise additions, configuration examples, permissions, table choices, source clocks and API limits are documented in [enterprise API contracts](ENTERPRISE_APIS.md).

```bash
python -m pip install -e '.[collection,databricks]'
# Copy a configuration above and replace its source/account identifiers.
# Obtain credentials using your approved identity/secret tooling.
timeline collect --config collector.json --state collector-state --output output/window-001 --case-id window-001 --start 2026-09-01T10:00:00Z --end 2026-09-01T11:00:00Z
timeline verify output/window-001
```

Choose dates inside your source's retention. `source_id` is an operator label, not a verified tenant identity. Changing the configured source/account requires a distinct label/state policy; check the authenticated principal before production use. Credentials are never configuration values or report fields. Source responses may themselves contain sensitive data; restrict the state and bundle locations accordingly.

The interval is start-inclusive and end-exclusive using the configured source selection clock. New providers report `window_basis`; native event timestamps remain independent. The end must be in the past and the interval at most 24 hours. Defaults are 100 pages per invocation, 100,000 received records and 128 MiB of accumulated raw plus projected page bytes per window. Every response is bounded to 16 MiB. Use `--max-pages`, `--max-records` and `--max-bytes` to configure limits. Oversized API responses or SQL truncation need a narrower new window.

For a page-budget stop or transient request failure, repeat the identical command. Committed pages are hash-checked, then the saved cursor resumes; a completed window verifies and returns its existing bundle without another provider request. Record/byte limits are cumulative across resumes; increase them deliberately or collect narrower windows under new case IDs. An expired cursor is not silently discarded. Preserve the failed state and start an explicitly overlapping replacement window; reconcile the two reports.

## Continuous scheduling and late arrivals

```bash
timeline collect-until --config collector.json --state collector-state --output output/continuous --case-id tenant-a --start 2026-09-01T00:00:00Z --end 2026-09-01T12:00:00Z --window-seconds 3600 --overlap-seconds 300 --max-windows 24
```

Use `--end now --settling-seconds 300` for a clock-relative end, sampled once per invocation. The delay applies only to `now`; explicit end timestamps are used unchanged. The pending window end is committed before any fetch, so a later invocation with an extended end resumes that exact window first. An end earlier than the pending boundary fails before network access. [Systemd templates and setup](OPERATIONS.md#scheduled-acquisition) are included.

Schedule this command with your existing scheduler on a persistent collector host. Keep `--start`, case prefix, source configuration, output root and window policy fixed; advance `--end` to a closed boundary behind current time by an operator-selected ingestion lag. Each successful window is published and verified before a compare-and-swap watermark advances. `paused` means the invocation reached its window count; repeat it to catch up. Concurrent invocations sharing state serialize page requests and reject conflicting watermark changes.

Overlap reduces exposure to short delays but cannot prove complete collection. Records arriving after the overlap, source-side retention loss, mutable offset pagination and service filtering can still leave gaps. Reconcile source counts, monitor watermark lag and run wider backfills when needed. Repeated records remain attributable across bundles; consumers can deduplicate on `event_uuid` while retaining occurrence receipts. No scheduler is started automatically.

## Durability, receipts and recovery

Use a durable local filesystem supporting SQLite locks, hard links and atomic directory operations. Do not place the state database on a Unity Catalog Volume, DBFS or an unverified network filesystem. Use `timeline-ops backup` for a consistent snapshot of the database and its committed blobs; see [recovery](OPERATIONS.md). Keep state and output directories disjoint.

Each received page is saved and fsynced in a content-addressed store before its cursor is committed with SQLite `synchronous=FULL`. The final bundle archives projected input records plus raw decoded HTTP response bodies under `attachments/collection-pages/`; `attachments/collection.json` records response/projection hashes, fetch times, boundaries and excluded counts. Ordinary manifest verification covers every attachment. These receipts demonstrate captured bytes and drained pagination, not source authenticity or completeness.

An interruption can leave unreferenced blobs or an accepted read-only SQL submission whose ID was not yet saved. Orphan blobs are retained, never silently promoted or deleted. Disk retention and reconciliation are operator responsibilities. Missing/tampered committed blobs or published bundles fail verification; restore from a consistent trusted backup before advancing. Page failures leave the preceding cursor/watermark intact. GET requests have bounded transient retries; redirects are rejected, and Retry-After values over 30 seconds defer work to the next invocation. AWS SDK retries are disabled; retry a failed invocation later.

After collection, use the existing Databricks upload and Tines reference workflow. Collector credentials and state are not passed through a Tines story. Configure success/timeout alerts on the scheduler and review `source_completeness_proven: false` plus excluded counts before treating a window as ready for investigation. See [Tines operations](../integrations/tines/README.md) and [Databricks publication](../integrations/databricks/README.md).

## Acceptance record

Offline regressions cover the 19 source contracts, interrupted paging, replay, cursor cycles, window boundaries, hash alteration, budgets, throttling and SQL truncation. Before scheduling production collection, record the authenticated account/region/tenant, permissions and retention; compare a representative fixed window against the source UI/export, then exercise denial, interruption, expired cursors and late arrivals. No live collector credentials were available for this implementation.
