# Operations and recovery

## Storage and isolation

Use a dedicated non-root service identity, encrypted durable local storage, owner-only state/bundle directories and disk quotas. New local POSIX bundles have directory mode 0700 and file mode 0600. Ledger files are created as 0600 before SQLite opens them. Windows deployments must set equivalent ACLs. Only trusted operators may modify parent directories; hashes do not prevent a concurrent privileged writer from changing files. Cloud access is governed by Unity Catalog/IAM, not local chmod.

Keep collector state and published evidence separate. State contains sensitive raw pages, identifiers and continuation tokens; it is not a disposable cache. Give viewers read-only access to their mounted evidence and policy. Collectors should have source read scopes and no signer key. Publishers should have only required Volume, job and table grants. Signing keys and trust-policy administration belong to the custodian role.

## Health and monitoring

```bash
timeline-ops health --state /srv/timeline/state/entra --stale-seconds 7200
timeline-ops health --state /srv/timeline/state/entra --format prometheus
timeline-ops health --state /srv/timeline/state/entra --verify-blobs --verify-bundles
```

Exit codes: **0** healthy, **1** stale/incomplete acquisition requiring attention, **2** invalid/unavailable/corrupt state. An unfinished recent run can be healthy while it continues; stale unfinished runs raise an issue. Health does not create state or issue provider requests. Error output is a fixed diagnostic code, without paths, case names, tokens or raw evidence.

Prometheus output includes acquisition age for each hashed source identity, pending/published counts and watermark lag. Scrape through your existing agent/textfile collector; replace its textfile atomically and alert on probe errors as well as `timeline_collection_healthy == 0`. Alert separately on absent metrics, a stopped scheduler and disk pressure. Supply an expected-source inventory to detect sources that never ran (below). Use a state directory per source to simplify source-specific ownership and thresholds.

Choose staleness thresholds longer than your schedule plus provider delivery delay. Historical backfills intentionally have lagging watermarks. Deep checks hash all committed blobs and optionally all published bundles; schedule them according to evidence volume. Default health checks validate references and structure without rereading every byte. Status metrics are gauges, not monotonic counters across restores.

## Consistent backup

```bash
timeline-ops backup --state /srv/timeline/state/entra --output /srv/backup/entra-20260907
```

The command uses SQLite's [online backup API](https://www.sqlite.org/backup.html) and holds a reserved write lock while copying committed page blobs. Other collectors may receive a busy error and must retry the same window. A completed snapshot is flushed before publication; pre-existing destinations are rejected. Uncommitted orphan blobs and generated `.jsonl` hardlink aliases are omitted; aliases are recreated on resume.

Record the returned `snapshot_sha256` independently, in an access-controlled case/backup inventory. The snapshot includes its database and committed page blobs. **It does not contain published bundles, detached signatures, signing keys, trust policies or AI ledgers.** The result and `snapshot.json` list every published bundle path and manifest pin. Back up those artifacts separately to approved encrypted/immutable storage. Use the dedicated AI-ledger commands below; never discard uncertain charges or pending requests during restoration.

Snapshots are immutable recovery records, not encrypted archives or signed proofs of authenticity. Independently stored hashes detect accidental alteration or replacement against that pin. Restrict access and use approved backup encryption/signing where required.

## Restore drill

1. Stop and fence the original collector. Restore the independently inventoried published bundles to the **same absolute paths**, preserving their manifest bytes. Restore signer sidecars/trust and any AI ledger separately.
2. Restore into a new state directory using the independently recorded snapshot pin:

   ```bash
   timeline-ops restore --snapshot /srv/backup/entra-20260907 --snapshot-sha256 RECORDED_SHA256 --state /srv/timeline/state/entra-restored
   ```

3. The tool rejects missing/extra/altered files, unsafe members, corrupt checkpoint relationships and missing or changed published evidence. It never overwrites an existing state directory. A stale health result can be expected after an outage; integrity failures block restore.
4. Point the single collector at the restored state. Resume the original source configuration, case ID, output path and exact time window. Confirm committed pages were not refetched, published replay makes no API calls, and watermarks advance only after publication.
5. Run deep health checks, compare provider counts/time coverage, then resume scheduling. Record elapsed recovery time, last committed page, any lost interval and approval to retire the old writer.

Do not rebase bundle paths or reset watermarks in SQLite by hand. A restore to another host needs the same mounted bundle paths. Restoring both state and an old AI ledger while the originals remain active can duplicate collection or spend beyond case budgets.

## Upgrades, limits and retention

Stop old collector processes before upgrading; read [the version-specific migration procedure](../UPGRADING.md). Finish active 0.10 collection windows before upgrading from that release. New run checkpoints record parser versions. An incomplete checkpoint with an unknown or different parser version stops before another API call; use the original release to finish it or retain it and start a deliberately separate acquisition. Completed old bundles remain verifiable and replayable.

Default ingestion ceilings are 10 GiB aggregate raw input/attachment bytes, 1,000 inputs, 1,000,000 expanded source records, 2,000,000 emitted events and 100,000 distinct IOC candidates. Override explicitly with `timeline ingest --max-input-bytes`, `--max-inputs`, `--max-records`, `--max-events` and `--max-iocs`. A breach fails the entire run even with quarantine enabled. Compressed input bytes and expanded record counts are distinct budgets; source readers also enforce document/line limits. Apply process memory/CPU/runtime and filesystem quotas for limits beyond these counters.

Retain original evidence, snapshots, manifests, signatures, acquisition receipts and analyst decisions under the case's approved policy. Apply legal holds before any deletion. Keep AI transcripts, access logs, checkpoints and backups in the data inventory because they can contain or reveal sensitive evidence. This release performs no automated deletion, credential rotation, containment or retention changes.

Investigate token exhaustion through the durable AI ledger: completed cache hits spend zero new tokens; failed/unknown provider attempts keep their reservation. Reconcile with provider receipts through your approved process rather than deleting ledger rows or automatically retrying.

## Expected-source inventory

```bash
umask 077
timeline-ops inventory --config /etc/timeline/collectors/github.json --config /etc/timeline/collectors/kubernetes.json > expected-sources.json
timeline-ops health --state /srv/timeline/state/shared --inventory expected-sources.json --stale-seconds 7200
```

Use only the configurations that belong to the probed state directory. The inventory stores SHA-256 fingerprints of exact source configurations plus collector contract version; generation requires no credentials, SDK client setup or network request. It does not validate provider access or replace configuration/tenant acceptance. Defaults spelled out differently, changes to token environment names and other configuration changes intentionally yield a different identity; regenerate the approved inventory when the configuration changes. Provider identity reports use the same canonical JSON convention.

`missing_source:<hash>` and `timeline_collection_missing_sources` expose absent sources, and their age is reported as -1 in Prometheus. A source that exists but has never committed a page is stale. The inventory must be nonempty, unique and bounded; malformed inventories return exit 2. No state yet is also an operational error, not a healthy empty deployment. Protect the inventory against unauthorized removal of expected sources.

## Scheduled acquisition

[Service](../deploy/timeline-collect@.service), [timer](../deploy/timeline-collect@.timer) and [environment](../deploy/collector.example.env) templates provide a starting point for an existing Linux/systemd collector host. They are not installed automatically. For each source instance:

1. Create a dedicated `timeline` system user/group, install the approved wheel and dependencies under `/opt/timeline/venv`, and create owner-only `/srv/timeline/state/NAME` and `/srv/timeline/bundles/NAME` directories.
2. Install the reviewed configuration as `/etc/timeline/collectors/NAME.json`. Install a root-only `NAME.env` with stable `INITIAL_START` and `CASE_PREFIX`; supply expiring source credentials through approved delivery. SDK authentication needs environment/role configuration compatible with `ProtectHome=true`.
3. Customize cadence, resource limits, settling delay, window size and overlap for the source. The example uses a five-minute timer, five-minute settling delay, five-minute windows and one-minute overlap. A long outage or high-volume source may need more windows/pages or a separate backfill.
4. Check the units with `systemd-analyze verify`, run one manually supervised invocation and verify health/source counts. Install the units, reload systemd and enable `timeline-collect@NAME.timer` only after acceptance. The same active oneshot service does not run concurrently with itself; continue to fence other hosts using that state.
5. Route failed units and missing/stale inventory metrics to existing operations alerting. A 15-minute timeout can leave a durable pending window; the next invocation resumes it. A page-budget stop is an explicit error; a window-count stop returns `paused` and the next timer continues.

Retain the state after restarts and deployments. `--end now` captures the clock once and subtracts `--settling-seconds` (default 300, range 0–86400). Explicit end times are not adjusted. A pending window's end remains frozen across invocations; a smaller requested end is rejected. Settling and overlap mitigate only bounded delivery delays; delayed/expired source records need reconciliation and backfill.

## AI usage and recovery

```bash
timeline-ops ledger-usage --ledger /srv/timeline/analysis/usage.sqlite
timeline-ops ledger-backup --ledger /srv/timeline/analysis/usage.sqlite --output /srv/backup/ai-20260907
timeline-ops ledger-restore --snapshot /srv/backup/ai-20260907 --snapshot-sha256 RECORDED_SHA256 --output /srv/timeline/analysis/restored
```

Usage reports contain hashed case IDs, call counts by status, total charged tokens, provider-confirmed usage and reservations whose usage is unknown. They expose no prompt, response, case name or credential. Hashes are stable labels, not encryption. Reporting makes no AI request and never refunds, retries or changes a row. Invalid/missing ledgers return the sanitized operational error with exit 2. Completed response bodies and request/receipt relationships are checked before a snapshot is accepted.

Backup uses a consistent SQLite read transaction and its online backup API, including committed WAL data. The snapshot holds `usage.sqlite`, its hash/length and a hashed-case accounting summary. Record its manifest pin independently and encrypt/restrict the snapshot: its database contains minimized requests and provider transcripts. The snapshot format is bounded and published privately only when complete.

Stop and fence every original harness writer before recovery. Restore the most recent approved snapshot into a new directory, compare its accounting with provider receipts and your independently retained dispatch records, and point the single authorized harness at the returned ledger path. A stale snapshot cannot prove there were no later dispatches; reconcile these before enabling calls. Keep old snapshots and ledgers as evidence. The restore rejects incorrect pins, extra files, links, changed database bytes and inconsistent accounting; it never overwrites an existing directory.

Failed and pending rows keep their full unknown reservation or recorded actual charge. Completed rows retain cache results, so identical work uses zero new model tokens after recovery. A recovered pending/failed request remains blocked from automatic retry. This snapshot is separate from collector state and does not contain evidence bundles, policies, signing material or provider billing records. Its hash is an integrity pin, not independent proof that a ledger is authentic or current.
