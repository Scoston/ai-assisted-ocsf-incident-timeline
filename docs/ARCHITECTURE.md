# Evidence and integration architecture

The same Python pipeline serves the CLI, Jupyter and Databricks source-normalization notebook. It reads exported data; it does not acquire live vendor data automatically.

## Processing order

1. Copy each source into a private working directory, then hash and parse that snapshot. The source is never rewritten.
2. Decode the declared source format and normalize its records. Preserve the original timestamp, UTC conversion, offset, parser/mapping version, record index and source-file SHA-256.
3. Compute a deterministic record hash from sorted compact UTF-8 JSON. This is versioned project encoding, **not RFC 8785 canonicalization and not the hash of the original record bytes**.
4. Derive event identity from parser version, record hash and child index. Identical records deduplicate, while all ingestion occurrences retain receipts. A vendor event ID reused with changed content produces a different event identity.
5. Sort on disk by UTC milliseconds and identity. Write JSONL, CSV, optional Parquet, extracted indicators and quarantine receipts. IOC extraction is a deterministic string search, not a maliciousness verdict.
6. Hash all artifacts and compute a bundle identity over the manifest body. Publish the local bundle only when complete. Existing output directories are rejected.

`verify_bundle` checks artifact membership, byte sizes, hashes, safe relative paths and manifest identity. Keep an independently recorded manifest SHA-256 to detect replacement of both a bundle and its manifest. A self-contained unsigned manifest cannot prevent an attacker from replacing both.

## Storage contracts

| Artifact | Purpose |
| --- | --- |
| `evidence/<file-hash>.<original-extension>` | Snapshot of original source bytes, including original compression |
| `timeline.jsonl` | Authoritative normalized project profile, with exact normalized strings |
| `timeline.csv` | Flat display/export fields; formula-like strings prefixed with an apostrophe |
| `timeline.parquet` | Optional typed analytical columns plus complete `record_json`; not an upstream OCSF Parquet export |
| `receipts.jsonl` | Every emitted event occurrence and its source/record/child reference, including duplicates |
| `quarantine.jsonl` | Record-level errors and archived source references |
| `extracted_iocs.json` | Deduplicated indicator candidates; extraction does not assert maliciousness |
| `audit_manifest.json` | Counts, versions, input provenance, trust boundaries and file hashes |
| External AI ledger / analysis JSON | Minimized request, model response, usage, citations and review-required interpretation |

## Databricks publication

Raw bundle files remain in a Unity Catalog Volume. Delta tables hold evidence references, normalized event JSON, receipts, quarantine entries and separate analysis. Inserts match `(case_id, bundle_id, event_uuid)` for events. Publication is repeat-safe for the same bundle; distinct bundles remain distinct. Do not count multiple bundle versions as one deduplicated case without explicitly selecting the relevant bundle.

A publication marker is inserted after the evidence tables. The `published_timeline` view joins events to that marker, excluding partial publication. Operators should give analysts access to the published view and restrict staging-table access. Delta table properties and application insert-only behavior are **not WORM storage**; privileged identities and storage administrators need independent controls. Configure retention, legal holds and object-store protections for the actual environment.

## AI boundary

The harness verifies bundle integrity before reading. It sends bounded groups and representative examples, not full source files. Actor/asset/IP values become case-specific pseudonyms, and selected activity text is truncated with basic secret-pattern redaction. This is data minimization, not guaranteed de-identification. The saved transcript and analysis remain sensitive.

No tools, web browsing or containment functions are exposed to the model. Its schema and citation references are validated, but a valid reference can still support a mistaken interpretation. Human review remains mandatory. The evidence directory is kept separate from the analysis ledger and output files.

## Limits and failure behavior

JSON/Windows XML documents: 32 MiB; line-oriented records: 4 MiB. Whole-document parsing errors fail the batch, even with `--quarantine`. Use JSONL for large exports. CSV field limits and column counts are checked. DTD/entity declarations, duplicate JSON keys and non-finite JSON numbers are rejected.

Ordering uses source timestamps; it does not resolve clock skew or establish causation. Millisecond order does not distinguish sub-millisecond events; original timestamps remain available. Collection completeness, schema conformance, source authenticity and cryptographic signing are separate concerns.
