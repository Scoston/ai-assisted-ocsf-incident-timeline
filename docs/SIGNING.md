# Signed manifests and signer trust

Version 0.9.0 adds detached Ed25519 attestations for evidence bundles and OCSF exports. Signatures bind the exact manifest bytes, artifact kind, identity and key fingerprint. Verification checks every covered artifact and a separately pinned signer policy. This is an application signature format, not a certificate authority, trusted timestamp service or source-system attestation.

The implementation uses the maintained library's [Ed25519 signing and verification](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/) and [encrypted PKCS8 serialization](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/). It does not implement elliptic-curve arithmetic or encryption itself.

## Create a key and establish trust

```bash
python -m pip install -e '.[signing]'
# Set TIMELINE_SIGNING_PASSPHRASE through your secret tooling; do not put it in a command argument.
timeline-sign keygen --output keys/signer-2026-09 --passphrase-env TIMELINE_SIGNING_PASSPHRASE
timeline-sign trust-init --public-key keys/signer-2026-09/public.pem --output trust-v1.json
```

Key generation uses the OS-backed cryptographic generator. `private.pem` is encrypted PKCS8; files are created with owner-only permissions on POSIX and never overwrite existing paths. The passphrase must be 16..1023 UTF-8 bytes; length alone does not establish entropy. Provision it through your approved secret manager. On Windows, configure directory ACLs explicitly. New keys are local files, not HSM/KMS keys. Do not copy private keys into Tines, Databricks Volumes or this repository.

Trust initialization prints the public-key fingerprint and the exact `trust_store_sha256`. Validate the public key and record the trust-store hash through an independently controlled channel. Giving an attacker control of both the policy and its configured hash defeats the trust anchor. A fingerprint is a key identifier; associate it with an authorized signer through your organization's identity and audit process.

The trust store is limited to 100 keys. Each entry contains the public key, status and permitted kinds (`bundle`, `ocsf-export`). Use repeated `--allow-kind` arguments to restrict a new key. Unknown keys, altered policies, duplicate JSON keys, unsupported algorithms, malformed signatures and revoked keys fail verification. A public key carried alongside an untrusted bundle is never automatically trusted.

## Sign and verify an evidence bundle

Replace `TRUST_SHA256` below with the independently recorded hash. Keep signatures and trust files outside the evidence directory; adding a detached signature inside it would change manifest membership.

```bash
timeline-sign sign output/case-001 --private-key keys/signer-2026-09/private.pem --passphrase-env TIMELINE_SIGNING_PASSPHRASE --trust-store trust-v1.json --trust-store-sha256 TRUST_SHA256 --output attestations/case-001.sig.json
timeline verify output/case-001 --require-signature --signature attestations/case-001.sig.json --trust-store trust-v1.json --trust-store-sha256 TRUST_SHA256
```

`timeline verify` without signature options retains ordinary artifact-integrity behavior. Once any signature option is supplied, all three signature/trust/pin values are required. `--require-signature` makes omission fail explicitly. Automation must configure that requirement at a trusted entry point. A successful attestation returns `trusted_signature_verified`, key ID/status, signature and policy hashes, and manifest identity. No signing time is asserted.

The signing command first verifies the full artifact, decrypts an authorized active key and writes a new detached signature. Identical manifests and keys produce deterministic attestations. Signing material, policies and sidecars use exclusive local file creation and fsync; use a filesystem supporting hard links. A crash during key generation may leave an incomplete new key directory; preserve it for diagnosis and generate into a new path. Signing directly on a Unity Catalog Volume is not supported; generate locally and upload the public sidecar through the adapter.

## Sign an OCSF export

```bash
timeline-sign sign output/case-001-ocsf --kind ocsf-export --source-bundle output/case-001 --private-key keys/signer-2026-09/private.pem --passphrase-env TIMELINE_SIGNING_PASSPHRASE --trust-store trust-v1.json --trust-store-sha256 TRUST_SHA256 --output attestations/case-001-ocsf.sig.json
timeline verify-ocsf output/case-001-ocsf --bundle output/case-001 --require-signature --signature attestations/case-001-ocsf.sig.json --trust-store trust-v1.json --trust-store-sha256 TRUST_SHA256
```

Source-bound export verification checks the source manifest and event references. Supplying the source does not independently authenticate its signer; verify a required source signature separately. The OCSF export's artifact identity is its manifest SHA-256. A bundle signature cannot be substituted for an export signature.

## Rotation and revocation

Every policy command writes a new file and returns a new pin. Promote both the reviewed policy version and its pin to consumers through your controlled deployment process; old policy pins do not learn about revocation automatically.

```bash
timeline-sign keygen --output keys/signer-next --passphrase-env TIMELINE_NEXT_SIGNING_PASSPHRASE
timeline-sign trust-add --trust-store trust-v1.json --trust-store-sha256 OLD_TRUST_SHA256 --public-key keys/signer-next/public.pem --output trust-v2.json
timeline-sign trust-status --trust-store trust-v2.json --trust-store-sha256 V2_TRUST_SHA256 --key-id OLD_KEY_ID --status verify_only --output trust-v3.json
# If the old private key is compromised:
timeline-sign trust-status --trust-store trust-v3.json --trust-store-sha256 V3_TRUST_SHA256 --key-id OLD_KEY_ID --status revoked --output trust-v4.json
```

| Status | Signing command | Verification |
| --- | --- | --- |
| `active` | Permitted for configured artifact kinds | Accepted |
| `verify_only` | Refused | Accepted; no signing-date guarantee |
| `revoked` | Refused | Rejected, including previously created signatures |

The status command refuses to reactivate a revoked key; generate a new key. Without an external trusted timestamp, possession of a retired private key can still produce mathematically valid signatures. `verify_only` is a local signing policy and historical-verification allowance, not proof that an attestation predates retirement. Use revocation for compromise. Independently retain policy versions, approvals, key fingerprints and verification receipts; never use a retired policy as a silent fallback to pass current verification.

## Databricks and Tines

Set these deployment variables in `databricks.yml` for a job that requires signed source bundles:

| Variable | Value |
| --- | --- |
| `require_signature` | `"true"` |
| `signature_root` | `/Volumes/<catalog>/<schema>/<volume>/signatures-v1` |
| `trust_store_path` | `/Volumes/<catalog>/<schema>/<policy_volume>/trust-v1.json` |
| `trust_store_sha256` | Independently recorded policy hash |

Place the public policy in a separate read-only location. Grant job identity read access; restrict policy/pin and job-definition changes to authorized maintainers. The cryptography runtime dependency is included in the deployed tasks. The four policy fields are deployment literals, not incoming job parameters, so the supplied Tines story only forwards the existing bundle path and manifest pin. Callers with job-management permissions remain inside this trust boundary.

```bash
timeline databricks-upload output/case-001 --volume-root /Volumes/main/ir/evidence/bundles --signature attestations/case-001.sig.json --signature-root /Volumes/main/ir/evidence/signatures-v1 --trust-store trust-v1.json --trust-store-sha256 TRUST_SHA256
```

The adapter verifies locally and uploads `<bundle_id>.sig.json` to the fixed signature root without overwriting. Conflicting sidecars fail; use a new signature root for key rotation. It then uploads bundle artifacts with the manifest last. Policy deployment is a separate operator-controlled action. Uploading a signature does not configure remote trust automatically.

The publication task verifies trust before Spark writes and rechecks source bytes/policy before its final marker. The OCSF task rechecks the source signature before export and before publication. It does not hold a private key or automatically sign the derived export. To publish a separately signed OCSF export, call `publish_ocsf_export(..., signature=path, trust_store=path, trust_store_sha256=pin, require_signature=True)` after signing/uploading that export; its signature is independently verified.

Published source paths must be immutable during processing: restrict writer permissions and apply your retention controls. Checks before and after Spark reads detect persistent changes; they are not an atomic filesystem snapshot against a writer that changes and restores files during the read.

Successful signed publication inserts a `signature_verifications` Delta receipt before the publication marker. Receipts include key, policy, sidecar and artifact hashes; replay is insert-only and preserves previous policy decisions. These are historical checks, not a live view of current trust. Revoking a key blocks new verification/publication under the updated policy; it does not erase previously published rows or retroactively change old receipts. Reverify against current policy when making a current trust decision, and manage access to historical data using your governance process.

A Tines success receipt means the configured job completed. Configure the required-signature job before treating success as a signed-source gate. Missing, invalid or revoked signatures fail the job; the monitor's existing failure/timeout paths require operator review. Tines contains no signer private key and does not accept a trust policy or signer key from a webhook. See [Tines operational implications](../integrations/tines/README.md).

## Wire format and assurance boundary

A sidecar contains exactly `signature_version`, `algorithm`, `kind`, `artifact_id`, `manifest_sha256`, `key_id` and `signature`. Version is `1.0`, algorithm is `Ed25519`, digests are lowercase SHA-256 hex, and signature is canonical base64 of 64 bytes. The key ID is SHA-256 of the raw 32-byte public key.

The signed message is the ASCII domain `timeline-manifest-signature-v1` followed by one NUL byte and the sorted, compact UTF-8 JSON of the six fields excluding `signature`. Those fields use only fixed ASCII strings and hex digests; this narrow encoding is not a general RFC 8785 JSON canonicalizer. Manifest hashes cover exact bytes, including formatting. Verifiers also check artifact membership, hashes and supported schema/profile rules. No certificate chain or algorithm negotiation is performed.

A valid signature proves possession of the configured private key for the signed manifest. It does not prove the underlying source was truthful, complete, correctly timed or legally admissible. A compromised signing host can attest false input. Independent signer identity, storage retention, trusted timestamps and organization-level audit review remain external controls.

## Validation

Offline tests cover encrypted key generation, deterministic signatures, no overwrite, manifest/file/policy tampering, algorithm/kind/key substitution, source-bound OCSF, key scopes, rotation, revocation, symlink/size boundaries, required-signature CLI behavior and upload replay/conflicts. CI adds real Spark/Delta signed publication, repeat receipt counts and revocation denial. No production key, Tines tenant or Databricks policy was provisioned in this implementation environment. The [sixth notebook](../notebooks/06_signed_manifests.ipynb) demonstrates the lifecycle using temporary synthetic keys only.
