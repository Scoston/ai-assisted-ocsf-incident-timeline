# Deployment baseline

## Reproducible Linux/Python 3.12 installation

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/build-py312.txt
.venv/bin/python -m build --no-isolation
.venv/bin/python -m pip install --require-hashes -r requirements/runtime-py312-linux.txt
.venv/bin/python -m pip install --no-deps dist/*.whl
```

Start from a clean `dist/` directory so only this release's wheel is selected. The runtime lock includes collection, signing, AI, Databricks, UI/auth and Parquet dependencies. It targets Linux/Python 3.12; it is not a universal platform lock. The reusable package retains broader Python 3.10+ dependency ranges. Notebooks/development tools use their declared extras and are outside the deployed runtime lock.

Regenerate locks using Python 3.12 and `pip-tools==7.6.1`:

```bash
pip-compile --extra collection --extra signing --extra ai --extra databricks --extra ui --extra parquet --generate-hashes --strip-extras --no-emit-index-url --no-emit-trusted-host --output-file requirements/runtime-py312-linux.txt pyproject.toml
pip-compile --allow-unsafe --generate-hashes --no-emit-index-url --no-emit-trusted-host --output-file requirements/build-py312.txt requirements/build.in
```

Review dependency changes and licenses; run CI before accepting updates. Dependabot proposes updates, but operators still regenerate and review the deployment locks. CI audits both locks with `pip-audit`, produces CycloneDX inventories, runs CodeQL, builds the wheel and exercises it inside an unprivileged offline container. No audit suppressions are included. A clean advisory scan is a point-in-time result, not proof of vulnerability absence; scan the final container/host with your organization's OS vulnerability tooling too.

Every Action is pinned to a full commit, following [GitHub's secure use guidance](https://docs.github.com/en/actions/reference/security/secure-use). Main builds attest the exact wheel, source archive, dependency inventories and checksums after all required jobs pass. Retrieve `timeline-distribution` from the corresponding Actions run, verify checksums and use `gh attestation verify FILE --repo Scoston/ai-assisted-ocsf-incident-timeline` to verify build provenance. PR artifacts are untrusted review outputs and are not main-release attestations. Attestations identify the build; they do not certify the software or replace evidence signatures.

## Container

Build the wheel first, then `docker build -t incident-timeline:0.11.0 .`. The base image is pinned by digest, the image runs as UID/GID 10001, and only the wheel, runtime lock and viewer source enter the image. It contains no credentials or evidence.

```bash
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --memory 2g --cpus 2 --pids-limit 128 --tmpfs /tmp:size=512m --network none -v /srv/timeline:/data incident-timeline:0.11.0 ingest --input cloudtrail=/data/import/cloudtrail.json --case-id case-001 --output /data/bundles/case-001
```

Pre-create writable host directories for UID/GID 10001 with private permissions. Collection requires egress to its documented provider endpoints; permit only the required endpoints through platform controls. Supply short-lived credentials using the approved secret mechanism. Preserve state and output volumes between container runs. Do not put SQLite state on DBFS, Unity Catalog Volumes or unverified shared filesystems. A timer/orchestrator must retain each batch's fixed boundaries until it completes; use the existing `collect-until` command for bounded catch-up.

## Shared viewer

Local mode requires `server.address` to be a loopback address; the repository's `.streamlit/config.toml` configures this. Shared deployments must set:

```text
TIMELINE_VIEWER_MODE=oidc
TIMELINE_VIEWER_POLICY=/policy/viewer.json
TIMELINE_VIEWER_POLICY_SHA256=<independently pinned policy digest>
```

Populate `deploy/viewer-policy.example.json` with exact case IDs, bundle paths/pins, signature paths and pinned signer trust. Assign immutable **issuer + subject** pairs to explicit cases. There are no wildcard grants or user-controlled filesystem paths in shared mode. Do not substitute an email domain or forwarded authentication header.

Configure the OIDC app and a strong cookie secret outside git, using `deploy/secrets.example.toml` as a template. Mount it as `.streamlit/secrets.toml` in the viewer's working directory. Use `streamlit[auth]`, included in the runtime lock, and an approved HTTPS reverse proxy with WebSocket support. Bind the container's port only to the proxy/private network. For the image, override the entrypoint to `streamlit` and run `/opt/timeline/viewer.py --server.address=0.0.0.0 --server.headless=true`. Mount evidence/signatures/trust/policy read-only; do not mount signing private keys or collector/provider credentials. If AI review is enabled, mount only its dedicated protected ledger as writable and pin each case's `ai` configuration in the viewer policy.

[Streamlit OIDC authenticates identity](https://docs.streamlit.io/develop/concepts/connections/authentication); this project adds case authorization. [Identity expiry must be checked by the app](https://docs.streamlit.io/develop/api-reference/user/st.user), so expired/missing expiry claims are rejected on every interaction/rerun. Already delivered browser data cannot be revoked retroactively. Test your provider's `iss`, `sub` and `exp` claims. Policy edits require deployment of a new independently recorded digest. For emergency revocation, remove ingress/session access and restart the viewer with updated policy; do not assume instant identity-provider session revocation reaches an existing browser session.

The viewer logs allow/deny events with hashed subject identity and bundle ID, without claims, tokens or raw events. Forward logs to your protected logging system. Rate limits, TLS, session/egress policy and log retention belong to the deployment platform. Evidence remains read-only. The optional AI review panel writes only authenticated human decisions and audit events to its dedicated ledger; it requires a separate pinned case-scoped reviewer policy. `ai` settings contain absolute `ledger` and `review_policy` paths plus `review_policy_sha256`. Read [review identity and migration](AI_EVIDENCE_AND_REVIEW.md). Case administration remains separate.

## Databricks and Tines

Use the existing [Databricks guide](../integrations/databricks/README.md) and [Tines stories](../integrations/tines/README.md). Enable required signatures in the deployed fixed job policy, grant the submitting principal run-only access, and protect the trust-store digest outside job parameters.

`normalize_volume_sources` and the OCSF job stage SQLite locally and upload verified results through the SDK's Files API, manifest last. They need adequate driver-local space and the SDK dependency. Partial upload replay verifies existing bytes before continuing. Readers require complete manifests and hashes. [Volume random-write limitations](https://learn.microsoft.com/en-us/azure/databricks/volumes/volume-files) make direct SQLite staging on a Volume unsuitable. Direct `run_pipeline`/`export_bundle` Volume output is rejected with adapter guidance.

Configure live service principals, UC grants, immutable landing paths, secret management and tenant acceptance separately. Local POSIX fsync/permissions and CI Spark/Delta checks do not establish cloud storage durability or live API compatibility.
