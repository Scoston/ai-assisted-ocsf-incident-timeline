# Jupyter notebooks

Install with `python -m pip install -e '.[notebooks,ai,databricks,collection,signing]'`, then run `jupyter lab notebooks/` from the repository root.

| Notebook | What it does | Default network behavior |
| --- | --- | --- |
| `01_offline_investigation.ipynb` | Ingest the five-event sample, verify hashes, inspect source provenance/IOCs, demonstrate tamper detection | None |
| `02_databricks_integration.ipynb` | Prepare a bundle and Tines contract; optional upload, submit, status and download round trip | None until `LIVE=True` |
| `03_ai_harness.ipynb` | Inspect model routing, coverage and token bounds; optional analysis and cache demonstration | None until `ALLOW_AI=True` |
| `06_signed_manifests.ipynb` | Create temporary encrypted keys; sign, retire and revoke a signer with independent policy pins | None |
| `05_evaluation.ipynb` | Inspect measured coverage and score a deliberately imperfect handwritten analysis | None |
| `04_ocsf_export.ipynb` | Export pinned OCSF, inspect schemas, verify source binding and exercise rejection receipts | None |
| `07_enterprise_collection.ipynb` | Inspect collector configurations; simulate late M365 delivery, source receipts and completed replay | None |
| `08_operations_and_recovery.ipynb` | Back up an interrupted acquisition, restore by independent pin, resume committed pages and inspect health metrics | None |
| `09_developer_incidents.ipynb` | Normalize GitHub/Kubernetes audit evidence, validate OCSF, plan AI and fingerprint expected sources | None |
| `10_plaso_coverage.ipynb` | Inspect every native Plaso registration, ingest a synthetic export and optionally run the pinned backend | None; native execution requires `RUN_NATIVE=True` and local Docker |

Notebooks use temporary synthetic case directories and clean them up. Change the paths for retained investigations. A real AI ledger must persist outside temporary directories and outside the evidence bundle. The optional live examples may incur provider and compute charges.

The Databricks source notebooks in `integrations/databricks/` use workspace `spark` and `dbutils` objects. Import them into Databricks for interactive analyst use; the deployed job uses positional wheel tasks to protect its configured policy from job parameter pushdown. These ten `.ipynb` files also work in local Jupyter. The optional OCSF job task and its strict/quarantine behavior are covered in the [OCSF guide](../docs/OCSF_EXPORT.md).

Regenerate clean notebook sources with `python scripts/build_notebooks.py`. Verify offline cells with `python scripts/check_notebooks.py`, or use `--kernel` to execute them through Jupyter. Saved notebooks contain no execution output, credentials or real evidence.
