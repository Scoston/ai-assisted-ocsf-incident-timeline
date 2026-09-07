# Jupyter notebooks

Install with `python -m pip install -e '.[notebooks,ai,databricks]'`, then run `jupyter lab notebooks/` from the repository root.

| Notebook | What it does | Default network behavior |
| --- | --- | --- |
| `01_offline_investigation.ipynb` | Ingest the five-event sample, verify hashes, inspect source provenance/IOCs, demonstrate tamper detection | None |
| `02_databricks_integration.ipynb` | Prepare a bundle and Tines contract; optional upload, submit, status and download round trip | None until `LIVE=True` |
| `03_ai_harness.ipynb` | Inspect model routing, coverage and token bounds; optional analysis and cache demonstration | None until `ALLOW_AI=True` |
| `05_evaluation.ipynb` | Inspect measured coverage and score a deliberately imperfect handwritten analysis | None |
| `04_ocsf_export.ipynb` | Export pinned OCSF, inspect schemas, verify source binding and exercise rejection receipts | None |

Notebooks use temporary synthetic case directories and clean them up. Change the paths for retained investigations. A real AI ledger must persist outside temporary directories and outside the evidence bundle. The optional live examples may incur provider and compute charges.

The Databricks source notebooks in `integrations/databricks/` use workspace `spark` and `dbutils` objects. They are deployed/imported into Databricks, while these five `.ipynb` files also work in local Jupyter. The optional OCSF job task and its strict/quarantine behavior are covered in the [OCSF guide](../docs/OCSF_EXPORT.md).

Regenerate clean notebook sources with `python scripts/build_notebooks.py`. Verify offline cells with `python scripts/check_notebooks.py`, or use `--kernel` to execute them through Jupyter. Saved notebooks contain no execution output, credentials or real evidence.
