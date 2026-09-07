"""Generate clean, executable Jupyter examples without credentials or stored outputs."""

from pathlib import Path
import nbformat as nb

ROOT = Path(__file__).resolve().parents[1]

SETUP = """from pathlib import Path
import tempfile
import json
root = Path.cwd()
if not (root / 'examples').exists():
    root = root.parent
assert (root / 'examples/parser_samples.json').exists(), 'Run from the repository or notebooks directory'
from timeline_demo.pipeline import Input, run_pipeline, read_timeline
from timeline_demo.core.manifest import verify_bundle
work = tempfile.TemporaryDirectory()
workdir = Path(work.name)
bundle = workdir / 'bundle'
manifest = run_pipeline([
    Input('cloudtrail', root / 'examples/raw/aws/cloudtrail_real_sample.json'),
    Input('entra_signin', root / 'examples/raw/entra/entra_signin_real_sample.jsonl'),
    Input('crowdstrike_detection', root / 'examples/raw/edr/crowdstrike_detection_real_sample.json'),
], bundle, 'notebook-demo')
"""


def write(name, cells):
    notebook = nb.v4.new_notebook(
        cells=[
            nb.v4.new_markdown_cell(text) if kind == "md" else nb.v4.new_code_cell(text)
            for kind, text in cells
        ]
    )
    notebook.metadata.kernelspec = {"display_name": "Python 3", "language": "python", "name": "python3"}
    notebook.metadata.language_info = {"name": "python", "version": "3.12"}
    nb.write(notebook, ROOT / "notebooks" / name)


def main():
    build_ocsf_notebook()
    build_evaluation_notebook()
    write(
        "01_offline_investigation.ipynb",
        [
            (
                "md",
                "# Offline investigation\nBuild, verify, inspect and export a five-event synthetic case. No API key or network call is used. Install the project with the notebooks extra first.",
            ),
            ("code", SETUP),
            (
                "code",
                "checked = verify_bundle(bundle)\nassert checked['counts']['event_count'] == 5\nchecked['counts']",
            ),
            (
                "code",
                "events = list(read_timeline(bundle))\n[(e['time_utc'], e['source_name'], e['activity_name']) for e in events]",
            ),
            (
                "md",
                "## Inspect a source reference\nThe record hash covers deterministic JSON encoding. The file hash covers the archived original bytes. Neither hash proves that a source told the truth.",
            ),
            ("code", "event = events[0]\n{'event':event, 'raw_source':str(bundle / event['evidence_path'])}"),
            ("code", "json.loads((bundle/'extracted_iocs.json').read_text())"),
            ("md", "## Demonstrate tamper detection on a disposable copy"),
            (
                "code",
                "import shutil\naltered = workdir/'altered'\nshutil.copytree(bundle, altered)\n(altered/'timeline.jsonl').write_text('{}\\n')\ntry:\n    verify_bundle(altered)\n    raise AssertionError('tampering was not detected')\nexcept ValueError as error:\n    print(type(error).__name__, str(error))",
            ),
            ("code", "work.cleanup()"),
        ],
    )
    write(
        "02_databricks_integration.ipynb",
        [
            (
                "md",
                "# Databricks round trip\nThe default cells build and verify a local bundle and prepare the Tines contract. Set `LIVE = True` only after configuring your Databricks profile, Volume root and deployed job ID. Live cells upload evidence and launch billable compute.",
            ),
            ("code", SETUP),
            (
                "code",
                "from timeline_demo.integrations.databricks import DatabricksClient, tines_request\nfrom timeline_demo.parsers.common import file_hash\nLIVE = False\nVOLUME_ROOT = '/Volumes/main/incident_timelines/evidence/bundles'\nJOB_ID = 1  # Replace with the deployed publish_timeline job ID\nremote = VOLUME_ROOT + '/' + manifest['bundle_id']\ncontract = tines_request(bundle, remote, JOB_ID)\ncontract",
            ),
            (
                "code",
                "if LIVE:\n    client = DatabricksClient()\n    remote = client.upload_bundle(bundle, VOLUME_ROOT)\n    run = client.submit(bundle, remote, JOB_ID)\n    print(run)\nelse:\n    print('Prepared request; no Databricks call made.')",
            ),
            (
                "code",
                "if LIVE:\n    print(client.status(run['run_id']))\n    restored = workdir/'restored'\n    client.download_bundle(remote, restored, file_hash(bundle/'audit_manifest.json'))\n    assert verify_bundle(restored)['bundle_id'] == manifest['bundle_id']",
            ),
            (
                "md",
                "On Databricks, the deployed job publishes evidence references, events, receipts, quarantine records and a final publication marker. Its second notebook verifies the row count through `published_timeline`. Use `integrations/databricks/normalize_sources.py` for raw exports already in a Volume.",
            ),
            ("code", "work.cleanup()"),
        ],
    )
    write(
        "03_ai_harness.ipynb",
        [
            (
                "md",
                "# Token-bounded AI analysis\nStart with zero-token deterministic processing. Each selected AI task makes at most one call; cache hits use no additional model tokens. The default notebook only plans calls.",
            ),
            ("code", SETUP),
            (
                "code",
                "from timeline_demo.ai import Harness, load_policy, prepare\npolicy = load_policy()\n[{ 'task':task, **entry } for task, entry in policy['tasks'].items()]",
            ),
            (
                "code",
                "plans = {task:prepare(bundle, task, policy) for task in policy['tasks']}\n[{ 'task':task, 'model':p['model'], 'input_token_bound':p['input_token_bound'], 'coverage':p['coverage']} for task,p in plans.items()]",
            ),
            (
                "md",
                "The input bound includes the schema and instructions. It is a conservative UTF-8 byte bound plus framing reserve, not a tokenizer estimate. The model sees grouped event examples with short citation IDs; identities are pseudonymized. Review minimization requirements before enabling egress.",
            ),
            (
                "code",
                "ALLOW_AI = False\nif ALLOW_AI:\n    # Keep this ledger in a durable, access-controlled location for real cases.\n    harness = Harness(workdir/'analysis.sqlite', policy=policy)\n    result = harness.run(bundle, task='summarize', allow_ai=True)\n    print(result)\n    cached = harness.run(bundle, task='summarize', allow_ai=True)\n    assert cached['cache_hit']\n    assert cached['tokens_used_this_call'] == 0\nelse:\n    print('No model request made. Source evidence stays in the local bundle.')",
            ),
            (
                "md",
                "Run `correlate` or `review` explicitly when the investigation needs them. The harness does not auto-escalate to more expensive models. Do not treat model confidence or syntactically valid citations as proof of an interpretation.",
            ),
            ("code", "assert verify_bundle(bundle)['bundle_id'] == manifest['bundle_id']\nwork.cleanup()"),
        ],
    )


def build_ocsf_notebook():
    write(
        "04_ocsf_export.ipynb",
        [
            (
                "md",
                "# Pinned OCSF export\nExport a verified evidence bundle as core OCSF 1.3.0. Schema validation runs offline, uses zero model tokens, and keeps the original bundle unchanged. Required fields are never filled with model guesses.",
            ),
            ("code", SETUP),
            (
                "code",
                "from timeline_demo.ocsf import export_bundle, verify_export, schema_lock\nfrom timeline_demo.parsers.common import file_hash\nsource_pin = file_hash(bundle/'audit_manifest.json')\nocsf_dir = workdir/'ocsf'\nreport = export_bundle(bundle, ocsf_dir, manifest_sha256=source_pin)\nassert report['counts'] == {'source_events':5, 'exported_events':5, 'rejected_events':0}\nassert report['model_tokens'] == 0\nreport['counts']",
            ),
            (
                "code",
                "lock = schema_lock()\n[(int(uid), entry['name']) for uid, entry in lock['classes'].items()]",
            ),
            (
                "code",
                "export_pin = file_hash(ocsf_dir/'export_manifest.json')\nassert verify_export(ocsf_dir, bundle=bundle, manifest_sha256=export_pin) == report\nocsf_rows = [json.loads(line) for line in (ocsf_dir/'ocsf.jsonl').read_text().splitlines()]\nocsf_rows[0]",
            ),
            (
                "md",
                "## Explicitly account for sparse source records\nThe timeline can retain a partial audit record, but the API Activity export requires an actor and source endpoint. Strict mode rejects the export; quarantine mode writes a rejection receipt. Neither mode changes the evidence bundle.",
            ),
            (
                "code",
                "sparse = workdir/'sparse.json'\nsparse.write_text(json.dumps({'eventTime':'2026-09-01T10:00:00Z','eventName':'GetObject','eventID':'sparse-1'}))\nsparse_bundle = workdir/'sparse_bundle'\nrun_pipeline([Input('cloudtrail', sparse)], sparse_bundle, 'sparse-demo')\npartial = export_bundle(sparse_bundle, workdir/'partial', quarantine=True)\nassert partial['counts']['rejected_events'] == 1\njson.loads((workdir/'partial/rejections.jsonl').read_text())",
            ),
            (
                "md",
                "## Databricks publication\nOn a configured Databricks cluster, generate the export into a separate Unity Catalog Volume directory, then call `publish_ocsf_export(spark, export_dir, source_bundle, catalog, schema)`. Both paths must be accessible to Spark workers. The function verifies the source binding, inserts events and rejection receipts, then writes a final marker. Query `published_ocsf` for completed exports and inspect `published_ocsf_exports` for rejection counts. See `docs/OCSF_EXPORT.md` for a runnable Volume example and Tines completion implications. A successful export with quarantine enabled may be partial.",
            ),
            ("code", "assert file_hash(bundle/'audit_manifest.json') == source_pin\nwork.cleanup()"),
        ],
    )


def build_evaluation_notebook():
    write(
        "05_evaluation.ipynb",
        [
            (
                "md",
                "# Coverage and analyst-reviewed evaluation\nInspect offline scale measurements and a deliberately imperfect handwritten analysis. No provider call is made; these metrics are not measurements of real model quality.",
            ),
            (
                "code",
                "from pathlib import Path\nimport json\nroot = Path.cwd()\nif not (root/'benchmarks').exists():\n    root = root.parent\nfrom timeline_demo.evaluation import score_review",
            ),
            (
                "code",
                "measurements = json.loads((root/'benchmarks/results/2026-09-07-scale-ipv6.json').read_text())\n[{k: row[k] for k in ('shape', 'unique_events', 'ingest_seconds', 'process_peak_rss_mib', 'ai_coverage', 'ai_input_token_upper_bound')} for row in measurements['runs']]",
            ),
            (
                "md",
                "A group count represents source events, but the prompt only retains first/last examples. Distinct groups can exceed the input budget. Inspect omitted events; narrow the investigation scope before drawing conclusions.",
            ),
            (
                "code",
                "analysis = json.loads((root/'benchmarks/synthetic_analysis.json').read_text())\nlabels = json.loads((root/'benchmarks/synthetic_review.json').read_text())\nreport = score_review(analysis, root/'examples/demo_bundle', labels)\nassert report['citation_reference_validity'] == 1.0\nassert report['citation_faithfulness'] < 1.0\nassert report['duplicate_claims'] == 1\nreport",
            ),
            (
                "md",
                "The second finding has a real citation but an unsupported interpretation. The third repeats a credited claim. An analyst must supply every support/matching judgment. The scorer binds those judgments to the exact analysis and source bundle; it does not establish reviewer identity or judgment quality. Summary and next-step prose require separate review. See docs/EVALUATION.md.",
            ),
        ],
    )


if __name__ == "__main__":
    main()
