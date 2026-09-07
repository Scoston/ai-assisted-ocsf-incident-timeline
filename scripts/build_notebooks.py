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


if __name__ == "__main__":
    main()
