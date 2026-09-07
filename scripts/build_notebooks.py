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
    build_signing_notebook()
    build_enterprise_notebook()
    build_operations_notebook()
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


def build_signing_notebook():
    write(
        "06_signed_manifests.ipynb",
        [
            (
                "md",
                "# Signed manifests and explicit signer trust\nGenerate temporary demonstration keys, sign a synthetic bundle and verify it with a separately pinned trust policy. Keys are deleted on cleanup. Production keys need an approved secret workflow; never reuse this demonstration passphrase.",
            ),
            ("code", SETUP),
            (
                "code",
                "from timeline_demo.signing import generate_keypair, public_entry, write_trust, sign_artifact, verify_signature\nfrom timeline_demo.parsers.common import file_hash\npassword = b'synthetic-notebook-password-only'\nkeys = generate_keypair(workdir/'keys', password)\nkey_id, entry = public_entry(keys['public_key'])\npolicy = {'version':'1.0', 'keys':{key_id:entry}}\ntrust = workdir/'trust-v1.json'\ntrust_pin = write_trust(trust, policy)['trust_store_sha256']\nsignature = workdir/'bundle.sig.json'\nsource_pin = file_hash(bundle/'audit_manifest.json')\nsign_artifact(bundle, keys['private_key'], password, signature, trust, trust_pin)\nverify_signature(bundle, signature, trust, trust_pin)",
            ),
            (
                "md",
                "The trust policy and its hash must be obtained through an independent, controlled channel. The signature contains a key fingerprint, not a self-authorizing public key. No trusted signing time, source authenticity or completeness is asserted.",
            ),
            (
                "code",
                "policy['keys'][key_id]['status'] = 'verify_only'\nretired = workdir/'trust-v2.json'\nretired_pin = write_trust(retired, policy)['trust_store_sha256']\nassert verify_signature(bundle, signature, retired, retired_pin)['key_status'] == 'verify_only'\npolicy['keys'][key_id]['status'] = 'revoked'\nrevoked = workdir/'trust-v3.json'\nrevoked_pin = write_trust(revoked, policy)['trust_store_sha256']\ntry:\n    verify_signature(bundle, signature, revoked, revoked_pin)\nexcept ValueError as error:\n    print(type(error).__name__, str(error))\nelse:\n    raise AssertionError('Revoked signer was accepted')\nassert file_hash(bundle/'audit_manifest.json') == source_pin",
            ),
            (
                "md",
                "A verify_only key can verify historical attestations, but this signing command refuses to create new ones. Without a trusted timestamp, verification cannot establish when a signature was made. A compromised key must be revoked; revoked signatures are rejected regardless of claimed age. Historical Delta verification receipts remain audit records, not current authorization. See docs/SIGNING.md for rotation and Databricks/Tines deployment.",
            ),
            ("code", "work.cleanup()"),
        ],
    )


def build_enterprise_notebook():
    write(
        "07_enterprise_collection.ipynb",
        [
            (
                "md",
                "# Enterprise collection and late delivery\nInspect available source configurations and collect a simulated M365 feed. This notebook uses synthetic responses, makes no network request and consumes zero model tokens. It demonstrates why content-delivery windows differ from event timestamps; live permissions and source counts need tenant acceptance.",
            ),
            (
                "code",
                """from pathlib import Path
import json
import tempfile
from timeline_demo.collection import collect_window
from timeline_demo.collection.enterprise import M365
from timeline_demo.parsers.common import compact_json
from timeline_demo.pipeline import read_timeline
from timeline_demo.core.manifest import verify_bundle
root = Path.cwd()
if not (root/'examples').exists():
    root = root.parent
configs = [json.loads(p.read_text()) for p in sorted((root/'examples/collectors').glob('*.json'))]
assert len({c['source'] for c in configs}) == 18
[(c['source_id'], c['source'], c.get('table', c.get('content_type', ''))) for c in configs]""",
            ),
            (
                "md",
                "The response below delivers an August event in a September content window. All three source responses are archived before their cursors advance. A completed replay verifies the existing bundle and performs no new request.",
            ),
            (
                "code",
                """class SyntheticFeed:
    host = 'https://manage.office.com'
    def __init__(self):
        self.calls = 0
        tenant = '00000000-0000-0000-0000-000000000000'
        self.responses = [
            [{'contentType':'Audit.Exchange', 'status':'enabled'}],
            [{'contentType':'Audit.Exchange', 'contentCreated':'2026-09-01T10:15:00Z',
              'contentUri':self.host + '/api/v1.0/' + tenant + '/activity/feed/audit/synthetic-1'}],
            [{'Id':'synthetic-mail-1', 'CreationTime':'2026-08-31T23:00:00',
              'Operation':'New-InboxRule', 'UserId':'alice@example.test', 'ClientIP':'198.51.100.1'}],
        ]
    def request(self, method, path, **kwargs):
        assert method == 'GET'
        self.calls += 1
        value = self.responses.pop(0)
        result = compact_json(value).encode(), value
        return (*result, {}) if kwargs.get('headers') else result

work = tempfile.TemporaryDirectory()
workdir = Path(work.name)
configuration = json.loads((root/'examples/collectors/m365-exchange.json').read_text())
http = SyntheticFeed()
provider = M365(configuration, http)
arguments = (provider, workdir/'state', workdir/'bundle', 'late-mail-demo',
             '2026-09-01T10:00:00Z', '2026-09-01T11:00:00Z')
result = collect_window(*arguments, sleep=lambda _: None)
assert result['collection']['included_records'] == 1
assert result['collection']['model_tokens'] == 0
assert result['collection']['source_completeness_proven'] is False
result['collection']""",
            ),
            (
                "code",
                """events = list(read_timeline(workdir/'bundle'))
assert events[0]['time_utc'].startswith('2026-08-31T23:00:00')
assert events[0]['timezone_assumption'] == 'UTC'
assert collect_window(*arguments, sleep=lambda _: None)['manifest_sha256'] == result['manifest_sha256']
assert http.calls == 3
manifest = verify_bundle(workdir/'bundle', result['manifest_sha256'])
assert len([name for name in manifest['files'] if name.startswith('attachments/collection-pages/')]) == 3
[(e['time_utc'], e['activity_name'], e['user_name']) for e in events]""",
            ),
            (
                "md",
                "For retained investigations, choose durable state and bundle paths, refresh credentials through existing identity tooling, and follow docs/ENTERPRISE_APIS.md. Publish only verified bundles through the Databricks/Tines reference workflow. Review OCSF rejection counts and the AI harness's omitted coverage separately; drained pagination alone is not proof of complete source acquisition.",
            ),
            ("code", "work.cleanup()"),
        ],
    )


def build_operations_notebook():
    write("08_operations_and_recovery.ipynb", [
        ("md", "# Collector recovery and monitoring\nSimulate an interrupted collection, inspect health, back up committed pages, and resume from a verified snapshot. Synthetic data only; no provider or model calls. Install the collection extra."),
        ("code", """import tempfile
from pathlib import Path
from timeline_demo.collection import collect_window
from timeline_demo.collection.providers import Page
from timeline_demo.operations import backup, restore, health, prometheus
work = tempfile.TemporaryDirectory()
root = Path(work.name)
class Source:
    parser = 'entra_signin'
    identity = {'source': 'entra_signin', 'source_id': 'recovery-demo'}
    interval = 0
    def __init__(self, pages):
        self.pages, self.calls = iter(pages), 0
    def fetch(self, *args):
        self.calls += 1
        return next(self.pages)
first = Source([Page(b'{"value":[]}', [], {'next': 2})])
arguments = (root/'state', root/'bundle', 'recovery-demo', '2026-09-01T10:00:00Z', '2026-09-01T11:00:00Z')
try:
    collect_window(first, *arguments, max_pages=1)
    raise AssertionError('expected a paused collection')
except ValueError as error:
    assert 'page budget' in str(error)
assert not (root/'bundle').exists()
health(root/'state', verify_blobs=True)"""),
        ("code", """saved = backup(root/'state', root/'snapshot')
assert saved['published_bundles_included'] is False
restore(root/'snapshot', root/'restored', saved['snapshot_sha256'])
remaining = Source([Page(b'{"value":[]}', [], None)])
result = collect_window(remaining, root/'restored', *arguments[1:])
assert remaining.calls == 1
assert result['collection']['model_tokens'] == 0
assert health(root/'restored', verify_blobs=True, verify_bundles=True)['healthy']
print(prometheus(health(root/'restored')))"""),
        ("md", "Persist the snapshot SHA-256 independently in production. Backups contain state and committed page blobs, not published bundles, signing keys or AI ledgers. Restore published bundles to their original absolute paths first. Never run both restored and original collector state simultaneously. See docs/OPERATIONS.md for recovery, retention and monitoring procedures."),
        ("code", "work.cleanup()"),
    ])


if __name__ == "__main__":
    main()
