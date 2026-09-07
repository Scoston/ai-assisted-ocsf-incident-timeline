import json
import io
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from timeline_demo.integrations.databricks import DatabricksClient, identifier, tines_request, volume_path

ROOT = Path(__file__).resolve().parents[1]


def test_tines_contract_is_stable_and_job_scoped(bundle):
    a = tines_request(bundle, "/Volumes/main/ir/evidence/bundle", 42)
    assert a == tines_request(bundle, "/Volumes/main/ir/evidence/bundle", 42)
    assert (
        a["idempotency_key"]
        != tines_request(bundle, "/Volumes/main/ir/evidence/bundle", 43)["idempotency_key"]
    )
    assert len(a["idempotency_key"]) == 64
    assert "events" not in a
    import jsonschema
    from timeline_demo.ai import resource

    jsonschema.validate(a, resource("tines_request.schema.json"))


@pytest.mark.parametrize("value", ["x;DROP TABLE t", "x.y", "x`", "", "../root"])
def test_sql_identifier_allowlist(value):
    with pytest.raises(ValueError):
        identifier(value)


@pytest.mark.parametrize(
    "path", ["https://example.test/file", "/Volumes/a/b/c/../secret", "/Volumes/a/b/c//file", "/tmp/file"]
)
def test_remote_path_allowlist(path):
    with pytest.raises(ValueError):
        volume_path(path)


class FakeWorkspace:
    def __init__(self):
        self.files = self
        self.jobs = self
        self.uploads = {}
        self.requests = []

    def create_directory(self, path):
        pass

    def download(self, path):
        return SimpleNamespace(contents=io.BytesIO(self.uploads[path]))

    def upload(self, path, contents, overwrite):
        assert overwrite is False
        if path in self.uploads:
            from databricks.sdk.errors import ResourceAlreadyExists

            raise ResourceAlreadyExists("existing file")
        self.uploads[path] = contents.read()

    def run_now(self, **kwargs):
        self.requests.append(kwargs)
        return SimpleNamespace(response=SimpleNamespace(run_id=123))

    def get_run(self, run_id):
        return SimpleNamespace(
            as_dict=lambda: {
                "state": {"life_cycle_state": "TERMINATED", "result_state": "SUCCESS"},
                "run_page_url": "https://example.test/run/123",
            }
        )


def test_sdk_upload_submit_and_status(bundle):
    workspace = FakeWorkspace()
    client = DatabricksClient(workspace)
    remote = client.upload_bundle(bundle, "/Volumes/main/ir/evidence")
    assert list(workspace.uploads)[-1].endswith("audit_manifest.json")
    assert client.upload_bundle(bundle, "/Volumes/main/ir/evidence") == remote
    assert client.submit(bundle, remote, 42)["run_id"] == 123
    assert workspace.requests[0]["job_parameters"]["bundle_path"] == remote
    assert len(workspace.requests[0]["idempotency_token"]) == 64
    assert client.status(123)["state"]["result_state"] == "SUCCESS"


def test_tines_story_graphs_and_external_boundaries():
    for path in (ROOT / "integrations/tines/stories").glob("*.json"):
        story = json.loads(path.read_text())
        agents = story["agents"]
        assert agents and len({a["guid"] for a in agents}) == len(agents)
        for link in story["links"]:
            assert 0 <= link["source"] < len(agents) and 0 <= link["receiver"] < len(agents)
        for agent in agents:
            assert agent["disabled"] is True
            if agent["type"] == "Agents::HTTPRequestAgent":
                assert agent["options"]["url"].startswith("<<RESOURCE.databricks_host>>/api/2.2/jobs/")
                assert "CREDENTIAL.databricks_token" in json.dumps(agent["options"])
        assert set(story["exit_agent_guids"]) <= {a["guid"] for a in agents}
    monitor = json.loads((ROOT / "integrations/tines/stories/publish_and_monitor.json").read_text())
    payload = json.dumps(monitor)
    assert "Polling exhausted" in payload and "Submission error" in payload and "Polling error" in payload


def test_databricks_job_wheel_notebook_and_retry_contract():
    from databricks.sdk.service.jobs import JobSettings

    cfg = yaml.safe_load((ROOT / "databricks.yml").read_text())
    job = cfg["resources"]["jobs"]["publish_timeline"]
    parsed = JobSettings.from_dict(job)
    assert len(parsed.tasks) == 3
    assert job["max_concurrent_runs"] == 1
    assert job["tasks"][0]["python_wheel_task"]["entry_point"] == "timeline-databricks"
    assert "manifest_sha256" in json.dumps(job)
    ocsf = next(task for task in job["tasks"] if task["task_key"] == "export_and_publish_ocsf")
    assert ocsf["depends_on"] == [{"task_key": "verify_and_publish"}]
    assert cfg["variables"]["ocsf_enabled"]["default"] == "false"
    assert cfg["variables"]["ocsf_quarantine"]["default"] == "false"
    assert {task["python_wheel_task"]["entry_point"] for task in job["tasks"]} == {
        "timeline-databricks",
        "timeline-databricks-ocsf",
        "timeline-databricks-inspect",
    }
    assert all("notebook_task" not in task for task in job["tasks"])
    assert (ROOT / "integrations/databricks/inspect_published.py").exists()


def test_sdk_round_trip_and_pinned_download(bundle, tmp_path):
    from timeline_demo.parsers.common import file_hash

    workspace = FakeWorkspace()
    client = DatabricksClient(workspace)
    remote = client.upload_bundle(bundle, "/Volumes/main/ir/evidence")
    pin = file_hash(bundle / "audit_manifest.json")
    restored = tmp_path / "download"
    result = client.download_bundle(remote, restored, pin)
    assert result["counts"]["event_count"] == 1
    assert (restored / "timeline.jsonl").read_bytes() == (bundle / "timeline.jsonl").read_bytes()
    with pytest.raises(ValueError):
        client.download_bundle(remote, tmp_path / "bad", "0" * 64)
    assert not (tmp_path / "bad").exists()
