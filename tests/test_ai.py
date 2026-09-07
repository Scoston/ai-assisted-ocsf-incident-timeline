import copy
import json
import sqlite3
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor

import pytest
from timeline_demo.ai import Harness, load_policy, prepare
from timeline_demo.core.manifest import verify_bundle
from timeline_demo.pipeline import Input, run_pipeline


class FakeResponse:
    status = "completed"
    id = "offline-test-response"
    usage = SimpleNamespace(input_tokens=120, output_tokens=80)

    def __init__(self, bad_ref=False, status=None):
        self.output_text = json.dumps(
            {
                "observations": [
                    {"chunk_ref": "invented" if bad_ref else "c1", "field": "count", "value": "1"}
                ],
                "hypotheses": [],
                "abstain": False,
            }
        )
        if status:
            self.status = status

    def model_dump(self, **kwargs):
        return {
            "id": self.id,
            "status": self.status,
            "output_text": self.output_text,
            "usage": vars(self.usage),
        }


class FakeClient:
    def __init__(self, response=None, failure=None):
        self.responses = self
        self.calls = []
        self.response = response or FakeResponse()
        self.failure = failure

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.failure:
            raise self.failure
        return self.response


def test_no_network_by_default(bundle, tmp_path):
    client = FakeClient()
    result = Harness(tmp_path / "ledger.sqlite", client=client).run(bundle)
    assert result["status"] == "planned" and client.calls == []
    assert result["model"] == "gpt-5.6-luna"


def test_cache_and_provenance_preserve_evidence(bundle, tmp_path):
    original = verify_bundle(bundle)
    client = FakeClient()
    harness = Harness(tmp_path / "ledger.sqlite", client=client)
    result = harness.run(bundle, allow_ai=True)
    again = harness.run(bundle, allow_ai=True)
    assert len(client.calls) == 1
    assert again["cache_hit"] and again["tokens_used_this_call"] == 0
    assert result["human_review_required"] is True
    assert result["receipt"]["bundle_id"] == original["bundle_id"]
    assert verify_bundle(bundle) == original
    request = client.calls[0]
    assert request["store"] is False and request["max_output_tokens"] == 700
    assert request["text"]["format"]["strict"] is True
    assert "raw_data_hash" not in request["input"][1]["content"]
    assert "198.51.100.10" not in request["input"][1]["content"]
    assert "tools" not in request


def test_budget_blocks_dispatch(bundle, tmp_path):
    policy = load_policy()
    policy["max_case_tokens"] = 1
    client = FakeClient()
    with pytest.raises(ValueError, match="budget"):
        Harness(tmp_path / "ledger.sqlite", policy, client).run(bundle, allow_ai=True)
    assert client.calls == []


@pytest.mark.parametrize("response", [FakeResponse(bad_ref=True), FakeResponse(status="incomplete")])
def test_bad_or_incomplete_analysis_not_cached_as_success(bundle, tmp_path, response):
    client = FakeClient(response)
    harness = Harness(tmp_path / "ledger.sqlite", client=client)
    with pytest.raises(ValueError):
        harness.run(bundle, allow_ai=True)
    with pytest.raises(ValueError, match="already attempted"):
        harness.run(bundle, allow_ai=True)
    assert len(client.calls) == 1
    with sqlite3.connect(tmp_path / "ledger.sqlite") as db:
        assert db.execute("select status,charged from calls").fetchone() == ("failed", 200)


def test_network_error_consumes_reservation_no_hidden_retry(bundle, tmp_path):
    client = FakeClient(failure=TimeoutError("private-token-do-not-log"))
    path = tmp_path / "ledger.sqlite"
    with pytest.raises(TimeoutError):
        Harness(path, client=client).run(bundle, allow_ai=True)
    with sqlite3.connect(path) as db:
        status, charged, error = db.execute("select status,charged,error from calls").fetchone()
    assert status == "failed" and charged > 200 and error == "TimeoutError"
    assert b"private-token-do-not-log" not in path.read_bytes()


def test_case_scoped_cache(bundle, tmp_path, cloudtrail):
    raw = tmp_path / "copy.json"
    raw.write_text(json.dumps(cloudtrail))
    other = tmp_path / "other"
    run_pipeline([Input("cloudtrail", raw)], other, "different-case")
    client = FakeClient()
    harness = Harness(tmp_path / "ledger.sqlite", client=client)
    harness.run(bundle, allow_ai=True)
    assert not harness.run(other, allow_ai=True)["cache_hit"]
    assert len(client.calls) == 2


def test_selection_reports_omission_and_bounds_all_tasks(tmp_path, cloudtrail):
    raw = tmp_path / "many.jsonl"
    raw.write_text(
        "\n".join(json.dumps({**cloudtrail, "eventName": f"API{i}", "eventID": str(i)}) for i in range(300))
    )
    target = tmp_path / "bundle"
    run_pipeline([Input("cloudtrail", raw)], target, "many")
    for task in ["summarize", "correlate", "review"]:
        plan = prepare(target, task)
        assert 0 < plan["coverage"]["covered_events"] < 300
        assert plan["coverage"]["omitted_events"] + plan["coverage"]["covered_events"] == 300
        assert plan["input_token_bound"] <= load_policy()["tasks"][task]["max_input_tokens"]


def test_concurrent_cache_requests_dispatch_once(bundle, tmp_path):
    client = FakeClient()
    harness = Harness(tmp_path / "ledger.sqlite", client=client)

    def run():
        try:
            return harness.run(bundle, allow_ai=True)["status"]
        except ValueError:
            return "pending"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert "awaiting_review" in results and len(client.calls) == 1


def test_edited_cache_rejected(bundle, tmp_path):
    path = tmp_path / "ledger.sqlite"
    harness = Harness(path, client=FakeClient())
    harness.run(bundle, allow_ai=True)
    with sqlite3.connect(path) as db:
        altered = copy.deepcopy(json.loads(db.execute("select result from calls").fetchone()[0]))
    altered["candidate"]["observations"][0]["chunk_ref"] = "invented"
    with sqlite3.connect(path) as db:
        db.execute("update calls set result=?", (json.dumps(altered),))
    with pytest.raises(ValueError):
        harness.run(bundle, allow_ai=True)


def test_ledger_inside_evidence_rejected_without_writing(bundle):
    client = FakeClient()
    path = bundle / "forbidden.sqlite"
    harness = Harness(path, client=client)
    with pytest.raises(ValueError):
        harness.run(bundle, allow_ai=True)
    assert not path.exists()
    verify_bundle(bundle)
    assert not client.calls
