import sqlite3

import pytest

from timeline_demo.collection import collect_window, collect_until
from timeline_demo.collection.providers import Page, RestAudit, DatabricksAudit, CloudTrail, Http, origin
from timeline_demo.core.manifest import verify_bundle
from timeline_demo.parsers.common import compact_json
from timeline_demo.pipeline import read_timeline, run_pipeline, Input

START, END = "2026-09-01T10:00:00Z", "2026-09-01T11:00:00Z"


def signin(id, when=START):
    return {
        "id": str(id),
        "createdDateTime": when,
        "userPrincipalName": "alice@example.test",
        "status": {"errorCode": 0},
    }


def page(rows, cursor=None):
    return Page(compact_json({"value": rows}).encode(), rows, cursor)


class Provider:
    parser = "entra_signin"
    interval = 0
    identity = {"source": "entra_signin", "source_id": "test"}

    def __init__(self, pages):
        self.pages, self.calls = list(pages), []

    def fetch(self, start, end, cursor):
        self.calls.append((start, end, cursor))
        response = self.pages.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def collect(provider, tmp, **options):
    return collect_window(
        provider, tmp / "state", tmp / "bundle", "case-1", START, END, sleep=lambda _: None, **options
    )


def test_checkpoint_resume_and_source_attachments(tmp_path):
    provider = Provider([page([signin(1)], {"page": 2}), page([signin(2)])])
    with pytest.raises(ValueError, match="page budget"):
        collect(provider, tmp_path, max_pages=1)
    assert not (tmp_path / "bundle").exists()
    result = collect(provider, tmp_path)
    assert provider.calls[1][2] == {"page": 2}
    manifest = verify_bundle(result["bundle"])
    assert manifest["counts"]["event_count"] == 2
    assert "attachments/collection-pages/000002.json" in manifest["files"]
    assert result["collection"]["source_completeness_proven"] is False
    assert result["collection"]["model_tokens"] == 0
    assert collect(provider, tmp_path) == result
    assert len(provider.calls) == 2


def test_failed_page_and_parser_failure_do_not_advance(tmp_path):
    provider = Provider([page([signin(1)], {"page": 2}), ValueError("provider denied"), page([signin(2)])])
    with pytest.raises(ValueError, match="provider denied"):
        collect(provider, tmp_path)
    assert not (tmp_path / "bundle").exists()
    result = collect(provider, tmp_path)
    assert provider.calls[-1][2] == {"page": 2}
    assert result["collection"]["included_records"] == 2


def test_window_boundaries_and_duplicate_receipts(tmp_path):
    provider = Provider([page([signin(1), signin(1), signin(2, END), signin(3, "2026-09-01T09:59:59Z")])])
    result = collect(provider, tmp_path)
    assert result["collection"]["excluded_outside_window"] == 2
    counts = verify_bundle(result["bundle"])["counts"]
    assert counts["event_count"] == 1 and counts["duplicate_events"] == 1


@pytest.mark.parametrize("fault", ["cycle", "missing_time", "budget", "bytes"])
def test_incomplete_collections_fail_closed(tmp_path, fault):
    rows = [{}] if fault == "missing_time" else [signin(1), signin(2)]
    provider = Provider([page(rows, {"p": 1}), page(rows, {"p": 1})])
    kwargs = {"max_records": 1} if fault == "budget" else {"max_bytes": 1} if fault == "bytes" else {}
    with pytest.raises(ValueError):
        collect(provider, tmp_path, **kwargs)
    assert not (tmp_path / "bundle").exists()


def test_checkpoint_tampering_blocks_replay(tmp_path):
    provider = Provider([page([signin(1)], {"page": 2})])
    with pytest.raises(ValueError):
        collect(provider, tmp_path, max_pages=1)
    with sqlite3.connect(tmp_path / "state/collection.sqlite") as db:
        digest = db.execute("SELECT body_sha FROM pages").fetchone()[0]
    (tmp_path / "state/blobs" / digest).write_text("tampered")
    with pytest.raises(ValueError, match="altered"):
        collect(Provider([]), tmp_path)


def test_rolling_watermark_only_moves_after_publication(tmp_path):
    provider = Provider([page([signin(1)]), ValueError("interrupted")])
    args = (provider, tmp_path / "state", tmp_path / "bundles", "roll", START, "2026-09-01T12:00:00Z")
    with pytest.raises(ValueError, match="interrupted"):
        collect_until(*args, sleep=lambda _: None)
    with sqlite3.connect(tmp_path / "state/collection.sqlite") as db:
        assert db.execute("SELECT through_ms FROM watermarks").fetchone()[0] == 1788260400000
    provider.pages = [page([signin(2, "2026-09-01T11:30:00Z")])]
    result = collect_until(*args, sleep=lambda _: None)
    assert result["status"] == "caught_up"
    assert provider.calls[-1][0].startswith("2026-09-01T10:55:00")
    assert len(result["windows"]) == 1


def test_empty_source_and_output_state_boundary(tmp_path):
    result = collect(Provider([page([])]), tmp_path)
    assert verify_bundle(result["bundle"])["counts"]["event_count"] == 0
    with pytest.raises(ValueError, match="separate"):
        collect_window(Provider([]), tmp_path / "state", tmp_path / "state/out", "case", START, END)


class FakeHttp:
    def __init__(self, host, values):
        self.host, self.values, self.calls = host, list(values), []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        value = self.values.pop(0)
        return compact_json(value).encode(), value


def test_graph_paging_and_host_boundary():
    base = "https://graph.microsoft.com"
    http = FakeHttp(
        base,
        [
            {"value": [signin(1)], "@odata.nextLink": base + "/v1.0/auditLogs/signIns?$skiptoken=opaque"},
            {"value": []},
        ],
    )
    adapter = RestAudit({"source": "entra_signin", "source_id": "test"}, http)
    first = adapter.fetch(START, END, None)
    assert "$skiptoken=opaque" in first.cursor["path"]
    assert adapter.fetch(START, END, first.cursor).cursor is None
    http.values = [{"value": [], "@odata.nextLink": "https://evil.example/v1.0/auditLogs/signIns"}]
    with pytest.raises(ValueError, match="origin"):
        adapter.fetch(START, END, None)


def test_tines_count_contract_and_native_ip_mapping(tmp_path):
    log = {
        "created_at": START,
        "operation_name": "StoryCreation",
        "id": 1,
        "user_email": "alice@example.test",
        "request_ip": "198.51.100.1",
    }
    http = FakeHttp(
        "https://tenant.tines.com", [{"audit_logs": [log], "meta": {"count": 1, "next_page": None}}]
    )
    adapter = RestAudit({"source": "tines_audit", "source_id": "test"}, http)
    rows = adapter.fetch("2026-09-01T10:00:00+00:00", END, None).records
    path = tmp_path / "tines.json"
    path.write_text(compact_json(rows))
    run_pipeline([Input("tines_audit", path)], tmp_path / "bundle", "tines")
    event = next(read_timeline(tmp_path / "bundle"))
    assert event["src_ip"] == log["request_ip"] and event["parser_version"] == "2.1.0"
    http.values = [{"audit_logs": [], "meta": {"count": 3, "next_page": None}}]
    with pytest.raises(ValueError, match="record count"):
        adapter.fetch("2026-09-01T10:00:00+00:00", END, None)


def test_databricks_async_statement_and_chunk_integrity():
    row = compact_json({"event_time": START, "action_name": "runNow"})
    http = FakeHttp(
        "https://workspace.example",
        [
            {"statement_id": "statement-1", "status": {"state": "PENDING"}},
            {
                "statement_id": "statement-1",
                "status": {"state": "SUCCEEDED"},
                "manifest": {
                    "truncated": False,
                    "total_row_count": 2,
                    "schema": {"columns": [{"name": "record_json"}]},
                },
                "result": {
                    "chunk_index": 0,
                    "row_offset": 0,
                    "row_count": 1,
                    "data_array": [[row]],
                    "next_chunk_index": 1,
                },
            },
            {"chunk_index": 1, "row_offset": 1, "row_count": 1, "data_array": [[row]]},
        ],
    )
    provider = DatabricksAudit({"warehouse_id": "abc"}, http)
    first = provider.fetch(START, END, None)
    assert first.records == [] and first.cursor["statement_id"] == "statement-1"
    second = provider.fetch(START, END, first.cursor)
    assert provider.fetch(START, END, second.cursor).cursor is None
    assert [call[0] for call in http.calls] == ["POST", "GET", "GET"]
    assert http.calls[0][2]["body"]["parameters"][0]["value"] == START
    http.values = [{"statement_id": "bad", "status": {"state": "SUCCEEDED"}, "manifest": {"truncated": True}}]
    with pytest.raises(ValueError, match="truncated"):
        provider.fetch(START, END, None)


def test_cloudtrail_continuation_keeps_fixed_window():
    class Client:
        def lookup_events(self, **kwargs):
            self.kwargs = kwargs
            return {"Events": [{"CloudTrailEvent": '{"eventName":"GetObject"}'}], "NextToken": "next"}

    client = Client()
    provider = CloudTrail({"source_id": "aws", "region": "us-east-1"}, client)
    p = provider.fetch("2026-09-01T10:00:00+00:00", "2026-09-01T11:00:00+00:00", {"token": "before"})
    assert p.cursor == {"token": "next"}
    assert client.kwargs["NextToken"] == "before" and client.kwargs["MaxResults"] == 50
    assert client.kwargs["StartTime"].hour == 10


class Response:
    def __init__(self, code, data=b'{"value":[]}', headers=None):
        self.status_code, self.data, self.headers = code, data, headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def iter_content(self, size):
        yield self.data


def test_http_retry_after_redirect_and_ambiguous_post():
    class Session:
        def __init__(self, responses):
            self.responses, self.calls = list(responses), []

        def request(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return self.responses.pop(0)

    waited = []
    session = Session([Response(429, headers={"Retry-After": "2"}), Response(200)])
    http = Http(
        "https://tenant.example",
        lambda: {"Authorization": "Bearer test"},
        session=session,
        sleep=waited.append,
    )
    assert http.request("GET", "/audit")[1] == {"value": []}
    assert waited == [2] and session.calls[0][1]["allow_redirects"] is False
    for method, code in [("GET", 302), ("POST", 503), ("GET", 401)]:
        session.responses = [Response(code)]
        with pytest.raises(ValueError, match=str(code)):
            http.request(method, "/audit")
    session.responses = [Response(429, headers={"Retry-After": "120"})]
    with pytest.raises(ValueError, match="wait budget"):
        http.request("GET", "/audit")
    for host in [
        "http://tenant.example",
        "https://user:secret@tenant.example",
        "https://tenant.example/path",
    ]:
        with pytest.raises(ValueError):
            origin(host)
