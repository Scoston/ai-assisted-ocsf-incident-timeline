import copy
from urllib.parse import parse_qs, urlsplit

import pytest

from timeline_demo.collection import collect_window
from timeline_demo.collection.enterprise import GitHubAudit, CloudWatch
from timeline_demo.collection.providers import make_provider
from timeline_demo.ocsf import export_bundle, verify_export
from timeline_demo.parsers.common import compact_json
from timeline_demo.parsers.registry import normalize_record, parse_file
from timeline_demo.pipeline import read_timeline
from test_enterprise_collection import FakeHttp, SAMPLES, START, END, config


def test_github_collection_paging_window_and_ocsf(tmp_path, monkeypatch):
    github = config("github_audit", organization="example-enterprise")
    provider = make_provider(github)
    monkeypatch.setenv("GITHUB_AUDIT_TOKEN", "synthetic-token")
    assert provider.http.headers()["X-GitHub-Api-Version"] == "2026-03-10"
    first = copy.deepcopy(SAMPLES["github_audit"])
    last = {**first, "@timestamp": 1788260400000, "_document_id": "end-excluded"}
    http = FakeHttp(
        [
            (
                [first],
                {
                    "link": '<https://api.github.com/orgs/example-enterprise/audit-log?after=opaque>; rel="next"'
                },
            ),
            [last],
        ],
        "https://api.github.com",
    )
    provider.http = http
    result = collect_window(
        provider, tmp_path / "state", tmp_path / "bundle", "github-case", START, END, sleep=lambda _: None
    )
    params = parse_qs(urlsplit(http.calls[0][1]).query)
    assert params["include"] == ["all"] and params["order"] == ["asc"]
    assert params["phrase"] == ["created:2026-09-01T10:00:00+00:00..2026-09-01T11:00:00+00:00"]
    assert result["collection"]["excluded_outside_window"] == 1
    event = next(read_timeline(tmp_path / "bundle"))
    assert event["user_name"] == first["actor"] and event["status"] == "unknown"
    exported = export_bundle(tmp_path / "bundle", tmp_path / "ocsf")
    assert verify_export(tmp_path / "ocsf", bundle=tmp_path / "bundle") == exported


@pytest.mark.parametrize(
    "link",
    [
        '<https://evil.example/orgs/example-enterprise/audit-log?after=x>; rel="next"',
        '<https://api.github.com/orgs/other-org/audit-log?after=x>; rel="next"',
        "not a link",
        '<https://api.github.com/orgs/example-enterprise/audit-log?after=x>; rel="next", <https://api.github.com/orgs/example-enterprise/audit-log?after=y>; rel="next"',
    ],
)
def test_github_unsafe_or_ambiguous_links_fail(link):
    provider = GitHubAudit(
        config("github_audit", organization="example-enterprise"),
        FakeHttp([([], {"link": link})], "https://api.github.com"),
    )
    with pytest.raises(ValueError):
        provider.fetch(START, END, None)


@pytest.mark.parametrize(
    "extra", [{"organization": "../other"}, {"host": "https://evil.example"}, {"token": "forbidden"}]
)
def test_github_bad_configuration_fails_before_auth(extra):
    with pytest.raises(ValueError):
        make_provider({**config("github_audit", organization="example-enterprise"), **extra})


def test_kubernetes_audit_stages_are_preserved_with_original_identity(tmp_path):
    final = copy.deepcopy(SAMPLES["kubernetes_audit"])
    final["impersonatedUser"] = {"username": "impersonated-admin"}
    first = {**final, "stage": "RequestReceived", "stageTimestamp": final["requestReceivedTimestamp"]}
    first.pop("responseStatus")
    path = tmp_path / "audit.json"
    path.write_text(
        compact_json({"apiVersion": "audit.k8s.io/v1", "kind": "EventList", "items": [first, final]})
    )
    events = parse_file(path, "kubernetes_audit")
    assert len(events) == 2 and events[0]["event_uuid"] != events[1]["event_uuid"]
    assert events[0]["source_event_id"] == events[1]["source_event_id"] == final["auditID"]
    assert events[0]["epoch_ms"] < events[1]["epoch_ms"]
    assert [e["status"] for e in events] == ["unknown", "failure"]
    assert events[1]["user_name"] == final["user"]["username"]


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "Pod"},
        {"apiVersion": "v1"},
        {"stage": "unknown"},
        {"auditID": ""},
        {"responseStatus": {"code": True}},
        {"responseStatus": {"code": "200"}},
        {"requestReceivedTimestamp": None},
    ],
)
def test_kubernetes_rejects_non_audit_and_malformed_events(change):
    with pytest.raises(ValueError):
        normalize_record({**SAMPLES["kubernetes_audit"], **change}, "kubernetes_audit", "raw", "a" * 64, 1)


def test_kubernetes_existing_cloudwatch_transport_and_ocsf(tmp_path):
    row = SAMPLES["kubernetes_audit"]

    class Client:
        def filter_log_events(self, **kwargs):
            return {
                "events": [{"timestamp": 1788256800000, "message": compact_json(row)}],
                "searchedLogStreams": [],
            }

    provider = CloudWatch(
        config(
            "cloudwatch_logs",
            region="us-east-1",
            log_group="/aws/eks/example/cluster",
            parser="kubernetes_audit",
            format="json",
        ),
        Client(),
    )
    result = collect_window(
        provider, tmp_path / "state", tmp_path / "bundle", "kubernetes-case", START, END, sleep=lambda _: None
    )
    assert result["collection"]["included_records"] == 1
    export_bundle(tmp_path / "bundle", tmp_path / "ocsf")
    verify_export(tmp_path / "ocsf", bundle=tmp_path / "bundle")
