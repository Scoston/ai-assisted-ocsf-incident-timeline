import copy
import json
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from timeline_demo.collection import collect_window
from timeline_demo.collection.enterprise import (
    AWS,
    SOURCES,
    AzureActivity,
    CloudWatch,
    Falcon,
    GCP,
    GraphAudit,
    GuardDuty,
    Hunting,
    LogAnalytics,
    M365,
    Okta,
    SecurityHub,
    Splunk,
    Workspace,
    make_enterprise_provider,
)
from timeline_demo.collection.providers import Http, make_provider
from timeline_demo.core.manifest import verify_bundle
from timeline_demo.ocsf import map_event
from timeline_demo.parsers.common import compact_json
from timeline_demo.parsers.registry import normalize_record
from timeline_demo.pipeline import read_timeline

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = json.loads((ROOT / "examples/parser_samples.json").read_text())
START, END = "2026-09-01T10:00:00Z", "2026-09-01T11:00:00Z"
OLD = "2026-08-20T10:00:00Z"
GUID = "00000000-0000-0000-0000-000000000000"


class FakeHttp:
    def __init__(self, values, host="https://graph.microsoft.com"):
        self.values, self.host, self.calls = list(values), host, []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        value = self.values.pop(0)
        if isinstance(value, Exception):
            raise value
        headers = {}
        if isinstance(value, tuple):
            value, headers = value
        result = compact_json(value).encode(), copy.deepcopy(value)
        return (*result, headers) if kwargs.get("headers") else result


def config(source, **kwargs):
    return {"source": source, "source_id": "test-" + source, **kwargs}


def collect(provider, tmp, **kwargs):
    return collect_window(
        provider, tmp / "state", tmp / "bundle", "case-enterprise", START, END, sleep=lambda _: None, **kwargs
    )


def status(total=1, **extra):
    return {
        "entry": [
            {
                "content": {
                    "isFailed": False,
                    "isFinalized": False,
                    "isDone": True,
                    "dispatchState": "DONE",
                    "eventIsTruncated": False,
                    "dropCount": 0,
                    "resultCount": total,
                    "eventCount": total,
                    **extra,
                }
            }
        ]
    }


def table_response(row):
    return {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": name, "type": "dynamic" if isinstance(value, dict) else "string"}
                    for name, value in row.items()
                ],
                "rows": [list(row.values())],
            }
        ]
    }


def adapters():
    directory = GraphAudit(config("entra_audit"), FakeHttp([{"value": [SAMPLES["entra_audit"]]}]))
    alert = {**SAMPLES["defender_alert"], "createdDateTime": OLD, "lastUpdateDateTime": START}
    defender = GraphAudit(config("defender_alert"), FakeHttp([{"value": [alert]}]))
    azure = AzureActivity(
        config("azure_activity", subscription_id=GUID),
        FakeHttp([{"value": [SAMPLES["azure_activity"]]}], "https://management.azure.com"),
    )
    okta = Okta(config("okta"), FakeHttp([[SAMPLES["okta"]]], "https://tenant.okta.com"))
    google = GCP(
        config("gcp_audit", project_id="example-project"),
        FakeHttp([{"nextPageToken": "empty-page-is-not-the-end"}, {"entries": [SAMPLES["gcp_audit"]]}]),
    )
    workspace = Workspace(
        config("google_workspace", application="login"),
        FakeHttp(
            [
                {
                    "kind": "admin#reports#activities",
                    "items": [SAMPLES["google_workspace"]],
                    "nextPageToken": "two",
                },
                {"kind": "admin#reports#activities"},
            ]
        ),
    )
    hunting = Hunting(
        config("defender_hunting", table="DeviceProcessEvents"),
        FakeHttp(
            [
                {
                    "Results": [SAMPLES["defender_hunting"]["record"]],
                    "Schema": [{"Name": "Timestamp", "Type": "DateTime"}],
                }
            ]
        ),
    )
    logs = LogAnalytics(
        config("azure_log_analytics", table="SecurityEvent", workspace_id=GUID),
        FakeHttp([table_response(SAMPLES["azure_log_analytics"]["record"])]),
    )
    return [directory, defender, azure, okta, google, workspace, hunting, logs]


@pytest.mark.parametrize("index", range(8))
def test_http_sources_roundtrip_and_completed_replay(index, tmp_path):
    provider = adapters()[index]
    result = collect(provider, tmp_path)
    assert verify_bundle(result["bundle"])["counts"]["event_count"] == 1
    rows = list(read_timeline(result["bundle"]))
    assert rows[0]["parser_name"] == provider.parser
    if provider.parser == "defender_alert":
        assert rows[0]["original_timestamp"] == OLD
        assert result["collection"]["window_basis"] == "lastUpdateDateTime"
    calls = len(provider.http.calls)
    assert collect(provider, tmp_path)["manifest_sha256"] == result["manifest_sha256"]
    assert len(provider.http.calls) == calls
    assert result["collection"]["model_tokens"] == 0
    assert result["collection"]["source_completeness_proven"] is False


def test_m365_checkpoints_content_list_and_keeps_late_events(tmp_path):
    host = "https://manage.office.com"
    base = f"/api/v1.0/{GUID}/activity/feed"
    uri = host + base + "/audit/content$1"
    source = config("m365_audit", tenant_id=GUID, content_type="Audit.Exchange", publisher_id=GUID)
    http = FakeHttp(
        [
            [{"contentType": "Audit.Exchange", "status": "enabled"}],
            (
                [{"contentType": "Audit.Exchange", "contentCreated": START, "contentUri": uri}],
                {"nextpageuri": host + base + "/subscriptions/content?nextPage=two"},
            ),
            ValueError("temporary failure"),
            [{**SAMPLES["m365_audit"], "CreationTime": OLD}],
            [],
        ],
        host,
    )
    provider = M365(source, http)
    with pytest.raises(ValueError, match="temporary"):
        collect(provider, tmp_path)
    assert not (tmp_path / "bundle").exists()
    with sqlite3.connect(tmp_path / "state/collection.sqlite") as db:
        # Verify the metadata page was committed before fetching its content URI.
        assert db.execute("SELECT count(*) FROM pages").fetchone()[0] == 2
    result = collect(provider, tmp_path)
    assert len(http.calls) == 5
    assert http.calls[2][1] == http.calls[3][1]
    assert "PublisherIdentifier=" in http.calls[3][1]
    assert list(read_timeline(result["bundle"]))[0]["original_timestamp"] == OLD
    assert result["collection"]["included_records"] == 1
    assert "contentCreated" in result["collection"]["window_basis"]
    assert len(result["collection"]["pages"]) == 4


@pytest.mark.parametrize(
    "uri",
    [
        "https://evil.test/audit/1",
        f"https://manage.office.com/api/v1.0/{GUID}/activity/feed/audit/../subscriptions/start",
        f"https://manage.office.com/api/v1.0/{GUID}/activity/feed/audit/%2e%2e/x",
    ],
)
def test_m365_content_origin_and_path_enforced(uri):
    provider = M365(
        config("m365_audit", tenant_id=GUID, content_type="Audit.Exchange"),
        FakeHttp([], "https://manage.office.com"),
    )
    with pytest.raises(ValueError):
        provider._content_path(uri)


def test_m365_requires_enabled_subscription():
    provider = M365(config("m365_audit", tenant_id=GUID, content_type="Audit.Exchange"), FakeHttp([[]]))
    with pytest.raises(ValueError, match="subscription"):
        provider.fetch(START, END, None)


def test_graph_and_okta_next_link_constraints():
    http = FakeHttp(
        [([], {"link": '<https://tenant.okta.com/api/v1/logs?after=opaque>; rel="next"'}), []],
        "https://tenant.okta.com",
    )
    provider = Okta(config("okta"), http)
    first = provider.fetch(START, END, None)
    assert parse_qs(urlsplit(http.calls[0][1]).query)["until"] == [END]
    assert provider.fetch(START, END, first.cursor).cursor is None
    for source, base in [
        ("entra_audit", "/v1.0/auditLogs/directoryAudits"),
        ("defender_alert", "/v1.0/security/alerts_v2"),
    ]:
        http = FakeHttp([{"value": [], "@odata.nextLink": "https://evil.test" + base}])
        with pytest.raises(ValueError, match="origin"):
            GraphAudit(config(source), http).fetch(START, END, None)


class SDK:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def __getattr__(self, name):
        def call(**kwargs):
            from botocore.session import get_session
            from botocore.validate import validate_parameters

            service = {
                "list_findings": "guardduty",
                "get_findings": "guardduty" if "DetectorId" in kwargs else "securityhub",
                "filter_log_events": "logs",
            }[name]
            operation_name = "".join(part.title() for part in name.split("_"))
            model = get_session().get_service_model(service).operation_model(operation_name)
            validate_parameters(kwargs, model.input_shape)
            self.calls.append((name, kwargs))
            operation, response = self.responses.pop(0)
            assert operation == name
            return copy.deepcopy(response)

        return call


def test_guardduty_sdk_wire_names_and_resumed_detail_fetch(tmp_path):
    sdk = SDK(
        [
            ("list_findings", {"FindingIds": ["finding-1"], "NextToken": "two"}),
            (
                "get_findings",
                {
                    "Findings": [
                        {
                            "Id": "finding-1",
                            "UpdatedAt": START,
                            "Type": "Synthetic",
                            "Resource": {"InstanceDetails": {"InstanceId": "i-example"}},
                            "Severity": 7,
                        }
                    ]
                },
            ),
            ("list_findings", {"FindingIds": []}),
        ]
    )
    provider = GuardDuty(config("guardduty", region="us-east-1", detector_id="a" * 32), sdk)
    with pytest.raises(ValueError, match="page budget"):
        collect(provider, tmp_path, max_pages=1)
    result = collect(provider, tmp_path)
    row = list(read_timeline(result["bundle"]))[0]
    assert row["asset_name"] == "i-example" and row["severity"] == "high"
    assert sdk.calls[1][1]["FindingIds"] == ["finding-1"]
    assert sdk.calls[2][1]["NextToken"] == "two"
    assert "updatedAt" in sdk.calls[0][1]["FindingCriteria"]["Criterion"]


def test_securityhub_asff_and_cloudwatch_envelope_clock(tmp_path):
    sdk = SDK([("get_findings", {"Findings": [SAMPLES["securityhub"]]})])
    result = collect(SecurityHub(config("securityhub", region="us-east-1"), sdk), tmp_path / "hub")
    assert list(read_timeline(result["bundle"]))[0]["ocsf_class_uid"] == 2004
    native = {**SAMPLES["cloudtrail"], "eventTime": OLD}
    sdk = SDK(
        [
            ("filter_log_events", {"events": [], "nextToken": "two"}),
            (
                "filter_log_events",
                {"events": [{"timestamp": 1788256800000, "message": compact_json(native)}]},
            ),
        ]
    )
    provider = CloudWatch(
        config("cloudwatch_logs", region="us-east-1", log_group="/test", parser="cloudtrail", format="json"),
        sdk,
    )
    result = collect(provider, tmp_path / "cw")
    assert list(read_timeline(result["bundle"]))[0]["original_timestamp"] == OLD
    assert sdk.calls[1][1]["nextToken"] == "two"


def test_falcon_query_details_and_changed_total(tmp_path):
    alert = SAMPLES["crowdstrike_alert"]
    query = {
        "resources": [alert["composite_id"]],
        "meta": {"pagination": {"offset": 0, "total": 1}},
        "errors": [],
    }
    provider = Falcon(config("crowdstrike_alert"), FakeHttp([query, {"resources": [alert], "errors": []}]))
    result = collect(provider, tmp_path)
    assert list(read_timeline(result["bundle"]))[0]["severity"] == "high"
    assert provider.http.calls[1][2]["body"]["composite_ids"] == [alert["composite_id"]]
    provider.http = FakeHttp([query])
    with pytest.raises(ValueError, match="count"):
        provider.fetch(START, END, {"offset": 1, "total": 2})
    provider.http = FakeHttp([{"resources": [], "errors": []}])
    with pytest.raises(ValueError, match="every"):
        provider.fetch(START, END, {"ids": ["missing"], "offset": 1, "total": 1})


def test_splunk_async_resume_and_v2_results(tmp_path):
    native = {**SAMPLES["windows_event"], "TimeCreated": OLD}
    values = [
        {"sid": "search-1"},
        status(isDone=False, dispatchState="RUNNING"),
        status(),
        {
            "preview": False,
            "init_offset": 0,
            "messages": [],
            "results": [{"_time": START, "_raw": compact_json(native)}],
        },
    ]
    http = FakeHttp(values, "https://splunk.example.test:8089")
    provider = Splunk(
        config("splunk", index="windows", sourcetype="windows:json", parser="windows_event", format="json"),
        http,
    )
    with pytest.raises(ValueError, match="page budget"):
        collect(provider, tmp_path, max_pages=1)
    result = collect(provider, tmp_path)
    assert len([c for c in http.calls if c[0] == "POST"]) == 1
    assert http.calls[0][2]["form"]["allow_partial_results"] == "false"
    assert http.calls[-1][1].startswith("/services/search/v2/jobs/search-1/results?")
    assert list(read_timeline(result["bundle"]))[0]["original_timestamp"] == OLD


@pytest.mark.parametrize(
    "fault",
    [
        {"isFinalized": True},
        {"eventIsTruncated": True},
        {"dropCount": 1},
        {"eventCount": 2},
        {"isFailed": True},
    ],
)
def test_splunk_incomplete_search_never_publishes(fault, tmp_path):
    provider = Splunk(
        config("splunk", index="windows", sourcetype="windows:json", parser="windows_event", format="json"),
        FakeHttp([{"sid": "search-1"}, status(**fault)]),
    )
    with pytest.raises(ValueError):
        collect(provider, tmp_path)
    assert not (tmp_path / "bundle").exists()


def test_kql_caps_partial_errors_and_column_integrity(monkeypatch, tmp_path):
    monkeypatch.setattr("timeline_demo.collection.enterprise.QUERY_LIMIT", 1)
    with pytest.raises(ValueError, match="row cap"):
        collect(adapters()[6], tmp_path / "hunting")
    provider = adapters()[7]
    with pytest.raises(ValueError, match="row cap"):
        collect(provider, tmp_path / "logs")
    provider.http = FakeHttp([{"error": {"code": "PartialError"}, "tables": []}])
    with pytest.raises(ValueError, match="partial"):
        provider.fetch(START, END, None)
    monkeypatch.setattr("timeline_demo.collection.enterprise.QUERY_LIMIT", 100000)
    response = table_response({"TimeGenerated": START})
    response["tables"][0]["rows"] = [[START, "extra"]]
    provider.http = FakeHttp([response])
    with pytest.raises(ValueError, match="columns"):
        provider.fetch(START, END, None)


def test_workspace_nested_events_and_enterprise_ocsf():
    raw = copy.deepcopy(SAMPLES["google_workspace"])
    raw["events"].append({"name": "login_failure", "type": "login"})
    events = normalize_record(raw, "google_workspace", "raw", "a" * 64, 1)
    assert len(events) == 2 and events[0]["event_uuid"] != events[1]["event_uuid"]
    assert events[0]["raw_data_hash"] == events[1]["raw_data_hash"]
    for name in ("defender_hunting", "azure_log_analytics", "google_workspace", "crowdstrike_alert"):
        raw = SAMPLES[name]
        event = normalize_record(raw, name, "raw", "a" * 64, 1)[0]
        assert map_event(event, raw)["class_uid"] == event["ocsf_class_uid"]


@pytest.mark.parametrize(
    "source,extra",
    [
        ("defender_hunting", {"table": "DeviceEvents | invoke something"}),
        ("azure_log_analytics", {"table": "SecurityEvent; drop", "workspace_id": GUID}),
        ("m365_audit", {"tenant_id": "../../other", "content_type": "Audit.Exchange"}),
        ("google_workspace", {"application": "unknown"}),
        (
            "splunk",
            {"index": 'x" | outputlookup bad', "sourcetype": "a", "parser": "syslog", "format": "text"},
        ),
        (
            "cloudwatch_logs",
            {"region": "us-east-1", "log_group": "test", "parser": "unknown", "format": "json"},
        ),
        ("entra_audit", {"token": "must-never-be-accepted"}),
        ("defender_alert", {"host": "https://wrong.test"}),
    ],
)
def test_config_rejects_unbounded_queries_and_inline_secrets(source, extra):
    with pytest.raises(ValueError):
        make_enterprise_provider(config(source, **extra))


def test_all_example_configs_construct_without_reading_credentials(monkeypatch):
    monkeypatch.setattr(AWS, "__init__", lambda self, config, client=None: None)
    sources = set()
    for path in (ROOT / "examples/collectors").glob("*.json"):
        value = json.loads(path.read_text())
        if value["source"] in {"cloudtrail", "entra_signin", "databricks_audit", "tines_audit"}:
            continue
        sources.add(value["source"])
        make_provider(value)
    assert sources == SOURCES


def test_http_arrays_form_creation_and_pagination_header_allowlist():
    class Response:
        status_code = 201
        headers = {"Link": '<https://example.test/next>; rel="next"', "Set-Cookie": "secret"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def iter_content(self, size):
            yield b'[{"id":1}]'

    class Session:
        def request(self, method, url, **kwargs):
            assert kwargs["data"] == {"search": "bounded"}
            assert kwargs["allow_redirects"] is False
            assert url.startswith("https://example.test:8089/")
            return Response()

    http = Http("https://example.test:8089", lambda: {}, session=Session(), ports=(443, 8089))
    raw, value, headers = http.request(
        "POST", "/services/search/jobs", form={"search": "bounded"}, statuses=(201,), array=True, headers=True
    )
    assert value == [{"id": 1}] and "set-cookie" not in headers


def test_m365_native_utc_and_guardduty_remote_ip():
    raw = {**SAMPLES["m365_audit"], "CreationTime": "2026-09-01T10:00:00"}
    event = normalize_record(raw, "m365_audit", "raw", "a" * 64, 1)[0]
    assert event["epoch_ms"] == 1788256800000 and event["timezone_assumption"] == "UTC"
    assert event["original_timestamp"] == raw["CreationTime"] and event["parser_version"] == "2.1.0"
    raw = {
        **SAMPLES["guardduty"],
        "service": {
            "action": {"networkConnectionAction": {"remoteIpDetails": {"ipAddressV4": "198.51.100.9"}}}
        },
    }
    assert normalize_record(raw, "guardduty", "raw", "a" * 64, 1)[0]["src_ip"] == "198.51.100.9"


@pytest.mark.parametrize(
    "table",
    [
        "SigninLogs",
        "AADNonInteractiveUserSignInLogs",
        "AADServicePrincipalSignInLogs",
        "AADManagedIdentitySignInLogs",
    ],
)
def test_log_analytics_workload_identity_tables(table, tmp_path):
    raw = {
        "TimeGenerated": START,
        "OperationName": "Sign-in activity",
        "Id": "signin-1",
        "ServicePrincipalName": "example-app",
        "ResourceDisplayName": "example-resource",
        "IPAddress": "198.51.100.1",
        "ResultType": "Success",
    }
    provider = LogAnalytics(
        config("azure_log_analytics", workspace_id=GUID, table=table), FakeHttp([table_response(raw)])
    )
    result = collect(provider, tmp_path)
    event = list(read_timeline(result["bundle"]))[0]
    assert event["user_name"] == "example-app" and event["ocsf_class_uid"] == 3002
    assert map_event(event, {"table": table, "record": raw})["service"]["name"] == "example-resource"


@pytest.mark.parametrize(
    "table",
    [
        "EmailEvents",
        "EmailUrlInfo",
        "EmailAttachmentInfo",
        "UrlClickEvents",
        "DeviceRegistryEvents",
        "DeviceEvents",
    ],
)
def test_hunting_preserves_unmapped_telemetry(table):
    raw = {
        "table": table,
        "record": {"Timestamp": START, "ReportId": "r1", "AdditionalFields": {"unexpected": "retained"}},
    }
    event = normalize_record(raw, "defender_hunting", "raw", "a" * 64, 1)[0]
    assert event["activity_name"] == table and event["ocsf_class_uid"] == 0
    assert event["metadata"]["ocsf_mapping_status"] == "unmapped"
    with pytest.raises(ValueError, match="unsupported OCSF class"):
        map_event(event, raw)


@pytest.mark.parametrize(
    "table,row",
    [
        (
            "DeviceNetworkEvents",
            {
                "LocalIP": "192.0.2.1",
                "RemoteIP": "198.51.100.2",
                "LocalPort": 1234,
                "RemotePort": 443,
                "ActionType": "ConnectionSuccess",
            },
        ),
        (
            "CommonSecurityLog",
            {
                "SourceIP": "192.0.2.1",
                "DestinationIP": "198.51.100.2",
                "SourcePort": 1234,
                "DestinationPort": 443,
                "DeviceEventClassID": "allowed",
            },
        ),
    ],
)
def test_network_endpoints_keep_source_and_destination(table, row):
    parser = "defender_hunting" if table == "DeviceNetworkEvents" else "azure_log_analytics"
    raw = {"table": table, "record": {"Timestamp": START, "TimeGenerated": START, **row}}
    event = normalize_record(raw, parser, "raw", "a" * 64, 1)[0]
    mapped = map_event(event, raw)
    assert mapped["src_endpoint"] == {"ip": "192.0.2.1", "port": 1234}
    assert mapped["dst_endpoint"] == {"ip": "198.51.100.2", "port": 443}


def test_cloudwatch_excludes_envelope_end_boundary_with_receipt(tmp_path):
    source = config(
        "cloudwatch_logs", parser="vpc_flow", format="text", log_group="/test", region="us-east-1"
    )
    message = "2 123456789012 eni-1 192.0.2.1 198.51.100.1 1234 443 6 1 100 1788256800 1788256801 ACCEPT OK"
    sdk = SDK(
        [
            (
                "filter_log_events",
                {
                    "events": [
                        {"timestamp": 1788260400000, "message": message},
                        {"timestamp": 1788256800000, "message": message},
                    ]
                },
            )
        ]
    )
    result = collect(CloudWatch(source, sdk), tmp_path)
    assert result["collection"]["received_records"] == 2
    assert result["collection"]["excluded_outside_window"] == 1
    assert result["collection"]["included_records"] == 1


def test_bad_okta_header_cannot_silently_end_paging():
    provider = Okta(
        config("okta"),
        FakeHttp([([], {"link": '<https://graph.microsoft.com/api/v1/logs>; rel="self", corrupt-next'})]),
    )
    with pytest.raises(ValueError, match="header"):
        provider.fetch(START, END, None)


def test_m365_documented_v1_continuation_alias():
    provider = M365(
        config("m365_audit", tenant_id=GUID, content_type="Audit.Exchange"),
        FakeHttp([], "https://manage.office.com"),
    )
    link = f"https://manage.office.com/api/v1/{GUID}/activity/feed/subscriptions/content?nextPage=x"
    assert provider._list_path(link).startswith("/api/v1/")
    provider.http = FakeHttp([([], {"nextpageuri": ""})], "https://manage.office.com")
    with pytest.raises(ValueError, match="continuation"):
        provider.fetch(START, END, {"phase": "list"})


def test_json_null_is_rejected_instead_of_skipped_as_a_text_header(tmp_path):
    from timeline_demo.parsers.readers import iter_records

    path = tmp_path / "records.jsonl"
    path.write_text("null\n" + compact_json(SAMPLES["cloudtrail"]) + "\n")
    rows = list(iter_records(path, "cloudtrail"))
    assert len(rows) == 2 and rows[0][2] == "record must be an object"


def test_historical_ocsf_mapping_still_verifies_and_versions_must_agree(monkeypatch, tmp_path):
    import timeline_demo.ocsf as ocsf
    from timeline_demo.parsers.common import file_hash

    source = ROOT / "examples/demo_bundle"
    with monkeypatch.context() as patch:
        patch.setattr(ocsf, "MAPPING_VERSION", "ocsf-export-1.0.0")
        historical = ocsf.export_bundle(source, tmp_path / "export")
    assert ocsf.verify_export(tmp_path / "export", bundle=source) == historical
    path = tmp_path / "export/ocsf.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[0]["unmapped"]["timeline_export"]["mapping_version"] = "ocsf-export-1.1.0"
    path.write_text("".join(compact_json(row) + "\n" for row in rows))
    historical["files"]["ocsf.jsonl"] = {"sha256": file_hash(path), "bytes": path.stat().st_size}
    (tmp_path / "export/export_manifest.json").write_text(compact_json(historical) + "\n")
    with pytest.raises(ValueError, match="mapping version"):
        ocsf.verify_export(tmp_path / "export", bundle=source)
