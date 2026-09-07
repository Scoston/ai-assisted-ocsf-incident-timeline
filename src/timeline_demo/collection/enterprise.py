"""Read-only enterprise API contracts; every request is one durable runner page.

No arbitrary SQL/KQL/SPL, automatic tenant discovery, subscription creation or
response actions. Query clocks may differ from the source event's timeline clock.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from functools import lru_cache
from urllib.parse import urlencode, urlsplit, parse_qsl

from timeline_demo.parsers.common import compact_json, parse_time
from timeline_demo.parsers.readers import _strict_json, decode_line, MAX_RECORD_BYTES
from timeline_demo.parsers.registry import SPECS, field
from timeline_demo.parsers.enterprise import HUNTING_TABLES, LOG_TABLES, WORKSPACE_APPS

from .providers import Http, Page, _next_path, _records, origin

SOURCES = frozenset(
    {
        "entra_audit",
        "m365_audit",
        "defender_alert",
        "defender_hunting",
        "okta",
        "azure_activity",
        "azure_log_analytics",
        "gcp_audit",
        "google_workspace",
        "guardduty",
        "securityhub",
        "cloudwatch_logs",
        "crowdstrike_alert",
        "splunk",
    }
)
CONTENT_TYPES = frozenset(
    {
        "Audit.AzureActiveDirectory",
        "Audit.Exchange",
        "Audit.SharePoint",
        "Audit.General",
        "DLP.All",
    }
)
GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
QUERY_LIMIT = 100000


def token(value, key):
    result = value.get(key)
    if result is not None and (not isinstance(result, str) or not result):
        raise ValueError("invalid continuation token")
    return {"token": result} if result else None


def records(value):
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise ValueError("expected an array of source objects")
    return value


def api_errors(value):
    if value.get("error") or value.get("errors"):
        raise ValueError("source reported an error or partial result; checkpoint unchanged")


def in_window(value, start, end, unit=None):
    return parse_time(start)[1] <= parse_time(value, unit)[1] < parse_time(end)[1]


class Enterprise:
    interval = 1.0
    window_field = None
    retain_selected = False

    def __init__(self, config, http=None):
        self.config, self.http = config, http
        self.identity = {"collector_version": "1.0.0", **config}
        self.parser = config.get("parser", config["source"])
        self.window_basis = self.window_field or SPECS[self.parser].time

    def includes(self, record, start_ms, end_ms):
        if self.retain_selected:
            return True  # Selection was validated against the API envelope/feed metadata.
        spec = SPECS[self.parser]
        return start_ms <= parse_time(field(record, self.window_field or spec.time), spec.unit)[1] < end_ms


class GraphAudit(Enterprise):
    def __init__(self, config, http):
        super().__init__(config, http)
        if self.parser == "entra_audit":
            self.base, self.window_field = "/v1.0/auditLogs/directoryAudits", "activityDateTime"
        else:
            self.base, self.window_field = "/v1.0/security/alerts_v2", "lastUpdateDateTime"
        self.window_basis = self.window_field

    def fetch(self, start, end, cursor):
        params = {"$filter": f"{self.window_field} ge {start} and {self.window_field} le {end}", "$top": 100}
        path = cursor["path"] if cursor else self.base + "?" + urlencode(params)
        _next_path(self.http.host + path, self.http.host, self.base)
        raw, value = self.http.request("GET", path)
        api_errors(value)
        link = token(value, "@odata.nextLink")
        return Page(
            raw,
            _records(value, "value"),
            {"path": _next_path(link["token"], self.http.host, self.base)} if link else None,
        )


class AzureActivity(Enterprise):
    def fetch(self, start, end, cursor):
        base = f"/subscriptions/{self.config['subscription_id']}/providers/microsoft.insights/eventtypes/management/values"
        params = {
            "api-version": "2015-04-01",
            "$filter": f"eventTimestamp ge '{start}' and eventTimestamp le '{end}'",
        }
        path = cursor["path"] if cursor else base + "?" + urlencode(params)
        _next_path(self.http.host + path, self.http.host, base)
        raw, value = self.http.request("GET", path)
        api_errors(value)
        link = token(value, "nextLink")
        return Page(
            raw,
            _records(value, "value"),
            {"path": _next_path(link["token"], self.http.host, base)} if link else None,
        )


class Okta(Enterprise):
    def fetch(self, start, end, cursor):
        base = "/api/v1/logs"
        path = (
            cursor["path"]
            if cursor
            else base
            + "?"
            + urlencode(
                {
                    "since": start,
                    "until": end,
                    "sortOrder": "ASCENDING",
                    "limit": 1000,
                }
            )
        )
        _next_path(self.http.host + path, self.http.host, base)
        raw, value, headers = self.http.request("GET", path, array=True, headers=True)
        # RFC 8288 Link fields; a bounded query ends when rel=next is absent.
        links = []
        for part in re.split(r",\s*(?=<)", headers.get("link", "")):
            if not part:
                continue
            match = re.fullmatch(r'\s*<([^>]+)>\s*;\s*rel="([^"]+)"\s*', part)
            if not match:
                raise ValueError("malformed Okta pagination header")
            links.append(match.groups())
        next_links = [url for url, rel in links if "next" in rel.split()]
        if len(next_links) > 1:
            raise ValueError("ambiguous Okta next link")
        next_cursor = {"path": _next_path(next_links[0], self.http.host, base)} if next_links else None
        return Page(raw, records(value), next_cursor)


class M365(Enterprise):
    retain_selected = True
    window_field = "contentCreated (feed availability; event CreationTime retained)"

    def __init__(self, config, http):
        super().__init__(config, http)
        self.base = f"/api/v1.0/{config['tenant_id']}/activity/feed"

    def _publisher(self, path):
        if "publisher_id" in self.config:
            parsed = urlsplit(path)
            params = [(k, v) for k, v in parse_qsl(parsed.query) if k.lower() != "publisheridentifier"]
            params.append(("PublisherIdentifier", self.config["publisher_id"]))
            path = parsed.path + "?" + urlencode(params)
        return path

    def _content_path(self, link):
        if not isinstance(link, str):
            raise ValueError("invalid M365 content URI")
        parts = urlsplit(link)
        prefix = self.base + "/audit/"
        if (
            not parts.path.startswith(prefix)
            or not re.fullmatch(r"[A-Za-z0-9_$.-]+", parts.path[len(prefix) :])
            or parts.path[len(prefix) :] in {".", ".."}
        ):
            raise ValueError("M365 content URI leaves the tenant audit path")
        return self._publisher(_next_path(link, self.http.host, parts.path))

    def _list_path(self, link):
        expected = self.base + "/subscriptions/content"
        # Microsoft's continuation example uses the v1 alias of v1.0.
        path = urlsplit(link).path
        if path not in {expected, expected.replace("/api/v1.0/", "/api/v1/")}:
            raise ValueError("M365 next link leaves the tenant subscription path")
        return _next_path(link, self.http.host, path)

    def fetch(self, start, end, cursor):
        content_type = self.config["content_type"]
        if cursor is None:
            raw, value = self.http.request(
                "GET", self._publisher(self.base + "/subscriptions/list"), array=True
            )
            if not any(
                x.get("contentType") == content_type and x.get("status") == "enabled" for x in records(value)
            ):
                raise ValueError("M365 content subscription is not enabled; configure it before collecting")
            return Page(raw, [], {"phase": "list"})
        if cursor["phase"] == "content":
            paths = cursor["paths"]
            path = self._content_path(self.http.host + paths[0])
            raw, value = self.http.request("GET", path, array=True)
            remaining = paths[1:]
            next_cursor = (
                {**cursor, "paths": remaining}
                if remaining
                else ({"phase": "list", "path": cursor["next"]} if cursor.get("next") else None)
            )
            return Page(raw, records(value), next_cursor)
        base = self.base + "/subscriptions/content"
        # This API specifies UTC dates without offsets; no fractional precision.
        params = {"contentType": content_type, "startTime": start[:19], "endTime": end[:19]}
        if parse_time(start)[1] % 1000 or parse_time(end)[1] % 1000:
            raise ValueError("M365 feed windows require whole-second boundaries")
        path = cursor.get("path", base + "?" + urlencode(params))
        self._list_path(self.http.host + path)
        raw, value, headers = self.http.request("GET", self._publisher(path), array=True, headers=True)
        paths = []
        for item in records(value):
            if item.get("contentType") != content_type or not in_window(
                item.get("contentCreated"), start, end
            ):
                raise ValueError("M365 returned content outside the requested feed scope")
            paths.append(self._content_path(item.get("contentUri")))
        link = headers.get("nextpageuri")
        if "nextpageuri" in headers and (not isinstance(link, str) or not link):
            raise ValueError("invalid M365 continuation header")
        next_path = self._list_path(link) if link else None
        next_cursor = (
            {"phase": "content", "paths": paths, "next": next_path}
            if paths
            else ({"phase": "list", "path": next_path} if next_path else None)
        )
        return Page(raw, [], next_cursor)


class GCP(Enterprise):
    def fetch(self, start, end, cursor):
        project = self.config["project_id"]
        body = {
            "resourceNames": ["projects/" + project],
            "filter": f'logName:"cloudaudit.googleapis.com" AND timestamp >= "{start}" AND timestamp < "{end}"',
            "orderBy": "timestamp asc",
            "pageSize": 1000,
        }
        if cursor:
            body["pageToken"] = cursor["token"]
        raw, value = self.http.request("POST", "/v2/entries:list", body=body)
        api_errors(value)
        # Protobuf JSON omits empty arrays. An empty page with a token is NOT terminal.
        return Page(raw, records(value.get("entries", [])), token(value, "nextPageToken"))


class Workspace(Enterprise):
    def fetch(self, start, end, cursor):
        base = "/admin/reports/v1/activity/users/all/applications/" + self.config["application"]
        params = {"startTime": start, "endTime": end, "maxResults": 1000}
        if cursor:
            params["pageToken"] = cursor["token"]
        raw, value = self.http.request("GET", base + "?" + urlencode(params))
        api_errors(value)
        if value.get("kind") != "admin#reports#activities":
            raise ValueError("unexpected Google Workspace response kind")
        rows = records(value.get("items", []))
        if any(field(row, "id.applicationName") != self.config["application"] for row in rows):
            raise ValueError("Workspace response application does not match configuration")
        return Page(raw, rows, token(value, "nextPageToken"))


class Hunting(Enterprise):
    def fetch(self, start, end, cursor):
        if cursor:
            raise ValueError("hunting queries do not support continuation")
        table = self.config["table"]
        query = f"{table} | where Timestamp >= datetime({start}) and Timestamp < datetime({end}) | take {QUERY_LIMIT}"
        raw, value = self.http.request("POST", "/api/advancedhunting/run", body={"Query": query})
        api_errors(value)
        rows = _records(value, "Results")
        if len(rows) >= QUERY_LIMIT:
            raise ValueError("hunting result reached the row cap; narrow the window")
        schema = _records(value, "Schema")
        if not any(x.get("Name") == "Timestamp" and x.get("Type", "").lower() == "datetime" for x in schema):
            raise ValueError("hunting response lacks its timestamp schema")
        return Page(raw, [{"table": table, "record": row} for row in rows], None)


class LogAnalytics(Enterprise):
    def fetch(self, start, end, cursor):
        if cursor:
            raise ValueError("Log Analytics queries do not support continuation")
        table = self.config["table"]
        query = f"{table} | where TimeGenerated >= datetime({start}) and TimeGenerated < datetime({end}) | take {QUERY_LIMIT}"
        path = f"/v1/workspaces/{self.config['workspace_id']}/query"
        raw, value = self.http.request("POST", path, body={"query": query, "timespan": start + "/" + end})
        api_errors(value)  # Azure can return HTTP 200 with an error and partial tables.
        tables = _records(value, "tables")
        if len(tables) != 1 or tables[0].get("name") != "PrimaryResult":
            raise ValueError("Log Analytics returned an unexpected result table")
        result = tables[0]
        columns = _records(result, "columns")
        names = [x.get("name") for x in columns]
        if (
            any(not isinstance(x, str) or not x for x in names)
            or len(set(names)) != len(names)
            or "TimeGenerated" not in names
        ):
            raise ValueError("Log Analytics columns are missing or ambiguous")
        rows = result.get("rows")
        if not isinstance(rows, list) or len(rows) >= QUERY_LIMIT:
            raise ValueError("Log Analytics result missing or at row cap; narrow the window")
        projected = []
        for row in rows:
            if not isinstance(row, list) or len(row) != len(names):
                raise ValueError("Log Analytics row does not match its columns")
            item = dict(zip(names, row))
            for column in columns:
                key = column["name"]
                if column.get("type") == "dynamic" and isinstance(item[key], str) and item[key]:
                    item[key] = _strict_json(item[key])
            projected.append({"table": table, "record": item})
        return Page(raw, projected, None)


def decode_message(message, parser, fmt):
    if not isinstance(message, str) or len(message.encode()) > MAX_RECORD_BYTES:
        raise ValueError("central log message is missing or exceeds 4 MiB")
    value = _strict_json(message) if fmt == "json" else decode_line(message, parser)
    if not isinstance(value, dict):
        raise ValueError("central log message must decode to exactly one source object")
    return value


class AWS(Enterprise):
    def __init__(self, config, client=None):
        super().__init__(config)
        if client is None:
            import boto3
            from botocore.config import Config

            client = boto3.Session(profile_name=config.get("profile")).client(
                "logs" if config["source"] == "cloudwatch_logs" else config["source"],
                region_name=config["region"],
                config=Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30),
            )
        self.client = client

    def call(self, operation, **params):
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            value = getattr(self.client, operation)(**params)
        except (BotoCoreError, ClientError):
            raise ValueError("AWS collection request failed; checkpoint unchanged") from None

        def serializable(item):
            if isinstance(item, datetime):
                return item.isoformat()
            if isinstance(item, dict):
                return {k: serializable(v) for k, v in item.items()}
            if isinstance(item, list):
                return [serializable(v) for v in item]
            return item

        api_errors(value)
        return compact_json(serializable(value)).encode(), value


class GuardDuty(AWS):
    def fetch(self, start, end, cursor):
        detector = self.config["detector_id"]
        if cursor and "ids" in cursor:
            raw, value = self.call("get_findings", DetectorId=detector, FindingIds=cursor["ids"])
            rows = _records(value, "Findings")
            if len(rows) != len(cursor["ids"]) or {x.get("Id") for x in rows} != set(cursor["ids"]):
                raise ValueError("GuardDuty did not return every requested finding")
            # boto3 returns PascalCase, unlike GuardDuty's HTTP/export contract.
            rows = [_guardduty_record(row) for row in rows]
            return Page(raw, rows, {"token": cursor["next"]} if cursor.get("next") else None)
        params = {
            "DetectorId": detector,
            "MaxResults": 50,
            "FindingCriteria": {
                "Criterion": {"updatedAt": {"Gte": parse_time(start)[1], "Lt": parse_time(end)[1]}}
            },
            "SortCriteria": {"AttributeName": "updatedAt", "OrderBy": "ASC"},
        }
        if cursor:
            params["NextToken"] = cursor["token"]
        raw, value = self.call("list_findings", **params)
        ids = value.get("FindingIds")
        if (
            not isinstance(ids, list)
            or any(not isinstance(x, str) or not x for x in ids)
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("GuardDuty returned invalid finding IDs")
        next_cursor = token(value, "NextToken")
        return Page(
            raw,
            [],
            {"ids": ids, "next": next_cursor["token"] if next_cursor else None} if ids else next_cursor,
        )


@lru_cache(maxsize=1)
def _guardduty_shape():
    from botocore.session import get_session

    return get_session().get_service_model("guardduty").shape_for("Finding")


def _guardduty_record(record):
    # Convert using botocore's wire serialization names, not a guessed case rule
    # (e.g. IpAddressV4 -> ipAddressV4, AccountId -> accountId).
    shape = _guardduty_shape()

    def wire(value, model):
        if model.type_name == "structure":
            if set(value) - set(model.members):
                raise ValueError("GuardDuty SDK model does not describe every captured field")
            return {
                model.members[k].serialization.get("name", k): wire(v, model.members[k])
                for k, v in value.items()
            }
        if model.type_name == "list":
            return [wire(v, model.member) for v in value]
        if model.type_name == "map":
            return {k: wire(v, model.value) for k, v in value.items()}
        return value

    return wire(record, shape)


class SecurityHub(AWS):
    def fetch(self, start, end, cursor):
        params = {
            "Filters": {"UpdatedAt": [{"Start": start, "End": end}]},
            "MaxResults": 100,
            "SortCriteria": [{"Field": "UpdatedAt", "SortOrder": "asc"}],
        }
        if cursor:
            params["NextToken"] = cursor["token"]
        raw, value = self.call("get_findings", **params)
        return Page(raw, _records(value, "Findings"), token(value, "NextToken"))


class CloudWatch(AWS):
    retain_selected = True
    window_field = "CloudWatch event timestamp (native message timestamp retained)"

    def fetch(self, start, end, cursor):
        params = {
            "logGroupName": self.config["log_group"],
            "startTime": parse_time(start)[1],
            "endTime": parse_time(end)[1],
            "limit": 1000,
        }
        if cursor:
            params["nextToken"] = cursor["token"]
        raw, value = self.call("filter_log_events", **params)
        rows, selected = [], []
        for item in _records(value, "events"):
            selected.append(in_window(item.get("timestamp"), start, end, "ms"))
            rows.append(decode_message(item.get("message"), self.parser, self.config["format"]))
        # Empty and partially filled pages can still have nextToken.
        return Page(raw, rows, token(value, "nextToken"), selection=selected)


class Falcon(Enterprise):
    window_field = "updated_timestamp"

    def fetch(self, start, end, cursor):
        if cursor and "ids" in cursor:
            raw, value = self.http.request(
                "POST",
                "/alerts/entities/alerts/v2?include_hidden=true",
                body={"composite_ids": cursor["ids"]},
            )
            api_errors(value)
            rows = _records(value, "resources")
            if len(rows) != len(cursor["ids"]) or {x.get("composite_id") for x in rows} != set(cursor["ids"]):
                raise ValueError("Falcon did not return every requested alert")
            next_cursor = (
                {"offset": cursor["offset"], "total": cursor["total"]}
                if cursor["offset"] < cursor["total"]
                else None
            )
            return Page(raw, rows, next_cursor)
        offset = cursor["offset"] if cursor else 0
        params = {
            "filter": f"updated_timestamp:>='{start}'+updated_timestamp:<'{end}'",
            "include_hidden": "true",
            "offset": offset,
            "limit": 100,
        }
        raw, value = self.http.request("GET", "/alerts/queries/alerts/v2?" + urlencode(params))
        api_errors(value)
        ids, pagination = value.get("resources"), field(value, "meta.pagination", {})
        total = pagination.get("total")
        if type(total) is not int or total < 0 or (cursor and total != cursor["total"]):
            raise ValueError("Falcon result count is missing or changed")
        if (
            not isinstance(ids, list)
            or any(not isinstance(x, str) or not x for x in ids)
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("invalid Falcon alert IDs")
        seen = offset + len(ids)
        if pagination.get("offset") != offset or seen > total or (not ids and seen != total):
            raise ValueError("Falcon offset paging ended early or returned an unexpected page")
        return Page(raw, [], {"ids": ids, "offset": seen, "total": total} if ids else None)


def _number(value):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError("invalid source result count")
    return int(value)


def _flag(value):
    if value in (True, 1, "1", "true"):
        return True
    if value in (False, 0, "0", "false"):
        return False
    raise ValueError("missing or invalid source status flag")


class Splunk(Enterprise):
    retain_selected = True
    window_field = "Splunk _time (native _raw timestamp retained)"

    def fetch(self, start, end, cursor):
        base = "/services/search/jobs"
        if cursor is None:
            query = f'search index="{self.config["index"]}" sourcetype="{self.config["sourcetype"]}" | fields _raw _time | sort 0 _time'
            form = {
                "search": query,
                "earliest_time": str(parse_time(start)[1] / 1000),
                "latest_time": str(parse_time(end)[1] / 1000),
                "exec_mode": "normal",
                "output_mode": "json",
                "allow_partial_results": "false",
                "enable_lookups": "false",
                "max_count": QUERY_LIMIT,
                "max_time": 300,
                "auto_cancel": 600,
            }
            raw, value = self.http.request("POST", base, form=form, statuses=(201,))
            sid = value.get("sid")
            if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", sid):
                raise ValueError("Splunk did not return a valid search ID")
            return Page(raw, [], {"sid": sid, "poll": 0})
        sid = cursor["sid"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", sid):
            raise ValueError("invalid checkpointed Splunk search ID")
        if "offset" not in cursor:
            raw, value = self.http.request("GET", base + "/" + sid + "?output_mode=json")
            entries = _records(value, "entry")
            if len(entries) != 1 or not isinstance(entries[0].get("content"), dict):
                raise ValueError("Splunk response lacks one search status")
            status = entries[0]["content"]
            if _flag(status.get("isFailed")) or _flag(status.get("isFinalized")):
                raise ValueError("Splunk search failed or was finalized early")
            if not _flag(status.get("isDone")):
                if (
                    status.get("dispatchState") not in {"QUEUED", "PARSING", "RUNNING", "FINALIZING"}
                    or cursor["poll"] >= 300
                ):
                    raise ValueError("Splunk search did not complete within its polling budget")
                return Page(raw, [], {"sid": sid, "poll": cursor["poll"] + 1})
            total = _number(status.get("resultCount"))
            if (
                status.get("dispatchState") != "DONE"
                or _flag(status.get("eventIsTruncated"))
                or _number(status.get("dropCount"))
            ):
                raise ValueError("Splunk search results are partial or truncated")
            if total >= QUERY_LIMIT or total != _number(status.get("eventCount")):
                raise ValueError("Splunk result count reached its cap or differs from event count")
            return Page(raw, [], {"sid": sid, "offset": 0, "total": total} if total else None)
        offset, total = cursor["offset"], cursor["total"]
        path = f"/services/search/v2/jobs/{sid}/results?" + urlencode(
            {"count": min(1000, total - offset), "offset": offset, "output_mode": "json"}
        )
        raw, value = self.http.request("GET", path)
        rows = _records(value, "results")
        if (
            _flag(value.get("preview"))
            or _number(value.get("init_offset")) != offset
            or not rows
            or offset + len(rows) > total
        ):
            raise ValueError("Splunk returned preview, missing, or inconsistent results")
        messages = records(value.get("messages", []))
        if any(x.get("type", "").upper() in {"WARN", "ERROR", "FATAL"} for x in messages):
            raise ValueError("Splunk result reports a warning or failure; inspect the source job")
        projected = []
        for row in rows:
            if not in_window(row.get("_time"), start, end, "s"):
                raise ValueError("Splunk returned an event outside the search window")
            projected.append(decode_message(row.get("_raw"), self.parser, self.config["format"]))
        seen = offset + len(rows)
        return Page(raw, projected, {"sid": sid, "offset": seen, "total": total} if seen < total else None)


def make_enterprise_provider(config):
    source = config["source"]
    common = {"source", "source_id"}
    special = {
        "entra_audit": set(),
        "defender_alert": set(),
        "okta": {"auth_scheme"},
        "m365_audit": {"tenant_id", "content_type", "publisher_id"},
        "azure_activity": {"subscription_id"},
        "azure_log_analytics": {"workspace_id", "table"},
        "defender_hunting": {"table"},
        "gcp_audit": {"project_id"},
        "google_workspace": {"application"},
        "guardduty": {"region", "profile", "detector_id"},
        "securityhub": {"region", "profile"},
        "cloudwatch_logs": {"region", "profile", "log_group", "parser", "format"},
        "crowdstrike_alert": set(),
        "splunk": {"index", "sourcetype", "parser", "format"},
    }
    aws = source in {"guardduty", "securityhub", "cloudwatch_logs"}
    allowed = common | special[source] | (set() if aws else {"host", "token_env"})
    if set(config) - allowed:
        raise ValueError("unknown collector configuration key; credentials belong in environment/SDK auth")

    def match(key, pattern):
        value = config.get(key)
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError("invalid or missing collector " + key)

    match("source_id", r"[A-Za-z0-9_.-]{1,100}")
    for key in ("tenant_id", "subscription_id", "workspace_id"):
        if key in special[source]:
            match(key, GUID)
    if "publisher_id" in config:
        match("publisher_id", GUID)
    if source == "m365_audit" and config.get("content_type") not in CONTENT_TYPES:
        raise ValueError("choose one supported M365 content_type per configuration")
    if source == "defender_hunting" and config.get("table") not in HUNTING_TABLES:
        raise ValueError("choose a supported Defender hunting table")
    if source == "azure_log_analytics" and config.get("table") not in LOG_TABLES:
        raise ValueError("choose a supported Log Analytics table")
    if source == "google_workspace" and config.get("application") not in WORKSPACE_APPS:
        raise ValueError("choose a supported Workspace application")
    if source == "gcp_audit":
        match("project_id", r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
    if source in {"cloudwatch_logs", "splunk"}:
        if config.get("parser") not in SPECS or config.get("format") not in {"json", "text"}:
            raise ValueError("central logs require an explicit parser and json/text format")
        if config["format"] == "text" and config["parser"] not in {"syslog", "vpc_flow"}:
            raise ValueError("text central logs support RFC 5424 syslog or default VPC flow only")
    if source == "splunk":
        match("index", r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}")
        match("sourcetype", r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}")
    if aws:
        match("region", r"[a-z0-9-]{3,40}")
        if "profile" in config:
            match("profile", r"[A-Za-z0-9_.@-]{1,128}")
        if source == "guardduty":
            match("detector_id", r"[0-9a-fA-F]{32}")
        if source == "cloudwatch_logs":
            match("log_group", r"[A-Za-z0-9_./#-]{1,512}")
        return {"guardduty": GuardDuty, "securityhub": SecurityHub, "cloudwatch_logs": CloudWatch}[source](
            config
        )
    fixed = {
        "entra_audit": ("https://graph.microsoft.com", "GRAPH_ACCESS_TOKEN", GraphAudit),
        "defender_alert": ("https://graph.microsoft.com", "GRAPH_ACCESS_TOKEN", GraphAudit),
        "m365_audit": ("https://manage.office.com", "M365_ACCESS_TOKEN", M365),
        "azure_activity": ("https://management.azure.com", "AZURE_ACCESS_TOKEN", AzureActivity),
        "azure_log_analytics": (
            "https://api.loganalytics.azure.com",
            "LOG_ANALYTICS_ACCESS_TOKEN",
            LogAnalytics,
        ),
        "defender_hunting": ("https://api.security.microsoft.com", "DEFENDER_ACCESS_TOKEN", Hunting),
        "gcp_audit": ("https://logging.googleapis.com", "GOOGLE_ACCESS_TOKEN", GCP),
        "google_workspace": ("https://admin.googleapis.com", "GOOGLE_WORKSPACE_ACCESS_TOKEN", Workspace),
    }
    if source in fixed:
        host, env, cls = fixed[source]
        if config.get("host", host) != host:
            raise ValueError("collector requires its documented global-cloud API host")
    else:
        if not isinstance(config.get("host"), str):
            raise ValueError("collector host is required")
        host = origin(config["host"], (443, 8089) if source == "splunk" else (443,))
        env, cls = {
            "okta": ("OKTA_ACCESS_TOKEN", Okta),
            "crowdstrike_alert": ("FALCON_ACCESS_TOKEN", Falcon),
            "splunk": ("SPLUNK_ACCESS_TOKEN", Splunk),
        }[source]
        if source == "crowdstrike_alert" and host not in {
            "https://api.crowdstrike.com",
            "https://api.us-2.crowdstrike.com",
            "https://api.eu-1.crowdstrike.com",
        }:
            raise ValueError("choose a documented commercial Falcon API region")
    env = config.get("token_env", env)
    if not isinstance(env, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,100}", env):
        raise ValueError("invalid token environment variable name")
    scheme = config.get("auth_scheme", "Bearer")
    if scheme not in {"Bearer", "SSWS"}:
        raise ValueError("Okta auth_scheme must be Bearer or SSWS")

    def headers():
        value = os.environ.get(env)
        if not value:
            raise ValueError("collector token environment variable is unset")
        return {"Authorization": scheme + " " + value}

    return cls(config, Http(host, headers, ports=(443, 8089) if source == "splunk" else (443,)))
