"""Narrow provider contracts. Credentials never enter collection identity or reports."""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlencode, urlsplit

from timeline_demo.parsers.common import compact_json
from timeline_demo.parsers.readers import _strict_json

MAX_PAGE_BYTES = 16 * 1024 * 1024


@dataclass
class Page:
    body: bytes
    records: list
    cursor: dict | None


def origin(host):
    parts = urlsplit(host)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
        or parts.port not in {None, 443}
    ):
        raise ValueError("collector host must be an HTTPS origin without credentials or a path")
    return host.rstrip("/")


class Http:
    def __init__(self, host, headers, *, session=None, sleep=time.sleep):
        if session is None:
            import requests

            session = requests.Session()
        self.host, self.headers, self.session, self.sleep = origin(host), headers, session, sleep

    def request(self, method, path, *, body=None):
        import requests

        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("collector request must use a local API path")
        for attempt in range(4):
            try:
                response = self.session.request(
                    method,
                    self.host + path,
                    headers=self.headers(),
                    json=body,
                    timeout=(10, 30),
                    allow_redirects=False,
                    stream=True,
                )
            except requests.RequestException:
                if method == "GET" and attempt < 3:
                    self.sleep(2**attempt)
                    continue
                raise ValueError("collector transport failed; no checkpoint was advanced") from None
            with response:
                retryable = response.status_code == 429 or (
                    method == "GET" and response.status_code in {502, 503, 504}
                )
                if retryable and attempt < 3:
                    delay = response.headers.get("Retry-After")
                    try:
                        delay = float(delay) if delay is not None else float(2**attempt)
                    except ValueError:
                        try:
                            delay = (
                                parsedate_to_datetime(delay) - datetime.now(timezone.utc)
                            ).total_seconds()
                        except (ValueError, TypeError):
                            raise ValueError("invalid Retry-After; retry the window later") from None
                    if not 0 <= delay <= 30:
                        raise ValueError("Retry-After exceeds this invocation's wait budget; retry later")
                    self.sleep(delay)
                    continue
                if response.status_code != 200:
                    raise ValueError(f"collector HTTP {response.status_code}; no checkpoint was advanced")
                data = bytearray()
                for part in response.iter_content(65536):
                    data.extend(part)
                    if len(data) > MAX_PAGE_BYTES:
                        raise ValueError("collector page exceeds 16 MiB; narrow the window")
                raw = bytes(data)
                value = _strict_json(raw)
                if not isinstance(value, dict):
                    raise ValueError("collector response must be a JSON object")
                return raw, value
        raise ValueError("collector retries exhausted")


def _next_path(url, host, expected):
    if not isinstance(url, str):
        raise ValueError("invalid pagination link")
    p = urlsplit(url)
    h = urlsplit(host)
    if p.scheme != h.scheme or p.netloc != h.netloc or p.path != expected or p.fragment or p.username:
        raise ValueError("pagination link leaves the configured origin or API path")
    return p.path + ("?" + p.query if p.query else "")


def _records(value, name):
    rows = value.get(name)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("collector response has no valid record array")
    return rows


class RestAudit:
    def __init__(self, config, http):
        self.identity = {"collector_version": "1.0.0", **config}
        self.parser = config["source"]
        self.http = http
        self.interval = 0.6

    def fetch(self, start, end, cursor):
        if self.parser == "entra_signin":
            base = "/v1.0/auditLogs/signIns"
            initial = (
                base
                + "?"
                + urlencode(
                    {"$filter": f"createdDateTime ge {start} and createdDateTime lt {end}", "$top": 1000}
                )
            )
        else:
            base = "/api/v1/audit_logs"
            # Tines 'after' is exclusive; fetch one extra second then filter locally.
            after = (datetime.fromisoformat(start) - timedelta(seconds=1)).isoformat()
            initial = base + "?" + urlencode({"after": after, "before": end, "per_page": 100, "page": 1})
        path = cursor["path"] if cursor else initial
        _next_path(self.http.host + path, self.http.host, base)
        raw, response = self.http.request("GET", path)
        if self.parser == "entra_signin":
            rows, link = _records(response, "value"), response.get("@odata.nextLink")
        else:
            rows = _records(response, "audit_logs")
            meta = response.get("meta")
            if not isinstance(meta, dict) or "next_page" not in meta:
                raise ValueError("Tines response lacks explicit pagination metadata")
            link = meta["next_page"]
            if not link and meta.get("next_page_number") is not None:
                raise ValueError("Tines pagination fields disagree")
            total = meta.get("count")
            if type(total) is not int or total < 0 or (cursor and total != cursor.get("total")):
                raise ValueError("Tines result count is missing or changed during pagination")
            seen = (cursor or {}).get("seen", 0) + len(rows)
            if (link is None and seen != total) or seen > total:
                raise ValueError("Tines paging ended before the reported record count")
        if link is not None and (not isinstance(link, str) or not link):
            raise ValueError("invalid collector continuation link")
        next_cursor = {"path": _next_path(link, self.http.host, base)} if link else None
        if next_cursor is not None and self.parser == "tines_audit":
            next_cursor.update(total=total, seen=seen)
        return Page(raw, rows, next_cursor)


class DatabricksAudit:
    parser = "databricks_audit"
    interval = 1.0

    def __init__(self, config, http):
        self.identity = {"collector_version": "1.0.0", **config}
        self.http = http
        self.warehouse = config["warehouse_id"]

    def fetch(self, start, end, cursor):
        base = "/api/2.0/sql/statements"
        if cursor is None:
            raw, response = self.http.request(
                "POST",
                base,
                body={
                    "warehouse_id": self.warehouse,
                    "statement": "SELECT to_json(struct(*), map('timeZone','UTC')) AS record_json FROM system.access.audit WHERE event_time >= CAST(:start AS TIMESTAMP) AND event_time < CAST(:end AS TIMESTAMP) ORDER BY event_time, request_id",
                    "parameters": [
                        {"name": "start", "value": start, "type": "STRING"},
                        {"name": "end", "value": end, "type": "STRING"},
                    ],
                    "format": "JSON_ARRAY",
                    "disposition": "INLINE",
                    "row_limit": 100000,
                    "byte_limit": 24 * 1024 * 1024,
                    "wait_timeout": "10s",
                    "on_wait_timeout": "CONTINUE",
                },
            )
        else:
            sid = cursor["statement_id"]
            if not re.fullmatch(r"[A-Za-z0-9-]{1,100}", sid):
                raise ValueError("invalid Databricks statement ID")
            path = base + "/" + sid
            if "chunk" in cursor:
                path += "/result/chunks/" + str(cursor["chunk"])
            raw, response = self.http.request("GET", path)
        if cursor is None or "chunk" not in cursor:
            sid = response.get("statement_id")
            if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,100}", sid):
                raise ValueError("Databricks response lacks a valid statement ID")
            if cursor and sid != cursor["statement_id"]:
                raise ValueError("Databricks statement identity changed")
            status = response.get("status", {}).get("state")
            if status in {"PENDING", "RUNNING"}:
                return Page(raw, [], {"statement_id": sid, "poll": (cursor or {}).get("poll", 0) + 1})
            if status != "SUCCEEDED":
                raise ValueError("Databricks statement did not succeed")
            manifest = response.get("manifest", {})
            if manifest.get("truncated") is not False:
                raise ValueError("Databricks result may be truncated; narrow the collection window")
            if [c.get("name") for c in manifest.get("schema", {}).get("columns", [])] != ["record_json"]:
                raise ValueError("Databricks result schema changed")
            total = manifest.get("total_row_count")
            chunk, seen, expected = response.get("result", {}), 0, 0
        else:
            sid, total, seen, expected = (
                cursor["statement_id"],
                cursor["total"],
                cursor["seen"],
                cursor["chunk"],
            )
            chunk = response
        if type(total) is not int or total < 0 or total > 100000:
            raise ValueError("invalid Databricks row count")
        values = chunk.get("data_array", [])
        if not isinstance(values, list) or any(
            not isinstance(row, list) or len(row) != 1 or not isinstance(row[0], str) for row in values
        ):
            raise ValueError("invalid Databricks result row")
        if values or total:
            if (
                chunk.get("row_offset") != seen
                or chunk.get("chunk_index") != expected
                or chunk.get("row_count") != len(values)
            ):
                raise ValueError("Databricks chunk sequence or row count mismatch")
        rows = [_strict_json(row[0]) for row in values]
        if any(not isinstance(row, dict) for row in rows):
            raise ValueError("Databricks audit record must be an object")
        seen += len(rows)
        next_index = chunk.get("next_chunk_index")
        if next_index is None:
            if seen != total:
                raise ValueError("Databricks result ended before all rows were collected")
            next_cursor = None
        else:
            if type(next_index) is not int or next_index != expected + 1 or seen >= total:
                raise ValueError("Databricks chunk continuation is invalid")
            next_cursor = {"statement_id": sid, "total": total, "seen": seen, "chunk": next_index}
        return Page(raw, rows, next_cursor)


class CloudTrail:
    parser = "cloudtrail"
    interval = 0.6

    def __init__(self, config, client=None):
        self.identity = {"collector_version": "1.0.0", **config}
        if client is None:
            import boto3
            from botocore.config import Config

            client = boto3.Session(profile_name=config.get("profile")).client(
                "cloudtrail",
                region_name=config["region"],
                config=Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30),
            )
        self.client = client

    def fetch(self, start, end, cursor):
        params = {
            "StartTime": datetime.fromisoformat(start),
            "EndTime": datetime.fromisoformat(end),
            "MaxResults": 50,
        }
        if cursor:
            params["NextToken"] = cursor["token"]
        # SDK retries are disabled. A throttled/failed lookup leaves the page checkpoint intact.
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            response = self.client.lookup_events(**params)
        except (BotoCoreError, ClientError):
            raise ValueError("CloudTrail lookup failed; retry this window with the same state") from None

        def serializable(value):
            if isinstance(value, datetime):
                return value.isoformat()
            if isinstance(value, dict):
                return {key: serializable(item) for key, item in value.items()}
            if isinstance(value, list):
                return [serializable(item) for item in value]
            return value

        raw = compact_json(serializable(response)).encode()
        rows = [_strict_json(row["CloudTrailEvent"]) for row in _records(response, "Events")]
        if any(not isinstance(row, dict) for row in rows):
            raise ValueError("CloudTrailEvent must encode an object")
        token = response.get("NextToken")
        if token is not None and (not isinstance(token, str) or not token):
            raise ValueError("invalid CloudTrail pagination token")
        return Page(raw, rows, {"token": token} if token else None)


def make_provider(config):
    if not isinstance(config, dict) or config.get("source") not in {
        "cloudtrail",
        "entra_signin",
        "tines_audit",
        "databricks_audit",
    }:
        raise ValueError("unsupported collector configuration")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", str(config.get("source_id", ""))):
        raise ValueError("collector source_id is required")
    allowed = {"source", "source_id", "host", "token_env", "region", "profile", "warehouse_id"}
    if set(config) - allowed:
        raise ValueError("unknown collector configuration key; use environment/SDK authentication")
    source = config["source"]
    if source in {"tines_audit", "databricks_audit"} and not isinstance(config.get("host"), str):
        raise ValueError("collector host is required")
    if source == "cloudtrail":
        if not re.fullmatch(r"[a-z0-9-]{3,40}", str(config.get("region", ""))):
            raise ValueError("CloudTrail region is required")
        return CloudTrail(config)
    if source == "databricks_audit":
        from databricks.sdk import WorkspaceClient

        if not re.fullmatch(r"[a-fA-F0-9]{1,64}", str(config.get("warehouse_id", ""))):
            raise ValueError("Databricks warehouse_id is required")
        client = WorkspaceClient(host=origin(config["host"]))
        return DatabricksAudit(config, Http(config["host"], client.config.authenticate))
    host = "https://graph.microsoft.com" if source == "entra_signin" else origin(config["host"])
    if source == "entra_signin" and config.get("host", host) != host:
        raise ValueError("this Entra collector supports graph.microsoft.com only")
    env = config.get("token_env", "GRAPH_ACCESS_TOKEN" if source == "entra_signin" else "TINES_API_TOKEN")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,100}", env):
        raise ValueError("invalid token environment variable name")

    def headers():
        value = os.environ.get(env)
        if not value:
            raise ValueError("collector token environment variable is unset")
        return {"Authorization": "Bearer " + value}

    return RestAudit(config, Http(host, headers))
