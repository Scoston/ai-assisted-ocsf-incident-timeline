"""Supported source contracts; raw evidence remains available for unmapped fields."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path

from .common import compact_json, file_hash, parse_time, pick, sha256_of_text
from .readers import _strict_json, iter_records
from .enterprise import enterprise_class

PARSER_VERSION = "2.0.0"
PROFILE_VERSION = "timeline-ocsf-aligned-2.0"


@dataclass(frozen=True)
class Spec:
    product: str
    class_uid: int
    time: str
    activity: str
    actor: str = ""
    asset: str = ""
    ip: str = ""
    identity: str = "id"
    status: str = "status"
    severity: str = "severity"
    unit: str | None = None
    version: str = PARSER_VERSION
    source_timezone: str | None = None


SPECS = {
    "github_audit": Spec(
        "GitHub Organization Audit",
        6003,
        "@timestamp|created_at",
        "action",
        "actor",
        "repo|org",
        "actor_ip",
        "_document_id",
        status="",
        unit="ms",
        version="1.0.0",
    ),
    "kubernetes_audit": Spec(
        "Kubernetes API Audit",
        6003,
        "stageTimestamp",
        "verb",
        "user.username",
        "objectRef.uid|objectRef.name|requestURI",
        "sourceIPs.0",
        "auditID",
        "responseStatus.code",
        version="1.0.0",
    ),
    "defender_hunting": Spec(
        "Microsoft Defender Advanced Hunting",
        0,
        "record.Timestamp",
        "record.ActionType|table",
        "record.AccountUpn|record.AccountName|record.InitiatingProcessAccountUpn|record.InitiatingProcessAccountName|record.SenderFromAddress",
        "record.DeviceName|record.Application",
        "record.LocalIP|record.IPAddress|record.RemoteIP",
        "record.ReportId|record.NetworkMessageId",
        "record.ActionType",
        version="1.0.0",
    ),
    "azure_log_analytics": Spec(
        "Azure Monitor Logs",
        0,
        "record.TimeGenerated",
        "record.EventID|record.Activity|record.OperationName|record.DeviceEventClassID|record.ProcessName|table",
        "record.TargetUserName|record.Account|record.EventData.TargetUserName|record.SourceUserName|record.UserPrincipalName|record.ServicePrincipalName|record.Identity",
        "record.Computer|record.DeviceName|record.HostName|record.ResourceDisplayName|record.AppDisplayName",
        "record.IpAddress|record.EventData.IpAddress|record.SourceIP|record.HostIP|record.IPAddress",
        "record.EventRecordId|record.EventRecordID|record._ItemId|record.Id",
        "record.DeviceAction|record.ResultType",
        "record.SeverityLevel|record.LogSeverity",
        version="1.0.0",
    ),
    "google_workspace": Spec(
        "Google Workspace Audit",
        6003,
        "id.time",
        "workspace_event.name",
        "actor.email|actor.profileId",
        "id.applicationName",
        "ipAddress",
        "id.uniqueQualifier",
        "workspace_event.type",
        version="1.0.0",
    ),
    "crowdstrike_alert": Spec(
        "CrowdStrike Falcon Alert",
        2004,
        "timestamp|created_timestamp",
        "display_name|name|scenario|description",
        "user_name",
        "device.hostname|hostname",
        "device.external_ip",
        "composite_id|id",
        "status",
        "severity_name",
        version="1.0.0",
    ),
    "cloudtrail": Spec(
        "AWS CloudTrail",
        6003,
        "eventTime",
        "eventName",
        "userIdentity.arn|userIdentity.userName|userIdentity.principalId",
        "resources.0.ARN|eventSource",
        "sourceIPAddress",
        "eventID",
        "errorCode",
    ),
    "guardduty": Spec(
        "AWS GuardDuty",
        2004,
        "updatedAt|createdAt",
        "type",
        "resource.accessKeyDetails.userName",
        "resource.instanceDetails.instanceId",
        "service.action.awsApiCallAction.remoteIpDetails.ipAddressV4|service.action.networkConnectionAction.remoteIpDetails.ipAddressV4|service.action.awsApiCallAction.remoteIpDetails.ipAddress",
        "id",
        "service.archived",
        version="2.1.0",
    ),
    "securityhub": Spec(
        "AWS Security Hub ASFF",
        2004,
        "UpdatedAt|CreatedAt",
        "Title",
        "Resources.0.Id",
        "Resources.0.Id",
        "Network.SourceIpV4",
        "Id",
        "Workflow.Status|RecordState",
        "Severity.Label",
    ),
    "vpc_flow": Spec(
        "AWS VPC Flow Logs",
        4001,
        "start",
        "action",
        "account-id",
        "interface-id",
        "srcaddr",
        "id",
        "action",
        unit="s",
    ),
    "entra_signin": Spec(
        "Microsoft Entra Sign-in",
        3002,
        "createdDateTime|CreatedDateTime|TimeGenerated",
        "OperationName|operationName",
        "userPrincipalName|UserPrincipalName|Identity",
        "appDisplayName|AppDisplayName|ResourceDisplayName",
        "ipAddress|IPAddress",
        "id|Id",
        "status.errorCode|ResultType",
    ),
    "entra_audit": Spec(
        "Microsoft Entra Directory Audit",
        6003,
        "activityDateTime|TimeGenerated",
        "activityDisplayName|OperationName",
        "initiatedBy.user.userPrincipalName|initiatedBy.app.displayName",
        "targetResources.0.id",
        "initiatedBy.user.ipAddress",
        "id",
        "result",
    ),
    "azure_activity": Spec(
        "Azure Activity",
        6003,
        "eventTimestamp|TimeGenerated|time",
        "operationName.value|OperationNameValue|operationName",
        "caller|Caller",
        "resourceId|ResourceId",
        "callerIpAddress|CallerIpAddress",
        "eventDataId|EventDataId|correlationId",
        "status.value|ActivityStatusValue|resultType",
        "level",
    ),
    "m365_audit": Spec(
        "Microsoft 365 Unified Audit",
        6003,
        "CreationTime",
        "Operation",
        "UserId",
        "ObjectId",
        "ClientIP",
        "Id",
        "ResultStatus",
        version="2.1.0",
        source_timezone="UTC",
    ),
    "defender_alert": Spec(
        "Microsoft Defender Alert",
        2004,
        "createdDateTime|alertCreationTime|firstActivityDateTime",
        "title",
        "evidence.0.userAccount.accountName",
        "evidence.0.deviceDnsName|machineId",
        "evidence.0.ipAddress",
        "id",
    ),
    "crowdstrike_detection": Spec(
        "CrowdStrike Falcon",
        2004,
        "behavior.timestamp|created_timestamp|created_time|timestamp",
        "behavior.display_name|behavior.name|scenario",
        "behavior.user_name|user_name",
        "device.hostname|hostname|behavior.device_name",
        "device.external_ip",
        "detection_id|id",
        "status|state",
        "behavior.severity|severity",
    ),
    "gcp_audit": Spec(
        "Google Cloud Audit",
        6003,
        "timestamp|receiveTimestamp",
        "protoPayload.methodName",
        "protoPayload.authenticationInfo.principalEmail",
        "protoPayload.resourceName",
        "protoPayload.requestMetadata.callerIp",
        "insertId",
        "protoPayload.status.code",
        "severity",
    ),
    "okta": Spec(
        "Okta System Log",
        3002,
        "published",
        "eventType",
        "actor.alternateId|actor.id",
        "target.0.alternateId",
        "client.ipAddress",
        "uuid",
        "outcome.result",
        "severity",
    ),
    "windows_event": Spec(
        "Windows Event Export",
        0,
        "TimeCreated.SystemTime|TimeCreated|@timestamp|System.TimeCreated.SystemTime",
        "EventID|event.code|System.EventID",
        "EventData.TargetUserName|EventData.User|winlog.user.name",
        "Computer|System.Computer|host.name",
        "EventData.IpAddress",
        "EventRecordID|RecordId|System.EventRecordID",
        "Level",
    ),
    "syslog": Spec(
        "RFC 5424 Syslog", 0, "timestamp", "app", "user", "hostname", "src_ip", "id", "status", "pri"
    ),
    "zeek": Spec(
        "Zeek JSON",
        4001,
        "ts",
        "_path|service|conn_state",
        "user",
        "id.resp_h",
        "id.orig_h",
        "uid",
        "conn_state",
        unit="s",
    ),
    "suricata": Spec(
        "Suricata EVE",
        4001,
        "timestamp",
        "alert.signature|event_type",
        "user",
        "dest_ip",
        "src_ip",
        "flow_id",
        "alert.action",
        "alert.severity",
    ),
    "plaso": Spec(
        "Plaso psort Export",
        0,
        "datetime|timestamp",
        "message|data_type",
        "username",
        "hostname|filename",
        "source_ip",
        "event_identifier|_event_identifier|inode",
        unit="us",
    ),
    "ocsf": Spec(
        "OCSF",
        0,
        "time|time_utc",
        "activity_name|message|api.operation",
        "actor.user.name|user.name",
        "device.hostname|dst_endpoint.ip",
        "src_endpoint.ip",
        "metadata.uid|event_uuid",
        "status|status_id",
        "severity|severity_id",
        unit="ms",
    ),
    "tines_audit": Spec(
        "Tines Audit Log",
        6003,
        "created_at|timestamp",
        "operation_name|action|operation",
        "user_email|user.email|actor.email",
        "story_id|resource_id",
        "request_ip|ip_address|ip",
        "id",
        version="2.1.0",
    ),
    "databricks_audit": Spec(
        "Databricks Audit Log",
        6003,
        "event_time|timestamp",
        "action_name|actionName",
        "user_identity.email|userIdentity.email",
        "service_name|serviceName",
        "source_ip_address|sourceIPAddress",
        "request_id|requestId",
        "response.statusCode",
        unit="ms",
    ),
    "ai_agent": Spec(
        "AI Agent Audit Contract",
        6003,
        "timestamp",
        "action|tool_name",
        "agent_id",
        "resource|tool_name",
        "src_ip",
        "event_id",
        "status",
    ),
}


def field(record, paths, default=None):
    return pick(record, *paths.split("|"), default=default) if paths else default


def _severity(record, parser, spec):
    value = field(record, spec.severity, "unknown")
    text = str(value).lower()
    if parser == "crowdstrike_detection":
        try:
            number = float(value)
            return (
                "critical" if number >= 9 else "high" if number >= 6 else "medium" if number >= 3 else "low"
            )
        except ValueError:
            pass
    if parser == "guardduty":
        try:
            number = float(value)
            return (
                "critical" if number >= 9 else "high" if number >= 7 else "medium" if number >= 4 else "low"
            )
        except ValueError:
            pass
    if parser == "suricata":
        return {"1": "high", "2": "medium", "3": "low"}.get(text, "unknown")
    if parser == "syslog":
        try:
            number = int(value) % 8
            return (
                "critical"
                if number < 3
                else "high"
                if number == 3
                else "medium"
                if number == 4
                else "informational"
            )
        except ValueError:
            return "unknown"
    if parser == "ocsf":
        return {
            "0": "unknown",
            "1": "informational",
            "2": "low",
            "3": "medium",
            "4": "high",
            "5": "critical",
            "6": "fatal",
        }.get(text, text)
    return {
        "info": "informational",
        "warn": "medium",
        "warning": "medium",
        "error": "high",
        "alert": "critical",
        "emergency": "critical",
    }.get(
        text,
        text
        if text in {"unknown", "informational", "low", "medium", "high", "critical", "fatal"}
        else "unknown",
    )


def normalize_record(raw, parser, evidence_path, raw_file_hash, record_index, assume_timezone=None):
    spec = SPECS[parser]
    if not isinstance(raw, dict):
        raise ValueError("record must be an object")
    record = copy.deepcopy(raw)
    if parser == "kubernetes_audit":
        if (
            record.get("apiVersion") != "audit.k8s.io/v1"
            or record.get("kind") != "Event"
            or record.get("stage") not in {"RequestReceived", "ResponseStarted", "ResponseComplete", "Panic"}
            or record.get("level") not in {"None", "Metadata", "Request", "RequestResponse"}
            or not isinstance(record.get("auditID"), str)
            or not record["auditID"]
            or not isinstance(field(record, "user.username"), str)
            or not isinstance(record.get("verb"), str)
            or not record["verb"]
        ):
            raise ValueError("Kubernetes input requires an audit.k8s.io/v1 Event")
        parse_time(record.get("requestReceivedTimestamp"))
        code = field(record, "responseStatus.code")
        if code is not None and (type(code) is not int or not 100 <= code <= 599):
            raise ValueError("invalid Kubernetes response status")
    if parser == "m365_audit" and "AuditData" in record:
        record = (
            _strict_json(record["AuditData"]) if isinstance(record["AuditData"], str) else record["AuditData"]
        )
        if not isinstance(record, dict):
            raise ValueError("AuditData must be an object")
    if (
        parser == "cloudtrail"
        and isinstance(record.get("detail"), dict)
        and record["detail"].get("eventTime")
    ):
        record = record["detail"]
    if parser == "ocsf" and "record_json" in record:
        record = _strict_json(record["record_json"])
        if not isinstance(record, dict):
            raise ValueError("record_json must encode an object")
    variants = [None]
    if parser == "crowdstrike_detection" and record.get("behaviors"):
        variants = record["behaviors"]
        if not isinstance(variants, list) or any(not isinstance(x, dict) for x in variants):
            raise ValueError("behaviors must contain objects")
    if parser == "google_workspace":
        variants = record.get("events")
        if not isinstance(variants, list) or not variants or any(not isinstance(x, dict) for x in variants):
            raise ValueError("Workspace activity requires a nonempty events array")
    raw_hash = sha256_of_text(compact_json(raw))
    results = []
    for child_index, behavior in enumerate(variants):
        if behavior is not None:
            record["workspace_event" if parser == "google_workspace" else "behavior"] = behavior
        ts = field(record, spec.time)
        effective_timezone = spec.source_timezone or assume_timezone
        time_utc, epoch_ms, offset = parse_time(ts, spec.unit, effective_timezone)
        activity = field(record, spec.activity)
        if activity is None and parser == "entra_signin":
            activity = "user.signin"
        if activity is None:
            raise ValueError("missing source activity field")
        class_uid = spec.class_uid
        if parser in {"defender_hunting", "azure_log_analytics", "google_workspace"}:
            class_uid = enterprise_class(record, parser)
        if parser == "ocsf":
            class_uid = int(pick(record, "class_uid", "ocsf_class_uid", default=0))
            if class_uid <= 0:
                raise ValueError("OCSF input requires class_uid")
        if parser == "suricata":
            class_uid = {"alert": 2004, "flow": 4001, "netflow": 4001, "dns": 4003, "http": 4002}.get(
                record.get("event_type"), 0
            )
        if parser == "zeek":
            class_uid = {"conn": 4001, "dns": 4003, "http": 4002}.get(record.get("_path", "conn"), 0)
        if parser == "okta" and not str(activity).startswith(
            ("user.authentication.", "user.session.", "user.mfa.")
        ):
            class_uid = 6003
        if parser == "windows_event":
            event_id = str(activity)
            if event_id in {"4624", "4625", "4634", "4648"}:
                class_uid = 3002
            elif event_id == "4688":
                class_uid = 1007
            elif event_id == "1102":
                class_uid = 1008
            else:
                class_uid = 0
        if parser == "plaso":
            class_uid = 1001 if str(record.get("data_type", "")).startswith("fs:") else 0
        status = field(record, spec.status, "unknown")
        if parser == "cloudtrail":
            status = "failure" if status != "unknown" else "success"
        elif parser == "entra_signin":
            status = "success" if str(status) == "0" else "unknown" if status == "unknown" else "failure"
        elif parser == "gcp_audit":
            status = "success" if str(status) == "0" else "unknown" if status == "unknown" else "failure"
        elif parser == "kubernetes_audit":
            status = (
                "unknown"
                if status == "unknown" or status is None or status < 200
                else "success"
                if status < 400
                else "failure"
            )
        event_uuid = sha256_of_text(compact_json([parser, spec.version, raw_hash, child_index]))
        results.append(
            {
                "event_uuid": event_uuid,
                "source_event_id": str(field(record, spec.identity, raw_hash)),
                "time_utc": time_utc,
                "epoch_ms": epoch_ms,
                "timezone_offset": offset,
                "original_timestamp": str(ts),
                "timezone_assumption": effective_timezone,
                "temporal_confidence": "source_reported",
                "parser_name": parser,
                "parser_version": spec.version,
                "source_name": parser,
                "product_name": spec.product,
                "ocsf_class_uid": class_uid,
                "activity_name": str(activity),
                "status": str(status),
                "severity": _severity(record, parser, spec),
                "user_name": str(field(record, spec.actor, "")),
                "asset_name": str(field(record, spec.asset, "")),
                "src_ip": str(field(record, spec.ip, "")),
                "raw_data_hash": raw_hash,
                "raw_file_hash": raw_file_hash,
                "evidence_path": evidence_path,
                "record_index": record_index,
                "child_index": child_index,
                "metadata": {
                    "schema_version": PROFILE_VERSION,
                    "mapping_version": spec.version,
                    "ocsf_class_reference_version": "1.3.0",
                    "ocsf_mapping_status": "mapped_class" if class_uid else "unmapped",
                    "record_hash_encoding": "sorted-compact-json-utf8-v1",
                    "read_only": True,
                },
            }
        )
    return results


def parse_file(path, parser, assume_timezone=None):
    path = Path(path)
    digest = file_hash(path)
    events = []
    for index, raw, error in iter_records(path, parser):
        if error:
            raise ValueError(f"record {index}: {error}")
        events.extend(normalize_record(raw, parser, str(path), digest, index, assume_timezone))
    return events
