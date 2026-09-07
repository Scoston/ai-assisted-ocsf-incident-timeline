"""Explicit source/table contracts for enterprise query and audit exports."""

HUNTING_TABLES = frozenset(
    {
        "DeviceProcessEvents",
        "DeviceNetworkEvents",
        "DeviceLogonEvents",
        "DeviceFileEvents",
        "DeviceRegistryEvents",
        "DeviceEvents",
        "EmailEvents",
        "EmailUrlInfo",
        "EmailAttachmentInfo",
        "UrlClickEvents",
        "IdentityLogonEvents",
        "IdentityDirectoryEvents",
        "IdentityQueryEvents",
        "CloudAppEvents",
    }
)
SIGNIN_TABLES = frozenset(
    {
        "SigninLogs",
        "AADNonInteractiveUserSignInLogs",
        "AADServicePrincipalSignInLogs",
        "AADManagedIdentitySignInLogs",
    }
)
LOG_TABLES = frozenset({"SecurityEvent", "WindowsEvent", "Syslog", "CommonSecurityLog"}) | SIGNIN_TABLES
WORKSPACE_APPS = frozenset({"login", "admin", "token", "drive"})


def validate_table(record, parser):
    tables = HUNTING_TABLES if parser == "defender_hunting" else LOG_TABLES
    if record.get("table") not in tables or not isinstance(record.get("record"), dict):
        raise ValueError("query export requires a supported table and a record object")


def enterprise_class(record, parser):
    if parser == "google_workspace":
        app = record.get("id", {}).get("applicationName")
        if app not in WORKSPACE_APPS:
            raise ValueError("unsupported Workspace application")
        return 3002 if app == "login" else 6003
    validate_table(record, parser)
    table, row = record["table"], record["record"]
    if parser == "defender_hunting":
        # Email, registry, generic device and URL records remain explicitly unmapped
        # until their own OCSF class schemas and semantic mappings are shipped.
        return {
            "DeviceProcessEvents": 1007,
            "DeviceNetworkEvents": 4001,
            "DeviceLogonEvents": 3002,
            "IdentityLogonEvents": 3002,
            "DeviceFileEvents": 1001,
            "IdentityDirectoryEvents": 6003,
            "IdentityQueryEvents": 6003,
            "CloudAppEvents": 6003,
        }.get(table, 0)
    if table == "CommonSecurityLog":
        return 4001 if row.get("SourceIP") and row.get("DestinationIP") else 0
    if table in SIGNIN_TABLES:
        return 3002
    if table in {"SecurityEvent", "WindowsEvent"}:
        return {"4624": 3002, "4625": 3002, "4634": 3002, "4648": 3002, "4688": 1007, "1102": 1008}.get(
            str(row.get("EventID")), 0
        )
    return 0
