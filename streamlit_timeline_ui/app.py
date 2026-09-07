"""Read-only viewer: integrity status is computed, and source text is never rendered as HTML."""

import json
import os
from pathlib import Path
from itertools import islice

import pandas as pd
import streamlit as st

from timeline_demo.ai_view import display_ai
from timeline_demo.core.manifest import verify_bundle
from timeline_demo.pipeline import read_timeline
from timeline_demo.viewer import load_access_policy, authorized_cases, open_case, audit_access

st.set_page_config(page_title="Incident Timeline", layout="wide")
st.title("Incident Timeline")
st.caption("Source evidence, normalized chronology, and analyst interpretation")
mode = os.environ.get("TIMELINE_VIEWER_MODE", "local")
claims = {}
try:
    if mode == "oidc":
        policy = load_access_policy(
            os.environ["TIMELINE_VIEWER_POLICY"], os.environ["TIMELINE_VIEWER_POLICY_SHA256"]
        )
        if not getattr(st.user, "is_logged_in", False):
            if st.button("Sign in"):
                st.login()
            st.stop()
        claims = st.user.to_dict()
        if st.sidebar.button("Sign out"):
            st.logout()
            st.stop()
        cases = authorized_cases(policy, claims)
        if not cases:
            raise PermissionError("no cases assigned")
        case = st.sidebar.selectbox("Case", cases)
        bundle, manifest, _ = open_case(policy, claims, case)
        audit_access(claims, "allowed", manifest["bundle_id"])
    elif mode == "local":
        if st.get_option("server.address") not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("local viewer requires a loopback bind address")
        default = Path(__file__).resolve().parents[1] / "examples" / "demo_bundle"
        bundle = Path(st.sidebar.text_input("Bundle directory", str(default)))
        manifest = verify_bundle(bundle)
    else:
        raise ValueError("unsupported viewer mode")
except (OSError, ValueError, KeyError, TypeError):
    if mode == "oidc":
        audit_access(claims, "denied")
    st.error("Case access or evidence verification failed. Contact the deployment administrator.")
    st.stop()
st.success("Bundle file hashes verified. Source authenticity is assessed separately.")
counts = manifest["counts"]
columns = st.columns(4)
for column, label, value in zip(
    columns,
    ["Case", "Events", "Quarantined", "Duplicates"],
    [manifest["case_id"], counts["event_count"], counts["quarantined_records"], counts["duplicate_events"]],
):
    column.metric(label, value)
limit = st.sidebar.number_input("Maximum displayed events", min_value=1, max_value=100000, value=5000)

rows = list(islice(read_timeline(bundle), int(limit)))
st.caption(f"Displaying {len(rows):,} of {counts['event_count']:,} events in UTC order.")
if rows:
    frame = pd.DataFrame(rows)
    source = st.multiselect("Sources", sorted(frame["source_name"].unique()))
    if source:
        frame = frame[frame["source_name"].isin(source)]
    st.dataframe(
        frame[["time_utc", "source_name", "activity_name", "user_name", "asset_name", "severity", "status"]],
        use_container_width=True,
    )
    index = st.selectbox(
        "Inspect source provenance",
        range(len(rows)),
        format_func=lambda i: f"{i + 1}. {rows[i]['activity_name']}",
    )
    st.json(rows[index])
with st.expander("Manifest and acquisition references"):
    st.json(manifest)
with st.expander("Extracted indicators (not verdicts)"):
    st.json(json.loads((bundle / "extracted_iocs.json").read_text()))
# Analysis is resolved from a protected ledger, never trusted from an arbitrary JSON file.

display_ai(st, bundle, manifest, mode=mode, viewer_policy=policy if mode == "oidc" else None, claims=claims)
