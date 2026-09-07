"""Read-only viewer: integrity status is computed, and source text is never rendered as HTML."""

import json
from pathlib import Path
from itertools import islice

import pandas as pd
import streamlit as st

from timeline_demo.core.manifest import verify_bundle
from timeline_demo.pipeline import read_timeline

st.set_page_config(page_title="Incident Timeline", layout="wide")
st.title("Incident Timeline")
st.caption("Source evidence, normalized chronology, and analyst interpretation")
default = Path(__file__).resolve().parents[1] / "examples" / "demo_bundle"
bundle = Path(st.sidebar.text_input("Bundle directory", str(default)))
try:
    manifest = verify_bundle(bundle)
except (OSError, ValueError) as exc:
    st.error(f"Bundle integrity could not be verified: {exc}")
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
analysis_path = st.sidebar.text_input("Optional analysis JSON file")
if analysis_path:
    st.subheader("AI interpretation — human review required")
    try:
        analysis = json.loads(Path(analysis_path).read_text())
        if analysis.get("receipt", {}).get("bundle_id") != manifest["bundle_id"]:
            st.error("Analysis belongs to a different bundle.")
        else:
            st.json(analysis)
    except (ValueError, OSError) as exc:
        st.error(str(exc))
