import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st


st.set_page_config(page_title="Executive Timeline Viewer", layout="wide")


# ---------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------

st.markdown(
    """
<style>
.stApp {
  background:
    radial-gradient(circle at top left, rgba(96,165,250,0.14), transparent 28%),
    radial-gradient(circle at top right, rgba(94,234,212,0.10), transparent 24%),
    linear-gradient(180deg, #08101d 0%, #0b1220 100%);
}

.hero,
.section-card,
.detail-panel,
.summary-card,
.ai-card,
[data-testid="stMetric"] {
  background: linear-gradient(180deg, rgba(18,27,46,0.94), rgba(12,19,35,0.94));
  border: 1px solid rgba(148,163,184,0.18);
  border-radius: 18px;
}

.hero {
  padding: 1.25rem 1.35rem;
  margin-bottom: 1rem;
}

.section-card {
  padding: 1rem;
  margin-bottom: 1rem;
}

.detail-panel {
  padding: 1rem;
}

.summary-card {
  padding: 1rem;
  min-height: 115px;
}

.ai-card {
  padding: 1rem;
  margin-bottom: 0.8rem;
}

.badge {
  display: inline-block;
  background: rgba(96,165,250,0.10);
  border: 1px solid rgba(96,165,250,0.25);
  padding: .35rem .65rem;
  border-radius: 999px;
  margin-right: .4rem;
  margin-bottom: .35rem;
}

.badge-info {
  display: inline-block;
  background: rgba(96,165,250,0.12);
  border: 1px solid rgba(96,165,250,0.30);
  padding: .25rem .55rem;
  border-radius: 999px;
  margin-right: .35rem;
  margin-bottom: .35rem;
  font-size: 0.85rem;
}

.trust-boundary {
  background: linear-gradient(90deg, rgba(248,113,113,0.12), rgba(96,165,250,0.08));
  border: 1px solid rgba(248,113,113,0.22);
  border-radius: 16px;
  padding: .9rem 1rem;
  margin-top: 1rem;
}

[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #0c1324 0%, #0d172b 100%);
  border-right: 1px solid rgba(148,163,184,0.18);
}

.ai-heading {
  font-size: 1.05rem;
  font-weight: 700;
  margin-bottom: .35rem;
}

.ai-subheading {
  color: #94a3b8;
  font-size: .9rem;
  margin-bottom: .7rem;
}
</style>
""",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------

APP_DIR = Path(__file__).resolve().parent
STREAMLIT_DIR = APP_DIR.parent
REPO_ROOT = STREAMLIT_DIR.parent

OUTPUT_BASE = REPO_ROOT / "data" / "output"
SAMPLE_BASE = STREAMLIT_DIR / "sample_data"


def resolve_data_file(filename: str) -> Path:
    """
    Prefer fresh pipeline output from data/output.
    Fall back to bundled sample_data only if output does not exist.
    """
    output_file = OUTPUT_BASE / filename
    sample_file = SAMPLE_BASE / filename

    if output_file.exists():
        return output_file

    return sample_file


def load_jsonl(filename: str) -> pd.DataFrame:
    path = resolve_data_file(filename)

    if not path.exists():
        return pd.DataFrame()

    rows = []

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))

    return pd.DataFrame(rows)


def load_json(filename: str):
    path = resolve_data_file(filename)

    if not path.exists():
        return {}

    return json.loads(path.read_text(encoding="utf-8"))


df = load_jsonl("timeline.jsonl")

if "time_utc" in df.columns:
    df["time_utc"] = pd.to_datetime(df["time_utc"], utc=True, errors="coerce")

manifest = load_json("audit_manifest.json")
iocs = load_json("extracted_iocs.json")
ti = load_json("threat_intel_enrichment.json")
ai = load_json("ai_enrichment.json")


# ---------------------------------------------------------------------
# Helper rendering functions
# ---------------------------------------------------------------------

def ensure_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def render_bullets(value: Any, empty_message: str = "No data available.") -> None:
    items = ensure_list(value)

    if not items:
        st.info(empty_message)
        return

    for item in items:
        if isinstance(item, dict):
            st.json(item)
        else:
            st.write(f"- {item}")


def render_key_value_list(value: Any, empty_message: str = "No data available.") -> None:
    if not value:
        st.info(empty_message)
        return

    if isinstance(value, dict):
        for key, item in value.items():
            st.markdown(f"**{key}**")
            if isinstance(item, (dict, list)):
                st.json(item)
            else:
                st.write(item)
        return

    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                st.json(item)
            else:
                st.write(f"- {item}")
        return

    st.write(value)


def render_ai_status(ai_payload: dict) -> None:
    status = ai_payload.get("status") or ai_payload.get("_meta", {}).get("status", "available")
    model = ai_payload.get("model") or ai_payload.get("_meta", {}).get("model", "unknown")

    if status == "skipped":
        st.warning("ChatGPT enrichment was skipped.")
        return

    if status == "error":
        st.error("ChatGPT enrichment returned an error.")
        return

    if status == "empty_response":
        st.warning("ChatGPT returned an empty response.")
        return

    st.success(f"ChatGPT enrichment loaded. Status: {status}. Model: {model}.")


def render_ioc_badges(ioc_payload: Any) -> None:
    if not ioc_payload:
        st.info("No IOC data available.")
        return

    if isinstance(ioc_payload, dict):
        for category, values in ioc_payload.items():
            values_list = ensure_list(values)
            if not values_list:
                continue

            st.markdown(f"**{category}**")
            badge_html = ""

            for value in values_list:
                if isinstance(value, dict):
                    badge_html += f'<span class="badge-info">{json.dumps(value, ensure_ascii=False)}</span>'
                else:
                    badge_html += f'<span class="badge-info">{value}</span>'

            st.markdown(badge_html, unsafe_allow_html=True)

        return

    render_bullets(ioc_payload)


def render_ti_table(ti_payload: Any) -> None:
    if not ti_payload:
        st.info("No threat intelligence enrichment data available.")
        return

    if isinstance(ti_payload, list):
        rows = []

        for item in ti_payload:
            if isinstance(item, dict):
                rows.append(
                    {
                        "provider": item.get("provider", ""),
                        "ioc": item.get("ioc", ""),
                        "status": item.get("status", ""),
                        "reason": item.get("reason", ""),
                        "error": item.get("error", ""),
                    }
                )

        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, height=220)
            with st.expander("Raw TI enrichment JSON"):
                st.json(ti_payload)
            return

    st.json(ti_payload)


# ---------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------

with st.sidebar:
    st.header("Data Sources")

    st.caption("Timeline")
    st.code(str(resolve_data_file("timeline.jsonl")))

    st.caption("ChatGPT API Enrichment")
    st.code(str(resolve_data_file("ai_enrichment.json")))

    st.caption("Threat Intelligence")
    st.code(str(resolve_data_file("threat_intel_enrichment.json")))

    st.divider()

    st.header("Display")
    show_raw_json = st.toggle("Show raw JSON expanders", value=True)
    show_data_paths = st.toggle("Show data source paths", value=True)


# ---------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------

st.markdown(
    """
<div class="hero">
  <div style="font-size:2rem;font-weight:700;">Executive Timeline Viewer</div>
  <div style="color:#94a3b8;">
    Evidence-first breach reconstruction with IOC extraction, TI enrichment, and isolated ChatGPT analysis.
  </div>
  <div style="margin-top:.8rem;">
    <span class="badge">Verified Evidence</span>
    <span class="badge">UTC Timeline</span>
    <span class="badge">IOC Extraction</span>
    <span class="badge">Threat Intel</span>
    <span class="badge">ChatGPT Analysis</span>
    <span class="badge">AI Isolated</span>
  </div>
</div>
""",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------

high_critical = 0
if "severity" in df.columns:
    high_critical = int(
        df["severity"].astype(str).str.lower().isin(["high", "critical"]).sum()
    )

source_count = 0
if "source_name" in df.columns:
    source_count = len(set(df["source_name"].dropna().astype(str)))

ioc_count = sum(len(v) for v in iocs.values()) if isinstance(iocs, dict) else 0

ai_status = "missing"
if isinstance(ai, dict) and ai:
    ai_status = ai.get("status") or ai.get("_meta", {}).get("status", "available")

m1, m2, m3, m4, m5 = st.columns(5)

with m1:
    st.metric("Total Events", len(df))

with m2:
    st.metric("Sources", source_count)

with m3:
    st.metric("High/Critical", high_critical)

with m4:
    st.metric("Extracted IOCs", ioc_count)

with m5:
    st.metric("ChatGPT", ai_status)


# ---------------------------------------------------------------------
# Investigation overview
# ---------------------------------------------------------------------

st.markdown('<div class="section-card">', unsafe_allow_html=True)
st.subheader("Investigation Overview")

overview_1, overview_2, overview_3 = st.columns(3)

with overview_1:
    st.markdown('<div class="summary-card">', unsafe_allow_html=True)
    st.markdown('<div class="ai-heading">Evidence Posture</div>', unsafe_allow_html=True)
    st.write("The timeline is generated from normalized security events and ordered by UTC time.")
    st.markdown("</div>", unsafe_allow_html=True)

with overview_2:
    st.markdown('<div class="summary-card">', unsafe_allow_html=True)
    st.markdown('<div class="ai-heading">Analytic Layer</div>', unsafe_allow_html=True)
    st.write("IOC and threat-intelligence enrichment are derived from verified outputs.")
    st.markdown("</div>", unsafe_allow_html=True)

with overview_3:
    st.markdown('<div class="summary-card">', unsafe_allow_html=True)
    st.markdown('<div class="ai-heading">AI Boundary</div>', unsafe_allow_html=True)
    st.write("ChatGPT reads the timeline and enrichment data but does not alter evidence.")
    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------
# Evidence timeline
# ---------------------------------------------------------------------

timeline_columns = [
    "timeline_position",
    "time_utc",
    "source_name",
    "product_name",
    "activity_name",
    "user_name",
    "asset_name",
    "severity",
    "status",
]

available_timeline_columns = [column for column in timeline_columns if column in df.columns]

st.markdown('<div class="section-card">', unsafe_allow_html=True)
st.subheader("Evidence Timeline")

if df.empty:
    st.warning("No timeline data found. Run `python -m src.timeline_demo.run_real_pipeline` from the repo root.")
else:
    st.dataframe(
        df[available_timeline_columns] if available_timeline_columns else df,
        use_container_width=True,
        height=340,
    )

st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------
# Event detail + audit manifest
# ---------------------------------------------------------------------

left, right = st.columns([3, 2])

with left:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.subheader("Event Detail")

    if df.empty:
        st.info("No events available.")
    else:
        labels = [
            f"{i + 1}. {row.get('time_utc')} | {row.get('source_name')} | {row.get('activity_name')}"
            for i, row in df.fillna("—").iterrows()
        ]

        selected = st.selectbox("Select Event", labels)
        idx = labels.index(selected)
        row = df.fillna("—").iloc[idx].to_dict()

        c1, c2, c3 = st.columns(3)

        with c1:
            st.markdown(
                f"""
<div class="detail-panel">
  <b>Activity</b><br>{row.get("activity_name")}<br><br>
  <b>Timestamp</b><br>{row.get("time_utc")}<br><br>
  <b>Source</b><br>{row.get("source_name")}
</div>
""",
                unsafe_allow_html=True,
            )

        with c2:
            st.markdown(
                f"""
<div class="detail-panel">
  <b>User</b><br>{row.get("user_name")}<br><br>
  <b>Asset</b><br>{row.get("asset_name")}<br><br>
  <b>Severity</b><br>{row.get("severity")}
</div>
""",
                unsafe_allow_html=True,
            )

        with c3:
            st.markdown(
                f"""
<div class="detail-panel">
  <b>Event UUID</b><br>{row.get("event_uuid", "—")}<br><br>
  <b>Raw Hash</b><br>{row.get("raw_data_hash", "—")}
</div>
""",
                unsafe_allow_html=True,
            )

        with st.expander("Full selected event JSON"):
            st.json(row)

    st.markdown("</div>", unsafe_allow_html=True)

with right:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.subheader("Audit Manifest")
    st.json(manifest if manifest else {"status": "missing"})
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------
# IOC + TI
# ---------------------------------------------------------------------

b1, b2 = st.columns(2)

with b1:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.subheader("Extracted IOCs")
    render_ioc_badges(iocs)
    if show_raw_json:
        with st.expander("Raw extracted IOC JSON"):
            st.json(iocs if iocs else {"status": "none"})
    st.markdown("</div>", unsafe_allow_html=True)

with b2:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.subheader("Threat Intelligence Enrichment")
    render_ti_table(ti)
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------
# ChatGPT API Enrichment
# ---------------------------------------------------------------------

st.markdown('<div class="section-card">', unsafe_allow_html=True)
st.subheader("ChatGPT Analysis")

if not ai:
    st.warning("No ai_enrichment.json data found.")

else:
    render_ai_status(ai)

    if ai.get("status") == "skipped":
        st.info("Add `OPENAI_API_KEY` to `.env`, rerun the pipeline, and refresh this app.")
        st.json(ai)

    elif ai.get("status") == "error":
        st.error("The ChatGPT enrichment call returned an error.")
        st.json(ai)

    elif ai.get("status") == "empty_response":
        st.warning("The ChatGPT enrichment call returned an empty response.")
        st.json(ai)

    elif ai.get("status") == "ok_non_json_response" or "raw_response" in ai:
        st.info("ChatGPT returned a non-JSON response. Showing raw response.")
        st.write(ai.get("raw_response", ai))

    else:
        tab_exec, tab_analyst, tab_pivots, tab_objectives, tab_ai_iocs, tab_ti, tab_raw = st.tabs(
            [
                "Executive Summary",
                "Analyst Summary",
                "Notable Pivots",
                "Likely Objectives",
                "AI IOC Assessment",
                "TI Summary",
                "Raw JSON",
            ]
        )

        with tab_exec:
            st.markdown('<div class="ai-card">', unsafe_allow_html=True)
            st.markdown('<div class="ai-heading">Executive Summary</div>', unsafe_allow_html=True)
            st.markdown(
                '<div class="ai-subheading">Board-level interpretation of the verified evidence.</div>',
                unsafe_allow_html=True,
            )
            render_bullets(ai.get("executive_summary"), "No executive summary returned.")
            st.markdown("</div>", unsafe_allow_html=True)

        with tab_analyst:
            st.markdown('<div class="ai-card">', unsafe_allow_html=True)
            st.markdown('<div class="ai-heading">Analyst Summary</div>', unsafe_allow_html=True)
            st.markdown(
                '<div class="ai-subheading">Operational interpretation for incident responders.</div>',
                unsafe_allow_html=True,
            )
            render_bullets(ai.get("analyst_summary"), "No analyst summary returned.")
            st.markdown("</div>", unsafe_allow_html=True)

        with tab_pivots:
            st.markdown('<div class="ai-card">', unsafe_allow_html=True)
            st.markdown('<div class="ai-heading">Notable Investigation Pivots</div>', unsafe_allow_html=True)
            st.markdown(
                '<div class="ai-subheading">Recommended next places to investigate.</div>',
                unsafe_allow_html=True,
            )
            render_key_value_list(ai.get("notable_pivots"), "No notable pivots returned.")
            st.markdown("</div>", unsafe_allow_html=True)

        with tab_objectives:
            st.markdown('<div class="ai-card">', unsafe_allow_html=True)
            st.markdown('<div class="ai-heading">Likely Adversary Objectives</div>', unsafe_allow_html=True)
            st.markdown(
                '<div class="ai-subheading">Possible attacker goals inferred from verified evidence.</div>',
                unsafe_allow_html=True,
            )
            render_key_value_list(ai.get("likely_objectives"), "No likely objectives returned.")
            st.markdown("</div>", unsafe_allow_html=True)

        with tab_ai_iocs:
            st.markdown('<div class="ai-card">', unsafe_allow_html=True)
            st.markdown('<div class="ai-heading">AI IOC Assessment</div>', unsafe_allow_html=True)
            st.markdown(
                '<div class="ai-subheading">Indicator interpretation from the AI analysis layer.</div>',
                unsafe_allow_html=True,
            )
            render_ioc_badges(ai.get("iocs"))
            st.markdown("</div>", unsafe_allow_html=True)

        with tab_ti:
            st.markdown('<div class="ai-card">', unsafe_allow_html=True)
            st.markdown('<div class="ai-heading">Threat Intelligence Summary</div>', unsafe_allow_html=True)
            st.markdown(
                '<div class="ai-subheading">AI interpretation of enrichment provider results.</div>',
                unsafe_allow_html=True,
            )
            render_key_value_list(ai.get("ti_summary"), "No TI summary returned.")
            st.markdown("</div>", unsafe_allow_html=True)

        with tab_raw:
            st.json(ai)

st.markdown(
    """
<div class="trust-boundary">
  <strong>Trust Boundary:</strong> AI reads verified outputs only.
  It does not modify evidence, timestamps, hashes, event order, or audit hashes.
</div>
""",
    unsafe_allow_html=True,
)

st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------
# Optional data-source debug
# ---------------------------------------------------------------------

if show_data_paths:
    with st.expander("Resolved Data File Paths"):
        st.write("Timeline:", str(resolve_data_file("timeline.jsonl")))
        st.write("Audit manifest:", str(resolve_data_file("audit_manifest.json")))
        st.write("Extracted IOCs:", str(resolve_data_file("extracted_iocs.json")))
        st.write("Threat intelligence:", str(resolve_data_file("threat_intel_enrichment.json")))
        st.write("ChatGPT enrichment:", str(resolve_data_file("ai_enrichment.json")))