import json
from pathlib import Path
import pandas as pd
import streamlit as st
st.set_page_config(page_title="Executive Timeline Viewer", layout="wide")
st.markdown('<style>.stApp{background:linear-gradient(180deg,#08101d 0%,#0b1220 100%)}.hero,.section-card,.detail-panel,[data-testid="stMetric"]{background:linear-gradient(180deg,rgba(18,27,46,.94),rgba(12,19,35,.94));border:1px solid rgba(148,163,184,.18);border-radius:18px}.hero{padding:1.25rem;margin-bottom:1rem}.section-card{padding:1rem;margin-bottom:1rem}.detail-panel{padding:1rem}.badge{display:inline-block;background:rgba(96,165,250,.10);border:1px solid rgba(96,165,250,.25);padding:.35rem .65rem;border-radius:999px;margin-right:.4rem}.trust-boundary{background:linear-gradient(90deg,rgba(248,113,113,.12),rgba(96,165,250,.08));border:1px solid rgba(248,113,113,.22);border-radius:16px;padding:.9rem;margin-top:1rem}</style>',unsafe_allow_html=True)
BASE=Path(__file__).resolve().parent.parent/'sample_data'
def load_jsonl(p): return pd.DataFrame([json.loads(line) for line in p.read_text(encoding='utf-8').splitlines() if line.strip()]) if p.exists() else pd.DataFrame()
def load_json(p): return json.loads(p.read_text(encoding='utf-8')) if p.exists() else {}
df=load_jsonl(BASE/'timeline.jsonl')
if 'time_utc' in df.columns: df['time_utc']=pd.to_datetime(df['time_utc'],utc=True,errors='coerce')
manifest=load_json(BASE/'audit_manifest.json'); iocs=load_json(BASE/'extracted_iocs.json'); ti=load_json(BASE/'threat_intel_enrichment.json'); ai=load_json(BASE/'ai_enrichment.json')
st.markdown('<div class="hero"><div style="font-size:2rem;font-weight:700;">Executive Timeline Viewer</div><div style="color:#94a3b8;">Verified evidence timeline, IOC extraction, threat-intel enrichment, and isolated ChatGPT API narrative.</div><div style="margin-top:.8rem;"><span class="badge">Verified Evidence</span><span class="badge">IOC Extraction</span><span class="badge">Threat Intel</span><span class="badge">AI Isolated</span></div></div>',unsafe_allow_html=True)
m1,m2,m3,m4=st.columns(4)
with m1: st.metric('Total Events',len(df))
with m2: st.metric('Sources',len(set(df['source_name'].dropna().astype(str))) if 'source_name' in df.columns else 0)
with m3: st.metric('High/Critical',int(df['severity'].astype(str).str.lower().isin(['high','critical']).sum()) if 'severity' in df.columns else 0)
with m4: st.metric('Extracted IOCs',sum(len(v) for v in iocs.values()) if isinstance(iocs,dict) else 0)
cols=[c for c in ['timeline_position','time_utc','source_name','product_name','activity_name','user_name','asset_name','severity','status'] if c in df.columns]
st.markdown('<div class="section-card">',unsafe_allow_html=True); st.subheader('Evidence Timeline'); st.dataframe(df[cols] if cols else df,use_container_width=True,height=320); st.markdown('</div>',unsafe_allow_html=True)
left,right=st.columns([3,2])
with left:
    st.markdown('<div class="section-card">',unsafe_allow_html=True)
    labels=[f"{i+1}. {row.get('time_utc')} | {row.get('source_name')} | {row.get('activity_name')}" for i,row in df.fillna('—').iterrows()]
    if labels:
        selected=st.selectbox('Event',labels); row=df.fillna('—').iloc[labels.index(selected)].to_dict(); c1,c2,c3=st.columns(3)
        with c1: st.markdown(f'<div class="detail-panel"><b>Activity</b><br>{row.get("activity_name")}<br><br><b>Timestamp</b><br>{row.get("time_utc")}<br><br><b>Source</b><br>{row.get("source_name")}</div>',unsafe_allow_html=True)
        with c2: st.markdown(f'<div class="detail-panel"><b>User</b><br>{row.get("user_name")}<br><br><b>Asset</b><br>{row.get("asset_name")}<br><br><b>Severity</b><br>{row.get("severity")}</div>',unsafe_allow_html=True)
        with c3: st.markdown(f'<div class="detail-panel"><b>Event UUID</b><br>{row.get("event_uuid","—")}<br><br><b>Raw Hash</b><br>{row.get("raw_data_hash","—")}</div>',unsafe_allow_html=True)
    st.markdown('</div>',unsafe_allow_html=True)
with right: st.markdown('<div class="section-card">',unsafe_allow_html=True); st.subheader('Audit Manifest'); st.json(manifest if manifest else {'status':'missing'}); st.markdown('</div>',unsafe_allow_html=True)
b1,b2=st.columns(2)
with b1: st.markdown('<div class="section-card">',unsafe_allow_html=True); st.subheader('Extracted IOCs'); st.json(iocs if iocs else {'status':'none'}); st.markdown('</div>',unsafe_allow_html=True)
with b2: st.markdown('<div class="section-card">',unsafe_allow_html=True); st.subheader('Threat Intelligence Enrichment'); st.json(ti if ti else [{'status':'none'}]); st.markdown('</div>',unsafe_allow_html=True)
st.markdown('<div class="section-card">',unsafe_allow_html=True); st.subheader('ChatGPT API Enrichment'); st.json(ai if ai else {'status':'missing'}); st.markdown('<div class="trust-boundary"><strong>Trust Boundary:</strong> AI reads verified outputs only. It does not modify evidence, timestamps, hashes, or event ordering.</div>',unsafe_allow_html=True); st.markdown('</div>',unsafe_allow_html=True)
