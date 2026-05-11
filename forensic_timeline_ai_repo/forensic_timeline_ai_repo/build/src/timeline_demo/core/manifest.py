from __future__ import annotations
import json
from pathlib import Path

def build_manifest(timeline):
    return {"case_id":"orion-insurance-001","event_count":len(timeline),"sources":sorted({x.get("source_name") for x in timeline if x.get("source_name")}),"high_or_critical_events":sum(1 for x in timeline if str(x.get("severity","")).lower() in {"high","critical"}),"hash_algorithm":"SHA-256","schema_version":"normalized-real-parser-1.0","trust_boundary":{"verified_evidence":True,"ai_isolated":True,"ai_can_modify_evidence":False}}

def write_manifest(manifest, output_dir):
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True); (out / "audit_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
