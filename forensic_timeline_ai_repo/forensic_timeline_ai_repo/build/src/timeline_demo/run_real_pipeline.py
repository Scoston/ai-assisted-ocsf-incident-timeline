from __future__ import annotations
import json
from pathlib import Path
from dotenv import load_dotenv
from src.timeline_demo.parsers.cloudtrail_parser import parse_cloudtrail_file
from src.timeline_demo.parsers.entra_signin_parser import parse_entra_signin_file
from src.timeline_demo.parsers.crowdstrike_detection_parser import parse_crowdstrike_detection_file
from src.timeline_demo.parsers.common import write_jsonl
from src.timeline_demo.core.timeline_builder import build_timeline, write_timeline_outputs
from src.timeline_demo.core.manifest import build_manifest, write_manifest
from src.timeline_demo.enrichment.ioc_extractor import extract_iocs_from_events
from src.timeline_demo.enrichment.ti_enricher import enrich_iocs
from src.timeline_demo.enrichment.openai_enricher import generate_ai_enrichment

def main():
    load_dotenv(); repo = Path(__file__).resolve().parents[2]; data = repo / "data"; output_dir = data / "output"; processed_dir = data / "processed"
    events = []
    for path, parser in [(data / "raw/aws/cloudtrail_real_sample.json", parse_cloudtrail_file),(data / "raw/entra/entra_signin_real_sample.jsonl", parse_entra_signin_file),(data / "raw/edr/crowdstrike_detection_real_sample.json", parse_crowdstrike_detection_file)]:
        if path.exists(): events.extend(parser(path))
    processed_dir.mkdir(parents=True, exist_ok=True); (processed_dir / ".gitkeep").write_text("", encoding="utf-8"); write_jsonl(processed_dir / "normalized_events.jsonl", events)
    timeline = build_timeline(events); write_timeline_outputs(timeline, output_dir); (output_dir / ".gitkeep").write_text("", encoding="utf-8")
    manifest = build_manifest(timeline); write_manifest(manifest, output_dir)
    iocs = extract_iocs_from_events(timeline); (output_dir / "extracted_iocs.json").write_text(json.dumps(iocs, indent=2), encoding="utf-8")
    ti = enrich_iocs(iocs); (output_dir / "threat_intel_enrichment.json").write_text(json.dumps(ti, indent=2), encoding="utf-8")
    ai = generate_ai_enrichment(timeline, iocs, ti); (output_dir / "ai_enrichment.json").write_text(json.dumps(ai, indent=2), encoding="utf-8")
    sample = repo / "streamlit_timeline_ui/sample_data"; sample.mkdir(parents=True, exist_ok=True)
    for name in ["timeline.jsonl","timeline.csv","audit_manifest.json","extracted_iocs.json","threat_intel_enrichment.json","ai_enrichment.json"]:
        src = output_dir / name
        if src.exists(): (sample / name).write_bytes(src.read_bytes())
    print(f"Wrote outputs to {output_dir}")
if __name__ == "__main__": main()
