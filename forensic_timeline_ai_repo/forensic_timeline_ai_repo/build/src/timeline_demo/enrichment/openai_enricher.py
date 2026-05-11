from __future__ import annotations
import json, os
from openai import OpenAI
SYSTEM_PROMPT = """You are a cyber defense copilot. Treat the verified timeline as source of truth. Do not invent events or alter timestamps, hashes, or ordering. Separate verified facts from interpretation. AI is outside the evidentiary chain. Return strict JSON with keys: analyst_summary, executive_summary, notable_pivots, likely_objectives, iocs, ti_summary."""
def generate_ai_enrichment(timeline, iocs, ti_results, model="gpt-5.4"):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key: return {"status":"skipped","reason":"missing OPENAI_API_KEY"}
    client = OpenAI(api_key=api_key)
    response = client.responses.create(model=model, input=[{"role":"system","content":SYSTEM_PROMPT},{"role":"user","content":json.dumps({"verified_timeline":timeline,"extracted_iocs":iocs,"threat_intelligence_results":ti_results})}])
    text = getattr(response, "output_text", "")
    if not text: return {"status":"empty_response"}
    try: return json.loads(text)
    except Exception: return {"raw_response":text}
