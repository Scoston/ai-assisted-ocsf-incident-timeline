from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from openai import OpenAI


SYSTEM_PROMPT = """You are a cyber defense copilot.

Rules:
1. Treat the verified timeline as the source of truth.
2. Do not invent events.
3. Do not alter timestamps, hashes, or event ordering.
4. Separate verified facts from analytic interpretation.
5. AI is outside the evidentiary chain.
6. Extract indicators of compromise.
7. Explain likely malicious activity, likely objectives, and investigation pivots.
8. If threat-intelligence lookup results are provided, use them carefully and name the provider in plain text.
9. Map to the correct Mitre Attack Framework
10. Search the Internet for any sources that help describe what is occurring with tool, techniques and procedures. Also map out the attack surface which is for educational and learning purposes. Include any open source theart Inteligence and full urls.  

Return strict JSON with keys:
analyst_summary
executive_summary
notable_pivots
likely_objectives
iocs
ti_summary
"""


def generate_ai_enrichment(
    timeline: List[Dict[str, Any]],
    iocs: Dict[str, Any],
    ti_results: List[Dict[str, Any]],
    model: str | None = None,
) -> Dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return {
            "status": "skipped",
            "reason": "missing OPENAI_API_KEY",
            "fix": "Create a .env file in the repo root with OPENAI_API_KEY=your_key_here",
        }

    selected_model = model or os.getenv("OPENAI_MODEL", "gpt-5.5")

    client = OpenAI(api_key=api_key)

    payload = {
        "verified_timeline": timeline,
        "extracted_iocs": iocs,
        "threat_intelligence_results": ti_results,
    }

    user_prompt = f"""
Analyze the following verified incident timeline and return strict JSON only.

Verified data:
{json.dumps(payload, indent=2)}
"""

    try:
        response = client.responses.create(
            model=selected_model,
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )

        text = getattr(response, "output_text", "")

        if not text:
            return {
                "status": "error",
                "reason": "empty_response",
                "model": selected_model,
            }

        try:
            parsed = json.loads(text)
            parsed["_meta"] = {
                "status": "ok",
                "model": selected_model,
                "ai_boundary": "AI read verified timeline, IOCs, and TI results only. It did not modify evidence.",
            }
            return parsed

        except json.JSONDecodeError:
            return {
                "status": "ok_non_json_response",
                "model": selected_model,
                "raw_response": text,
                "note": "The model returned text instead of strict JSON. The UI can still display this under raw_response.",
            }

    except Exception as exc:
        return {
            "status": "error",
            "model": selected_model,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }