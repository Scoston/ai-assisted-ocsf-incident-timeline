"""The legacy unbounded API path is intentionally retired."""


def generate_ai_enrichment(timeline, iocs, ti_results, model=None):
    return {
        "status": "skipped",
        "reason": "Use timeline analyze on a verified bundle with an explicit AI budget.",
    }
