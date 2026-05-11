from src.timeline_demo.enrichment.ioc_extractor import extract_iocs_from_text

def test_ioc_extraction():
    text = "Suspicious call to https://evil.example/path from 198.51.100.10 with hash " + ("a" * 64)
    iocs = extract_iocs_from_text(text)
    assert "198.51.100.10" in iocs["ips"]
    assert "evil.example" in iocs["domains"]
    assert ("a" * 64) in iocs["sha256"]
