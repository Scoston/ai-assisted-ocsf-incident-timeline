from __future__ import annotations
import re
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s\"'>]+")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
def extract_iocs_from_text(text: str): return {"ips":sorted(set(IP_RE.findall(text))),"domains":sorted(set(DOMAIN_RE.findall(text))),"urls":sorted(set(URL_RE.findall(text))),"sha256":sorted(set(SHA256_RE.findall(text))),"emails":sorted(set(EMAIL_RE.findall(text)))}
def extract_iocs_from_events(events): return extract_iocs_from_text("\n".join(str(v) for event in events for v in event.values()))
