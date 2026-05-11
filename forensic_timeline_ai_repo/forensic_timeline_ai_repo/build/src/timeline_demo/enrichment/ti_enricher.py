from __future__ import annotations
import os, requests
def enrich_ip_abuseipdb(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key: return {"provider":"abuseipdb","ioc":ip,"status":"skipped","reason":"missing ABUSEIPDB_API_KEY"}
    try: return {"provider":"abuseipdb","ioc":ip,"status":"ok","response":requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key":api_key,"Accept":"application/json"}, params={"ipAddress":ip,"maxAgeInDays":90}, timeout=20).json()}
    except Exception as exc: return {"provider":"abuseipdb","ioc":ip,"status":"error","error":str(exc)}
def enrich_domain_otx(domain):
    api_key = os.getenv("OTX_API_KEY")
    if not api_key: return {"provider":"otx","ioc":domain,"status":"skipped","reason":"missing OTX_API_KEY"}
    try: return {"provider":"otx","ioc":domain,"status":"ok","response":requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general", headers={"X-OTX-API-KEY":api_key}, timeout=20).json()}
    except Exception as exc: return {"provider":"otx","ioc":domain,"status":"error","error":str(exc)}
def enrich_hash_virustotal(file_hash):
    api_key = os.getenv("VT_API_KEY")
    if not api_key: return {"provider":"virustotal","ioc":file_hash,"status":"skipped","reason":"missing VT_API_KEY"}
    try: return {"provider":"virustotal","ioc":file_hash,"status":"ok","response":requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers={"x-apikey":api_key}, timeout=20).json()}
    except Exception as exc: return {"provider":"virustotal","ioc":file_hash,"status":"error","error":str(exc)}
def enrich_iocs(iocs):
    out=[]
    for ip in iocs.get("ips", []): out.append(enrich_ip_abuseipdb(ip))
    for domain in iocs.get("domains", []): out.append(enrich_domain_otx(domain))
    for h in iocs.get("sha256", []): out.append(enrich_hash_virustotal(h))
    return out
