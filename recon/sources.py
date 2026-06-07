import json
import os
from urllib.parse import quote_plus

import requests

from .utils import clean_hostname, fetch_json, fetch_text
from dotenv import load_dotenv

load_dotenv()

def hunter_domain_search(domain: str) -> dict:
    api_key = os.getenv("HUNTER_API_KEY", "").strip()
    if not api_key:
        return {"status": "skipped", "reason": "Set HUNTER_API_KEY environment variable"}
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "body": r.text[:300]}
        data = r.json()
        emails = data.get("data", {}).get("emails", [])
        return {
            "status": "ok",
            "domain": data.get("data", {}).get("domain"),
            "pattern": data.get("data", {}).get("pattern"),
            "organization": data.get("data", {}).get("organization"),
            "emails": [
                {
                    "value": e.get("value"),
                    "type": e.get("type"),
                    "confidence": e.get("confidence"),
                    "first_name": e.get("first_name"),
                    "last_name": e.get("last_name"),
                    "position": e.get("position"),
                    "department": e.get("department"),
                    "sources": e.get("sources", [])[:3],
                }
                for e in emails
            ],
        }
    except Exception as e:
        return {"error": str(e)}


def crtsh_subdomains(domain: str) -> dict:
    data = fetch_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=60)
    subdomains = set()
    if isinstance(data, dict) and data.get("error"):
        return {"source": "crt.sh", "error": data["error"], "subdomains": []}
    if not isinstance(data, list):
        return {"source": "crt.sh", "error": "Unexpected crt.sh response", "subdomains": []}
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            host = clean_hostname(name, domain)
            if host:
                subdomains.add(host)
    return {"source": "crt.sh", "subdomains": sorted(subdomains)}


def hackertarget_subdomains(domain: str) -> dict:
    text = fetch_text(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30)
    subdomains = set()
    records = []
    if text.startswith("ERROR") or "API count exceeded" in text:
        return {"source": "hackertarget", "error": text, "subdomains": []}
    for line in text.splitlines():
        parts = line.split(",")
        if len(parts) == 2:
            host = clean_hostname(parts[0], domain)
            ip = parts[1].strip()
            if host:
                subdomains.add(host)
                records.append({"host": host, "ip": ip})
    return {"source": "hackertarget", "subdomains": sorted(subdomains), "records": records[:200]}


def urlscan_lookup(domain: str) -> dict:
    data = fetch_json(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100", timeout=30)
    subdomains = set()
    results = []
    if not isinstance(data, dict):
        return {"source": "urlscan", "error": "Unexpected URLScan response", "subdomains": [], "results": []}
    if data.get("error"):
        return {"source": "urlscan", "error": data.get("error"), "subdomains": [], "results": []}
    for item in data.get("results", []):
        page = item.get("page", {})
        task = item.get("task", {})
        page_domain = clean_hostname(page.get("domain", ""), domain)
        if page_domain:
            subdomains.add(page_domain)
        results.append({
            "source": "urlscan",
            "url": page.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "asn": page.get("asn"),
            "server": page.get("server"),
            "title": page.get("title"),
            "date": task.get("time"),
        })
    return {"source": "urlscan", "subdomains": sorted(subdomains), "results": results[:100]}


def wayback_urls(domain: str) -> dict:
    urls = []
    seen = set()
    for pattern in [f"{domain}/*", f"*.{domain}/*"]:
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={pattern}"
            "&output=json&fl=original,statuscode,mimetype,timestamp"
            "&collapse=urlkey&filter=statuscode:200&limit=1000"
        )
        data = fetch_json(url, timeout=60)
        if isinstance(data, dict) and data.get("error"):
            continue
        if isinstance(data, list) and len(data) > 1:
            for row in data[1:]:
                if len(row) >= 4 and row[0] not in seen:
                    seen.add(row[0])
                    urls.append({"source": "wayback", "url": row[0], "status": row[1], "mimetype": row[2], "timestamp": row[3]})
    return {"source": "wayback", "urls": urls[:2000]}


def commoncrawl_indexes() -> list[str]:
    data = fetch_json("https://index.commoncrawl.org/collinfo.json", timeout=30)
    if not isinstance(data, list):
        return []
    return [x.get("cdx-api") for x in data[:2] if x.get("cdx-api")]


def commoncrawl_urls(domain: str) -> dict:
    urls = []
    seen = set()
    for api in commoncrawl_indexes():
        for pattern in [f"{domain}/*", f"*.{domain}/*"]:
            query = f"{api}?url={pattern}&output=json&fl=url,mime,status,timestamp&filter=status:200&limit=1000"
            text = fetch_text(query, timeout=60)
            if text.startswith("ERROR"):
                continue
            for line in text.splitlines():
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                u = row.get("url")
                if u and u not in seen:
                    seen.add(u)
                    urls.append({"source": "commoncrawl", "url": u, "mimetype": row.get("mime"), "status": row.get("status"), "timestamp": row.get("timestamp")})
    return {"source": "commoncrawl", "urls": urls[:2000]}


def alienvault_otx_urls(domain: str) -> dict:
    data = fetch_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1", timeout=30)
    urls = []
    if not isinstance(data, dict) or data.get("error"):
        return {"source": "alienvault_otx", "urls": [], "error": data.get("error") if isinstance(data, dict) else "unexpected_response"}
    for item in data.get("url_list", []):
        u = item.get("url")
        if u:
            urls.append({"source": "alienvault_otx", "url": u, "mimetype": None, "status": None, "timestamp": item.get("date")})
    return {"source": "alienvault_otx", "urls": urls[:500]}


def urlscan_urls(urlscan_data: dict) -> dict:
    urls = []
    for item in urlscan_data.get("results", []):
        u = item.get("url")
        if u:
            urls.append({"source": "urlscan", "url": u, "mimetype": None, "status": None, "timestamp": item.get("date")})
    return {"source": "urlscan", "urls": urls}
