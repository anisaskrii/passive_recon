import json
import re
from urllib.parse import urlparse

import requests


HTTP_HEADERS = {"User-Agent": "Mozilla/5.0"}
HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0].strip("/")
    domain = domain.split(":")[0]
    return domain.strip(".")


def fetch_json(url: str, timeout: int = 45):
    try:
        r = requests.get(url, timeout=timeout, headers=HTTP_HEADERS)
        if r.status_code == 404:
            return {"status": "not_found"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "body": r.text[:500]}
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def fetch_text(url: str, timeout: int = 45) -> str:
    try:
        r = requests.get(url, timeout=timeout, headers=HTTP_HEADERS)
        if r.status_code != 200:
            return f"ERROR HTTP {r.status_code}: {r.text[:300]}"
        return r.text
    except Exception as e:
        return f"ERROR {e}"


def is_valid_hostname(host: str) -> bool:
    if not host:
        return False
    host = host.lower().strip().strip(".")
    if "@" in host or "*" in host or "_" in host:
        return False
    if len(host) > 253:
        return False
    return bool(HOST_RE.match(host))


def is_domain_or_subdomain(host: str, domain: str) -> bool:
    host = normalize_domain(host)
    domain = normalize_domain(domain)
    return host == domain or host.endswith("." + domain)


def clean_hostname(host: str, domain: str | None = None) -> str | None:
    if not host:
        return None
    host = host.lower().strip().strip(".")
    host = host.replace("*.", "")
    host = host.split(":")[0]
    if not is_valid_hostname(host):
        return None
    if domain and not is_domain_or_subdomain(host, domain):
        return None
    return host


def host_from_url(url: str) -> str | None:
    try:
        if url.startswith("//"):
            url = "https:" + url
        parsed = urlparse(url)
        return parsed.hostname.lower().strip(".") if parsed.hostname else None
    except Exception:
        return None


def html_escape(value) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def compact_json(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False)
