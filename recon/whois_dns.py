import re
import socket

import dns.resolver

from .utils import fetch_json

try:
    import whois
except Exception:
    whois = None


def _normalize_value(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        normalized = []
        for item in value:
            if item is None:
                continue
            if hasattr(item, "isoformat"):
                normalized.append(item.isoformat())
            else:
                normalized.append(str(item).strip())
        return normalized
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value).strip()


def _extract_rdap_structured(data: dict) -> dict:
    structured = {
        "domain_name": data.get("ldhName") or data.get("handle"),
        "status": _normalize_value(data.get("status")) or [],
        "name_servers": [],
        "events": {},
        "entities": [],
    }

    for ns in data.get("nameservers", []):
        if isinstance(ns, dict) and ns.get("ldhName"):
            structured["name_servers"].append(ns["ldhName"])
        elif isinstance(ns, str):
            structured["name_servers"].append(ns)

    for event in data.get("events", []):
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action and date:
            structured["events"][action] = date

    for entity in data.get("entities", []):
        structured["entities"].append({
            "handle": entity.get("handle"),
            "roles": entity.get("roles"),
            "vcardArray": entity.get("vcardArray"),
        })

    return structured


def _extract_python_whois_structured(data: dict) -> dict:
    structured = {}
    for key, value in data.items():
        if key in ["name_servers", "status", "emails", "domain_name"]:
            structured[key] = _normalize_value(value) or []
        elif key in ["creation_date", "expiration_date", "updated_date"]:
            structured[key] = _normalize_value(value)
        elif key in ["registrar", "whois_server", "referral_url", "dnssec", "name", "org", "address", "city", "state", "zipcode", "country"]:
            normalized = _normalize_value(value)
            structured[key] = normalized if normalized else None
        else:
            if value not in [None, "", [], {}]:
                structured[key] = _normalize_value(value)
    return structured


def _parse_raw_whois_text(raw: str) -> dict:
    normalized = raw.replace("\r", "")
    structured = {}
    name_servers = []
    emails = []

    def normalize_key(key: str) -> str:
        return key.strip().lower().replace(" ", "_").replace("-", "_")

    for line in normalized.splitlines():
        line = line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = normalize_key(key)
        value = value.strip()
        if not key:
            continue

        if key == "nserver" or key == "name_server":
            name_servers.append(value)
        if key in ["email", "emails"]:
            emails.append(value)
        if key in structured:
            existing = structured[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                structured[key] = [existing, value]
        else:
            structured[key] = value

    if name_servers:
        structured["name_servers"] = name_servers
    if emails:
        structured["emails"] = list(dict.fromkeys(emails))

    return structured


def raw_whois(domain: str, server: str | None = None) -> dict:
    tld = domain.rsplit(".", 1)[-1].lower()
    whois_servers = {
        "tn": "whois.ati.tn",
        "ru": "whois.tcinet.ru",
        "ca": "whois.cira.ca",
        "us": "whois.nic.us",
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
    }
    server = server or whois_servers.get(tld, "whois.iana.org")
    try:
        with socket.create_connection((server, 43), timeout=15) as s:
            s.send((domain + "\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
        raw_text = response.decode(errors="replace").strip()
        return {
            "source": "raw_whois",
            "server": server,
            "raw": raw_text,
            "structured": _parse_raw_whois_text(raw_text),
        }
    except Exception as e:
        return {"source": "raw_whois", "server": server, "error": str(e)}


def domain_rdap_lookup(domain: str) -> dict:
    data = fetch_json(f"https://rdap.org/domain/{domain}", timeout=30)
    if isinstance(data, dict) and data.get("error"):
        return {"source": "domain_rdap", "error": data.get("error"), "body": data.get("body")}
    if isinstance(data, dict) and data.get("status") == "not_found":
        return {"source": "domain_rdap", "error": "not_found"}
    return {"source": "domain_rdap", "data": data}


def whois_lookup(domain: str) -> dict:
    rdap = domain_rdap_lookup(domain)
    if not rdap.get("error"):
        rdap_data = rdap.get("data") if isinstance(rdap, dict) else {}
        return {
            "source": "domain_rdap",
            "data": rdap_data,
            "structured": _extract_rdap_structured(rdap_data),
        }
    if domain.endswith(".tn") or domain.endswith(".ru"):
        raw = raw_whois(domain)
        return {"source": "raw_whois_fallback", "rdap_error": rdap, "raw_whois": raw}
    if whois:
        try:
            data = whois.whois(domain)
            parsed = {k: v for k, v in data.items() if v not in [None, "", [], {}]}
            if parsed:
                return {
                    "source": "python_whois_fallback",
                    "rdap_error": rdap,
                    "data": parsed,
                    "structured": _extract_python_whois_structured(parsed),
                }
        except Exception as e:
            raw = raw_whois(domain)
            return {"source": "python_whois_error", "rdap_error": rdap, "error": str(e), "raw_whois": raw}
    raw = raw_whois(domain)
    return {"source": "raw_whois_fallback", "rdap_error": rdap, "raw_whois": raw}


def dns_lookup(domain: str) -> dict:
    record_types = ["A", "AAAA", "NS", "MX", "TXT", "CAA", "SOA"]
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 6
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(a).strip('"') for a in answers]
        except dns.resolver.NoAnswer:
            results[rtype] = []
        except Exception as e:
            results[rtype] = [f"ERROR: {e}"]
    return results


def email_security(domain: str, dns_data: dict) -> dict:
    txt = dns_data.get("TXT", [])
    caa = dns_data.get("CAA", [])
    spf = [x for x in txt if "v=spf1" in x.lower()]
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = [str(a).strip('"') for a in answers]
    except Exception:
        dmarc = []
    return {
        "spf_found": bool(spf),
        "spf_records": spf,
        "dmarc_found": bool(dmarc),
        "dmarc_records": dmarc,
        "caa_found": bool(caa),
        "caa_records": caa,
    }
