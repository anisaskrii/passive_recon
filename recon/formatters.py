from typing import Any, Dict


def _limited_list(items, limit=200):
    if not isinstance(items, list):
        return []
    return items[:limit]


def format_api_response(results: Dict[str, Any], include_raw: bool = False, limit: int = 200) -> Dict[str, Any]:
    # metadata
    metadata = results.get("metadata", {})

    # summary
    summary = {
        "url_count": results.get("url_corpus", {}).get("count", 0),
        "subdomain_count": len(results.get("subdomains", [])),
        "ip_count": results.get("ip_enrichment", {}).get("ip_count", 0),
        "documents_count": len(results.get("archive_analysis", {}).get("documents", [])),
        "javascript_files_count": len(results.get("archive_analysis", {}).get("javascript_files", [])),
        "risk_findings_count": len(results.get("risk_findings", [])),
    }

    # registration / whois
    whois = results.get("whois", {}) or {}
    registration = {}
    if whois.get("structured"):
        registration = whois.get("structured")
    elif whois.get("raw_whois") and isinstance(whois.get("raw_whois"), dict):
        registration = whois.get("raw_whois", {}).get("structured", {})

    if include_raw:
        if whois.get("data"):
            registration["python_whois_raw"] = whois.get("data")
        if whois.get("raw_whois"):
            registration["raw_text"] = whois.get("raw_whois", {}).get("raw")
        if whois.get("data") and whois.get("source") == "domain_rdap":
            registration["rdap_raw"] = whois.get("data")

    # dns and email security
    dns = results.get("dns", {})
    email_security = results.get("email_security", {})

    # discovery
    discovery = {
        "subdomains": _limited_list(results.get("subdomains", []), limit),
        "subdomains_resolved": _limited_list(results.get("ip_enrichment", {}).get("results", []), limit),
        "url_corpus_summary": {"count": results.get("url_corpus", {}).get("count", 0)},
    }

    if include_raw:
        discovery["url_corpus"] = _limited_list(results.get("url_corpus", {}).get("urls", []), limit)

    # archive analysis
    archive = {
        "interesting_urls": _limited_list(results.get("archive_analysis", {}).get("interesting_urls", []), limit),
        "documents": _limited_list(results.get("archive_analysis", {}).get("documents", []), limit),
        "javascript_files": _limited_list(results.get("archive_analysis", {}).get("javascript_files", []), limit),
    }

    # ip enrichment
    ip_enrichment = {
        "ip_count": results.get("ip_enrichment", {}).get("ip_count", 0),
        "ips": _limited_list(results.get("ip_enrichment", {}).get("ips", []), limit),
        "results": _limited_list(results.get("ip_enrichment", {}).get("results", []), limit),
    }

    # technologies
    technology_inventory = _limited_list(results.get("technology_inventory", []), limit)
    technology_cves = results.get("technology_cves", {})

    # findings and sources
    findings = _limited_list(results.get("risk_findings", []), limit)
    sources = {k: {"count": (v.get("count") if isinstance(v, dict) else None), "status": (v.get("status") if isinstance(v, dict) else None)} for k, v in (results.get("sources") or {}).items()}

    response = {
        "metadata": metadata,
        "summary": summary,
        "registration": registration,
        "dns": dns,
        "email_security": email_security,
        "discovery": discovery,
        "archive": archive,
        "ip_enrichment": ip_enrichment,
        "technology_inventory": technology_inventory,
        "technology_cves": technology_cves,
        "findings": findings,
        "sources": sources,
    }

    return response
