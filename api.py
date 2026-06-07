from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=True)

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from recon.pipeline import gather_results


app = FastAPI(
    title="Recon API",
    description="Passive recon and enrichment API",
    version="1.0.0",
)


class ReconRequest(BaseModel):
    domain: str
    active: bool = False
    include_raw: bool = False
    url_limit: int = 50


def filter_interesting_urls(urls: list[dict], limit: int = 50) -> list[dict]:
    allowed_categories = {
        "admin",
        "auth",
        "api",
        "upload",
        "backup",
        "config",
    }

    blocked_patterns = [
        "utm_source=",
        "utm_medium=",
        "utm_campaign=",
        "/feed/",
        "author-sitemap.xml",
    ]

    filtered = []

    for item in urls:
        category = item.get("category")
        url = item.get("url", "").lower()

        if category not in allowed_categories:
            continue

        if any(pattern in url for pattern in blocked_patterns):
            continue

        filtered.append(item)

    return filtered[:limit]


def extract_shodan_findings(results: dict) -> tuple[list[dict], dict]:
    findings = []

    for host_result in results.get("ip_enrichment", {}).get("results", []):
        subdomain = host_result.get("subdomain")

        for item in host_result.get("ip_enrichment", []):
            shodan = item.get("shodan_internetdb", {}) or {}

            finding = {
                "subdomain": subdomain,
                "ip": item.get("ip"),
                "found": shodan.get("found", False),
                "ports": shodan.get("ports", []),
                "cpes": shodan.get("cpes", []),
                "vulns": shodan.get("vulns", []),
                "tags": shodan.get("tags", []),
                "hostnames": shodan.get("hostnames", []),
                "vuln_note": (
                    "Shodan InternetDB vulnerabilities are candidates, "
                    "not confirmed exploitability."
                ),
            }

            findings.append(finding)

    summary = {
        "hosts_found": sum(1 for x in findings if x.get("found")),
        "open_ports": sorted({
            port
            for x in findings
            for port in x.get("ports", [])
        }),
        "cpes": sorted({
            cpe
            for x in findings
            for cpe in x.get("cpes", [])
        }),
        "vulns": sorted({
            vuln
            for x in findings
            for vuln in x.get("vulns", [])
        }),
        "tags": sorted({
            tag
            for x in findings
            for tag in x.get("tags", [])
        }),
        "vuln_note": (
            "These CVEs come from Shodan InternetDB and must be manually verified."
        ),
    }

    return findings, summary


def clean_response(
    results: dict,
    include_raw: bool = False,
    url_limit: int = 50,
) -> dict:
    archive = results.get("archive_analysis", {})
    interesting_urls = archive.get("interesting_urls", [])

    filtered_interesting_urls = filter_interesting_urls(
        interesting_urls,
        limit=url_limit,
    )

    shodan_findings, shodan_summary = extract_shodan_findings(results)

    response = {
        "domain": results.get("domain"),
        "generated_at": results.get("generated_at"),

        "summary": {
            "subdomains": len(results.get("subdomains", [])),
            "resolved_ips": results.get("ip_enrichment", {}).get("ip_count", 0),
            "hunter_emails": len(results.get("hunter", {}).get("emails", [])),
            "documents": len(archive.get("documents", [])),
            "javascript_files": len(archive.get("javascript_files", [])),
            "interesting_urls": len(filtered_interesting_urls),
            "shodan_hosts_found": shodan_summary.get("hosts_found", 0),
            "shodan_open_ports": shodan_summary.get("open_ports", []),
            "shodan_cve_candidates": len(shodan_summary.get("vulns", [])),
        },

        "whois": results.get("whois", {}).get("structured", {}),

        "dns": results.get("dns", {}),

        "email_security": results.get("email_security", {}),

        "hunter": {
            "status": results.get("hunter", {}).get("status"),
            "domain": results.get("hunter", {}).get("domain"),
            "organization": results.get("hunter", {}).get("organization"),
            "pattern": results.get("hunter", {}).get("pattern"),
            "email_count": len(results.get("hunter", {}).get("emails", [])),
            "emails": results.get("hunter", {}).get("emails", []),
        },

        "subdomains": results.get("subdomains", []),

        "ip_enrichment": {
            "ip_count": results.get("ip_enrichment", {}).get("ip_count", 0),
            "ips": results.get("ip_enrichment", {}).get("ips", []),
            "shodan_summary": shodan_summary,
            "shodan_internetdb": shodan_findings,
        },

        "archive_analysis": {
            "counts": {
                "documents": len(archive.get("documents", [])),
                "javascript_files": len(archive.get("javascript_files", [])),
                "interesting_urls_raw": len(interesting_urls),
                "interesting_urls_filtered": len(filtered_interesting_urls),
            },
            "documents": archive.get("documents", [])[:url_limit],
            "javascript_files": archive.get("javascript_files", [])[:url_limit],
            "interesting_urls": filtered_interesting_urls,
        },

        "technology_inventory": results.get("technology_inventory", []),

        "security_headers": results.get("security_headers", {}),

        "metadata": results.get("metadata", {}),
    }

    if include_raw:
        response["raw"] = {
            "sources": results.get("sources", {}),
            "url_corpus": {
                "count": results.get("url_corpus", {}).get("count", 0),
            },
            "httpx_tech": results.get("httpx_tech", {}),
            "whatweb_tech": results.get("whatweb_tech", {}),
            "technology_cves": results.get("technology_cves", {}),
            "risk_findings": results.get("risk_findings", []),
        }

    return response


@app.get("/health")
def health():
    return {
        "status": "ok",
    }


@app.get("/debug/env")
def debug_env():
    import os

    return {
        "hunter_loaded": bool(os.getenv("HUNTER_API_KEY")),
        "hunter_preview": os.getenv("HUNTER_API_KEY", "")[:6],
    }


@app.get("/recon/{domain}")
def recon_get(
    domain: str,
    active: bool = Query(False),
    include_raw: bool = Query(False),
    url_limit: int = Query(50, ge=0, le=500),
):
    try:
        results = gather_results(domain, active=active)

        return clean_response(
            results,
            include_raw=include_raw,
            url_limit=url_limit,
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


@app.post("/recon")
def recon_post(request: ReconRequest):
    try:
        results = gather_results(
            request.domain,
            active=request.active,
        )

        return clean_response(
            results,
            include_raw=request.include_raw,
            url_limit=request.url_limit,
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )