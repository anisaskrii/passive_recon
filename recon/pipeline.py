from datetime import datetime, timezone
import time
import uuid

from .cves import technology_cve_enrichment
from .enrichment import subdomain_ip_enrichment
from .report import google_dorks, risk_summary, save_report
from .sources import (
    alienvault_otx_urls,
    commoncrawl_urls,
    crtsh_subdomains,
    hackertarget_subdomains,
    hunter_domain_search,
    urlscan_lookup,
    urlscan_urls,
    wayback_urls,
)
from .subdomains import extract_subdomains_from_url_corpus, merge_subdomains, merge_url_corpus
from .tech import merge_technologies, run_httpx_tech_detect, run_whatweb, security_headers
from .url_analysis import analyze_url_corpus
from .utils import normalize_domain
from .whois_dns import dns_lookup, email_security, whois_lookup

from dotenv import load_dotenv
load_dotenv()
def gather_results(domain: str, active: bool = False) -> dict:
    start = time.time()
    scan_id = uuid.uuid4().hex
    domain = normalize_domain(domain)

    whois_data = whois_lookup(domain)
    dns_data = dns_lookup(domain)
    email_data = email_security(domain, dns_data)
    hunter_data = hunter_domain_search(domain)
    crtsh_data = crtsh_subdomains(domain)
    hackertarget_data = hackertarget_subdomains(domain)
    urlscan_data = urlscan_lookup(domain)
    wayback_data = wayback_urls(domain)
    commoncrawl_data = commoncrawl_urls(domain)
    otx_url_data = alienvault_otx_urls(domain)

    url_corpus = merge_url_corpus(wayback_data, urlscan_urls(urlscan_data), commoncrawl_data, otx_url_data)
    url_corpus_subdomains = extract_subdomains_from_url_corpus(domain, url_corpus)
    subdomains = merge_subdomains(crtsh_data, hackertarget_data, urlscan_data, url_corpus_subdomains)
    archive_analysis = analyze_url_corpus(url_corpus)
    ip_enrichment = subdomain_ip_enrichment(subdomains)

    httpx_tech_data = {"status": "skipped", "reason": "Use --active to run httpx technology detection", "tech": []}
    whatweb_tech_data = {"status": "skipped", "reason": "Use --active to run WhatWeb", "tech": []}
    headers_data = {"status": "skipped", "reason": "Use --active to check security headers"}

    if active:
        httpx_tech_data = run_httpx_tech_detect(domain)
        whatweb_tech_data = run_whatweb(domain)
        headers_data = security_headers(domain)

    technology_inventory = merge_technologies(httpx_tech_data, whatweb_tech_data)
    tech_cve_data = technology_cve_enrichment(technology_inventory)

    results = {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "whois": whois_data,
        "dns": dns_data,
        "email_security": email_data,
        "hunter": hunter_data,
        "subdomains": subdomains,
        "ip_enrichment": ip_enrichment,
        "url_corpus": url_corpus,
        "archive_analysis": archive_analysis,
        "httpx_tech": httpx_tech_data,
        "whatweb_tech": whatweb_tech_data,
        "technology_inventory": technology_inventory,
        "technology_cves": tech_cve_data,
        "security_headers": headers_data,
        "google_dorks": google_dorks(domain),
        "sources": {
            "crtsh": crtsh_data,
            "hackertarget": hackertarget_data,
            "urlscan": urlscan_data,
            "wayback": wayback_data,
            "commoncrawl": commoncrawl_data,
            "alienvault_otx_urls": otx_url_data,
            "url_corpus_subdomains": url_corpus_subdomains,
        },
    }

    results["risk_findings"] = risk_summary(results)
    # metadata
    duration = round(time.time() - start, 2)
    results["metadata"] = {"scan_id": scan_id, "generated_at": results.get("generated_at"), "duration_seconds": duration, "api_version": "1.0"}
    return results


def run(domain: str, active: bool = False):
    print(f"[+] Target: {normalize_domain(domain)}")
    results = gather_results(domain, active=active)
    json_path, html_path = save_report(results)

    print(f"[+] JSON report: {json_path}")
    print(f"[+] HTML report: {html_path}")
    print(f"[+] URLs: {results.get('url_corpus', {}).get('count', 0)}")
    print(f"[+] Subdomains: {len(results.get('subdomains', []))}")
    print(f"[+] Resolved IPs: {results.get('ip_enrichment', {}).get('ip_count', 0)}")
    print(f"[+] Hunter emails: {len(results.get('hunter', {}).get('emails', []))}")
    print(f"[+] Findings: {len(results.get('risk_findings', []))}")
