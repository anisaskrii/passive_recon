import json
from pathlib import Path
from urllib.parse import quote_plus

from .utils import compact_json, html_escape


def google_dorks(domain: str) -> list[dict]:
    dorks = [
        f"site:{domain}",
        f"site:{domain} ext:pdf",
        f"site:{domain} inurl:login",
        f"site:{domain} inurl:admin",
        f"site:{domain} filetype:xls OR filetype:xlsx",
        f"site:github.com {domain}",
    ]
    return [{"query": d, "url": f"https://www.google.com/search?q={quote_plus(d)}"} for d in dorks]


def risk_summary(results: dict) -> list[dict]:
    findings = []
    email = results.get("email_security", {})
    if not email.get("dmarc_found"):
        findings.append({"severity": "medium", "title": "DMARC not found", "source": "dns", "evidence": "_dmarc TXT record not found"})
    if not email.get("spf_found"):
        findings.append({"severity": "medium", "title": "SPF not found", "source": "dns", "evidence": "No TXT record containing v=spf1"})
    if not email.get("caa_found"):
        findings.append({"severity": "low", "title": "CAA not found", "source": "dns", "evidence": "No CAA record found"})
    for item in results.get("archive_analysis", {}).get("interesting_urls", []):
        if item["category"] in ["admin", "auth", "api", "sensitive_files"]:
            findings.append({"severity": "low", "title": f"Interesting archived URL: {item['category']}", "source": item.get("source"), "evidence": item.get("url")})
    for missing in results.get("security_headers", {}).get("missing", []):
        findings.append({"severity": "low", "title": f"Missing security header: {missing}", "source": "http_headers", "evidence": results.get("security_headers", {}).get("final_url")})
    for row in results.get("ip_enrichment", {}).get("results", []):
        sub = row.get("subdomain")
        for item in row.get("ip_enrichment", []):
            for vuln in item.get("shodan_internetdb", {}).get("vulns", []):
                findings.append({"severity": "high", "title": f"Shodan InternetDB vulnerability hint: {vuln}", "source": "shodan_internetdb", "evidence": f"{sub} -> {item.get('ip')}"})
    return findings[:300]


def render_table(data: dict) -> str:
    rows = ""
    for key, value in data.items():
        rows += f"""
        <tr>
          <td>{html_escape(key)}</td>
          <td><pre>{html_escape(compact_json(value))}</pre></td>
        </tr>
        """
    return f"<table>{rows}</table>"


def section(title: str, body: str) -> str:
    return f"<section><h2>{html_escape(title)}</h2>{body}</section>"


def generate_html(results: dict) -> str:
    css = """
    body { font-family: Arial, sans-serif; margin: 40px; background: #f8f9fb; color: #111827; }
    section { background: white; border: 1px solid #e5e7eb; border-radius: 10px; padding: 18px; margin-bottom: 18px; }
    table { width: 100%; border-collapse: collapse; }
    td { border: 1px solid #e5e7eb; padding: 8px; vertical-align: top; }
    pre { white-space: pre-wrap; word-break: break-word; }
    .note { background: #fff7ed; border: 1px solid #fed7aa; padding: 12px; border-radius: 8px; }
    """
    summary = {
        "domain": results["domain"],
        "generated_at": results["generated_at"],
        "subdomains": len(results.get("subdomains", [])),
        "resolved_ips": results.get("ip_enrichment", {}).get("ip_count", 0),
        "hunter_emails": len(results.get("hunter", {}).get("emails", [])),
        "url_corpus": results.get("url_corpus", {}).get("count", 0),
        "documents": len(results.get("archive_analysis", {}).get("documents", [])),
        "javascript_files": len(results.get("archive_analysis", {}).get("javascript_files", [])),
        "risk_findings": len(results.get("risk_findings", [])),
    }
    return f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"><title>Recon Report - {html_escape(results['domain'])}</title><style>{css}</style></head>
    <body>
      <h1>Recon Report: {html_escape(results['domain'])}</h1>
      <div class="note">
        Passive/OSINT sources: RDAP, raw WHOIS fallback, DNS, Hunter.io, crt.sh, HackerTarget, URLScan, Wayback, Common Crawl, AlienVault OTX, IP RDAP, and Shodan InternetDB.
        Optional active checks: httpx, WhatWeb, and security headers. NVD output is candidate matching, not confirmation.
      </div>
      {section('Summary', render_table(summary))}
      {section('Domain Registration', render_table(results.get('whois', {})))}
      {section('DNS', render_table(results.get('dns', {})))}
      {section('Email Security', render_table(results.get('email_security', {})))}
      {section('Hunter.io', render_table(results.get('hunter', {})))}
      {section('Subdomains', render_table({'subdomains': results.get('subdomains', [])}))}
      {section('IP Enrichment', render_table(results.get('ip_enrichment', {})))}
      {section('URL Corpus', render_table(results.get('url_corpus', {})))}
      {section('URL Analysis', render_table(results.get('archive_analysis', {})))}
      {section('Technology - httpx', render_table(results.get('httpx_tech', {})))}
      {section('Technology - WhatWeb', render_table(results.get('whatweb_tech', {})))}
      {section('Merged Technology Inventory', render_table(results.get('technology_inventory', {})))}
      {section('Technology CVEs - NVD Candidates', render_table(results.get('technology_cves', {})))}
      {section('Security Headers', render_table(results.get('security_headers', {})))}
      {section('Risk Findings', render_table({'risk_findings': results.get('risk_findings', [])}))}
      {section('Raw Sources', render_table(results.get('sources', {})))}
    </body>
    </html>
    """


def save_report(results: dict):
    outdir = Path("reports") / results["domain"].replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "report.json"
    html_path = outdir / "report.html"
    json_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    html_path.write_text(generate_html(results), encoding="utf-8")
    return json_path, html_path
