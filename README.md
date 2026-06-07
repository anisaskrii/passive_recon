# Passive Recon Pipeline

Modular passive/OSINT recon pipeline with optional low-noise active checks.

## Install

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows PowerShell
pip install -r requirements.txt
```

Optional tools for `--active`:

```bash
# ProjectDiscovery httpx
# WhatWeb
```

## Usage

```bash
python main.py example.com
python main.py example.com --active
```

### API mode

Install the new dependencies and then run:

```bash
uvicorn api:app --host 0.0.0.0 --port 8000
```

Requests:

```bash
curl "http://127.0.0.1:8000/recon/example.com"
curl "http://127.0.0.1:8000/recon/example.com?active=true"
curl -X POST "http://127.0.0.1:8000/recon" -H "Content-Type: application/json" -d '{"domain":"example.com","active":true}'
```

Reports are written to:

```text
reports/<domain>/report.json
reports/<domain>/report.html
```

## Pipeline

```text
Domain normalization
WHOIS/RDAP
DNS + email security
Hunter.io
crt.sh + HackerTarget + URLScan
Wayback + Common Crawl + AlienVault OTX URL corpus
Extract hostnames from full URL corpus
Merge subdomains
Analyze URL corpus for documents, JS, interesting URLs
Resolve subdomains + IP RDAP + Shodan InternetDB
Optional httpx + WhatWeb + security headers
NVD candidate lookup for versioned technologies
HTML/JSON report
```

## Notes

Subdomain discovery and DNS resolution are separated. A subdomain can be discovered from passive sources but fail resolution because it is historical, removed, or internal-only.

CVE results are candidates based on extracted product/version strings. They are not confirmed vulnerabilities.
