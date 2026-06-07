# Passive Recon Pipeline with Optional Active Checks

Modular reconnaissance and OSINT pipeline focused on structured intelligence collection, low-noise enrichment, and explainable technology fingerprinting.

## Features

### Passive Collection

* WHOIS / RDAP lookup
* DNS enumeration
* SPF / DKIM / DMARC analysis (Email security )
* Hunter.io email enrichment
* Passive subdomain discovery:

  * crt.sh
  * HackerTarget
  * URLScan
* URL corpus collection:

  * Wayback Machine
  * Common Crawl
  * AlienVault OTX
* Historical URL analysis
* Document discovery
* JavaScript asset extraction
* Subdomain resolution
* IP enrichment
* Shodan InternetDB enrichment:

  * open ports
  * CPEs
  * candidate CVEs
  * service tags

### Optional Active Checks

Enabled using `--active`.

Low-noise HTTP probing using:

* httpx technology detection
* WhatWeb fingerprinting
* Security header analysis

These checks send requests to the target.

## Installation

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```

### Create Virtual Environment

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

## Optional External Tools

The following tools are used only when `--active` is enabled.

### httpx (ProjectDiscovery)

Install:

https://github.com/projectdiscovery/httpx

Verify:

```bash
httpx -version
```

### WhatWeb

Install:

https://github.com/urbanadventurer/WhatWeb

Verify:

```bash
whatweb --version
```

## Environment Variables

Create a `.env` file in the project root:

```env
HUNTER_API_KEY=your_hunter_api_key
```

## Usage

### Passive Recon

```bash
python main.py example.com
```

### Passive + Active Checks

```bash
python main.py example.com --active
```

## API Mode

Start the API server:

```bash
python -m uvicorn api:app --reload
```

Default server:

```text
http://127.0.0.1:8000
```

### Health Check

```bash
curl "http://127.0.0.1:8000/health"
```

### Passive Recon Request

```bash
curl "http://127.0.0.1:8000/recon/example.com"
```

### Recon with Active Checks

```bash
curl "http://127.0.0.1:8000/recon/example.com?active=true"
```

### Include Raw Collector Data

```bash
curl "http://127.0.0.1:8000/recon/example.com?include_raw=true"
```

### POST Request

```bash
curl -X POST "http://127.0.0.1:8000/recon" \
-H "Content-Type: application/json" \
-d '{"domain":"example.com","active":true}'
```

## JSON Response Structure

```json
{
  "domain": "...",
  "generated_at": "...",

  "summary": {},
  "whois": {},
  "dns": {},
  "email_security": {},
  "hunter": {},

  "subdomains": [],

  "ip_enrichment": {
    "ip_count": 0,
    "ips": [],
    "shodan_summary": {},
    "shodan_internetdb": []
  },

  "archive_analysis": {
    "counts": {},
    "documents": [],
    "javascript_files": [],
    "interesting_urls": []
  },

  "technology_inventory": [],
  "security_headers": {},
  "metadata": {}
}
```

## Pipeline

### Passive Collection Pipeline

```text
Domain normalization
WHOIS / RDAP
DNS enumeration
Email security analysis
Hunter.io enrichment
crt.sh + HackerTarget + URLScan
Wayback + Common Crawl + AlienVault OTX
Historical URL corpus analysis
Subdomain extraction and merging
Document and JavaScript extraction
Subdomain resolution
IP enrichment
Shodan InternetDB enrichment
```

### Optional Active Pipeline

```text
httpx technology detection
WhatWeb fingerprinting
Security header analysis
```

## Notes

Subdomain discovery and DNS resolution are separated.

A subdomain may appear in passive sources while failing DNS resolution because it is:

* historical
* internal-only
* deprecated
* no longer reachable

Technology fingerprinting is inference-based and depends on externally observable indicators such as:

* HTTP headers
* HTML metadata
* JavaScript paths
* cookies
* favicon fingerprints

Some technologies may be hidden behind:

* CDNs
* reverse proxies
* WAFs
* frontend frameworks

Shodan InternetDB findings and NVD mappings are informational candidate findings only.

They do not confirm:

* exploitability
* successful verification
* vulnerability presence

Version-based CVE enrichment depends on extracted product/version strings and may contain false positives or incomplete mappings.

## Recommended Production Usage

Default production mode:

```text
Passive collection only
Raw collector data disabled
Filtered URL intelligence
Low-noise enrichment
```

Recommended API usage:

```text
/recon/example.com
```

Analyst/debug mode:

```text
/recon/example.com?include_raw=true
```

