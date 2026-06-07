import json
import re
import subprocess

import requests


def run_httpx_tech_detect(domain: str) -> dict:
    try:
        cmd = ["httpx", "-u", f"https://{domain}", "--tech-detect", "-json", "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return {"status": "error", "error": result.stderr.strip() or result.stdout.strip(), "tech": []}
        output = result.stdout.strip()
        if not output:
            return {"status": "empty", "tech": []}
        data = json.loads(output.splitlines()[0])
        return {"status": "ok", "mode": "active_low_noise", "url": data.get("url"), "host": data.get("host"), "tech": data.get("tech", []), "webserver": data.get("webserver"), "title": data.get("title"), "status_code": data.get("status_code")}
    except FileNotFoundError:
        return {"status": "skipped", "reason": "httpx is not installed or not in PATH", "tech": []}
    except Exception as e:
        return {"status": "error", "error": str(e), "tech": []}


def run_whatweb(domain: str) -> dict:
    try:
        cmd = ["whatweb", f"https://{domain}", "--log-json=-", "--no-errors"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if result.returncode != 0:
            return {"status": "error", "error": result.stderr.strip() or result.stdout.strip(), "tech": []}
        output = result.stdout.strip()
        if not output:
            return {"status": "empty", "tech": []}
        data = json.loads(output)
        if isinstance(data, list) and data:
            plugins = data[0].get("plugins", {})
            tech = []
            for name, details in plugins.items():
                versions = details.get("version") or []
                if versions:
                    for v in versions:
                        tech.append(f"{name}:{v}")
                else:
                    tech.append(name)
            return {"status": "ok", "mode": "active_low_noise", "target": data[0].get("target"), "http_status": data[0].get("http_status"), "tech": sorted(set(tech)), "plugins": plugins}
        return {"status": "raw", "raw": output, "tech": []}
    except FileNotFoundError:
        return {"status": "skipped", "reason": "WhatWeb is not installed or not in PATH", "tech": []}
    except Exception as e:
        return {"status": "error", "error": str(e), "tech": []}


def security_headers(domain: str) -> dict:
    wanted = ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"]
    try:
        r = requests.get(f"https://{domain}", timeout=15, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        headers = {k.lower(): v for k, v in r.headers.items()}
        return {"status": "ok", "mode": "active_low_noise", "final_url": r.url, "headers": {h: headers.get(h) for h in wanted}, "missing": [h for h in wanted if h not in headers]}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def merge_technologies(*tech_sources: dict) -> dict:
    tech = set()
    for source in tech_sources:
        for item in source.get("tech", []):
            if item:
                tech.add(str(item).strip())
    return {"source": "merged_technology_inventory", "tech": sorted(tech)}


def extract_name_version(tech: str):
    tech = str(tech).strip()
    patterns = [r"^(.+?):([0-9][A-Za-z0-9_.\-]+)$", r"^(.+?)\s+([0-9][A-Za-z0-9_.\-]+)$"]
    for pattern in patterns:
        m = re.match(pattern, tech)
        if m:
            return m.group(1).strip(), m.group(2).strip()
    return tech, None
