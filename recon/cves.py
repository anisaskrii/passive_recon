from urllib.parse import quote_plus

from .tech import extract_name_version
from .utils import fetch_json


def nvd_cve_lookup(product: str, version: str) -> dict:
    if not product or not version:
        return {"status": "skipped", "reason": "No version found"}
    keyword = f"{product} {version}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote_plus(keyword)}&resultsPerPage=10"
    data = fetch_json(url, timeout=30)
    if not isinstance(data, dict) or data.get("error"):
        return {"status": "error", "query": keyword, "error": data}
    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        cves.append({"id": cve.get("id"), "published": cve.get("published"), "lastModified": cve.get("lastModified"), "cvss": cvss, "description": description[:300]})
    return {"status": "ok", "query": keyword, "count": len(cves), "cves": cves}


def technology_cve_enrichment(technology_inventory: dict) -> dict:
    results = []
    for tech in technology_inventory.get("tech", []):
        name, version = extract_name_version(tech)
        item = {"technology": tech, "name": name, "version": version}
        item["nvd"] = nvd_cve_lookup(name, version) if version else {"status": "skipped", "reason": "No version found"}
        results.append(item)
    return {"source": "nvd", "mode": "keyword_search_candidates_not_confirmed", "results": results}
