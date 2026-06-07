import dns.resolver
from ipwhois import IPWhois

from .utils import fetch_json


def resolve_ips(hostname: str) -> list[str]:
    ips = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    for rtype in ["A", "AAAA"]:
        try:
            answers = resolver.resolve(hostname, rtype)
            for ans in answers:
                ips.add(str(ans))
        except Exception:
            pass
    return sorted(ips)


def ip_rdap_lookup(ip: str) -> dict:
    try:
        data = IPWhois(ip).lookup_rdap()
        return {
            "ip": ip,
            "asn": data.get("asn"),
            "asn_description": data.get("asn_description"),
            "asn_country_code": data.get("asn_country_code"),
            "network": {
                "name": data.get("network", {}).get("name"),
                "cidr": data.get("network", {}).get("cidr"),
                "country": data.get("network", {}).get("country"),
                "start_address": data.get("network", {}).get("start_address"),
                "end_address": data.get("network", {}).get("end_address"),
            },
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def shodan_internetdb_lookup(ip: str) -> dict:
    data = fetch_json(f"https://internetdb.shodan.io/{ip}", timeout=20)
    if isinstance(data, dict) and data.get("status") == "not_found":
        return {"ip": ip, "found": False, "ports": [], "cpes": [], "hostnames": [], "vulns": [], "tags": []}
    if isinstance(data, dict) and data.get("error"):
        return {"ip": ip, "found": False, "error": data.get("error"), "body": data.get("body")}
    return {"ip": ip, "found": True, "ports": data.get("ports", []), "cpes": data.get("cpes", []), "hostnames": data.get("hostnames", []), "vulns": data.get("vulns", []), "tags": data.get("tags", [])}


def subdomain_ip_enrichment(subdomains: list[str], max_subdomains: int = 100) -> dict:
    results = []
    all_ips = set()
    for subdomain in subdomains[:max_subdomains]:
        ips = resolve_ips(subdomain)
        for ip in ips:
            all_ips.add(ip)
        ip_results = [{"ip": ip, "rdap": ip_rdap_lookup(ip), "shodan_internetdb": shodan_internetdb_lookup(ip)} for ip in ips]
        results.append({"subdomain": subdomain, "resolved": bool(ips), "ips": ips, "ip_enrichment": ip_results})
    return {"source": "dns_resolution_plus_ip_rdap_plus_shodan_internetdb", "subdomains_checked": min(len(subdomains), max_subdomains), "ip_count": len(all_ips), "ips": sorted(all_ips), "results": results}
