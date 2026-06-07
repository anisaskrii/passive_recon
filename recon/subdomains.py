from .utils import clean_hostname, host_from_url


def merge_subdomains(*sources: dict) -> list[str]:
    merged = set()
    for source in sources:
        for sub in source.get("subdomains", []):
            host = clean_hostname(sub)
            if host:
                merged.add(host)
    return sorted(merged)


def merge_url_corpus(*sources: dict) -> dict:
    merged = []
    seen = set()
    for source in sources:
        for item in source.get("urls", []):
            u = item.get("url")
            if not u or u in seen:
                continue
            seen.add(u)
            merged.append(item)
    return {"source": "merged_url_corpus", "count": len(merged), "urls": merged}


def extract_subdomains_from_url_corpus(domain: str, url_corpus: dict) -> dict:
    subdomains = set()
    for item in url_corpus.get("urls", []):
        host = host_from_url(item.get("url", ""))
        host = clean_hostname(host, domain) if host else None
        if host:
            subdomains.add(host)
    return {"source": "url_corpus_hostname_extraction", "subdomains": sorted(subdomains)}
