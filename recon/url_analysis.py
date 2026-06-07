def analyze_url_corpus(url_corpus: dict) -> dict:
    items = url_corpus.get("urls", [])
    categories = {
        "admin": ["admin", "administrator", "dashboard", "backend"],
        "auth": ["login", "signin", "sso", "oauth", "auth"],
        "api": ["/api/", "graphql", "swagger", "openapi"],
        "sensitive_files": [".env", ".git", ".sql", ".bak", "backup", "config"],
        "dev": ["dev", "test", "staging", "debug"],
    }
    documents = []
    js_files = []
    interesting = []
    doc_extensions = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".txt", ".rtf")
    doc_mime_keywords = ["pdf", "msword", "officedocument", "excel", "powerpoint", "spreadsheet", "presentation", "text/csv"]
    for item in items:
        u = item.get("url", "")
        lower = u.lower()
        clean_url = lower.split("?")[0].split("#")[0]
        mimetype = (item.get("mimetype") or "").lower()
        for category, keywords in categories.items():
            if any(k in lower for k in keywords):
                interesting.append({"source": item.get("source"), "category": category, "url": u, "timestamp": item.get("timestamp")})
        if clean_url.endswith(doc_extensions) or any(k in mimetype for k in doc_mime_keywords):
            documents.append(item)
        if (
            clean_url.endswith(".js")
            or ".js?" in lower
            or "javascript" in mimetype
            or "/js/" in lower
            or "bundle" in lower
            or "runtime" in lower
            or "webpack" in lower
        ):
            js_files.append(item)
    return {"interesting_urls": interesting[:300], "documents": documents[:300], "javascript_files": js_files[:300]}
