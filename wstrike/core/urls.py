"""Small URL/host helpers shared across modules."""
from __future__ import annotations

from urllib.parse import urlparse


def hostname(target: str) -> str:
    """Extract the host from a URL, host:port, or bare hostname."""
    t = target if "://" in target else f"//{target}"
    return (urlparse(t, "http").hostname or target).lower()


def base_domain(host: str) -> str:
    """Registrable-domain extractor (scope-matching is safety-critical).

    Uses the Public Suffix List via ``tldextract`` when available so multi-part
    TLDs (co.uk, com.au, …) resolve correctly. Falls back to a last-two-labels
    heuristic only if tldextract isn't installed.
    """
    host = hostname(host)
    try:
        import tldextract

        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def as_url(target: str, scheme: str = "https") -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"{scheme}://{target}"
