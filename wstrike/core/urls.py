"""Small URL/host helpers shared across modules."""
from __future__ import annotations

from urllib.parse import urlparse


def hostname(target: str) -> str:
    """Extract the host from a URL, host:port, or bare hostname."""
    t = target if "://" in target else f"//{target}"
    return (urlparse(t, "http").hostname or target).lower()


def base_domain(host: str) -> str:
    """Naive registrable-domain extractor (last two labels).

    Good enough for v1 — does not handle multi-part TLDs like co.uk.
    """
    host = hostname(host)
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def as_url(target: str, scheme: str = "https") -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"{scheme}://{target}"
