"""Upstream proxy support — route every tool's traffic through Burp/mitmproxy
for manual follow-up. Each tool spells its proxy flag differently, so we emit
the right one per tool (whatweb wants host:port, the rest want a full URL).
"""
from __future__ import annotations

from urllib.parse import urlparse

# tool -> (flag, value-kind)
_FLAGS: dict[str, tuple[str, str]] = {
    "whatweb": ("--proxy", "hostport"),
    "katana": ("-proxy", "url"),
    "nuclei": ("-proxy", "url"),
    "ffuf": ("-x", "url"),
    "sqlmap": ("--proxy", "url"),
    "dalfox": ("--proxy", "url"),
    "curl": ("-x", "url"),
}


def _hostport(proxy: str) -> str:
    u = urlparse(proxy if "://" in proxy else f"http://{proxy}")
    return u.netloc or proxy


def tool_args(tool: str, proxy: str) -> list[str]:
    """Argv fragment to point `tool` at the proxy, or [] if no proxy/unsupported."""
    if not proxy or tool not in _FLAGS:
        return []
    flag, kind = _FLAGS[tool]
    return [flag, _hostport(proxy) if kind == "hostport" else proxy]
