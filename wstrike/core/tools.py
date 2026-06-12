"""Tool resolution — map a logical tool name to a real binary on disk.

Handles the well-known Kali collision where ``/usr/bin/httpx`` is the Python
httpx library CLI, while ProjectDiscovery's prober ships as ``httpx-toolkit``.
We always prefer the security tool.
"""
from __future__ import annotations

import shutil

# Logical name -> ordered list of candidate binaries (first match wins).
_ALIASES: dict[str, list[str]] = {
    "httpx": ["httpx-toolkit", "httpx"],   # prefer ProjectDiscovery build
    "nuclei": ["nuclei"],
    "ffuf": ["ffuf"],
    "subfinder": ["subfinder"],
    "whatweb": ["whatweb"],
    "katana": ["katana"],
    "dnsx": ["dnsx"],
    "naabu": ["naabu"],
    "curl": ["curl"],
}


def resolve(name: str) -> str | None:
    """Return the absolute path to the binary for a logical tool name, or None."""
    for candidate in _ALIASES.get(name, [name]):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def available(name: str) -> bool:
    return resolve(name) is not None


def missing(names: list[str]) -> list[str]:
    """Return the subset of tool names that are NOT installed."""
    return [n for n in names if not available(n)]
