"""Rules of Engagement — the safety envelope for `auto` mode.

In `manual` mode the operator gates intrusive modules by hand. In `auto` mode
everything runs, but bounded by these rules: only touch in-scope hosts, never
touch denied paths, and respect a global rate limit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

from wstrike.core.urls import hostname
from urllib.parse import urlparse


@dataclass
class RulesOfEngagement:
    scope_allow: list[str] = field(default_factory=list)  # e.g. ["*.acme.com"]
    deny_paths: list[str] = field(default_factory=list)    # e.g. ["/logout", "/*/delete*"]
    rate_limit: int = 150                                   # requests/sec ceiling
    max_subdomains: int = 0                                 # 0 = unlimited

    @classmethod
    def from_profile(cls, profile: dict | None) -> "RulesOfEngagement":
        roe = (profile or {}).get("roe") or {}
        return cls(
            scope_allow=list(roe.get("scope_allow") or []),
            deny_paths=list(roe.get("deny_paths") or []),
            rate_limit=int(roe.get("rate_limit", 150)),
            max_subdomains=int(roe.get("max_subdomains", 0)),
        )

    def host_in_scope(self, host: str) -> bool:
        if not self.scope_allow:
            return True  # no allowlist defined = everything in scope
        host = hostname(host)
        return any(fnmatch(host, p.lower()) for p in self.scope_allow)

    def url_in_scope(self, url: str) -> bool:
        return self.host_in_scope(hostname(url))

    def path_allowed(self, url: str) -> bool:
        path = urlparse(url if "://" in url else f"//{url}", "http").path or "/"
        return not any(fnmatch(path, p) for p in self.deny_paths)

    def allows(self, url: str) -> bool:
        """A URL is touchable if it's in scope and its path isn't denied."""
        return self.url_in_scope(url) and self.path_allowed(url)
