"""Authentication config — carried on Context and injected into every module so
the whole pipeline can test the surface *behind* a login.

Each wrapped tool takes auth slightly differently, so AuthConfig emits the
correct flag form per tool rather than assuming one shape fits all.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AuthConfig:
    headers: list[str] = field(default_factory=list)   # ["Key: Value", ...]
    cookies: str = ""                                   # "a=b; c=d"
    user_agent: str = ""

    @classmethod
    def from_profile(cls, profile: dict | None) -> "AuthConfig":
        a = (profile or {}).get("auth") or {}
        headers = list(a.get("headers") or [])
        if a.get("bearer_token"):
            headers.append(f"Authorization: Bearer {a['bearer_token']}")
        cookies = a.get("cookies") or ""
        if isinstance(cookies, dict):
            cookies = "; ".join(f"{k}={v}" for k, v in cookies.items())
        return cls(headers=headers, cookies=str(cookies), user_agent=a.get("user_agent", ""))

    def merge_cli(self, headers: list[str] | None, cookie: str | None) -> "AuthConfig":
        if headers:
            self.headers.extend(headers)
        if cookie:
            self.cookies = cookie
        return self

    def active(self) -> bool:
        return bool(self.headers or self.cookies or self.user_agent)

    def has_ua(self) -> bool:
        return bool(self.user_agent)

    def summary(self) -> str:
        bits = []
        if self.headers:
            bits.append(f"{len(self.headers)} header(s)")
        if self.cookies:
            bits.append("cookies")
        if self.user_agent:
            bits.append("custom UA")
        return ", ".join(bits) or "none"

    # --- internal -------------------------------------------------------

    def _has(self, name: str) -> bool:
        return any(h.lower().startswith(name.lower() + ":") for h in self.headers)

    def _lines(self, include_cookie: bool = True, include_ua: bool = True) -> list[str]:
        lines = list(self.headers)
        if include_cookie and self.cookies and not self._has("cookie"):
            lines.append(f"Cookie: {self.cookies}")
        if include_ua and self.user_agent and not self._has("user-agent"):
            lines.append(f"User-Agent: {self.user_agent}")
        return lines

    # --- tool-specific flag forms --------------------------------------

    def h_args(self, flag: str = "-H") -> list[str]:
        """ProjectDiscovery tools + ffuf: repeated `-H "Key: Value"` (cookie/UA
        folded into headers)."""
        out: list[str] = []
        for line in self._lines():
            out += [flag, line]
        return out

    def whatweb_args(self) -> list[str]:
        out: list[str] = []
        for line in self.headers:
            out += ["--header", line]
        if self.cookies:
            out += ["--cookie", self.cookies]
        if self.user_agent:
            out += ["--user-agent", self.user_agent]
        return out

    def dalfox_args(self) -> list[str]:
        out: list[str] = []
        for line in self.headers:
            out += ["-H", line]
        if self.cookies:
            out += ["--cookies", self.cookies]   # note: dalfox uses plural
        if self.user_agent:
            out += ["--user-agent", self.user_agent]
        return out

    def sqlmap_args(self) -> list[str]:
        out: list[str] = []
        hdrs = list(self.headers)
        if self.user_agent:
            hdrs.append(f"User-Agent: {self.user_agent}")
        if hdrs:
            out.append("--headers=" + "\\n".join(hdrs))   # sqlmap splits on \n
        if self.cookies:
            out.append(f"--cookie={self.cookies}")
        return out
