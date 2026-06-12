"""Content-discovery phase — directory/file brute forcing with ffuf.

Runs against each live URL from the probe phase. Wordlist is configurable in
the scan profile; defaults to SecLists if present, else a tiny built-in list.
"""
from __future__ import annotations

import json
import os

from wstrike.core import proxy, runner, tools
from wstrike.core.console import good, info, warn
from wstrike.core.context import Context, Finding
from wstrike.modules.base import Module

_SECLISTS_DEFAULT = "/usr/share/seclists/Discovery/Web-Content/common.txt"
_FALLBACK_WORDS = [
    "admin", "login", "robots.txt", ".git/HEAD", ".env", "backup",
    "api", "config", "dashboard", "phpinfo.php", "wp-admin", "uploads",
    "server-status", "actuator", "swagger", "test",
]


class ContentDiscovery(Module):
    name = "content-discovery"
    phase = "content"
    requires = ["ffuf"]
    intrusive = True
    description = "Directory & file discovery (ffuf)"

    async def run(self, ctx: Context) -> None:
        wordlist = self._wordlist(ctx)
        ext = self.options.get("extensions", "")
        mc = self.options.get("match_codes", "200,204,301,302,307,401,403")
        # In auto mode honour the RoE rate ceiling; manual uses the profile value.
        rate = ctx.roe.rate_limit if ctx.mode == "auto" else self.options.get("rate", 0)

        for base in ctx.live_urls():
            if not ctx.roe.allows(base):
                warn(f"Skipping out-of-scope/denied base: {base}")
                continue
            ffuf = tools.resolve("ffuf")
            out_file = ctx.artifact_path(f"ffuf_{_slug(base)}.json")
            cmd = [
                ffuf, "-u", f"{base.rstrip('/')}/FUZZ",
                "-w", wordlist, "-mc", mc, "-ac", "-t", "40",
                "-of", "json", "-o", str(out_file), "-s",
            ]
            if ext:
                cmd += ["-e", ext]
            if rate:
                cmd += ["-rate", str(rate)]
            cmd += ctx.auth.h_args("-H") + proxy.tool_args("ffuf", ctx.proxy)

            info(f"Fuzzing {base} ({os.path.basename(wordlist)})")
            res = await runner.run(cmd, timeout=self.options.get("timeout", 600))
            if not res.ok and not out_file.exists():
                warn(f"ffuf failed on {base}: {res.stderr.strip()[:160]}")
                continue

            hits = [h for h in self._parse(out_file) if ctx.roe.path_allowed(h["url"])]
            for hit in hits:
                ctx.add_finding(
                    Finding(
                        title=f"Discovered path: {hit['url']}",
                        severity="low" if hit["status"] in (401, 403) else "info",
                        module=self.name,
                        target=hit["url"],
                        evidence=f"HTTP {hit['status']} ({hit['length']} bytes)",
                        metadata=hit,
                    )
                )
            good(f"{len(hits)} path(s) on {base}")

    def _wordlist(self, ctx: Context) -> str:
        configured = self.options.get("wordlist")
        if configured and os.path.exists(configured):
            return configured
        # Tech-aware: if probe detected a CMS/stack with a tailored wordlist, use it.
        for wl in ctx.data.get("tech_wordlists", []):
            if os.path.exists(wl):
                info(f"Tech-aware wordlist: {os.path.basename(wl)}")
                return wl
        if os.path.exists(_SECLISTS_DEFAULT):
            return _SECLISTS_DEFAULT
        # write the tiny fallback list into the workdir
        path = ctx.artifact_path("fallback_wordlist.txt")
        path.write_text("\n".join(_FALLBACK_WORDS) + "\n")
        return str(path)

    @staticmethod
    def _parse(out_file) -> list[dict]:
        try:
            data = json.loads(out_file.read_text())
        except (OSError, json.JSONDecodeError):
            return []
        results = []
        for r in data.get("results", []):
            results.append(
                {
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words": r.get("words", 0),
                }
            )
        return results


def _slug(url: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in url)[:48]
