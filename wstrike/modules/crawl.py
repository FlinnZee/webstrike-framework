"""Crawl phase — active endpoint discovery with katana.

Crawls every live URL from the probe phase and records discovered endpoints in
ctx.data['crawled_urls'], which the vuln-scan phase then scans. Active traffic,
so it's marked intrusive (gated in manual mode) and respects RoE scope/deny.
"""
from __future__ import annotations

from wstrike.core import proxy, runner, tools
from wstrike.core.console import good, info, warn
from wstrike.core.context import Context, Finding
from wstrike.modules.base import Module


class KatanaCrawl(Module):
    name = "katana-crawl"
    phase = "crawl"
    requires = ["katana"]
    intrusive = True
    rate_aware = True
    description = "Active crawl of live URLs to discover endpoints (katana)"

    async def run(self, ctx: Context) -> None:
        roots = ctx.live_urls()
        if not roots:
            return
        katana = tools.resolve("katana")
        depth = str(self.options.get("depth", 2))
        cmd = [katana, "-silent", "-d", depth, "-jc", "-list", "-",
               *ctx.auth.h_args("-H"), *proxy.tool_args("katana", ctx.proxy)]
        if ctx.mode == "auto":
            cmd += ["-rate-limit", str(ctx.effective_rate())]
        info(f"katana crawling {len(roots)} root(s) [depth={depth}]")
        res = await runner.run(
            cmd, stdin="\n".join(roots),
            timeout=self.options.get("timeout", 600),
        )

        found = set()
        for url in res.lines():
            url = url.strip()
            if url and ctx.roe.allows(url):
                found.add(url)

        if not found:
            warn("katana found no in-scope endpoints")
            return
        ctx.data["crawled_urls"] = sorted(set(ctx.data.get("crawled_urls") or []) | found)
        good(f"katana: {len(found)} endpoint(s)")
        ctx.add_finding(
            Finding(
                title=f"{len(found)} crawled endpoint(s)",
                module=self.name,
                target=ctx.target,
                evidence=", ".join(sorted(found)[:15]),
                metadata={"endpoints": sorted(found)},
            )
        )
