"""Probe phase — confirm what's alive and fingerprint the tech stack.

Probes the target plus every subdomain discovered in recon. Primary tool is
whatweb (reliable on Kali). Populates ctx.data['live_urls'] which every later
phase consumes. Non-intrusive (light, single request per host/scheme).
"""
from __future__ import annotations

import asyncio
import json

from wstrike.core import proxy, runner, techmap, tools
from wstrike.core.console import good, info, warn
from wstrike.core.context import Context, Finding
from wstrike.core.urls import as_url, hostname
from wstrike.modules.base import Module


class HttpProbe(Module):
    name = "http-probe"
    phase = "probe"
    requires = ["whatweb"]
    intrusive = False
    description = "Liveness + technology fingerprinting (whatweb)"

    async def run(self, ctx: Context) -> None:
        # Probe the original target verbatim (keeps scheme/port), then add any
        # subdomains discovered in recon (bare hosts).
        target_host = hostname(ctx.target)
        hosts = [ctx.target] + [
            h for h in ctx.subdomains() if h != target_host
        ]
        hosts = [h for h in hosts if ctx.roe.host_in_scope(h)]
        cap = self.options.get("max_targets", 50)
        if len(hosts) > cap:
            warn(f"Capping probe at {cap}/{len(hosts)} hosts (raise max_targets)")
            hosts = hosts[:cap]

        info(f"Probing {len(hosts)} host(s)")
        results = await asyncio.gather(*(self._probe_host(ctx, h) for h in hosts))

        live = [url for url, _ in results if url]
        techs = sorted({t for _, techlist in results for t in techlist})
        ctx.data["live_urls"] = live or [as_url(ctx.target)]
        ctx.data["technologies"] = techs
        info(f"{len(live)} live endpoint(s) recorded")

        self._enrich(ctx, techs)

    async def _probe_host(self, ctx: Context, host: str) -> tuple[str | None, list[str]]:
        candidates = (
            [host] if host.startswith(("http://", "https://"))
            else [as_url(host, "https"), as_url(host, "http")]
        )
        ww = tools.resolve("whatweb")
        auth = ctx.auth.whatweb_args() + proxy.tool_args("whatweb", ctx.proxy)
        for url in candidates:
            res = await runner.run(
                [ww, "--no-errors", "-a", "3", "--log-json=-", *auth, url], timeout=60
            )
            if not res.ok or not res.stdout.strip():
                continue
            techs = self._parse_whatweb(res.stdout)
            if techs is None:
                continue
            good(f"Live: {url}  [{', '.join(techs[:6]) or 'no fingerprint'}]")
            ctx.add_finding(
                Finding(
                    title=f"Live web service: {url}",
                    severity="info",
                    module=self.name,
                    target=url,
                    evidence="Technologies: " + (", ".join(techs) or "unknown"),
                    metadata={"technologies": techs},
                )
            )
            return url, techs
        return None, []

    def _enrich(self, ctx: Context, techs: list[str]) -> None:
        """Turn notable fingerprints into actionable findings + drive later phases."""
        mapped = techmap.match(techs)
        if mapped["tags"]:
            ctx.data["tech_tags"] = mapped["tags"]
        if mapped["wordlists"]:
            ctx.data["tech_wordlists"] = mapped["wordlists"]
        for tech, note in mapped["notes"].items():
            good(f"Notable tech: {tech} — {note}")
            ctx.add_finding(
                Finding(
                    title=f"Notable technology: {tech}",
                    severity="info",
                    module=self.name,
                    target=ctx.target,
                    evidence=note,
                    metadata={"technology": tech, "follow_up": note},
                )
            )

    @staticmethod
    def _parse_whatweb(stdout: str) -> list[str] | None:
        """whatweb --log-json emits one JSON object per target. Return plugin
        names, or None if the target didn't respond."""
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            plugins = obj.get("plugins", {})
            return sorted(plugins.keys()) if plugins else []
        return None
