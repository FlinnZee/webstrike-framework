"""Recon phase — passive subdomain enumeration.

Fills ctx.data['subdomains'], which the probe phase then resolves to live URLs.
All recon here is passive (non-intrusive): certificate transparency + passive
DNS sources. Discovered hosts are filtered through the RoE scope allowlist.
"""
from __future__ import annotations

import json
import os

from wstrike.core import runner, tools
from wstrike.core.console import good, info, warn
from wstrike.core.context import Context, Finding
from wstrike.core.urls import base_domain, hostname
from wstrike.modules.base import Module


def _record(ctx: Context, hosts: set[str], source: str) -> int:
    """Merge in-scope hosts into ctx.data['subdomains']; return how many added."""
    existing = set(ctx.data.get("subdomains") or [])
    added = 0
    for h in hosts:
        h = hostname(h)
        if not h or h in existing:
            continue
        if not ctx.roe.host_in_scope(h):
            continue
        existing.add(h)
        added += 1
    ctx.data["subdomains"] = sorted(existing)
    if added:
        good(f"{source}: +{added} subdomain(s) (total {len(existing)})")
    return added


class CrtShEnum(Module):
    name = "crtsh"
    phase = "recon"
    requires = ["curl"]
    intrusive = False
    description = "Passive subdomain enum via crt.sh certificate transparency"

    async def run(self, ctx: Context) -> None:
        domain = base_domain(ctx.target)
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        curl = tools.resolve("curl")
        info(f"crt.sh lookup for {domain}")
        res = await runner.run([curl, "-s", "--max-time", "45", url], timeout=60)
        if not res.stdout.strip():
            warn("crt.sh returned no data (rate-limited or offline)")
            return
        try:
            entries = json.loads(res.stdout)
        except json.JSONDecodeError:
            warn("crt.sh response was not valid JSON")
            return

        hosts: set[str] = set()
        for e in entries:
            for name in str(e.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain):
                    hosts.add(name)
        _record(ctx, hosts, "crt.sh")


class SubfinderEnum(Module):
    name = "subfinder"
    phase = "recon"
    requires = ["subfinder"]
    intrusive = False
    description = "Passive subdomain enum via subfinder"

    async def run(self, ctx: Context) -> None:
        domain = base_domain(ctx.target)
        sf = tools.resolve("subfinder")
        cmd = [sf, "-d", domain, "-silent"]
        if self.options.get("all"):
            cmd.append("-all")          # query every source (slower, thorough)
        pc = self.options.get("provider_config")
        if pc and os.path.exists(pc):
            cmd += ["-pc", pc]          # API keys -> far more passive coverage
            info(f"subfinder using provider config {pc}")
        info(f"subfinder enumeration for {domain}")
        res = await runner.run(cmd, timeout=300)
        hosts = {ln.strip().lower() for ln in res.lines()}
        _record(ctx, hosts, "subfinder")


class DnsxResolve(Module):
    name = "dnsx-resolve"
    phase = "recon"
    requires = ["dnsx"]
    intrusive = False
    description = "Filter discovered subdomains down to those that resolve (dnsx)"

    async def run(self, ctx: Context) -> None:
        hosts = ctx.data.get("subdomains") or []
        if not hosts:
            return
        dnsx = tools.resolve("dnsx")
        info(f"dnsx resolving {len(hosts)} host(s)")
        res = await runner.run([dnsx, "-silent", "-a", "-resp-only"], stdin="\n".join(hosts))
        # dnsx -resp-only emits IPs; re-run without flag to get resolvable names
        res2 = await runner.run([dnsx, "-silent"], stdin="\n".join(hosts))
        resolvable = {ln.strip().lower() for ln in res2.lines()}
        if resolvable:
            ctx.data["subdomains"] = sorted(resolvable)
            good(f"dnsx: {len(resolvable)} host(s) resolve")
            ctx.add_finding(
                Finding(
                    title=f"{len(resolvable)} resolvable subdomain(s)",
                    module=self.name,
                    target=base_domain(ctx.target),
                    evidence=", ".join(sorted(resolvable)[:20]),
                    metadata={"resolvable": sorted(resolvable)},
                )
            )
