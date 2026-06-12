"""Out-of-band (OAST) blind SSRF testing.

`param-audit` only *flags* SSRF-prone parameters. This module actually tests
them: it injects a unique OAST payload into each SSRF-candidate parameter and
watches for the callback.

Two ways to get a collaborator:
  * `interactsh-client` installed → we auto-provision a payload domain and
    harvest interactions (fully automated confirmation).
  * `oast.payload` set in the profile (your own Burp Collaborator / listener) →
    we inject and tell you to check it (manual confirmation).
"""
from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from wstrike.core import proxy as proxymod
from wstrike.core import runner, tools
from wstrike.core.console import bad, good, info, warn
from wstrike.core.context import Context, Finding
from wstrike.modules.base import Module

# Reuse the SSRF parameter vocabulary from the passive auditor.
from wstrike.modules.webtest import ParamAudit

_OAST_RE = re.compile(r"[\w-]+\.oast\.[a-z]+", re.IGNORECASE)


def inject(url: str, param: str, value: str) -> str:
    """Return `url` with `param`'s value replaced by `value` (others intact)."""
    u = urlparse(url)
    q = parse_qsl(u.query, keep_blank_values=True)
    newq = [(k, value if k == param else v) for k, v in q]
    return urlunparse(u._replace(query=urlencode(newq)))


def ssrf_candidates(param_urls: list[str], roe) -> list[tuple[str, str]]:
    """(url, param) pairs whose parameter name is a known SSRF sink, in scope."""
    out, seen = [], set()
    for url in param_urls:
        if not roe.allows(url):
            continue
        for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
            if k.lower() in ParamAudit._SSRF and (url, k) not in seen:
                seen.add((url, k))
                out.append((url, k))
    return out


def correlate(interaction_lines: list[str], tag_map: dict[str, tuple[str, str]]) -> dict:
    """Map captured OAST interactions back to the (url, param) that fired them."""
    hits: dict[str, tuple[str, str]] = {}
    for line in interaction_lines:
        for tag, up in tag_map.items():
            if f"{tag}." in line:
                hits[tag] = up
    return hits


class OastSsrf(Module):
    name = "oast-ssrf"
    phase = "webtest"
    requires = []                 # needs interactsh-client OR a profile payload
    intrusive = True
    description = "Blind SSRF via OAST callback (interactsh / Collaborator)"

    def available(self) -> bool:
        return tools.available("interactsh-client") or bool(
            (self.options or {}).get("payload")
        )

    def missing_tools(self) -> list[str]:
        return [] if self.available() else ["interactsh-client (or profile oast.payload)"]

    async def run(self, ctx: Context) -> None:
        candidates = ssrf_candidates(ctx.param_urls(), ctx.roe)
        if not candidates:
            warn("oast-ssrf: no SSRF-candidate parameters (run a crawl first)")
            return

        proc, payload, out_file = await self._provision(ctx)
        if not payload:
            warn("oast-ssrf: could not obtain an OAST payload domain")
            return
        info(f"oast-ssrf: payload {payload}; injecting into {len(candidates)} param(s)")

        tag_map: dict[str, tuple[str, str]] = {}
        curl = tools.resolve("curl")
        for i, (url, param) in enumerate(candidates):
            tag = f"ws{i}"
            tag_map[tag] = (url, param)
            injected = inject(url, param, f"http://{tag}.{payload}/")
            await runner.run(
                [curl, "-sk", "--max-time", "10", *proxymod.tool_args("curl", ctx.proxy),
                 *self._curl_auth(ctx), injected],
                timeout=15,
            )

        # Auto-harvest (interactsh) or hand off for manual confirmation.
        if proc is not None:
            wait = self.options.get("poll_seconds", 25)
            info(f"oast-ssrf: waiting {wait}s for callbacks…")
            await asyncio.sleep(wait)
            lines = self._harvest(proc, out_file)
            hits = correlate(lines, tag_map)
            for tag, (url, param) in hits.items():
                bad(f"[HIGH] Blind SSRF confirmed: '{param}' on {url}")
                ctx.add_finding(self._finding(url, param, payload, confirmed=True))
            if not hits:
                info("oast-ssrf: no callbacks received")
        else:
            good(f"oast-ssrf: injected {len(candidates)} payload(s) — check your "
                 f"collaborator ({payload}) for callbacks")
            for url, param in candidates:
                ctx.add_finding(self._finding(url, param, payload, confirmed=False))

    async def _provision(self, ctx: Context):
        """Return (process|None, payload_domain, out_file|None)."""
        static = (self.options or {}).get("payload")
        if static:
            return None, static, None
        ic = tools.resolve("interactsh-client")
        if not ic:
            return None, "", None
        out_file = str(ctx.artifact_path("interactsh.jsonl"))
        try:
            proc = await asyncio.create_subprocess_exec(
                ic, "-json", "-o", out_file,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
        except Exception as e:
            warn(f"oast-ssrf: failed to start interactsh-client ({e})")
            return None, "", None
        # Read early output to capture the generated payload domain.
        payload = ""
        try:
            for _ in range(40):
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=15)
                if not line:
                    break
                m = _OAST_RE.search(line.decode(errors="replace"))
                if m:
                    payload = m.group(0)
                    break
        except asyncio.TimeoutError:
            pass
        return proc, payload, out_file

    def _harvest(self, proc, out_file: str) -> list[str]:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            with open(out_file, encoding="utf-8") as fh:
                return [ln for ln in fh if ln.strip()]
        except OSError:
            return []

    @staticmethod
    def _curl_auth(ctx: Context) -> list[str]:
        out = []
        for line in ctx.auth._lines():
            out += ["-H", line]
        return out

    @staticmethod
    def _finding(url, param, payload, confirmed: bool) -> Finding:
        return Finding(
            title=f"{'Blind SSRF (confirmed)' if confirmed else 'SSRF tested via OAST'}"
                  f" in '{param}'",
            severity="high" if confirmed else "info",
            module="oast-ssrf",
            target=url,
            evidence=(f"OAST callback received for payload {payload}" if confirmed
                      else f"Payload injected ({payload}); verify on your collaborator"),
            references=["https://cwe.mitre.org/data/definitions/918.html"],
            metadata={"parameter": param, "cwe": "CWE-918", "confirmed": confirmed},
        )
