"""Visual recon — screenshot every live host with gowitness.

Invaluable when a scan turns up dozens/hundreds of live vhosts: a screenshot
grid lets you eyeball login panels, default installs, and admin UIs fast.
Non-destructive (headless page load), so it runs in manual mode too.
"""
from __future__ import annotations

from wstrike.core import runner, tools
from wstrike.core.console import good, info, warn
from wstrike.core.context import Context, Finding
from wstrike.modules.base import Module


class Screenshot(Module):
    name = "screenshot"
    phase = "crawl"
    requires = ["gowitness"]
    intrusive = False
    description = "Screenshot live hosts for visual triage (gowitness)"

    async def run(self, ctx: Context) -> None:
        urls = ctx.live_urls()
        if not urls:
            return
        shot_dir = ctx.artifact_path("screenshots")
        shot_dir.mkdir(parents=True, exist_ok=True)
        url_file = ctx.artifact_path("screenshot_urls.txt")
        url_file.write_text("\n".join(urls) + "\n")

        gw = tools.resolve("gowitness")
        # gowitness v3 syntax; --write-db=false keeps it to flat PNGs.
        cmd = [
            gw, "scan", "file", "-f", str(url_file),
            "--screenshot-path", str(shot_dir),
            "--write-db=false",
            "--timeout", str(self.options.get("timeout", 10)),
        ]
        info(f"gowitness screenshotting {len(urls)} host(s)")
        res = await runner.run(cmd, timeout=self.options.get("total_timeout", 900))

        shots = sorted(p.name for p in shot_dir.glob("*.png"))
        if not shots and not res.ok:
            warn(f"gowitness produced no screenshots: {res.stderr.strip()[:160]}")
            return
        good(f"{len(shots)} screenshot(s) in {shot_dir}")
        ctx.add_finding(
            Finding(
                title=f"{len(shots)} host screenshot(s) captured",
                severity="info",
                module=self.name,
                target=ctx.target,
                evidence=f"Saved to {shot_dir}",
                metadata={"count": len(shots), "dir": str(shot_dir), "files": shots},
            )
        )
