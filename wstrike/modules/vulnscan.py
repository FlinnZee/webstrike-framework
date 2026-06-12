"""Vuln-scan phase — template-based scanning with nuclei.

Maps nuclei severities straight into our Finding model and dedupes by
(template-id, matched-url).
"""
from __future__ import annotations

import json

from wstrike.core import proxy, runner, tools
from wstrike.core.console import bad, good, info, warn
from wstrike.core.context import Context, Finding
from wstrike.modules.base import Module


class NucleiScan(Module):
    name = "nuclei-scan"
    phase = "vulnscan"
    requires = ["nuclei"]
    intrusive = True
    rate_aware = True
    description = "Template-driven vulnerability scanning (nuclei)"

    async def run(self, ctx: Context) -> None:
        # Scan live roots + crawled endpoints, minus anything RoE forbids.
        urls = [u for u in ctx.scan_urls() if ctx.roe.allows(u)]
        if not urls:
            warn("No in-scope targets to scan")
            return
        target_list = ctx.artifact_path("nuclei_targets.txt")
        target_list.write_text("\n".join(urls) + "\n")

        nuclei = tools.resolve("nuclei")
        severity = self.options.get("severity", "low,medium,high,critical")
        rate = ctx.effective_rate() if ctx.mode == "auto" else self.options.get("rate_limit", 150)
        cmd = [
            nuclei, "-l", str(target_list),
            "-jsonl", "-silent", "-no-color",
            "-severity", severity,
            "-rate-limit", str(rate),
            *ctx.auth.h_args("-H"),
            *proxy.tool_args("nuclei", ctx.proxy),
        ]
        if self.options.get("templates"):
            cmd += ["-t", self.options["templates"]]
        # Tech-aware (opt-in): restrict to templates matching detected stack —
        # faster + narrower. Off by default to preserve full template coverage.
        if self.options.get("tech_tags") and ctx.data.get("tech_tags"):
            tags = ",".join(ctx.data["tech_tags"])
            cmd += ["-tags", tags]
            info(f"Tech-aware nuclei tags: {tags}")

        info(f"nuclei scanning {len(urls)} target(s) [severity={severity}]")
        res = await runner.run(cmd, timeout=self.options.get("timeout", 1800))
        if not res.ok and not res.stdout.strip():
            warn(f"nuclei produced no output: {res.stderr.strip()[:160]}")
            return

        seen: set[tuple[str, str]] = set()
        count = 0
        for line in res.lines():
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            tid = ev.get("template-id", "unknown")
            matched = ev.get("matched-at") or ev.get("host", "")
            if (tid, matched) in seen:
                continue
            seen.add((tid, matched))

            sev = (ev.get("info", {}).get("severity") or "info").lower()
            name = ev.get("info", {}).get("name", tid)
            ctx.add_finding(
                Finding(
                    title=f"{name} [{tid}]",
                    severity=sev if sev in ("low", "medium", "high", "critical") else "info",
                    module=self.name,
                    target=matched,
                    evidence=ev.get("matcher-name") or ev.get("extracted-results", [""])[0] if ev.get("extracted-results") else f"matched at {matched}",
                    references=ev.get("info", {}).get("reference") or [],
                    metadata={"template_id": tid, "tags": ev.get("info", {}).get("tags", [])},
                )
            )
            count += 1
            emit = bad if sev in ("high", "critical") else good
            emit(f"[{sev.upper()}] {name} -> {matched}")

        info(f"nuclei: {count} finding(s)")
