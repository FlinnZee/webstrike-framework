"""The conductor. Groups modules by phase, runs phases in order, and runs the
modules inside a phase concurrently.

Two ways a module gets skipped (both with a clear message, never a crash):
  * missing external tool(s)
  * it's `intrusive` and we're in `manual` mode and the operator didn't opt in
    (via --enable / --only). In `auto` mode intrusive modules run, bounded by RoE.
"""
from __future__ import annotations

import asyncio

from wstrike.core import checkpoint
from wstrike.core.console import bad, info, phase, warn
from wstrike.core.context import Context
from wstrike.modules.base import PHASES, Module


class Orchestrator:
    def __init__(
        self, ctx: Context, modules: list[Module], enabled: set[str] | None = None,
        completed_phases: list[str] | None = None,
    ) -> None:
        self.ctx = ctx
        self.modules = modules
        self.enabled = enabled or set()
        self.completed = list(completed_phases or [])

    def _gate(self, m: Module) -> str | None:
        """Return a skip reason, or None if the module should run."""
        if not m.available():
            return f"missing tool(s): {', '.join(m.missing_tools())}"
        if m.intrusive and self.ctx.mode != "auto" and m.name not in self.enabled:
            return (
                "intrusive — skipped in manual mode "
                f"(run with --mode auto, or --enable {m.name})"
            )
        return None

    async def run(self) -> Context:
        info(f"Mode: {self.ctx.mode}")
        if self.completed:
            info(f"Resuming — skipping completed phase(s): {', '.join(self.completed)}")
        for ph in PHASES:
            if ph in self.completed:
                continue
            phase_mods = [m for m in self.modules if m.phase == ph]
            if not phase_mods:
                self.completed.append(ph)
                continue

            runnable = []
            for m in phase_mods:
                reason = self._gate(m)
                if reason:
                    warn(f"Skipping '{m.name}' — {reason}")
                else:
                    runnable.append(m)
            if not runnable:
                continue

            # How many rate-aware modules share this phase concurrently — used to
            # split the RoE req/sec budget so the aggregate stays within the cap.
            self.ctx.data["_rate_split"] = max(
                1, sum(1 for m in runnable if m.rate_aware)
            )

            phase(f"PHASE: {ph}  ({len(runnable)} module(s))")
            results = await asyncio.gather(
                *(m.run(self.ctx) for m in runnable), return_exceptions=True
            )
            for m, r in zip(runnable, results):
                if isinstance(r, Exception):
                    bad(f"Module '{m.name}' errored: {r}")

            self.completed.append(ph)
            checkpoint.save(self.ctx, self.completed)

        info(f"Run complete — {len(self.ctx.findings)} finding(s) total")
        return self.ctx
