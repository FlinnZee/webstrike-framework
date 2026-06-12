"""Module contract. Subclass this and drop the file in modules/ to extend the
pipeline — the registry auto-discovers it. A module is ~30 lines: declare the
tools you need, run one, parse output into Findings.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from wstrike.core import tools
from wstrike.core.context import Context

# Pipeline order. Modules declare which phase they belong to.
PHASES = ["recon", "probe", "crawl", "content", "vulnscan", "webtest"]


class Module(ABC):
    name: str = "base"
    phase: str = "recon"
    requires: list[str] = []      # logical tool names (see core/tools.py)
    description: str = ""
    intrusive: bool = False       # active/noisy? gated in manual mode

    def __init__(self, options: dict | None = None) -> None:
        self.options = options or {}

    def missing_tools(self) -> list[str]:
        return tools.missing(self.requires)

    def available(self) -> bool:
        return not self.missing_tools()

    @abstractmethod
    async def run(self, ctx: Context) -> None:
        """Do the work: read ctx.data, run a tool, append ctx.add_finding(...)."""
        raise NotImplementedError
