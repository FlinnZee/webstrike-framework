"""Shared engagement state passed to every module.

Modules read prior results from ``ctx.data`` (e.g. subdomains found in recon,
live URLs found in probe) and append ``Finding`` objects. This is how output of
one tool becomes input to the next — the core value of an orchestrator.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from wstrike.core.auth import AuthConfig
from wstrike.core.roe import RulesOfEngagement
from wstrike.core.urls import as_url

SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    title: str
    severity: str = "info"
    module: str = ""
    target: str = ""
    evidence: str = ""
    references: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            self.severity = "info"

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "module": self.module,
            "target": self.target,
            "evidence": self.evidence,
            "references": self.references,
            "metadata": self.metadata,
        }


@dataclass
class Context:
    target: str
    workdir: Path
    profile: dict
    mode: str = "manual"                              # "manual" | "auto"
    roe: RulesOfEngagement = field(default_factory=RulesOfEngagement)
    auth: AuthConfig = field(default_factory=AuthConfig)
    proxy: str = ""                                   # upstream proxy URL (Burp)
    findings: list[Finding] = field(default_factory=list)
    data: dict = field(default_factory=dict)          # cross-module scratchpad
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    # --- cross-phase data accessors -------------------------------------

    def subdomains(self) -> list[str]:
        """Hosts discovered in the recon phase (target always included)."""
        from wstrike.core.urls import hostname

        hosts = set(self.data.get("subdomains") or [])
        hosts.add(hostname(self.target))
        return sorted(hosts)

    def live_urls(self) -> list[str]:
        """URLs confirmed alive by the probe phase (falls back to the target)."""
        return self.data.get("live_urls") or [as_url(self.target)]

    def scan_urls(self) -> list[str]:
        """Everything worth scanning: live roots + crawled endpoints, deduped."""
        urls = list(self.live_urls()) + list(self.data.get("crawled_urls") or [])
        seen, out = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def param_urls(self) -> list[str]:
        """In-scope URLs that carry query parameters — the input for active web
        tests (SQLi/XSS/param audit)."""
        return [
            u for u in self.scan_urls()
            if "?" in u and "=" in u and self.roe.allows(u)
        ]

    def artifact_path(self, name: str) -> Path:
        self.workdir.mkdir(parents=True, exist_ok=True)
        return self.workdir / name
