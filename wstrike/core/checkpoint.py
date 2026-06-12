"""Checkpoint/resume support.

The orchestrator writes a checkpoint.json into the run workdir after each phase
(completed phases + the shared data scratchpad + findings so far). `scan
--resume <workdir>` reloads it and continues from where it stopped — so a crash
or Ctrl-C in a long scan doesn't throw away hours of recon.
"""
from __future__ import annotations

import json
from pathlib import Path

from wstrike.core.context import Context, Finding

_NAME = "checkpoint.json"


def save(ctx: Context, completed_phases: list[str]) -> None:
    path = ctx.artifact_path(_NAME)
    payload = {
        "target": ctx.target,
        "mode": ctx.mode,
        "started_at": ctx.started_at,
        "completed_phases": completed_phases,
        "data": ctx.data,
        "findings": [f.to_dict() for f in ctx.findings],
    }
    path.write_text(json.dumps(payload, indent=2))


def load(workdir: Path) -> dict | None:
    path = Path(workdir) / _NAME
    if not path.exists():
        return None
    return json.loads(path.read_text())


def restore_into(ctx: Context, snapshot: dict) -> list[str]:
    """Repopulate a context from a checkpoint; return completed phase names."""
    ctx.data = snapshot.get("data", {})
    ctx.started_at = snapshot.get("started_at", ctx.started_at)
    ctx.findings = [
        Finding(
            title=d["title"], severity=d.get("severity", "info"),
            module=d.get("module", ""), target=d.get("target", ""),
            evidence=d.get("evidence", ""), references=d.get("references", []),
            metadata=d.get("metadata", {}),
        )
        for d in snapshot.get("findings", [])
    ]
    return snapshot.get("completed_phases", [])
