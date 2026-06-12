"""Async subprocess runner — the single choke point for invoking external tools.

Every module shells out through ``run()`` so we get uniform timeout handling,
logging and structured results. No module should call subprocess directly.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class CommandResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]


async def run(
    cmd: list[str],
    timeout: float = 300.0,
    stdin: str | None = None,
) -> CommandResult:
    """Run a command asynchronously with a hard timeout.

    Args:
        cmd: argv list (already resolved to a real binary path).
        timeout: seconds before the process is killed.
        stdin: optional text piped to the process stdin.
    """
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    timed_out = False
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin is not None else None),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        out, err = await proc.communicate()

    return CommandResult(
        cmd=cmd,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=out.decode(errors="replace"),
        stderr=err.decode(errors="replace"),
        duration=time.monotonic() - start,
        timed_out=timed_out,
    )
