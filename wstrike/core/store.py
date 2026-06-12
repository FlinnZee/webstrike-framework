"""SQLite persistence + cross-run diffing.

Each finding gets a stable fingerprint (module|target|title). On every run we
record the findings and compare against the *previous* run of the same target,
so we can answer the question that matters for continuous testing:
**what's new since last scan?**
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from wstrike.core.context import Context, Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    mode        TEXT,
    started_at  TEXT,
    finished_at TEXT,
    total       INTEGER
);
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL,
    target       TEXT,
    fingerprint  TEXT NOT NULL,
    title        TEXT,
    severity     TEXT,
    module       TEXT,
    url          TEXT,
    evidence     TEXT,
    first_seen   INTEGER,
    FOREIGN KEY(run_id) REFERENCES runs(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(target, fingerprint);
"""


def fingerprint(f: Finding) -> str:
    key = f"{f.module}|{(f.target or '').rstrip('/')}|{f.title}"
    return hashlib.sha1(key.encode()).hexdigest()[:16]


@dataclass
class Diff:
    new: list[Finding] = field(default_factory=list)
    known: list[Finding] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)   # rows from prev run
    prev_run_id: int | None = None
    first_run: bool = False


def default_db_path() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "webstrike" / "state.db"


class Store:
    def __init__(self, db_path: Path) -> None:
        self.path = db_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def _prev_run_id(self, target: str) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM runs WHERE target=? AND finished_at IS NOT NULL "
            "ORDER BY id DESC LIMIT 1",
            (target,),
        ).fetchone()
        return row["id"] if row else None

    def record(self, ctx: Context) -> Diff:
        """Persist this run's findings and diff against the previous run."""
        target = ctx.target
        prev_id = self._prev_run_id(target)
        prev_rows = {}
        if prev_id is not None:
            for r in self.conn.execute(
                "SELECT * FROM findings WHERE run_id=?", (prev_id,)
            ):
                prev_rows[r["fingerprint"]] = r
        prev_fps = set(prev_rows)

        cur = self.conn.execute(
            "INSERT INTO runs(target, mode, started_at, finished_at, total) "
            "VALUES(?,?,?,?,?)",
            (target, ctx.mode, ctx.started_at,
             datetime.now(timezone.utc).isoformat(), len(ctx.findings)),
        )
        run_id = cur.lastrowid

        diff = Diff(prev_run_id=prev_id, first_run=prev_id is None)
        cur_fps = set()
        for f in ctx.findings:
            fp = fingerprint(f)
            cur_fps.add(fp)
            # earliest run that has ever seen this fingerprint for this target
            seen = self.conn.execute(
                "SELECT MIN(first_seen) AS m FROM findings WHERE target=? AND fingerprint=?",
                (target, fp),
            ).fetchone()["m"]
            first_seen = seen if seen is not None else run_id
            self.conn.execute(
                "INSERT INTO findings(run_id,target,fingerprint,title,severity,"
                "module,url,evidence,first_seen) VALUES(?,?,?,?,?,?,?,?,?)",
                (run_id, target, fp, f.title, f.severity, f.module, f.target,
                 f.evidence, first_seen),
            )
            (diff.known if fp in prev_fps else diff.new).append(f)

        diff.resolved = [dict(prev_rows[fp]) for fp in (prev_fps - cur_fps)]
        self.conn.commit()
        return diff
