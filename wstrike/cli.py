"""Command-line interface.

    webstrike.py scan <target> [--profile P] [--output DIR] [--only m1,m2]
    webstrike.py modules        list available modules and tool status
    webstrike.py check          show which external tools are installed
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime
from pathlib import Path

from wstrike import __version__
from wstrike.core import checkpoint, tools
from wstrike.core.auth import AuthConfig
from wstrike.core.console import bad, banner, good, info, warn
from wstrike.core.context import Context
from wstrike.core.notify import Notifier
from wstrike.core.orchestrator import Orchestrator
from wstrike.core.roe import RulesOfEngagement
from wstrike.core.store import Store, default_db_path
from wstrike.modules import discover
from wstrike.report.reporter import write_reports

_DEFAULT_PROFILE = Path(__file__).resolve().parent.parent / "profiles" / "default.yaml"


def _all_required_tools() -> list[str]:
    """Every external tool any discovered module needs (deduped, sorted)."""
    tset: set[str] = set()
    for cls in discover():
        tset.update(cls.requires)
    return sorted(tset)


def _load_profile(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        import yaml

        return yaml.safe_load(path.read_text()) or {}
    except ImportError:
        warn("pyyaml not installed — using built-in defaults (pip install pyyaml)")
        return {}


def _build_modules(profile: dict, only: list[str] | None):
    module_opts = profile.get("modules", {})
    instances = []
    for cls in discover():
        if only and cls.name not in only:
            continue
        instances.append(cls(options=module_opts.get(cls.name, {})))
    return instances


def _collect_targets(args: argparse.Namespace) -> list[str]:
    """Targets from -l FILE (one per line, # comments) or the positional arg."""
    if args.list:
        try:
            lines = Path(args.list).read_text().splitlines()
        except OSError as e:
            bad(f"Cannot read target list {args.list}: {e}")
            return []
        return [ln.strip() for ln in lines
                if ln.strip() and not ln.lstrip().startswith("#")]
    return [args.target] if args.target else []


def _workdir_for(target: str, output: str | None) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in target)[:40]
    return Path(output or "runs") / f"{safe}_{stamp}"


async def _scan_one(target, args, profile, sem, store_lock, snapshot=None, rate_divisor=1):
    only = [m.strip() for m in args.only.split(",")] if args.only else None
    if snapshot:
        workdir, mode = Path(args.resume), snapshot["mode"]
    else:
        workdir, mode = _workdir_for(target, args.output), args.mode

    ctx = Context(
        target=target, workdir=workdir, profile=profile, mode=mode,
        roe=RulesOfEngagement.from_profile(profile),
        auth=AuthConfig.from_profile(profile).merge_cli(args.header, args.cookie),
        proxy=args.proxy or profile.get("proxy", ""),
        rate_divisor=rate_divisor,   # split the global rate budget across targets
    )
    completed = checkpoint.restore_into(ctx, snapshot) if snapshot else []
    modules = _build_modules(profile, only)
    if not modules:
        bad(f"[{target}] no modules selected")
        return None

    enabled = set(only or [])
    if args.enable:
        enabled |= {m.strip() for m in args.enable.split(",")}

    extra = "".join([
        f" proxy={ctx.proxy}" if ctx.proxy else "",
        f" auth=({ctx.auth.summary()})" if ctx.auth.active() else "",
    ])
    info(f"[{target}] {mode} mode, {len(modules)} module(s), workdir={workdir}{extra}")

    async with sem:
        await Orchestrator(
            ctx, modules, enabled=enabled, completed_phases=completed
        ).run()

    async with store_lock:           # serialize SQLite writes across targets
        diff = _persist(ctx, args)
    write_reports(ctx, diff)

    notifier = Notifier.from_profile(profile).merge_cli(args.notify)
    if notifier.active() and notifier.maybe_send(ctx, diff):
        good(f"[{target}] notification sent ({notifier._provider()})")
    return ctx


async def _drive(targets, args, profile, snapshot) -> list:
    conc = max(1, args.concurrency or int(profile.get("concurrency", 3)))
    sem = asyncio.Semaphore(conc)
    store_lock = asyncio.Lock()
    # At most `conc` targets ever run at once, so that's how far the global rate
    # budget must stretch — each target's tools get rate_limit / divisor.
    rate_divisor = min(conc, len(targets))
    coros = [
        _scan_one(t, args, profile, sem, store_lock,
                  snapshot=snapshot if i == 0 else None, rate_divisor=rate_divisor)
        for i, t in enumerate(targets)
    ]
    return await asyncio.gather(*coros, return_exceptions=True)


def cmd_scan(args: argparse.Namespace) -> int:
    banner()
    profile = _load_profile(Path(args.profile) if args.profile else _DEFAULT_PROFILE)

    snapshot = checkpoint.load(Path(args.resume)) if args.resume else None
    if args.resume and snapshot is None:
        bad(f"No checkpoint.json found in {args.resume}")
        return 1

    targets = [snapshot["target"]] if snapshot else _collect_targets(args)
    if not targets:
        bad("A target is required (positional, -l FILE, or --resume DIR).")
        return 1
    if len(targets) > 1:
        conc = max(1, args.concurrency or int(profile.get("concurrency", 3)))
        info(f"Multi-target: {len(targets)} target(s), concurrency {conc}")

    results = asyncio.run(_drive(targets, args, profile, snapshot))

    contexts = [r for r in results if isinstance(r, Context)]
    errors = [r for r in results if isinstance(r, Exception)]
    for e in errors:
        bad(f"Target errored: {e}")
    total = sum(len(c.findings) for c in contexts)
    info(f"Done: {len(contexts)}/{len(targets)} target(s) ok, {total} finding(s) total")
    return 1 if errors else 0


def _persist(ctx: Context, args: argparse.Namespace):
    """Record the run to SQLite and print the diff vs the previous scan."""
    if args.no_store:
        return None
    try:
        store = Store(Path(args.db) if args.db else default_db_path())
    except Exception as e:  # don't let a storage hiccup lose the report
        warn(f"State store unavailable ({e}); skipping persistence")
        return None
    diff = store.record(ctx)
    store.close()
    if diff.first_run:
        info("First recorded scan of this target — baseline saved")
    else:
        good(
            f"Diff vs previous scan: {len(diff.new)} new, "
            f"{len(diff.known)} known, {len(diff.resolved)} resolved"
        )
        for f in diff.new:
            info(f"  NEW [{f.severity.upper()}] {f.title}")
    return diff


def cmd_modules(_: argparse.Namespace) -> int:
    banner()
    info("Discovered modules:\n")
    from wstrike.modules.base import PHASES

    for cls in sorted(discover(), key=lambda c: (PHASES.index(c.phase), c.name)):
        status = "ready" if not tools.missing(cls.requires) else (
            "needs: " + ", ".join(tools.missing(cls.requires))
        )
        tag = " [intrusive]" if cls.intrusive else ""
        print(f"  [{cls.phase:>9}] {cls.name:<20}{tag} {cls.description}")
        print(f"  {'':>11} requires {cls.requires}  -> {status}\n")
    return 0


def cmd_check(_: argparse.Namespace) -> int:
    banner()
    info("External tool availability:\n")
    for t in _all_required_tools():
        path = tools.resolve(t)
        if path:
            good(f"{t:<12} {path}")
        else:
            warn(f"{t:<12} not installed")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webstrike", description="WebStrike — Automated Web Pentesting Framework (by NiMAA)"
    )
    p.add_argument("--version", action="version", version=f"WebStrike {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="run the pipeline against a target")
    s.add_argument("target", nargs="?", help="hostname, domain or URL")
    s.add_argument("-l", "--list", metavar="FILE", help="file of targets (one per line)")
    s.add_argument("--concurrency", type=int, help="targets to scan in parallel (default 3)")
    s.add_argument("--profile", help="path to a YAML scan profile")
    s.add_argument("--output", help="base output directory (default: runs/)")
    s.add_argument("--only", help="comma-separated module names to run")
    s.add_argument(
        "--mode", choices=["manual", "auto"], default="manual",
        help="manual: intrusive modules opt-in; auto: run all, bounded by RoE",
    )
    s.add_argument(
        "--enable", help="comma-separated intrusive modules to allow in manual mode",
    )
    s.add_argument(
        "--header", action="append", metavar="'K: V'",
        help="custom header injected into every tool (repeatable)",
    )
    s.add_argument("--cookie", help="cookie header value, e.g. 'session=abc; t=1'")
    s.add_argument("--proxy", help="route all tool traffic via proxy, e.g. http://127.0.0.1:8080")
    s.add_argument("--notify", metavar="WEBHOOK", help="Slack/Discord webhook for a summary on finish")
    s.add_argument("--resume", metavar="DIR", help="resume a previous run's workdir")
    s.add_argument("--db", help="SQLite state DB path (default: XDG data dir)")
    s.add_argument("--no-store", action="store_true", help="don't persist to the state DB")
    s.set_defaults(func=cmd_scan)

    sub.add_parser("modules", help="list modules and their tool status").set_defaults(
        func=cmd_modules
    )
    sub.add_parser("check", help="check external tool availability").set_defaults(
        func=cmd_check
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        bad("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
