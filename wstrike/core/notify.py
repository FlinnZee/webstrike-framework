"""Webhook notifications — ping Slack/Discord when a run turns up findings at or
above a severity threshold. Stdlib only (urllib), so no extra dependency.

Useful for long-running or scheduled/continuous scans you aren't watching.
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass

from wstrike.core.context import SEVERITIES, Context

_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Notifier:
    webhook: str = ""
    min_severity: str = "high"
    kind: str = "auto"          # auto | slack | discord | generic

    @classmethod
    def from_profile(cls, profile: dict | None) -> "Notifier":
        n = (profile or {}).get("notify") or {}
        return cls(
            webhook=n.get("webhook", ""),
            min_severity=n.get("min_severity", "high"),
            kind=n.get("type", "auto"),
        )

    def merge_cli(self, webhook: str | None) -> "Notifier":
        if webhook:
            self.webhook = webhook
        return self

    def active(self) -> bool:
        return bool(self.webhook)

    def _provider(self) -> str:
        if self.kind != "auto":
            return self.kind
        if "discord.com" in self.webhook or "discordapp.com" in self.webhook:
            return "discord"
        if "hooks.slack.com" in self.webhook:
            return "slack"
        return "generic"

    def _threshold_met(self, ctx: Context) -> list:
        floor = _RANK.get(self.min_severity, _RANK["high"])
        return [f for f in ctx.findings if _RANK.get(f.severity, 0) >= floor]

    def _message(self, ctx: Context, notable: list, diff) -> str:
        counts: dict[str, int] = {}
        for f in ctx.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        bits = " ".join(f"{s}:{counts[s]}" for s in reversed(SEVERITIES) if counts.get(s))
        lines = [
            f"🎯 WebStrike — {ctx.target}",
            f"Findings: {len(ctx.findings)}  [{bits or 'none'}]",
        ]
        if diff is not None and not getattr(diff, "first_run", False):
            lines.append(f"🆕 New since last scan: {len(diff.new)}")
        lines.append(f"At/above {self.min_severity}:")
        for f in notable[:10]:
            lines.append(f"  • [{f.severity.upper()}] {f.title} — {f.target}")
        if len(notable) > 10:
            lines.append(f"  …and {len(notable) - 10} more")
        return "\n".join(lines)

    def maybe_send(self, ctx: Context, diff=None) -> bool:
        """Send a summary if the webhook is set and the threshold is met."""
        if not self.active():
            return False
        notable = self._threshold_met(ctx)
        if not notable:
            return False
        text = self._message(ctx, notable, diff)
        provider = self._provider()
        payload = {"content": text} if provider == "discord" else {"text": text}
        try:
            req = urllib.request.Request(
                self.webhook,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=15)
            return True
        except Exception:
            return False
