"""AI triage — correlate findings across the whole engagement and prioritize.

This is what makes WebStrike more than glue: instead of a flat list, an LLM acts
as a senior pentester over ALL findings at once — ranking by real-world
exploitability, spotting *chains* (findings that combine into a bigger issue),
and proposing the next moves. Output is structured and attached to the report.

OPSEC: this sends finding metadata (titles, URLs, evidence) to an external LLM
endpoint. It is opt-in — it only runs when an API key env var is set — and it
warns before sending. Point it at a LOCAL model for sensitive engagements.
"""
from __future__ import annotations

import json
import os
import re

from wstrike.core.console import bad, good, info, warn
from wstrike.core.context import Context
from wstrike.core.llm import LLMClient
from wstrike.modules.base import Module

_KEY_ENV = "WEBSTRIKE_LLM_KEY"

_SYSTEM = (
    "You are a senior penetration tester triaging the findings of an automated "
    "web assessment. Prioritize strictly by real-world exploitability and "
    "business impact (not by scanner severity alone). Identify CHAINS where "
    "several findings combine into a larger attack. Be concise and concrete. "
    "Respond with ONLY valid JSON, no prose, matching exactly this schema:\n"
    '{"summary": str, '
    '"priorities": [{"id": str, "rank": int, "exploitability": "high|medium|low", "why": str}], '
    '"chains": [{"name": str, "ids": [str], "impact": str}], '
    '"next_steps": [str]}'
)


class AITriage(Module):
    name = "ai-triage"
    phase = "triage"
    requires = []                 # needs an LLM endpoint + API key, not a binary
    intrusive = False
    description = "AI-assisted finding triage: prioritize, correlate chains, suggest next steps"

    def available(self) -> bool:
        # Opt-in: only runs when an API key is present (so data never leaves
        # unless the operator deliberately configured it).
        return bool(os.environ.get(_KEY_ENV))

    def missing_tools(self) -> list[str]:
        return [] if self.available() else [f"{_KEY_ENV} env var (LLM API key)"]

    async def run(self, ctx: Context) -> None:
        if not ctx.findings:
            info("ai-triage: no findings to triage")
            return
        client = LLMClient.from_profile(ctx.profile)
        if not client.configured():
            warn(f"ai-triage: no API key ({_KEY_ENV}) — skipping")
            return

        idx = {f"f{i}": f for i, f in enumerate(ctx.findings)}
        user = self._build_prompt(ctx, idx)
        warn(f"ai-triage: sending {len(idx)} finding(s) to LLM ({client.base_url}) "
             f"[model={client.model}] — finding data leaves the host")
        try:
            raw = client.chat(_SYSTEM, user)
        except Exception as e:
            bad(f"ai-triage: LLM request failed ({e})")
            return

        data = self._extract_json(raw)
        if data is None:
            bad("ai-triage: could not parse a JSON response from the model")
            return

        triage = self._resolve(data, idx)
        ctx.data["triage"] = triage
        self._report_to_console(triage)

    @staticmethod
    def _build_prompt(ctx: Context, idx: dict) -> str:
        techs = ", ".join(ctx.data.get("technologies", [])) or "unknown"
        lines = [
            f"Target: {ctx.target}",
            f"Detected technologies: {techs}",
            f"Findings ({len(idx)}):",
        ]
        for fid, f in idx.items():
            ev = (f.evidence or "").replace("\n", " ")[:300]
            lines.append(
                f"- {fid} | sev={f.severity} | module={f.module} | "
                f"{f.title} | target={f.target} | evidence={ev}"
            )
        lines.append(
            "\nReturn the JSON. Reference findings by their id (e.g. f0). "
            "Rank the most exploitable first."
        )
        return "\n".join(lines)

    @staticmethod
    def _extract_json(text: str) -> dict | None:
        text = text.strip()
        # tolerate ```json fenced blocks
        m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
        if m:
            text = m.group(1)
        else:
            s, e = text.find("{"), text.rfind("}")
            if s != -1 and e != -1:
                text = text[s:e + 1]
        try:
            obj = json.loads(text)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _resolve(data: dict, idx: dict) -> dict:
        """Replace finding ids with human-readable titles where possible."""
        def title(fid):
            f = idx.get(fid)
            return f.title if f else fid

        priorities = []
        for p in data.get("priorities", []) or []:
            fid = p.get("id", "")
            priorities.append({
                "rank": p.get("rank"),
                "title": title(fid),
                "exploitability": p.get("exploitability", ""),
                "why": p.get("why", ""),
            })
        chains = []
        for c in data.get("chains", []) or []:
            chains.append({
                "name": c.get("name", ""),
                "findings": [title(i) for i in c.get("ids", [])],
                "impact": c.get("impact", ""),
            })
        return {
            "summary": data.get("summary", ""),
            "priorities": priorities,
            "chains": chains,
            "next_steps": data.get("next_steps", []) or [],
        }

    @staticmethod
    def _report_to_console(triage: dict) -> None:
        good("ai-triage: complete")
        if triage["summary"]:
            info(f"  {triage['summary']}")
        for p in triage["priorities"][:3]:
            info(f"  #{p['rank']} [{p['exploitability']}] {p['title']}")
        if triage["chains"]:
            info(f"  {len(triage['chains'])} attack chain(s) identified")
