"""Tests for the AI triage engine (LLM mocked — no network)."""
import asyncio
import os
from pathlib import Path
from unittest.mock import patch

from wstrike.core.context import Context, Finding
from wstrike.core.llm import LLMClient
from wstrike.modules.triage import AITriage


def _run(coro):
    return asyncio.run(coro)


def _ctx(tmp_path):
    c = Context(target="acme.com", workdir=tmp_path, profile={"llm": {"model": "x"}})
    c.findings = [
        Finding(title="/.env exposed", severity="low", module="content-discovery",
                target="acme.com/.env"),
        Finding(title="SQLi in id", severity="high", module="sqli-scan",
                target="acme.com/q?id=1"),
    ]
    return c


def test_triage_opt_in_gating(monkeypatch):
    monkeypatch.delenv("WEBSTRIKE_LLM_KEY", raising=False)
    assert AITriage().available() is False
    monkeypatch.setenv("WEBSTRIKE_LLM_KEY", "k")
    assert AITriage().available() is True


def test_extract_json_handles_fences_and_prose():
    assert AITriage._extract_json('```json\n{"a":1}\n```') == {"a": 1}
    assert AITriage._extract_json('here you go {"a":2} thanks') == {"a": 2}
    assert AITriage._extract_json("not json at all") is None


def test_triage_resolves_ids_and_attaches(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSTRIKE_LLM_KEY", "k")
    canned = (
        '{"summary":"bad","priorities":[{"id":"f1","rank":1,'
        '"exploitability":"high","why":"db"}],'
        '"chains":[{"name":"c","ids":["f0","f1"],"impact":"breach"}],'
        '"next_steps":["x"]}'
    )
    ctx = _ctx(tmp_path)
    with patch.object(LLMClient, "chat", lambda self, s, u: canned):
        _run(AITriage().run(ctx))
    t = ctx.data["triage"]
    assert t["priorities"][0]["title"] == "SQLi in id"          # f1 resolved
    assert t["chains"][0]["findings"] == ["/.env exposed", "SQLi in id"]
    assert t["next_steps"] == ["x"]


def test_triage_handles_llm_error_gracefully(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSTRIKE_LLM_KEY", "k")
    ctx = _ctx(tmp_path)

    def boom(self, s, u):
        raise RuntimeError("network down")

    with patch.object(LLMClient, "chat", boom):
        _run(AITriage().run(ctx))     # must not raise
    assert "triage" not in ctx.data
