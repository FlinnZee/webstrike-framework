"""Tests for module logic: discovery, param-audit, sqlmap parsing, OAST helpers."""
import asyncio
from pathlib import Path
from unittest.mock import patch

from wstrike.core import runner
from wstrike.core.context import Context
from wstrike.core.roe import RulesOfEngagement
from wstrike.modules import discover
from wstrike.modules.base import PHASES
from wstrike.modules.webtest import ParamAudit, SqliScan
from wstrike.modules.oast import inject, ssrf_candidates, correlate, OastSsrf


def _run(coro):
    return asyncio.run(coro)


def test_all_modules_discover_with_valid_phase():
    mods = discover()
    assert len(mods) >= 12
    for m in mods:
        assert m.phase in PHASES


def test_param_audit_flags_ssrf_and_idor(tmp_path):
    ctx = Context(target="https://app.tld", workdir=tmp_path, profile={},
                  roe=RulesOfEngagement())
    ctx.data["crawled_urls"] = [
        "https://app.tld/fetch?url=x&id=5",
        "https://app.tld/doc?document=7",
        "https://app.tld/static.png",          # no params -> ignored
    ]
    _run(ParamAudit().run(ctx))
    classes = sorted(f.metadata["class"] for f in ctx.findings)
    assert classes == ["IDOR", "IDOR", "SSRF"]


def test_sqlmap_parser_extracts_injection(tmp_path):
    sample = (
        "[INFO] testing URL 'https://app.tld/q?id=1'\n"
        "[INFO] GET parameter 'id' is vulnerable.\n"
        "back-end DBMS: MySQL\n"
    )

    class R:
        stdout = sample
        ok = True
        def lines(self): return [l for l in sample.splitlines() if l.strip()]

    async def fake(cmd, timeout=0, stdin=None):
        return R()

    ctx = Context(target="https://app.tld", workdir=tmp_path, profile={})
    ctx.data["crawled_urls"] = ["https://app.tld/q?id=1"]
    with patch.object(runner, "run", fake):
        _run(SqliScan().run(ctx))
    assert any(f.severity == "high" and "id" in f.title for f in ctx.findings)


def test_sqlmap_csv_parser_is_primary(tmp_path):
    csv = tmp_path / "r.csv"
    csv.write_text(
        'Target URL,Place,Parameter,Technique(s),Note\n'
        '"http://app.tld/q?id=1",GET,id,"boolean-based blind",\n'
    )
    rows = SqliScan._parse_csv(csv)
    assert rows == [{"url": "http://app.tld/q?id=1", "parameter": "id",
                     "place": "GET", "technique": "boolean-based blind"}]
    assert SqliScan._parse_csv(tmp_path / "missing.csv") == []


def test_dalfox_parser_handles_array_and_jsonl():
    from wstrike.modules.webtest import XssScan
    arr = '[{"param":"q","data":"p1"}]'
    jsonl = '{"param":"x","data":"p2"}\n{"param":"y","data":"p3"}'
    assert len(XssScan._parse(arr)) == 1
    assert len(XssScan._parse(jsonl)) == 2
    assert XssScan._parse("") == []
    assert XssScan._parse("not json") == []


def test_oast_inject_preserves_other_params():
    out = inject("https://a/f?url=x&id=5", "url", "http://c/")
    assert "id=5" in out and "url=http" in out


def test_oast_candidates_and_correlate():
    roe = RulesOfEngagement()
    cands = ssrf_candidates(["https://a/f?url=x&id=5", "https://a/v?id=1"], roe)
    assert cands == [("https://a/f?url=x&id=5", "url")]

    tag_map = {"ws0": ("u0", "url"), "ws1": ("u1", "next"), "ws10": ("u10", "dest")}
    hits = correlate(['{"full-id":"ws1.c.oast.fun"}'], tag_map)
    assert hits == {"ws1": ("u1", "next")}        # ws1 != ws10


def test_oast_availability():
    assert not OastSsrf().available()
    assert OastSsrf(options={"payload": "x.oast.fun"}).available()
