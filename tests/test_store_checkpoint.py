"""Tests for SQLite state/diff and checkpoint resume."""
from pathlib import Path

from wstrike.core.context import Context, Finding
from wstrike.core.store import Store
from wstrike.core import checkpoint


def _ctx(tmp_path, findings):
    c = Context(target="https://app.tld", workdir=tmp_path / "wd", profile={})
    c.findings = findings
    return c


def test_store_diff_new_known_resolved(tmp_path):
    A = Finding(title="SQLi", severity="high", module="sqli", target="https://app.tld/q?id=1")
    B = Finding(title="Live", severity="info", module="probe", target="https://app.tld")
    C = Finding(title="XSS", severity="medium", module="xss", target="https://app.tld/s?q=1")
    store = Store(tmp_path / "state.db")

    d1 = store.record(_ctx(tmp_path, [A, B]))
    assert d1.first_run and len(d1.new) == 2

    d2 = store.record(_ctx(tmp_path, [B, C]))
    assert not d2.first_run
    assert [f.title for f in d2.new] == ["XSS"]
    assert [f.title for f in d2.known] == ["Live"]
    assert [r["title"] for r in d2.resolved] == ["SQLi"]
    store.close()


def test_checkpoint_round_trip(tmp_path):
    c = _ctx(tmp_path, [Finding(title="t", module="m", target="x")])
    c.data["subdomains"] = ["a.app.tld"]
    c.data["live_urls"] = ["https://app.tld"]
    checkpoint.save(c, ["recon", "probe"])

    snap = checkpoint.load(c.workdir)
    fresh = Context(target="ignored", workdir=c.workdir, profile={})
    done = checkpoint.restore_into(fresh, snap)
    assert done == ["recon", "probe"]
    assert [f.title for f in fresh.findings] == ["t"]
    assert fresh.data["subdomains"] == ["a.app.tld"]


def test_checkpoint_missing_returns_none(tmp_path):
    assert checkpoint.load(tmp_path) is None
