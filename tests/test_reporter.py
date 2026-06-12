"""Tests for report generation (HTML + SARIF)."""
import json

from wstrike.core.context import Context, Finding
from wstrike.report.reporter import write_reports


def _ctx(tmp_path):
    c = Context(target="acme.com", workdir=tmp_path, profile={})
    c.findings = [
        Finding(title="SQLi", severity="critical", module="sqli-scan",
                target="acme.com/q?id=1", metadata={"cwe": "CWE-89"}),
        Finding(title="XSS", severity="medium", module="xss-scan",
                target="acme.com/s?q=1", metadata={"cwe": "CWE-79"}),
        Finding(title="Live", severity="info", module="http-probe", target="acme.com"),
    ]
    return c


def test_write_reports_emits_four_formats(tmp_path):
    paths = write_reports(_ctx(tmp_path))
    assert set(paths) == {"json", "md", "html", "sarif"}
    for p in paths.values():
        assert p.endswith((".json", ".md", ".html", ".sarif"))


def test_sarif_level_mapping(tmp_path):
    write_reports(_ctx(tmp_path))
    sarif = json.loads((tmp_path / "report.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    levels = [r["level"] for r in sarif["runs"][0]["results"]]
    assert levels == ["error", "warning", "note"]   # crit, med, info


def test_html_contains_target_and_severity(tmp_path):
    write_reports(_ctx(tmp_path))
    html = (tmp_path / "report.html").read_text()
    assert "acme.com" in html
    assert "CRITICAL 1" in html
