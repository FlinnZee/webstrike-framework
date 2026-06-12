"""Web-test phase — active injection testing against parameterized URLs.

Input is ctx.param_urls() (in-scope URLs with query parameters, mostly produced
by the katana crawl). SQLi/XSS modules are intrusive (gated in manual mode).
The param auditor is passive (no extra requests) so it always runs as a helper.
"""
from __future__ import annotations

import csv
import json
import re
from urllib.parse import parse_qs, urlparse

from wstrike.core import proxy, runner, tools
from wstrike.core.console import bad, good, info, warn
from wstrike.core.context import Context, Finding
from wstrike.core.urls import hostname
from wstrike.modules.base import Module


class SqliScan(Module):
    name = "sqli-scan"
    phase = "webtest"
    requires = ["sqlmap"]
    intrusive = True
    description = "SQL injection testing of parameterized URLs (sqlmap)"

    # Fallback patterns only — primary source is sqlmap's structured CSV.
    _RE_TESTING = re.compile(r"testing URL '([^']+)'")
    _RE_VULN = re.compile(r"parameter '([^']+)' .*is vulnerable", re.IGNORECASE)

    async def run(self, ctx: Context) -> None:
        urls = ctx.param_urls()
        if not urls:
            warn("sqli-scan: no parameterized URLs to test (run a crawl first)")
            return

        targets = ctx.artifact_path("sqli_targets.txt")
        targets.write_text("\n".join(urls) + "\n")
        results_csv = ctx.artifact_path("sqli_results.csv")
        sqlmap = tools.resolve("sqlmap")
        cmd = [
            sqlmap, "-m", str(targets), "--batch", "--smart",
            "--disable-coloring",
            "--level", str(self.options.get("level", 1)),
            "--risk", str(self.options.get("risk", 1)),
            "--output-dir", str(ctx.artifact_path("sqlmap")),
            "--results-file", str(results_csv),   # structured output (not stdout)
            *ctx.auth.sqlmap_args(),
            *proxy.tool_args("sqlmap", ctx.proxy),
        ]
        # Use a random UA only when the operator hasn't supplied their own.
        if not ctx.auth.has_ua():
            cmd.append("--random-agent")
        info(f"sqlmap testing {len(urls)} URL(s) [level={self.options.get('level', 1)}]")
        res = await runner.run(cmd, timeout=self.options.get("timeout", 1800))

        # Primary: parse the machine-readable CSV. Fallback: scrape stdout, so a
        # CSV-format change can never turn a real SQLi into a silent miss.
        rows = self._parse_csv(results_csv)
        found = (self._emit_csv(ctx, rows) if rows
                 else self._emit_stdout_fallback(ctx, res))
        info(f"sqli-scan: {found} injectable parameter(s)")

    @staticmethod
    def _parse_csv(path) -> list[dict]:
        if not path.exists():
            return []
        out = []
        try:
            with open(path, newline="", encoding="utf-8", errors="replace") as fh:
                for raw in csv.DictReader(fh):
                    row = {(k or "").strip(): (v or "").strip() for k, v in raw.items()}
                    param = row.get("Parameter", "")
                    if not param:
                        continue
                    out.append({
                        "url": row.get("Target URL") or row.get("Target", ""),
                        "parameter": param,
                        "place": row.get("Place", ""),
                        "technique": row.get("Technique(s)") or row.get("Technique", ""),
                    })
        except OSError:
            return []
        return out

    def _emit_csv(self, ctx: Context, rows: list[dict]) -> int:
        for r in rows:
            bad(f"[HIGH] SQLi: parameter '{r['parameter']}' on {r['url']}")
            ctx.add_finding(Finding(
                title=f"SQL injection in parameter '{r['parameter']}'",
                severity="high", module=self.name, target=r["url"] or "?",
                evidence=f"sqlmap confirmed injectable ({r['place']}) "
                         f"via {r['technique'] or 'unknown technique'}",
                references=["https://cwe.mitre.org/data/definitions/89.html"],
                metadata={"parameter": r["parameter"], "place": r["place"],
                          "technique": r["technique"], "cwe": "CWE-89"},
            ))
        return len(rows)

    def _emit_stdout_fallback(self, ctx: Context, res) -> int:
        current, found = "", 0
        for line in res.stdout.splitlines():
            m = self._RE_TESTING.search(line)
            if m:
                current = m.group(1)
            v = self._RE_VULN.search(line)
            if v:
                found += 1
                bad(f"[HIGH] SQLi: parameter '{v.group(1)}' on {current}")
                ctx.add_finding(Finding(
                    title=f"SQL injection in parameter '{v.group(1)}'",
                    severity="high", module=self.name, target=current or "?",
                    evidence="sqlmap confirmed injectable (parsed from stdout)",
                    references=["https://cwe.mitre.org/data/definitions/89.html"],
                    metadata={"parameter": v.group(1), "cwe": "CWE-89",
                              "source": "stdout-fallback"},
                ))
        return found


class XssScan(Module):
    name = "xss-scan"
    phase = "webtest"
    requires = ["dalfox"]
    intrusive = True
    description = "Reflected/DOM XSS testing of parameterized URLs (dalfox)"

    async def run(self, ctx: Context) -> None:
        urls = ctx.param_urls()
        if not urls:
            warn("xss-scan: no parameterized URLs to test (run a crawl first)")
            return

        dalfox = tools.resolve("dalfox")
        info(f"dalfox testing {len(urls)} URL(s)")
        res = await runner.run(
            [dalfox, "pipe", "--format", "json", "--silence", "--no-spinner",
             *ctx.auth.dalfox_args(), *proxy.tool_args("dalfox", ctx.proxy)],
            stdin="\n".join(urls),
            timeout=self.options.get("timeout", 1800),
        )

        found = 0
        for ev in self._parse(res.stdout):
            poc = ev.get("data") or ev.get("poc") or ev.get("message_str", "")
            sev = (ev.get("severity") or "medium").lower()
            param = ev.get("param", "")
            found += 1
            good(f"[{sev.upper()}] XSS param '{param}': {poc[:100]}")
            ctx.add_finding(
                Finding(
                    title=f"Cross-site scripting ({ev.get('type', 'XSS')}) in '{param}'",
                    severity=sev if sev in ("low", "medium", "high", "critical") else "medium",
                    module=self.name,
                    target=ev.get("url", poc),
                    evidence=poc,
                    references=["https://cwe.mitre.org/data/definitions/79.html"],
                    metadata={"parameter": param, "cwe": "CWE-79", **ev},
                )
            )
        info(f"xss-scan: {found} XSS finding(s)")

    @staticmethod
    def _parse(stdout: str) -> list[dict]:
        """Tolerant of dalfox emitting either a single JSON array or JSONL.

        dalfox's output shape has varied across versions; rather than assume one,
        try array-of-objects first, then fall back to per-line objects.
        """
        text = stdout.strip()
        if not text:
            return []
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)]
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass
        out = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out


class ParamAudit(Module):
    name = "param-audit"
    phase = "webtest"
    requires = []                 # pure-python analysis, no external tool
    intrusive = False             # sends no requests — safe in manual mode
    description = "Flag SSRF/IDOR-prone parameters for manual review (no requests)"

    _SSRF = {"url", "uri", "redirect", "redirect_url", "next", "dest", "destination",
             "target", "file", "path", "domain", "host", "callback", "webhook",
             "feed", "site", "data", "reference", "ref", "out", "link", "load"}
    _IDOR = {"id", "uid", "user", "user_id", "userid", "account", "account_id",
             "order", "order_id", "doc", "document", "file_id", "num", "no",
             "pid", "key", "object", "item", "invoice", "ticket", "profile"}

    async def run(self, ctx: Context) -> None:
        seen: set[tuple[str, str, str]] = set()
        ssrf = idor = 0
        for url in ctx.param_urls():
            host = hostname(url)
            for param in parse_qs(urlparse(url).query):
                low = param.lower()
                if low in self._SSRF and (host, param, "ssrf") not in seen:
                    seen.add((host, param, "ssrf"))
                    ssrf += 1
                    ctx.add_finding(self._finding(param, url, "SSRF", "CWE-918",
                                                  "918", "medium"))
                if low in self._IDOR and (host, param, "idor") not in seen:
                    seen.add((host, param, "idor"))
                    idor += 1
                    ctx.add_finding(self._finding(param, url, "IDOR", "CWE-639",
                                                  "639", "low"))
        info(f"param-audit: {ssrf} SSRF + {idor} IDOR candidate(s) for review")

    @staticmethod
    def _finding(param, url, kind, cwe, num, sev) -> Finding:
        return Finding(
            title=f"{kind} candidate: parameter '{param}'",
            severity=sev,
            module="param-audit",
            target=url,
            evidence=f"Parameter '{param}' is a common {kind} sink — manual review advised",
            references=[f"https://cwe.mitre.org/data/definitions/{num}.html"],
            metadata={"parameter": param, "class": kind, "cwe": cwe, "needs_manual_review": True},
        )
