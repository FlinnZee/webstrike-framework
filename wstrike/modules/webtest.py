"""Web-test phase — active injection testing against parameterized URLs.

Input is ctx.param_urls() (in-scope URLs with query parameters, mostly produced
by the katana crawl). SQLi/XSS modules are intrusive (gated in manual mode).
The param auditor is passive (no extra requests) so it always runs as a helper.
"""
from __future__ import annotations

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

    _RE_TESTING = re.compile(r"testing URL '([^']+)'")
    _RE_VULN = re.compile(r"parameter '([^']+)' .*is vulnerable", re.IGNORECASE)
    _RE_DBMS = re.compile(r"back-end DBMS:\s*(.+)")

    async def run(self, ctx: Context) -> None:
        urls = ctx.param_urls()
        if not urls:
            warn("sqli-scan: no parameterized URLs to test (run a crawl first)")
            return

        targets = ctx.artifact_path("sqli_targets.txt")
        targets.write_text("\n".join(urls) + "\n")
        sqlmap = tools.resolve("sqlmap")
        cmd = [
            sqlmap, "-m", str(targets), "--batch", "--smart",
            "--disable-coloring",
            "--level", str(self.options.get("level", 1)),
            "--risk", str(self.options.get("risk", 1)),
            "--output-dir", str(ctx.artifact_path("sqlmap")),
            *ctx.auth.sqlmap_args(),
            *proxy.tool_args("sqlmap", ctx.proxy),
        ]
        # Use a random UA only when the operator hasn't supplied their own.
        if not ctx.auth.has_ua():
            cmd.append("--random-agent")
        info(f"sqlmap testing {len(urls)} URL(s) [level={self.options.get('level', 1)}]")
        res = await runner.run(cmd, timeout=self.options.get("timeout", 1800))

        current = ""
        dbms = ""
        found = 0
        for line in res.stdout.splitlines():
            m = self._RE_TESTING.search(line)
            if m:
                current = m.group(1)
            d = self._RE_DBMS.search(line)
            if d:
                dbms = d.group(1).strip()
            v = self._RE_VULN.search(line)
            if v:
                found += 1
                bad(f"[HIGH] SQLi: parameter '{v.group(1)}' on {current}")
                ctx.add_finding(
                    Finding(
                        title=f"SQL injection in parameter '{v.group(1)}'",
                        severity="high",
                        module=self.name,
                        target=current or "?",
                        evidence=f"sqlmap confirmed injectable; DBMS: {dbms or 'unknown'}",
                        references=["https://cwe.mitre.org/data/definitions/89.html"],
                        metadata={"parameter": v.group(1), "dbms": dbms, "cwe": "CWE-89"},
                    )
                )
        info(f"sqli-scan: {found} injectable parameter(s)")


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
        for line in res.lines():
            line = line.strip().rstrip(",")
            if not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
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
