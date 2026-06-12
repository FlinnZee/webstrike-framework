# WebStrike — Automated Web Pentesting Framework

> **Created by NiMAA.**
> A modular orchestration engine that *conducts* best-in-class Kali tools through
> a phase-based pipeline. WebStrike does **not** reinvent scanners — it chains
> them, passes the output of one as the input to the next, dedupes, and reports.

```
 __        __   _     ___ _        _ _
 \ \      / /__| |__ / __| |_ _ _(_) |_____
  \ \ /\ / / -_) '_ \\__ \  _| '_| | / / -_)
   \_/\_/\___|_.__/|___/\__|_| |_|_\_\___|
        Automated Web Pentesting Framework · by NiMAA
```

## Why an orchestrator (and not "yet another scanner")

The hard part of web pentesting isn't *running* a tool — it's deciding what to
run next based on what you just found, and reporting it cleanly. WebStrike owns
that workflow. Each tool stays the best at its job; WebStrike is the conductor.

## Design

A **phase pipeline**. Modules declare which phase they belong to; phases run in
order, modules inside a phase run **concurrently**. Output flows through a shared
`Context` — subdomains found in recon become probe targets, live URLs become
crawl/scan targets, and so on.

```
recon  →  probe  →  crawl  →  content  →  vulnscan  →  webtest  →  report
crt.sh    whatweb   katana    ffuf        nuclei       sqlmap      md + json
subfinder                                              dalfox
dnsx                                                   param-audit
```

| Phase     | Module             | Tool       | Intrusive | What it does                          |
|-----------|--------------------|------------|:---------:|---------------------------------------|
| recon     | `crtsh`            | curl       |     no    | Passive subdomain enum (crt.sh CT)    |
| recon     | `subfinder`        | subfinder  |     no    | Passive subdomain enum                |
| recon     | `dnsx-resolve`     | dnsx       |     no    | Keep only resolvable subdomains       |
| probe     | `http-probe`       | whatweb    |     no    | Liveness + tech fingerprint           |
| crawl     | `katana-crawl`     | katana     |  **yes**  | Active crawl for endpoints            |
| content   | `content-discovery`| ffuf       |  **yes**  | Directory / file brute force          |
| vulnscan  | `nuclei-scan`      | nuclei     |  **yes**  | Template-driven vuln scanning         |
| webtest   | `sqli-scan`        | sqlmap     |  **yes**  | SQL injection (CWE-89)                |
| webtest   | `xss-scan`         | dalfox     |  **yes**  | Reflected/DOM XSS (CWE-79)            |
| webtest   | `param-audit`      | —          |     no    | Flag SSRF/IDOR-prone params (CWE-918/639) |

Missing tools are **skipped with a clear message**, never a crash.

> **Active web tests** (`sqli-scan`, `xss-scan`) consume parameterized URLs —
> they shine *after* a `katana` crawl has discovered `?param=` endpoints.
> `param-audit` sends no traffic; it just flags SSRF/IDOR-prone parameters as a
> manual-review to-do list, so it's safe to run in `manual` mode.

## Run modes — manual vs auto

You choose how far automation goes with `--mode` (default `manual`):

- **`manual`** (human-in-the-loop): passive recon + probe run automatically.
  Intrusive modules (crawl, content, vuln-scan) are **skipped** unless you opt in
  with `--enable <module>` or `--only <module>`. Recon, look, then decide.
- **`auto`** (hands-off): every module runs, bounded by the **Rules of
  Engagement** in your profile.

### Rules of Engagement (the `auto`-mode safety envelope)

Set in the profile under `roe:` and enforced hardest in `auto` mode:

```yaml
roe:
  scope_allow: ["*.acme.com", "acme.com"]   # only touch these hosts ([] = any)
  deny_paths:  ["/logout", "/*/delete*"]    # never request these paths
  rate_limit:  100                          # global req/sec ceiling
  max_subdomains: 0                         # 0 = unlimited
```

Out-of-scope hosts and denied paths are dropped before any tool touches them.

## Authenticated scanning

Most real bugs live *behind a login*. Auth is injected into **every** tool
(whatweb / katana / ffuf / nuclei / sqlmap / dalfox):

```yaml
auth:
  headers: ["X-Api-Key: abc123"]
  bearer_token: "eyJ..."          # -> Authorization: Bearer eyJ...
  cookies: "session=abc; csrf=def"
  user_agent: "Mozilla/5.0 (engagement-xyz)"
```

…or per-run on the CLI:

```bash
./webstrike.py scan acme.com --header "Authorization: Bearer eyJ..." --cookie "session=abc"
```

## State, diff & resume

Every run is recorded to a SQLite store (`~/.local/share/webstrike/state.db`,
override with `--db`, disable with `--no-store`). This gives you:

- **Diff** — each run reports *what's new since the last scan* of that target
  (new / known / resolved), printed to the console and into the report. Perfect
  for scheduled/continuous monitoring and bug-bounty re-checks.
- **Resume** — a `checkpoint.json` is written after each phase. If a long scan
  dies, continue it: `./webstrike.py scan --resume runs/acme.com_20260612_x/`.

## Tech-aware chaining

The probe phase fingerprints the stack, and later phases **adapt to it** — this
is the payoff of an orchestrator over a static script:

- Detected **WordPress/Drupal/Joomla/Tomcat** → ffuf auto-selects a CMS-specific
  wordlist.
- Notable tech (Jenkins, Spring, GitLab, Laravel, GraphQL, …) → an actionable
  follow-up finding ("Spring — probe /actuator …").
- `nuclei-scan.tech_tags: true` (opt-in) → restrict nuclei to templates matching
  the detected stack (faster, narrower).

## Install

```bash
cd webstrike
pip install -r requirements.txt          # rich + pyyaml (optional but nice)

# External tools (Kali). Install whatever you're missing:
sudo apt install whatweb ffuf
# nuclei / subfinder etc. via:  go install github.com/projectdiscovery/...@latest
```

> **Kali note:** `/usr/bin/httpx` is usually the *Python* httpx CLI, not
> ProjectDiscovery's prober (`httpx-toolkit`). WebStrike's tool resolver prefers
> the security build automatically.

## Usage

```bash
./webstrike.py check                 # what's installed?
./webstrike.py modules               # list modules + tool status + intrusive flag

# manual mode (default): passive recon + probe only
./webstrike.py scan acme.com

# manual, but opt into directory brute forcing
./webstrike.py scan acme.com --enable content-discovery

# full auto, bounded by the profile's Rules of Engagement
./webstrike.py scan acme.com --mode auto --profile profiles/default.yaml

# authenticated scan
./webstrike.py scan acme.com --header "Authorization: Bearer eyJ..." --cookie "sid=abc"

# route everything through Burp for manual follow-up
./webstrike.py scan acme.com --proxy http://127.0.0.1:8080

# resume a crashed run
./webstrike.py scan --resume runs/acme.com_20260612_141500/

# run just specific modules
./webstrike.py scan https://app.tld --only http-probe,nuclei-scan
```

Reports land in `runs/<target>_<timestamp>/` as `report.md` + `report.json`,
plus raw tool artifacts.

## Extending — add an attack in ~30 lines

Drop a file in `wstrike/modules/`. It's auto-discovered, no registration:

```python
from wstrike.modules.base import Module
from wstrike.core import runner, tools
from wstrike.core.context import Context, Finding

class MySubdomainEnum(Module):
    name = "subfinder"
    phase = "recon"
    requires = ["subfinder"]
    description = "Passive subdomain enumeration"

    async def run(self, ctx: Context) -> None:
        bin_ = tools.resolve("subfinder")
        res = await runner.run([bin_, "-d", ctx.target, "-silent"])
        for host in res.lines():
            ctx.add_finding(Finding(title=f"Subdomain: {host}",
                                    module=self.name, target=host))
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

CI (`.github/workflows/ci.yml`) runs the suite on Python 3.11 & 3.12.

## Roadmap

- **Done:** full pipeline (recon → probe → crawl → content → vulnscan → webtest)
  with manual/auto modes + RoE, **authenticated scanning**, **SQLite state +
  diff + resume**, **tech-aware chaining**, **multi-target + concurrency**,
  **proxy**, **OAST/interactsh blind SSRF**, **Slack/Discord notifications**,
  **HTML + SARIF reports**, **gowitness screenshots**, **subfinder API keys**,
  and a **pytest suite + CI** ✅
- **Next:** wayback/gau URL sources; amass; nuclei `-as` automatic scan
- **later:** REST API + web dashboard wrapping this CLI engine (CLI-first);
  AI triage to prioritize findings and suggest the next module

## Scope & ethics

For **authorized** security testing only. Always operate within a signed
engagement / explicit permission and the target's rules of engagement.

## License

[MIT](LICENSE) © 2026 TK NiRMAL

---
*WebStrike — created by **NiMAA**.*
