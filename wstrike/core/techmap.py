"""Technology → action map. This is what makes WebStrike an *orchestrator*
rather than a fixed tool chain: the probe phase fingerprints the stack, and
later phases adapt — nuclei tags, ffuf wordlists, and follow-up advice are all
derived from what was actually detected.

Keys are matched as case-insensitive substrings against whatweb plugin names
(e.g. detected "Microsoft-IIS" matches key "iis").
"""
from __future__ import annotations

# token -> {tags: nuclei tags, wordlists: candidate ffuf wordlists, note: advice}
TECH_PROFILES: dict[str, dict] = {
    "wordpress": {
        "tags": ["wordpress", "wp-plugin", "wp-theme"],
        "wordlists": ["/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt"],
        "note": "WordPress — run wpscan; check /wp-json, xmlrpc.php, plugin CVEs",
    },
    "drupal": {
        "tags": ["drupal"],
        "wordlists": ["/usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt"],
        "note": "Drupal — run droopescan; check CHANGELOG.txt for version",
    },
    "joomla": {
        "tags": ["joomla"],
        "wordlists": ["/usr/share/seclists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt"],
        "note": "Joomla — run joomscan; check /administrator",
    },
    "tomcat": {
        "tags": ["tomcat", "apache"],
        "wordlists": ["/usr/share/seclists/Discovery/Web-Content/tomcat.txt"],
        "note": "Tomcat — check /manager/html for default creds, WAR deploy RCE",
    },
    "jenkins": {
        "tags": ["jenkins"],
        "note": "Jenkins — check /script console (RCE), /asynchPeople",
    },
    "gitlab": {"tags": ["gitlab"], "note": "GitLab — check version for known RCE CVEs"},
    "jira": {"tags": ["jira", "atlassian"], "note": "Jira — SSRF/CVE-2019-8451, user enum"},
    "spring": {
        "tags": ["spring", "actuator"],
        "note": "Spring — probe /actuator (env, heapdump, gateway RCE)",
    },
    "graphql": {"tags": ["graphql"], "note": "GraphQL — test introspection, batching abuse"},
    "swagger": {"tags": ["exposure", "api"], "note": "Swagger/OpenAPI exposed — map the API"},
    "phpmyadmin": {"tags": ["phpmyadmin"], "note": "phpMyAdmin — default creds, version CVEs"},
    "iis": {"tags": ["iis", "microsoft"], "note": "IIS — check tilde enum, .NET viewstate"},
    "asp.net": {"tags": ["aspnet", "iis"], "note": "ASP.NET — viewstate, trace.axd, debug"},
    "php": {"tags": ["php"]},
    "nginx": {"tags": ["nginx"]},
    "apache": {"tags": ["apache"]},
    "django": {"tags": ["django"], "note": "Django — check DEBUG=True, /admin"},
    "laravel": {"tags": ["laravel"], "note": "Laravel — .env exposure, debug mode RCE"},
}


def match(technologies: list[str]) -> dict:
    """Aggregate tags/wordlists/notes for the detected technologies."""
    tags: set[str] = set()
    wordlists: list[str] = []
    notes: dict[str, str] = {}
    for tech in technologies:
        t = tech.lower()
        for key, prof in TECH_PROFILES.items():
            if key in t:
                tags.update(prof.get("tags", []))
                for wl in prof.get("wordlists", []):
                    if wl not in wordlists:
                        wordlists.append(wl)
                if "note" in prof:
                    notes[key] = prof["note"]
    return {"tags": sorted(tags), "wordlists": wordlists, "notes": notes}
