"""Unit tests for the core config layers: auth, proxy, RoE, techmap, notify."""
from pathlib import Path
from unittest.mock import patch

from wstrike.core.auth import AuthConfig
from wstrike.core import proxy
from wstrike.core.roe import RulesOfEngagement
from wstrike.core import techmap
from wstrike.core.context import Context, Finding
from wstrike.core import notify as notifymod
from wstrike.core.notify import Notifier
from wstrike.core.store import Diff, fingerprint


# --- auth -----------------------------------------------------------------

def test_auth_from_profile_expands_bearer_and_dict_cookies():
    a = AuthConfig.from_profile({"auth": {
        "bearer_token": "TOK", "cookies": {"s": "1", "t": "2"}}})
    assert "Authorization: Bearer TOK" in a.headers
    assert a.cookies == "s=1; t=2"
    assert a.active()


def test_auth_h_args_fold_cookie_and_ua():
    a = AuthConfig(headers=["X-K: v"], cookies="s=1", user_agent="UA")
    args = a.h_args("-H")
    assert args.count("-H") == 3
    assert "Cookie: s=1" in args and "User-Agent: UA" in args


def test_auth_tool_specific_forms():
    a = AuthConfig(headers=["X-K: v"], cookies="s=1", user_agent="UA")
    assert "--cookies" in a.dalfox_args()          # dalfox uses plural
    assert "--cookie" in " ".join(a.whatweb_args())
    assert any(x.startswith("--headers=") for x in a.sqlmap_args())


def test_auth_inactive_empty():
    assert not AuthConfig().active()
    assert AuthConfig().h_args() == []


# --- proxy ----------------------------------------------------------------

def test_proxy_whatweb_hostport_others_url():
    assert proxy.tool_args("whatweb", "http://127.0.0.1:8080") == ["--proxy", "127.0.0.1:8080"]
    assert proxy.tool_args("nuclei", "http://127.0.0.1:8080") == ["-proxy", "http://127.0.0.1:8080"]
    assert proxy.tool_args("ffuf", "http://x:1")[0] == "-x"
    assert proxy.tool_args("nuclei", "") == []


# --- RoE ------------------------------------------------------------------

def test_roe_scope_and_deny():
    roe = RulesOfEngagement(scope_allow=["*.acme.com"], deny_paths=["/logout"])
    assert roe.host_in_scope("api.acme.com")
    assert not roe.host_in_scope("evil.com")
    assert roe.path_allowed("https://api.acme.com/x")
    assert not roe.path_allowed("https://api.acme.com/logout")
    assert not roe.allows("https://evil.com/")


def test_roe_empty_allow_means_all():
    assert RulesOfEngagement().host_in_scope("anything.com")


# --- techmap --------------------------------------------------------------

def test_techmap_aggregates_tags_wordlist_notes():
    m = techmap.match(["WordPress", "Apache", "PHP"])
    assert "wordpress" in m["tags"] and "php" in m["tags"]
    assert any("wordpress" in w for w in m["wordlists"])
    assert "wordpress" in m["notes"]


# --- notify ---------------------------------------------------------------

def test_notify_provider_detection():
    assert Notifier(webhook="https://hooks.slack.com/x")._provider() == "slack"
    assert Notifier(webhook="https://discord.com/api/webhooks/x")._provider() == "discord"
    assert Notifier(webhook="https://e.com/h")._provider() == "generic"


def _ctx_with(sev):
    c = Context(target="acme.com", workdir=Path("/tmp/_t"), profile={})
    c.findings = [Finding(title="x", severity=sev, module="m", target="acme.com")]
    return c


def test_notify_threshold_and_payload_shape():
    sent = {}

    def fake(req, timeout=0):
        sent["body"] = req.data.decode()
        return object()

    with patch.object(notifymod.urllib.request, "urlopen", fake):
        assert Notifier(webhook="https://discord.com/api/webhooks/x",
                        min_severity="high").maybe_send(_ctx_with("high"))
    import json
    assert "content" in json.loads(sent["body"])     # discord shape

    with patch.object(notifymod.urllib.request, "urlopen", fake):
        assert not Notifier(webhook="https://hooks.slack.com/x",
                            min_severity="critical").maybe_send(_ctx_with("high"))


def test_notify_inactive_without_webhook():
    assert not Notifier().active()


# --- fingerprint ----------------------------------------------------------

def test_fingerprint_stable_and_path_insensitive_to_trailing_slash():
    a = Finding(title="t", module="m", target="https://x/p/")
    b = Finding(title="t", module="m", target="https://x/p")
    assert fingerprint(a) == fingerprint(b)
    c = Finding(title="other", module="m", target="https://x/p")
    assert fingerprint(a) != fingerprint(c)
