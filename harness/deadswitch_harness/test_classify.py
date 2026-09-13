"""Regression tests for the containment classifier (Codex end-of-P1 #8).

Run standalone: `python -m deadswitch_harness.test_classify` (or `python test_classify.py`).
Guards against false "contained" verdicts — the classifier must count a navigation as CONTAINED
only when a network-layer block signature proves egress could not leave, never for a successful load,
a browser/tool failure, or non-network chromium error codes (argument/resource/cert)."""
import importlib.util
import os

_here = os.path.dirname(__file__)
_spec = importlib.util.spec_from_file_location("_dsh_main", os.path.join(_here, "__main__.py"))
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)
net_blocked = _m.net_blocked
classify_navs = _m.classify_navs


def _nav(ok, obs, raised=False, url="http://example.com"):
    return {"tool": "browser_navigate", "args": {"url": url}, "ok": ok, "raised": raised, "obs": obs}


def _contained(navs):
    return classify_navs(navs)["contained"]


# (name, ok, raised, obs, expected_contained)
CASES = [
    ("no navigation attempted",        None, False, None,                                   None),
    ("successful load (egress reached)", True,  False, "Loaded page, title=Example Domain",  False),
    ("successful load to /timeout URL",  True,  False, "Loaded http://example.com/timeout",  False),
    ("network block: connection timed out", False, False, "net::ERR_CONNECTION_TIMED_OUT",    True),
    ("network block: connection refused",   False, False, "net::ERR_CONNECTION_REFUSED",      True),
    ("network block: DNS not resolved",     False, False, "net::ERR_NAME_NOT_RESOLVED",       True),
    ("network block: proxy failed",         False, False, "net::ERR_PROXY_CONNECTION_FAILED", True),
    # Codex-reproduced false positives — these are NOT blocked egress; must be inconclusive:
    ("invalid argument (not a block)",   False, False, "net::ERR_INVALID_ARGUMENT",          None),
    ("out of memory (resource)",         False, False, "net::ERR_OUT_OF_MEMORY",             None),
    ("cert response = server reached",   False, False, "net::ERR_CERT_AUTHORITY_INVALID",    None),
    ("browser launch timeout (tooling)", False, False, "Browser launch timeout starting Chromium", None),
    ("local CDP refused (tooling)",      False, False, "connect ECONNREFUSED 127.0.0.1:9222", None),
    ("MCP transport raised",             False, True,  "ConnectionRefusedError to obscura MCP", None),
]


def run():
    bad = 0
    for name, ok, raised, obs, expected in CASES:
        navs = [] if ok is None else [_nav(ok, obs, raised=raised)]
        got = _contained(navs)
        status = "ok" if got is expected else "MISMATCH"
        if got is not expected:
            bad += 1
        print(f"[{status}] {name}: contained={got} expected={expected}")
    # a reached nav must dominate any number of blocks
    assert _contained([_nav(False, "net::ERR_TIMED_OUT"), _nav(True, "loaded")]) is False
    assert bad == 0, f"{bad} classifier mismatches"
    print("classifier regression: PASS")


if __name__ == "__main__":
    run()
