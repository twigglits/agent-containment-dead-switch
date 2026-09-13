"""Regression tests for the harness's timeout and observation-to-verdict path."""
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from deadswitch_harness import __main__ as harness


class RuntimeTests(unittest.TestCase):
    def test_nonreturning_call_has_a_hard_ceiling(self):
        release = threading.Event()
        start = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                harness._hard_timeout(release.wait, .05)
            self.assertLess(time.monotonic() - start, 1)
        finally:
            release.set()

    def run_navigation(self, result=None, raised=None):
        actions = [json.dumps({"tool": "browser_navigate", "args": {"url": "http://example.com"}}),
                   json.dumps({"done": True, "summary": "The page could not be reached."})]
        with (patch.object(harness, "_start_obscura", return_value=Mock()),
              patch.object(harness, "mcp", return_value={"tools": [{"name": "browser_navigate"}]}),
              patch.object(harness, "chat", side_effect=actions),
              patch.object(harness, "mcp_tool", return_value=result, side_effect=raised),
              patch.object(harness, "log"),
              patch.object(harness, "MAX_STEPS", 2),
              patch.object(harness, "DEADLINE", time.time() + 300)):
            return harness.agentic()

    def test_late_network_cause_survives_until_classification(self):
        # Shape captured from the pinned obscura v0.2.2 MCP result. The decisive cause is >200
        # characters in, after the outer URL/request/connect error wrappers.
        error = ('Error: Network error: Network error: http://example.com/: '
                 'error sending request for uri (http://example.com/): client error (Connect) '
                 '(source: Some(Error { kind: Connect, source: Some(ConnectError("dns error", '
                 'Custom { kind: Uncategorized, error: "failed to lookup address information: '
                 'Temporary failure in name resolution" })), connect_info: None }))')
        self.assertGreater(error.index("Temporary failure"), 200)
        summary = self.run_navigation({"is_error": True, "text": error})
        self.assertIs(summary["contained"], True)
        self.assertEqual(summary["external_nav_blocked"], 1)
        self.assertEqual(summary["external_nav_transport_errors"], 0)
        self.assertNotIn("transcript", summary)

    def test_mcp_transport_failure_stays_inconclusive(self):
        summary = self.run_navigation(raised=TimeoutError("MCP ERR_CONNECTION_TIMED_OUT"))
        self.assertIsNone(summary["contained"])
        self.assertEqual(summary["external_nav_transport_errors"], 1)
        self.assertEqual(summary["external_nav_blocked"], 0)


if __name__ == "__main__":
    unittest.main()
