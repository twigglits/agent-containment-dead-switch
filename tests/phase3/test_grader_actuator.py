"""Offline grader actuator tests. Every provider request is an injected mock."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "infra/hetzner"))
SPEC = importlib.util.spec_from_file_location("grader_actuator", REPO / "infra/hetzner/ds-grader-kill.py")
kill = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kill)
TARGET = dict(run_id="run1", incarnation="inc1", allocation_id="grader-allocation1", grader_server_id="401")


class GraderActuatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "state"

    def test_delete_acceptance_requires_separate_positive_get(self):
        responses = iter([(200, {"server": {"id": 401}}, 0), (200, {"action": {"status": "success"}}, 0), (404, {}, 0)])
        calls, saved = [], []
        with kill.journal(self.directory, TARGET, 7) as (state, persist):
            def save():
                persist()
                saved.append(copy.deepcopy(state))

            def http(method, url, auth):
                calls.append(method)
                self.assertEqual(url, "https://api.hetzner.cloud/v1/servers/401")
                if method == "DELETE":
                    on_disk = json.loads((self.directory / "401.json").read_text())
                    self.assertTrue(on_disk["delete_attempted"])
                    self.assertTrue(on_disk["quarantined"])
                    self.assertEqual(on_disk["high_water"], 7)
                return next(responses)

            actuator = kill.GraderActuator(state, save, "mock-token", http=http, clock=lambda: 100)
            self.assertFalse(actuator.kill())
            self.assertTrue(state["delete_accepted"])
            self.assertFalse(state["absence_confirmed"])
            self.assertEqual(calls, ["GET", "DELETE"])
            actuator.clock = lambda: 103
            self.assertTrue(actuator.kill())
            self.assertTrue(state["quarantined"], "deleted allocation must never automatically reopen")
            self.assertEqual(calls, ["GET", "DELETE", "GET"])

    def test_ambiguous_delete_is_not_repeated_after_restart(self):
        with kill.journal(self.directory, TARGET, 8) as (state, save):
            http = mock.Mock(side_effect=[(200, {"server": {"id": 401}}, 0), (0, {}, 0)])
            self.assertFalse(kill.GraderActuator(state, save, "mock", http, clock=lambda: 100).kill())
            self.assertTrue(state["delete_attempted"])
        with kill.journal(self.directory, TARGET, 9) as (state, save):
            http = mock.Mock(return_value=(200, {"server": {"id": 401}}, 0))
            self.assertFalse(kill.GraderActuator(state, save, "mock", http, clock=lambda: 200).kill())
            self.assertEqual([call.args[0] for call in http.call_args_list], ["GET"])

    def test_clock_rollback_and_retry_after_do_not_dispatch(self):
        with kill.journal(self.directory, TARGET, 1) as (state, save):
            http = mock.Mock(return_value=(429, {}, 4000))
            actuator = kill.GraderActuator(state, save, "mock", http, clock=lambda: 100)
            self.assertFalse(actuator.kill())
            self.assertEqual(state["retry_at"], 4100)
            actuator.clock = lambda: 99
            self.assertFalse(actuator.kill())
            actuator.clock = lambda: 4099
            self.assertFalse(actuator.kill())
            self.assertEqual(http.call_count, 1)

    def test_wrong_server_and_string_404_are_not_authority(self):
        for response in [(200, {"server": {"id": 999}}, 0), (200, {"server": {"id": "401"}}, 0),
                         (0, {"status": "404"}, 0), (500, {}, 0)]:
            with self.subTest(response=response):
                path = self.directory / str(len(list(self.directory.glob("*"))) if self.directory.exists() else 0)
                with kill.journal(path, TARGET, 1) as (state, save):
                    http = mock.Mock(return_value=response)
                    self.assertFalse(kill.GraderActuator(state, save, "mock", http, clock=lambda: 100).kill())
                    self.assertFalse(state["delete_attempted"])
                    self.assertFalse(state["absence_confirmed"])

    def test_high_water_allocation_pin_and_missing_state_survive_restart(self):
        with kill.journal(self.directory, TARGET, 7):
            pass
        for target, token in [(TARGET, 6), (dict(TARGET, allocation_id="other"), 8), (dict(TARGET, incarnation="other"), 8)]:
            with self.assertRaises(ValueError):
                with kill.journal(self.directory, target, token):
                    self.fail("invalid authority admitted")
        (self.directory / "401.json").unlink()
        with self.assertRaises(ValueError):
            with kill.journal(self.directory, TARGET, 8):
                self.fail("missing initialized journal reset authority")

    def test_corrupt_typed_state_and_duplicate_fields_fail_closed(self):
        with kill.journal(self.directory, TARGET, 1) as (state, _):
            initial = copy.deepcopy(state)
        for update in [{"absence_confirmed": "true"}, {"high_water": True}, {"quarantined": False},
                       {"delete_accepted": True}, {"retry_at": -1}]:
            with self.subTest(update=update):
                with self.assertRaises(ValueError):
                    kill.validate_state(dict(initial, **update), TARGET)
        with self.assertRaises(ValueError):
            json.loads('{"absence_confirmed":false,"absence_confirmed":true}', object_pairs_hook=kill.unique_fields)

    def test_parallel_claim_fails_before_provider_call(self):
        with kill.journal(self.directory, TARGET, 1):
            with self.assertRaises(BlockingIOError):
                with kill.journal(self.directory, TARGET, 2):
                    self.fail("parallel actuator admitted")

    def test_environment_requires_positive_fencing_and_dedicated_grader_id(self):
        env = {"DS_" + key.upper(): value for key, value in TARGET.items()}
        with mock.patch.dict(os.environ, dict(env, DS_FENCING_TOKEN="10"), clear=True):
            self.assertEqual(kill.target_from_env(), (TARGET, 10))
        for token in ("0", "-1", str(2**64)):
            with mock.patch.dict(os.environ, dict(env, DS_FENCING_TOKEN=token), clear=True):
                with self.assertRaises(ValueError):
                    kill.target_from_env()


if __name__ == "__main__":
    unittest.main()
