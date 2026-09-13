"""Offline fault injection. All provider calls are replaced; never uses real credentials/APIs."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[2] / 'infra/hetzner/ds_kill.py'
spec = importlib.util.spec_from_file_location('ds_kill', MODULE)
kill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kill)
TARGET = dict(run_id='run', incarnation='inc', allocation_id='allocation', server_number='123', chokepoint_id='456', evalhost_ip='192.0.2.3')
CAPABILITIES = {'reset': {'server_number': 123, 'server_ip': '192.0.2.3', 'type': ['hw'], 'operating_status': 'not supported'}}


class ActuatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.ctx = kill.journal(self.directory, TARGET, 5)
        self.state, self.save = self.ctx.__enter__()
        self.now = 1000
        self.calls = []
        self.replies = []
        self.act = kill.Actuator(self.state, self.save, ('fake-token', 'fake-user', 'fake-password'), self.http, lambda: self.now)

    def tearDown(self):
        self.ctx.__exit__(None, None, None)
        self.tmp.cleanup()

    def http(self, method, url, auth, data):
        self.calls.append((method, url, data))
        if method == 'POST':
            persisted = json.loads((self.directory / '123.json').read_text())
            self.assertTrue(persisted['reset_attempted'], 'uncertainty must be durable BEFORE reset dispatch')
        return self.replies.pop(0)

    def test_delete_requires_get_404_and_is_idempotent(self):
        self.replies = [(200, {'server': {'id': 456}}, 0), (200, {'action': {'status': 'running'}}, 0)]
        self.assertFalse(self.act.cut())
        self.assertFalse(self.state['egress_cut'])
        self.now += 2
        self.replies = [(404, {'error': {'code': 'not_found'}}, 0)]
        self.assertTrue(self.act.cut())
        calls = len(self.calls)
        self.assertTrue(self.act.cut())
        self.assertEqual(len(self.calls), calls)

    def test_delete_timeout_does_not_prevent_independent_reset_attempt(self):
        self.replies = [(0, {}, 0), (200, CAPABILITIES, 0), (200, {'reset': {'type': 'hw'}}, 0)]
        self.assertFalse(self.act.cut())
        self.act.reset()
        self.assertTrue(self.state['reset_accepted'])
        self.assertFalse(self.state['egress_cut'])

    def test_ambiguous_reset_is_not_automatically_repeated(self):
        self.replies = [(200, CAPABILITIES, 0), (0, {}, 0)]
        self.act.reset()
        self.assertTrue(self.state['reset_attempted'])
        self.assertFalse(self.state['reset_accepted'])
        self.now += 10000
        restarted = kill.Actuator(json.loads((self.directory / '123.json').read_text()), lambda: None, self.act.creds, self.http, lambda: self.now)
        restarted.reset()
        self.assertEqual(sum(c[0] == 'POST' for c in self.calls), 1)

    def test_robot_403_and_429_persist_backoff_and_allow_only_rejected_reset_retry(self):
        for code in (403, 429):
            with self.subTest(code=code):
                self.state['reset_attempted'] = False
                self.state['robot_retry_at'] = 0
                self.replies = [(200, CAPABILITIES, 0), (code, {'error': {'code': 'RATE_LIMIT_EXCEEDED'}}, 4000)]
                self.act.reset()
                self.assertFalse(self.state['reset_attempted'])
                self.assertGreaterEqual(self.state['robot_retry_at'], self.now + 4000)
                count = len(self.calls)
                self.act.reset()
                self.assertEqual(len(self.calls), count)
                self.now += 5000

    def test_clock_rollback_cannot_bypass_backoff(self):
        self.replies = [(429, {}, 7200)]
        self.assertFalse(self.act.cut())
        self.now -= 100
        self.assertFalse(self.act.cut())
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.state['cloud_retry_at'], 8200)

    def test_wrong_robot_server_or_no_hw_never_dispatches_reset(self):
        for body in ({'reset': dict(CAPABILITIES['reset'], server_number=999)}, {'reset': dict(CAPABILITIES['reset'], type=['sw'])}):
            self.replies = [(200, body, 0)]
            self.act.reset()
            self.now += 10
        self.assertFalse(any(c[0] == 'POST' for c in self.calls))

    def test_missing_credentials_never_makes_provider_calls(self):
        self.act.creds = ('', '', '')
        self.assertFalse(self.act.cut())
        self.act.reset()
        self.assertEqual(self.calls, [])

    def test_cli_never_reports_terminated_from_reset_acceptance(self):
        self.replies = [(404, {}, 0), (200, CAPABILITIES, 0), (200, {'reset': {'type': 'hw'}}, 0)]
        @contextlib.contextmanager
        def existing(*_):
            yield self.state, self.save
        with patch.object(sys, 'argv', ['ds-kill', 'kill']), patch.object(os, 'geteuid', return_value=0), \
                patch.object(kill, 'target_from_env', return_value=(TARGET, 5)), patch.object(kill, 'journal', existing), \
                patch.object(kill, 'credentials', return_value=self.act.creds), patch.object(kill, 'Actuator', return_value=self.act), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertNotEqual(kill.main(), 0)
        self.assertIn('UNCONFIRMED', output.getvalue())
        self.assertNotIn('TERMINATED', output.getvalue())


class JournalAndTransportTests(unittest.TestCase):
    def test_stale_and_foreign_allocations_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with kill.journal(directory, TARGET, 5):
                with self.assertRaises(BlockingIOError):
                    with kill.journal(directory, TARGET, 5): pass
            for target, token in ((TARGET, 4), (dict(TARGET, incarnation='later-boot'), 6), (dict(TARGET, allocation_id='later'), 6)):
                with self.assertRaises(ValueError):
                    with kill.journal(directory, target, token): pass
            with kill.journal(directory, TARGET, 6) as (state, _):
                self.assertEqual(state['high_water'], 6)

    def test_missing_or_corrupt_initialized_journal_is_not_reset(self):
        for corrupt in (False, True):
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                with kill.journal(directory, TARGET, 5): pass
                path = directory / '123.json'
                if corrupt: path.write_text('{corrupt')
                else: path.unlink()
                with self.assertRaises(ValueError):
                    with kill.journal(directory, TARGET, 5): pass

    def test_private_files_and_target_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'credential'
            path.write_text('fake')
            path.chmod(0o644)
            with self.assertRaises(ValueError): kill.private_file(path)
        env = {'DS_' + k.upper(): v for k, v in TARGET.items()}
        env['DS_FENCING_TOKEN'] = '5'
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(kill.target_from_env(), (TARGET, 5))
            os.environ['DS_CHOKEPOINT_ID'] = '../servers'
            with self.assertRaises(ValueError): kill.target_from_env()

    def test_curl_404_is_distinct_from_transport_error_and_auth_is_not_in_argv(self):
        def curl(cmd, **kwargs):
            self.assertFalse(any('SECRET' in x for x in cmd))
            self.assertIn('SECRET', kwargs['input'])
            self.assertNotIn('--fail', cmd)
            self.assertNotIn('--retry', cmd)
            self.assertEqual(kwargs['timeout'], 25)
            Path(cmd[cmd.index('--output') + 1]).write_text('{}')
            Path(cmd[cmd.index('--dump-header') + 1]).write_text('HTTP/2 404\r\n')
            return types.SimpleNamespace(returncode=0, stdout='404')
        with patch.object(subprocess, 'run', curl):
            self.assertEqual(kill.request('GET', kill.CLOUD_API + '/servers/456', 'Bearer SECRET')[0], 404)
        with patch.object(subprocess, 'run', return_value=types.SimpleNamespace(returncode=28, stdout='404')):
            self.assertEqual(kill.request('GET', kill.CLOUD_API + '/servers/456', 'Bearer SECRET')[0], 0)


if __name__ == '__main__':
    unittest.main()
