"""Local hook regressions: render rules and replace privileged/VM commands with harmless stubs.

Run: python3 -m unittest discover -s tests/phase2 -p test_evalhost_hooks.py -v
No Linux networking, QEMU, privileges, or remote machines are used.
"""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
HOOKS = REPO / 'infra/hetzner/evalhost'
CANONICAL = HOOKS.parent / 'evalhost-egress.sh'
MANAGEMENT = dict(PUBLIC_IFACE='pub0', OPERATOR_CIDR='192.0.2.10/32',
                  CTRL_PUBLIC_IP='198.51.100.1', CHOKE_PUBLIC_IP='198.51.100.2',
                  NTP_IP='198.51.100.4')
ALIASES = dict(WORKLOAD_IFACE=('DS_TAP', 'dstap0'), WORKLOAD_SRC=('DS_WL_SUBNET', '10.99.0.0/24'),
               HOSTD_IP=('DS_WL_HOST_IP', '10.99.0.1'), WG_IF=('DS_WG_IF', 'wg0'),
               EVAL_WGIP=('DS_EVAL_WGIP', '10.20.0.3'), CHOKE_WGIP=('DS_CHOKE_WGIP', '10.20.0.2'),
               CTRL_WGIP=('DS_CTRL_WGIP', '10.20.0.1'))

# Every command that could manipulate networking, processes, or VMs is replaced. Stubs only touch
# the TemporaryDirectory fixture or append to its trace; they NEVER execute a passed command.
STUB = r'''
import json, os, pathlib, sys
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
root = pathlib.Path(os.environ['TEST_ROOT'])
event = {'command': name, 'args': args}
if name == 'nft' and args == ['-f', '-']:
    event['rules'] = sys.stdin.read()
with (root / 'trace').open('a') as f:
    f.write(json.dumps(event) + '\n')
if name == 'id':
    print(0)
elif name == 'ip':
    if args[:2] == ['rule', 'del']: sys.exit(2)
elif name == 'nft':
    if args == ['-j', 'list', 'ruleset']: print('{"nftables": []}')
    elif os.environ.get('TEST_NFT_FAIL'): sys.exit(1)
elif name == 'conntrack':
    if os.environ.get('TEST_CONNTRACK_FAIL') and args[:1] == ['-L']: sys.exit(1)
elif name == 'pgrep':
    sys.exit(int(os.environ.get('TEST_PGREP_STATUS', '1')))
elif name == 'pkill':
    sys.exit(1)
elif name == 'setsid':
    pidfile = args[args.index('-pidfile') + 1]
    pathlib.Path(pidfile).write_text(os.environ['TEST_PID'])
elif name == 'qemu-img':
    if args[0] == 'convert': pathlib.Path(args[-1]).touch()
elif name == 'cloud-localds':
    (root / 'cloud-config').write_text(pathlib.Path(args[1]).read_text())
    pathlib.Path(args[0]).touch()
elif name == 'timeout':
    pathlib.Path('vm2-build-serial.log').write_text('DEADSWITCH_VM2_BUILD_OK\n')
    sys.exit(int(os.environ.get('TEST_QEMU_STATUS', '0')))
elif name in ('curl', 'qemu-system-x86_64'):
    raise SystemExit('unexpected direct VM or network invocation')
'''


def write_files(config):
    """Read just our emitted cloud-config write_files subset, without adding a test dependency."""
    result = {}
    for match in re.finditer(r'^  - path: ([^\n]+)\n((?:^    [^\n]*\n)*)', config, re.MULTILINE):
        path, fields = match.groups()
        if '    content: |\n' in fields:
            body = fields.split('    content: |\n', 1)[1]
            result[path] = ''.join(line[6:] + '\n' for line in body.splitlines())
        else:
            result[path] = re.search(r'^    content: (.*)$', fields, re.MULTILINE).group(1)
    return result


class EvalHostHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ds-hooks-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bindir = self.root / 'bin'
        self.bindir.mkdir()
        for name in ('id', 'ip', 'nft', 'sysctl', 'conntrack', 'setsid', 'qemu-img', 'cloud-localds',
                     'timeout', 'curl', 'qemu-system-x86_64', 'pgrep', 'pkill'):
            path = self.bindir / name
            path.write_text(f'#!{sys.executable}\n' + STUB)
            path.chmod(0o755)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(('DS_', 'TEST_')) and k not in (*MANAGEMENT, *ALIASES)}
        self.env.update(MANAGEMENT)
        self.env.update(PATH=f'{self.bindir}:{os.environ["PATH"]}', TEST_ROOT=str(self.root),
                        TEST_PID=str(os.getpid()), DS_VM2_DIR=str(self.root / 'vm2'))
        (self.root / 'vm2').mkdir()
        (self.root / 'vm2/vm2.qcow2').touch()
        (self.root / 'vm2/base.img').touch()

    def run_hook(self, name, *args, env=None):
        return subprocess.run(['bash', str(HOOKS / name), *args], env=env or self.env,
                              capture_output=True, text=True, timeout=10)

    def trace(self):
        path = self.root / 'trace'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_wrapper_uses_exact_canonical_rules(self):
        env = dict(self.env, **{name: value for name, (_, value) in ALIASES.items()})
        for state in ('sealed', 'cut'):
            with self.subTest(state=state):
                wrapper = self.run_hook('gate-seal.sh', 'render', state)
                canonical = subprocess.run(['bash', str(CANONICAL), 'render', state], env=env,
                                           capture_output=True, text=True, timeout=5)
                self.assertEqual(wrapper.returncode, 0, wrapper.stderr)
                self.assertEqual(canonical.returncode, 0, canonical.stderr)
                self.assertEqual(wrapper.stdout, canonical.stdout)
        self.assertEqual(self.trace(), [])

    def test_conflicting_aliases_are_refused_before_mutation(self):
        for canonical, (legacy, value) in ALIASES.items():
            with self.subTest(canonical=canonical):
                result = self.run_hook('gate-seal.sh', 'seal', env=dict(self.env, **{canonical: value, legacy: 'conflict'}))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('conflicting', result.stderr)
        self.assertEqual(self.trace(), [])

    def test_missing_management_tuples_are_refused(self):
        for key in MANAGEMENT:
            with self.subTest(key=key):
                env = dict(self.env)
                del env[key]
                result = self.run_hook('gate-seal.sh', 'seal', env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(key, result.stderr)
        self.assertEqual(self.trace(), [])

    def test_raw_backend_port_cannot_be_reconfigured(self):
        result = self.run_hook('gate-seal.sh', 'seal', env=dict(self.env, DS_OLLAMA_PORT='8080'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('must be 11434', result.stderr)
        self.assertEqual(self.trace(), [])

    def test_sealed_has_only_local_proxy_and_host_backend_allowances(self):
        result = self.run_hook('gate-seal.sh', 'render', 'sealed')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('iifname "dstap0" ip saddr 10.99.0.0/24 ip daddr 10.99.0.1 tcp dport 7001 accept', result.stdout)
        self.assertIn('oifname "wg0" ip saddr 10.20.0.3 ip daddr 10.20.0.2 tcp dport 11434 accept', result.stdout)
        forward = result.stdout.split('  chain forward {', 1)[1].split('  }', 1)[0]
        self.assertNotIn('accept', forward)
        self.assertIn('policy drop', forward)
        self.assertNotIn('masquerade', result.stdout)
        self.assertNotIn('related', result.stdout)

    def test_conntrack_failure_leaves_cut_and_never_installs_sealed(self):
        result = self.run_hook('gate-seal.sh', 'seal', env=dict(self.env, TEST_CONNTRACK_FAIL='1'))
        self.assertNotEqual(result.returncode, 0)
        applied = [event['rules'] for event in self.trace() if 'rules' in event]
        self.assertEqual(len(applied), 1)
        self.assertNotIn('tcp dport 7001 accept', applied[0])
        self.assertNotIn('tcp dport 11434 accept', applied[0])

    def test_boot_cuts_before_launch_and_uses_tap_without_build_seed(self):
        result = self.run_hook('vm2-boot.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        trace = self.trace()
        applied = next(i for i, event in enumerate(trace) if 'rules' in event)
        launched = next(i for i, event in enumerate(trace) if event['command'] == 'setsid')
        self.assertLess(applied, launched)
        self.assertNotIn('tcp dport 7001 accept', trace[applied]['rules'])
        args = trace[launched]['args']
        self.assertIn('tap,id=n0,ifname=dstap0,script=no,downscript=no', args)
        self.assertIn('virtio-net-pci,netdev=n0,mac=52:54:00:99:00:02,romfile=', args)
        self.assertNotIn('seed.iso', ' '.join(args))
        self.assertTrue(any(event['args'] == ['addr', 'replace', '10.99.0.1/24', 'dev', 'dstap0'] for event in trace))

    def test_boot_never_launches_when_cut_fails(self):
        result = self.run_hook('vm2-boot.sh', env=dict(self.env, TEST_NFT_FAIL='1'))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(event['command'] == 'setsid' for event in self.trace()))

    def test_destroy_attempts_kill_even_if_cut_fails_and_reports_failure(self):
        result = self.run_hook('vm2-destroy.sh', env=dict(self.env, TEST_NFT_FAIL='1'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('gate CUT failed', result.stderr)
        self.assertTrue(any(event['command'] == 'pkill' for event in self.trace()))

    def test_destroy_does_not_signal_recycled_pid_and_refuses_unknown_death(self):
        sleeper = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            (self.root / 'vm2/vm2.pid').write_text(str(sleeper.pid))
            result = self.run_hook('vm2-destroy.sh')
            self.assertIsNone(sleeper.poll(), 'unrelated pidfile process must not be killed')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('UNCONFIRMED', result.stderr)
            self.assertTrue((self.root / 'vm2/vm2.pid').exists())
        finally:
            sleeper.terminate()
            sleeper.wait(timeout=5)

    def test_destroy_cannot_treat_failed_process_observation_as_absence(self):
        result = self.run_hook('vm2-destroy.sh', env=dict(self.env, TEST_PGREP_STATUS='2'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('process observation failed', result.stderr)

    def test_build_stages_exact_request_and_offline_runtime_network(self):
        result = self.run_hook('vm2-build.sh', env=dict(self.env, DS_MODEL='model:unit-test'))
        self.assertEqual(result.returncode, 0, result.stderr)
        vm2 = write_files((self.root / 'cloud-config').read_text())
        vm1 = write_files(base64.b64decode(vm2['/var/lib/vm1/user-data.b64']).decode())
        request = json.loads(base64.b64decode(vm1['/etc/deadswitch/request.json']))
        self.assertEqual(request, dict(model='model:unit-test', messages=[dict(role='user', content='Reply with exactly OK.')],
                                       stream=False, n=1, max_tokens=16))
        loop = vm1['/usr/local/bin/ds-workload']
        self.assertIn('http://10.99.0.1:7001/v1/chat/completions', loop)
        self.assertIn('--data-binary @/etc/deadswitch/request.json', loop)
        self.assertIn('raw_backend_canary=', loop)
        self.assertNotIn('/api/chat', loop)
        netplan = vm2['/var/lib/deadswitch/runtime-netplan.yaml']
        self.assertIn('addresses: [10.99.0.2/24]', netplan)
        self.assertIn('via: 10.99.0.1', netplan)
        self.assertIn('dhcp4: false', netplan)
        self.assertNotIn('/etc/systemd/network/10-eth.network', vm2)
        finish = vm2['/usr/local/sbin/finish-deadswitch-vm2-build']
        self.assertLess(finish.index('grep -q DEADSWITCH_VM1_BUILD_OK'), finish.index('install -m 600'))
        self.assertIn('netplan generate', finish)
        self.assertNotIn('netplan apply', finish)
        self.assertIn('cloud-init.disabled', finish)
        self.assertNotIn('seed.iso', vm2['/usr/local/bin/boot-vm1'])
        for files in (vm2, vm1):
            for path, content in files.items():
                if content.startswith('#!/bin/bash'):
                    syntax = subprocess.run(['bash', '-n'], input=content, capture_output=True, text=True, timeout=5)
                    self.assertEqual(syntax.returncode, 0, f'{path}: {syntax.stderr}')

    def test_qemu_timeout_refuses_success_even_with_old_marker(self):
        result = self.run_hook('vm2-build.sh', env=dict(self.env, TEST_QEMU_STATUS='124'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('QEMU failed or timed out', result.stderr)
        self.assertNotIn('VM2 image built:', result.stdout)


if __name__ == '__main__':
    unittest.main()
