"""Offline airlock rule contract and transaction-order regressions; not kernel attestation.

The small rule evaluator exercises every permitted tuple and adverse packet variants. Linux nft
readback, namespace packet probes and trusted live captures remain explicit G4 requirements.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
HOOKS = REPO / "infra/hetzner/grader"
MANAGEMENT = dict(PUBLIC_IFACE="pub0", OPERATOR_CIDR="192.0.2.10/32", CTRL_PUBLIC_IP="198.51.100.1", NTP_IP="198.51.100.10")


def decision(rules, chain, packet):
    body = rules.split("  chain " + chain + " {\n", 1)[1].split("\n  }", 1)[0]
    default = re.search(r"policy (accept|drop);", body)[1]
    for line in body.splitlines():
        line = line.strip()
        action = re.search(r"\b(accept|drop)$", line)
        if not action:
            continue
        matches = True
        for selector, key in (("iifname", "iface"), ("oifname", "iface")):
            found = re.search(selector + r' "([^"]+)"', line)
            matches &= found is None or packet["iface"] == found[1]
        for selector, key in (("saddr", "src"), ("daddr", "dst")):
            found = re.search("ip " + selector + r" ([0-9./]+)", line)
            matches &= found is None or ipaddress.ip_address(packet[key]) in ipaddress.ip_network(found[1])
        for proto in ("tcp", "udp"):
            if proto + " " in line:
                matches &= packet["proto"] == proto
            for selector in ("sport", "dport"):
                found = re.search(proto + " " + selector + r" (\{[^}]+\}|[0-9]+)", line)
                matches &= found is None or packet[selector] in [int(v) for v in re.findall(r"\d+", found[1])]
        direction = re.search(r"ct direction (original|reply)", line)
        matches &= direction is None or packet["direction"] == direction[1]
        states = re.search(r"ct state (\{[^}]+\}|[a-z]+)", line)
        matches &= states is None or packet["state"] in re.findall(r"[a-z]+", states[1])
        if matches:
            return action[1]
    return default


def packet(src="10.20.0.1", dst="10.20.0.4", iface="wg0", proto="tcp", sport=45678, dport=7200,
           direction="original", state="new"):
    return locals()


STUB = r'''
import json, os, pathlib, sys
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
root = pathlib.Path(os.environ['TEST_ROOT'])
event = {'command': name, 'args': args}
if name == 'nft' and args == ['-f', '-']:
    event['rules'] = sys.stdin.read()
with (root / 'trace').open('a') as out:
    out.write(json.dumps(event) + '\n')
if name == 'id':
    print(0)
elif name == 'ip':
    if args[:2] == ['rule', 'del']: sys.exit(2)
elif name == 'nft':
    if args == ['-j', 'list', 'ruleset']: print('{"nftables": []}')
    elif os.environ.get('TEST_NFT_FAIL'): sys.exit(1)
elif name == 'conntrack':
    if os.environ.get('TEST_CONNTRACK_FAIL') and args[:1] == ['-L']: sys.exit(1)
'''


class GraderAirlockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {key: value for key, value in os.environ.items() if key not in MANAGEMENT and not key.startswith(("DS_", "TEST_"))}
        self.env.update(MANAGEMENT, WG_IF="wg0")

    def run_hook(self, hook="airlock.sh", *args, env=None):
        return subprocess.run(["bash", str(HOOKS / hook), *args], env=env or self.env, text=True,
                              capture_output=True, timeout=5)

    def render(self, state="sealed"):
        result = self.run_hook("airlock.sh", "render", state)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_exact_dispatch_and_result_flows_plus_their_established_replies(self):
        rules = self.render()
        cases = [("input", packet()),
                 ("output", packet(src="10.20.0.4", dst="10.20.0.1", dport=7201)),
                 ("output", packet(src="10.20.0.4", dst="10.20.0.1", sport=7200, dport=45678, direction="reply", state="established")),
                 ("input", packet(sport=7201, dport=45678, direction="reply", state="established"))]
        for chain, allowed in cases:
            self.assertEqual(decision(rules, chain, allowed), "accept")
            for change in ({"iface": "pub0"}, {"src": "10.20.0.2"}, {"dst": "10.20.0.3"}, {"proto": "udp"},
                           {"state": "related"}, {"src": "2001:db8::1", "dst": "2001:db8::4"}):
                with self.subTest(chain=chain, change=change):
                    self.assertEqual(decision(rules, chain, dict(allowed, **change)), "drop")
        self.assertEqual(decision(rules, "input", packet(sport=7201, dport=45678, direction="reply", state="new")), "drop")

    def test_no_hostd_operator_public_metadata_mesh_dns_or_forward_egress(self):
        rules = self.render()
        for dst in ("10.20.0.1", "10.20.0.2", "10.20.0.3", "203.0.113.1", "169.254.169.254", "2001:db8::1"):
            for port in (22, 53, 80, 443, 853, 7100, 7101, 11434):
                outgoing = packet(src="10.20.0.4", dst=dst, dport=port, state="established")
                with self.subTest(dst=dst, port=port):
                    self.assertEqual(decision(rules, "output", outgoing), "drop")
                    self.assertEqual(decision(rules, "forward", outgoing), "drop")
        self.assertEqual(decision(rules, "output", packet(src="10.20.0.4", dst="10.20.0.1", dport=7201, iface="pub0")), "drop")

    def test_management_tuples_are_pinned_and_cut_retains_only_management(self):
        rules = self.render("cut")
        self.assertEqual(decision(rules, "input", packet()), "drop")
        self.assertEqual(decision(rules, "output", packet(src="10.20.0.4", dst="10.20.0.1", dport=7201)), "drop")
        for chain, permitted in [
            ("input", packet(src="192.0.2.10", dst="198.51.100.4", iface="pub0", dport=22)),
            ("output", packet(src="198.51.100.4", dst="192.0.2.10", iface="pub0", sport=22, dport=45000, direction="reply", state="established")),
            ("input", packet(src="198.51.100.1", dst="198.51.100.4", iface="pub0", proto="udp", sport=51820, dport=51820)),
            ("output", packet(src="198.51.100.4", dst="198.51.100.10", iface="pub0", proto="udp", dport=123)),
            ("input", packet(src="198.51.100.10", dst="198.51.100.4", iface="pub0", proto="udp", sport=123, direction="reply", state="established"))]:
            self.assertEqual(decision(rules, chain, permitted), "accept")
            wrong = dict(permitted, src="203.0.113.9") if chain == "input" else dict(permitted, dst="203.0.113.9")
            self.assertEqual(decision(rules, chain, wrong), "drop")

    def test_controller_additive_guard_blocks_every_other_grader_tuple(self):
        result = self.run_hook("controller-guard.sh", "render")
        self.assertEqual(result.returncode, 0, result.stderr)
        for port in (7100, 7101, 22, 80, 443, 7200):
            self.assertEqual(decision(result.stdout, "input", packet(src="10.20.0.4", dst="10.20.0.1", dport=port)), "drop")
        self.assertEqual(decision(result.stdout, "input", packet(src="10.20.0.4", dst="10.20.0.1", dport=7201)), "accept")
        self.assertEqual(decision(result.stdout, "input", packet(src="10.20.0.3", dst="10.20.0.1", dport=7100)), "accept")
        self.assertEqual(decision(result.stdout, "forward", packet(src="10.20.0.4", dst="10.20.0.2")), "drop")

    def test_validation_refuses_missing_or_injected_management_config(self):
        for key in MANAGEMENT:
            env = dict(self.env)
            del env[key]
            self.assertNotEqual(self.run_hook("airlock.sh", "render", "sealed", env=env).returncode, 0)
        for update in ({"WG_IF": 'wg0"; accept'}, {"PUBLIC_IFACE": "wg0"}, {"OPERATOR_CIDR": "0.0.0.0/0"},
                       {"NTP_IP": "169.254.169.254"}, {"CTRL_PUBLIC_IP": "10.20.0.2"}):
            self.assertNotEqual(self.run_hook("airlock.sh", "render", "sealed", env=dict(self.env, **update)).returncode, 0)

    def test_failed_conntrack_read_never_installs_sealed(self):
        bindir = self.root / "bin"
        bindir.mkdir()
        for name in ("id", "nft", "ip", "sysctl", "conntrack"):
            path = bindir / name
            path.write_text(f"#!{sys.executable}\n" + STUB)
            path.chmod(0o755)
        env = dict(self.env, PATH=f"{bindir}:{self.env['PATH']}", TEST_ROOT=str(self.root), TEST_CONNTRACK_FAIL="1")
        result = self.run_hook("airlock.sh", "seal", env=env)
        self.assertNotEqual(result.returncode, 0)
        trace = [json.loads(line) for line in (self.root / "trace").read_text().splitlines()]
        applied = [event["rules"] for event in trace if "rules" in event]
        self.assertEqual(applied, [self.render("cut")])
        self.assertEqual(trace[1]["command"], "nft", "deny application traffic before routing or conntrack work")

    def test_live_skeleton_never_passes_when_node_ready_flag_is_present(self):
        result = subprocess.run(["bash", str(REPO / "tests/phase3/acceptance.sh")], text=True, capture_output=True,
                                env=dict(self.env, GRADER_UP="1", G1="PASS", G2="PASS"), timeout=5)
        self.assertEqual(result.returncode, 77)
        self.assertIn("BLOCKED", result.stderr)
        for gate in ("G1", "G2", "G3", "G4", "G5"):
            self.assertIn(gate, result.stderr)


if __name__ == "__main__":
    unittest.main()
