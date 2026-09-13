"""Kernel packet regressions in a disposable outer network AND mount namespace.

Linux (root, iproute2, nft, conntrack):
  sudo unshare --mount --net python3 tests/phase2/network_ns.py
WireGuard transport is represented by a veth named wg0: this tests nft/routing/conntrack,
NOT WireGuard authentication or provider deletion. No host namespace rules/routes are changed.
"""
import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess as sp
import sys
import time
import uuid

REPO = Path(__file__).resolve().parents[2]
ENV = dict(os.environ, WORKLOAD_IFACE='tap0', WORKLOAD_SRC='192.168.64.0/24', HOSTD_IP='192.168.64.1',
           PUBLIC_IFACE='pub0', OPERATOR_CIDR='192.0.2.10/32', CTRL_PUBLIC_IP='198.51.100.1',
           CHOKE_PUBLIC_IP='198.51.100.2', NTP_IP='198.51.100.4')
SERVER = r'''
import socket, threading, time, json, subprocess

def tcp(port, ipv6=False):
    s = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(('::' if ipv6 else '0.0.0.0', port)); s.listen()
    def serve(c):
        try:
            while data := c.recv(4096): c.sendall(data)
        except OSError: pass
        finally: c.close()
    def accept():
        while True: threading.Thread(target=serve, args=(s.accept()[0],), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()

def udp(port, address):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((address, port))
    def serve():
        while True:
            data, addr = s.recvfrom(4096); s.sendto(data, addr)
    threading.Thread(target=serve, daemon=True).start()
for port in (22, 53, 80, 7001, 7100, 11434): tcp(port)
tcp(7001, ipv6=True)
for interface in json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show'])):
    for addr in interface['addr_info']:
        for port in (53, 123): udp(port, addr['local'])
print('READY', flush=True)
time.sleep(300)
'''
processes, spaces, sockets = [], [], []
checks = 0


def command(*args, ns=None, check=True, **kwargs):
    prefix = ['ip', 'netns', 'exec', ns] if ns else []
    result = sp.run(prefix + list(args), check=False, text=True, capture_output=True, **kwargs)
    if check and result.returncode:
        print(result.stderr, file=sys.stderr)
        result.check_returncode()
    return result


def check(ok, description):
    global checks
    assert ok, description
    checks += 1
    print('PASS:', description, flush=True)


def namespace():
    name = 'ds-test-' + uuid.uuid4().hex[:10]
    command('ip', 'netns', 'add', name)
    spaces.append(name)
    command('ip', 'link', 'set', 'lo', 'up', ns=name)
    return name


def link(local, peer, local_ip, peer_ip):
    command('ip', 'link', 'add', local, 'type', 'veth', 'peer', 'name', local + 'p')
    command('ip', 'link', 'set', local + 'p', 'netns', peer)
    command('ip', 'link', 'set', local + 'p', 'name', 'eth0', ns=peer)
    command('ip', 'addr', 'add', local_ip, 'dev', local)
    command('ip', 'addr', 'add', peer_ip, 'dev', 'eth0', ns=peer)
    command('ip', 'link', 'set', local, 'up')
    command('ip', 'link', 'set', 'eth0', 'up', ns=peer)


def server(ns=None):
    prefix = ['ip', 'netns', 'exec', ns] if ns else []
    p = sp.Popen(prefix + [sys.executable, '-u', '-c', SERVER], stdout=sp.PIPE, text=True)
    processes.append(p)
    assert p.stdout.readline().strip() == 'READY'


@contextlib.contextmanager
def in_namespace(ns):
    original = os.open('/proc/self/ns/net', os.O_RDONLY)
    try:
        if ns:
            fd = os.open('/run/netns/' + ns, os.O_RDONLY)
            try: os.setns(fd, 0)
            finally: os.close(fd)
        yield
    finally:
        os.setns(original, 0)
        os.close(original)


def connect(address, port, ns=None, source=None, udp=False):
    with in_namespace(ns):
        sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        sockets.append(sock)
        sock.settimeout(0.35)
        if source: sock.bind((source, 0))
        sock.connect((address, port))
        return sock


def echo(sock):
    try:
        token = uuid.uuid4().hex.encode()
        sock.sendall(token)
        return sock.recv(len(token)) == token
    except OSError:
        return False


def probe(address, port, **kwargs):
    try: return echo(connect(address, port, **kwargs))
    except OSError: return False


def gate(state, **kwargs):
    result = command('bash', str(REPO / 'infra/hetzner/evalhost-egress.sh'), state, env=ENV, **kwargs)
    if result.returncode: print(result.stderr, file=sys.stderr)
    return result


def main():
    assert os.geteuid() == 0, 'run under sudo unshare --mount --net'
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'refusing the host network namespace'
    assert os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'), 'refusing the host mount namespace'
    command('ip', 'link', 'set', 'lo', 'up')
    guest, backend, wan = namespace(), namespace(), namespace()
    link('tap0', guest, '192.168.64.1/24', '192.168.64.2/24')
    link('wg0', backend, '10.20.0.3/24', '10.20.0.2/24')
    link('pub0', wan, '198.51.100.3/24', '198.51.100.1/24')
    command('ip', 'addr', 'add', '10.20.0.1/24', 'dev', 'eth0', ns=backend)
    for addr in ('198.51.100.2/24', '198.51.100.4/24', '192.0.2.10/32', '169.254.169.254/32'):
        command('ip', 'addr', 'add', addr, 'dev', 'eth0', ns=wan)
    command('ip', 'route', 'add', 'default', 'via', '198.51.100.1')
    command('ip', 'route', 'add', 'default', 'via', '192.168.64.1', ns=guest)
    command('ip', '-6', 'addr', 'add', 'fd00:64::1/64', 'dev', 'tap0', 'nodad')
    command('ip', '-6', 'addr', 'add', 'fd00:64::2/64', 'dev', 'eth0', 'nodad', ns=guest)
    server(); server(backend); server(wan)
    command('sysctl', '-w', 'net.ipv4.ip_forward=1')
    command('nft', '-f', '-', input='table ip test_nat {\n chain post {\n type nat hook postrouting priority srcnat;\n oifname "pub0" masquerade\n }\n}\n')
    guest_flow = connect('198.51.100.1', 80, ns=guest)
    root_flow = connect('198.51.100.1', 80)
    dns_flow = connect('198.51.100.1', 53, udp=True)
    for sock in (guest_flow, root_flow, dns_flow): check(echo(sock), 'positive control before seal')
    check(probe('fd00:64::1', 7001, ns=guest), 'positive IPv6 control before seal')
    gate('seal')
    check(not echo(guest_flow), 'seal tears down guest established NAT flow')
    check(not echo(root_flow), 'seal blocks host-origin established public flow')
    check(not echo(dns_flow), 'seal blocks established public DNS')
    check(probe('192.168.64.1', 7001, ns=guest), 'guest can reach exact-action hostd endpoint')
    check(probe('10.20.0.2', 11434), 'host proxy can reach backend over wg0')
    check(probe('10.20.0.1', 7100), 'host control channel remains available')
    check(probe('198.51.100.4', 123, udp=True), 'fixed NTP endpoint remains available')
    check(probe('198.51.100.3', 22, ns=wan, source='192.0.2.10'), 'operator SSH remains available')
    check(not probe('198.51.100.3', 22, ns=wan), 'non-operator SSH is denied')
    for addr, port in (('10.20.0.2', 11434), ('10.20.0.1', 7100), ('192.168.64.1', 22), ('192.168.64.1', 53), ('169.254.169.254', 80), ('198.51.100.1', 80), ('fd00:64::1', 7001)):
        check(not probe(addr, port, ns=guest), f'guest bypass denied: {addr}:{port}')
    check(not probe('198.51.100.1', 53, ns=guest, udp=True), 'guest UDP DNS denied')
    # Re-enable kernel forwarding with an existing masquerade rule: nft still owns the boundary.
    command('sysctl', '-w', 'net.ipv4.ip_forward=1')
    check(not probe('198.51.100.1', 80, ns=guest), 'libvirt-like forwarding/NAT cannot bypass nft')
    command('ip', 'addr', 'add', '10.20.0.3/32', 'dev', 'eth0', ns=guest)
    check(not probe('10.20.0.1', 7100, ns=guest, source='10.20.0.3'), 'source-spoofed guest cannot reach management')
    def rule_count():
        return sum('rule' in item for item in json.loads(command('nft', '-j', 'list', 'ruleset').stdout)['nftables'])
    count = rule_count()
    gate('seal')
    check(rule_count() == count, 'repeated seal replaces rules without accumulation')
    proxy_flow = connect('10.20.0.2', 11434)
    hostd_flow = connect('192.168.64.1', 7001, ns=guest)
    check(echo(proxy_flow) and echo(hostd_flow), 'positive established permitted flows before cut')
    gate('cut')
    check(not echo(proxy_flow) and not echo(hostd_flow), 'cut stops established backend and guest-hostd flows')
    check(not probe('10.20.0.2', 11434) and not probe('192.168.64.1', 7001, ns=guest), 'cut stops new backend and guest-hostd flows')
    check(probe('10.20.0.1', 7100), 'cut preserves controller management path')
    gate('seal')
    command('ip', 'route', 'flush', 'table', '100')
    check(command('ip', 'route', 'get', '10.20.0.2', 'mark', '0x0d5', check=False).returncode != 0, 'empty policy table has terminal unreachable fallback')
    check(not probe('10.20.0.2', 11434), 'empty table cannot fall through to main')
    gate('seal')
    command('ip', 'link', 'set', 'wg0', 'down')
    check(not probe('10.20.0.2', 11434), 'missing tunnel cannot use public default route')
    command('ip', 'link', 'set', 'wg0', 'up')
    # Now isolate the chokepoint INPUT rules: parent output is opened only inside this test namespace.
    command('nft', 'flush', 'ruleset')
    old_ssh = connect('10.20.0.2', 22)
    check(echo(old_ssh), 'positive SSH control before chokepoint policy')
    choke_env = dict(os.environ, WG_IF='eth0', PUBLIC_IFACE='pub0', OPERATOR_CIDR='192.0.2.10/32')
    command('bash', str(REPO / 'infra/hetzner/chokepoint-forward.sh'), 'apply', env=choke_env, ns=backend)
    check(probe('10.20.0.2', 11434), 'chokepoint accepts inference from eval peer')
    check(not echo(old_ssh) and not probe('10.20.0.2', 22), 'chokepoint denies both existing and new SSH over WG')
    check(not probe('10.20.0.2', 80), 'chokepoint denies non-inference service over WG')
    print(f'{checks} kernel packet/routing checks passed; provider/WireGuard live validation still required')


try:
    main()
finally:
    for sock in sockets: sock.close()
    for p in processes:
        p.terminate()
        try: p.wait(timeout=3)
        except sp.TimeoutExpired: p.kill(); p.wait()
    for ns in reversed(spaces): command('ip', 'netns', 'del', ns, check=False)
