"""Pure observation regressions; no QEMU, /proc access, networking or privileged commands."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / 'infra/hetzner/evalhost/vm2-observe.py'
SPEC = importlib.util.spec_from_file_location('vm2_observe', SOURCE)
OBSERVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVE)


class ObservationTests(unittest.TestCase):
    def argv(self):
        return ['qemu-system-x86_64', '-name', 'deadswitch-vm2', '-machine', 'q35,accel=kvm',
                '-cpu', 'host', '-smp', '4', '-m', '16384', '-nographic', '-nodefaults',
                '-no-user-config', '-drive', 'if=virtio,format=qcow2,file=/vm2/vm2.qcow2',
                '-netdev', 'tap,id=n0,ifname=dstap0,script=no,downscript=no',
                '-device', 'virtio-net-pci,netdev=n0,mac=52:54:00:99:00:02,romfile=',
                '-device', 'virtio-rng-pci', '-serial', 'file:/vm2/vm2-serial.log',
                '-display', 'none', '-pidfile', '/vm2/vm2.pid']

    def config(self, argv, nested=True):
        return OBSERVE.vm2_config(argv, Path('/vm2/vm2.qcow2'), nested)

    def test_supported_boot_profile_and_unknown_nesting(self):
        for nested in (True, False, None):
            self.assertEqual(self.config(self.argv(), nested),
                             dict(nested_virt=nested, port_forwards=0, writable_mounts=0))

    def test_drift_does_not_invent_healthy_observations(self):
        for option in (['-readconfig', 'extra.conf'], ['-virtfs', 'local,path=/host'],
                       ['-fsdev', 'local,id=fs,path=/host'], ['-device', 'vhost-user-fs-pci'],
                       ['-netdev', 'user,id=n1,hostfwd=tcp::8000-:80']):
            with self.subTest(option=option):
                result = self.config(self.argv() + option)
                self.assertIsNone(result['writable_mounts'])
                self.assertIsNone(result['port_forwards'])
        argv = self.argv()
        argv.remove('-no-user-config')
        self.assertIsNone(self.config(argv)['port_forwards'])
        argv = self.argv()
        argv[argv.index('host')] = 'host,-vmx'
        self.assertIsNone(self.config(argv)['nested_virt'])
        argv = self.argv()
        index = argv.index('-netdev') + 1
        argv[index] = 'user,id=n0,hostfwd=tcp::8000-:80'
        self.assertIsNone(self.config(argv)['port_forwards'])

    def test_host_kvm_parameter_must_be_observed(self):
        with patch.object(Path, 'read_text', side_effect=FileNotFoundError):
            self.assertIsNone(OBSERVE.host_nested_enabled())
        for enabled in ('Y', '1', 'N', '0'):
            with patch.object(Path, 'read_text', side_effect=[enabled, FileNotFoundError()]):
                self.assertEqual(OBSERVE.host_nested_enabled(), enabled in ('Y', '1'))

    def test_host_network_backends_and_foreign_taps_are_not_healthy(self):
        for flag, value in (
            ('-serial', 'tcp:10.20.0.2:11434'),
            ('-serial', 'mon:stdio'),
            ('-display', 'vnc=10.20.0.3:0'),
            ('-netdev', 'tap,id=n0,ifname=other0,script=no,downscript=no'),
            ('-pidfile', '/other/vm2.pid'),
        ):
            with self.subTest(flag=flag, value=value):
                argv = self.argv()
                argv[argv.index(flag) + 1] = value
                self.assertEqual(self.config(argv),
                                 dict(nested_virt=None, port_forwards=None, writable_mounts=None))
        argv = self.argv()
        argv[argv.index('-netdev') + 1] = 'tap,id=n0,ifname=custom0,script=no,downscript=no'
        self.assertEqual(OBSERVE.vm2_config(argv, Path('/vm2/vm2.qcow2'), True, 'custom0'),
                         dict(nested_virt=True, port_forwards=0, writable_mounts=0))

    def test_unobservable_or_dead_process_cannot_claim_running(self):
        for error, running in [(FileNotFoundError, False), (PermissionError, None), (ValueError, None)]:
            with patch.object(Path, 'read_text', side_effect=error):
                self.assertEqual(OBSERVE.observe(Path('/vm2')),
                                 dict(running=running, pid=None, nested_virt=None,
                                      port_forwards=None, writable_mounts=None))


if __name__ == '__main__':
    unittest.main()
