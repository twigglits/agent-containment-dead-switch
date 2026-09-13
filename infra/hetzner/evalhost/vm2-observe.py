#!/usr/bin/env python3
"""Read-only evidence for vm2-boot.sh's supported QEMU launch profile."""

import json
import os
from pathlib import Path


def vm2_config(argv, image, nested_enabled, workload_iface='dstap0'):
    """Recognize the host-owned launch profile; unfamiliar configuration stays unobservable.

    A live PID alone cannot establish nesting, absence of forwarded ports, or shared mounts.
    Restrict configuration sources/devices so an added QEMU option cannot silently report zeros.
    The writable VM disk is intentional and is not a shared host-directory mount.
    """
    unknown = dict(nested_virt=None, port_forwards=None, writable_mounts=None)
    flags = {'-nographic', '-nodefaults', '-no-user-config'}
    pairs = {'-name', '-machine', '-cpu', '-smp', '-m', '-drive', '-netdev', '-device',
             '-serial', '-display', '-pidfile'}
    options = {}
    index = 1
    while index < len(argv):
        flag = argv[index]
        if flag in flags:
            options.setdefault(flag, []).append(True)
            index += 1
        elif flag in pairs and index + 1 < len(argv):
            options.setdefault(flag, []).append(argv[index + 1])
            index += 2
        else:
            return unknown
    if not all(options.get(flag) == [True] for flag in flags):
        return unknown
    if (options.get('-name') != ['deadswitch-vm2']
            or options.get('-machine') != ['q35,accel=kvm']
            or options.get('-drive') != [f'if=virtio,format=qcow2,file={image}']
            or options.get('-serial') != [f'file:{image.parent / "vm2-serial.log"}']
            or options.get('-display') != ['none']
            or options.get('-pidfile') != [str(image.parent / 'vm2.pid')]
            or len(options.get('-smp', [])) != 1
            or len(options.get('-m', [])) != 1):
        return unknown
    networks = options.get('-netdev', [])
    devices = options.get('-device', [])
    # Only a tap can provide the VM's network. Usernet/hostfwd, config files, arbitrary devices,
    # fsdev/virtfs, TCP serial/monitor/display and vhost-user backends fall outside this profile.
    # The tap identity must match the kernel gate, not merely look like some tap device.
    tap = networks == [f'tap,id=n0,ifname={workload_iface},script=no,downscript=no']
    known_devices = (len(devices) == 2 and 'virtio-rng-pci' in devices
                     and 'virtio-net-pci,netdev=n0,mac=52:54:00:99:00:02,romfile=' in devices)
    if not tap or not known_devices:
        return unknown
    return dict(nested_virt=nested_enabled if options.get('-cpu') == ['host'] else None,
                port_forwards=0, writable_mounts=0)


def host_nested_enabled():
    observed = []
    for module in ('kvm_intel', 'kvm_amd'):
        try:
            value = Path(f'/sys/module/{module}/parameters/nested').read_text().strip().lower()
        except OSError:
            continue
        if value in ('y', '1', 'n', '0'):
            observed.append(value in ('y', '1'))
    return any(observed) if observed else None


def observe(directory):
    result = dict(running=None, pid=None, nested_virt=None, port_forwards=None, writable_mounts=None)
    try:
        pid = int((directory / 'vm2.pid').read_text().strip())
        if pid <= 1:
            return result
        proc = Path(f'/proc/{pid}')
        argv = (proc / 'cmdline').read_bytes().decode().rstrip('\0').split('\0')
        executable = Path(os.readlink(proc / 'exe')).name
        os.kill(pid, 0)
        if executable != 'qemu-system-x86_64' or not any(
                argv[i:i + 2] == ['-name', 'deadswitch-vm2'] for i in range(len(argv))):
            result['running'] = False
            return result
        result.update(running=True, pid=pid)
        result.update(vm2_config(argv, directory / 'vm2.qcow2', host_nested_enabled(),
                                 os.environ.get('WORKLOAD_IFACE', 'dstap0')))
    except (FileNotFoundError, ProcessLookupError):
        result['running'] = False
    except (OSError, ValueError, UnicodeError):
        pass  # Unreadable/invalid observations never become positive health.
    return result


if __name__ == '__main__':
    print(json.dumps(observe(Path(os.environ.get('DS_VM2_DIR', '/var/lib/deadswitch/vm2')))))
