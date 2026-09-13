#!/bin/sh
# Install ONLY in the immutable guest image as the boot-time runner. This is guest code.
# BusyBox sh/tar, virtio_blk and virtio_console support must be built into the pinned image.
# The root scorer never executes this runner or imports the candidate on the grader host.
set -eu
mount -t tmpfs -o size=1m,nodev,nosuid tmpfs /run/candidate
cd /run/candidate
tar -xf /dev/vdb submission.bin input.txt
chmod 0444 submission.bin input.txt
# No guest PASS/status report is authoritative. Exit merely powers the throwaway guest down.
/bin/sh /run/candidate/submission.bin </run/candidate/input.txt >/dev/virtio-ports/deadswitch.candidate 2>/dev/null || true
sync
poweroff -f
