"""Trusted hook regressions, using pipes/temporary files and mocked Linux supervisors only.

No QEMU, systemd, privileged network mutation, SSH or provider request is executed.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import types
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("grader_launcher", REPO / "infra/hetzner/grader/launcher.py")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def job_fixture():
    return dict(sandbox_id="a" * 32, job_id="job1", submission_digest=hashlib.sha256(b"opaque submission").hexdigest(),
                task_id="tiny-sum", input_version="1", scorer_version="1", job_dir="/var/lib/grader/job1",
                capture_path="/var/lib/grader/job1/capture.bin", submission_path="/var/lib/grader/job1/submission.bin",
                expires_at=int(time.time()) + 120, wall_seconds=30)


class PipeProcess:
    def __init__(self, data, code=0, close=True):
        reader, self.writer = os.pipe()
        self.stdout = os.fdopen(reader, "rb", buffering=0)
        os.write(self.writer, data)
        if close:
            os.close(self.writer)
            self.writer = None
        self.code, self.killed = code, False

    def wait(self, timeout):
        return self.code

    def poll(self):
        return self.code

    def kill(self):
        self.killed = True

    def close(self):
        self.stdout.close()
        if self.writer is not None:
            os.close(self.writer)


class GraderHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("sandbox", "state", "cgroup", "job"):
            (self.root / name).mkdir()
        (self.root / "cgroup/cgroup.controllers").write_text("cpu memory pids")
        self.config = dict(sandbox_root=self.root / "sandbox", state_root=self.root / "state", base_image=self.root / "base.raw",
                           base_sha256="b" * 64, qemu_uid=991, qemu_gid=991, memory_mib=256, vcpus=1)
        self.job = job_fixture()

    def test_seed_is_fixed_readonly_input_plus_opaque_submission_only(self):
        # Deliberately malicious-looking content is neither unpacked nor imported on the host.
        candidate = b'../../key\0#!/bin/sh\ncat /etc/deadswitch-grader/scorer.key\nPASS\n'
        seed = launcher.create_seed(candidate)
        with tarfile.open(fileobj=io.BytesIO(seed)) as archive:
            self.assertEqual(archive.getnames(), ["submission.bin", "input.txt"])
            self.assertEqual(archive.extractfile("submission.bin").read(), candidate)
            self.assertEqual(archive.extractfile("input.txt").read(), b"17 25\n")
            self.assertTrue(all(member.mode == 0o444 for member in archive.getmembers()))
        for bad in (b"", b"x" * 65537):
            with self.assertRaises(ValueError):
                launcher.create_seed(bad)

    def test_qemu_profile_is_software_no_network_no_host_secret_or_monitor(self):
        args = launcher.qemu_command(self.config, self.job)
        self.assertEqual(args[args.index("-machine") + 1], "q35,accel=tcg")
        self.assertEqual(args[args.index("-net") + 1], "none")
        self.assertEqual(args[args.index("-monitor") + 1], "none")
        self.assertEqual(args[args.index("-m") + 1], "256")
        self.assertEqual(args[args.index("-smp") + 1], "1")
        self.assertIn("--no-new-privs", args)
        self.assertIn("--reuid=991", args)
        self.assertIn("stdio,id=candidate,signal=off", args)
        self.assertTrue(any("readonly=on" in arg and "input.tar" in arg for arg in args))
        self.assertFalse(any(word in " ".join(args) for word in ("expected-output", "scorer.key", "-netdev", "9p", "-virtfs", "-qmp", "accel=kvm")))

    def test_capture_preserves_forged_pass_as_untrusted_bytes(self):
        for candidate in (b"42\n", b"0\n", b'{"status":"PASS","started":true}\n', bytes(range(256))):
            process = PipeProcess(candidate)
            self.addCleanup(process.close)
            self.assertEqual(launcher.capture_candidate(process, 1), candidate)

    def test_capture_overflow_crash_and_stall_fail_closed(self):
        for data, code in ((b"x" * 4097, 0), (b"42\n", 1), (b"42\n", -9), (b"42\n", 124)):
            process = PipeProcess(data, code)
            self.addCleanup(process.close)
            with self.assertRaises(ValueError):
                launcher.capture_candidate(process, 1)
        process = PipeProcess(b"", close=False)
        self.addCleanup(process.close)
        ticks = iter([1, 3])
        with self.assertRaises(TimeoutError):
            launcher.capture_candidate(process, 1, monotonic=lambda: next(ticks))

    def test_supervisor_records_host_lifecycle_and_freezes_opaque_capture(self):
        candidate = b'{"status":"PASS","started_at":1,"exited_at":1}\n'
        process = PipeProcess(candidate)
        state = dict(job=self.job, phase="claimed", observation=None)
        with mock.patch.object(launcher, "read_state", return_value=state), \
                mock.patch.object(launcher.subprocess, "Popen", return_value=process) as popen, \
                mock.patch.object(launcher, "bounded_write") as output, \
                mock.patch.object(launcher, "atomic_json") as save:
            launcher.supervise(self.config, self.job["sandbox_id"])
        output.assert_called_once_with(Path(self.job["capture_path"]), candidate)
        self.assertEqual(state["phase"], "executed")
        self.assertGreater(state["observation"]["started_at"], 1)
        self.assertNotIn("status", state["observation"])
        self.assertTrue(state["observation"]["exited"])
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(set(popen.call_args.kwargs["env"]), {"PATH", "LC_ALL"})
        self.assertTrue(save.called)

    def test_observe_freezes_only_positive_lifecycle_and_digest(self):
        observation = dict(sandbox_id=self.job["sandbox_id"], launched_artifact_digest=self.job["submission_digest"],
                           started=True, exited=True, timed_out=False, started_at=10, exited_at=11)
        state = dict(job=self.job, phase="executed", observation=observation)
        with mock.patch.object(launcher, "read_state", return_value=state), \
                mock.patch.object(launcher, "show_unit", return_value={"ActiveState": "inactive"}), \
                mock.patch.object(launcher, "protected", return_value=types.SimpleNamespace(st_mode=0o100400)), \
                mock.patch.object(launcher, "read_regular", return_value=b"42\n"), \
                mock.patch.object(launcher, "atomic_json") as save:
            frozen = launcher.observe(self.config, self.job)
            self.assertTrue(frozen["frozen"])
            self.assertEqual(frozen["captured_output_digest"], hashlib.sha256(b"42\n").hexdigest())
            self.assertEqual(frozen["capture_bytes"], 3)
            self.assertEqual(state["phase"], "frozen")
            self.assertTrue(save.called)
            with self.assertRaises(ValueError):
                launcher.observe(self.config, self.job)
        for update in ({"started": "true"}, {"timed_out": True}, {"exited": False}, {"launched_artifact_digest": "0" * 64},
                       {"started_at": True}, {"exited_at": self.job["expires_at"]}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                launcher.validate_observation(dict(observation, **update), self.job)

    def test_launch_digest_mismatch_never_starts_qemu_or_unit(self):
        base = self.config["base_image"]
        base.write_bytes(b"reviewed base")
        base.chmod(0o400)
        self.config["base_sha256"] = hashlib.sha256(base.read_bytes()).hexdigest()
        real_lstat = Path.lstat

        def root_lstat(path):
            original = real_lstat(path)
            return types.SimpleNamespace(st_mode=original.st_mode, st_uid=0)

        with mock.patch.object(launcher, "show_unit", return_value={"ActiveState": "active"}), \
                mock.patch.object(launcher, "read_regular", return_value=b"different bytes"), \
                mock.patch.object(Path, "lstat", root_lstat), mock.patch.object(launcher, "command") as command:
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                launcher.launch(self.config, self.job)
        self.assertFalse(command.called)
        record = json.loads(launcher.state_path(self.config, self.job["sandbox_id"]).read_text())
        self.assertEqual(record["phase"], "claimed", "uncertain/failed claim is durable and never reusable")
        with self.assertRaises(FileExistsError):
            launcher.atomic_json(launcher.state_path(self.config, self.job["sandbox_id"]), record, exclusive=True)

    def test_positive_cgroup_observation_required_before_storage_removal(self):
        sid = self.job["sandbox_id"]
        name = launcher.unit(sid)
        cg = self.root / "cgroup" / launcher.SLICE / name
        cg.mkdir(parents=True)
        (cg / "cgroup.events").write_text("populated 1\nfrozen 0\n")
        work = self.config["sandbox_root"] / sid
        work.mkdir()
        (work / "poison-A").write_text("poison")
        view = dict(LoadState="loaded", ActiveState="inactive", SubState="dead", ControlGroup="/" + launcher.SLICE + "/" + name)
        with mock.patch.object(launcher, "CGROUP", self.root / "cgroup"), \
                mock.patch.object(launcher, "command", return_value=types.SimpleNamespace(returncode=0)), \
                mock.patch.object(launcher, "show_unit", return_value=view), \
                mock.patch.object(launcher, "protected"), \
                mock.patch.object(launcher.shutil.rmtree, "avoids_symlink_attacks", True):
            with self.assertRaises(ValueError):
                launcher.destroy(self.config, sid)
            self.assertTrue((work / "poison-A").exists())
            (cg / "cgroup.events").write_text("populated 0\nfrozen 0\n")
            result = launcher.destroy(self.config, sid)
            self.assertTrue(result["processes_gone"] and result["storage_gone"])
            self.assertFalse(work.exists())
            fresh = self.config["sandbox_root"] / ("b" * 32)
            fresh.mkdir()
            self.assertEqual(list(fresh.iterdir()), [])

    def test_missing_failed_and_unexpected_cgroup_observations_do_not_confirm(self):
        for view in (dict(LoadState="loaded", ActiveState="active", SubState="running", ControlGroup=""),
                     dict(LoadState="loaded", ActiveState="inactive", SubState="dead", ControlGroup="/different")):
            with mock.patch.object(launcher, "command"), mock.patch.object(launcher, "show_unit", return_value=view):
                with self.assertRaises(ValueError):
                    launcher.processes_gone(self.config, "a" * 32)
        for raw, status in ((b"", 1), (b"LoadState=not-found\n", 1),
                            (b"LoadState=not-found\nActiveState=inactive\nSubState=dead\nControlGroup=\n", 127)):
            with mock.patch.object(launcher, "command", return_value=types.SimpleNamespace(stdout=raw, returncode=status)):
                with self.assertRaises(ValueError):
                    launcher.show_unit(launcher.unit("a" * 32))

    def test_global_cleanup_attempts_all_despite_actuator_failure(self):
        for sid in ("a" * 32, "b" * 32):
            (self.config["sandbox_root"] / sid).mkdir()
        attempted = []

        def destroy(config, sid):
            attempted.append(sid)
            raise ValueError("mock uncertainty")

        with mock.patch.object(launcher, "command", return_value=types.SimpleNamespace(stdout=b"")), \
                mock.patch.object(launcher, "destroy", side_effect=destroy):
            with self.assertRaises(ValueError):
                launcher.destroy_all(self.config)
        self.assertEqual(attempted, ["a" * 32, "b" * 32])

    def test_unsafe_identifiers_paths_and_guest_forged_observations_rejected(self):
        for sid in ("../other", "A" * 32, "", "a" * 31):
            with self.assertRaises(ValueError):
                launcher.unit(sid)
        for path in ("relative", "/safe/../other", "/x,key=secret", "/x//other"):
            with self.assertRaises(ValueError):
                launcher.safe_path(path, inspect=False)
        with self.assertRaises(ValueError):
            launcher.validate_observation({"PASS": True}, self.job)


if __name__ == "__main__":
    unittest.main()
