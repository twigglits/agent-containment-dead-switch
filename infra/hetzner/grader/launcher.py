#!/usr/bin/env python3
"""Trusted Linux-only QEMU hook implementation. Submitted bytes are opaque on this host.

The synchronous hook delegates execution to a separately bounded systemd cgroup. A trusted root
supervisor owns the read end of QEMU stdout and freezes at most 4096 candidate bytes. QEMU runs as
a dedicated unprivileged uid, has no NIC, and cannot read scorer keys, expected output or journals.
All operational failures require destruction; no failed/ambiguous claim may be launched again.
"""
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

CONFIG = Path("/etc/deadswitch-grader/launcher.json")
MAX_SUBMISSION = 65536
MAX_CAPTURE = 4096
INPUT = b"17 25\n"
SERVICE = "deadswitch-grader.service"
SLICE = "dsgrader.slice"
CGROUP = Path("/sys/fs/cgroup")
SAFE_PATH = re.compile(r"/[A-Za-z0-9_./-]+")
SID = re.compile(r"[0-9a-f]{32}")
DIGEST = re.compile(r"[0-9a-f]{64}")
IDENTITY = re.compile(r"[A-Za-z0-9_-]{1,128}")


def unique_fields(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate trusted field")
        value[key] = item
    return value


def protected(path, directory=False, traversal=False):
    st = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    allowed = 0o111 if traversal else 0
    if not expected(st.st_mode) or st.st_uid != 0 or st.st_mode & (0o077 & ~allowed):
        raise ValueError("untrusted ownership/mode or symlink")
    return st


def safe_path(raw, inspect=True):
    if type(raw) is not str or not SAFE_PATH.fullmatch(raw):
        raise ValueError("unsafe absolute path")
    path = Path(raw)
    if ".." in path.parts or str(path) != raw:
        raise ValueError("noncanonical path")
    # A trusted leaf inside a writable ancestor is not a trusted path.
    if inspect:
        for parent in path.parents:
            st = parent.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise ValueError("unsafe path ancestor")
    return path


def read_regular(path, limit, private=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        st = os.fstat(source.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & (0o077 if private else 0o022):
            raise ValueError("untrusted input file")
        if st.st_size > limit:
            raise ValueError("oversized input")
        result = source.read(limit + 1)
        if len(result) > limit or len(result) != st.st_size:
            raise ValueError("changing/oversized input")
        return result


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, data, exclusive=False):
    fd, temp = tempfile.mkstemp(prefix=".trusted-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(data, out, sort_keys=True, separators=(",", ":"))
            out.flush()
            os.fsync(out.fileno())
        if exclusive:
            os.link(temp, path, follow_symlinks=False)
            os.unlink(temp)
        else:
            os.replace(temp, path)
        fsync_dir(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def bounded_write(path, data, mode=0o400):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as out:
        # Grader/systemd use umask0077. The root-owned guest seed deliberately needs read-only
        # access for the dedicated QEMU uid; capture remains root-only 0400.
        os.fchmod(out.fileno(), mode)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    fsync_dir(path.parent)


def load_config():
    safe_path(str(CONFIG))
    raw = json.loads(read_regular(CONFIG, 8192), object_pairs_hook=unique_fields)
    if set(raw) != {"base_image", "base_sha256", "sandbox_root", "state_root", "qemu_uid", "qemu_gid", "memory_mib", "vcpus"}:
        raise ValueError("invalid launcher configuration")
    if not DIGEST.fullmatch(raw["base_sha256"]):
        raise ValueError("base digest required")
    for name in ("base_image", "sandbox_root", "state_root"):
        raw[name] = safe_path(raw[name])
    if any(type(raw[key]) is not int for key in ("qemu_uid", "qemu_gid", "memory_mib", "vcpus")):
        raise ValueError("invalid resource settings")
    if raw["qemu_uid"] <= 0 or raw["qemu_gid"] <= 0 or pwd.getpwuid(raw["qemu_uid"]).pw_name != "deadswitch-qemu":
        raise ValueError("dedicated unprivileged deadswitch-qemu user required")
    if not 64 <= raw["memory_mib"] <= 512 or not 1 <= raw["vcpus"] <= 2:
        raise ValueError("unsafe resource bounds")
    protected(raw["sandbox_root"], directory=True, traversal=True)
    protected(raw["state_root"], directory=True)
    if raw["state_root"] == raw["sandbox_root"]:
        raise ValueError("separate supervisor state and disposable storage required")
    if not (CGROUP / "cgroup.controllers").is_file():
        raise ValueError("Linux cgroup v2 required")
    return raw


@contextlib.contextmanager
def locked(config):
    path = config["state_root"] / "hook.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        protected(path)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def job_from_env(env, inspect=True):
    keys = {"sandbox_id": "DS_SANDBOX_ID", "job_id": "DS_JOB_ID", "submission_digest": "DS_SUBMISSION_DIGEST",
            "task_id": "DS_TASK_ID", "input_version": "DS_INPUT_VERSION", "scorer_version": "DS_SCORER_VERSION"}
    job = {key: env.get(var, "") for key, var in keys.items()}
    if not SID.fullmatch(job["sandbox_id"]) or not IDENTITY.fullmatch(job["job_id"]) or not DIGEST.fullmatch(job["submission_digest"]):
        raise ValueError("invalid job identity")
    if (job["task_id"], job["input_version"], job["scorer_version"]) != ("tiny-sum", "1", "1"):
        raise ValueError("unsupported trusted fixture")
    for key, var in (("job_dir", "DS_JOB_DIR"), ("capture_path", "DS_CAPTURE_PATH"), ("submission_path", "DS_SUBMISSION_PATH")):
        job[key] = str(safe_path(env.get(var, ""), inspect=inspect))
    if Path(job["capture_path"]) != Path(job["job_dir"]) / "capture.bin":
        raise ValueError("capture must be fixed launcher-owned path")
    if inspect:
        protected(Path(job["job_dir"]), directory=True)
    for key, var, upper in (("expires_at", "DS_JOB_EXPIRES_AT", 2**64 - 1), ("wall_seconds", "DS_WALL_TIMEOUT_SECS", 90)):
        text = env.get(var, "")
        if not re.fullmatch(r"[1-9][0-9]{0,19}", text) or int(text) > upper:
            raise ValueError("invalid lease/resource bound")
        job[key] = int(text)
    return job


def unit(sandbox_id):
    if not SID.fullmatch(sandbox_id):
        raise ValueError("invalid sandbox identity")
    return "ds-grader-sandbox-" + sandbox_id + ".service"


def command(args, timeout=10, check=True):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, timeout=timeout, check=False)
    if len(result.stdout) > 65536 or (check and result.returncode):
        raise ValueError("trusted command failed")
    return result


def show_unit(name):
    result = command(["/usr/bin/systemctl", "show", name, "--property=LoadState,ActiveState,SubState,ControlGroup"], check=False)
    lines = result.stdout.decode("ascii").splitlines()
    fields = unique_fields(line.split("=", 1) for line in lines)
    if set(fields) != {"LoadState", "ActiveState", "SubState", "ControlGroup"}:
        raise ValueError("incomplete systemd observation")
    missing = fields == dict(LoadState="not-found", ActiveState="inactive", SubState="dead", ControlGroup="")
    if result.returncode and not (result.returncode in {1, 4} and missing):
        raise ValueError("failed systemd observation")
    return fields


def create_seed(submission):
    """Construct a fixed archive; never parse/extract submitted bytes on the trusted host."""
    if not 0 < len(submission) <= MAX_SUBMISSION:
        raise ValueError("submission size")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in (("submission.bin", submission), ("input.txt", INPUT)):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.uid, entry.gid, entry.mtime = len(data), 0o444, 0, 0, 0
            archive.addfile(entry, io.BytesIO(data))
    return out.getvalue()


def qemu_command(config, job):
    work = config["sandbox_root"] / job["sandbox_id"]
    return ["/usr/bin/timeout", "--signal=KILL", str(job["wall_seconds"]) + "s",
            "/usr/bin/setpriv", "--reuid=" + str(config["qemu_uid"]), "--regid=" + str(config["qemu_gid"]),
            "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
            "/usr/bin/qemu-system-x86_64", "-name", "ds-grader-" + job["sandbox_id"],
            "-machine", "q35,accel=tcg", "-cpu", "max", "-m", str(config["memory_mib"]), "-smp", str(config["vcpus"]),
            "-nodefaults", "-no-user-config", "-net", "none", "-display", "none", "-monitor", "none",
            "-serial", "none", "-parallel", "none", "-no-reboot",
            "-drive", "if=virtio,format=qcow2,file=" + str(work / "overlay.qcow2"),
            "-drive", "if=virtio,format=raw,readonly=on,file=" + str(work / "input.tar"),
            "-chardev", "stdio,id=candidate,signal=off", "-device", "virtio-serial-pci",
            "-device", "virtserialport,chardev=candidate,name=deadswitch.candidate",
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]


def state_path(config, sandbox_id):
    unit(sandbox_id)
    return config["state_root"] / (sandbox_id + ".json")


def retired_path(config, sandbox_id):
    unit(sandbox_id)
    return config["state_root"] / (sandbox_id + ".retired")


def require_unretired(config, sandbox_id):
    marker = retired_path(config, sandbox_id)
    if marker.exists() or marker.is_symlink():
        raise ValueError("retired sandbox: delayed launch rejected")


def retire(config, sandbox_id):
    # Persist the barrier BEFORE stopping/checking the unit. A delayed StartTransientUnit may
    # arrive after systemctl stop returned; any later supervisor must reject before spawning
    # QEMU. A supervisor that passed its check already belongs to the unit being stopped.
    marker = retired_path(config, sandbox_id)
    try:
        bounded_write(marker, b"retired\n")
    except FileExistsError:
        protected(marker)


def read_state(config, sandbox_id):
    state = json.loads(read_regular(state_path(config, sandbox_id), 32768), object_pairs_hook=unique_fields)
    if (type(state) is not dict or set(state) != {"job", "phase", "observation"} or
            type(state["job"]) is not dict or state["job"].get("sandbox_id") != sandbox_id or
            state["phase"] not in {"claimed", "executed", "frozen", "failed", "destroyed"}):
        raise ValueError("corrupt sandbox journal")
    # Replay the environment validator: corrupt paths must not become delete/read capabilities.
    job = state["job"]
    env_keys = {"sandbox_id": "DS_SANDBOX_ID", "job_id": "DS_JOB_ID", "submission_digest": "DS_SUBMISSION_DIGEST",
                "task_id": "DS_TASK_ID", "input_version": "DS_INPUT_VERSION", "scorer_version": "DS_SCORER_VERSION",
                "job_dir": "DS_JOB_DIR", "capture_path": "DS_CAPTURE_PATH", "submission_path": "DS_SUBMISSION_PATH",
                "expires_at": "DS_JOB_EXPIRES_AT", "wall_seconds": "DS_WALL_TIMEOUT_SECS"}
    if set(job) != set(env_keys):
        raise ValueError("invalid sandbox job record")
    checked = job_from_env({var: str(job[key]) for key, var in env_keys.items()}, inspect=False)
    if checked != job:
        raise ValueError("invalid typed sandbox record")
    return state


def launch(config, job):
    require_unretired(config, job["sandbox_id"])
    now = int(time.time())
    if job["expires_at"] <= now + job["wall_seconds"]:
        raise ValueError("insufficient grading lease")
    if show_unit(SERVICE)["ActiveState"] != "active":
        raise ValueError("grader must run under its bound systemd service")
    path = state_path(config, job["sandbox_id"])
    state = {"job": job, "phase": "claimed", "observation": None}
    atomic_json(path, state, exclusive=True)  # one-shot durable intent BEFORE any launch side effect
    work = config["sandbox_root"] / job["sandbox_id"]
    work.mkdir(mode=0o711)
    work.chmod(0o711)  # preserve traversal for QEMU despite the service's private umask
    fsync_dir(config["sandbox_root"])
    base_st = config["base_image"].lstat()
    if not stat.S_ISREG(base_st.st_mode) or base_st.st_uid != 0 or base_st.st_mode & 0o222:
        raise ValueError("base must be an immutable root-owned raw file")
    # Stream the pinned base rather than allocating its size. No runtime image downloads/conversion.
    base_hash = hashlib.sha256()
    with config["base_image"].open("rb") as base:
        for part in iter(lambda: base.read(1024 * 1024), b""):
            base_hash.update(part)
    if base_hash.hexdigest() != config["base_sha256"]:
        raise ValueError("base digest mismatch")
    submission = read_regular(Path(job["submission_path"]), MAX_SUBMISSION)
    if hashlib.sha256(submission).hexdigest() != job["submission_digest"]:
        raise ValueError("submission digest mismatch")
    bounded_write(work / "input.tar", create_seed(submission), mode=0o444)
    command(["/usr/bin/qemu-img", "create", "-q", "-f", "qcow2", "-F", "raw", "-b", str(config["base_image"]), str(work / "overlay.qcow2")])
    overlay = work / "overlay.qcow2"
    os.chmod(overlay, 0o600)
    os.chown(overlay, config["qemu_uid"], config["qemu_gid"])
    args = ["/usr/bin/systemd-run", "--quiet", "--wait", "--service-type=exec", "--unit=" + unit(job["sandbox_id"]),
            "--slice=" + SLICE, "--property=BindsTo=" + SERVICE, "--property=After=" + SERVICE,
            "--property=RuntimeMaxSec=" + str(job["wall_seconds"] + 3), "--property=TimeoutStopSec=3s",
            "--property=KillMode=control-group", "--property=SendSIGKILL=yes", "--property=Restart=no",
            "--property=PrivateNetwork=yes", "--property=PrivateDevices=yes", "--property=PrivateTmp=yes",
            "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=ProtectControlGroups=yes",
            "--property=NoNewPrivileges=yes", "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=MemoryMax=" + str(config["memory_mib"] + 256) + "M", "--property=TasksMax=32",
            "--property=UMask=0077", "--property=ReadWritePaths=" + str(work) + " " + str(config["state_root"]) + " " + job["job_dir"],
            "/usr/bin/python3", "-I", str(Path(__file__).resolve()), "supervise", job["sandbox_id"]]
    command(args, timeout=job["wall_seconds"] + 8)
    completed = read_state(config, job["sandbox_id"])
    if completed["phase"] != "executed":
        raise ValueError("execution not positively observed")
    return completed["observation"]


def capture_candidate(process, wall_seconds, monotonic=time.monotonic):
    """Bound memory independently of guest exit/status messages. Never interpret candidate bytes."""
    captured = bytearray()
    deadline = monotonic() + wall_seconds
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError("hard candidate capture deadline")
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, min(4096, MAX_CAPTURE + 1 - len(captured)))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                captured.extend(chunk)
                if len(captured) > MAX_CAPTURE:
                    raise ValueError("candidate capture overflow")
        code = process.wait(timeout=max(0.001, deadline - monotonic()))
        if code != 0:
            raise ValueError("QEMU/timeout process did not exit normally")
    return bytes(captured)


def supervise(config, sandbox_id):
    require_unretired(config, sandbox_id)
    state = read_state(config, sandbox_id)
    if state["phase"] != "claimed":
        raise ValueError("no reusable execution authority")
    job = state["job"]
    if int(time.time()) + job["wall_seconds"] >= job["expires_at"]:
        raise ValueError("expired launch authority")
    started = int(time.time())
    require_unretired(config, sandbox_id)
    process = subprocess.Popen(qemu_command(config, job), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                               cwd=config["sandbox_root"] / sandbox_id, start_new_session=True, close_fds=True)
    try:
        captured = capture_candidate(process, job["wall_seconds"])
        bounded_write(Path(job["capture_path"]), captured)
        state["observation"] = dict(sandbox_id=sandbox_id, launched_artifact_digest=job["submission_digest"],
                                    started=True, exited=True, timed_out=False, started_at=started, exited_at=int(time.time()))
        state["phase"] = "executed"
        atomic_json(state_path(config, sandbox_id), state)
    except BaseException:
        # The trusted timeout remains independently active; systemd also kills every cgroup member
        # if this supervisor crashes. The handle here is a live child, not an untrusted saved PID.
        if process.poll() is None:
            process.kill()
        state["phase"] = "failed"
        atomic_json(state_path(config, sandbox_id), state)
        raise
    finally:
        process.stdout.close()


def validate_observation(observation, job):
    fields = {"sandbox_id", "launched_artifact_digest", "started", "exited", "timed_out", "started_at", "exited_at"}
    if type(observation) is not dict or set(observation) != fields:
        raise ValueError("invalid trusted lifecycle record")
    if (observation["sandbox_id"] != job["sandbox_id"] or observation["launched_artifact_digest"] != job["submission_digest"] or
            any(type(observation[key]) is not bool for key in ("started", "exited", "timed_out")) or
            not observation["started"] or not observation["exited"] or observation["timed_out"] or
            any(type(observation[key]) is not int for key in ("started_at", "exited_at")) or
            not 0 < observation["started_at"] <= observation["exited_at"] < job["expires_at"]):
        raise ValueError("unconfirmed or mismatched lifecycle")


def observe(config, job):
    state = read_state(config, job["sandbox_id"])
    if state["job"] != job or state["phase"] != "executed":
        raise ValueError("ambiguous or already frozen execution")
    validate_observation(state["observation"], job)
    view = show_unit(unit(job["sandbox_id"]))
    if view["ActiveState"] not in {"inactive", "failed"}:
        raise ValueError("execution unit remains active")
    path = Path(job["capture_path"])
    if stat.S_IMODE(protected(path).st_mode) != 0o400:
        raise ValueError("capture must be root-owned read-only")
    captured = read_regular(path, MAX_CAPTURE)
    observation = dict(state["observation"], frozen=True, captured_output_digest=hashlib.sha256(captured).hexdigest(), capture_bytes=len(captured))
    state["phase"] = "frozen"
    atomic_json(state_path(config, job["sandbox_id"]), state)
    return observation


def processes_gone(config, sandbox_id):
    name = unit(sandbox_id)
    command(["/usr/bin/systemctl", "stop", name], timeout=6, check=False)
    view = show_unit(name)
    expected = "/" + SLICE + "/" + name
    if (view["LoadState"] not in {"loaded", "not-found"} or view["ActiveState"] not in {"inactive", "failed"} or
            view["ControlGroup"] not in {"", expected}):
        raise ValueError("systemd process teardown unconfirmed")
    path = CGROUP / expected.lstrip("/")
    if path.exists():
        events = unique_fields(line.split(" ", 1) for line in (path / "cgroup.events").read_text().splitlines())
        if events.get("populated") != "0":
            raise ValueError("cgroup still populated")
    # Absence is read from the mounted cgroup-v2 hierarchy, never inferred from a PID or timeout.
    if not (CGROUP / "cgroup.controllers").is_file():
        raise ValueError("lost cgroup observer")


def destroy(config, sandbox_id):
    retirement_failed = False
    try:
        retire(config, sandbox_id)
    except (OSError, ValueError):
        # Disk/journal failure must not suppress the independent best-effort stop. Missing
        # retirement evidence still prevents a successful teardown acknowledgement below.
        retirement_failed = True
    processes_gone(config, sandbox_id)
    work = config["sandbox_root"] / sandbox_id
    if work.exists() or work.is_symlink():
        protected(work, directory=True, traversal=True)
        # After a cgroup stop no untrusted uid can mutate this root-owned directory. Never follow
        # guest-controlled mounts: the sandbox has no host filesystem mount capability.
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError("symlink-safe Linux rmtree required")
        shutil.rmtree(work)
        fsync_dir(config["sandbox_root"])
    if work.exists() or work.is_symlink():
        raise ValueError("storage teardown unconfirmed")
    path = state_path(config, sandbox_id)
    if path.exists():
        state = read_state(config, sandbox_id)
        state["phase"] = "destroyed"
        atomic_json(path, state)
    if retirement_failed:
        raise ValueError("retirement barrier unavailable: quarantine")
    return dict(sandbox_id=sandbox_id, processes_gone=True, storage_gone=True, teardown_confirmed_at=int(time.time()))


def destroy_all(config):
    listing = command(["/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend", "--no-pager", "ds-grader-sandbox-*.service"])
    identities = set()
    for line in listing.stdout.decode("ascii").splitlines():
        found = re.fullmatch(r"ds-grader-sandbox-([0-9a-f]{32})\.service", line.split()[0])
        if not found:
            raise ValueError("unknown sandbox unit: quarantine")
        identities.add(found[1])
    for entry in config["sandbox_root"].iterdir():
        if not SID.fullmatch(entry.name):
            raise ValueError("unknown disposable storage: quarantine")
        identities.add(entry.name)
    errors = []
    for entry in config["state_root"].glob("*.json"):
        if not SID.fullmatch(entry.stem):
            raise ValueError("unknown sandbox journal: quarantine")
        try:
            archived = read_state(config, entry.stem)
            if archived["phase"] != "destroyed":
                identities.add(entry.stem)
            else:
                retire(config, entry.stem)
        except (OSError, ValueError, KeyError, TypeError):
            errors.append("corrupt journal")
            identities.add(entry.stem)
    if len(identities) > 4096:
        raise ValueError("operator archival required before further grading")
    for sandbox_id in sorted(identities):
        try:
            destroy(config, sandbox_id)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(type(error).__name__)
    if errors or list(config["sandbox_root"].iterdir()):
        raise ValueError("global sandbox teardown unconfirmed")
    return dict(processes_gone=True, storage_gone=True, teardown_confirmed_at=int(time.time()))


def main():
    if os.geteuid() != 0 or sys.platform != "linux":
        raise ValueError("trusted Linux root launcher required")
    config = load_config()
    mode = sys.argv[1] if len(sys.argv) >= 2 else ""
    if mode == "supervise" and len(sys.argv) == 3:
        supervise(config, sys.argv[2])
        return
    if len(sys.argv) != 2:
        raise ValueError("one hook action required")
    with locked(config):
        if mode == "destroy-all":
            result = destroy_all(config)
        elif mode == "destroy":
            result = destroy(config, os.environ.get("DS_SANDBOX_ID", ""))
        elif mode in {"launch", "observe"}:
            job = job_from_env(os.environ)
            result = launch(config, job) if mode == "launch" else observe(config, job)
        else:
            raise ValueError("unknown hook")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, TimeoutError, subprocess.SubprocessError):
        print("GRADER_HOOK_INCOMPLETE: quarantine until positive teardown", file=sys.stderr)
        sys.exit(1)
