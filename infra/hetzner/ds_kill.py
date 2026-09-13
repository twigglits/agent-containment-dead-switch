"""Bounded, journaled provider dispatch; never confuse reset acceptance with termination.

Required: DS_RUN_ID, DS_INCARNATION, DS_ALLOCATION_ID, DS_FENCING_TOKEN,
DS_SERVER_NUMBER, DS_CHOKEPOINT_ID, DS_EVALHOST_IP. The journal pins one allocation to a
physical server and has NO automatic reallocation/unlock path. The future allocator must
coordinate that boundary, including uncertain in-flight resets; an incarnation hash alone
cannot fence a Robot request. Missing/corrupt initialized state requires reconciliation.
Credentials: environment or mode-0600 DS_ENV_FILE (default /etc/deadswitch/actuator.env).
"""
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

CLOUD_API = "https://api.hetzner.cloud/v1"
ROBOT_API = "https://robot-ws.your-server.de"


def private_file(path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError("state/credential file must be regular, private and owned by this user")


def atomic_write(path, value):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".actuator-")
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(value, out, sort_keys=True)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def credentials():
    values = {}
    path = Path(os.environ.get("DS_ENV_FILE", "/etc/deadswitch/actuator.env"))
    if path.exists():
        private_file(path)
        for line in path.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and key in {"HETZNER_API_KEY", "HETZNER_ROBOT_USER", "HETZNER_ROBOT_USERNAME_1", "HETZNER_ROBOT_PASSWORD"}:
                values[key] = value
    values.update(os.environ)
    return (values.get("HETZNER_API_KEY", ""),
            values.get("HETZNER_ROBOT_USER") or values.get("HETZNER_ROBOT_USERNAME_1", ""),
            values.get("HETZNER_ROBOT_PASSWORD", ""))


def request(method, url, authorization, data=None):
    """No retry, redirects, ambient proxy/curlrc, or credentials in argv. Bound total runtime.

    HTTP and transport statuses are separate: a real HTTP 404 is not the string '404000'.
    Never log provider bodies. Credentials enter curl through stdin, not its command line.
    """
    if any(c in authorization for c in "\r\n\0"):
        raise ValueError("invalid credential encoding")
    escaped = authorization.replace("\\", "\\\\").replace('"', '\\"')
    with tempfile.TemporaryDirectory(prefix="ds-http-") as tmp:
        body, headers = Path(tmp) / "body", Path(tmp) / "headers"
        cmd = ["curl", "--disable", "--silent", "--globoff", "--proto", "=https",
               "--noproxy", "*", "--connect-timeout", "5", "--max-time", "20",
               "--max-filesize", "65536", "--config", "-", "--request", method,
               "--output", str(body), "--dump-header", str(headers), "--write-out", "%{http_code}", url]
        if data is not None:
            cmd += ["--data", data]
        try:
            out = subprocess.run(cmd, input=f'header = "Authorization: {escaped}"\n',
                                 text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=25, check=False)
        except subprocess.TimeoutExpired:
            return 0, {}, 0
        if out.returncode or not re.fullmatch(r"[0-9]{3}", out.stdout):
            return 0, {}, 0
        retry = 0
        for line in headers.read_text().splitlines():
            if line.lower().startswith("retry-after:"):
                val = line.partition(":")[2].strip()
                retry = max(retry, int(val) if val.isdecimal() else 3600)
        raw = body.read_bytes()
        try:
            payload = json.loads(raw) if len(raw) <= 65536 else {}
        except (ValueError, UnicodeDecodeError):
            payload = {}
        return int(out.stdout), payload if isinstance(payload, dict) else {}, retry


def target_from_env():
    target = {k: os.environ.get("DS_" + k.upper(), "") for k in
              ("run_id", "incarnation", "allocation_id", "server_number", "chokepoint_id", "evalhost_ip")}
    for key in ("server_number", "chokepoint_id"):
        if not re.fullmatch(r"[1-9][0-9]*", target[key]):
            raise ValueError(f"DS_{key.upper()} must be a positive numeric ID")
    for key in ("run_id", "incarnation", "allocation_id"):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", target[key]):
            raise ValueError(f"DS_{key.upper()} is required")
    ipaddress.IPv4Address(target["evalhost_ip"])
    token = os.environ.get("DS_FENCING_TOKEN", "")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", token) or int(token) > 2**64 - 1:
        raise ValueError("DS_FENCING_TOKEN must be a positive u64")
    return target, int(token)


@contextlib.contextmanager
def journal(directory, target, token):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError("actuator state directory must be private and owned by this user")
    lock_path = directory / (target["server_number"] + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        private_file(lock_path)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = directory / (target["server_number"] + ".json")
        initialized = lock.read().strip()
        if path.exists():
            private_file(path)
            state = json.loads(path.read_text())
            if state["target"] != target or token < state["high_water"]:
                raise ValueError("stale token or different allocation: physical server remains quarantined")
        else:
            if initialized:
                raise ValueError("lost actuator journal: reconciliation required")
            state = {"target": target, "high_water": token, "clock_floor": 0,
                     "egress_cut": False, "reset_attempted": False, "reset_accepted": False,
                     "cloud_retry_at": 0, "robot_retry_at": 0}
        state["high_water"] = token
        atomic_write(path, state)
        lock.seek(0)
        lock.write("initialized\n")
        lock.flush()
        os.fsync(lock.fileno())
        yield state, lambda: atomic_write(path, state)


def object_field(value, key):
    field = value.get(key)
    return field if isinstance(field, dict) else {}


class Actuator:
    def __init__(self, state, save, creds, http=request, clock=time.time):
        self.s, self.save, self.creds, self.http, self.clock = state, save, creds, http, clock

    def call(self, provider, method, path, data=None):
        now = int(self.clock())
        if now < self.s["clock_floor"] or now < self.s[provider + "_retry_at"]:
            return 0, {}
        self.s["clock_floor"] = now
        # Persist minimum spacing BEFORE I/O; survives death/ambiguous replies. Robot has separate
        # 50 POST/hour and 500 GET/hour limits; 403 RATE_LIMIT_EXCEEDED is its documented response.
        spacing = 75 if provider == "robot" and method == "POST" else 8 if provider == "robot" else 2
        self.s[provider + "_retry_at"] = now + spacing
        self.save()
        if provider == "cloud":
            auth, api = "Bearer " + self.creds[0], CLOUD_API
        else:
            import base64
            auth = "Basic " + base64.b64encode((self.creds[1] + ":" + self.creds[2]).encode()).decode()
            api = ROBOT_API
        code, body, retry = self.http(method, api + path, auth, data)
        error = object_field(body, "error")
        throttled = code == 429 or (code == 403 and error.get("code") == "RATE_LIMIT_EXCEEDED")
        if throttled or code == 0 or code >= 500:
            self.s[provider + "_retry_at"] = max(self.s[provider + "_retry_at"], now + max(retry, 3600 if throttled else 75))
        self.save()
        return code, body

    def cut(self):
        if self.s["egress_cut"]:
            return True
        if not self.creds[0]:
            return False
        path = "/servers/" + self.s["target"]["chokepoint_id"]
        code, body = self.call("cloud", "GET", path)
        if code == 404:
            self.s["egress_cut"] = True
            self.save()
            return True
        if code == 200 and str(object_field(body, "server").get("id")) == self.s["target"]["chokepoint_id"]:
            # GET->DELETE may proceed immediately. Confirmation is a separate GET on a later
            # invocation. Neither DELETE acceptance nor a timeout is proof the server is gone.
            self.s["cloud_retry_at"] = 0
            self.call("cloud", "DELETE", path)
        return False

    def reset(self):
        if self.s["reset_attempted"] or not all(self.creds[1:]):
            return
        target = self.s["target"]
        path = "/reset/" + target["server_number"]
        code, body = self.call("robot", "GET", path)
        reset = object_field(body, "reset")
        if code != 200 or str(reset.get("server_number")) != target["server_number"] or reset.get("server_ip") != target["evalhost_ip"] or not isinstance(reset.get("type"), list) or "hw" not in reset["type"]:
            return
        # Persist uncertainty BEFORE dispatch. Death/timeout must never trigger an automatic second
        # reset that could strike a later boot/allocation. Only proven rejection can be retried.
        self.s["reset_attempted"] = True
        self.s["robot_retry_at"] = 0
        self.save()
        code, body = self.call("robot", "POST", path, "type=hw")
        self.s["reset_accepted"] = code == 200 and object_field(body, "reset").get("type") == "hw"
        error = object_field(body, "error")
        if code == 429 or (code == 403 and error.get("code") == "RATE_LIMIT_EXCEEDED"):
            self.s["reset_attempted"] = False
        self.save()


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode not in {"cut", "kill"}:
        raise ValueError("usage: ds-kill.sh cut|kill")
    if os.geteuid() != 0:
        raise ValueError("actuator must run as root on the controller")
    target, token = target_from_env()
    with journal(Path(os.environ.get("DS_ACTUATOR_STATE_DIR", "/var/lib/deadswitch/actuator")), target, token) as (state, save):
        actuator = Actuator(state, save, credentials())
        cut = actuator.cut()
        if mode == "cut":
            print("EGRESS_CUT" if cut else "INCOMPLETE: deletion not yet confirmed")
            return 0 if cut else 1
        actuator.reset()  # independent of cloud-layer failure
        print(f"INCOMPLETE: egress_cut={cut} reset_accepted={state['reset_accepted']}; physical termination UNCONFIRMED")
        # Robot acceptance/reachability/ping loss does not prove termination. Keep the allocation
        # quarantined until an independently qualified hardware observer has been implemented.
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError):
        print("INCOMPLETE: invalid/unavailable configuration or journal; operator reconciliation required", file=sys.stderr)
        sys.exit(3)
