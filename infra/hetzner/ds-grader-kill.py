#!/usr/bin/env python3
"""Off-host grader deletion: durable intent, separate positive absence observation, quarantine.

Runs on the controller, never in the grader or a candidate. Reuses ds_kill's bounded HTTPS
transport/private-state primitives. No automatic reallocation or ambiguous DELETE retry.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from ds_kill import CLOUD_API, atomic_write, credentials, private_file, request, unique_fields


def target_from_env():
    target = {key: os.environ.get("DS_" + key.upper(), "") for key in
              ("run_id", "incarnation", "allocation_id", "grader_server_id")}
    for key in ("run_id", "incarnation", "allocation_id"):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", target[key]):
            raise ValueError("missing/invalid grader identity")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", target["grader_server_id"]):
        raise ValueError("DS_GRADER_SERVER_ID must be a positive cloud server ID")
    raw = os.environ.get("DS_FENCING_TOKEN", "")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", raw) or int(raw) > 2**64 - 1:
        raise ValueError("DS_FENCING_TOKEN must be positive u64")
    return target, int(raw)


def validate_state(state, target):
    counters = {"high_water", "clock_floor", "retry_at"}
    flags = {"delete_attempted", "delete_accepted", "absence_confirmed", "quarantined"}
    if type(state) is not dict or set(state) != {"target", *counters, *flags}:
        raise ValueError("invalid grader actuator journal schema")
    if state["target"] != target or type(state["target"]) is not dict:
        raise ValueError("allocation mismatch: grader ID remains quarantined")
    if any(type(state[key]) is not int or not 0 <= state[key] <= 2**64 - 1 for key in counters):
        raise ValueError("invalid journal counter")
    if state["high_water"] == 0 or any(type(state[key]) is not bool for key in flags):
        raise ValueError("invalid journal authority")
    if not state["quarantined"] or (state["delete_accepted"] and not state["delete_attempted"]):
        raise ValueError("invalid deletion/quarantine state")


@contextlib.contextmanager
def journal(directory, target, token):
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    st = directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError("grader actuator directory must be private")
    lock_path = directory / (target["grader_server_id"] + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        private_file(lock_path)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = directory / (target["grader_server_id"] + ".json")
        initialized = lock.read().strip()
        if path.exists():
            private_file(path)
            if path.stat().st_size > 65536:
                raise ValueError("oversized journal")
            state = json.loads(path.read_text(), object_pairs_hook=unique_fields)
            validate_state(state, target)
            if token < state["high_water"]:
                raise ValueError("stale fencing token")
        else:
            if initialized:
                raise ValueError("lost journal: reconciliation required")
            state = dict(target=target, high_water=token, clock_floor=0, retry_at=0,
                         delete_attempted=False, delete_accepted=False,
                         absence_confirmed=False, quarantined=True)
        state["high_water"] = token
        atomic_write(path, state)
        lock.seek(0)
        lock.write("initialized\n")
        lock.flush()
        os.fsync(lock.fileno())
        yield state, lambda: atomic_write(path, state)


class GraderActuator:
    def __init__(self, state, save, token, http=request, clock=time.time):
        self.s, self.save, self.token, self.http, self.clock = state, save, token, http, clock

    def call(self, method):
        now = int(self.clock())
        if now < self.s["clock_floor"] or now < self.s["retry_at"]:
            return 0, {}
        self.s["clock_floor"] = now
        self.s["retry_at"] = now + 2
        self.save()  # authorization and rate high-water durable BEFORE any provider operation
        path = CLOUD_API + "/servers/" + self.s["target"]["grader_server_id"]
        code, body, retry = self.http(method, path, "Bearer " + self.token)
        if code == 429 or code == 0 or code >= 500:
            self.s["retry_at"] = max(self.s["retry_at"], now + max(retry, 3600 if code == 429 else 75))
        self.save()
        return code, body

    def kill(self):
        if self.s["absence_confirmed"]:
            return True
        if not self.token:
            return False
        code, body = self.call("GET")
        if code == 404:
            self.s["absence_confirmed"] = True
            self.save()
            return True
        server = body.get("server", {}) if type(body) is dict else {}
        if (code == 200 and type(server) is dict and
                type(server.get("id")) is int and str(server["id"]) == self.s["target"]["grader_server_id"] and
                not self.s["delete_attempted"]):
            # A separate later invocation must observe HTTP404. Timeout, accepted DELETE, empty
            # body, unreachable service, or deletion action completion are not absence evidence.
            self.s["delete_attempted"] = True
            self.s["retry_at"] = 0
            self.save()
            code, _ = self.call("DELETE")
            self.s["delete_accepted"] = code in {200, 202, 204}
            self.save()
        return False


def main():
    if sys.argv[1:] != ["kill"] or os.geteuid() != 0:
        raise ValueError("usage (controller root): ds-grader-kill.py kill")
    target, token = target_from_env()
    directory = Path(os.environ.get("DS_GRADER_ACTUATOR_STATE_DIR", "/var/lib/deadswitch/grader-actuator"))
    with journal(directory, target, token) as (state, save):
        confirmed = GraderActuator(state, save, credentials()[0]).kill()
        print("GRADER_DELETED_CONFIRMED; allocation remains retired" if confirmed else
              "INCOMPLETE: grader deletion unconfirmed; allocation quarantined")
        return 0 if confirmed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError):
        print("INCOMPLETE: unavailable/invalid grader actuator state; reconciliation required", file=sys.stderr)
        sys.exit(3)
