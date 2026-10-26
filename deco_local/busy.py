"""Post-write lockout for the Deco's control port, shared by every process on this machine.

Measured on an X55 (firmware 1.11.1) with led_set, probing every 5 s: the write ACKs and reads back
fine within ~3 s, then port 20001 refuses connections from ~5-14 s to ~64-95 s after the write while
the router applies the config. Probing it every 0.5 s kept it closed longer (connection rate
limiting), so the watcher here probes gently. Connecting during that window only prolongs it.

  begin(write_name, host)   called after a write ACKs; watches the port in a background thread
  status()                  {"busy", "phase", "write", "since", "elapsed", "expected", "retry_after", "last"}
  check()                   raises Busy while locked

State lives in a file (config.state_path("lockout.json")) so separate processes -- an MCP server,
a script, a cron job -- all see the same lock. A dead watcher can't wedge it: every state carries a
hard deadline after which it is ignored.

on_event, if set, is called as on_event(event, **fields) for "lock" and "release" (for logging).
"""
import json
import os
import socket
import threading
import time

from . import config

PORT = 20001
PROBE_EVERY = 5          # s; faster probing extends the outage
EXPECTED = 90            # s; typical full outage
NEVER_CLOSED_AFTER = 25  # s; port never went down -> assume the write didn't need a restart
HARD_CAP = 150           # s; give up waiting regardless
on_event = None
_lock = threading.Lock()


class Busy(RuntimeError):
    def __init__(self, st):
        super().__init__(f"router is applying a change ({st['phase']}); try again in {st['retry_after']} s")
        self.status = st


def _path():
    return config.state_path("lockout.json")


def _write(st):
    tmp = _path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, _path())


def _emit(event, **fields):
    if on_event:
        try:
            on_event(event, **fields)
        except Exception:  # noqa: BLE001 - a logging hook must not break the lockout
            pass


def status():
    now = time.time()
    try:
        with open(_path()) as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {}
    busy = bool(st.get("busy")) and now < st.get("deadline", 0)
    out = {"busy": busy, "phase": st.get("phase", "idle") if busy else "idle", "write": st.get("write"),
           "since": st.get("since"), "expected": EXPECTED, "last": st.get("last")}
    if busy:
        out["elapsed"] = round(now - st["since"], 1)
        out["retry_after"] = max(PROBE_EVERY, int(EXPECTED - out["elapsed"]))
    return out


def check():
    st = status()
    if st["busy"]:
        raise Busy(st)


def port_open(host):
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((host, PORT))
        return True
    except OSError:
        return False
    finally:
        s.close()


def begin(write_name, host):
    """Lock now and watch the port in a background thread until the router is back."""
    since = time.time()
    with _lock:
        _write({"busy": True, "phase": "applying", "write": write_name, "since": since, "deadline": since + HARD_CAP})
    _emit("lock", write=write_name)
    threading.Thread(target=_watch, args=(write_name, host, since), daemon=True).start()


def wait(poll=2.0):
    """Block until the lockout is over (for scripts that write and then want to read again)."""
    while status()["busy"]:
        time.sleep(poll)


def _watch(write_name, host, since):
    went_down = False
    down_at = None
    outcome = "timeout"
    while time.time() - since < HARD_CAP:
        time.sleep(PROBE_EVERY)
        up = port_open(host)
        elapsed = time.time() - since
        if not up and not went_down:
            went_down = True
            down_at = round(elapsed, 1)
            with _lock:
                _write({"busy": True, "phase": "restarting", "write": write_name, "since": since,
                        "deadline": since + HARD_CAP, "down_at": down_at})
        elif up and went_down:
            time.sleep(PROBE_EVERY)  # one more probe so a brief flap doesn't release the lock
            if port_open(host):
                outcome = "back"
                break
        elif up and elapsed > NEVER_CLOSED_AFTER:
            outcome = "never_closed"
            break
    took = round(time.time() - since, 1)
    with _lock:
        _write({"busy": False, "phase": "idle", "write": write_name, "since": since, "deadline": 0,
                "last": {"write": write_name, "outcome": outcome, "seconds": took, "at": time.time()}})
    # down_at: s after the ACK that port 20001 closed; seconds: until it was back (or the cap)
    _emit("release", write=write_name, outcome=outcome, seconds=took, down_at=down_at,
          closed_s=round(took - down_at, 1) if down_at is not None and outcome == "back" else None)
