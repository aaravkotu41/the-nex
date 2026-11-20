#!/usr/bin/env python3
"""Live end-to-end verifier for The Nex (Windows and macOS).

Runs the real release binary against harmless decoys confined to ./thenex_live_sandbox:
  1 startup & canaries        4 nested zip bomb           7 canary trip & recovery
  2 benign zip pass-through   5 overlapping-header bomb   8 --restore CLI
  3 ratio zip bomb            6 LotL process kill         9 --dry-run mode
Exit status is 0 only when all nine checks pass.

Note: like the real product, the console engine watches every process on the machine while
it runs; checks 6 and 7 rely on that and only target the decoy processes this script starts.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SANDBOX = ROOT / "thenex_live_sandbox"
WATCH = SANDBOX / "watch"
QUARANTINE = SANDBOX / "quarantine"
STAGING = SANDBOX / "staging"
EVENTS = SANDBOX / "events.jsonl"
DAEMON_LOG = SANDBOX / "daemon-output.log"
WINDOWS = os.name == "nt"
EXE = ROOT / "target" / "release" / ("the-nex.exe" if WINDOWS else "the-nex")
MODEL = ROOT / "thenex_model.onnx"
ICON = ROOT / "crates" / "the-nex-gui" / "icons" / "icon.ico"
CANARIES = (".thenex_canary_01.docx", ".thenex_canary_02.xlsx")
CANARY_MAGIC = b"THENEX\x00CANARY"
ACTION_TIMEOUT = 3.0
KILL_TIMEOUT = 2.5
COOLDOWN = 2.5


def wait_until(predicate, timeout, interval=0.1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def read_events():
    if not EVENTS.exists():
        return []
    events = []
    for line in EVENTS.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def find_event(threat_type, target_suffix=None, action_prefix=None):
    for event in read_events():
        if event.get("threat_type") != threat_type:
            continue
        if target_suffix and not str(event.get("target", "")).endswith(target_suffix):
            continue
        if action_prefix and not str(event.get("action_taken", "")).startswith(action_prefix):
            continue
        return event
    return None


def zip_bytes(entries, level=6):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=level) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


def ratio_bomb(megabytes):
    buffer = io.BytesIO()
    zeros = bytes(1024 * 1024)
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        with archive.open("zeros.bin", "w") as entry:
            for _ in range(megabytes):
                entry.write(zeros)
    return buffer.getvalue()


def nested_bomb(levels):
    current = zip_bytes([("payload.txt", b"nested payload\n")])
    for level in range(levels, 1, -1):
        current = zip_bytes([(f"level{level}.zip", current)])
    return current


def overlap_bomb():
    """Valid ZIP whose central directory lists three entries sharing one local file's data."""
    data = b"Z" * 65536
    crc = zlib.crc32(data) & 0xFFFFFFFF
    name = b"kernel.bin"
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21, crc, len(data), len(data), len(name), 0)
    out = bytearray(local + name + data)
    cd_offset = len(out)
    aliases = [b"kernel.bin", b"alias-1.bin", b"alias-2.bin"]
    for alias in aliases:
        out += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50, 20, 20, 0, 0, 0, 0x21, crc, len(data), len(data), len(alias), 0, 0, 0, 0, 0, 0,
        ) + alias
    cd_size = len(out) - cd_offset
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(aliases), len(aliases), cd_size, cd_offset, 0)
    return bytes(out)


def drop(name, data):
    """Writes outside the watch folder, then renames in, so the engine only sees a complete file."""
    STAGING.mkdir(parents=True, exist_ok=True)
    staged = STAGING / name
    staged.write_bytes(data)
    target = WATCH / name
    os.replace(staged, target)
    return target


def quarantined(name):
    return QUARANTINE.exists() and any(p.name.endswith(f"_{name}.quarantined") for p in QUARANTINE.iterdir())


class Daemon:
    def __init__(self):
        self.process = None
        self.started = 0.0

    def start(self, dry_run=False):
        command = [
            str(EXE), "--console",
            "--watch-dir", str(WATCH),
            "--quarantine-dir", str(QUARANTINE),
            "--log-file", str(EVENTS),
        ]
        if dry_run:
            command.append("--dry-run")
        kwargs = {}
        if WINDOWS:
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        log = open(DAEMON_LOG, "ab")
        self.process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **kwargs)
        log.close()
        self.started = time.monotonic()

    def running(self):
        return self.process is not None and self.process.poll() is None

    def stop(self):
        if not self.running():
            self.process = None
            return
        try:
            self.process.send_signal(signal.CTRL_BREAK_EVENT if WINDOWS else signal.SIGINT)
            self.process.wait(timeout=10)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            self.process.kill()
            self.process.wait(timeout=10)
        self.process = None

    def wait_for_cooldown(self):
        remaining = COOLDOWN - (time.monotonic() - self.started)
        if remaining > 0:
            time.sleep(remaining)


def check_startup(daemon):
    daemon.start()
    ok = wait_until(lambda: all((WATCH / name).exists() for name in CANARIES), ACTION_TIMEOUT)
    if not daemon.running():
        return False, "the-nex exited early; see thenex_live_sandbox/daemon-output.log"
    return ok, "both canaries created" if ok else "canaries missing after 3s"


def check_benign(daemon):
    path = drop("benign.zip", zip_bytes([("readme.txt", b"The Nex benign sample\n" * 20), ("data.csv", b"1,2,3\n")]))
    time.sleep(2.0)
    flagged = any(str(e.get("target", "")).endswith("benign.zip") for e in read_events())
    ok = path.exists() and not flagged
    return ok, "left untouched, no alert" if ok else f"exists={path.exists()} alerted={flagged}"


def check_bomb(name, data):
    path = drop(name, data)
    ok = wait_until(
        lambda: not path.exists() and quarantined(name) and find_event("ZIP_BOMB", name, "QUARANTINED"),
        ACTION_TIMEOUT,
    )
    event = find_event("ZIP_BOMB", name)
    detail = event["details"].split(":")[0] if event else "no ZIP_BOMB event"
    return ok, f"quarantined ({detail})" if ok else f"exists={path.exists()} quarantined={quarantined(name)} event={bool(event)}"


def lotl_decoy_command():
    if WINDOWS:
        script = base64.b64encode("Start-Sleep -Seconds 15".encode("utf-16-le")).decode("ascii")
        return ["powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", script]
    # "; exit 0" keeps sh alive (no exec of sleep), so the guard sees the shell's command line.
    return ["/bin/sh", "-c", "sleep 15; exit 0 # base64 -D"]


def check_lotl(daemon):
    decoy = subprocess.Popen(lotl_decoy_command(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        killed = wait_until(lambda: decoy.poll() is not None, KILL_TIMEOUT)
        logged = wait_until(lambda: find_event("LOTL_SCRIPT", f"(pid {decoy.pid})", "TERMINATED"), 1.0)
        ok = killed and bool(logged)
        return ok, f"pid {decoy.pid} terminated and logged" if ok else f"killed={killed} logged={bool(logged)}"
    finally:
        if decoy.poll() is None:
            decoy.kill()
            decoy.wait(timeout=10)


CANARY_WORKER = r"""
import sys, time
canary, scratch = sys.argv[1], sys.argv[2]
with open(canary, "r+b") as handle:
    handle.seek(0)
    handle.write(b"ENCRYPTED-BY-HARMLESS-DECOY")
    handle.truncate()
block = b"\0" * (8 * 1024 * 1024)
deadline = time.monotonic() + 6
with open(scratch, "wb") as out:
    while time.monotonic() < deadline:
        out.seek(0)
        out.write(block)
        out.flush()
"""


def check_canary(daemon):
    daemon.wait_for_cooldown()
    canary = WATCH / CANARIES[0]
    scratch = SANDBOX / "decoy-writer.bin"
    worker = subprocess.Popen([sys.executable, "-c", CANARY_WORKER, str(canary), str(scratch)], stdin=subprocess.DEVNULL)
    try:
        alerted = wait_until(lambda: find_event("RANSOMWARE_CANARY", CANARIES[0]), ACTION_TIMEOUT)

        def restored():
            try:
                return canary.read_bytes().startswith(CANARY_MAGIC)
            except OSError:
                return False

        recovered = wait_until(restored, ACTION_TIMEOUT)
        ok = bool(alerted) and recovered
        return ok, "alert logged, canary recreated" if ok else f"alerted={bool(alerted)} recovered={recovered}"
    finally:
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=10)
        try:
            scratch.unlink()
        except OSError:
            pass


def check_restore(daemon, ratio_data):
    daemon.stop()
    event = find_event("ZIP_BOMB", "ratio_bomb.zip", "QUARANTINED")
    if not event:
        return False, "no quarantine record for ratio_bomb.zip"
    quarantine_id = event["action_taken"].split("id=", 1)[1].split()[0]
    result = subprocess.run(
        [str(EXE), "--restore", quarantine_id, "--quarantine-dir", str(QUARANTINE), "--log-file", str(EVENTS)],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    restored = WATCH / "ratio_bomb.zip"
    same = restored.exists() and hashlib.sha256(restored.read_bytes()).digest() == hashlib.sha256(ratio_data).digest()
    ok = result.returncode == 0 and same
    detail = f"id {quarantine_id} restored byte-for-byte" if ok else f"exit={result.returncode} restored={same} {result.stderr.strip()[:160]}"
    return ok, detail


def check_dry_run(daemon):
    daemon.start(dry_run=True)
    time.sleep(1.5)
    path = drop("ratio_bomb_dry.zip", ratio_bomb(50))
    logged = wait_until(lambda: find_event("ZIP_BOMB", "ratio_bomb_dry.zip", "DRY_RUN"), ACTION_TIMEOUT)
    time.sleep(0.5)
    ok = bool(logged) and path.exists() and not quarantined("ratio_bomb_dry.zip")
    daemon.stop()
    return ok, "logged, file untouched" if ok else f"logged={bool(logged)} exists={path.exists()}"


def ensure_assets(skip_build):
    if not MODEL.exists():
        subprocess.run([sys.executable, str(ROOT / "scripts" / "train_onnx.py"), "--out", str(MODEL)], check=True)
    if not ICON.exists():
        subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_icons.py")], check=True)
    if not EXE.exists():
        if skip_build:
            raise SystemExit(f"{EXE} is missing and --skip-build was given")
        subprocess.run(["cargo", "build", "--release", "--workspace"], cwd=ROOT, check=True)


def remove_sandbox():
    if not SANDBOX.exists():
        return
    if WINDOWS:
        # Quarantined files carry a restricted ACL and the read-only bit; reset before deleting.
        subprocess.run(["icacls", str(SANDBOX), "/reset", "/T", "/C", "/Q"], capture_output=True)

    def make_writable(function, path, _error):
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        function(path)

    if sys.version_info >= (3, 12):
        shutil.rmtree(SANDBOX, onexc=make_writable)
    else:
        shutil.rmtree(SANDBOX, onerror=make_writable)


def main():
    parser = argparse.ArgumentParser(description="Live end-to-end verification of The Nex.")
    parser.add_argument("--skip-build", action="store_true", help="fail instead of building missing binaries")
    parser.add_argument("--keep-sandbox", action="store_true", help="leave thenex_live_sandbox for inspection")
    args = parser.parse_args()

    ensure_assets(args.skip_build)
    remove_sandbox()
    for folder in (WATCH, QUARANTINE, STAGING):
        folder.mkdir(parents=True, exist_ok=True)

    ratio_data = ratio_bomb(50)
    daemon = Daemon()
    checks = [
        ("Startup & canaries", lambda: check_startup(daemon)),
        ("Benign zip pass-through", lambda: check_benign(daemon)),
        ("Live ratio zip bomb", lambda: check_bomb("ratio_bomb.zip", ratio_data)),
        ("Live nested zip bomb", lambda: check_bomb("nested_bomb.zip", nested_bomb(4))),
        ("Live overlapping-header bomb", lambda: check_bomb("overlap_bomb.zip", overlap_bomb())),
        ("Live LotL process kill", lambda: check_lotl(daemon)),
        ("Live canary trip & recovery", lambda: check_canary(daemon)),
        ("Live restore CLI", lambda: check_restore(daemon, ratio_data)),
        ("Live dry-run mode", lambda: check_dry_run(daemon)),
    ]
    results = []
    try:
        for name, check in checks:
            started = time.monotonic()
            try:
                ok, detail = check()
            except Exception as error:  # a crashed check is a failed check, not an aborted run
                ok, detail = False, f"{type(error).__name__}: {error}"
            results.append((name, ok, time.monotonic() - started, detail))
    finally:
        daemon.stop()

    width = max(len(name) for name, *_ in results)
    print()
    for name, ok, seconds, detail in results:
        print(f"{'[PASS]' if ok else '[FAIL]'}  {name.ljust(width)}  {seconds:5.2f}s  {detail}")
    passed = sum(1 for _, ok, _, _ in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        print(f"daemon output: {DAEMON_LOG}")
        try:
            tail = DAEMON_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-60:]
            print("---- last daemon output ----")
            print("\n".join(tail))
        except OSError as e:
            print(f"(cannot read daemon output: {e})")
        args.keep_sandbox = True
    if not args.keep_sandbox:
        remove_sandbox()
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
