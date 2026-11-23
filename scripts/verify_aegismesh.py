#!/usr/bin/env python3
"""AegisMesh verifier: build, test, run every simulation scenario, prove nothing is persisted.

    python scripts/verify_aegismesh.py [--skip-build] [--skip-tests]

The simulator runs once per form factor inside a throwaway sandbox whose working directory,
HOME, TEMP and app-data folders all point into it; afterwards the sandbox must contain no
files at all (no location log, no cache, nothing). Exits 0 only when every check passes.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "target" / "release" / ("aegismesh-sim.exe" if os.name == "nt" else "aegismesh-sim")
SCENARIOS = ["simulate-tap", "simulate-mesh", "verify-zeroization", "privacy-audit", "benchmark"]
FORMS = ["ring", "bracelet", "clothing-tag"]

results = []


def record(name, ok, detail=""):
    results.append((name, bool(ok), str(detail).strip().replace("\n", " ")[:150]))


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", **kwargs)


def tail(proc, lines=3):
    text = (proc.stderr or proc.stdout or "").strip().splitlines()
    return " | ".join(text[-lines:])


def sandbox_env(sandbox):
    home = sandbox / "home"
    tmp = sandbox / "tmp"
    for folder in (home, tmp, sandbox / "work"):
        folder.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update({
        "HOME": str(home), "USERPROFILE": str(home),
        "TMP": str(tmp), "TEMP": str(tmp), "TMPDIR": str(tmp),
        "APPDATA": str(home / "AppData" / "Roaming"), "LOCALAPPDATA": str(home / "AppData" / "Local"),
        "XDG_DATA_HOME": str(home / ".local" / "share"), "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
    })
    return env


def check_scenarios(sandbox):
    env = sandbox_env(sandbox)
    work = sandbox / "work"
    for form in FORMS:
        proc = run([str(EXE), "--json-logs", "--form", form], cwd=work, env=env)
        lines = []
        for line in proc.stdout.splitlines():
            try:
                lines.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        by_name = {entry.get("scenario"): entry for entry in lines}
        for name in SCENARIOS:
            entry = by_name.get(name)
            if entry is None:
                record(f"{name} [{form}]", False, f"no result (exit {proc.returncode}): {tail(proc)}")
            else:
                record(f"{name} [{form}]", entry.get("pass") is True, entry.get("summary", ""))
        record(f"exit code [{form}]", proc.returncode == 0, f"exit {proc.returncode}")

    bogus = run([str(EXE), "--bogus"], cwd=work, env=env)
    record("rejects unknown arguments", bogus.returncode == 2, f"exit {bogus.returncode}")
    help_text = run([str(EXE), "--help"], cwd=work, env=env)
    record("documents every scenario", help_text.returncode == 0 and all(
        f"--{flag}" in help_text.stdout for flag in ["simulate-tap", "simulate-mesh", "verify-zeroization", "json-logs"]
    ), "--help")

    leftovers = [p for p in sandbox.rglob("*") if p.is_file()]
    record("zero persisted files (no location history)", not leftovers,
           "sandbox empty" if not leftovers else ", ".join(str(p.relative_to(sandbox)) for p in leftovers[:5]))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--skip-build", action="store_true", help="use the existing release binary")
    parser.add_argument("--skip-tests", action="store_true", help="CI already ran cargo test")
    args = parser.parse_args()

    if EXE.is_file():
        record("release binary", True, EXE.relative_to(ROOT))
    elif args.skip_build:
        record("release binary", False, f"{EXE} is missing (run without --skip-build)")
    else:
        proc = run(["cargo", "build", "--release", "--workspace"], cwd=ROOT)
        record("cargo build --release --workspace", proc.returncode == 0 and EXE.is_file(), tail(proc))

    if not args.skip_tests:
        proc = run(["cargo", "test", "--workspace"], cwd=ROOT)
        passed = sum(int(line.split()[3]) for line in proc.stdout.splitlines()
                     if line.startswith("test result:") and len(line.split()) > 3 and line.split()[3].isdigit())
        record("cargo test --workspace", proc.returncode == 0, f"{passed} tests passed" if proc.returncode == 0 else tail(proc))

    if EXE.is_file():
        with tempfile.TemporaryDirectory(prefix="aegismesh-verify-") as sandbox:
            check_scenarios(Path(sandbox))

    width = max(len(name) for name, _, _ in results)
    print("AegisMesh verification")
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<{width}}  {detail}")
    failed = [name for name, ok, _ in results if not ok]
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
