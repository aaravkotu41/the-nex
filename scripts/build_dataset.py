#!/usr/bin/env python3
"""Build data/benign_pe_features.csv from real, known-good Windows programs on this machine.

The model's "normal software" class comes from here: system binaries, .NET assemblies,
installed applications and (deliberately) plenty of UNSIGNED developer tools, so the model
does not learn "unsigned = malware". Only feature values and a coarse category are written;
file paths never leave the machine.

Usage:  python scripts/build_dataset.py [--out data/benign_pe_features.csv] [--per-root 4000]
Needs:  pip install pefile numpy   (Windows)
"""

import argparse
import csv
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import thenex_features as tf  # noqa: E402

EXTENSIONS = {".exe", ".dll", ".sys", ".pyd", ".node", ".ocx", ".cpl"}
MIN_BYTES = 1024
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "data" / "benign_pe_features.csv"


def env_path(name, *parts):
    base = os.environ.get(name)
    return Path(base, *parts) if base else None


def roots():
    """(category, folder, recursive) for every known-good source that exists here."""
    windir = env_path("SystemRoot") or Path("C:/Windows")
    pf = env_path("ProgramFiles")
    pf86 = env_path("ProgramFiles(x86)")
    home = Path.home()
    python_dir = Path(sys.executable).resolve().parent
    candidates = [
        ("system32", windir / "System32", False),
        ("system32", windir / "System32" / "drivers", False),
        ("syswow64", windir / "SysWOW64", False),
        ("dotnet", windir / "Microsoft.NET", True),
        ("devtools", pf / "Git" / "usr" / "bin" if pf else None, False),
        ("devtools", pf / "Git" / "mingw64" / "bin" if pf else None, False),
        ("devtools", python_dir, True),
        ("devtools", home / ".cargo" / "bin", False),
        ("devtools", home / ".rustup" / "toolchains", True),
        ("devtools", env_path("APPDATA", "npm"), True),
        ("programfiles", pf, True),
        ("programfiles", pf86, True),
    ]
    return [(c, p, r) for c, p, r in candidates if p and p.is_dir()]


def candidate_files(folder, recursive, limit, seen):
    found = []
    walker = os.walk(folder) if recursive else [(str(folder), [], os.listdir(folder))]
    for directory, _, files in walker:
        for name in files:
            if Path(name).suffix.lower() not in EXTENSIONS:
                continue
            path = os.path.join(directory, name)
            key = os.path.normcase(os.path.abspath(path))
            if key in seen:
                continue
            seen.add(key)
            found.append(path)
            if len(found) >= limit:
                return found
    return found


def extract(path):
    try:
        size = os.path.getsize(path)
        if size < MIN_BYTES or size > tf.MAX_AI_SCAN_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    prof = tf.profile_pe(data)
    if prof is None:
        return None
    return [round(v, 6) for v in tf.features(prof)]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--per-root", type=int, default=4000)
    parser.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    args = parser.parse_args()

    seen = set()
    jobs = []
    for category, folder, recursive in roots():
        try:
            files = candidate_files(folder, recursive, args.per_root, seen)
        except OSError:
            continue
        jobs.extend((category, f) for f in files)
        print(f"{category:13s} {len(files):6d} candidates  ({'recursive' if recursive else 'top level'})")

    rows = []
    unique = set()
    stats = {}
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for (category, _), feats in zip(jobs, pool.map(extract, [f for _, f in jobs], chunksize=16)):
            if feats is None:
                continue
            key = tuple(feats)
            if key in unique:
                continue
            unique.add(key)
            rows.append([category] + feats)
            s = stats.setdefault(category, {"n": 0, "signed": 0, "dotnet": 0})
            s["n"] += 1
            s["signed"] += int(feats[8] > 0.5)
            s["dotnet"] += int(feats[12] > 0.5)

    if len(rows) < 500:
        raise SystemExit(f"only {len(rows)} usable binaries found; is this a Windows machine with pefile installed?")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["category"] + tf.FEATURE_NAMES)
        writer.writerows(rows)

    total = len(rows)
    signed = sum(s["signed"] for s in stats.values())
    for category, s in sorted(stats.items()):
        print(f"  {category:13s} {s['n']:6d} unique  signed {s['signed'] / s['n']:.0%}  .NET {s['dotnet'] / s['n']:.0%}")
    print(f"wrote {args.out} ({total} unique benign programs, {signed / total:.0%} signed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
