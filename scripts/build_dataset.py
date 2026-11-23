#!/usr/bin/env python3
"""Build data/benign_pe_features.csv from real, known-good Windows programs on this machine.

The model's "normal software" class comes from here: system binaries, .NET assemblies,
installed applications (machine-wide and per-user) and (deliberately) plenty of UNSIGNED
developer tools, so the model does not learn "unsigned = malware".

Every program also gets a `group`: an anonymous number shared by the files of one application
(or, for Windows' own folders, by files with the same name, so the 32- and 64-bit twins of a
system DLL stay together). Training holds out whole groups, which measures false positives on
software the model has never seen instead of on more files of apps it trained on. The number
is a salted hash and the salt is thrown away, so it cannot be turned back into a folder name.

Only feature values, a coarse category and that number are written; file paths and names
never leave the machine. No single application contributes more than --per-group programs.

Usage:  python scripts/build_dataset.py [--out data/benign_pe_features.csv] [--per-group 600]
Needs:  pip install pefile numpy   (Windows)
"""

import argparse
import csv
import hashlib
import os
import random
import secrets
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import thenex_features as tf  # noqa: E402

EXTENSIONS = {".exe", ".dll", ".sys", ".pyd", ".node", ".ocx", ".cpl"}
MIN_BYTES = 1024
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "data" / "benign_pe_features.csv"
# Never a source of "known good" programs: scratch space, downloads still to be judged, and
# anything The Nex itself set aside.
SKIP_DIRS = {"temp", "tmp", "downloads", "quarantine", "thenex", "$recycle.bin", "inetcache"}


def env_path(name, *parts):
    base = os.environ.get(name)
    return Path(base, *parts) if base else None


def roots():
    """(category, folder, grouping) for every known-good source that exists here.

    grouping "name": one group per file name (Windows' own folders).
    grouping "app":  one group per application folder (the first two levels under the root).
    """
    windir = env_path("SystemRoot") or Path("C:/Windows")
    pf = env_path("ProgramFiles")
    pf86 = env_path("ProgramFiles(x86)")
    home = Path.home()
    python_dir = Path(sys.executable).resolve().parent
    candidates = [
        ("system32", windir / "System32", "name"),
        ("syswow64", windir / "SysWOW64", "name"),
        ("dotnet", windir / "Microsoft.NET", "name"),
        ("systemapps", windir / "SystemApps", "app"),
        ("devtools", pf / "Git" if pf else None, "app"),
        ("devtools", python_dir, "app"),
        ("devtools", home / ".cargo", "app"),
        ("devtools", home / ".rustup", "app"),
        ("devtools", home / ".vscode", "app"),
        ("devtools", home / ".nuget", "app"),
        ("devtools", home / ".dotnet", "app"),
        ("devtools", home / ".cache", "app"),
        ("devtools", env_path("APPDATA", "npm"), "app"),
        ("programfiles", pf, "app"),
        ("programfiles", pf86, "app"),
        ("userapps", env_path("LOCALAPPDATA", "Programs"), "app"),
        ("userapps", env_path("LOCALAPPDATA"), "app"),
        ("userapps", env_path("APPDATA"), "app"),
        ("userapps", env_path("ProgramData"), "app"),
    ]
    return [(c, p, g) for c, p, g in candidates if p and p.is_dir()]


def candidate_files(category, folder, grouping, seen):
    """[(category, group key, path)] for every program under `folder` not listed before."""
    found = []
    root = str(folder)
    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for name in files:
            if Path(name).suffix.lower() not in EXTENSIONS:
                continue
            path = os.path.join(directory, name)
            key = os.path.normcase(os.path.abspath(path))
            if key in seen:
                continue
            seen.add(key)
            if grouping == "name":
                group = "name:" + name.lower()
            else:
                parts = os.path.relpath(directory, root).split(os.sep)
                parts = [p for p in parts if p != "."][:2]
                group = "app:" + os.path.normcase(root) + "|" + "|".join(parts).lower()
            found.append((category, group, path))
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
    parser.add_argument("--per-group", type=int, default=600, help="most programs taken from one application")
    parser.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    seen = set()
    by_group = {}
    for category, folder, grouping in roots():
        try:
            files = candidate_files(category, folder, grouping, seen)
        except OSError:
            continue
        for cat, group, path in files:
            by_group.setdefault(group, []).append((cat, path))
        print(f"{category:13s} {len(files):6d} candidates  ({folder})")

    # No application may dominate: a random --per-group of each one's programs.
    rng = random.Random(args.seed)
    jobs = []
    for group in sorted(by_group):
        members = by_group[group]
        if len(members) > args.per_group:
            members = rng.sample(members, args.per_group)
        jobs.extend((cat, group, path) for cat, path in members)
    print(f"{len(by_group)} groups, {len(jobs)} programs to read")

    salt = secrets.token_bytes(16)

    def anonymous(group):
        return int.from_bytes(hashlib.blake2b(group.encode("utf-8"), key=salt, digest_size=4).digest(), "big")

    rows = []
    unique = set()
    stats = {}
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for (category, group, _), feats in zip(jobs, pool.map(extract, [j[2] for j in jobs], chunksize=16)):
            if feats is None:
                continue
            key = tuple(feats)
            if key in unique:
                continue
            unique.add(key)
            rows.append([category, anonymous(group)] + feats)
            s = stats.setdefault(category, {"n": 0, "signed": 0, "dotnet": 0, "groups": set()})
            s["n"] += 1
            s["signed"] += int(feats[8] > 0.5)
            s["dotnet"] += int(feats[12] > 0.5)
            s["groups"].add(group)

    if len(rows) < 500:
        raise SystemExit(f"only {len(rows)} usable binaries found; is this a Windows machine with pefile installed?")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["category", "group"] + tf.FEATURE_NAMES)
        writer.writerows(rows)

    total = len(rows)
    signed = sum(s["signed"] for s in stats.values())
    for category, s in sorted(stats.items()):
        print(f"  {category:13s} {s['n']:6d} unique in {len(s['groups']):5d} groups  "
              f"signed {s['signed'] / s['n']:.0%}  .NET {s['dotnet'] / s['n']:.0%}")
    print(f"wrote {args.out} ({total} unique benign programs, {signed / total:.0%} signed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
