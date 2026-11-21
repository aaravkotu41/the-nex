#!/usr/bin/env python3
"""CI gate for the binary AI, run on real programs of the runner's operating system.

    python scripts/check_feature_parity.py --binary target/release/the-nex.exe \
        [--extra target/TheNexSetup.exe ...] [--limit 400] [--max-fpr 0.02]

1. Samples real executables shipped with the OS (Windows: System32; macOS: /bin, /sbin,
   /usr/bin, /usr/sbin and the apps in /System/Applications), deterministically.
2. Runs `the-nex --scan-file @list` once and reads its JSON lines; the ONNX model must be loaded.
3. Train/serve parity (Windows): recomputes all features with pefile through
   scripts/thenex_features.py (the code that built the training data) and fails when Rust and
   Python disagree. A model fed different numbers in production than in training silently
   stops working; this is what catches it.
4. Fallback parity: the heuristic score Rust reports must equal thenex_features.heuristic_score.
5. False positives: at most --max-fpr of these real OS programs may reach the threshold. Each
   flagged file is printed with the engine's reasons.
6. Every --extra file (our own binaries and installers) must be scored, and scored clean.
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import thenex_features as tf  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TOLERANCE = 1e-4
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}


def readable_size(path):
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return None, b""
    return size, head


def windows_candidates():
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    out = []
    for path in sorted(system32.iterdir()):
        if path.suffix.lower() in {".exe", ".dll"}:
            size, head = readable_size(path)
            if size and 1024 <= size <= tf.MAX_AI_SCAN_BYTES and head[:2] == b"MZ":
                out.append(path)
    return out


def macos_candidates():
    files = []
    for folder in ("/bin", "/sbin", "/usr/bin", "/usr/sbin"):
        folder = Path(folder)
        if folder.is_dir():
            files.extend(p for p in folder.iterdir() if not p.is_symlink())
    for app in sorted(Path("/System/Applications").glob("*.app")):
        macos = app / "Contents" / "MacOS"
        if macos.is_dir():
            files.extend(macos.iterdir())
    out = []
    for path in sorted(set(files)):
        size, head = readable_size(path)
        if size and 1024 <= size <= tf.MAX_AI_SCAN_BYTES and head in MACHO_MAGICS:
            out.append(path)
    return out


def sample(paths, limit):
    step = max(1, len(paths) // limit)
    return paths[::step][:limit]


def run_scan(binary, paths):
    with tempfile.TemporaryDirectory() as tmp:
        listing = Path(tmp) / "files.txt"
        listing.write_text("".join(f"{p}\n" for p in paths), encoding="utf-8")
        proc = subprocess.run(
            [str(binary), "--scan-file", f"@{listing}"],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    if proc.returncode != 0:
        raise SystemExit(f"--scan-file exited with {proc.returncode}\n{proc.stderr}")
    print(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "(no summary)")
    records = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    if len(records) != len(paths):
        raise SystemExit(f"expected {len(paths)} results, got {len(records)}")
    return records


def describe(record):
    reasons = "; ".join(record.get("reasons", [])) or "no specific reasons"
    return f"{record['score']:.3f}  {record['path']}\n           {reasons}"


def check_pe_parity(records):
    """Returns (compared, mismatched, rust_only_rejects)."""
    compared, mismatched, rust_rejected, python_rejected = 0, [], 0, 0
    for record in records:
        try:
            data = Path(record["path"]).read_bytes()
        except OSError:
            continue
        prof = tf.profile_pe(data)
        if record["verdict"] == "not_scored":
            rust_rejected += prof is not None
            continue
        if prof is None:
            python_rejected += 1
            continue
        compared += 1
        python = tf.features(prof)
        diffs = [
            f"{name}: rust {r:.6f} python {p:.6f}"
            for name, r, p in zip(tf.FEATURE_NAMES, record["features"], python)
            if abs(r - p) > TOLERANCE
        ]
        if diffs:
            mismatched.append((record["path"], diffs, record["profile"], prof))
    print(f"parity: {compared} files compared, {len(mismatched)} differ; "
          f"rejected only by Rust: {rust_rejected}, only by pefile: {python_rejected}")
    for path, diffs, rust_profile, python_profile in mismatched[:15]:
        print(f"  {path}\n    " + "\n    ".join(diffs))
        print(f"    rust   {json.dumps(rust_profile, sort_keys=True)}")
        print(f"    python {json.dumps(python_profile, sort_keys=True, default=str)}")
    return compared, len(mismatched), rust_rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--binary", type=Path, required=True, help="the-nex executable to test")
    parser.add_argument("--extra", type=Path, action="append", default=[],
                        help="own binary or installer that must be scored clean (repeatable)")
    parser.add_argument("--limit", type=int, default=400)
    parser.add_argument("--max-fpr", type=float, default=0.02)
    args = parser.parse_args()

    windows = platform.system() == "Windows"
    candidates = windows_candidates() if windows else macos_candidates()
    chosen = sample(candidates, args.limit)
    extras = [p.resolve() for p in args.extra if p.is_file()]
    for missing in (p for p in args.extra if not p.is_file()):
        print(f"note: --extra {missing} does not exist; skipped")
    print(f"{len(chosen)} of {len(candidates)} OS programs sampled, {len(extras)} own files")
    records = run_scan(args.binary.resolve(), [str(p) for p in chosen + extras])
    os_records, own_records = records[:len(chosen)], records[len(chosen):]
    failures = []

    scored = [r for r in records if r["verdict"] != "not_scored"]
    engines = {r["engine"] for r in scored}
    if engines != {"onnx"}:
        failures.append(f"expected every file scored by the ONNX model, got engines {sorted(engines)}")

    bad_heuristic = [r for r in scored if abs(r["heuristic"] - tf.heuristic_score(r["features"])) > TOLERANCE]
    print(f"heuristic parity: {len(scored) - len(bad_heuristic)}/{len(scored)} match")
    if bad_heuristic:
        failures.append(f"Rust heuristic differs from thenex_features.heuristic_score on {len(bad_heuristic)} files")

    if windows:
        compared, mismatched, rust_rejected = check_pe_parity(os_records)
        if compared < 0.8 * len(os_records):
            failures.append(f"only {compared} of {len(os_records)} files could be compared")
        if mismatched > max(1, 0.005 * compared):
            failures.append(f"{mismatched} files have different features in Rust and Python")
        if rust_rejected > 0.02 * len(os_records):
            failures.append(f"Rust could not parse {rust_rejected} files that pefile reads")

    os_scored = [r for r in os_records if r["verdict"] != "not_scored"]
    flagged = [r for r in os_scored if r["verdict"] == "malicious"]
    fpr = len(flagged) / max(1, len(os_scored))
    print(f"false positives: {len(flagged)}/{len(os_scored)} real OS programs flagged ({fpr:.2%}, limit {args.max_fpr:.0%})")
    for record in flagged:
        print("  " + describe(record))
    if not os_scored:
        failures.append("no OS program could be scored")
    if fpr > args.max_fpr:
        failures.append(f"{fpr:.2%} of real OS programs flagged (limit {args.max_fpr:.0%})")

    for record in own_records:
        print(f"own file: {record['verdict']:10s} {record.get('score', float('nan')):.3f}  {record['path']}")
        if record["verdict"] != "clean":
            failures.append(f"our own {record['path']} is {record['verdict']}: {record.get('reasons')}")

    if failures:
        print("\nFAILED:\n  " + "\n  ".join(failures))
        return 1
    print("\nbinary AI checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
