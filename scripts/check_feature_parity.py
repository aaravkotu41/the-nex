#!/usr/bin/env python3
"""CI gate for the binary AI, run on real programs of the runner's operating system.

    python scripts/check_feature_parity.py --binary target/release/the-nex.exe \
        [--extra target/TheNexSetup.exe ...] [--limit 400] [--max-fpr 0.02]

1. Samples real executables shipped with the OS (Windows: System32; macOS: /bin, /sbin,
   /usr/bin, /usr/sbin and the apps in /System/Applications), and real third-party software
   (Program Files, the CI toolcache, Homebrew, /Applications and running processes).
2. Runs `the-nex --scan-file @list` once and reads its JSON lines; the ONNX model must be loaded.
3. Train/serve parity (Windows): recomputes all features with pefile through
   scripts/thenex_features.py (the code that built the training data) and fails when Rust and
   Python disagree. A model fed different numbers in production than in training silently
   stops working; this is what catches it.
4. Fallback parity: the heuristic score Rust reports must equal thenex_features.heuristic_score.
5. False positives: at most --max-fpr of the OS programs, and at most --max-fpr-third-party of
   the third-party programs that are not trusted by signature, may reach the threshold. Each
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


def is_binary(path, windows):
    size, head = readable_size(path)
    if not size or not 1024 <= size <= tf.MAX_AI_SCAN_BYTES:
        return False
    return head[:2] == b"MZ" if windows else head in MACHO_MAGICS


def running_executables(windows):
    """Executables of the processes running right now (what the process guard looks at)."""
    if windows:
        command = ["powershell", "-NoProfile", "-Command", "Get-Process | ForEach-Object { $_.Path }"]
    else:
        command = ["ps", "-axo", "comm="]
    try:
        out = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return [Path(line.strip()) for line in out.splitlines() if line.strip().startswith(("/", "C:", "D:"))]


def third_party_candidates(windows, per_root=4000):
    """Software that is not part of the OS: installed apps, developer tools, the CI toolcache,
    Homebrew, and whatever is running. These are what The Nex actually scores in practice."""
    if windows:
        roots = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
                 os.environ.get("RUNNER_TOOL_CACHE") or r"C:\hostedtoolcache"]
        skip = ("windowsapps", "windows defender", "windows nt", "microsoft office")
    else:
        roots = ["/opt/homebrew/bin", "/opt/homebrew/opt", "/usr/local/bin", "/usr/local/opt",
                 os.environ.get("RUNNER_TOOL_CACHE") or "/Users/runner/hostedtoolcache", "/Applications"]
        skip = ("/system/",)
    seen, out = set(), []

    def add(path):
        try:
            real = path.resolve()
        except OSError:
            return
        key = str(real).lower()
        if key in seen or any(part in key for part in skip) or real.is_dir():
            return
        seen.add(key)
        if is_binary(real, windows):
            out.append(real)

    for root in filter(None, roots):
        count = 0
        for directory, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not any(part in d.lower() for part in skip)]
            for name in names:
                if windows and Path(name).suffix.lower() not in {".exe", ".dll"}:
                    continue
                add(Path(directory) / name)
                count += 1
            if count >= per_root:
                break
    walked = sorted(out, key=lambda q: str(q).lower())
    out = []
    for exe in running_executables(windows):
        add(exe)
    return walked, out


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
    parser.add_argument("--third-party", type=int, default=300, help="third-party programs to sample")
    parser.add_argument("--max-fpr-third-party", type=float, default=0.03,
                        help="limit for third-party programs that are not trusted by signature")
    args = parser.parse_args()

    windows = platform.system() == "Windows"
    candidates = windows_candidates() if windows else macos_candidates()
    chosen = sample(candidates, args.limit)
    extras = [p.resolve() for p in args.extra if p.is_file()]
    for missing in (p for p in args.extra if not p.is_file()):
        print(f"note: --extra {missing} does not exist; skipped")
    own_keys = {str(p).lower() for p in extras}
    os_keys = {str(p.resolve()).lower() for p in chosen}
    walked, running = third_party_candidates(windows)
    fresh = lambda paths: [q for q in paths if str(q).lower() not in own_keys | os_keys]
    walked, running = fresh(walked), fresh(running)[:150]
    third = running + walked
    third_chosen = running + (sample(walked, args.third_party) if walked else [])
    print(f"{len(chosen)} of {len(candidates)} OS programs and {len(third_chosen)} of {len(third)} "
          f"third-party programs sampled, {len(extras)} own files")
    records = run_scan(args.binary.resolve(), [str(p) for p in chosen + third_chosen + extras])
    os_records = records[:len(chosen)]
    third_records = records[len(chosen):len(chosen) + len(third_chosen)]
    own_records = records[len(chosen) + len(third_chosen):]
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
        parity_records = os_records + third_records
        compared, mismatched, rust_rejected = check_pe_parity(parity_records)
        if compared < 0.8 * len(parity_records):
            failures.append(f"only {compared} of {len(parity_records)} files could be compared")
        if mismatched > max(1, 0.005 * compared):
            failures.append(f"{mismatched} files have different features in Rust and Python")
        if rust_rejected > 0.02 * len(parity_records):
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

    # Third-party software: what matters is what The Nex would actually score, i.e. files that
    # are not already trusted by a valid signature (Windows) or Apple's anchor (macOS).
    third_scored = [r for r in third_records if r["verdict"] != "not_scored"]
    exposed = [r for r in third_scored if not r.get("trusted")]
    third_flagged = [r for r in exposed if r["verdict"] == "malicious"]
    third_fpr = len(third_flagged) / max(1, len(exposed))
    trusted_flagged = sum(1 for r in third_scored if r.get("trusted") and r["verdict"] == "malicious")
    print(f"third-party: {len(third_flagged)}/{len(exposed)} untrusted programs flagged ({third_fpr:.2%}, "
          f"limit {args.max_fpr_third_party:.0%}); {len(third_scored) - len(exposed)} trusted by signature "
          f"({trusted_flagged} of those would have been flagged)")
    kill_level = [r for r in exposed if r.get("score", 0) >= 0.9]
    print(f"third-party at the 0.9 process-kill level: {len(kill_level)}")
    for record in third_flagged:
        print("  " + describe(record))
    if third_fpr > args.max_fpr_third_party:
        failures.append(f"{third_fpr:.2%} of untrusted third-party programs flagged (limit {args.max_fpr_third_party:.0%})")

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
