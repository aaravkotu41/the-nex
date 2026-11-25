#!/usr/bin/env python3
"""Measure the Binary AI on real malware data: the EMBER2024 test split.

EMBER2024 (Joyce et al., 2025; Apache-2.0; https://huggingface.co/datasets/joyce8/EMBER2024) holds
measurements of real Windows programs, malware included, and no program files. This script turns
each EMBER row into our 14 features, scores them with the shipped model through the Rust engine,
and reports malware caught and clean programs flagged.

    python scripts/ember_eval.py fetch [--cache DIR]     # download (4 GB, checksummed), convert, delete
    python scripts/ember_eval.py score [--cache DIR]     # score every converted row with thenex_model.onnx
    python scripts/ember_eval.py report [--cache DIR]    # print the numbers; --json FILE to save them
    python scripts/ember_eval.py sample                  # write data/ember2024_sample.csv
    python scripts/ember_eval.py check                   # score that committed sample (no download)
    python scripts/ember_eval.py --self-test

fetch, score and report run locally only: the data is far too large for CI. `check` and
`--self-test` need no download and run in CI. Needs numpy and, for scoring, cargo.

How each feature is derived, and how close it is to the engine's own measurement:
  exact        size, section count, W+X ratio, risky imports, packer names, resources, .NET
  approximate  section entropies (pefile's bytes, not goblin's), import count (two parsers),
               entry-point section and anomaly (EMBER has no section addresses, so the layout is
               rebuilt from sizes and alignment), overlay (EMBER's overlay minus the certificate)
  fixed        has_signature = 0 (as in training; the model ignores this input), is_macho = 0

The test files list every program twice; each is counted once.
"""

import argparse
import csv
import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import numpy as np

import thenex_features as tf

ROOT = Path(__file__).resolve().parent.parent
REVISION = "3d23efef7c0f0b702c5024400cfff4c3744a3832"
URL = "https://huggingface.co/datasets/joyce8/EMBER2024/resolve/" + REVISION + "/{name}.zip"
# name -> (bytes, sha256), from the Hugging Face file listing at REVISION
FILES = {
    "Win32_test": (2593425203, "c05f6562dee3ace4195087be918eb00181e33bc31464c671fb5ba00c9dd5dfdb"),
    "Win64_test": (1176459716, "52a5a05c1bfa5bb021bb8b44c2e0afcf8983dfa1c6c0a9d76db393e5c682ce10"),
    "Dot_Net_test": (220481493, "b74c4181dbd77565fce16ba47c8ab0f7c7044ae6d880d859ec2c27365dea6299"),
    "challenge": (32144161, "dd215997b10596e4397d2b305d54afe9678e91e3051918262f0172b36e40baf1"),
}
PE_TYPES = ("Win32", "Win64", "Dot_Net")
ALERT, KILL = 0.65, 0.9  # config.rs AI_MALWARE_THRESHOLD, ai_policy.rs KILL_CONFIDENCE
SAMPLE = ROOT / "data" / "ember2024_sample.csv"
# Floors for `check`, set loosely under what the 0.4.1 model scores on the sample (29.4% / 3.7%):
# they catch a model that got clearly worse on real malware data, not small retraining noise.
MIN_SAMPLE_CAUGHT, MAX_SAMPLE_FLAGGED = 0.20, 0.08


# ------------------------------------------------------------------ one row -> our features


def directory(row, name):
    """(file offset or RVA, size) of a data directory; (0, 0) when absent."""
    for entry in row.get("datadirectories") or []:
        if entry.get("name") == name:
            return int(entry.get("virtual_address") or 0), int(entry.get("size") or 0)
    return 0, 0


def entry_section(row, sections):
    """Index of the section holding the entry point, or None, and how it was found.

    EMBER records the name of the section containing the entry point, but falls back to the
    first executable section when none does, which would hide exactly the anomaly feature 5
    looks for. Section addresses are not stored, so they are rebuilt: Windows only loads images
    whose sections follow each other at SectionAlignment boundaries.
    """
    optional = row["header"]["optional"]
    entry = int(optional.get("address_of_entrypoint") or 0)
    align = max(int(optional.get("section_alignment") or 0), 1)
    up = lambda value: -(-value // align) * align
    address, rebuilt = up(max(int(optional.get("sizeof_headers") or 0), 1)), None
    for index, section in enumerate(sections):
        span = max(int(section["vsize"]), int(section["size"]))
        if rebuilt is None and address <= entry < address + span:
            rebuilt = index
        # The loader steps by the virtual size, and by the raw size only when that is zero.
        address += up(max(int(section["vsize"]) or int(section["size"]), 1))
    named = row["section"].get("entry") or ""
    names = [s["name"] for s in sections]
    first_exec = next((s["name"] for s in sections if "MEM_EXECUTE" in s["props"]), "")
    if rebuilt is not None and names[rebuilt] == named:
        return rebuilt, "agree"
    if named and named != first_exec and named in names:
        return names.index(named), "ember"  # EMBER really found it; the rebuilt layout is off
    return rebuilt, "rebuilt"


def profile(row):
    """The engine's BinaryProfile for one EMBER row (see pe_profile in thenex_features.py)."""
    sections = row["section"]["sections"]
    size = int(row["general"]["size"])
    index, how = entry_section(row, sections)
    entry = int(row["header"]["optional"].get("address_of_entrypoint") or 0)
    holder = sections[index] if index is not None else None
    anomaly = entry != 0 and (
        holder is None
        or "MEM_EXECUTE" not in holder["props"]
        or (len(sections) > 1 and index == len(sections) - 1)
    )
    names = {name for functions in (row.get("imports") or {}).values() for name in functions}
    cert_offset, cert_size = directory(row, "SECURITY")
    overlay = int(row["section"]["overlay"]["size"])
    if cert_offset > 0 and cert_size > 0 and cert_offset >= size - overlay:
        overlay -= min(cert_size, overlay)  # EMBER's overlay includes the certificate; ours does not
    resource_at, resource_size = directory(row, "RESOURCE")
    clr_at, clr_size = directory(row, "COM_DESCRIPTOR")
    return {
        "format": "pe",
        "size_bytes": size,
        "section_count": len(sections),
        "max_section_entropy": max((s["entropy"] for s in sections if s["size"] > 0), default=0.0),
        "entry_section_entropy": holder["entropy"] if holder and holder["size"] > 0 else 0.0,
        "wx_sections": sum(1 for s in sections if "MEM_WRITE" in s["props"] and "MEM_EXECUTE" in s["props"]),
        "entry_anomaly": anomaly,
        "import_count": sum(len(functions) for functions in (row.get("imports") or {}).values()),
        "suspicious_imports": [n for n in tf.SUSPICIOUS_IMPORTS if any(name.startswith(n) for name in names)],
        "signed": False,  # held at 0, as in training; the model has no connection to this input
        "overlay_bytes": max(overlay, 0),
        "packer_sections": [s["name"].lower() for s in sections if s["name"].lower() in tf.PACKER_SECTION_NAMES],
        "resource_bytes": min(resource_size, size) if resource_at > 0 else 0,
        "dotnet": clr_at > 0 and clr_size > 0,
        "_entry_how": how,
        "_has_certificate": cert_offset > 0 and cert_size > 0,
    }


# ------------------------------------------------------------------ fetch and convert


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def convert(zip_path, out_path):
    rows = {"x": [], "label": [], "week": [], "kind": [], "certificate": [], "family": [], "confidence": [], "how": [], "sha": []}
    skipped, seen = 0, set()
    with zipfile.ZipFile(zip_path) as archive:
        for member in sorted(archive.namelist()):
            if not member.endswith(".jsonl"):
                continue
            with archive.open(member) as handle:
                for line in io.TextIOWrapper(handle, encoding="utf-8"):
                    row = json.loads(line)
                    if row["sha256"] in seen:
                        continue  # the test files list every program twice (the copies differ only in "caps")
                    seen.add(row["sha256"])
                    if row.get("file_type") not in PE_TYPES or not row["general"].get("is_pe") or not row["section"]["sections"]:
                        skipped += 1  # not a Windows program, or one pefile could not read
                        continue
                    p = profile(row)
                    rows["x"].append(tf.features(p))
                    rows["label"].append(int(row["label"]))
                    rows["week"].append(int(row.get("week_id") or 0))
                    rows["kind"].append(PE_TYPES.index(row["file_type"]))
                    rows["certificate"].append(p["_has_certificate"])
                    rows["family"].append((row.get("family") or "")[:40])
                    rows["confidence"].append(float(row.get("family_confidence") or 0.0))
                    rows["how"].append(("agree", "ember", "rebuilt").index(p["_entry_how"]))
                    rows["sha"].append(row["sha256"][:16])
    np.savez_compressed(
        out_path, x=np.array(rows["x"], dtype=np.float32), label=np.array(rows["label"], dtype=np.int8),
        week=np.array(rows["week"], dtype=np.int16), kind=np.array(rows["kind"], dtype=np.int8),
        certificate=np.array(rows["certificate"], dtype=bool), family=np.array(rows["family"]),
        confidence=np.array(rows["confidence"], dtype=np.float32), how=np.array(rows["how"], dtype=np.int8),
        sha=np.array(rows["sha"]), skipped=np.array(skipped))
    return len(rows["label"]), skipped


def fetch(cache, names):
    cache.mkdir(parents=True, exist_ok=True)
    for name in names:
        size, digest = FILES[name]
        out = cache / f"{name}.npz"
        if out.exists():
            print(f"{name}: already converted")
            continue
        archive = cache / f"{name}.zip"
        if not archive.exists() or archive.stat().st_size != size:
            print(f"{name}: downloading {size / 1e9:.2f} GB")
            subprocess.run(["curl", "-sS", "-L", "-C", "-", "--retry", "5", "-A", "Mozilla/5.0", "-o", str(archive), URL.format(name=name)], check=True)
        if sha256_of(archive) != digest:
            sys.exit(f"{name}: checksum mismatch, refusing to use {archive}")
        kept, skipped = convert(archive, out)
        archive.unlink()
        print(f"{name}: {kept:,} rows converted, {skipped:,} skipped")


def load(cache, name):
    data = np.load(cache / f"{name}.npz")
    scores = cache / f"{name}.scores"
    return data, (np.fromfile(scores, dtype="<f4") if scores.exists() else None)


# ------------------------------------------------------------------ score through the engine


def score_matrix(x, release=True):
    """Scores rows with thenex_model.onnx exactly as the engine does (tract, via a Rust test)."""
    work = ROOT / "target" / "ember_scores"
    work.mkdir(parents=True, exist_ok=True)
    x.astype("<f4").tofile(work / "in.f32")
    env = dict(__import__("os").environ, THENEX_FEATURES_IN=str(work / "in.f32"), THENEX_SCORES_OUT=str(work / "out.f32"))
    subprocess.run(["cargo", "test"] + (["--release"] if release else []) + ["--locked", "-p", "the-nex-core", "--test", "edr_suite",
                    "score_feature_rows", "--", "--ignored", "--exact"], check=True, cwd=ROOT, env=env, capture_output=True)
    scores = np.fromfile(work / "out.f32", dtype="<f4")
    assert len(scores) == len(x), (len(scores), len(x))
    return scores


def score(cache, names):
    for name in names:
        data, _ = load(cache, name)
        score_matrix(data["x"]).astype("<f4").tofile(cache / f"{name}.scores")
        print(f"{name}: {len(data['label']):,} rows scored")


# ------------------------------------------------------------------ report


def rate(mask, hits):
    total = int(mask.sum())
    return (float((hits & mask).sum()) / total if total else float("nan")), total


def auc(scores, labels):
    """ROC AUC by ranks (ties share a rank)."""
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores))
    sorted_scores = scores[order]
    edges = np.flatnonzero(np.r_[True, sorted_scores[1:] != sorted_scores[:-1], True])
    for start, end in zip(edges[:-1], edges[1:]):
        ranks[order[start:end]] = (start + end + 1) / 2.0
    positives = labels == 1
    n_pos, n_neg = int(positives.sum()), int((~positives).sum())
    return (ranks[positives].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg) if n_pos and n_neg else float("nan")


def summarise(label, scores, certificate):
    malware, clean = label == 1, label == 0
    out = {"auc": auc(scores, label)}
    for name, level in (("alert", ALERT), ("kill", KILL)):
        hits = scores >= level
        out[name] = {
            "malware_caught": rate(malware, hits),
            "clean_flagged": rate(clean, hits),
            "clean_flagged_no_certificate": rate(clean & ~certificate, hits),
            "malware_caught_no_certificate": rate(malware & ~certificate, hits),
        }
    return out


def report(cache, json_out):
    parts = [load(cache, n) for n in ("Win32_test", "Win64_test", "Dot_Net_test")]
    if any(s is None for _, s in parts):
        sys.exit("run `score` first")
    cat = lambda key: np.concatenate([d[key] for d, _ in parts])
    label, week, kind, cert, family, conf, how = (cat(k) for k in ("label", "week", "kind", "certificate", "family", "confidence", "how"))
    scores = np.concatenate([s for _, s in parts])
    pct = lambda pair: f"{100 * pair[0]:6.2f}% of {pair[1]:,}"
    result = {"rows": int(len(label)), "skipped": int(sum(int(d["skipped"]) for d, _ in parts)), "all": summarise(label, scores, cert)}
    print(f"EMBER2024 test split: {len(label):,} Windows programs ({int((label == 1).sum()):,} malware), {result['skipped']:,} rows skipped")
    print(f"entry-point section found by: both {np.mean(how == 0):.1%}, EMBER's name {np.mean(how == 1):.1%}, rebuilt layout only {np.mean(how == 2):.1%}")
    def show(title, summary):
        print(f"\n{title}  (ROC AUC {summary['auc']:.4f})")
        for name, level in (("alert", ALERT), ("kill", KILL)):
            s = summary[name]
            print(f"  at {level}: malware caught {pct(s['malware_caught'])} | clean flagged {pct(s['clean_flagged'])}"
                  f" | no certificate: malware caught {pct(s['malware_caught_no_certificate'])},"
                  f" clean flagged {pct(s['clean_flagged_no_certificate'])}")
    show("All Windows programs", result["all"])
    result["by_type"] = {}
    for index, name in enumerate(PE_TYPES):
        m = kind == index
        result["by_type"][name] = summarise(label[m], scores[m], cert[m])
        show(name, result["by_type"][name])
    print("\nBy week (malware caught / clean flagged at 0.65):")
    result["by_week"] = {}
    for w in sorted(set(week.tolist())):
        m = week == w
        caught, flagged = rate(m & (label == 1), scores >= ALERT), rate(m & (label == 0), scores >= ALERT)
        result["by_week"][int(w)] = [caught[0], flagged[0]]
        print(f"  week {w}: {100 * caught[0]:5.1f}% / {100 * flagged[0]:5.2f}%")
    print("\nBy malware family (labelled with confidence >= 0.7, at least 500 samples), caught at 0.65 / 0.9:")
    result["by_family"] = {}
    sure = (label == 1) & (conf >= 0.7) & (family != "")
    names, counts = np.unique(family[sure], return_counts=True)
    for name, count in sorted(zip(names.tolist(), counts.tolist()), key=lambda item: -item[1]):
        if count < 500:
            continue
        m = sure & (family == name)
        a, k = rate(m, scores >= ALERT)[0], rate(m, scores >= KILL)[0]
        result["by_family"][name] = [count, a, k]
        print(f"  {name:22s} {count:7,}  {100 * a:5.1f}% / {100 * k:5.1f}%")
    if (cache / "challenge.npz").exists():
        data, s = load(cache, "challenge")
        if s is not None:
            result["challenge"] = {"rows": int(len(s)), "alert": float(np.mean(s >= ALERT)), "kill": float(np.mean(s >= KILL))}
            print(f"\nChallenge set (malware no antivirus caught at first): {len(s):,} programs, "
                  f"caught {np.mean(s >= ALERT):.1%} at 0.65, {np.mean(s >= KILL):.1%} at 0.9")
    if json_out:
        Path(json_out).write_text(json.dumps(result, indent=1) + "\n")


def write_sample(cache, per_cell=170):
    """A small, fixed sample (same count per type, label and week parity) for regression checks."""
    rng = np.random.default_rng(2024)
    with open(SAMPLE, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["file_type", "label", "week", "sha256_prefix"] + tf.FEATURE_NAMES)
        for name in ("Win32_test", "Win64_test", "Dot_Net_test"):
            data, _ = load(cache, name)
            for label in (0, 1):
                for parity in (0, 1):
                    pool = np.flatnonzero((data["label"] == label) & (data["week"] % 2 == parity))
                    for i in sorted(rng.choice(pool, size=min(per_cell, len(pool)), replace=False).tolist()):
                        writer.writerow([name[:-5], label, int(data["week"][i]), str(data["sha"][i])] + [f"{v:.6f}" for v in data["x"][i]])
    print(f"wrote {SAMPLE}")


def check():
    """Scores the committed sample with the current model: a regression check that needs no download."""
    with open(SAMPLE, newline="") as handle:
        rows = list(csv.DictReader(handle))
    x = np.array([[float(r[n]) for n in tf.FEATURE_NAMES] for r in rows], dtype=np.float32)
    label = np.array([int(r["label"]) for r in rows])
    hits = score_matrix(x, release=False) >= ALERT  # debug build: CI has it already, and 2,040 rows are instant
    caught, flagged = rate(label == 1, hits), rate(label == 0, hits)
    print(f"EMBER2024 sample at {ALERT}: malware caught {100 * caught[0]:.1f}% of {caught[1]:,}, "
          f"clean flagged {100 * flagged[0]:.1f}% of {flagged[1]:,}")
    if caught[0] < MIN_SAMPLE_CAUGHT or flagged[0] > MAX_SAMPLE_FLAGGED:
        sys.exit(f"worse than the floor (caught >= {MIN_SAMPLE_CAUGHT:.0%}, flagged <= {MAX_SAMPLE_FLAGGED:.0%})")


# ------------------------------------------------------------------ self-test


def self_test():
    def section(name, size, vsize, entropy, props):
        return {"name": name, "size": size, "vsize": vsize, "entropy": entropy, "props": props}
    row = {
        "general": {"size": 100_000, "is_pe": 1}, "file_type": "Win32",
        "header": {"optional": {"address_of_entrypoint": 0x1100, "sizeof_headers": 0x400, "section_alignment": 0x1000}},
        "section": {"entry": ".text", "overlay": {"size": 30_000},
                    "sections": [section(".text", 0x3000, 0x1800, 6.0, ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]),
                                 section(".data", 0x1000, 0x3000, 2.0, ["MEM_READ", "MEM_WRITE"]),
                                 section("UPX1", 0x1000, 0x1000, 7.9, ["MEM_READ", "MEM_WRITE", "MEM_EXECUTE"])]},
        "imports": {"KERNEL32.dll": ["WriteProcessMemory", "ShellExecuteExW", "CreateFileA"], "X.DLL": ["X.DLL:ordinal3"]},
        "datadirectories": [{"has_relocs": 0}, {"name": "RESOURCE", "size": 5_000, "virtual_address": 0x9000},
                            {"name": "SECURITY", "size": 10_000, "virtual_address": 90_000},
                            {"name": "COM_DESCRIPTOR", "size": 0, "virtual_address": 0}],
    }
    p = profile(row)
    assert (p["section_count"], p["wx_sections"], p["import_count"]) == (3, 1, 4), p
    assert p["suspicious_imports"] == ["WriteProcessMemory", "ShellExecute"], p["suspicious_imports"]
    assert p["max_section_entropy"] == 7.9 and p["entry_section_entropy"] == 6.0
    assert not p["entry_anomaly"] and p["_entry_how"] == "agree"
    assert p["overlay_bytes"] == 20_000, p["overlay_bytes"]  # certificate (10,000 at offset 90,000) taken out
    assert p["packer_sections"] == ["upx1"] and p["resource_bytes"] == 5_000 and not p["dotnet"] and not p["signed"]
    f = tf.features(p)
    assert len(f) == 14 and f[8] == 0.0 and f[13] == 0.0 and abs(f[9] - 0.2) < 1e-9 and abs(f[4] - 1 / 3) < 1e-9, f

    # Layout: .text at 0x1000, .data at 0x3000 (.text's raw size is larger than its virtual size,
    # which must not push the next section along), UPX1 at 0x6000.
    # Entry point in the last section, in a non-executable one, and outside every section: anomalies.
    for entry, named, expect_how in ((0x6100, "UPX1", "agree"), (0x4100, ".data", "agree"), (0x90000, ".text", "rebuilt")):
        row["header"]["optional"]["address_of_entrypoint"], row["section"]["entry"] = entry, named
        q = profile(row)
        assert q["entry_anomaly"] and q["_entry_how"] == expect_how, (entry, q["entry_anomaly"], q["_entry_how"])
    # A DLL with no entry point is never an anomaly; the certificate inside the image is not overlay.
    row["header"]["optional"]["address_of_entrypoint"] = 0
    row["datadirectories"][2]["virtual_address"] = 50_000
    q = profile(row)
    assert not q["entry_anomaly"] and q["overlay_bytes"] == 30_000
    # EMBER names a section the rebuilt layout does not reach (odd alignment): its name wins.
    row["header"]["optional"].update(address_of_entrypoint=0x7100, section_alignment=0x10)
    row["section"]["entry"] = ".data"
    assert profile(row)["_entry_how"] == "ember"

    labels = np.array([0, 0, 1, 1, 1])
    assert abs(auc(np.array([0.1, 0.4, 0.35, 0.8, 0.9]), labels) - 5 / 6) < 1e-9
    assert abs(auc(np.array([0.5] * 5), labels) - 0.5) < 1e-9
    print("self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", nargs="?", choices=["fetch", "score", "report", "sample", "check"])
    parser.add_argument("--cache", type=Path, default=ROOT / "ember_cache", help="where converted rows are kept (git-ignored)")
    parser.add_argument("--only", nargs="+", choices=list(FILES), default=list(FILES))
    parser.add_argument("--json", help="report: also write the numbers to this file")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.command == "fetch":
        fetch(args.cache, args.only)
    elif args.command == "score":
        score(args.cache, args.only)
    elif args.command == "report":
        report(args.cache, args.json)
    elif args.command == "sample":
        write_sample(args.cache)
    elif args.command == "check":
        check()
    else:
        parser.error("give a command or --self-test")


if __name__ == "__main__":
    main()
