#!/usr/bin/env python3
"""Build, check and test the known-malware hash list (known_bad.bin) used by The Nex.

    python scripts/fetch_hash_list.py --from-file dump.csv [more.txt ...] [--out PATH]
    python scripts/fetch_hash_list.py --synthetic 1000 [--seed 1]
    python scripts/fetch_hash_list.py --check known_bad.bin
    python scripts/fetch_hash_list.py --self-test

File format, all integers little-endian:
    0    8 bytes   magic  b"NEXKB\\x01\\x00\\x00"
    8    u64       entry count N
    16   u64       created time, Unix seconds UTC
    24   32 bytes  SHA-256 of the body
    56   body      N entries x 16 bytes, each the FIRST 16 BYTES of a file's SHA-256,
                   sorted ascending as raw bytes, no duplicates
The file is exactly 56 + 16*N bytes. N may be 0.

This script makes no network request. --download is deliberately not wired (see download_dump).
Other scripts can import prefix(), build(), parse() and write_list().
"""

import argparse
import csv
import hashlib
import os
import random
import re
import struct
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Compiled into the service (include_str!): it loads only the list whose body checksum is here.
PIN_FILE = ROOT / "crates" / "the-nex-core" / "known_bad.sha256"
MAGIC = b"NEXKB\x01\x00\x00"
HEADER = 56
ENTRY = 16
HASH_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
TYPE_COLUMNS = ("file_type_guess", "file_type")
DEFAULT_TYPES = ("exe,dll,msi,elf,macho,dmg,pkg,ps1,vbs,vbe,js,jse,wsf,hta,bat,cmd,lnk,doc,docx,docm,"
                 "xls,xlsx,xlsm,ppt,pptx,pptm,rtf,pdf,iso,img,jar,zip")


# ------------------------------------------------------------------ format


def prefix(value):
    """16-byte list entry from a SHA-256 given as 64 hex digits (either case) or as 32 raw bytes."""
    if isinstance(value, str):
        value = value.strip()
        if not re.fullmatch(r"[0-9A-Fa-f]{64}", value):
            raise ValueError("not a 64-digit hex SHA-256")
        return bytes.fromhex(value)[:ENTRY]
    if len(value) != 32:
        raise ValueError(f"a raw SHA-256 is 32 bytes, got {len(value)}")
    return bytes(value[:ENTRY])


def build(prefixes, created):
    """The whole list file as bytes: deduplicated, sorted, checksummed."""
    entries = sorted({bytes(p) for p in prefixes})
    if any(len(e) != ENTRY for e in entries):
        raise ValueError(f"every entry must be {ENTRY} bytes")
    if not 0 <= created < 2 ** 64:
        raise ValueError("created time out of range")
    body = b"".join(entries)
    return MAGIC + struct.pack("<QQ", len(entries), created) + hashlib.sha256(body).digest() + body


def parse(data):
    """Validate a list file. Returns (count, created, body_sha256_hex) or raises ValueError(reason)."""
    if len(data) < HEADER:
        raise ValueError(f"too short: {len(data)} bytes, the header alone is {HEADER}")
    if data[:8] != MAGIC:
        raise ValueError("wrong magic (not a Nex known-malware list, or an unsupported version)")
    count, created = struct.unpack_from("<QQ", data, 8)
    if len(data) != HEADER + ENTRY * count:
        raise ValueError(f"length is {len(data)} bytes, expected {HEADER + ENTRY * count} for {count} entries")
    body = data[HEADER:]
    digest = hashlib.sha256(body)
    if digest.digest() != data[24:56]:
        raise ValueError("body checksum mismatch (file is corrupted)")
    for i in range(1, count):
        if body[(i - 1) * ENTRY:i * ENTRY] >= body[i * ENTRY:(i + 1) * ENTRY]:
            raise ValueError(f"entries are not strictly ascending at index {i}")
    return count, created, digest.hexdigest()


def write_list(path, prefixes, created):
    """Atomically write the list (temp file in the same folder, then os.replace). Returns the bytes written."""
    path = Path(path)
    data = build(prefixes, created)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o644)
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise
    return data


def check_file(path):
    """Read and validate a list file: the one code path behind --check and the post-write verify."""
    try:
        data = Path(path).read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read {path}: {error}")
    return parse(data)


def iso(created):
    try:
        return datetime.fromtimestamp(created, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return f"{created} (out of range)"


# ------------------------------------------------------------------ input


def parse_types(text):
    return {t.strip().lstrip(".").lower() for t in text.split(",") if t.strip()}


def type_column(text):
    """Index of the file-type column if this line is a CSV header naming one, else None."""
    try:
        row = next(csv.reader([text], skipinitialspace=True))
    except (csv.Error, StopIteration):
        return None
    names = [cell.strip().strip("\"' ").lower() for cell in row]
    for wanted in TYPE_COLUMNS:
        if wanted in names:
            return names.index(wanted)
    return None


def read_hashes(path, keep):
    """Returns (lowercase hex hashes, lines skipped, rows dropped by type, whether a type column exists,
    rows kept although their type was empty or missing)."""
    hashes, skipped, filtered, unknown = [], 0, 0, 0
    column = None
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        match = None if line.startswith("#") else HASH_RE.search(line)
        if not match:
            # A header may sit in a "# ..." comment (MalwareBazaar dumps) or be a plain first row.
            text = line.lstrip("#").strip()
            if text and column is None:
                column = type_column(text)
            skipped += 1
            continue
        if column is not None:
            try:
                row = next(csv.reader([line], skipinitialspace=True))
            except (csv.Error, StopIteration):
                row = []
            kind = row[column].strip().lstrip(".").lower() if len(row) > column else ""
            if not kind:
                unknown += 1  # unknown type is not a reason to drop a known-bad hash
            elif kind not in keep:
                filtered += 1
                continue
        hashes.append(match.group().lower())
    return hashes, skipped, filtered, column is not None, unknown


# ------------------------------------------------------------------ download (not wired)

DOWNLOAD_REASON = (
    "the MalwareBazaar exports need a personal abuse.ch Auth-Key, and their terms "
    "(https://abuse.ch/terms-of-use/) limit free use to not-for-profit purposes and restrict derivative "
    "works. This stays off until the project owner has permission from abuse.ch."
)


def download_dump(auth_key):
    """WIRING POINT for the MalwareBazaar export. Intentionally not implemented, see DOWNLOAD_REASON."""
    raise NotImplementedError(DOWNLOAD_REASON)


# ------------------------------------------------------------------ self-test


def self_test():
    sha = lambda s: hashlib.sha256(s).hexdigest()
    a, b, c, d, e = (sha(x) for x in (b"a", b"b", b"c", b"d", b"e"))
    created = 1_700_000_000

    def rejects(blob, word):
        try:
            parse(blob)
        except ValueError as error:
            assert word in str(error), f"expected {word!r} in {error!r}"
        else:
            raise AssertionError(f"defect not detected ({word})")

    def raw(entries, stamp=created):
        body = b"".join(entries)
        return MAGIC + struct.pack("<QQ", len(entries), stamp) + hashlib.sha256(body).digest() + body

    # round trip, entries sorted, hex case and raw digest give the same prefix
    data = build([prefix(x) for x in (c, a, b)], created)
    count, stamp, body_hex = parse(data)
    assert (count, stamp) == (3, created) and len(data) == HEADER + 3 * ENTRY
    assert data[HEADER:] == b"".join(sorted(prefix(x) for x in (a, b, c)))
    assert body_hex == sha(data[HEADER:])
    assert prefix(bytes.fromhex(a)) == prefix(a) == prefix(a.upper())

    # empty list is valid; duplicates collapse
    empty = build([], created)
    assert len(empty) == HEADER and parse(empty)[0] == 0
    assert parse(build([prefix(a)] * 3 + [prefix(b)], created))[0] == 2

    # defects
    bad = bytearray(data)
    bad[HEADER + 3] ^= 1
    rejects(bytes(bad), "checksum")
    rejects(data[:-1], "length")
    rejects(data[:20], "too short")
    rejects(b"XXXX" + data[4:], "magic")
    rejects(raw(sorted([prefix(a), prefix(b)], reverse=True)), "ascending")
    rejects(raw([prefix(a), prefix(a)]), "ascending")

    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        out = folder / "list.bin"
        write_list(out, [prefix(x) for x in (a, b)], created)
        assert check_file(out)[0] == 2 and os.listdir(folder) == ["list.bin"]
        rejects(b"", "too short")

        keep = parse_types(DEFAULT_TYPES)
        csv_file = folder / "dump.csv"
        csv_file.write_text(
            "# first_seen_utc,sha256_hash,md5_hash,file_name,file_type_guess,mime_type\n"
            "# a comment\n"
            f"2024-01-01,{a},m,a.exe,exe,app\n"
            f"2024-01-02,{b.upper()},m,b.txt,txt,text\n"
            f'"2024-01-03", "{c}", "m", "c.docm", "docm", "app"\n'
            f"2024-01-04,{d},m,d.bin,,app\n"
            f"2024-01-05,{e}\n",
            encoding="utf-8")
        assert read_hashes(csv_file, keep) == ([a, c, d, e], 2, 1, True, 2)

        plain = folder / "plain.txt"
        plain.write_text(f"{a}\n\n# {c}\n{b.upper()}\n{c} trailing words\nnot a hash\n{a}f\n", encoding="utf-8")
        assert read_hashes(plain, keep) == ([a, b, c], 4, 0, False, 0)
    print("self-test passed")


# ------------------------------------------------------------------ main


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--from-file", nargs="+", metavar="PATH", help="read hashes from local text/CSV files")
    mode.add_argument("--synthetic", type=int, metavar="N", help="N pseudo-random entries, for size/speed tests")
    mode.add_argument("--download", action="store_true", help="not wired yet; explains why and exits 2")
    mode.add_argument("--check", metavar="PATH", help="verify an existing list file")
    mode.add_argument("--self-test", action="store_true", help="run built-in asserts, touches nothing in the repo")
    parser.add_argument("--keep-types", default=DEFAULT_TYPES, help="comma list; only used when a type column exists")
    parser.add_argument("--seed", type=int, default=0, help="seed for --synthetic (default 0)")
    parser.add_argument("--out", type=Path, default=ROOT / "known_bad.bin", help="output file (default: known_bad.bin)")
    parser.add_argument("--created", type=int, help="created time, Unix seconds (default: now)")
    parser.add_argument("--pin", action="store_true",
                        help="also record the list's checksum for the next build of the service, which then "
                             "accepts exactly this list (git checkout the pin file to undo)")
    args = parser.parse_args()

    if args.self_test:
        try:
            self_test()
        except AssertionError as error:
            print(f"self-test FAILED: {error}")
            return 1
        return 0

    if args.check:
        try:
            count, created, digest = check_file(args.check)
        except ValueError as error:
            print(f"invalid: {error}")
            return 1
        print(f"valid: {count:,} entries, created {iso(created)}, body sha256 {digest}")
        return 0

    if args.download:
        key_state = "set" if os.environ.get("ABUSECH_AUTH_KEY") else "not set"
        print(f"--download is not wired yet (ABUSECH_AUTH_KEY is {key_state}): {DOWNLOAD_REASON}")
        print("For now build the list from local dumps with --from-file.")
        return 2

    created = int(time.time()) if args.created is None else args.created
    found, skipped, dropped, unknown_type = [], 0, 0, 0
    if args.synthetic is not None:
        if args.synthetic < 0:
            parser.error("--synthetic must be 0 or more")
        rng = random.Random(args.seed)
        found = [rng.randbytes(ENTRY) for _ in range(args.synthetic)]
        print(f"SYNTHETIC list: {args.synthetic:,} random entries (seed {args.seed}). It matches no real file; "
              "use it only for size and speed measurements.")
    else:
        keep = parse_types(args.keep_types)
        for path in args.from_file:
            try:
                hashes, lines_skipped, filtered, typed, unknown = read_hashes(path, keep)
            except OSError as error:
                print(f"cannot read {path}: {error}")
                return 1
            if not typed:
                print(f"{path}: no file_type_guess/file_type column found, so nothing was filtered")
            found += [prefix(h) for h in hashes]
            skipped += lines_skipped
            dropped += filtered
            unknown_type += unknown
    unique = set(found)

    try:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        data = write_list(args.out, unique, created)
        count, stamp, digest = check_file(args.out)  # same code path as --check
    except (ValueError, OSError) as error:
        print(f"failed: {error}")
        return 1
    assert count == len(unique) and data == args.out.read_bytes()

    print(f"entries kept:       {count:,}")
    print(f"duplicates removed: {len(found) - len(unique):,}")
    print(f"lines skipped:      {skipped:,} (blank, comment or no hash)")
    print(f"dropped by type:    {dropped:,}")
    print(f"kept, unknown type: {unknown_type:,}")
    print(f"file size:          {len(data):,} bytes")
    print(f"created:            {iso(stamp)}")
    print(f"body sha256:        {digest}")
    print(f"file sha256:        {hashlib.sha256(data).hexdigest()}")
    print(f"wrote {args.out}")
    if args.pin:
        PIN_FILE.write_text(digest + "\n")
        print(f"pinned in {PIN_FILE}; rebuild the app so the service accepts this list")
    return 0


if __name__ == "__main__":
    sys.exit(main())
