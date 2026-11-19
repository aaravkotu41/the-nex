#!/usr/bin/env python3
"""Generate safe zip-bomb samples for The Nex in ./test_sandbox.

  benign.zip       one small text file
  ratio_bomb.zip   ~200 MB of zeros deflated to ~200 KB (about 1000:1)
  nested_bomb.zip  4 levels of nested .zip archives around a tiny payload

Nothing is ever extracted here; the samples only hurt tools that unpack them completely.
Each sample is written under a .tmp name and then renamed, so a running watcher sees a
complete file appear.
"""

import argparse
import io
import os
import sys
import zipfile
from pathlib import Path

CHUNK = 1024 * 1024


def write_atomically(target: Path, build) -> int:
    staging = target.with_name(target.name + ".tmp")
    if staging.exists():
        staging.unlink()
    build(staging)
    os.replace(staging, target)
    return target.stat().st_size


def build_benign(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("readme.txt", "The Nex benign sample archive.\n" * 20)
        archive.writestr("data/numbers.csv", "\n".join(f"{i},{i * i}" for i in range(500)))


def build_ratio_bomb(path: Path, megabytes: int) -> None:
    zeros = bytes(CHUNK)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        with archive.open("zeros.bin", "w") as entry:
            for _ in range(megabytes):
                entry.write(zeros)


def nested_archive(levels: int) -> bytes:
    payload = b"The Nex nested sample payload\n"
    current = None
    for level in range(levels, 0, -1):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            if current is None:
                archive.writestr("payload.txt", payload)
            else:
                archive.writestr(f"level{level + 1}.zip", current)
        current = buffer.getvalue()
    return current


def build_nested(path: Path, levels: int) -> None:
    path.write_bytes(nested_archive(levels))


def declared_size(path: Path) -> int:
    with zipfile.ZipFile(path) as archive:
        return sum(info.file_size for info in archive.infolist())


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate safe zip-bomb samples for The Nex.")
    parser.add_argument("--out-dir", type=Path, default=Path("test_sandbox"))
    parser.add_argument("--ratio-mb", type=int, default=200, help="zeros in ratio_bomb.zip, in MiB")
    parser.add_argument("--levels", type=int, default=4, help="archive levels in nested_bomb.zip")
    args = parser.parse_args()
    if args.ratio_mb < 1 or args.levels < 1:
        parser.error("--ratio-mb and --levels must be at least 1")

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    benign = out_dir / "benign.zip"
    size = write_atomically(benign, build_benign)
    print(f"{benign}  {size:,} B")

    ratio = out_dir / "ratio_bomb.zip"
    size = write_atomically(ratio, lambda p: build_ratio_bomb(p, args.ratio_mb))
    expanded = declared_size(ratio)
    print(f"{ratio}  {size:,} B -> {expanded:,} B declared ({expanded / size:,.0f}:1)")

    nested = out_dir / "nested_bomb.zip"
    size = write_atomically(nested, lambda p: build_nested(p, args.levels))
    print(f"{nested}  {size:,} B, {args.levels} archive levels")
    return 0


if __name__ == "__main__":
    sys.exit(main())
