#!/usr/bin/env python3
"""Vendor the on-device vision runtime used by AegisMesh's hand-sign and face-expression watch.

    python scripts/fetch_vision_models.py [--check]

Downloads Google MediaPipe Tasks Vision (Apache-2.0) and its hand and face landmark models into
ui/aegismesh/vendor/mediapipe/, verifying every file against a pinned SHA-256. The app embeds
them at build time and runs them locally in its webview: no camera frame, landmark or usage
statistic ever leaves the device (the console page also blocks all off-device connections).
The folder is git-ignored; CI runs this before building. --check only verifies what is there.
"""

import argparse
import hashlib
import io
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "ui" / "aegismesh" / "vendor" / "mediapipe"
VERSION = "1.2.2"
PACKAGE_URL = f"https://registry.npmjs.org/@mediapipe/tasks-vision/-/tasks-vision-{VERSION}.tgz"
MODELS = "https://storage.googleapis.com/mediapipe-models"

# destination name -> (source, sha256). Source is a URL or "package:<member path>".
FILES = {
    "vision_bundle.js": ("package:package/vision_bundle.js",
                         "a8c95ebecb9efca4ef79ce32f7b77fa5cb61b809e7e21a2f3d792d181ca0b822"),
    "vision_wasm_internal.js": ("package:package/wasm/vision_wasm_internal.js",
                                "f2b9c17131ea79716ec6bf07b117a087b2749a6f8a1e2f1f2e77a9382092db5b"),
    "vision_wasm_internal.wasm": ("package:package/wasm/vision_wasm_internal.wasm",
                                  "f5bd25147ac89d506074293ce2675969b10e827180db95a0d9689c2ed80764ab"),
    "hand_landmarker.task": (f"{MODELS}/hand_landmarker/hand_landmarker/float16/1/hand_landmarker.task",
                             "fbc2a30080c3c557093b5ddfc334698132eb341044ccee322ccf8bcf3607cde1"),
    "face_landmarker.task": (f"{MODELS}/face_landmarker/face_landmarker/float16/1/face_landmarker.task",
                             "64184e229b263107bc2b804c6625db1341ff2bb731874b0bcc2fe6544e0bc9ff"),
}
NOTICE = f"""MediaPipe Tasks Vision {VERSION} (@mediapipe/tasks-vision) and the MediaPipe hand and face
landmarker models, Copyright Google LLC, licensed under the Apache License, Version 2.0
(https://www.apache.org/licenses/LICENSE-2.0). Fetched and SHA-256 verified by
scripts/fetch_vision_models.py. Run locally in the app; network use is blocked by the page.
"""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def download(url, attempts=4):
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "thenex-build"})
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read()
        except OSError as error:
            if attempt == attempts:
                raise SystemExit(f"download failed: {url}: {error}")
            print(f"  retry {attempt} for {url}: {error}")
            time.sleep(3 * attempt)
    return b""


def current_ok(name, expected):
    path = OUT / name
    return path.is_file() and sha256(path.read_bytes()) == expected


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify only, download nothing")
    args = parser.parse_args()

    missing = [name for name, (_, digest) in FILES.items() if not current_ok(name, digest)]
    if args.check:
        for name in FILES:
            print(f"  {'ok     ' if name not in missing else 'MISSING'} {name}")
        return 1 if missing else 0
    if not missing:
        print(f"vision runtime already present and verified in {OUT.relative_to(ROOT)}")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    package = None
    for name in missing:
        source, expected = FILES[name]
        if source.startswith("package:"):
            if package is None:
                print(f"fetching {PACKAGE_URL}")
                package = tarfile.open(fileobj=io.BytesIO(download(PACKAGE_URL)), mode="r:gz")
            member = package.getmember(source.split(":", 1)[1])
            if not member.isfile():
                raise SystemExit(f"{member.name} is not a regular file in the package")
            data = package.extractfile(member).read()
        else:
            print(f"fetching {source}")
            data = download(source)
        actual = sha256(data)
        if actual != expected:
            raise SystemExit(f"checksum mismatch for {name}: expected {expected}, got {actual}")
        (OUT / name).write_bytes(data)
        print(f"  {name}  {len(data):,} B  sha256 ok")
    (OUT / "NOTICE.txt").write_text(NOTICE, encoding="utf-8")
    total = sum((OUT / name).stat().st_size for name in FILES)
    print(f"vision runtime ready: {total / 1e6:.1f} MB in {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
