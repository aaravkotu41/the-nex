#!/usr/bin/env python3
"""Vendor the on-device runtimes used by AegisMesh: vision (signs, expressions) and the 3D viewer.

    python scripts/fetch_vision_models.py [--check]

Downloads Google MediaPipe Tasks Vision (Apache-2.0) and its hand and face landmark models into
ui/aegismesh/vendor/mediapipe/, and three.js (MIT) for the 3D wearable viewer into
ui/aegismesh/vendor/three/, verifying every file against a pinned SHA-256. The app embeds them
at build time and runs them locally in its webview: no camera frame, landmark or usage
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
VENDOR = ROOT / "ui" / "aegismesh" / "vendor"
VERSION = "1.2.2"
PACKAGE_URL = f"https://registry.npmjs.org/@mediapipe/tasks-vision/-/tasks-vision-{VERSION}.tgz"
MODELS = "https://storage.googleapis.com/mediapipe-models"
THREE_VERSION = "0.170.0"
THREE_URL = f"https://registry.npmjs.org/three/-/three-{THREE_VERSION}.tgz"

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

# three.js: destination name -> (member of the npm package, sha256 of that member as published).
THREE_FILES = {
    "three.module.min.js": ("package/build/three.module.min.js",
                            "08fd7545d13d2c7fb65ab691530a802dafefd638596501854f267d0fb13c39e7"),
    "GLTFLoader.js": ("package/examples/jsm/loaders/GLTFLoader.js",
                      "45139faddd5aaf48ed2d62203d976e5cbd703db1a592de40527f9f6cf58abd44"),
    "BufferGeometryUtils.js": ("package/examples/jsm/utils/BufferGeometryUtils.js",
                               "c25b7930e570e9ec56173cd3b866ec8d2e10016630db3937efb439daf1cedbf6"),
    "RoomEnvironment.js": ("package/examples/jsm/environments/RoomEnvironment.js",
                           "85869bdd22f7cf0b22e68dcefe6cb710480af0f5c901a76f7a7764fd07fc8014"),
    "OrbitControls.js": ("package/examples/jsm/controls/OrbitControls.js",
                         "80efaadea4f8a636a65fb0bd08bfef62f3d93a0bb94e2e7500f23176c5c07f4e"),
    "LICENSE.txt": ("package/LICENSE",
                    "4c40a1ef62450b857c3b2aaf294936304cd552d965fbcd9d32d4c5bcf4ba4454"),
}
THREE_NOTICE = f"""three.js r{THREE_VERSION.split('.')[1]} (npm package three@{THREE_VERSION}), MIT licence: see LICENSE.txt.
Files: build/three.module.min.js and, from examples/jsm, GLTFLoader.js, BufferGeometryUtils.js,
RoomEnvironment.js and OrbitControls.js, SHA-256 verified by scripts/fetch_vision_models.py.
The only change: their `from 'three'` imports point at ./three.module.min.js (and GLTFLoader's
BufferGeometryUtils import at ./BufferGeometryUtils.js), so they load as plain ES modules
without an import map. Used by ../../wearable3d.js.
"""
# The import rewrites above; a stamp records which published file each local copy came from.
THREE_REWRITES = (
    ("from 'three';", "from './three.module.min.js';"),
    ("from '../utils/BufferGeometryUtils.js';", "from './BufferGeometryUtils.js';"),
)
THREE_STAMP = ".sources"


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


def rewrite_three(name, data):
    if not name.endswith(".js") or name == "three.module.min.js":
        return data
    text = data.decode("utf-8")
    for old, new in THREE_REWRITES:
        text = text.replace(old, new)
    return text.encode("utf-8")


def package_member(package, path):
    member = package.getmember(path)
    if not member.isfile():
        raise SystemExit(f"{member.name} is not a regular file in the package")
    return package.extractfile(member).read()


# ------------------------------------------------------------------ MediaPipe


def vision_missing():
    out = VENDOR / "mediapipe"
    return [name for name, (_, digest) in FILES.items()
            if not ((out / name).is_file() and sha256((out / name).read_bytes()) == digest)]


def fetch_vision(missing):
    out = VENDOR / "mediapipe"
    out.mkdir(parents=True, exist_ok=True)
    package = None
    for name in missing:
        source, expected = FILES[name]
        if source.startswith("package:"):
            if package is None:
                print(f"fetching {PACKAGE_URL}")
                package = tarfile.open(fileobj=io.BytesIO(download(PACKAGE_URL)), mode="r:gz")
            data = package_member(package, source.split(":", 1)[1])
        else:
            print(f"fetching {source}")
            data = download(source)
        actual = sha256(data)
        if actual != expected:
            raise SystemExit(f"checksum mismatch for {name}: expected {expected}, got {actual}")
        (out / name).write_bytes(data)
        print(f"  {name}  {len(data):,} B  sha256 ok")
    (out / "NOTICE.txt").write_text(NOTICE, encoding="utf-8")
    total = sum((out / name).stat().st_size for name in FILES)
    print(f"vision runtime ready: {total / 1e6:.1f} MB in {out.relative_to(ROOT)}")


# ------------------------------------------------------------------ three.js


def three_missing():
    """A local copy is current when it is exactly the rewrite of the pinned published file."""
    out = VENDOR / "three"
    stamp = out / THREE_STAMP
    recorded = {}
    if stamp.is_file():
        for line in stamp.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 3:
                recorded[parts[0]] = (parts[1], parts[2])
    missing = []
    for name, (_, published) in THREE_FILES.items():
        path = out / name
        entry = recorded.get(name)
        if not (path.is_file() and entry and entry[0] == published and entry[1] == sha256(path.read_bytes())):
            missing.append(name)
    return missing


def fetch_three():
    out = VENDOR / "three"
    out.mkdir(parents=True, exist_ok=True)
    print(f"fetching {THREE_URL}")
    package = tarfile.open(fileobj=io.BytesIO(download(THREE_URL)), mode="r:gz")
    lines = []
    for name, (member, expected) in THREE_FILES.items():
        data = package_member(package, member)
        actual = sha256(data)
        if actual != expected:
            raise SystemExit(f"checksum mismatch for three.js {name}: expected {expected}, got {actual}")
        local = rewrite_three(name, data)
        (out / name).write_bytes(local)
        lines.append(f"{name} {expected} {sha256(local)}")
        print(f"  {name}  {len(local):,} B  sha256 ok")
    (out / THREE_STAMP).write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "NOTICE.txt").write_text(THREE_NOTICE, encoding="utf-8")
    total = sum((out / name).stat().st_size for name in THREE_FILES)
    print(f"3D viewer runtime ready: {total / 1e6:.1f} MB in {out.relative_to(ROOT)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify only, download nothing")
    args = parser.parse_args()

    vision = vision_missing()
    three = three_missing()
    if args.check:
        for name in FILES:
            print(f"  {'ok     ' if name not in vision else 'MISSING'} mediapipe/{name}")
        for name in THREE_FILES:
            print(f"  {'ok     ' if name not in three else 'MISSING'} three/{name}")
        return 1 if vision or three else 0

    if vision:
        fetch_vision(vision)
    else:
        print(f"vision runtime already present and verified in {(VENDOR / 'mediapipe').relative_to(ROOT)}")
    if three:
        fetch_three()
    else:
        print(f"3D viewer runtime already present and verified in {(VENDOR / 'three').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
