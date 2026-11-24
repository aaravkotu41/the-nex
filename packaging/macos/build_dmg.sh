#!/bin/bash
# Builds target/macos/TheNex.app (desktop app + daemon, ad-hoc signed) and the drag-to-Applications TheNex.dmg.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "build_dmg.sh must run on macOS" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGING="${ROOT}/packaging/macos"
OUT="${ROOT}/target/macos"
APP="${OUT}/TheNex.app"
STAGE="${OUT}/dmg"
DMG="${OUT}/TheNex.dmg"
MODEL="${ROOT}/thenex_model.onnx"
ICONS="${ROOT}/crates/the-nex-gui/icons"

cd "${ROOT}"
mkdir -p "${OUT}"

if [[ ! -f "${ICONS}/icon.icns" ]]; then
  echo "==> Generating icons"
  python3 scripts/gen_icons.py
fi

if [[ ! -f "${MODEL}" ]]; then
  echo "==> Training ${MODEL}"
  VENV="${OUT}/venv"
  python3 -m venv "${VENV}"
  "${VENV}/bin/python" -m pip install --quiet --disable-pip-version-check numpy onnx
  "${VENV}/bin/python" scripts/train_onnx.py --out "${MODEL}"
fi

echo "==> cargo build --release --workspace"
cargo build --release --locked --workspace

echo "==> Assembling ${APP}"
rm -rf "${APP}" "${STAGE}" "${DMG}"
mkdir -p "${APP}/Contents/MacOS" "${APP}/Contents/Resources"
cp "${PACKAGING}/Info.plist" "${APP}/Contents/Info.plist"
cp "${ROOT}/target/release/the-nex-gui" "${APP}/Contents/MacOS/the-nex-gui"
cp "${ROOT}/target/release/the-nex" "${APP}/Contents/MacOS/the-nex"
cp "${MODEL}" "${APP}/Contents/Resources/thenex_model.onnx"
# Known-malware list: shipped only when one was built and pinned into this build
# (scripts/fetch_hash_list.py --pin); the service refuses any other list.
if [[ -f "${ROOT}/known_bad.bin" ]] && ! grep -qi '^none' "${ROOT}/crates/the-nex-core/known_bad.sha256"; then
  cp "${ROOT}/known_bad.bin" "${APP}/Contents/Resources/known_bad.bin"
  chmod 644 "${APP}/Contents/Resources/known_bad.bin"
fi
cp "${ICONS}/icon.icns" "${APP}/Contents/Resources/icon.icns"
cp "${PACKAGING}/install_mac.sh" "${PACKAGING}/uninstall_mac.sh" "${APP}/Contents/Resources/"
chmod 755 "${APP}/Contents/MacOS/the-nex-gui" \
  "${APP}/Contents/MacOS/the-nex" \
  "${APP}/Contents/Resources/install_mac.sh" \
  "${APP}/Contents/Resources/uninstall_mac.sh"
chmod 644 "${APP}/Contents/Info.plist" \
  "${APP}/Contents/Resources/thenex_model.onnx" \
  "${APP}/Contents/Resources/icon.icns"

echo "==> Ad-hoc signing"
codesign --force --deep --sign - "${APP}"
codesign --verify --deep --strict "${APP}"

echo "==> Building ${DMG}"
mkdir -p "${STAGE}"
cp -R "${APP}" "${STAGE}/"
ln -s /Applications "${STAGE}/Applications"
hdiutil create -volname "The Nex" -srcfolder "${STAGE}" -ov -format UDZO "${DMG}"
rm -rf "${STAGE}"
echo "Built ${DMG}"
