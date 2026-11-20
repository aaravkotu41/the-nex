#!/bin/bash
# Builds target/macos/TheNex.pkg: a one-click installer that puts TheNex.app in /Applications
# and runs install_mac.sh (model, LaunchDaemon, notifier). Run build_dmg.sh first; it assembles
# and signs target/macos/TheNex.app.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "build_pkg.sh must run on macOS" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGING="${ROOT}/packaging/macos"
OUT="${ROOT}/target/macos"
APP="${OUT}/TheNex.app"
PKG_ROOT="${OUT}/pkg-root"
PKG_SCRIPTS="${OUT}/pkg-scripts"
COMPONENT_PLIST="${OUT}/pkg-component.plist"
COMPONENT_PKG="${OUT}/TheNex-component.pkg"
PKG="${OUT}/TheNex.pkg"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT}/Cargo.toml" | head -n 1)"

if [[ ! -d "${APP}" ]]; then
  echo "${APP} not found; run packaging/macos/build_dmg.sh first" >&2
  exit 1
fi

echo "==> Staging ${APP} for /Applications"
rm -rf "${PKG_ROOT}" "${PKG_SCRIPTS}" "${COMPONENT_PLIST}" "${COMPONENT_PKG}" "${PKG}"
mkdir -p "${PKG_ROOT}/Applications" "${PKG_SCRIPTS}"
cp -R "${APP}" "${PKG_ROOT}/Applications/"
cp "${PACKAGING}/pkg-preinstall.sh" "${PKG_SCRIPTS}/preinstall"
cp "${PACKAGING}/pkg-postinstall.sh" "${PKG_SCRIPTS}/postinstall"
chmod 755 "${PKG_SCRIPTS}/preinstall" "${PKG_SCRIPTS}/postinstall"

# Without this, Installer "relocates" the app to any other copy of TheNex.app it finds
# (for example one still in Downloads) instead of installing to /Applications.
pkgbuild --analyze --root "${PKG_ROOT}" "${COMPONENT_PLIST}"
plutil -replace 0.BundleIsRelocatable -bool NO "${COMPONENT_PLIST}"

echo "==> pkgbuild (version ${VERSION})"
pkgbuild \
  --root "${PKG_ROOT}" \
  --component-plist "${COMPONENT_PLIST}" \
  --scripts "${PKG_SCRIPTS}" \
  --identifier com.thenex.pkg \
  --version "${VERSION}" \
  --install-location / \
  "${COMPONENT_PKG}"

echo "==> productbuild"
productbuild --package "${COMPONENT_PKG}" "${PKG}"
rm -rf "${PKG_ROOT}" "${PKG_SCRIPTS}" "${COMPONENT_PLIST}" "${COMPONENT_PKG}"
echo "Built ${PKG}"
