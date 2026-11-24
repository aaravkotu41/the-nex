#!/bin/bash
# Installs The Nex from TheNex.app: model into /Library/Application Support/TheNex, then the
# LaunchDaemon and per-user notifier LaunchAgent via `the-nex --install`.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo: sudo \"$0\"" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTENTS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="$(cd "${CONTENTS_DIR}/.." && pwd)"
BIN="${CONTENTS_DIR}/MacOS/the-nex"
MODEL="${SCRIPT_DIR}/thenex_model.onnx"
DATA_DIR="/Library/Application Support/TheNex"

if [[ ! -x "${BIN}" ]]; then
  echo "the-nex binary not found at ${BIN}" >&2
  exit 1
fi

case "${APP_DIR}" in
  /Volumes/*)
    echo "Drag TheNex.app to /Applications first, then run:" >&2
    echo "  sudo /Applications/TheNex.app/Contents/Resources/install_mac.sh" >&2
    exit 1
    ;;
esac

# The daemon runs as root: the app it runs from must not be writable by anyone else.
chown -R root:wheel "${APP_DIR}"
chmod -R go-w "${APP_DIR}"

if xattr -p com.apple.quarantine "${BIN}" >/dev/null 2>&1; then
  echo "warning: ${APP_DIR} carries the Gatekeeper quarantine flag (downloaded, ad-hoc signed)." >&2
  echo "         launchd may refuse to start it. Approve it in System Settings > Privacy & Security," >&2
  echo "         or clear the flag with: sudo xattr -dr com.apple.quarantine \"${APP_DIR}\"" >&2
fi

install -d -m 755 -o root -g wheel "${DATA_DIR}"
if [[ -f "${MODEL}" ]]; then
  install -m 644 -o root -g wheel "${MODEL}" "${DATA_DIR}/thenex_model.onnx"
else
  echo "warning: ${MODEL} is missing; the daemon will fall back to heuristic scoring" >&2
fi

"${BIN}" --install

echo
launchctl print system/com.thenex.edr 2>/dev/null \
  | grep -E '^[[:space:]]*(state|pid|program) =' \
  || echo "daemon status unavailable; inspect with: launchctl print system/com.thenex.edr"
echo
echo "Next: System Settings > Privacy & Security > Full Disk Access > add ${APP_DIR}"
echo "      (required to watch Desktop, Documents and Downloads)."
echo "Events: ${DATA_DIR}/logs/events.jsonl"
