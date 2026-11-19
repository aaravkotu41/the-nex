#!/bin/bash
# Removes The Nex's LaunchDaemon, notifier LaunchAgent and canaries.
# --purge also deletes /Library/Application Support/TheNex (logs, model, quarantined files).
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo: sudo \"$0\" [--purge]" >&2
  exit 1
fi

PURGE=0
case "${1:-}" in
  --purge) PURGE=1 ;;
  "") ;;
  *)
    echo "usage: sudo $0 [--purge]" >&2
    exit 2
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="/Library/Application Support/TheNex"
DAEMON_PLIST="/Library/LaunchDaemons/com.thenex.edr.plist"
AGENT_PLIST="/Library/LaunchAgents/com.thenex.edr.notifier.plist"

BIN=""
for candidate in "${SCRIPT_DIR}/../MacOS/the-nex" "/Applications/TheNex.app/Contents/MacOS/the-nex"; do
  if [[ -x "${candidate}" ]]; then
    BIN="${candidate}"
    break
  fi
done

if [[ -n "${BIN}" ]]; then
  "${BIN}" --uninstall || echo "warning: the-nex --uninstall failed; cleaning up directly" >&2
fi

CONSOLE_UID="$(stat -f %u /dev/console)"
if [[ "${CONSOLE_UID}" != "0" ]]; then
  launchctl bootout "gui/${CONSOLE_UID}/com.thenex.edr.notifier" 2>/dev/null || true
fi
launchctl bootout system/com.thenex.edr 2>/dev/null || true
rm -f "${DAEMON_PLIST}" "${AGENT_PLIST}"
pkill -x the-nex 2>/dev/null || true

for dir in /Users/*/Desktop /Users/*/Documents; do
  rm -f "${dir}/.thenex_canary_01.docx" "${dir}/.thenex_canary_02.xlsx" 2>/dev/null || true
done

if [[ ${PURGE} -eq 1 ]]; then
  rm -rf "${DATA_DIR}"
  echo "Deleted ${DATA_DIR}"
else
  echo "Kept ${DATA_DIR} (quarantine, logs, model). Re-run with --purge to delete it."
fi
echo "The Nex has been uninstalled. Delete TheNex.app from /Applications to finish."
