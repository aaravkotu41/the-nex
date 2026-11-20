#!/bin/bash
# Installer postinstall (runs as root after TheNex.app is copied to /Applications): installs the
# model, LaunchDaemon and notifier via install_mac.sh, then, for an interactive install, opens
# the Full Disk Access pane and the app for the signed-in user.
set -euo pipefail

APP="/Applications/TheNex.app"
xattr -dr com.apple.quarantine "${APP}" 2>/dev/null || true
"${APP}/Contents/Resources/install_mac.sh"

CONSOLE_UID="$(stat -f %u /dev/console)"
if [[ "${CONSOLE_UID}" != "0" && "${COMMAND_LINE_INSTALL:-0}" != "1" ]]; then
  launchctl asuser "${CONSOLE_UID}" /usr/bin/open \
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" || true
  launchctl asuser "${CONSOLE_UID}" /usr/bin/open "${APP}" || true
fi
exit 0
