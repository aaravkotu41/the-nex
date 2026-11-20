#!/bin/bash
# Installer preinstall (runs as root): stop a previous The Nex so its binaries can be replaced.
launchctl bootout system/com.thenex.edr 2>/dev/null || true
CONSOLE_UID="$(stat -f %u /dev/console)"
if [[ "${CONSOLE_UID}" != "0" ]]; then
  launchctl bootout "gui/${CONSOLE_UID}/com.thenex.edr.notifier" 2>/dev/null || true
fi
pkill -x the-nex-gui 2>/dev/null || true
pkill -x the-nex 2>/dev/null || true
exit 0
