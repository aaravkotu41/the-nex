# Installing The Nex

The Nex is a local endpoint protection app for Windows and macOS: it stops zip bombs before
extraction, scores new programs with a small on-device AI model, kills malicious
PowerShell/shell one-liners, and catches ransomware with decoy "canary" files. Detection runs
entirely on the device. While you are signed in, the dashboard talks to Supabase (sign-in, a small
device-status summary every 60 s and a command check every 15 s, which reveals your IP address and
activity times to Supabase); a pasted wallpaper URL contacts that page's host and then the image host it points to, following redirects. Device rows and command history stay on Supabase after sign-out or uninstall until removed from the Devices page; in-app account deletion isn't available yet. See
Settings → Privacy in the app for the full list.

## Windows 10 / 11 (64-bit)

1. Download **TheNexSetup.exe** from the latest release
   (repository page → **Releases** on the right).
2. Double-click it and choose **Yes** on the administrator prompt.
3. That's it. The installer copies The Nex to `C:\ProgramData\TheNex`, starts the background
   service, puts the gyroscope icon in the system tray, and adds **The Nex** to the Start menu and
   desktop.

**"Windows protected your PC"?** The installer is not code-signed yet. Click **More info →
Run anyway**. If **Smart App Control** is turned on, Windows blocks unsigned programs
completely and The Nex cannot be installed on that PC until the builds are signed.

**Uninstall:** Settings → Apps → Installed apps → **The Nex** → Uninstall (or Start menu →
The Nex → Uninstall The Nex). Logs and quarantined files stay in `C:\ProgramData\TheNex`;
delete that folder too if you want them gone.

## macOS (Apple Silicon)

1. Download **TheNex.pkg** from the latest release.
2. Double-click it. macOS will say it is from an unidentified developer (the package is not
   notarized yet): open **System Settings → Privacy & Security**, click **Open Anyway** next to
   TheNex.pkg, then confirm.
3. Click through the installer and enter your Mac password when asked. It installs
   **TheNex.app** in Applications and starts the background daemon.
4. When System Settings opens **Full Disk Access**, click **+**, press **Cmd-Shift-G**, paste
   `/Library/Application Support/TheNex/engine/the-nex` and switch it on. The background daemon
   runs from that root-only copy, not from the app. Without this macOS hides Desktop,
   Documents and Downloads from it.

**Uninstall:** in Terminal run

    sudo /Applications/TheNex.app/Contents/Resources/uninstall_mac.sh --purge

then drag TheNex.app to the Trash.

## Before you rely on it

- The Nex acts on what it detects: it moves files into quarantine and stops malicious
  script commands. It stops a newly started program only when the AI is at least 90% sure;
  for anything less, or for programs already running when it starts, it alerts you instead.
  To watch what it *would* do first, open The Nex → **Settings** and switch on **Dry run**.
- The **AegisMesh** page is a simulation: it never contacts anyone. Its camera watch asks for
  camera access the first time; video stays on your device.
- Quarantined files can be restored from the **Quarantine** page.
- Your wallpaper and theme are under **Settings → Appearance & Wallpaper**.

## Sign-in setup (Supabase)

The dashboard needs a Supabase project before anyone can sign in. Put its project URL and its
**publishable** key (`sb_publishable_…`, or the legacy anon key) into `ui/supabase-config.js`.
Never put the service_role or secret key there. While either value is empty, the login screen
says sign-in is not set up and the dashboard stays locked.
