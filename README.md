# The Nex

The Nex is free protection software for Windows and macOS. It runs quietly in the background, watches for bad programs, and tells you when it finds something. It is written in Rust, and the smart parts run on your own computer, not in the cloud.

**Install it:** see [INSTALL.md](INSTALL.md). On Windows you run `TheNexSetup.exe`, on Mac you open `TheNex.pkg`. Both are on the [releases page](https://github.com/eeshanambati/the-nex/releases).

## What it does

| Protection | What it does for you |
|---|---|
| **Known threats check** | Compares files with a list of programs already known to be malware. A match is certain, not a guess. |
| **New program check (AI)** | A small AI on your device looks at new programs and flags ones that look like malware. It can be wrong, so it only stops a program when it is very sure. |
| **Compressed file check** | Looks inside zip files before they open, to stop ones built to crash your computer or fill your disk. |
| **Sneaky command guard** | Stops attackers from using your computer's own tools (like PowerShell) to download and run harmful things. |
| **Ransomware tripwire** | Hides decoy files. If something starts changing them, it is probably ransomware, and The Nex reacts. |

You can also scan Downloads and Desktop (Quick Scan) or the whole computer (Full Scan), drop a single file on the window to check it, see what starts with your computer, and move anything suspicious into quarantine, where you can restore it if it was a mistake.

**Look-only mode (dry run)** makes The Nex tell you what it finds without ever stopping, moving or deleting anything. Use it if you want to see how it behaves first.

## What it cannot do (the honest part)

The Nex is an early project. It is **not** a replacement for Windows Defender or a full antivirus yet, and it is best used as an extra layer.

- **The known-threats list is not included yet.** The check is built and tested, but no real list ships with the app, so right now it catches nothing until one is added.
- **It cannot update itself.** The background service has no internet access on purpose, so protection only changes when you install a new version.
- **The AI is not perfect.** On a public set of real Windows malware it caught roughly two out of three, and it flags a small share of clean programs by mistake. Details are in the [technical reference](docs/TECHNICAL.md).
- **It does not watch the internet.** It has no web, phishing or network protection, and does not react when you plug in a USB drive.
- **It does not look inside Office files, PDFs or script files** beyond comparing them with the (currently empty) list.
- **No Linux support.** Windows support was only compiled in testing, not run on a real PC by the author.
- **You cannot yet tell it to ignore a folder.** The only exception is "Always allow" for one exact file.

## Privacy in one paragraph

Detecting threats happens on your device. You can sign in to see your devices in one place; if you do, a small summary (device name, platform, counts, on/off flags, no file paths) is sent to the sign-in service, which can see your IP address and when you were active. There are no ads and no analytics. The full list of what is stored and sent is on the Privacy page in the app (Settings, then Privacy).

## For developers

- Everything technical (how each check works, measurements, limits, scan behavior, account sync) is in [docs/TECHNICAL.md](docs/TECHNICAL.md).
- Layout: `crates/the-nex-core` (checks, quarantine, OS layer), `crates/the-nex-daemon` (background service and command line), `crates/the-nex-gui` (desktop app, its pages are plain HTML, CSS and JavaScript in `ui/`), `crates/aegismesh-*` (a separate wearable-SOS simulation), `packaging/` (installers), `scripts/` (tests and tools).
- Run the interface tests: `for t in scripts/test_*.js; do node $t; done`. Run the engine tests: `cargo test` (needs Windows or macOS).
- CI builds, tests and installs on Windows and macOS; pushing a `v*` tag publishes a release.
