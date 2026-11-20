# The Nex

Local endpoint protection for Windows and macOS, written in Rust: zip-bomb inspection before
extraction, an on-device ONNX model for new executables, living-off-the-land process guard,
and ransomware canary files, with a Tauri desktop dashboard.

**To install it, see [INSTALL.md](INSTALL.md)**: one-click `TheNexSetup.exe` on Windows and
`TheNex.pkg` on macOS, attached to each [release](../../releases).

## Repository layout

- `crates/the-nex-core`: detection engines, quarantine, platform layer
- `crates/the-nex-daemon`: the `the-nex` service / CLI (`--help` lists every mode)
- `crates/the-nex-gui`: Tauri v2 desktop app; its frontend is the plain HTML/CSS/JS in `ui/`
- `packaging/windows/installer.nsi`: Windows installer; `packaging/macos/`: app bundle, DMG and pkg
- `scripts/`: icon and model generation, live verifier, developer install scripts

CI (`.github/workflows/ci.yml`) builds, tests and live-verifies both platforms, builds both
installers, and installs and uninstalls each one on the runner. Pushing a `v*` tag publishes a
release with the installers attached.
