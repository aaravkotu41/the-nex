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

## Binary AI

New executables in watched folders (and the images of new processes) that are not validly
signed get a malware score from a small neural network running on the device (ONNX via tract;
no cloud). Every detection says why, for example:

```
score=0.972 threshold=0.65 engine=onnx; packed or encrypted code (entropy 7.95/8);
packer section names: upx0, upx1; 2 writable+executable sections; very few imports (6);
risky APIs: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread; not digitally signed
```

**What it looks at** (14 features, `crates/the-nex-core/src/bin_ai.rs`): size, section
entropy (overall and at the entry point), writable+executable sections, entry-point
anomalies, import count, risky APIs (injection, keylogging, downloading, credential dumping),
signature presence, appended data, packer section names, resources, .NET and Mach-O.

**How it is trained** (`scripts/train_onnx.py`, runs in CI):
- benign: `data/benign_pe_features.csv`, features of 14,515 real Windows programs (system
  files, .NET assemblies, installed apps, unsigned developer tools) from
  `scripts/build_dataset.py`, plus synthetic installers and macOS programs;
- malicious: synthetic profiles of documented malware traits (packed, crypted, injectors and
  stealers, droppers, obfuscated .NET, Mac stealers). No malware is downloaded or stored;
- signature dropout, because validly signed files are trusted and never reach the model;
- calibrated so that at most 0.5% of held-out real programs reach the quarantine threshold.

**Measured** (before → after this model): on 1,927 real user-installed apps it never saw,
false positives fell from 3.27% to 0.62%; on fresh samples of the seven malware-trait
families, detection rose from 36% to 91%. The malware figures come from synthetic profiles, so
treat them as a regression benchmark, not a real-world detection rate. Mac programs are the
weakest spot (no real Mac training data yet): CI checks the model against the runner's own
macOS programs on every push.

**See a verdict yourself** (read-only, changes nothing):

```
the-nex --scan-file C:\path\to\program.exe     # or a folder, or @list.txt
```

**Train/serve parity:** `scripts/thenex_features.py` computes the training features in Python;
CI runs `scripts/check_feature_parity.py`, which fails if the Rust engine computes anything
different on real System32 files, if the model flags more than 2% (Windows) or 5% (macOS) of
the runner's own programs, or if our own binaries and installer are not scored clean.
