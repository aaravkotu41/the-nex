#!/usr/bin/env python3
"""Train The Nex binary classifier (v3) and export it as a tract-compatible ONNX graph.

Data
  benign    data/benign_pe_features.csv: ~21k REAL Windows programs and libraries (system
            files, .NET assemblies, machine-wide and per-user applications, unsigned developer
            tools), made by scripts/build_dataset.py. Plus synthetic profiles of what a folder
            scan of a clean machine cannot contain: installers (large appended payloads),
            protector-wrapped commercial software and macOS Mach-O programs.
  malicious synthetic profiles of well-documented malware traits: packed, crypted, process
            injectors / stealers / keyloggers, droppers, obfuscated .NET and Mach-O stealers.
            No malware is downloaded or stored.

Features come from scripts/thenex_features.py, which mirrors crates/the-nex-core/src/bin_ai.rs.

Unseen applications: every real program carries the (anonymous) number of its application.
Whole applications are held out for the final test, so the false-positive rate printed here is
for software the model has never seen, not for more files of programs it trained on.

Signature blindness: a file with a VALID signature is trusted by the platform check and never
scored, so the only signature blocks the model meets in production are ones that failed that
check (or, on macOS, free ad-hoc signatures), and an attacker can staple one onto anything.
The network therefore has no connection to the has_signature input at all: those first-layer
weights are fixed at zero. The model has to judge the code; a signature block changes nothing.

Look-alikes: a quarter of the synthetic .NET malware is unobfuscated, and so has exactly the
shape of an ordinary .NET program. Training on those does not teach the model to find them; it
teaches it to flag clean .NET applications that happen to sit at the edge of normal (measured:
half of the false positives on unseen applications were ordinary .NET files of one program).
They are left out of training (--dotnet-lookalike 0) and kept in the held-out test, where
the .NET detection figure therefore tops out near 75%: what these features can honestly see.

Evasion training: an attacker can also grow a file for free, by appending junk after the image
or importing extra harmless functions. A share of the PE malware profiles is trained in those
padded forms, and the held-out test reports detection for each disguise and all three at once.

Ensemble: --members small networks are trained together, each on its own random batches and
each without one fold of the real programs. Their logits are averaged; the export folds them
into ONE Gemm -> Relu -> Gemm -> Relu -> Gemm -> Sigmoid graph (block-diagonal weights), so the
runtime sees the same kind of model as before.

Calibration: every real training program is scored by the member that never saw its
application. The output bias is lowered (if needed) until at most --target-fpr of them reach
the quarantine threshold. Training fails when held-out
detection drops below --min-tpr, or below --min-evasive-tpr with all three disguises applied.

Graph: opset 13, default domain only (no ai.onnx.ml); input "features" [N, 14] float32, output
"probability" [N, 1] float32.
"""

import argparse
import csv
import sys
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

sys.path.insert(0, str(Path(__file__).resolve().parent))
import thenex_features as tf  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "thenex_model.onnx"
DEFAULT_DATA = ROOT / "data" / "benign_pe_features.csv"
N_FEATURES = tf.N_FEATURES
OPSET = 13
IR_VERSION = 7
ALLOWED_OPS = {"Gemm", "Relu", "Sigmoid"}
HIDDEN = (32, 16)
THRESHOLD = 0.65  # config::AI_MALWARE_THRESHOLD
KILL_CONFIDENCE = 0.9  # process_guard::PROCESS_KILL_CONFIDENCE
SIGNED = tf.FEATURE_NAMES.index("has_signature")
IS_DOTNET = tf.FEATURE_NAMES.index("is_dotnet")

INJECTION = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
             "QueueUserAPC", "NtWriteVirtualMemory", "SetThreadContext"]
SPYING = ["SetWindowsHookEx", "GetAsyncKeyState", "MiniDumpWriteDump"]
NETWORK = ["URLDownloadToFile", "InternetOpenUrl"]
EXECUTION = ["WinExec", "ShellExecute"]
CRYPTO = ["CryptEncrypt"]
CRT = ["IsDebuggerPresent"]
PACKERS = [["upx0", "upx1"], [".mpress1", ".mpress2"], [".aspack", ".adata"], [".petite"],
           [".nsp0", ".nsp1"], ["upx0", "upx1", "upx2"]]
PROTECTORS = [[".themida"], [".vmp0", ".vmp1"], [".enigma1", ".enigma2"], [".winlice"]]
# Legitimate Mac software uses these a lot: plugin loaders dlopen, JIT runtimes (browsers,
# Electron, Java) mprotect, launchers execve/NSTask, scripts system/popen, and some commercial
# apps ptrace(PT_DENY_ATTACH). Symbol hits alone must not convict a Mach-O program.
MACHO_BENIGN_SYMBOL_RATES = {"dlopen": 0.55, "system": 0.12, "execve": 0.15, "popen": 0.10,
                             "mprotect": 0.25, "ptrace": 0.02, "NSTask": 0.12}


# ---------------------------------------------------------------- synthetic profiles

class Synth:
    def __init__(self, rng):
        self.rng = rng

    def u(self, lo, hi):
        return float(self.rng.uniform(lo, hi))

    def logu(self, lo, hi):
        return float(10.0 ** self.rng.uniform(np.log10(lo), np.log10(hi)))

    def chance(self, p):
        return bool(self.rng.random() < p)

    def int(self, lo, hi):
        """Inclusive."""
        return int(self.rng.integers(lo, hi + 1))

    def pick(self, pool, k):
        k = max(0, min(int(k), len(pool)))
        return [str(x) for x in self.rng.choice(pool, size=k, replace=False)] if k else []

    def weighted(self, values, p):
        return values[int(self.rng.choice(len(values), p=p))]

    # ---- malicious PE

    def packed(self):
        size = self.logu(25e3, 4e6)
        max_e = self.u(7.55, 7.995)
        return tf.profile(
            size_bytes=size, max_section_entropy=max_e, entry_section_entropy=max_e - self.u(0.0, 0.3),
            section_count=self.int(2, 4), wx_sections=self.int(1, 2), entry_anomaly=self.chance(0.4),
            import_count=self.int(3, 30),
            suspicious_imports=self.pick(INJECTION + EXECUTION + NETWORK + CRT, self.weighted([0, 0, 1, 2], None)),
            signed=self.chance(0.04), packer_sections=PACKERS[self.int(0, len(PACKERS) - 1)],
            overlay_bytes=size * self.u(0.05, 0.5) if self.chance(0.1) else 0,
            resource_bytes=size * self.u(0.0, 0.15),
        )

    def crypted(self):
        size = self.logu(20e3, 5e6)
        sections = self.int(3, 8)
        if self.chance(0.5):  # encrypted code with a small decryption stub
            entry_e = self.u(7.0, 7.95)
            max_e = max(entry_e, self.u(6.5, 7.99))
        else:  # normal-looking loader carrying an encrypted payload section
            entry_e = self.u(5.6, 6.8)
            max_e = self.u(7.3, 7.99)
        return tf.profile(
            size_bytes=size, max_section_entropy=max_e, entry_section_entropy=entry_e,
            section_count=sections, wx_sections=0 if self.chance(0.4) else self.int(1, 2),
            entry_anomaly=self.chance(0.45), import_count=int(self.logu(2, 80)),
            suspicious_imports=self.pick(INJECTION + EXECUTION + CRT,
                                         self.weighted([0, 1, 2, 3, 4], [0.25, 0.25, 0.2, 0.15, 0.15])),
            signed=self.chance(0.06),
            overlay_bytes=size * self.u(0.05, 0.6) if self.chance(0.2) else 0,
            resource_bytes=size * self.u(0.0, 0.2),
        )

    def injector(self):
        """Unpacked RATs, stealers, keyloggers and process injectors: the APIs give them away."""
        size = self.logu(15e3, 3e6)
        entry_e = self.u(5.7, 6.9)
        return tf.profile(
            size_bytes=size, max_section_entropy=max(entry_e, self.u(5.9, 7.4)),
            entry_section_entropy=entry_e, section_count=self.int(4, 8),
            wx_sections=1 if self.chance(0.1) else 0, entry_anomaly=self.chance(0.05),
            import_count=int(self.logu(30, 450)),
            suspicious_imports=self.pick(INJECTION + SPYING + NETWORK + EXECUTION + CRYPTO + CRT,
                                         self.weighted([3, 4, 5, 6, 7, 8], [0.25, 0.25, 0.2, 0.15, 0.1, 0.05])),
            signed=self.chance(0.08), resource_bytes=size * self.u(0.0, 0.15),
        )

    def dropper(self):
        size = self.logu(40e3, 8e6)
        entry_e = self.u(5.8, 6.8)
        if self.chance(0.55):  # payload appended after the image
            overlay, resource, max_e = size * self.u(0.3, 0.95), size * self.u(0.0, 0.05), self.u(6.0, 7.3)
        else:  # payload hidden in the resource section
            overlay, resource, max_e = 0, size * self.u(0.3, 0.95), self.u(7.5, 7.99)
        susp = self.pick(NETWORK + EXECUTION + CRYPTO + CRT, self.int(1, 4))
        if self.chance(0.3):
            susp += self.pick(INJECTION, self.int(1, 2))
        return tf.profile(
            size_bytes=size, max_section_entropy=max(entry_e, max_e), entry_section_entropy=entry_e,
            section_count=self.int(4, 6), wx_sections=1 if self.chance(0.05) else 0,
            entry_anomaly=self.chance(0.1), import_count=int(self.logu(8, 200)),
            suspicious_imports=susp, signed=self.chance(0.08), overlay_bytes=overlay,
            resource_bytes=resource,
        )

    def dotnet(self, lookalike=0.25):
        """.NET stealers/RATs: one import by design; obfuscators and packed payloads raise entropy.
        `lookalike`: the share left unobfuscated, which these features cannot tell from an
        ordinary .NET program."""
        size = self.logu(20e3, 4e6)
        entry_e = self.u(5.2, 6.4) if self.chance(lookalike) else self.u(7.0, 7.9)
        return tf.profile(
            size_bytes=size, max_section_entropy=max(entry_e, self.u(4.0, 6.5)), entry_section_entropy=entry_e,
            section_count=self.weighted([2, 3], [0.3, 0.7]), import_count=1, dotnet=True,
            signed=self.chance(0.05), resource_bytes=size * self.u(0.0, 0.25),
            overlay_bytes=size * self.u(0.1, 0.6) if self.chance(0.1) else 0,
        )

    # ---- malicious Mach-O

    def macho_packed(self):
        return tf.profile(
            format="macho", size_bytes=self.logu(50e3, 8e6), max_section_entropy=self.u(7.5, 7.99),
            entry_section_entropy=self.u(6.0, 7.99), section_count=self.int(3, 5),
            wx_sections=1 if self.chance(0.7) else 0, import_count=self.int(0, 15),
            suspicious_imports=self.pick(tf.SUSPICIOUS_MACHO_SYMBOLS, self.int(0, 2)),
            signed=self.chance(0.6), packer_sections=["upx_data"],
        )

    def macho_stealer(self):
        text_e = self.u(5.7, 7.0)
        return tf.profile(
            format="macho", size_bytes=self.logu(80e3, 20e6), max_section_entropy=max(text_e, self.u(5.9, 7.5)),
            entry_section_entropy=text_e, section_count=self.int(4, 6),
            wx_sections=1 if self.chance(0.05) else 0, import_count=int(self.logu(20, 500)),
            suspicious_imports=self.pick(tf.SUSPICIOUS_MACHO_SYMBOLS,
                                         self.weighted([2, 3, 4, 5, 6], [0.2, 0.3, 0.25, 0.15, 0.1])),
            signed=self.chance(0.85),
        )

    # ---- benign that a folder scan cannot provide

    def installer(self):
        """NSIS / Inno Setup / 7-Zip SFX: a normal stub plus a large compressed payload appended."""
        stub = self.logu(100e3, 600e3)
        payload = self.logu(200e3, 100e6)
        entry_e = self.u(6.0, 6.7)
        susp = []
        if self.chance(0.7):
            susp.append("ShellExecute")
        if self.chance(0.4):
            susp.append("IsDebuggerPresent")
        if self.chance(0.05):
            susp.append("InternetOpenUrl")
        if self.chance(0.03):
            susp.append("URLDownloadToFile")
        return tf.profile(
            size_bytes=stub + payload, max_section_entropy=max(entry_e, self.u(6.2, 7.4)),
            entry_section_entropy=entry_e, section_count=self.int(4, 6),
            import_count=self.int(80, 350), suspicious_imports=susp, signed=self.chance(0.3),
            overlay_bytes=payload, resource_bytes=stub * self.u(0.02, 0.3),
        )

    def protected_app(self):
        """Signed commercial software wrapped by Themida / VMProtect / Enigma (games, licensed tools)."""
        return tf.profile(
            size_bytes=self.logu(2e6, 80e6), max_section_entropy=self.u(7.6, 7.99),
            entry_section_entropy=self.u(6.8, 7.95), section_count=self.int(6, 10),
            wx_sections=self.int(0, 2), entry_anomaly=self.chance(0.5), import_count=int(self.logu(20, 400)),
            suspicious_imports=self.pick(tf.SUSPICIOUS_IMPORTS, self.int(0, 3)), signed=True,
            packer_sections=PROTECTORS[self.int(0, len(PROTECTORS) - 1)],
        )

    def macho_benign(self):
        text_e = self.u(5.5, 6.7)
        return tf.profile(
            format="macho", size_bytes=self.logu(16e3, 80e6), max_section_entropy=max(text_e, self.u(5.0, 7.2)),
            entry_section_entropy=text_e, section_count=self.weighted([4, 5, 6, 7], [0.2, 0.5, 0.2, 0.1]),
            wx_sections=1 if self.chance(0.003) else 0, import_count=int(self.logu(5, 3000)),
            suspicious_imports=[s for s, rate in MACHO_BENIGN_SYMBOL_RATES.items() if self.chance(rate)],
            signed=self.chance(0.97),
        )

    def macho_runtime(self):
        """Interpreters, VMs, browsers, Electron and .NET hosts (python, node, java, dotnet, the
        CI runner): plugin loading, JITs, child processes and debuggers mean they import most of
        the 'risky' Mach-O symbols. CI showed the model must not treat that as malware."""
        rates = {"dlopen": 0.95, "mprotect": 0.8, "execve": 0.6, "system": 0.5, "popen": 0.5,
                 "ptrace": 0.3, "NSTask": 0.25}
        text_e = self.u(5.6, 6.8)
        return tf.profile(
            format="macho", size_bytes=self.logu(200e3, 100e6), max_section_entropy=max(text_e, self.u(5.5, 7.4)),
            entry_section_entropy=text_e, section_count=self.weighted([4, 5, 6, 7, 8], [0.1, 0.3, 0.3, 0.2, 0.1]),
            wx_sections=1 if self.chance(0.03) else 0, import_count=int(self.logu(150, 5000)),
            suspicious_imports=[s for s, rate in rates.items() if self.chance(rate)],
            signed=self.chance(0.9),
        )


MALICIOUS_FAMILIES = {  # name -> share of the malicious class
    "packed": 0.19, "crypted": 0.18, "injector": 0.23, "dropper": 0.13, "dotnet": 0.11,
    "macho_packed": 0.05, "macho_stealer": 0.11,
}
# Detection is gated on these; Mac stealers whose only evidence is imported symbols look like
# legitimate runtimes, so they are reported but not gated.
GATED_FAMILIES = ["packed", "crypted", "injector", "dropper", "dotnet", "macho_packed"]
SYNTHETIC_BENIGN = {"installer": 2500, "protected_app": 300, "macho_benign": 6000, "macho_runtime": 3000}
# How much one training row of a synthetic benign family counts. Padded malware looks more like
# an installer than plain malware does, so installers count double to keep them cleared.
BENIGN_WEIGHT = {"installer": 2.0}


def features_of(profiles):
    return np.array([tf.features(p) for p in profiles], dtype=np.float32)


def synth_rows(synth, family, n):
    make = getattr(synth, family)
    return features_of([make() for _ in range(n)])


# ---------------------------------------------------------------- disguises an attacker gets for free

def pad_overlay(p, synth):
    """Junk appended after the image: the file grows, nothing inside it changes."""
    q = dict(p)
    pad = p["size_bytes"] * synth.logu(0.3, 20.0)
    q["size_bytes"] = p["size_bytes"] + pad
    q["overlay_bytes"] = p["overlay_bytes"] + pad
    return q


def pad_imports(p, synth):
    """Extra harmless functions in the import table."""
    q = dict(p)
    q["import_count"] = p["import_count"] + int(synth.logu(20, 400))
    return q


def staple_signature(p):
    """A signature block that does not verify (copied from another file, or self-made)."""
    q = dict(p)
    q["signed"] = True
    return q


DISGUISES = ["plain", "fake signature", "padded file", "extra imports", "all three"]


def disguised(profiles, synth):
    """{disguise: feature rows} for held-out malware. Mach-O has no overlay to pad."""
    out = {"plain": features_of(profiles), "fake signature": features_of([staple_signature(p) for p in profiles])}
    macho = profiles[0]["format"] == "macho"
    out["padded file"] = features_of([p if macho else pad_overlay(p, synth) for p in profiles])
    out["extra imports"] = features_of([pad_imports(p, synth) for p in profiles])
    out["all three"] = features_of([pad_imports(p if macho else pad_overlay(staple_signature(p), synth), synth)
                                    for p in profiles])
    return out


# ---------------------------------------------------------------- data

def load_benign(path):
    """(categories, application numbers, feature rows). Datasets made before application numbers
    existed get one number per row, which makes the split a plain random one."""
    if not path.is_file():
        raise SystemExit(f"{path} is missing; run scripts/build_dataset.py on a Windows machine")
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        rows = list(reader)
    first = 2 if header[:2] == ["category", "group"] else 1
    if header[first:] != tf.FEATURE_NAMES:
        raise SystemExit(f"{path} has features {header[first:]}, expected {tf.FEATURE_NAMES}; rebuild it")
    categories = np.array([r[0] for r in rows])
    groups = np.array([int(r[1]) for r in rows]) if first == 2 else np.arange(len(rows))
    x = np.array([[float(v) for v in r[first:]] for r in rows], dtype=np.float32)
    return categories, groups, x


def hold_out_groups(groups, rng, share):
    """Mask of rows whose whole application is held out (about `share` of the rows)."""
    ids, counts = np.unique(groups, return_counts=True)
    held = set()
    filled = 0
    for i in rng.permutation(len(ids)):
        if filled + counts[i] <= len(groups) * share:
            held.add(ids[i])
            filled += counts[i]
    return np.isin(groups, list(held))


def build_sets(args, rng):
    categories, groups, real = load_benign(args.data)
    test = hold_out_groups(groups, rng, args.test_share)
    real_train, groups_train = real[~test], groups[~test]
    # Each ensemble member trains without one fold of the applications; the member that never saw
    # an application is the one that scores it for calibration.
    ids = np.unique(groups_train)
    fold_of = dict(zip(ids, rng.integers(0, args.members, len(ids))))
    real_fold = np.array([fold_of[g] for g in groups_train])

    synth = Synth(rng)
    benign_parts, benign_weights = [real_train], [np.ones(len(real_train), dtype=np.float32)]
    benign_test = {"real": (real[test], categories[test])}
    for family, n in SYNTHETIC_BENIGN.items():
        rows = synth_rows(synth, family, n)
        split = int(n * 0.8)
        benign_parts.append(rows[:split])
        benign_weights.append(np.full(split, BENIGN_WEIGHT.get(family, 1.0), dtype=np.float32))
        benign_test[family] = (rows[split:], None)
    benign_train = np.concatenate(benign_parts)

    n_mal = int(len(benign_train) * args.malicious_ratio)
    malicious_train, malicious_test = [], {}
    for family, share in MALICIOUS_FAMILIES.items():
        make = getattr(synth, family)
        profiles = []
        for _ in range(int(n_mal * share)):
            p = synth.dotnet(lookalike=args.dotnet_lookalike) if family == "dotnet" else make()
            if p["format"] != "macho":  # padding a Mac stealer makes it a Mac runtime: not trainable
                if synth.chance(args.evasion):
                    p = pad_overlay(p, synth)
                if synth.chance(args.evasion):
                    p = pad_imports(p, synth)
            profiles.append(p)
        malicious_train.append(features_of(profiles))
        malicious_test[family] = disguised([make() for _ in range(int(n_mal * share / 4))], synth)
    malicious_train = np.concatenate(malicious_train)

    x = np.concatenate([benign_train, malicious_train])
    y = np.concatenate([np.zeros(len(benign_train)), np.ones(len(malicious_train))]).astype(np.float32)
    w = np.concatenate(benign_weights + [np.ones(len(malicious_train), dtype=np.float32)])
    flip = rng.random(len(y)) < args.label_noise
    y[flip] = 1.0 - y[flip]
    # fold[i] = the member that must not train on row i (-1: every member may).
    fold = np.full(len(x), -1)
    fold[:len(real_train)] = real_fold
    return x, y, w, fold, benign_test, malicious_test


# ---------------------------------------------------------------- model (members stacked on axis 0)

def init_params(rng, members):
    sizes = (N_FEATURES,) + HIDDEN + (1,)
    params = []
    for fan_in, fan_out in zip(sizes[:-1], sizes[1:]):
        params.append(rng.normal(0.0, np.sqrt(2.0 / fan_in), (members, fan_in, fan_out)).astype(np.float32))
        params.append(np.zeros((members, 1, fan_out), dtype=np.float32))
    return params


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -60.0, 60.0)))


def forward(params, x):
    """x: [n, f] (every member scores the same rows) or [members, n, f]. Returns per-member
    logits [members, n] and the activations."""
    w1, b1, w2, b2, w3, b3 = params
    z1 = x @ w1 + b1
    h1 = np.maximum(z1, 0.0)
    z2 = h1 @ w2 + b2
    h2 = np.maximum(z2, 0.0)
    z3 = h2 @ w3 + b3
    return z3[..., 0], (z1, h1, z2, h2)


def member_logits(params, x, chunk=20000):
    return np.concatenate([forward(params, x[i:i + chunk])[0] for i in range(0, len(x), chunk)], axis=1)


def logits(params, x):
    """The ensemble's logit: the mean of its members'."""
    return member_logits(params, x).mean(axis=0)


def model_scores(params, x):
    return sigmoid(logits(params, x))


def train(x, y, w, fold, rng, args):
    members = args.members
    params = init_params(rng, members)
    params[0][:, SIGNED, :] = 0.0  # signature blindness: no connection to that input, ever
    m = [np.zeros_like(p) for p in params]
    v = [np.zeros_like(p) for p in params]
    beta1, beta2, eps = 0.9, 0.999, 1e-8
    allowed = [np.flatnonzero(fold != k) for k in range(members)]
    usable = min(len(a) for a in allowed)
    step = 0
    for epoch in range(1, args.epochs + 1):
        lr = args.lr * (0.5 * (1.0 + np.cos(np.pi * (epoch - 1) / args.epochs)))  # cosine decay
        order = np.stack([rng.permutation(a)[:usable] for a in allowed])
        for start in range(0, usable, args.batch_size):
            idx = order[:, start:start + args.batch_size]  # [members, batch]
            xb = x[idx]
            wb = w[idx]
            z, (z1, h1, z2, h2) = forward(params, xb)
            w1, _, w2, _, w3, _ = params
            dz3 = ((sigmoid(z) - y[idx]) * wb / wb.sum(axis=1, keepdims=True))[..., None]
            dw3 = h2.transpose(0, 2, 1) @ dz3 + args.weight_decay * w3
            db3 = dz3.sum(axis=1, keepdims=True)
            dz2 = (dz3 @ w3.transpose(0, 2, 1)) * (z2 > 0)
            dw2 = h1.transpose(0, 2, 1) @ dz2 + args.weight_decay * w2
            db2 = dz2.sum(axis=1, keepdims=True)
            dz1 = (dz2 @ w2.transpose(0, 2, 1)) * (z1 > 0)
            dw1 = xb.transpose(0, 2, 1) @ dz1 + args.weight_decay * w1
            dw1[:, SIGNED, :] = 0.0
            db1 = dz1.sum(axis=1, keepdims=True)
            step += 1
            for i, g in enumerate([dw1, db1, dw2, db2, dw3, db3]):
                m[i] = beta1 * m[i] + (1.0 - beta1) * g
                v[i] = beta2 * v[i] + (1.0 - beta2) * g * g
                m_hat = m[i] / (1.0 - beta1 ** step)
                v_hat = v[i] / (1.0 - beta2 ** step)
                params[i] = (params[i] - lr * m_hat / (np.sqrt(v_hat) + eps)).astype(np.float32)
        if epoch % 25 == 0 or epoch == args.epochs:
            p = sigmoid(member_logits(params, x))
            pc = np.clip(p, 1e-7, 1.0 - 1e-7)
            loss = float(-np.mean(y * np.log(pc) + (1.0 - y) * np.log(1.0 - pc)))
            print(f"epoch {epoch:4d}  loss {loss:.4f}")
    return params


def with_signature(x, bit):
    out = x.copy()
    out[:, SIGNED] = bit
    return out


def calibrate(params, x, fold, target_fpr):
    """Lower the output bias until at most target_fpr of the real training programs reach the
    threshold, each scored by the member that never saw its application. Returns the shift
    applied (0 when the model is already inside the budget)."""
    real = fold >= 0
    rows, member = x[real], fold[real]
    scores = member_logits(params, rows)[member, np.arange(len(rows))]
    limit = float(np.log(THRESHOLD / (1.0 - THRESHOLD)))
    quantile = float(np.quantile(scores, 1.0 - target_fpr))
    shift = max(0.0, quantile - limit + 0.05)
    params[5] = (params[5] - shift).astype(np.float32)
    return shift


# ---------------------------------------------------------------- evaluation

def rate(scores, threshold=THRESHOLD):
    return float(np.mean(scores >= threshold)) if len(scores) else float("nan")


def heuristic_scores(x):
    return np.array([tf.heuristic_score(row) for row in x.astype(np.float64)])


def evaluate(name, score_fn, benign_test, malicious_test):
    """Prints the held-out results and returns the gated numbers."""
    print(f"\n{name}: share of each held-out set at or above {THRESHOLD}")
    x_real, cats = benign_test["real"]
    # What production scores: no valid signature. A signature block that fails verification
    # still sets the bit, so both states are reported; the model gives the same answer for both
    # (the heuristic fallback does not).
    unsigned_scores = score_fn(with_signature(x_real, 0.0))
    fpr = rate(unsigned_scores)
    fpr_signed = rate(score_fn(with_signature(x_real, 1.0)))
    print(f"  real programs of unseen applications {fpr:7.2%} flagged   (n={len(x_real)}; "
          f"{fpr_signed:.2%} with a signature block; {rate(unsigned_scores, KILL_CONFIDENCE):.2%} at the "
          f"{KILL_CONFIDENCE} process-kill level)")
    for cat in sorted(set(cats)):
        mask = cats == cat
        print(f"    {cat:24s} {rate(unsigned_scores[mask]):7.2%}   (n={mask.sum()})")
    synthetic_fpr = {}
    for family in SYNTHETIC_BENIGN:
        rows, _ = benign_test[family]
        scores = score_fn(rows)
        synthetic_fpr[family] = rate(scores)
        print(f"  benign {family:20s} {synthetic_fpr[family]:7.2%} flagged   (n={len(rows)}; "
              f"{rate(scores, KILL_CONFIDENCE):.2%} at kill level)")
    caught = {d: [0.0, 0] for d in DISGUISES}
    for family, variants in malicious_test.items():
        rates = {d: rate(score_fn(rows)) for d, rows in variants.items()}
        n = len(variants["plain"])
        if family in GATED_FAMILIES:
            for d in DISGUISES:
                caught[d][0] += rates[d] * n
                caught[d][1] += n
        print(f"  malware {family:14s} {rates['plain']:7.2%} detected  (n={n})  | "
              + "  ".join(f"{d} {rates[d]:.1%}" for d in DISGUISES[1:])
              + ("" if family in GATED_FAMILIES else "  [reported, not gated]"))
    tpr = {d: a / b for d, (a, b) in caught.items()}
    print(f"  malware (gated families) {tpr['plain']:7.2%} detected  | "
          + "  ".join(f"{d} {tpr[d]:.1%}" for d in DISGUISES[1:]))
    # Installers and Mac programs only exist synthetically here; gate them separately.
    # (Protected apps are always signed, so on Windows they are trusted and never scored.)
    worst_synthetic = max(synthetic_fpr["installer"], synthetic_fpr["macho_benign"], synthetic_fpr["macho_runtime"])
    return {"fpr": fpr, "fpr_signed": fpr_signed, "tpr": tpr["plain"], "tpr_signed": tpr["fake signature"],
            "tpr_evasive": tpr["all three"], "synthetic_fpr": worst_synthetic}


def check_prototypes(name, score_fn):
    names = list(tf.PROTOTYPES)
    x = features_of([tf.PROTOTYPES[n][0] for n in names])
    scores = score_fn(x)
    print(f"{name} prototypes: " + "  ".join(f"{n}={s:.3f}" for n, s in zip(names, scores)))
    wrong = [n for n, s in zip(names, scores) if (s >= THRESHOLD) != tf.PROTOTYPES[n][1]]
    if wrong:
        raise SystemExit(f"{name} misclassifies prototypes {wrong} at threshold {THRESHOLD}")


# ---------------------------------------------------------------- export

def merged(params):
    """The ensemble as one network: member weights side by side in the first layer, on the block
    diagonal in the second, and averaged into a single output in the third."""
    w1, b1, w2, b2, w3, b3 = params
    members, _, h1 = w1.shape
    h2 = w2.shape[2]
    big_w2 = np.zeros((members * h1, members * h2), dtype=np.float32)
    for k in range(members):
        big_w2[k * h1:(k + 1) * h1, k * h2:(k + 1) * h2] = w2[k]
    return [
        np.concatenate(list(w1), axis=1), np.concatenate([b[0] for b in b1]),
        big_w2, np.concatenate([b[0] for b in b2]),
        (np.concatenate(list(w3), axis=0) / members).astype(np.float32),
        np.array([float(np.mean(b3))], dtype=np.float32),
    ]


def build_model(params):
    arrays = merged(params)
    initializers = [numpy_helper.from_array(a.astype(np.float32), n)
                    for a, n in zip(arrays, ["W1", "B1", "W2", "B2", "W3", "B3"])]
    nodes = [
        helper.make_node("Gemm", ["features", "W1", "B1"], ["dense1"], name="dense1"),
        helper.make_node("Relu", ["dense1"], ["relu1"], name="relu1"),
        helper.make_node("Gemm", ["relu1", "W2", "B2"], ["dense2"], name="dense2"),
        helper.make_node("Relu", ["dense2"], ["relu2"], name="relu2"),
        helper.make_node("Gemm", ["relu2", "W3", "B3"], ["logit"], name="dense3"),
        helper.make_node("Sigmoid", ["logit"], ["probability"], name="sigmoid"),
    ]
    graph = helper.make_graph(
        nodes,
        "thenex_binary_classifier_v3",
        [helper.make_tensor_value_info("features", TensorProto.FLOAT, ["N", N_FEATURES])],
        [helper.make_tensor_value_info("probability", TensorProto.FLOAT, ["N", 1])],
        initializer=initializers,
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", OPSET)],
        producer_name="thenex-train",
        producer_version="3.0",
        doc_string=f"ensemble of {params[0].shape[0]}; features: " + ", ".join(tf.FEATURE_NAMES),
    )
    model.ir_version = IR_VERSION
    return model


def verify_graph(model):
    onnx.checker.check_model(model, full_check=True)
    domains = {opset.domain for opset in model.opset_import}
    if not domains <= {"", "ai.onnx"}:
        raise SystemExit(f"non-standard opset domains present: {sorted(domains)}")
    for node in model.graph.node:
        if node.domain not in ("", "ai.onnx"):
            raise SystemExit(f"node {node.name} uses domain {node.domain!r}")
        if node.op_type not in ALLOWED_OPS:
            raise SystemExit(f"node {node.name} uses disallowed op {node.op_type}")
    ops = sorted({node.op_type for node in model.graph.node})
    print(f"graph ops: {ops} (opset {OPSET}, IR {model.ir_version}, no ai.onnx.ml)")


def verify_against_reference(model, params, x):
    try:
        from onnx.reference import ReferenceEvaluator
    except ImportError:
        print("onnx.reference unavailable; skipped reference-evaluator parity check")
        return
    session = ReferenceEvaluator(model)
    sample = x[:512]
    (onnx_out,) = session.run(None, {"features": sample})
    diff = float(np.max(np.abs(onnx_out.ravel() - model_scores(params, sample))))
    if diff > 1e-4:
        raise SystemExit(f"ONNX output diverges from training graph (max |diff| = {diff})")
    print(f"reference evaluator parity: max |diff| = {diff:.2e}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--members", type=int, default=5, help="networks in the ensemble")
    parser.add_argument("--epochs", type=int, default=150)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--lr", type=float, default=3e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--label-noise", type=float, default=0.01)
    parser.add_argument("--malicious-ratio", type=float, default=0.9)
    parser.add_argument("--evasion", type=float, default=0.3,
                        help="chance that a PE malware training profile gets each padding disguise")
    parser.add_argument("--dotnet-lookalike", type=float, default=0.0,
                        help="share of .NET malware TRAINING profiles left unobfuscated (the test always has 25%%)")
    parser.add_argument("--test-share", type=float, default=0.2, help="share of real programs held out, by application")
    parser.add_argument("--target-fpr", type=float, default=0.005)
    parser.add_argument("--min-tpr", type=float, default=0.90)
    parser.add_argument("--min-evasive-tpr", type=float, default=0.80)
    parser.add_argument("--max-heuristic-fpr", type=float, default=0.03)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()
    if args.members < 2:
        raise SystemExit("--members must be at least 2: calibration scores each program with a member that never saw it")

    rng = np.random.default_rng(args.seed)
    x, y, w, fold, benign_test, malicious_test = build_sets(args, rng)
    print(f"training rows: {len(x)} ({int(y.sum())} malicious, {int((fold >= 0).sum())} real programs), "
          f"held-out real programs: {len(benign_test['real'][0])}, ensemble of {args.members}")

    params = train(x, y, w, fold, rng, args)
    shift = calibrate(params, x, fold, args.target_fpr)
    print(f"calibration: output bias lowered by {shift:.3f} for a {args.target_fpr:.2%} false-positive budget")

    result = evaluate("model", lambda rows: model_scores(params, rows), benign_test, malicious_test)
    heuristic = evaluate("heuristic fallback", heuristic_scores, benign_test, malicious_test)
    print()
    check_prototypes("model", lambda rows: model_scores(params, rows))
    check_prototypes("heuristic", heuristic_scores)
    if result["tpr"] < args.min_tpr:
        raise SystemExit(f"held-out detection {result['tpr']:.2%} is below --min-tpr {args.min_tpr:.0%}")
    if result["tpr_evasive"] < args.min_evasive_tpr:
        raise SystemExit(f"held-out detection of disguised malware {result['tpr_evasive']:.2%} is below "
                         f"--min-evasive-tpr {args.min_evasive_tpr:.0%}")
    # Whole applications are held out, so one unusual program (a dozen similar files) moves this
    # figure by a few tenths of a percent; three times the budget means the calibration failed.
    if result["fpr"] > 3 * args.target_fpr:
        raise SystemExit(f"held-out false positives {result['fpr']:.2%} exceed three times "
                         f"the {args.target_fpr:.2%} budget")
    if result["fpr"] != result["fpr_signed"] or result["tpr"] != result["tpr_signed"]:
        raise SystemExit("the model is not blind to the signature block: "
                         f"false positives {result['fpr']:.2%} vs {result['fpr_signed']:.2%} with one, "
                         f"detection {result['tpr']:.2%} vs {result['tpr_signed']:.2%} with one")
    if result["synthetic_fpr"] > 0.03:
        raise SystemExit(f"model flags {result['synthetic_fpr']:.2%} of synthetic benign installers or Mac programs")
    if max(heuristic["fpr"], heuristic["synthetic_fpr"]) > args.max_heuristic_fpr:
        raise SystemExit(f"heuristic fallback flags {max(heuristic['fpr'], heuristic['synthetic_fpr']):.2%} of a benign set")

    model = build_model(params)
    verify_graph(model)
    verify_against_reference(model, params, x)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(model, str(args.out))
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)  model: {result['fpr']:.2%} false positives on unseen "
          f"applications, {result['tpr']:.2%} detection ({result['tpr_evasive']:.2%} when disguised) on held-out data")
    return 0


if __name__ == "__main__":
    sys.exit(main())
