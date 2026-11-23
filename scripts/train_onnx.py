#!/usr/bin/env python3
"""Train The Nex binary classifier (v2) and export it as a tract-compatible ONNX graph.

Data
  benign    data/benign_pe_features.csv: ~14.5k REAL Windows programs and libraries (system
            files, .NET assemblies, installed applications and unsigned developer tools), made
            by scripts/build_dataset.py. Plus synthetic profiles of what a folder scan of a
            clean machine cannot contain: installers (large appended payloads),
            protector-wrapped commercial software and macOS Mach-O programs.
  malicious synthetic profiles of well-documented malware traits: packed, crypted, process
            injectors / stealers / keyloggers, droppers, obfuscated .NET and Mach-O stealers.
            No malware is downloaded or stored.

Features come from scripts/thenex_features.py, which mirrors crates/the-nex-core/src/bin_ai.rs.

Signature dropout: on Windows a file with a VALID signature is trusted and never scored, so in
production the model mostly sees unsigned files. Every signed real benign program is therefore
also trained on with its signature removed: the model has to judge the code, not the
certificate.

Calibration: after training, the output bias is lowered (if needed) so that at most
--target-fpr of held-out REAL benign programs reach the quarantine threshold. Training fails
when held-out detection drops below --min-tpr.

Graph: Gemm -> Relu -> Gemm -> Relu -> Gemm -> Sigmoid at opset 13, default domain only (no
ai.onnx.ml); input "features" [N, 14] float32, output "probability" [N, 1] float32.
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

    def dotnet(self):
        """.NET stealers/RATs: one import by design; obfuscators and packed payloads raise entropy."""
        size = self.logu(20e3, 4e6)
        entry_e = self.u(7.0, 7.9) if self.chance(0.75) else self.u(5.2, 6.4)
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
KILL_CONFIDENCE = 0.9  # process_guard::PROCESS_KILL_CONFIDENCE


def synth_rows(synth, family, n):
    make = getattr(synth, family)
    return np.array([tf.features(make()) for _ in range(n)], dtype=np.float32)


# ---------------------------------------------------------------- data

def load_benign(path):
    if not path.is_file():
        raise SystemExit(f"{path} is missing; run scripts/build_dataset.py on a Windows machine")
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        if header[1:] != tf.FEATURE_NAMES:
            raise SystemExit(f"{path} has features {header[1:]}, expected {tf.FEATURE_NAMES}; rebuild it")
        rows = list(reader)
    categories = np.array([r[0] for r in rows])
    x = np.array([[float(v) for v in r[1:]] for r in rows], dtype=np.float32)
    return categories, x


def signature_dropout(x):
    signed = x[x[:, SIGNED] > 0.5].copy()
    signed[:, SIGNED] = 0.0
    return np.concatenate([x, signed])


def build_sets(args, rng):
    categories, real = load_benign(args.data)
    order = rng.permutation(len(real))
    n_cal = n_test = int(len(real) * 0.15)
    test_idx, cal_idx, train_idx = order[:n_test], order[n_test:n_test + n_cal], order[n_test + n_cal:]

    synth = Synth(rng)
    benign_train = [signature_dropout(real[train_idx])]
    benign_test = {"real": (real[test_idx], categories[test_idx])}
    for family, n in SYNTHETIC_BENIGN.items():
        rows = synth_rows(synth, family, n)
        split = int(n * 0.8)
        benign_train.append(rows[:split])
        benign_test[family] = (rows[split:], None)
    benign_train = np.concatenate(benign_train)

    n_mal = int(len(benign_train) * args.malicious_ratio)
    malicious_train, malicious_test = [], {}
    for family, share in MALICIOUS_FAMILIES.items():
        n = int(n_mal * share / 0.8)
        rows = synth_rows(synth, family, n)
        split = int(n * 0.8)
        malicious_train.append(rows[:split])
        malicious_test[family] = rows[split:]
    malicious_train = np.concatenate(malicious_train)

    x = np.concatenate([benign_train, malicious_train])
    y = np.concatenate([np.zeros(len(benign_train)), np.ones(len(malicious_train))]).astype(np.float32)
    flip = rng.random(len(y)) < args.label_noise
    y[flip] = 1.0 - y[flip]
    shuffle = rng.permutation(len(x))
    return x[shuffle], y[shuffle].reshape(-1, 1), real[cal_idx], benign_test, malicious_test


# ---------------------------------------------------------------- model

def init_params(rng):
    sizes = (N_FEATURES,) + HIDDEN + (1,)
    params = []
    for fan_in, fan_out in zip(sizes[:-1], sizes[1:]):
        params.append(rng.normal(0.0, np.sqrt(2.0 / fan_in), (fan_in, fan_out)).astype(np.float32))
        params.append(np.zeros(fan_out, dtype=np.float32))
    return params


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -60.0, 60.0)))


def forward(params, x):
    w1, b1, w2, b2, w3, b3 = params
    z1 = x @ w1 + b1
    h1 = np.maximum(z1, 0.0)
    z2 = h1 @ w2 + b2
    h2 = np.maximum(z2, 0.0)
    z3 = h2 @ w3 + b3
    return sigmoid(z3), (x, z1, h1, z2, h2, z3)


def logits(params, x):
    return forward(params, x)[1][5].ravel()


def gradients(params, x, y, weight_decay):
    w1, _, w2, _, w3, _ = params
    p, (x0, z1, h1, z2, h2, _) = forward(params, x)
    n = x.shape[0]
    dz3 = (p - y) / n
    dw3 = h2.T @ dz3 + weight_decay * w3
    db3 = dz3.sum(axis=0)
    dz2 = (dz3 @ w3.T) * (z2 > 0)
    dw2 = h1.T @ dz2 + weight_decay * w2
    db2 = dz2.sum(axis=0)
    dz1 = (dz2 @ w2.T) * (z1 > 0)
    dw1 = x0.T @ dz1 + weight_decay * w1
    db1 = dz1.sum(axis=0)
    return [dw1, db1, dw2, db2, dw3, db3]


def bce(p, y):
    p = np.clip(p, 1e-7, 1.0 - 1e-7)
    return float(-np.mean(y * np.log(p) + (1.0 - y) * np.log(1.0 - p)))


def train(x, y, rng, args):
    params = init_params(rng)
    m = [np.zeros_like(p) for p in params]
    v = [np.zeros_like(p) for p in params]
    beta1, beta2, eps = 0.9, 0.999, 1e-8
    step = 0
    for epoch in range(1, args.epochs + 1):
        lr = args.lr * (0.5 * (1.0 + np.cos(np.pi * (epoch - 1) / args.epochs)))  # cosine decay
        order = rng.permutation(len(x))
        for start in range(0, len(x), args.batch_size):
            batch = order[start:start + args.batch_size]
            grads = gradients(params, x[batch], y[batch], args.weight_decay)
            step += 1
            for i, g in enumerate(grads):
                m[i] = beta1 * m[i] + (1.0 - beta1) * g
                v[i] = beta2 * v[i] + (1.0 - beta2) * g * g
                m_hat = m[i] / (1.0 - beta1 ** step)
                v_hat = v[i] / (1.0 - beta2 ** step)
                params[i] = (params[i] - lr * m_hat / (np.sqrt(v_hat) + eps)).astype(np.float32)
        if epoch % 25 == 0 or epoch == args.epochs:
            p, _ = forward(params, x)
            print(f"epoch {epoch:4d}  loss {bce(p, y):.4f}")
    return params


def calibrate(params, benign_cal, target_fpr):
    """Lower the output bias until at most target_fpr of real benign calibration programs reach the
    threshold. Returns the shift applied (0 when the model is already inside the budget)."""
    limit = float(np.log(THRESHOLD / (1.0 - THRESHOLD)))
    quantile = float(np.quantile(logits(params, benign_cal), 1.0 - target_fpr))
    shift = max(0.0, quantile - limit + 0.05)
    params[5] = (params[5] - shift).astype(np.float32)
    return shift


# ---------------------------------------------------------------- evaluation

def rate(scores, threshold=THRESHOLD):
    return float(np.mean(scores >= threshold)) if len(scores) else float("nan")


def model_scores(params, x):
    return forward(params, x)[0].ravel()


def heuristic_scores(x):
    return np.array([tf.heuristic_score(row) for row in x.astype(np.float64)])


def evaluate(name, score_fn, benign_test, malicious_test):
    print(f"\n{name}: share of each held-out set at or above {THRESHOLD}")
    x_real, cats = benign_test["real"]
    real_scores = score_fn(x_real)
    fpr = rate(real_scores)
    unsigned = x_real[:, SIGNED] < 0.5
    print(f"  benign real programs       {fpr:7.2%} flagged   (n={len(x_real)}; unsigned only {rate(real_scores[unsigned]):.2%})")
    for cat in sorted(set(cats)):
        mask = cats == cat
        print(f"    {cat:24s} {rate(real_scores[mask]):7.2%}   (n={mask.sum()})")
    stripped = x_real.copy()
    stripped[:, SIGNED] = 0.0
    print(f"  benign real, signature removed {rate(score_fn(stripped)):7.2%} flagged")
    print(f"  benign real programs at the {KILL_CONFIDENCE} process-kill level {rate(real_scores, KILL_CONFIDENCE):.2%}")
    synthetic_fpr = {}
    for family in SYNTHETIC_BENIGN:
        rows, _ = benign_test[family]
        scores = score_fn(rows)
        synthetic_fpr[family] = rate(scores)
        print(f"  benign {family:20s} {synthetic_fpr[family]:7.2%} flagged   (n={len(rows)}; "
              f"{rate(scores, KILL_CONFIDENCE):.2%} at kill level)")
    caught = []
    for family, rows in malicious_test.items():
        r = rate(score_fn(rows))
        if family in GATED_FAMILIES:
            caught.append((r, len(rows)))
        print(f"  malware {family:19s} {r:7.2%} detected  (n={len(rows)}){'' if family in GATED_FAMILIES else '  [reported, not gated]'}")
    tpr = sum(r * n for r, n in caught) / sum(n for _, n in caught)
    print(f"  malware (gated families)   {tpr:7.2%} detected")
    # Installers and Mac programs only exist synthetically here; gate them separately.
    # (Protected apps are always signed, so on Windows they are trusted and never scored.)
    worst_synthetic = max(synthetic_fpr["installer"], synthetic_fpr["macho_benign"], synthetic_fpr["macho_runtime"])
    return fpr, tpr, worst_synthetic


def check_prototypes(name, score_fn):
    names = list(tf.PROTOTYPES)
    x = np.array([tf.features(tf.PROTOTYPES[n][0]) for n in names], dtype=np.float32)
    scores = score_fn(x)
    print(f"{name} prototypes: " + "  ".join(f"{n}={s:.3f}" for n, s in zip(names, scores)))
    wrong = [n for n, s in zip(names, scores) if (s >= THRESHOLD) != tf.PROTOTYPES[n][1]]
    if wrong:
        raise SystemExit(f"{name} misclassifies prototypes {wrong} at threshold {THRESHOLD}")


# ---------------------------------------------------------------- export

def build_model(params):
    w1, b1, w2, b2, w3, b3 = params
    initializers = [numpy_helper.from_array(a.astype(np.float32), n)
                    for a, n in zip(params, ["W1", "B1", "W2", "B2", "W3", "B3"])]
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
        "thenex_binary_classifier_v2",
        [helper.make_tensor_value_info("features", TensorProto.FLOAT, ["N", N_FEATURES])],
        [helper.make_tensor_value_info("probability", TensorProto.FLOAT, ["N", 1])],
        initializer=initializers,
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", OPSET)],
        producer_name="thenex-train",
        producer_version="2.0",
        doc_string="features: " + ", ".join(tf.FEATURE_NAMES),
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
    numpy_out, _ = forward(params, sample)
    diff = float(np.max(np.abs(onnx_out - numpy_out)))
    if diff > 1e-4:
        raise SystemExit(f"ONNX output diverges from training graph (max |diff| = {diff})")
    print(f"reference evaluator parity: max |diff| = {diff:.2e}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--epochs", type=int, default=150)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--lr", type=float, default=3e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--label-noise", type=float, default=0.01)
    parser.add_argument("--malicious-ratio", type=float, default=0.9)
    parser.add_argument("--target-fpr", type=float, default=0.005)
    parser.add_argument("--min-tpr", type=float, default=0.90)
    parser.add_argument("--max-heuristic-fpr", type=float, default=0.03)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)
    x, y, benign_cal, benign_test, malicious_test = build_sets(args, rng)
    print(f"training rows: {len(x)} ({int(y.sum())} malicious), calibration rows: {len(benign_cal)}")

    params = train(x, y, rng, args)
    shift = calibrate(params, benign_cal, args.target_fpr)
    print(f"calibration: output bias lowered by {shift:.3f} for a {args.target_fpr:.2%} false-positive budget")

    fpr, tpr, synth_fpr = evaluate("model", lambda rows: model_scores(params, rows), benign_test, malicious_test)
    h_fpr, h_tpr, h_synth_fpr = evaluate("heuristic fallback", heuristic_scores, benign_test, malicious_test)
    print()
    check_prototypes("model", lambda rows: model_scores(params, rows))
    check_prototypes("heuristic", heuristic_scores)
    if tpr < args.min_tpr:
        raise SystemExit(f"held-out detection {tpr:.2%} is below --min-tpr {args.min_tpr:.0%}")
    if fpr > 2 * args.target_fpr:
        raise SystemExit(f"held-out false positives {fpr:.2%} exceed twice the {args.target_fpr:.2%} budget")
    if synth_fpr > 0.03:
        raise SystemExit(f"model flags {synth_fpr:.2%} of synthetic benign installers or Mac programs")
    if max(h_fpr, h_synth_fpr) > args.max_heuristic_fpr:
        raise SystemExit(f"heuristic fallback flags {max(h_fpr, h_synth_fpr):.2%} of a benign set")

    model = build_model(params)
    verify_graph(model)
    verify_against_reference(model, params, x)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(model, str(args.out))
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)  model: {fpr:.2%} false positives, "
          f"{tpr:.2%} detection on held-out data")
    return 0


if __name__ == "__main__":
    sys.exit(main())
