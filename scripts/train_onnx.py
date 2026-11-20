#!/usr/bin/env python3
"""Train The Nex binary classifier and export it as a tract-compatible ONNX graph.

Features (must match crates/the-nex-core/src/bin_ai.rs::feature_vector):
  0 log10(size_kb), size floored at 1 KiB  in [0, 6]  (10 KB -> 1.0, 3 MB -> 3.5)
  1 max section Shannon entropy / 8        in [0, 1]
  2 section (PE) or segment (Mach-O) count / 16, clipped to [0, 1]
  3 distinct suspicious imports / 9        in [0, 1]

The exported graph is Gemm -> Relu -> Gemm -> Relu -> Gemm -> Sigmoid at opset 13,
default domain only (no ai.onnx.ml operators), input "features" [N, 4] float32,
output "probability" [N, 1] float32.
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

N_FEATURES = 4
N_SUSPICIOUS_IMPORTS = 9
MAX_LOG10_SIZE_KB = 6.0
OPSET = 13
IR_VERSION = 7
ALLOWED_OPS = {"Gemm", "Relu", "Sigmoid"}
HIDDEN = (16, 8)
THRESHOLD = 0.65
# Reference vectors the Rust test-suite also checks against the exported model.
MALICIOUS_REFERENCE = [1.0, 0.98, 0.1, 0.9]
BENIGN_REFERENCE = [3.5, 0.55, 0.3, 0.0]
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "thenex_model.onnx"


def to_features(size_bytes, entropy, sections, suspicious):
    size_kb = np.maximum(size_bytes / 1024.0, 1.0)
    f_size = np.clip(np.log10(size_kb), 0.0, MAX_LOG10_SIZE_KB)
    f_entropy = np.clip(entropy / 8.0, 0.0, 1.0)
    f_sections = np.clip(sections / 16.0, 0.0, 1.0)
    f_suspicious = np.clip(suspicious / N_SUSPICIOUS_IMPORTS, 0.0, 1.0)
    return np.stack([f_size, f_entropy, f_sections, f_suspicious], axis=1).astype(np.float32)


def synth_benign(n, rng):
    size = 10.0 ** rng.uniform(4.3, 8.0, n)  # 20 KB .. 100 MB
    kind = rng.random(n)
    # Typical compiled code, small/simple tools with low entropy, and installers with packed resources.
    entropy = np.where(
        kind < 0.62,
        rng.normal(6.3, 0.45, n),
        np.where(kind < 0.82, rng.uniform(3.5, 6.0, n), rng.uniform(7.2, 7.98, n)),
    )
    sections = rng.integers(3, 11, n)
    # CRT start-up code alone pulls in IsDebuggerPresent; shells use ShellExecute.
    suspicious = rng.choice(np.arange(0, 4), size=n, p=[0.35, 0.40, 0.20, 0.05])
    return to_features(size, np.clip(entropy, 0.0, 8.0), sections, suspicious)


def synth_malicious(n, rng):
    size = 10.0 ** rng.uniform(3.7, 6.8, n)  # 5 KB .. 6 MB
    packed = rng.random(n) < 0.70
    entropy = np.where(packed, rng.uniform(7.2, 7.99, n), rng.normal(6.6, 0.4, n))
    sections = np.where(rng.random(n) < 0.6, rng.integers(1, 5, n), rng.integers(5, 12, n))
    suspicious = rng.choice(
        np.arange(0, 10),
        size=n,
        p=[0.04, 0.06, 0.12, 0.18, 0.18, 0.15, 0.11, 0.08, 0.05, 0.03],
    )
    return to_features(size, np.clip(entropy, 0.0, 8.0), sections, suspicious)


def make_dataset(n, rng, label_noise):
    n_benign = n // 2
    n_malicious = n - n_benign
    x = np.concatenate([synth_benign(n_benign, rng), synth_malicious(n_malicious, rng)])
    y = np.concatenate([np.zeros(n_benign), np.ones(n_malicious)]).astype(np.float32)
    flip = rng.random(n) < label_noise
    y[flip] = 1.0 - y[flip]
    order = rng.permutation(n)
    return x[order], y[order].reshape(-1, 1)


def init_params(rng):
    sizes = (N_FEATURES,) + HIDDEN + (1,)
    params = []
    for fan_in, fan_out in zip(sizes[:-1], sizes[1:]):
        w = rng.normal(0.0, np.sqrt(2.0 / fan_in), (fan_in, fan_out)).astype(np.float32)
        b = np.zeros(fan_out, dtype=np.float32)
        params.extend([w, b])
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
    return sigmoid(z3), (x, z1, h1, z2, h2)


def gradients(params, x, y):
    w1, _, w2, _, w3, _ = params
    p, (x0, z1, h1, z2, h2) = forward(params, x)
    n = x.shape[0]
    dz3 = (p - y) / n
    dw3 = h2.T @ dz3
    db3 = dz3.sum(axis=0)
    dz2 = (dz3 @ w3.T) * (z2 > 0)
    dw2 = h1.T @ dz2
    db2 = dz2.sum(axis=0)
    dz1 = (dz2 @ w2.T) * (z1 > 0)
    dw1 = x0.T @ dz1
    db1 = dz1.sum(axis=0)
    return [dw1, db1, dw2, db2, dw3, db3]


def bce(p, y):
    p = np.clip(p, 1e-7, 1.0 - 1e-7)
    return float(-np.mean(y * np.log(p) + (1.0 - y) * np.log(1.0 - p)))


def auc(scores, labels):
    scores = scores.ravel()
    labels = labels.ravel()
    order = np.argsort(scores)
    ranks = np.empty_like(order, dtype=np.float64)
    ranks[order] = np.arange(1, len(scores) + 1)
    pos = labels > 0.5
    n_pos = pos.sum()
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    return float((ranks[pos].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


def train(x, y, rng, epochs, batch_size, lr):
    params = init_params(rng)
    m = [np.zeros_like(p) for p in params]
    v = [np.zeros_like(p) for p in params]
    beta1, beta2, eps = 0.9, 0.999, 1e-8
    step = 0
    for epoch in range(1, epochs + 1):
        order = rng.permutation(len(x))
        for start in range(0, len(x), batch_size):
            batch = order[start:start + batch_size]
            grads = gradients(params, x[batch], y[batch])
            step += 1
            for i, g in enumerate(grads):
                m[i] = beta1 * m[i] + (1.0 - beta1) * g
                v[i] = beta2 * v[i] + (1.0 - beta2) * g * g
                m_hat = m[i] / (1.0 - beta1 ** step)
                v_hat = v[i] / (1.0 - beta2 ** step)
                params[i] = (params[i] - lr * m_hat / (np.sqrt(v_hat) + eps)).astype(np.float32)
        if epoch % 50 == 0 or epoch == epochs:
            p, _ = forward(params, x)
            print(f"epoch {epoch:4d}  loss {bce(p, y):.4f}")
    return params


def build_model(params):
    w1, b1, w2, b2, w3, b3 = params
    initializers = [
        numpy_helper.from_array(w1.astype(np.float32), "W1"),
        numpy_helper.from_array(b1.astype(np.float32), "B1"),
        numpy_helper.from_array(w2.astype(np.float32), "W2"),
        numpy_helper.from_array(b2.astype(np.float32), "B2"),
        numpy_helper.from_array(w3.astype(np.float32), "W3"),
        numpy_helper.from_array(b3.astype(np.float32), "B3"),
    ]
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
        "thenex_pe_classifier",
        [helper.make_tensor_value_info("features", TensorProto.FLOAT, ["N", N_FEATURES])],
        [helper.make_tensor_value_info("probability", TensorProto.FLOAT, ["N", 1])],
        initializer=initializers,
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", OPSET)],
        producer_name="thenex-train",
        producer_version="1.0",
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
    sample = x[:256]
    (onnx_out,) = session.run(None, {"features": sample})
    numpy_out, _ = forward(params, sample)
    diff = float(np.max(np.abs(onnx_out - numpy_out)))
    if diff > 1e-4:
        raise SystemExit(f"ONNX output diverges from training graph (max |diff| = {diff})")
    print(f"reference evaluator parity: max |diff| = {diff:.2e}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--samples", type=int, default=40_000)
    parser.add_argument("--epochs", type=int, default=300)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--lr", type=float, default=3e-3)
    parser.add_argument("--label-noise", type=float, default=0.02)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)
    x, y = make_dataset(args.samples, rng, args.label_noise)
    split = int(len(x) * 0.8)
    x_train, y_train = x[:split], y[:split]
    x_val, y_val = x[split:], y[split:]

    params = train(x_train, y_train, rng, args.epochs, args.batch_size, args.lr)
    p_val, _ = forward(params, x_val)
    accuracy = float(np.mean((p_val >= 0.5) == (y_val >= 0.5)))
    print(f"validation: accuracy {accuracy:.4f}  auc {auc(p_val, y_val):.4f}  loss {bce(p_val, y_val):.4f}")

    prototypes = to_features(
        np.array([800 * 1024, 120 * 1024], dtype=np.float64),
        np.array([6.3, 7.9]),
        np.array([6, 3]),
        np.array([1, 5]),
    )
    references = np.array([BENIGN_REFERENCE, MALICIOUS_REFERENCE], dtype=np.float32)
    checks = np.concatenate([prototypes, references])
    scores, _ = forward(params, checks)
    scores = scores.ravel()
    print(
        f"prototype benign={scores[0]:.3f} malicious={scores[1]:.3f}  "
        f"reference benign={scores[2]:.3f} malicious={scores[3]:.3f}"
    )
    expected_malicious = [False, True, False, True]
    wrong = [i for i, malicious in enumerate(expected_malicious) if (scores[i] >= THRESHOLD) != malicious]
    if wrong:
        raise SystemExit(f"model misclassifies reference vectors {wrong} at threshold {THRESHOLD}; retrain with another --seed")

    model = build_model(params)
    verify_graph(model)
    verify_against_reference(model, params, x_val)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(model, str(args.out))
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
