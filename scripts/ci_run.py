#!/usr/bin/env python3
"""Runs a command as it is; when it fails, repeats what failed as public GitHub annotations.

A run's log can only be read by someone signed in to GitHub, its annotations by anyone.
    python scripts/ci_run.py cargo test --workspace        (exit status is the command's)
    python scripts/ci_run.py --self-test
"""

import contextlib
import io
import subprocess
import sys

LIMIT = 3500  # characters in one annotation
MAX_NOTES = 8


def failures(lines):
    """The lines that say what failed: failed tests, panics with what follows, failed live checks."""
    out, after = [], 0
    for line in lines:
        line = line.rstrip()
        hit = "... FAILED" in line or "[FAIL]" in line or line.startswith(("error[", "error:")) or "panicked at" in line
        if "panicked at" in line:
            after = 6
        if hit or (after and line and not line.startswith(("note:", "stack backtrace"))):
            out.append(line)
        after = max(after - 1, 0)
        if line.startswith("stack backtrace"):
            after = 0
    return out


def annotations(title, lines):
    notes, current = [], ""
    for line in lines:
        line = line[:600]
        if current and len(current) + len(line) > LIMIT:
            notes.append(current)
            current = ""
        current += ("\n" if current else "") + line
    if current:
        notes.append(current)
    escape = lambda s: s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return [f"::error title={escape(title)}::{escape(note)}" for note in notes[:MAX_NOTES]]


def run(command):
    lines = []
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", errors="replace")
    for line in process.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        lines.append(line)
    status = process.wait()
    if status:
        for note in annotations(" ".join(command[:2]), failures(lines) or lines[-15:]):
            print(note)
    return status


def self_test():
    log = ["test a ... ok", "test b::c ... FAILED", "thread 'b::c' panicked at src/x.rs:1:2:", "assertion failed", "  left: 1",
           "stack backtrace:", "   0: std::panicking", "[FAIL]  Live thing   1.00s  why", "error: test failed, to rerun"]
    found = failures(log)
    assert found == [log[1], log[2], log[3], log[4], log[7], log[8]], found
    notes = annotations("t", ["100% a\nb", "x" * 5000] + ["y" * 590] * 9)
    assert notes[0].startswith("::error title=t::100%25 a%0Ab%0Axx") and len(notes) == 2, len(notes)
    assert all("\n" not in n and len(n) < LIMIT + 700 for n in notes), [len(n) for n in notes]
    with contextlib.redirect_stdout(io.StringIO()) as shown:  # or the runner would take the note for a real one
        status = run([sys.executable, "-c", "import sys; print('fine'); sys.exit(3)"])
    assert status == 3 and shown.getvalue().startswith("fine") and "::error title=" in shown.getvalue()
    print("self-test passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.exit(run(sys.argv[1:]))
