"""The Nex binary-AI feature definition, shared by training and the CI parity check.

Everything here mirrors crates/the-nex-core/src/bin_ai.rs exactly
(`BinaryProfile` -> `BinaryProfile::features`). If you change one side, change the other:
CI runs scripts/check_feature_parity.py, which fails when Rust and Python disagree, because a
model fed different numbers in production than in training silently stops working.

`profile_pe` needs pefile (pip install pefile). Everything else needs only the standard
library and numpy, so training does not depend on pefile. There is no Mach-O extractor here:
Mach-O training profiles are synthetic, and bin_ai.rs extracts real ones.
"""

import math

import numpy as np

FEATURE_NAMES = [
    "size_log10_kb",            # 0  log10(max(size KiB, 1)) / 6
    "max_section_entropy",      # 1  highest section entropy / 8
    "entry_section_entropy",    # 2  entropy of the section holding the entry point / 8
    "section_count",            # 3  sections (PE) or segments (Mach-O) / 16
    "wx_section_ratio",         # 4  writable+executable sections / sections
    "entry_point_anomaly",      # 5  entry outside an executable section, or in the last one
    "import_count_log",         # 6  log10(1 + imported functions) / 3
    "suspicious_import_ratio",  # 7  distinct risky APIs imported / list size
    "has_signature",            # 8  Authenticode table (PE) or LC_CODE_SIGNATURE (Mach-O)
    "overlay_ratio",            # 9  bytes appended after the last section (minus signature) / size
    "packer_section_names",     # 10 a known packer section name is present
    "resource_ratio",           # 11 resource directory size / size
    "is_dotnet",                # 12 has a CLR (.NET) header
    "is_macho",                 # 13 Mach-O rather than PE
]
N_FEATURES = len(FEATURE_NAMES)

MAX_LOG10_SIZE_KB = 6.0
SECTION_COUNT_SCALE = 16.0
IMPORT_LOG_SCALE = 3.0
MAX_AI_SCAN_BYTES = 100 * 1024 * 1024

# Prefix matches, so "ShellExecute" also catches ShellExecuteW / ShellExecuteExW.
SUSPICIOUS_IMPORTS = [
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "SetWindowsHookEx",
    "URLDownloadToFile",
    "IsDebuggerPresent",
    "WinExec",
    "ShellExecute",
    "QueueUserAPC",
    "NtWriteVirtualMemory",
    "SetThreadContext",
    "GetAsyncKeyState",
    "MiniDumpWriteDump",
    "InternetOpenUrl",
    "CryptEncrypt",
]
SUSPICIOUS_MACHO_SYMBOLS = ["dlopen", "ptrace", "NSTask", "system", "popen", "execve", "mprotect"]

# Section names left behind by common packers/protectors (compared lowercase).
PACKER_SECTION_NAMES = {
    "upx0", "upx1", "upx2", ".upx",
    ".aspack", ".adata",
    ".mpress1", ".mpress2",
    ".petite",
    ".nsp0", ".nsp1", ".nsp2",
    ".themida", ".winlice",
    ".vmp0", ".vmp1", ".vmp2",
    ".enigma1", ".enigma2",
    ".packed", ".rlpack", "pec2", "pec2to", ".perplex", ".spack", ".svkp", ".yp", ".boom",
}

IMAGE_SCN_MEM_EXECUTE = 0x2000_0000
IMAGE_SCN_MEM_WRITE = 0x8000_0000
DIR_RESOURCE = 2
DIR_SECURITY = 4
DIR_CLR = 14


def clamp01(value):
    return min(max(value, 0.0), 1.0)


def entropy(buf):
    """Shannon entropy in bits per byte (0..8)."""
    if not buf:
        return 0.0
    counts = np.bincount(np.frombuffer(buf, dtype=np.uint8), minlength=256).astype(np.float64)
    p = counts[counts > 0] / float(len(buf))
    return float(-(p * np.log2(p)).sum())


def features(p):
    """Normalised feature vector (all in [0, 1]); mirrors BinaryProfile::features in Rust."""
    size = p["size_bytes"]
    size_kb = max(size / 1024.0, 1.0)
    sections = p["section_count"]
    macho = p["format"] == "macho"
    risky_total = len(SUSPICIOUS_MACHO_SYMBOLS) if macho else len(SUSPICIOUS_IMPORTS)
    return [
        clamp01(math.log10(size_kb) / MAX_LOG10_SIZE_KB),
        clamp01(p["max_section_entropy"] / 8.0),
        clamp01(p["entry_section_entropy"] / 8.0),
        clamp01(sections / SECTION_COUNT_SCALE),
        clamp01(p["wx_sections"] / max(sections, 1)),
        1.0 if p["entry_anomaly"] else 0.0,
        clamp01(math.log10(1.0 + p["import_count"]) / IMPORT_LOG_SCALE),
        clamp01(len(p["suspicious_imports"]) / risky_total),
        1.0 if p["signed"] else 0.0,
        clamp01(p["overlay_bytes"] / size) if size > 0 else 0.0,
        1.0 if p["packer_sections"] else 0.0,
        clamp01(p["resource_bytes"] / size) if size > 0 else 0.0,
        1.0 if p["dotnet"] else 0.0,
        1.0 if macho else 0.0,
    ]


# Fallback scorer used when the ONNX model is missing: logistic regression over the same
# features, fitted on the training data (weights rounded to 0.5; packer names nudged to +1 so a
# packer always counts against a file) with the bias set for ~0.2% false positives on held-out
# real programs. Mirrors bin_ai.rs::HEURISTIC_BIAS / HEURISTIC_WEIGHTS; keep them identical.
HEURISTIC_BIAS = -16.0
HEURISTIC_WEIGHTS = [-2.0, 16.5, 7.5, -6.5, 7.5, 1.0, -6.0, 19.0, -2.5, -0.5, 1.0, 2.0, -1.5, -2.5]


def heuristic_score(f):
    z = HEURISTIC_BIAS + sum(w * v for w, v in zip(HEURISTIC_WEIGHTS, f))
    return 1.0 / (1.0 + math.exp(-z))


def _raw_slice(data, start, length):
    """bytes[start .. min(start + length, len)] or None, like bin_ai.rs::section_slice."""
    end = min(start + length, len(data))
    if start >= end:
        return None
    return data[start:end]


def profile_pe(data):
    """Raw facts about a PE image, or None if it does not parse. Mirrors bin_ai.rs::pe_profile."""
    import pefile  # only needed for real files (dataset build / parity check)

    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        return None
    try:
        size = len(data)
        sections = list(pe.sections)
        max_entropy = 0.0
        for s in sections:
            chunk = _raw_slice(data, s.PointerToRawData, s.SizeOfRawData)
            if chunk:
                max_entropy = max(max_entropy, entropy(chunk))

        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_index = None
        for i, s in enumerate(sections):
            span = max(s.Misc_VirtualSize, s.SizeOfRawData)
            if s.VirtualAddress <= entry < s.VirtualAddress + span:
                entry_index = i
                break
        entry_entropy = 0.0
        if entry_index is not None:
            chunk = _raw_slice(data, sections[entry_index].PointerToRawData, sections[entry_index].SizeOfRawData)
            if chunk:
                entry_entropy = entropy(chunk)
        anomaly = False
        if entry != 0:
            if entry_index is None:
                anomaly = True
            elif not sections[entry_index].Characteristics & IMAGE_SCN_MEM_EXECUTE:
                anomaly = True
            elif len(sections) > 1 and entry_index == len(sections) - 1:
                anomaly = True

        wx = sum(
            1 for s in sections
            if s.Characteristics & IMAGE_SCN_MEM_WRITE and s.Characteristics & IMAGE_SCN_MEM_EXECUTE
        )

        import_count = 0
        names = []
        for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in dll.imports:
                import_count += 1
                if imp.name:
                    names.append(imp.name.decode("latin-1"))
        risky = [needle for needle in SUSPICIOUS_IMPORTS if any(n.startswith(needle) for n in names)]

        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY

        def present(index):
            return len(dirs) > index and dirs[index].VirtualAddress > 0 and dirs[index].Size > 0

        signed = present(DIR_SECURITY)
        last_end = 0
        for s in sections:
            if s.SizeOfRawData > 0:
                last_end = max(last_end, min(s.PointerToRawData + s.SizeOfRawData, size))
        overlay = max(size - last_end, 0)
        if signed and dirs[DIR_SECURITY].VirtualAddress >= last_end:
            overlay -= min(dirs[DIR_SECURITY].Size, overlay)
        resources = min(dirs[DIR_RESOURCE].Size, size) if present(DIR_RESOURCE) else 0

        packers = []
        for s in sections:
            name = s.Name.split(b"\x00", 1)[0].decode("latin-1").lower()
            if name in PACKER_SECTION_NAMES:
                packers.append(name)

        return {
            "format": "pe",
            "size_bytes": size,
            "max_section_entropy": max_entropy,
            "entry_section_entropy": entry_entropy,
            "section_count": len(sections),
            "wx_sections": wx,
            "entry_anomaly": anomaly,
            "import_count": import_count,
            "suspicious_imports": risky,
            "signed": signed,
            "overlay_bytes": overlay,
            "packer_sections": packers,
            "resource_bytes": resources,
            "dotnet": present(DIR_CLR),
        }
    finally:
        pe.close()


def profile(**fields):
    """A profile with defaults, for prototypes and synthetic samples."""
    base = {
        "format": "pe",
        "size_bytes": 512 * 1024,
        "max_section_entropy": 6.2,
        "entry_section_entropy": 6.2,
        "section_count": 5,
        "wx_sections": 0,
        "entry_anomaly": False,
        "import_count": 150,
        "suspicious_imports": [],
        "signed": False,
        "overlay_bytes": 0,
        "packer_sections": [],
        "resource_bytes": 0,
        "dotnet": False,
    }
    base.update(fields)
    return base


# Reference programs checked against the exported model here and in the Rust test-suite
# (bin_ai.rs::tests::prototypes and tests/edr_suite.rs). Keep the numbers identical.
PROTOTYPES = {
    "signed_app": (profile(
        size_bytes=800 * 1024, max_section_entropy=6.4, entry_section_entropy=6.3, section_count=6,
        import_count=320, suspicious_imports=["IsDebuggerPresent"], signed=True,
        resource_bytes=60 * 1024,
    ), False),
    "unsigned_tool": (profile(
        size_bytes=600 * 1024, max_section_entropy=6.5, entry_section_entropy=6.4, section_count=8,
        import_count=180, suspicious_imports=["IsDebuggerPresent"], resource_bytes=5 * 1024,
    ), False),
    "packed_injector": (profile(
        size_bytes=120 * 1024, max_section_entropy=7.95, entry_section_entropy=7.92, section_count=3,
        wx_sections=2, entry_anomaly=True, import_count=6,
        suspicious_imports=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "IsDebuggerPresent"],
        packer_sections=["upx0", "upx1"], resource_bytes=2 * 1024,
    ), True),
}
