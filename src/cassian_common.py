from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
TOPO_DIR = BASE_DIR / "topologies"
LABS_DIR = BASE_DIR / "labs"
QUIET_RUN = False
_QUIET_DIE = False


DEFAULT_IMAGES = {
    "frr": "frrouting/frr:latest",
    "linux": "alpine:latest",
    "host": "alpine:latest",
    "nft-fw": "alpine:latest",
}

# -------------------------
# NOS-neutral address helpers (Phase 2 §4.5-b re-homes)
# -------------------------
# Re-homed to the ruled acyclic floor (design §3.2: model -> provider ->
# common) so the FRR provider can reach them without a provider->core import
# (W10/B12). Behaviour byte-identical; one-line re-import shims stand at the
# original sites and are owed removal at §4.5-c (BL-P2-4.5b-3).

# `_normalize_prefix`: re-homed from cassian_runtime_container:927 (A-H4/A-S4)
# -- NOS-neutral, census-invisible, dual-consumed by STAYS-core surfaces
# (engine, cassian_tests, facade) and by the relocated FRR parse family.
def _normalize_prefix(cidr: str) -> str | None:
    try:
        # Accept inputs that may already be parsed (e.g., IPv4Network) by coercing to str.
        if not isinstance(cidr, str):
            cidr = str(cidr)

        cidr = cidr.strip()
        if not cidr:
            return None

        n = ipaddress.ip_network(cidr, strict=False)
        if n.version != 4:
            return None
        return str(n)
    except Exception:
        return None

# `_RE_NEIGH_LINE` / `_RE_IPV4_PREFIX`: re-homed from cassian_tests:373-374
# per founder ruling (option A, F-45b-C1-1) -- census-invisible module-level
# data in the W10/B12 closure of the relocated parse family; NOS-neutral IPv4
# patterns (no FRR token), so common is their home on merit, following the
# A-H3 `_BGP_COMMUNITY_CANON` module-level-data re-home pattern.
_RE_NEIGH_LINE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+")
_RE_IPV4_PREFIX = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")

# -------------------------
# Shell helpers
# -------------------------

def run(
    cmd: list[str],
    check: bool = True,
    capture: bool = False,
    capture_output: bool | None = None,
    text: bool = True,
    timeout_s: float | None = None,
) -> subprocess.CompletedProcess:
    """
    Run a command deterministically.
    - capture=True is the legacy flag (captures stdout/stderr)
    - capture_output overrides capture if explicitly set
    - timeout_s maps to subprocess.run(timeout=...) (seconds)
    """
    global QUIET_RUN
    if not QUIET_RUN:
        print("+", " ".join(cmd))

    if capture_output is None:
        capture_output = capture

    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture_output,
        text=text,
        timeout=timeout_s,
    )

LAST_ERROR_MSG: str | None = None

def die(msg: str, code: int = 1) -> None:
    global _QUIET_DIE
    global LAST_ERROR_MSG

    # Record last Cassian Gate-owned error message deterministically for gate artifact emission.
    # This MUST be set even in quiet mode (where we raise SystemExit(str(msg))).
    LAST_ERROR_MSG = str(msg).strip()

    if _QUIET_DIE:
        # IMPORTANT: raise with the MESSAGE (string), not the int code
        # so cmd_validate can capture str(e) and put it into JSON.
        raise SystemExit(str(msg))

    # Avoid duplicate "ERROR:" prefix when callers already include it.
    m = str(msg)
    if m.lstrip().startswith("ERROR:"):
        print(m, file=sys.stderr)
    else:
        print(f"ERROR: {m}", file=sys.stderr)

    raise SystemExit(code)

def fail(msg: str, code: int = 1) -> None:
    """
    Human-facing gate failure (deterministic FAIL verdict), never an engine/runtime fault.
    Mirrors die() behavior but uses FAIL: prefix.
    """
    global _QUIET_DIE
    global LAST_ERROR_MSG

    # Record last Cassian Gate-owned failure message deterministically for gate artifact emission.
    LAST_ERROR_MSG = str(msg).strip()

    if _QUIET_DIE:
        # Same contract as die(): raise with the MESSAGE so callers can capture it deterministically.
        raise SystemExit(str(msg))

    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(code)

def is_wsl2() -> bool:
    """
    Deterministic environment detection.
    Used only for gating VM runtime support (fail-fast), not for behavior tweaks.
    """
    # Common signals: WSL_INTEROP, WSL_DISTRO_NAME, and /proc/version contains Microsoft.
    if os.environ.get("WSL_INTEROP") or os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        v = Path("/proc/version").read_text(errors="ignore").lower()
        return "microsoft" in v or "wsl" in v
    except Exception:
        return False

def has_kvm() -> bool:
    """
    VM runtime requires KVM for determinism.
    """
    try:
        p = Path("/dev/kvm")
        return p.exists() and os.access(str(p), os.R_OK | os.W_OK)
    except Exception:
        return False

def assert_vm_runtime_supported(vm_node: str | None = None) -> None:
    """
    Hard gate (fail-fast) when VM runtime is requested but host cannot support it deterministically.

    Contract (v1.5): Fail-fast before deploy with a stable, grep-friendly error structure.
    """
    node = (vm_node or "<unknown>").strip() if isinstance(vm_node, str) else "<unknown>"

    if is_wsl2():
        die(
            "VM runtime contract violation\n"
            f"node: {node}\n"
            "reason: unsupported environment (WSL2)\n"
            "detail: runtime=vm requires a Linux host/VM with KVM (WSL2 is unsupported)\n"
            "required: run Cassian Gate inside a Linux host/VM with KVM enabled and accessible\n"
            "notes: VM runtime is not supported on WSL2. "
            "Run Cassian Gate inside a Linux host/VM with KVM enabled (e.g., Windows Hyper-V + Ubuntu VM)."
        )

    if not has_kvm():
        die(
            "VM runtime contract violation\n"
            f"node: {node}\n"
            "reason: missing or inaccessible /dev/kvm\n"
            "detail: runtime=vm requires /dev/kvm to exist and be readable+writable\n"
            "required: enable KVM and ensure /dev/kvm is accessible (read+write) in your Linux host/VM\n"
            "notes: VM runtime requires KVM (/dev/kvm). "
            "Run on a Linux host/VM with KVM enabled and accessible."
        )

def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False

def validate_ip_literal(value: str, ctx: str) -> None:
    try:
        ipaddress.ip_address(value.strip())
    except Exception:
        die(f"{ctx}: invalid IPv4/IPv6 literal: {value!r}")

def classify_invalid_target(token: str) -> str:
    """
    Messaging-only helper. Does NOT change acceptance rules.
    Returns a short reason string for common invalid destination patterns.
    """
    t = (token or "").strip()
    if not t:
        return "empty destination"

    # IP:port (common copy/paste)
    if ":" in t:
        # If it's a pure IPv6 literal, it'll also contain ":".
        # Detect IP:port by "one colon" + numeric port and left side looks like IPv4.
        parts = t.rsplit(":", 1)
        if len(parts) == 2:
            left, right = parts[0].strip(), parts[1].strip()
            if right.isdigit() and is_ip_literal(left) and "." in left:
                return "appears to be IP:port; expected IPv4 literal only (no port)"

    # CIDR
    if "/" in t:
        left = t.split("/", 1)[0].strip()
        if is_ip_literal(left) and "." in left:
            return "appears to be CIDR; expected single IPv4 address (no /mask)"

    # IPv6 (v1.x: IPv4-only in these target contexts)
    if ":" in t and not t.count(":") == 1:
        # Heuristic: multiple colons strongly indicates IPv6
        return "appears to be IPv6; v1.x supports IPv4 only here"

    # Hostname-like (letters + dots)
    has_letter = any(ch.isalpha() for ch in t)
    if has_letter and "." in t:
        return "appears to be a hostname; DNS/hostnames are not supported (determinism)"

    # Generic fallback
    return "invalid destination (must be node name or IPv4 literal)"

def nodes_by_type(topo: dict, ntype: str) -> list[str]:
    return [n["name"] for n in topo.get("nodes", []) if n.get("type") == ntype]

