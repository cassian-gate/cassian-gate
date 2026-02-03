from __future__ import annotations

import ipaddress
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
    if _QUIET_DIE:
        # IMPORTANT: raise with the MESSAGE (string), not the int code
        # so cmd_validate can capture str(e) and put it into JSON.
        raise SystemExit(str(msg))

    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)

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

# -------------------------
# Paths for generated lab artifacts
# -------------------------

def lab_dir(lab_name: str) -> Path:
    return LABS_DIR / f"clab-{lab_name}"

def node_cfg_dir(lab_name: str, node: str) -> Path:
    return lab_dir(lab_name) / "nodes" / node

def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    # If a previous run created a directory where we expect a file, fix it.
    if path.exists() and path.is_dir():
        shutil.rmtree(path)

    path.write_text(content, encoding="utf-8")

def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data is None:
        die(f"Empty YAML file: {path}")
    return data

def topo_path_for_lab(lab_name: str) -> Path:
    p_resolved = lab_dir(lab_name) / "topology.resolved.yaml"
    if p_resolved.exists():
        return p_resolved

    p1 = lab_dir(lab_name) / "topology.yaml"
    if p1.exists():
        return p1

    return TOPO_DIR / f"{lab_name}.yaml"

def nodes_by_type(topo: dict, ntype: str) -> list[str]:
    return [n["name"] for n in topo.get("nodes", []) if n.get("type") == ntype]

