from __future__ import annotations

import shutil
from pathlib import Path

import json
import yaml

from netsim_common import LABS_DIR, TOPO_DIR, die

# -------------------------
# Paths for generated lab artifacts
# -------------------------

def lab_dir(lab_name: str) -> Path:
    return LABS_DIR / f"clab-{lab_name}"

def node_cfg_dir(lab_name: str, node: str) -> Path:
    return lab_dir(lab_name) / "nodes" / node

def _sanitize_token(s: str) -> str:
    """
    Deterministic filename token sanitizer.
    Allowed: [A-Za-z0-9._-]
    Others replaced with '_'.
    """
    out: list[str] = []
    for ch in str(s or ""):
        if ch.isalnum() or ch in "._-":
            out.append(ch)
        else:
            out.append("_")
    # avoid empty tokens
    return "".join(out) or "x"


def pcap_dir(lab_name: str, scenario_id: str) -> Path:
    """
    labs/clab-<lab>/artifacts/pcap/<scenario_id>/
    """
    return lab_dir(lab_name) / "artifacts" / "pcap" / _sanitize_token(scenario_id)


def pcap_session_paths(
    *,
    lab_name: str,
    scenario_id: str,
    step_seq: int,
    label: str | None,
    node: str,
    iface: str,
) -> tuple[Path, Path]:
    """
    Returns: (pcap_path, meta_path)
      <seq>_<label>_<node>_<iface>.pcap
      <seq>_<label>_<node>_<iface>.meta.json
    """
    seq = f"{int(step_seq):03d}"
    lab = _sanitize_token(label or "capture")
    n = _sanitize_token(node)
    i = _sanitize_token(iface)

    base = f"{seq}_{lab}_{n}_{i}"
    outdir = pcap_dir(lab_name, scenario_id)
    return (outdir / f"{base}.pcap", outdir / f"{base}.meta.json")

def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    # If a previous run created a directory where we expect a file, fix it.
    if path.exists() and path.is_dir():
        shutil.rmtree(path)

    path.write_text(content, encoding="utf-8")

def write_json_canonical(path: Path, obj: object) -> None:
    """
    Canonical JSON serialization for deterministic artifacts.

    Policy (frozen):
      - UTF-8
      - Unix newlines
      - indent=2
      - recursive key ordering (sort_keys=True)
      - final newline present (exactly one)
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    # If a previous run created a directory where we expect a file, fix it.
    if path.exists() and path.is_dir():
        shutil.rmtree(path)

    s = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)

    # Normalize newlines to Unix and enforce exactly one final newline.
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = s.rstrip("\n") + "\n"

    path.write_text(s, encoding="utf-8")

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


