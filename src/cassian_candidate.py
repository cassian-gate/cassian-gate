from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from cassian_common import die
from cassian_artifacts import lab_dir
from cassian_runtime_container import Runtime

def _candidate_artifacts_dir(lab: str) -> Path:
    return lab_dir(lab) / "artifacts" / "apply"

def _write_candidate_apply_artifact(lab: str, node: str, rec: dict[str, Any]) -> Path:
    outdir = _candidate_artifacts_dir(lab)
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / f"{node}.apply.json"
    out.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return out

def _is_within_dir(child: Path, parent: Path) -> bool:
    # Deterministic, portable traversal guard.
    try:
        child_r = child.resolve()
        parent_r = parent.resolve()
    except Exception:
        return False
    return os.path.commonpath([str(child_r), str(parent_r)]) == str(parent_r)

def _candidate_parse_dir_or_die(topo: dict[str, Any], cand_dir: Path) -> list[dict[str, Any]]:
    """
    v1.5 deterministic candidate dir contract:

      <dir>/frr/<node>.conf
      <dir>/nft/<node>.nft
      <dir>/nft/<node>.ruleset

    Rules:
      - dir must exist
      - must contain >=1 recognized candidate file
      - reject unknown subdirs + unknown file types
      - reject path traversal (candidate files must live inside cand_dir)
      - node must exist in topology and match node.type:
          frr/*.conf -> node.type == "frr"
          nft/*.(nft|ruleset) -> node.type == "nft-fw"
      - duplicates (same node+type) -> fail fast
      - file must be non-empty (size > 0)
      - plan order is stable: sort by node name
    """
    if not cand_dir.exists():
        die(
            f"ERROR: Candidate config directory not found: {cand_dir}\n"
            "Expected: a directory containing candidate configuration files.",
            code=2,
        )

    if not cand_dir.is_dir():
        die(
            f"ERROR: Candidate config directory not found: {cand_dir}\n"
            "Expected: a directory containing candidate configuration files.",
            code=2,
        )

    nodes = topo.get("nodes", []) or []
    nodes_by_name: dict[str, dict[str, Any]] = {}
    for n in nodes:
        if isinstance(n, dict) and isinstance(n.get("name"), str):
            nodes_by_name[n["name"]] = n

    allowed_subdirs = {"frr", "nft"}
    plan: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    saw_any = False

    def _cand_misuse_invalid_structure() -> None:
        die(
            f"ERROR: Candidate config directory structure invalid: {cand_dir}\n"
            "Meaning: this candidate-config surface is unsupported or malformed for the current command/topology.\n"
            "Expected structure:\n"
            "  <dir>/\n"
            "    <node-name>/\n"
            "      <config-files>\n"
            "Support boundary:\n"
            "  - supported current surfaces: generated FRR and nft-fw candidate files only\n"
            "  - unsupported current surfaces: vendor NOS / sonic-vm candidate-config input\n"
            "See operator cheat sheet for exact structure.",
            code=2,
        )

    # Reject unknown entries at root for determinism
    for entry in sorted(cand_dir.iterdir(), key=lambda p: p.name):
        if entry.is_dir():
            if entry.name not in allowed_subdirs:
                _cand_misuse_invalid_structure()
        else:
            _cand_misuse_invalid_structure()

    frr_dir_present = False
    nft_dir_present = False
    frr_any = False
    nft_any = False

    # frr/
    frr_dir = cand_dir / "frr"
    if frr_dir.exists():
        frr_dir_present = True
        if not frr_dir.is_dir():
            _cand_misuse(f"--candidate-config: expected directory: {frr_dir}")
        for p in sorted(frr_dir.iterdir(), key=lambda x: x.name):
            if p.is_dir():
                _cand_misuse(f"--candidate-config: unexpected directory under frr/: {p.name}")
            if p.suffix != ".conf":
                _cand_misuse(f"--candidate-config: unsupported file under frr/: {p.name} (only .conf allowed)")
            if not _is_within_dir(p, cand_dir):
                _cand_misuse(f"--candidate-config: path traversal detected for file: frr/{p.name}")
            if p.stat().st_size == 0:
                _cand_misuse(f"--candidate-config: empty candidate file: frr/{p.name}")

            node = p.stem
            if node not in nodes_by_name:
                _cand_misuse(f"--candidate-config: candidate targets unknown node '{node}' (file: frr/{p.name})")
            if nodes_by_name[node].get("type") != "frr":
                _cand_misuse(f"--candidate-config: frr/{p.name} targets node '{node}' but node.type is not 'frr'")

            key = (node, "frr")
            if key in seen:
                _cand_misuse(f"--candidate-config: duplicate candidate for node '{node}' type 'frr'")
            seen.add(key)
            saw_any = True
            frr_any = True
            plan.append({"node": node, "node_type": "frr", "source_path": str(p)})

        if frr_dir_present and not frr_any:
            _cand_misuse(f"--candidate-config: directory 'frr/' exists but contains no *.conf files")

    # nft/
    nft_dir = cand_dir / "nft"
    if nft_dir.exists():
        nft_dir_present = True
        if not nft_dir.is_dir():
            _cand_misuse(f"--candidate-config: expected directory: {nft_dir}")
        for p in sorted(nft_dir.iterdir(), key=lambda x: x.name):
            if p.is_dir():
                _cand_misuse(f"--candidate-config: unexpected directory under nft/: {p.name}")
            if p.suffix not in (".nft", ".ruleset"):
                _cand_misuse(f"--candidate-config: unsupported file under nft/: {p.name} (only .nft or .ruleset allowed)")
            if not _is_within_dir(p, cand_dir):
                _cand_misuse(f"--candidate-config: path traversal detected for file: nft/{p.name}")
            if p.stat().st_size == 0:
                _cand_misuse(f"--candidate-config: empty candidate file: nft/{p.name}")

            node = p.stem
            if node not in nodes_by_name:
                _cand_misuse(f"--candidate-config: candidate targets unknown node '{node}' (file: nft/{p.name})")
            if nodes_by_name[node].get("type") != "nft-fw":
                _cand_misuse(f"--candidate-config: nft/{p.name} targets node '{node}' but node.type is not 'nft-fw'")

            key = (node, "nft-fw")
            if key in seen:
                _cand_misuse(f"--candidate-config: duplicate candidate for node '{node}' type 'nft-fw'")
            seen.add(key)
            saw_any = True
            nft_any = True
            plan.append({"node": node, "node_type": "nft-fw", "source_path": str(p)})

        if nft_dir_present and not nft_any:
            _cand_misuse(f"--candidate-config: directory 'nft/' exists but contains no *.nft or *.ruleset files")

    if not saw_any:
        die(
            f"ERROR: Candidate config directory is empty: {cand_dir}\n"
            "Expected: at least one configuration file inside the directory.",
            code=2,
        )

    plan.sort(key=lambda r: r["node"])
    return plan

def _candidate_apply_frr_generated_only(rt: Runtime, lab: str, topo: dict[str, Any], node: str, src: Path) -> dict[str, Any]:
    from cassian import _safe_stdio, _sha256_file
    """
    v1.5 invariant (LOCKED):
      - Candidate apply MUST NOT restart containers.
      - FRR candidate must be applied without changing the container lifecycle, preserving netns/interfaces.

    Behavior:
      - Enforce frr_mode: generated only (fail fast otherwise)
      - Record container ID before/after (must match)
      - (Evidence) record ip link snapshot before/after
      - Copy candidate into container WITHOUT docker-cp replace semantics
      - Deterministically detect if /etc/frr/frr.conf is RO via mount flags
         - If RO: apply via vtysh -f from /tmp (no FRR restart)
           - Sanitize config-mode wrapper lines for vtysh batch mode
           - GUARDRAIL: if sanitized file becomes empty => FAIL (no-op apply is not allowed)
         - If not RO: write file then restart FRR inside container (never docker restart)
      - Robust fallback: if write fails with "Read-only file system", switch to vtysh -f (with sanitization)
      - Postcheck: vtysh show version (required); show bgp summary (evidence-only)

    FIX (gate correctness):
      - vtysh-mode apply is successful only if vtysh -f returns exit_code == 0.
        (No heuristics, no “it seems applied anyway”.)
    """
    started = time.time()

    topo_nodes = {n.get("name"): n for n in (topo.get("nodes", []) or []) if isinstance(n, dict)}
    n = topo_nodes.get(node) or {}
    frr_mode = (n.get("frr_mode") or "generated").strip().lower()
    if frr_mode != "generated":
        finished = time.time()
        return {
            "node": node,
            "node_type": "frr",
            "method": "frr_inplace_reload",
            "input": {"source_path": str(src), "sha256": _sha256_file(src)},
            "attempt": {"started_at_epoch_ms": int(started * 1000), "duration_ms": int((finished - started) * 1000)},
            "result": {"applied_ok": False, "exit_code": 2},
            "stdout": "",
            "stderr": _safe_stdio(
                f"candidate apply: frr_mode='{frr_mode}' is unsupported; v1.5 supports candidate apply only for frr_mode: generated"
            ),
            "post_checks": [],
        }

    sha = _sha256_file(src)

    # Evidence snapshots (must not fail apply by themselves)
    container_id_before = ""
    container_id_after = ""
    interfaces_before = ""
    interfaces_after = ""

    # Deterministic timeouts for in-container operations (LOCKED)
    CAND_FRR_RELOAD_TIMEOUT_S = 60.0
    CAND_FRR_POSTCHECK_TIMEOUT_S = 10.0
    CAND_FRR_PERMS_TIMEOUT_S = 5.0
    CAND_FRR_COPY_TIMEOUT_S = 10.0
    CAND_FRR_RO_PROBE_TIMEOUT_S = 2.0
    # vtysh -f applies can legitimately take longer than simple postchecks
    CAND_FRR_VTYSH_APPLY_TIMEOUT_S = 20.0

    dst_path = "/etc/frr/frr.conf"
    tmp_path = "/tmp/netsim.candidate.frr.conf"
    tmp_vty_path = "/tmp/netsim.candidate.frr.vtysh.conf"

    def _sanitize_for_vtysh_file(tmp_in: str, tmp_out: str) -> subprocess.CompletedProcess:
        """
        Deterministic sanitization for vtysh -f batch mode.

        Principle:
          - Do NOT attempt to be clever.
          - Remove config-mode wrapper lines that are commonly present in "conf t ... end" snippets,
            because many FRR vtysh batch modes reject them and return non-zero.

        Specifically REMOVE lines that match (ignoring leading/trailing whitespace):
          - conf t
          - conf term
          - configure terminal
          - end
          - exit

        Everything else is left unchanged, in the same order.
        """
        cmd = (
            r"grep -vE '^[[:space:]]*(conf[[:space:]]+(t|term)|configure[[:space:]]+terminal|end|exit)[[:space:]]*$' "
            + f"{tmp_in} > {tmp_out}"
        )
        return rt.exec(
            lab,
            node,
            ["sh", "-lc", cmd],
            check=False,
            capture_output=True,
            timeout_s=CAND_FRR_COPY_TIMEOUT_S,
        )

    def _file_nonempty(path: str) -> subprocess.CompletedProcess:
        # `test -s` returns 0 if exists and size > 0
        return rt.exec(
            lab,
            node,
            ["sh", "-lc", f"test -s {path}"],
            check=False,
            capture_output=True,
            timeout_s=2.0,
        )

    def _cleanup_tmp_files() -> None:
        rt.exec(
            lab,
            node,
            ["sh", "-lc", f"rm -f {tmp_path} {tmp_vty_path}"],
            check=False,
            capture_output=True,
            timeout_s=2.0,
        )

    try:
        container_id_before = rt.container_id(lab, node)
    except Exception as e:
        finished = time.time()
        return {
            "node": node,
            "node_type": "frr",
            "method": "frr_inplace_reload",
            "input": {"source_path": str(src), "sha256": sha},
            "attempt": {"started_at_epoch_ms": int(started * 1000), "duration_ms": int((finished - started) * 1000)},
            "result": {"applied_ok": False, "exit_code": 1},
            "stdout": "",
            "stderr": _safe_stdio(str(e)),
            "post_checks": [],
            "container_id_before": container_id_before,
            "container_id_after": container_id_after,
        }

    try:
        cp_if0 = rt.exec(lab, node, ["ip", "-o", "link", "show"], check=False, capture_output=True, timeout_s=5.0)
        interfaces_before = _safe_stdio((cp_if0.stdout or "") + (cp_if0.stderr or ""))
    except Exception:
        interfaces_before = ""

    # -------------------------------------------------------------------------
    # Candidate delivery (no container restart).
    # -------------------------------------------------------------------------
    cp_copy_tmp = rt.copy_to_node(lab, node, src, tmp_path)

    cp_ro_probe = None
    dst_is_ro = False
    apply_method = "unknown"

    cp_copy = cp_copy_tmp
    cp_sanitize = None
    cp_sanitize_nonempty = None
    cp_vty_apply = None

    if int(getattr(cp_copy_tmp, "returncode", 1)) == 0:
        cp_ro_probe = rt.exec(
            lab,
            node,
            ["sh", "-lc", f"mount | grep -F 'on {dst_path} ' | grep -q '(ro,'"],
            check=False,
            capture_output=True,
            timeout_s=CAND_FRR_RO_PROBE_TIMEOUT_S,
        )
        dst_is_ro = (int(getattr(cp_ro_probe, "returncode", 1)) == 0)

        if dst_is_ro:
            apply_method = "vtysh"
            cp_copy = subprocess.CompletedProcess(
                args=["sh", "-lc", f"SKIP write: {dst_path} is RO"],
                returncode=0,
                stdout="skipped (dst is RO; applying via vtysh -f)",
                stderr="",
            )

            cp_sanitize = _sanitize_for_vtysh_file(tmp_path, tmp_vty_path)
            if int(getattr(cp_sanitize, "returncode", 1)) == 0:
                cp_sanitize_nonempty = _file_nonempty(tmp_vty_path)
                if int(getattr(cp_sanitize_nonempty, "returncode", 1)) == 0:
                    cp_vty_apply = rt.exec(
                        lab,
                        node,
                        ["vtysh", "-f", tmp_vty_path],
                        check=False,
                        capture_output=True,
                        timeout_s=CAND_FRR_VTYSH_APPLY_TIMEOUT_S,
                    )
                else:
                    cp_vty_apply = subprocess.CompletedProcess(
                        args=["vtysh", "-f", tmp_vty_path],
                        returncode=1,
                        stdout="",
                        stderr="sanitized candidate is empty after removing wrapper lines; refusing no-op apply",
                    )
            else:
                cp_vty_apply = subprocess.CompletedProcess(
                    args=["vtysh", "-f", tmp_vty_path],
                    returncode=1,
                    stdout="",
                    stderr="sanitize failed; not running vtysh -f",
                )
            _cleanup_tmp_files()

        else:
            apply_method = "file+frrinit"
            cp_copy = rt.exec(
                lab,
                node,
                ["sh", "-lc", f"cat {tmp_path} > {dst_path} && rm -f {tmp_path}"],
                check=False,
                capture_output=True,
                timeout_s=CAND_FRR_COPY_TIMEOUT_S,
            )

            copy_rc = int(getattr(cp_copy, "returncode", 1))
            copy_err = (getattr(cp_copy, "stderr", "") or "")
            if (copy_rc != 0) and ("Read-only file system" in copy_err):
                apply_method = "vtysh"

                # Re-copy to tmp to be deterministic (tmp may have been removed or partial).
                rt.copy_to_node(lab, node, src, tmp_path)

                cp_sanitize = _sanitize_for_vtysh_file(tmp_path, tmp_vty_path)
                if int(getattr(cp_sanitize, "returncode", 1)) == 0:
                    cp_sanitize_nonempty = _file_nonempty(tmp_vty_path)
                    if int(getattr(cp_sanitize_nonempty, "returncode", 1)) == 0:
                        cp_vty_apply = rt.exec(
                            lab,
                            node,
                            ["vtysh", "-f", tmp_vty_path],
                            check=False,
                            capture_output=True,
                            timeout_s=CAND_FRR_VTYSH_APPLY_TIMEOUT_S,
                        )
                    else:
                        cp_vty_apply = subprocess.CompletedProcess(
                            args=["vtysh", "-f", tmp_vty_path],
                            returncode=1,
                            stdout="",
                            stderr="sanitized candidate is empty after removing wrapper lines; refusing no-op apply",
                        )
                else:
                    cp_vty_apply = subprocess.CompletedProcess(
                        args=["vtysh", "-f", tmp_vty_path],
                        returncode=1,
                        stdout="",
                        stderr="sanitize failed; not running vtysh -f",
                    )
                _cleanup_tmp_files()

    # Best-effort perms (safe no-op on RO; do not gate apply)
    rt.exec(
        lab,
        node,
        [
            "sh",
            "-lc",
            "id -u frr >/dev/null 2>&1 && chown frr:frr /etc/frr/frr.conf || true; chmod 0640 /etc/frr/frr.conf || true",
        ],
        check=False,
        capture_output=True,
        timeout_s=CAND_FRR_PERMS_TIMEOUT_S,
    )

    # -------------------------------------------------------------------------
    # Reload semantics
    # -------------------------------------------------------------------------
    if apply_method == "vtysh":
        cp_reload = subprocess.CompletedProcess(
            args=["/usr/lib/frr/frrinit.sh", "restart"],
            returncode=0,
            stdout="skipped (applied via vtysh -f)",
            stderr="",
        )
        cp_clear_bgp = rt.exec(
            lab,
            node,
            ["vtysh", "-c", "clear bgp *"],
            check=False,
            capture_output=True,
            timeout_s=CAND_FRR_RELOAD_TIMEOUT_S,
        )
    else:
        cp_clear_bgp = subprocess.CompletedProcess(
            args=["vtysh", "-c", "clear bgp *"],
            returncode=0,
            stdout="skipped (file apply path)",
            stderr="",
        )
        # Only reload if file write succeeded; otherwise skip.
        file_write_ok = bool(apply_method == "file+frrinit" and int(getattr(cp_copy, "returncode", 1)) == 0)
        if not file_write_ok:
            cp_reload = subprocess.CompletedProcess(
                args=["/usr/lib/frr/frrinit.sh", "restart"],
                returncode=0,
                stdout="skipped (apply failed)",
                stderr="",
            )
        else:
            cp_has = rt.exec(
                lab,
                node,
                ["sh", "-lc", "test -x /usr/lib/frr/frrinit.sh"],
                check=False,
                capture_output=True,
                timeout_s=CAND_FRR_PERMS_TIMEOUT_S,
            )
            if cp_has.returncode == 0:
                cp_reload = rt.exec(
                    lab,
                    node,
                    ["/usr/lib/frr/frrinit.sh", "restart"],
                    check=False,
                    capture_output=True,
                    timeout_s=CAND_FRR_RELOAD_TIMEOUT_S,
                )
            else:
                cp_reload = subprocess.CompletedProcess(
                    args=["/usr/lib/frr/frrinit.sh", "restart"],
                    returncode=127,
                    stdout="",
                    stderr="missing /usr/lib/frr/frrinit.sh",
                )

    # Postchecks (deterministic)
    post: list[dict[str, Any]] = []

    post.append(
        {
            "name": "clear_bgp",
            "cmd": 'vtysh -c "clear bgp *"',
            "exit_code": int(cp_clear_bgp.returncode),
            "stdout": _safe_stdio(cp_clear_bgp.stdout or ""),
            "stderr": _safe_stdio(cp_clear_bgp.stderr or ""),
        }
    )

    cp_ver = rt.exec(
        lab,
        node,
        ["vtysh", "-c", "show version"],
        check=False,
        capture_output=True,
        timeout_s=CAND_FRR_POSTCHECK_TIMEOUT_S,
    )
    post.append(
        {
            "name": "show_version",
            "cmd": 'vtysh -c "show version"',
            "exit_code": int(cp_ver.returncode),
            "stdout": _safe_stdio(cp_ver.stdout or ""),
            "stderr": _safe_stdio(cp_ver.stderr or ""),
        }
    )

    cp_bgp = rt.exec(
        lab,
        node,
        ["vtysh", "-c", "show bgp summary"],
        check=False,
        capture_output=True,
        timeout_s=CAND_FRR_POSTCHECK_TIMEOUT_S,
    )
    post.append(
        {
            "name": "show_bgp_summary",
            "cmd": 'vtysh -c "show bgp summary"',
            "exit_code": int(cp_bgp.returncode),
            "stdout": _safe_stdio(cp_bgp.stdout or ""),
            "stderr": _safe_stdio(cp_bgp.stderr or ""),
        }
    )

    try:
        container_id_after = rt.container_id(lab, node)
    except Exception:
        container_id_after = ""

    try:
        cp_if1 = rt.exec(lab, node, ["ip", "-o", "link", "show"], check=False, capture_output=True, timeout_s=5.0)
        interfaces_after = _safe_stdio((cp_if1.stdout or "") + (cp_if1.stderr or ""))
    except Exception:
        interfaces_after = ""

    restart_detected = bool(container_id_before and container_id_after and (container_id_before != container_id_after))

    reload_ok = int(getattr(cp_reload, "returncode", 1)) == 0
    ver_ok = int(getattr(cp_ver, "returncode", 1)) == 0

    # Success criteria (strict)
    if apply_method == "vtysh":
        sanitize_ok = bool(cp_sanitize is not None and int(getattr(cp_sanitize, "returncode", 1)) == 0)
        sanitized_nonempty_ok = bool(
            cp_sanitize_nonempty is not None and int(getattr(cp_sanitize_nonempty, "returncode", 1)) == 0
        )
        vty_rc_ok = bool(cp_vty_apply is not None and int(getattr(cp_vty_apply, "returncode", 1)) == 0)
        apply_ok = bool(sanitize_ok and sanitized_nonempty_ok and vty_rc_ok and ver_ok)
    elif apply_method == "file+frrinit":
        apply_ok = bool(int(getattr(cp_copy, "returncode", 1)) == 0)
    else:
        apply_ok = False

    applied_ok = bool(apply_ok and reload_ok and ver_ok and (not restart_detected))
    if restart_detected:
        applied_ok = False

    finished = time.time()

    stderr_msg = ""
    if not apply_ok:
        if int(getattr(cp_copy_tmp, "returncode", 1)) != 0:
            stderr_msg = "candidate apply: failed to copy candidate to tmp path inside container"
        elif apply_method == "vtysh":
            stderr_msg = "candidate apply: vtysh -f apply failed (non-zero exit), sanitize failed, or sanitized file empty"
        else:
            stderr_msg = f"candidate apply: failed to write candidate to {dst_path}"
    elif int(getattr(cp_reload, "returncode", 1)) != 0:
        stderr_msg = "candidate apply: in-container FRR restart failed (/usr/lib/frr/frrinit.sh restart)"
    elif not ver_ok:
        stderr_msg = "candidate apply: postcheck failed (vtysh show version)"

    if restart_detected:
        if stderr_msg:
            stderr_msg += "; "
        stderr_msg += "candidate apply invariant violated: container restart detected (container ID changed)"

    if apply_method == "vtysh":
        copy_cmd = f"copy_to_tmp:{tmp_path}; ro_probe:mount|grep on {dst_path}|grep (ro,; sanitize->vtysh -f {tmp_vty_path}"
    else:
        copy_cmd = f"copy_to_tmp:{tmp_path}; ro_probe:mount|grep on {dst_path}|grep (ro,; write(cat >):{dst_path}"

    copy_rc = int(getattr(cp_copy, "returncode", 1))
    copy_stdout = _safe_stdio(getattr(cp_copy, "stdout", "") or "")
    copy_stderr = _safe_stdio(getattr(cp_copy, "stderr", "") or "")

    vtysh_apply_block = None
    if cp_vty_apply is not None:
        vtysh_apply_block = {
            "cmd": f"vtysh -f {tmp_vty_path}",
            "exit_code": int(getattr(cp_vty_apply, "returncode", 1)),
            "stdout": _safe_stdio(getattr(cp_vty_apply, "stdout", "") or ""),
            "stderr": _safe_stdio(getattr(cp_vty_apply, "stderr", "") or ""),
        }

    sanitize_block = None
    if cp_sanitize is not None:
        sanitize_block = {
            "cmd": f"sanitize_for_vtysh: {tmp_path} -> {tmp_vty_path}",
            "exit_code": int(getattr(cp_sanitize, "returncode", 1)),
            "stdout": _safe_stdio(getattr(cp_sanitize, "stdout", "") or ""),
            "stderr": _safe_stdio(getattr(cp_sanitize, "stderr", "") or ""),
        }

    sanitize_nonempty_block = None
    if cp_sanitize_nonempty is not None:
        sanitize_nonempty_block = {
            "cmd": f"test -s {tmp_vty_path}",
            "exit_code": int(getattr(cp_sanitize_nonempty, "returncode", 1)),
            "stdout": _safe_stdio(getattr(cp_sanitize_nonempty, "stdout", "") or ""),
            "stderr": _safe_stdio(getattr(cp_sanitize_nonempty, "stderr", "") or ""),
        }

    ro_probe_block = {
        "cmd": f"mount | grep -F 'on {dst_path} ' | grep -q '(ro,'",
        "exit_code": (int(getattr(cp_ro_probe, "returncode", 1)) if cp_ro_probe is not None else None),
        "stdout": (_safe_stdio(getattr(cp_ro_probe, "stdout", "") or "") if cp_ro_probe is not None else ""),
        "stderr": (_safe_stdio(getattr(cp_ro_probe, "stderr", "") or "") if cp_ro_probe is not None else ""),
        "dst_is_ro": bool(dst_is_ro),
    }

    return {
        "node": node,
        "node_type": "frr",
        "method": "frr_inplace_reload",
        "input": {"source_path": str(src), "sha256": sha},
        "attempt": {"started_at_epoch_ms": int(started * 1000), "duration_ms": int((finished - started) * 1000)},
        "result": {"applied_ok": applied_ok, "exit_code": (0 if applied_ok else 1)},
        "stdout": _safe_stdio(""),
        "stderr": _safe_stdio(stderr_msg),
        "post_checks": post,
        "apply_method": apply_method,
        "container_id_before": str(container_id_before),
        "container_id_after": str(container_id_after),
        "interfaces_before": str(interfaces_before),
        "interfaces_after": str(interfaces_after),
        "ro_probe": ro_probe_block,
        "copy": {
            "cmd": copy_cmd,
            "exit_code": copy_rc,
            "stdout": copy_stdout,
            "stderr": copy_stderr,
        },
        "sanitize": sanitize_block,
        "sanitize_nonempty": sanitize_nonempty_block,
        "vtysh_apply": vtysh_apply_block,
        "reload": {
            "cmd": "/usr/lib/frr/frrinit.sh restart",
            "exit_code": int(getattr(cp_reload, "returncode", 1)),
            "stdout": _safe_stdio(getattr(cp_reload, "stdout", "") or ""),
            "stderr": _safe_stdio(getattr(cp_reload, "stderr", "") or ""),
        },
    }

def _candidate_apply_nft(rt: Runtime, lab: str, node: str, src: Path) -> dict[str, Any]:
    from cassian import _safe_stdio, _sha256_file
    started = time.time()
    ruleset = src.read_text(encoding="utf-8")
    sha = _sha256_file(src)

    # Require nft exists (no runtime installs)
    cp0 = rt.exec(lab, node, ["sh", "-lc", "command -v nft >/dev/null"], check=False, capture_output=True)
    if cp0.returncode != 0:
        finished = time.time()
        return {
            "node": node,
            "node_type": "nft-fw",
            "method": "nft -f",
            "input": {"source_path": str(src), "sha256": sha},
            "attempt": {"started_at_epoch_ms": int(started * 1000), "duration_ms": int((finished - started) * 1000)},
            "result": {"applied_ok": False, "exit_code": int(cp0.returncode)},
            "stdout": _safe_stdio(cp0.stdout or ""),
            "stderr": _safe_stdio(cp0.stderr or ""),
            "post_checks": [],
        }

    cmd = (
        "set -e\n"
        "cat > /tmp/rules.nft <<'EOF'\n"
        f"{ruleset}\n"
        "EOF\n"
        "nft -f /tmp/rules.nft\n"
    )
    cp1 = rt.exec(lab, node, ["sh", "-lc", cmd], check=False, capture_output=True)
    ok = (cp1.returncode == 0)

    post: list[dict[str, Any]] = []
    cp2 = rt.exec(lab, node, ["sh", "-lc", "nft list ruleset"], check=False, capture_output=True)
    post.append({
        "name": "nft_list_ruleset",
        "cmd": "nft list ruleset",
        "exit_code": int(cp2.returncode),
        "stdout": _safe_stdio(cp2.stdout or ""),
        "stderr": _safe_stdio(cp2.stderr or ""),
    })

    finished = time.time()
    return {
        "node": node,
        "node_type": "nft-fw",
        "method": "nft -f",
        "input": {"source_path": str(src), "sha256": sha},
        "attempt": {"started_at_epoch_ms": int(started * 1000), "duration_ms": int((finished - started) * 1000)},
        "result": {"applied_ok": bool(ok), "exit_code": int(cp1.returncode)},
        "stdout": _safe_stdio(cp1.stdout or ""),
        "stderr": _safe_stdio(cp1.stderr or ""),
        "post_checks": post,
    }
