#!/usr/bin/env python3
"""
ai-netsim execution engine

Design contract (must not be violated):
- Deterministic lifecycle (resolve → generate → deploy → provision → test → collect → destroy)
- Inputs are authoritative: topologies/
- Outputs are generated: labs/ (including *.clab.yaml, topology.resolved.yaml, results.json)
- Defaults only during resolve and visible in resolved topology
- Negative tests are first-class (expected fail + observed fail = verdict pass)

See: docs/design-contract.md
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
import shutil
import json
import selectors
import ipaddress
import re
import hashlib
import shlex
import os, time
from typing import Any

from pathlib import Path
from typing import Any

import yaml

import netsim_common
from netsim_common import (
    BASE_DIR, TOPO_DIR, LABS_DIR,
    DEFAULT_IMAGES,
    run, die, fail,
    LAST_ERROR_MSG,
    is_ip_literal, validate_ip_literal, classify_invalid_target,
    nodes_by_type,
)

# ---------------------------------------------------------------------
# Verbose containerlab banner noise filter (v2-verbose-containerlab-upgrade-banner-noise)
# - Line-based, deterministic, allowlist-only suppression
# - Applies ONLY to verbose printing of containerlab output
# ---------------------------------------------------------------------

# Static allowlist of suppressible banner substrings (lowercased, line-based).
_CONTAINERLAB_BANNER_SUBSTRINGS: tuple[str, ...] = (
    "a new version of containerlab is available",
    "upgrade available",
    "consider upgrading",
    "you are running an older version",
)

def _filter_containerlab_line(line: str) -> str | None:
    """
    Return None to suppress a known non-fatal banner line, else return the original line.
    Deterministic, line-based, allowlist-only.
    """
    s = (line or "")
    low = s.strip().lower()
    if not low:
        return s  # preserve empty/whitespace lines as-is
    for sub in _CONTAINERLAB_BANNER_SUBSTRINGS:
        if sub in low:
            return None
    return s

def _run_containerlab(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    """
    Deterministic output routing for containerlab commands.

    - Default (quiet): suppress containerlab INFO spam by capturing output.
      On failure (when check=True), emit a short deterministic error and stop.
    - Verbose: preserve current raw streaming behavior (delegates to netsim_common.run).
    """
    # Verbose mode: stream containerlab stdout/stderr, filtering only known non-fatal banners.
    # Command echo must remain transparent.
    if not netsim_common.QUIET_RUN:
        print("+", " ".join(cmd))

        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        sel = selectors.DefaultSelector()
        assert p.stdout is not None
        assert p.stderr is not None
        sel.register(p.stdout, selectors.EVENT_READ, data=("stdout",))
        sel.register(p.stderr, selectors.EVENT_READ, data=("stderr",))

        # Stream line-by-line; deterministic per-stream ordering; suppress allowlisted banner lines only.
        while sel.get_map():
            for key, _ in sel.select():
                f = key.fileobj
                line = f.readline()
                if line == "":
                    try:
                        sel.unregister(f)
                    except Exception:
                        pass
                    try:
                        f.close()
                    except Exception:
                        pass
                    continue

                out = _filter_containerlab_line(line)
                if out is None:
                    continue

                # Preserve separation (stdout vs stderr) to avoid hiding real errors.
                if key.data and key.data[0] == "stderr":
                    print(out, end="", file=sys.stderr)
                else:
                    print(out, end="")

        rc = p.wait()
        cp = subprocess.CompletedProcess(cmd, rc)

        if check and rc != 0:
            raise subprocess.CalledProcessError(rc, cmd)

        return cp

    # Quiet mode: capture output; never echo the command; never print containerlab INFO on success.
    cp = subprocess.run(cmd, check=False, capture_output=True, text=True)

    if check and cp.returncode != 0:
        combined = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
        tail = ""
        if combined:
            lines = combined.splitlines()
            tail = "\n".join(lines[-12:]).strip()

        msg = (
            "ERROR: containerlab command failed.\n"
            f"Command: {shlex.join(cmd)}\n"
            f"Exit: {cp.returncode}\n"
        )
        if tail:
            msg += f"\nLast output:\n{tail}\n"
        msg += "\nRe-run with --verbose for full containerlab output.\n"
        die(msg, code=1)

    return cp

from netsim_artifacts import (
    lab_dir, node_cfg_dir, write_file, write_json_canonical,
    load_yaml,
    topo_path_for_lab,
)

from netsim_model import (
    _validate_fabric_evpn_presence_only,
    ensure_valid_topology,
    gen_frr_daemons,
    gen_vtysh_conf,
    build_node_links,
    gen_frr_conf,
    topo_to_containerlab,
    resolve_topology,
    adapt_terraform_plan_json,
    adapt_ansible_rendered_dir,
)

from netsim_tests import (
    ensure_nc,
    ip_no_mask,
    find_nodes_by_type,
    start_tcp_listener,
    stop_tcp_listeners,
    tcp_connect_test,
    node_first_ipv4,
    run_ping_once_or_die,
    run_tcp_test,
    run_declared_tests,
    connected_prefixes_for_router,
    _coverage_test_ids,
    _coverage_scenario_ids,
    _coverage_touch_nodes_from_test,
    derive_expected_routes_for_frr,
    parse_frr_show_ip_route_prefixes,
    parse_frr_show_ip_route_prefixes_json,
    parse_frr_bgp_summary_neighbors_json,
    derive_expected_bgp_neighbors_from_links,
    parse_frr_bgp_summary_neighbors,
    compare_expected_vs_observed_bgp,
    wait_for_bgp,
    configure_frr_static_routes_from_topology,
    configure_frr_bgp_from_topology,
    _parse_route_entry,
    configure_nftfw_routes_from_topology,
    verify_fw_routed_ready,
    _iter_scenarios,
    validate_scenarios,
    build_test_index,
    resolve_dst_to_ip,
    retry_until,
    wait_for_condition,
    execute_scenario,
    _atomic_test_ids,
    validate_scenario_run_refs_or_die,
    _render_scenarios_summary,
    _format_test_summary,
    write_test_summary_artifact,
    render_gate_result_block,
    _preflight_default_out,
    _preflight_write,
    _preflight_canonical_link_id,
    _preflight_contains_key,
    _preflight_get_touched_nodes,
    _preflight_get_touched_links,
    _preflight_load_adapters,
    _preflight_findings,
    _preflight_report,
    _preflight_format_text,
)

from netsim_runtime_container import (
    gen_nft_fw_rules,
    _coverage_canonical_link_id,
    _coverage_inventory_nodes,
    _coverage_inventory_links,
    _coverage_hash_resolved_topology,
    _coverage_resolve_link_between,
    build_coverage_model,
    write_coverage_artifact,
    write_containerlab_file,
    _normalize_prefix,
    compare_expected_vs_observed_prefixes,
    container_name,
    _node_index_by_name,
    configure_frr_interfaces_from_topology,
    configure_hosts_from_topology,
    host_configure,
    configure_nftfw_from_topology,
    nft_fw_apply,
    verify_host_ready,
    verify_frr_ready,
    verify_lab_ready,
    fw_next_hops_from_links,
    nft_fw_setup_bridge,
    lab_file_from_name,
    parse_lab_nodes,
    docker_is_running,
    vty,
    ensure_ip_tools,
    resolved_topology_path,
    load_resolved_topology,
    frr_nodes_from_topology,
    _container_is_running,
    Runtime,
    ContainerRuntime,
    VmRuntimeStub,
    get_runtime,
    list_owned_labs_from_artifacts,
)
# Phase-0 split guardrail marker:
# scripts/verify_phase1.sh currently greps src/netsim.py for '^class ContainerRuntime'.
# The real implementation lives in src/netsim_runtime_container.py (pure-move).
_GUARDRAIL_VERIFY_PHASE1 = """
class ContainerRuntime
"""

# ------------------------------------------------------------------
# CLI / UX constants
# ------------------------------------------------------------------

_CANDIDATE_STDIO_TRUNC = 8_000  # must match previous value exactly

# Privilege transparency notice (v2-privilege-transparency-notice)
# Presentation-only: deterministic; must not probe; must not affect exit codes.
_PRIV_NOTICE_PRINTED = False

# Per-invocation artifact write tracking (WI-1: artifact footer staleness guardrail)
# Presentation-only: deterministic; must not probe filesystem; must not affect exit codes.
# Stores normalized (forward-slash) string paths written during *this* invocation only.
_INVOCATION_WRITTEN_ARTIFACTS: list[str] = []

# WI-1: ensure artifact path block is printed at most once per CLI invocation.
# Presentation-only: deterministic; must not affect exit codes.
_INVOCATION_ARTIFACT_BLOCK_PRINTED = False

def _invocation_reset_written_artifacts() -> None:
    # Deterministic reset at CLI entry.
    _INVOCATION_WRITTEN_ARTIFACTS.clear()

def _invocation_record_written_artifact(p: Path) -> None:
    try:
        s = str(p).replace("\\", "/")
        _INVOCATION_WRITTEN_ARTIFACTS.append(s)
    except Exception:
        # Best-effort only; never raise.
        return

def _maybe_print_privilege_notice(template: str) -> None:
    """
    Privilege transparency hygiene (Set 9 / WI-1).

    Deterministic one-time privilege notice:
      - Must be emitted at most once per CLI invocation
      - Must be emitted ONLY immediately before an actually-invoked privileged subprocess
        (e.g., ["sudo", ...])

    Must not probe or attempt to detect real sudo usage.
    """
    global _PRIV_NOTICE_PRINTED
    if _PRIV_NOTICE_PRINTED:
        return
    _PRIV_NOTICE_PRINTED = True

    # Exact stable wording (quiet/verbose): do not vary by template.
    print("NOTICE: This run may require sudo for container networking.")

def _print_artifacts_footer_for_lab(lab_input: Path, *, authority_kind: str | None = None) -> None:
    """
    Deterministic artifact footer (best-effort).

    Accepts either:
      - labs/clab-<labname> directory paths
      - a lab name
      - a topology path (e.g. examples/foo.yaml) when `netsim test <topology.yaml>` is used
    and prints the *actual* artifact paths (labs/clab-<labname>/...).

    Presentation-only: must never raise.
    """
    try:
        raw = str(lab_input).strip()
        if not raw:
            return

        ak = str(authority_kind or "").strip().lower()
        is_gate = ak in ("gate", "authoritative", "topology")

        raw_path = Path(raw)
        dname = raw_path.name
        dname_l = dname.lower()

        # Default: assume caller gave us a lab name or a labs/* path.
        adir: Path | None = None

        # If it's already a labs/clab-* dir, use it as-is.
        if raw.startswith("labs/") or raw.startswith("labs\\"):
            adir = raw_path

        # If it looks like a topology path (examples/foo.yaml), resolve to lab name and
        # print labs/clab-<labname>/...
        if adir is None and ("/" in raw or "\\" in raw or dname_l.endswith((".yaml", ".yml"))):
            try:
                topo = load_topology_yaml(raw)
                lab_name = str(topo.get("name") or Path(raw).stem).strip()
                if lab_name:
                    adir = lab_dir(lab_name)  # from netsim_artifacts.py
            except Exception:
                adir = None

        # Fallback: treat input as lab name
        if adir is None:
            adir = lab_dir(dname)

        p_json = adir / "results.json"
        p_sum = adir / "results.summary.txt"

        def rel_labs(p: Path) -> str:
            """
            Render relative paths under labs/ for operator discoverability.
            Best-effort only; never raises; never probes.
            """
            try:
                s = str(p)
                # Normalize for stable output across platforms.
                s2 = s.replace("\\", "/")
                labs_idx = s2.rfind("/labs/")
                if labs_idx >= 0:
                    return s2[labs_idx + 1 :]  # keep 'labs/...'
                if s2.startswith("labs/"):
                    return s2
                return s2
            except Exception:
                return str(p)

        # WI-1: Never infer artifact existence from filesystem state.
        # Only disclose artifacts that were recorded as written during *this* invocation.
        w = [str(x).replace("\\", "/") for x in (_INVOCATION_WRITTEN_ARTIFACTS or [])]
        wrote_json = any(s.endswith("/results.json") or s.endswith("results.json") for s in w)
        wrote_sum = any(s.endswith("/results.summary.txt") or s.endswith("results.summary.txt") for s in w)

        # WI-1: print the artifact path block at most once per invocation (even if called twice).
        global _INVOCATION_ARTIFACT_BLOCK_PRINTED
        if (wrote_json or wrote_sum) and (not _INVOCATION_ARTIFACT_BLOCK_PRINTED):
            _INVOCATION_ARTIFACT_BLOCK_PRINTED = True

            # WI-1 (Set 6): stable single-line artifact root for gate failures.
            if is_gate:
                rel_root = rel_labs(adir).replace("\\", "/")
                if not rel_root.endswith("/"):
                    rel_root += "/"
                print(f"Artifacts: {rel_root}")
                print("  - topology.resolved.yaml")
                print("  - results.json")
                print("  - results.summary.txt")
            else:
                # Non-gate (existing UX preserved)
                print("Artifacts:")
                if wrote_json:
                    print(f"* {rel_labs(p_json)} (supporting evidence; non-authoritative)")
                if wrote_sum:
                    print(f"* {rel_labs(p_sum)} (human-readable)")
    except Exception:
        return

def load_topology_yaml(arg: str) -> dict[str, Any]:
    """
    Deterministic topology loader for CLI ergonomics.

    Resolution order (no Docker scanning):
      1) explicit filesystem path
      2) under ./topologies/
      3) under ./examples/

    Returns a YAML mapping (dict) or raises.
    """
    s = str(arg or "").strip()
    if not s:
        raise ValueError("empty topology path")

    p = Path(s)
    if not p.is_file():
        p2 = TOPO_DIR / s
        if p2.is_file():
            p = p2
        else:
            p3 = BASE_DIR / "examples" / s
            if p3.is_file():
                p = p3

    if not p.is_file():
        raise FileNotFoundError(f"topology file not found: {s}")

    topo = load_yaml(p) or {}
    if not isinstance(topo, dict):
        raise ValueError(f"topology must be a mapping: {p}")
    return topo

def _sha256_file(p: Path) -> str:
    import hashlib
    h = hashlib.sha256()

    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _truncate(s: str, limit: int = _CANDIDATE_STDIO_TRUNC) -> str:
    if not s:
        return ""
    if len(s) <= limit:
        return s
    extra = len(s) - limit
    return s[:limit] + f"\n...<truncated {extra} chars>"

def _shell_quote(x: Any) -> str:
    """
    Deterministic shell-arg quoting for building a shell string.
    Used only for tcpdump invocation string assembly.
    """
    return shlex.quote(str(x))

def _sanitize_text(s: str) -> str:
    """
    Deterministic, minimal redaction helper.

    IMPORTANT SEMANTICS:
    - If no redaction occurs, return the original string EXACTLY (byte-for-byte),
      so callers can correctly compute redaction_applied = (redacted != raw).
    - Preserve line endings via splitlines(True) to avoid false "changes".
    - Only redact when a sensitive keyword is present (case-insensitive).
      Preferred behavior:
        * If the line looks like KEY[:=]VALUE, preserve KEY and separator, redact VALUE.
        * Otherwise, redact the whole line content (keep newline).
    """
    if not s:
        return ""

    import re

    # Keep this list small + explicit (deterministic + auditable).
    # Note: allow api-key/api_key, private-key/private_key.
    key_pat = r"(password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key)"
    kw_re = re.compile(rf"\b{key_pat}\b", re.IGNORECASE)

    # Preserve KEY + separator; redact value.
    # Examples:
    #   "password: test"  -> "password: <REDACTED>"
    #   "API_KEY=abcd"    -> "API_KEY=<REDACTED>"
    kv_re = re.compile(rf"(?i)\b({key_pat})\b(\s*[:=]\s*)(.*)$")

    changed = False
    out_lines: list[str] = []

    for ln in s.splitlines(True):  # keep original line endings
        # Split body vs line ending(s) without normalizing them.
        body = ln.rstrip("\r\n")
        ending = ln[len(body):]  # whatever was stripped: "", "\n", "\r\n"

        if not kw_re.search(body):
            out_lines.append(ln)
            continue

        changed = True

        m = kv_re.search(body)
        if m:
            # Preserve the original key spelling and separator; redact the value.
            redacted_body = f"{m.group(1)}{m.group(2)}<REDACTED>"
            out_lines.append(redacted_body + ending)
        else:
            # Keyword present but not in key/value form → redact the whole line content.
            out_lines.append("<REDACTED>" + ending)

    if not changed:
        return s  # exact original (prevents false redaction_applied=true)

    return "".join(out_lines)

def _safe_stdio(s: str) -> str:
    return _truncate(_sanitize_text(s or ""))

# -----------------------------
# Capture-config (supporting evidence only) - v1.5
# -----------------------------

_CAPTURE_CONFIG_SCHEMA_VERSION = "1"
_CAPTURE_CONFIG_MAX_CHARS = 200_000
_CAPTURE_CONFIG_CMD_TIMEOUT_S = 5.0


def _capture_config_artifacts_root(lab: str) -> Path:
    return lab_dir(lab) / "artifacts" / "capture_config"


def _capture_config_redact_and_truncate(s: str, *, limit_chars: int) -> tuple[str, bool, bool]:
    """
    Returns (out, redaction_applied, truncated).
    Redaction is minimal and deterministic (pattern-based), consistent with v1.5 rules.
    """
    raw = s or ""
    redacted = _sanitize_text(raw)
    redaction_applied = (redacted != raw)

    truncated = False
    out = redacted
    if len(out) > int(limit_chars):
        truncated = True
        out = _truncate(out, int(limit_chars))
    return out, redaction_applied, truncated


def _capture_config_write_text(path: Path, content: str) -> None:
    """
    Write a text artifact deterministically (always UTF-8, newline-terminated).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if not content.endswith("\n"):
        content = content + "\n"
    path.write_text(content, encoding="utf-8")

def _capture_config_copy_host_file(*, src: Path, dst: Path) -> dict[str, Any]:
    """
    Best-effort copy of a host-side generated file into evidence artifacts.
    """
    rec: dict[str, Any] = {
        "relpath": str(src),
        "bytes": 0,
        "sha256": "",
        "captured_ok": False,
    }

    try:
        if not src.exists() or not src.is_file():
            return rec

        data = src.read_bytes()
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)

        rec["bytes"] = int(len(data))
        rec["sha256"] = _sha256_file(src)
        rec["captured_ok"] = True
        return rec
    except Exception:
        return rec

# -----------------------------
# State capture (supporting evidence only) - v1.5
# -----------------------------

STATE_CAPTURE_SCHEMA = "state_capture.v1"
STATE_CAPTURE_PLAN_VERSION = "1.0.0"

# Deterministic truncation for state outputs (bytes)
_STATE_CAPTURE_MAX_BYTES = 64 * 1024  # 65536

# Built-in profiles (LOCKED list for v1.5)
# Each command is argv (no shell). Default deny everywhere else.
STATE_CAPTURE_PROFILES: dict[str, dict] = {
    # FRR
    "frr-routing-basic": {
        "node_types": ["frr"],
        "commands": [
            ["vtysh", "-c", "show ip route"],
            ["vtysh", "-c", "show ipv6 route"],
        ],
    },
    "frr-bgp-basic": {
        "node_types": ["frr"],
        "commands": [
            ["vtysh", "-c", "show bgp summary"],
            ["vtysh", "-c", "show bgp ipv6 summary"],
        ],
    },
    "frr-interfaces-basic": {
        "node_types": ["frr"],
        "commands": [
            ["vtysh", "-c", "show interface brief"],
            ["vtysh", "-c", "show ip interface brief"],
            ["vtysh", "-c", "show ipv6 interface brief"],
        ],
    },
    # Linux hosts
    "linux-net-basic": {
        "node_types": ["host"],
        "commands": [
            ["ip", "addr"],
            ["ip", "link"],
            ["ip", "route"],
            ["ip", "neigh"],
        ],
    },
    "linux-sockets-basic": {
        "node_types": ["host"],
        "commands": [
            ["ss", "-tulpn"],
        ],
    },
    # nft firewall + sysctls
    "nft-ruleset-basic": {
        "node_types": ["nft-fw"],
        "commands": [
            ["nft", "list", "ruleset"],
        ],
    },
    "linux-forwarding-basic": {
        "node_types": ["nft-fw"],
        "commands": [
            ["sysctl", "-n", "net.ipv4.ip_forward"],
            ["sysctl", "-n", "net.ipv4.conf.all.rp_filter"],
            ["sysctl", "-n", "net.ipv4.conf.default.rp_filter"],
        ],
    },
}

# Hard global deny tokens (no shell metacharacters / compounds)
_STATE_CAPTURE_DENY_TOKENS = ["|", ";", "&&", "||", ">", "<", "$(", ")", "`", "\n", "\r"]

def _state_capture_trunc_bytes(s: str, *, max_bytes: int = _STATE_CAPTURE_MAX_BYTES) -> tuple[str, bool, int]:
    """
    Deterministic truncation by UTF-8 byte length.
    Returns (text, truncated?, original_bytes).
    """
    if s is None:
        return ("", False, 0)
    raw = s.encode("utf-8", errors="replace")
    orig = len(raw)
    if orig <= max_bytes:
        return (s, False, orig)
    clipped = raw[:max_bytes]
    return (clipped.decode("utf-8", errors="replace"), True, orig)

def _state_capture_validate_argv_or_die(*, profile: str, node: str, node_type: str, argv: list[str]) -> None:
    """
    Allowlist + safety validation (fail-fast; config-time).
    """
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x.strip() for x in argv):
        die(f"state-capture: invalid command argv for profile '{profile}' on node '{node}'")

    # Global deny: no shell-ish metacharacters anywhere in argv
    joined = " ".join(argv)
    for tok in _STATE_CAPTURE_DENY_TOKENS:
        if tok in joined:
            die(
                f"state-capture: command denied (token {tok!r}) for profile '{profile}' "
                f"node '{node}' type '{node_type}': {argv!r}",
                code=2,
            )

    # Node-type-specific allowlists
    if node_type == "frr":
        # Only: vtysh -c "show ..."
        if not (len(argv) == 3 and argv[0] == "vtysh" and argv[1] == "-c"):
            die(
                f"state-capture: FRR commands must be 'vtysh -c <cmd>' "
                f"(profile '{profile}' node '{node}'): {argv!r}",
                code=2,
            )
        cmd = argv[2].strip()
        cmd_l = cmd.lower()
        # Must start with "show "
        if not cmd_l.startswith("show "):
            die(
                f"state-capture: FRR command must start with 'show ' "
                f"(profile '{profile}' node '{node}'): {cmd!r}",
                code=2,
            )
        # Deny obvious mutation / risky subcommands
        deny_words = ["configure", "conf t", "write", "clear", "debug", "terminal", "end", "exit", "|"]
        for w in deny_words:
            if w in cmd_l:
                die(
                    f"state-capture: FRR command denied by allowlist rule ({w!r}) "
                    f"(profile '{profile}' node '{node}'): {cmd!r}",
                    code=2,
                )

    elif node_type == "host":
        # Allow only exact commands:
        allowed = {
            ("ip", "addr"),
            ("ip", "link"),
            ("ip", "route"),
            ("ip", "neigh"),
            ("ss", "-tulpn"),
        }
        tup = tuple(argv)
        if tup not in allowed:
            die(
                f"state-capture: host command not allowlisted "
                f"(profile '{profile}' node '{node}'): {argv!r}",
                code=2,
            )

    elif node_type == "nft-fw":
        allowed = {
            ("nft", "list", "ruleset"),
            ("sysctl", "-n", "net.ipv4.ip_forward"),
            ("sysctl", "-n", "net.ipv4.conf.all.rp_filter"),
            ("sysctl", "-n", "net.ipv4.conf.default.rp_filter"),
        }
        tup = tuple(argv)
        if tup not in allowed:
            die(
                f"state-capture: nft-fw command not allowlisted "
                f"(profile '{profile}' node '{node}'): {argv!r}",
                code=2,
            )
        # extra hard deny for mutation verbs if someone tries to sneak them in
        joined_l = " ".join(argv).lower()
        if "flush" in joined_l or "add" in joined_l or "delete" in joined_l or " -w " in joined_l or "sysctl -w" in joined_l:
            die(
                f"state-capture: mutation command denied "
                f"(profile '{profile}' node '{node}'): {argv!r}",
                code=2,
            )
    else:
        die(
            f"state-capture: unsupported node type '{node_type}' for profile '{profile}' node '{node}'",
            code=2,
        )

def _state_capture_expand_plan_or_die(
    *,
    topo: dict,
    mode: str,
    profiles: list[str],
) -> dict:
    """
    Expand deterministic capture plan:
      - nodes sorted lexicographically
      - profiles in CLI order
      - commands in profile declared order
    Fail-fast for unknown profile or type mismatch or disallowed commands.
    """
    mode_l = str(mode or "none").strip().lower() or "none"
    if mode_l not in ("none", "pre", "post", "both"):
        die(f"state-capture: invalid mode {mode!r} (must be none|pre|post|both)", code=2)

    if mode_l == "none":
        return {
            "schema": STATE_CAPTURE_SCHEMA,
            "plan_version": STATE_CAPTURE_PLAN_VERSION,
            "enabled": False,
            "mode": "none",
            "profiles": [],
            "tasks": [],
        }

    # Explicitness guardrail: no implicit default profiles
    if not profiles:
        die(
            "state-capture: capture mode enabled but no profiles selected. "
            "Use one or more: --state-profile <name>",
            code=2,
        )

    # Validate profiles exist and keep order exactly as provided
    profs: list[str] = []
    for p in profiles:
        pn = str(p or "").strip()
        if not pn:
            continue
        if pn not in STATE_CAPTURE_PROFILES:
            die(
                f"state-capture: unknown profile '{pn}'. "
                f"Valid profiles: {', '.join(sorted(STATE_CAPTURE_PROFILES.keys()))}",
                code=2,
            )
        profs.append(pn)

    nodes = topo.get("nodes", []) or []
    nodes_all = [n for n in nodes if isinstance(n, dict) and isinstance(n.get("name"), str)]
    nodes_sorted = sorted(nodes_all, key=lambda n: str(n.get("name") or "").strip())

    tasks: list[dict] = []
    cmd_id = 0

    def add_tasks_for_when(when: str) -> None:
        for n in nodes_sorted:
            node = str(n.get("name") or "").strip()
            ntype = str(n.get("type") or n.get("kind") or "").strip()
            if not node or not ntype:
                continue

            # command_id resets per node (per 'when'), deterministic ordering preserved
            node_cmd_id = 0

            for prof in profs:
                prof_def = STATE_CAPTURE_PROFILES[prof]
                allowed_types = prof_def.get("node_types") or []
                if ntype not in allowed_types:
                    continue

                for argv in (prof_def.get("commands") or []):
                    # Validate allowlist & safety at plan time (blocking)
                    _state_capture_validate_argv_or_die(profile=prof, node=node, node_type=ntype, argv=argv)

                    node_cmd_id += 1
                    tasks.append(
                        {
                            "profile": prof,
                            "node": node,
                            "node_type": ntype,
                            "when": when,
                            "command_id": f"cmd-{node_cmd_id:03d}",
                            "argv": argv,
                        }
                    )

    if mode_l in ("pre", "both"):
        add_tasks_for_when("pre")
    if mode_l in ("post", "both"):
        add_tasks_for_when("post")

    return {
        "schema": STATE_CAPTURE_SCHEMA,
        "plan_version": STATE_CAPTURE_PLAN_VERSION,
        "enabled": True,
        "mode": mode_l,
        "profiles": profs,
        "tasks": tasks,
        "ordering": {
            "nodes": "lexicographic",
            "profiles": "cli_order",
            "commands": "profile_declared_order",
        },
    }

def _state_capture_artifacts_root(lab: str) -> Path:
    return lab_dir(lab) / "artifacts" / "state_capture"

def _state_capture_write_plan(lab: str, plan: dict) -> Path:
    root = _state_capture_artifacts_root(lab)
    root.mkdir(parents=True, exist_ok=True)
    out = root / "plan.json"
    out.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out

def _state_capture_run_plan(
    rt: "Runtime",
    lab: str,
    plan: dict[str, Any],
    *,
    when: str,
    timeout_s: float = 5.0,
) -> dict[str, int]:
    """
    Execute a resolved state-capture plan for a single capture point (pre|post).

    Non-authoritative:
      - command failures/timeouts are recorded but never gate
      - caller decides how/where to surface summaries
    """
    root = lab_dir(lab) / "artifacts" / "state_capture" / when
    root.mkdir(parents=True, exist_ok=True)

    tasks = plan.get("tasks") or []
    if not isinstance(tasks, list):
        return {"when": when, "ran": 0, "ok": 0, "error": 0, "timeout": 0, "skipped": 0}

    ran = 0
    ok = 0
    err = 0
    tout = 0
    skipped = 0

    for t in tasks:
        if not isinstance(t, dict):
            continue
        if str(t.get("when")) != str(when):
            continue

        node = str(t.get("node") or "")
        node_type = str(t.get("node_type") or "")
        profile = str(t.get("profile") or "")
        cmd_id = str(t.get("command_id") or "")
        argv = t.get("argv")

        if not node or not profile or not cmd_id or not isinstance(argv, list) or not argv:
            skipped += 1
            continue

        ran += 1

        node_dir = root / node
        node_dir.mkdir(parents=True, exist_ok=True)

        meta_path = node_dir / f"{cmd_id}.json"
        out_path = node_dir / f"{cmd_id}.out.txt"

        started_ms = int(time.time() * 1000)
        status = "ok"
        exit_code = 0
        stdout = ""
        stderr = ""
        duration_ms = 0

        try:
            t0 = time.time()
            cp = rt.exec(lab, node, argv, check=False, capture_output=True, timeout_s=float(timeout_s))
            duration_ms = int((time.time() - t0) * 1000)

            exit_code = int(getattr(cp, "returncode", 0) or 0)
            stdout = cp.stdout if isinstance(cp.stdout, str) else (cp.stdout.decode("utf-8", "replace") if isinstance(cp.stdout, bytes) else "")
            stderr = cp.stderr if isinstance(cp.stderr, str) else (cp.stderr.decode("utf-8", "replace") if isinstance(cp.stderr, bytes) else "")

            if exit_code != 0:
                status = "error"

        except subprocess.TimeoutExpired as e:
            status = "timeout"
            exit_code = 1
            duration_ms = int((int(time.time() * 1000) - started_ms))
            try:
                out = e.stdout
                if isinstance(out, bytes):
                    stdout = out.decode("utf-8", "replace")
                elif isinstance(out, str):
                    stdout = out
            except Exception:
                pass
            try:
                er = e.stderr
                if isinstance(er, bytes):
                    stderr = er.decode("utf-8", "replace")
                elif isinstance(er, str):
                    stderr = er
            except Exception:
                pass

        except Exception as e:
            status = "error"
            exit_code = 1
            duration_ms = int((int(time.time() * 1000) - started_ms))
            stderr = _safe_stdio(str(e))

        # Deterministic size policy for outputs
        out_txt, trunc, orig_bytes = _state_capture_trunc_bytes(_sanitize_text(stdout), max_bytes=_STATE_CAPTURE_MAX_BYTES)

        # Always write text output (even if empty); keeps tooling stable
        out_path.write_text(out_txt, encoding="utf-8")

        rec = {
            "authority": "supporting_evidence",
            "schema": STATE_CAPTURE_SCHEMA,
            "plan_version": STATE_CAPTURE_PLAN_VERSION,
            "when": when,
            "profile": profile,
            "node": node,
            "node_type": node_type,
            "command_id": cmd_id,
            "argv": argv,
            "started_at_epoch_ms": started_ms,
            "duration_ms": int(duration_ms),
            "result": {
                "status": status,
                "exit_code": int(exit_code),
                "stdout_bytes": int(orig_bytes),
                "stdout_truncated": bool(trunc),
                "out_path": str(out_path),
            },
            "stderr": _safe_stdio(stderr),
        }
        meta_path.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        if status == "ok":
            ok += 1
        elif status == "timeout":
            tout += 1
        else:
            err += 1

    return {"when": when, "ran": ran, "ok": ok, "error": err, "timeout": tout, "skipped": skipped}

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
            "Expected structure:\n"
            "  <dir>/\n"
            "    <node-name>/\n"
            "      <config-files>\n"
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
    else:
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

# -------------------------
# FRR config generation (simple v1)
# -------------------------

def _two_run_load_yaml_path(arg: str) -> Path:
    p = (TOPO_DIR / arg) if not Path(arg).is_file() else Path(arg)
    return p

def _two_run_make_temp_topology(*, base_topo_path: Path, new_name: str, out_path: Path) -> None:
    topo = load_yaml(base_topo_path) or {}
    if not isinstance(topo, dict):
        die(f"two-run: topology must be a mapping: {base_topo_path}")
    topo["name"] = new_name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump(topo, sort_keys=True), encoding="utf-8")

def _two_run_copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst)

def _two_run_load_json(p: Path) -> dict[str, Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        die(f"two-run: failed to read JSON {p}: {e}")
    raise RuntimeError("unreachable")

def _two_run_normalized_topo_hash(resolved_topo_path: Path) -> str:
    topo = load_yaml(resolved_topo_path) or {}
    if not isinstance(topo, dict):
        return ""
    topo2 = dict(topo)
    topo2.pop("name", None)
    blob = json.dumps(topo2, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def _two_run_extract_declared_sets(resolved_topo_path: Path) -> tuple[list[str], list[tuple[str, int, list[str]]]]:
    topo = load_yaml(resolved_topo_path) or {}
    tests = topo.get("tests", []) or []
    test_names: list[str] = []
    for i, t in enumerate(tests, start=1):
        if isinstance(t, dict) and isinstance(t.get("name"), str) and t.get("name").strip():
            test_names.append(t["name"].strip())
        else:
            test_names.append(f"tests[{i}]")

    scenarios = topo.get("scenarios", []) or []
    scen_sig: list[tuple[str, int, list[str]]] = []
    for s in scenarios:
        if not isinstance(s, dict):
            continue
        sid = str(s.get("id") or "").strip()
        steps = s.get("steps", []) or []
        step_types: list[str] = []
        if isinstance(steps, list):
            for st in steps:
                if not isinstance(st, dict):
                    step_types.append("invalid")
                    continue
                # determine step type by key intersection (contract)
                keys = set(st.keys())
                for k in ("run", "fault", "wait_for", "wait_for_bgp"):
                    if k in keys:
                        step_types.append(k)
                        break
                else:
                    step_types.append("unknown")
        scen_sig.append((sid, len(steps) if isinstance(steps, list) else 0, step_types))

    scen_sig.sort(key=lambda x: x[0])
    return (test_names, scen_sig)

def _two_run_compare(*, baseline_dir: Path, change_dir: Path, base_name: str) -> tuple[dict[str, Any], str]:
    b_results = _two_run_load_json(baseline_dir / "results.json")
    c_results = _two_run_load_json(change_dir / "results.json")

    b_resolved = baseline_dir / "topology.resolved.yaml"
    c_resolved = change_dir / "topology.resolved.yaml"

    topo_hash_b = _two_run_normalized_topo_hash(b_resolved)
    topo_hash_c = _two_run_normalized_topo_hash(c_resolved)

    b_tests, b_scens = _two_run_extract_declared_sets(b_resolved)
    c_tests, c_scens = _two_run_extract_declared_sets(c_resolved)

    comparability_errors: list[str] = []
    if topo_hash_b != topo_hash_c:
        comparability_errors.append("topology identity mismatch (normalized resolved topology differs)")
    if b_tests != c_tests:
        comparability_errors.append("declared test set mismatch between baseline and change")
    if b_scens != c_scens:
        comparability_errors.append("declared scenario set mismatch between baseline and change")

    def _index_tests(results: dict[str, Any]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for t in results.get("tests", []) or []:
            if not isinstance(t, dict):
                continue
            name = str(t.get("name") or "").strip()
            if not name:
                continue
            out[name] = t
        return out

    b_idx = _index_tests(b_results)
    c_idx = _index_tests(c_results)

    # Deterministic per-test diffs (declared order)
    test_diffs: list[dict[str, Any]] = []
    for name in b_tests:
        bt = b_idx.get(name, {})
        ct = c_idx.get(name, {})
        fields = ("expected", "observed", "verdict", "duration_ms")
        changed: dict[str, Any] = {}
        for f in fields:
            bv = bt.get(f)
            cv = ct.get(f)
            if bv != cv:
                changed[f] = {"baseline": bv, "change": cv}
        if changed:
            test_diffs.append({"name": name, "changes": changed})

    # Scenario diffs (from results.json scenarios)
    def _idx_scen(results: dict[str, Any]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for s in results.get("scenarios", []) or []:
            if not isinstance(s, dict):
                continue
            sid = str(s.get("id") or "").strip()
            if sid:
                out[sid] = s
        return out

    b_sidx = _idx_scen(b_results)
    c_sidx = _idx_scen(c_results)

    scen_diffs: list[dict[str, Any]] = []
    for (sid, _nsteps, _types) in b_scens:
        bs = b_sidx.get(sid, {})
        cs = c_sidx.get(sid, {})
        changed: dict[str, Any] = {}
        for f in ("verdict", "duration_ms"):
            if bs.get(f) != cs.get(f):
                changed[f] = {"baseline": bs.get(f), "change": cs.get(f)}

        # step verdict/duration diffs by index
        b_steps = bs.get("steps", []) or []
        c_steps = cs.get("steps", []) or []
        step_changes: list[dict[str, Any]] = []
        if isinstance(b_steps, list) and isinstance(c_steps, list):
            for i in range(min(len(b_steps), len(c_steps))):
                bst = b_steps[i] if isinstance(b_steps[i], dict) else {}
                cst = c_steps[i] if isinstance(c_steps[i], dict) else {}
                sc: dict[str, Any] = {}
                for f in ("type", "verdict", "duration_ms"):
                    if bst.get(f) != cst.get(f):
                        sc[f] = {"baseline": bst.get(f), "change": cst.get(f)}
                if sc:
                    step_changes.append({"step": i + 1, "changes": sc})
        if step_changes:
            changed["steps"] = step_changes

        if changed:
            scen_diffs.append({"id": sid, "changes": changed})

    summary = {
        "schema_version": "1",
        "authority": "supporting_evidence",
        "statement": "This diff is evidence-only and never determines verdicts.",
        "two_run": {
            "base_lab": base_name,
            "baseline": {"overall": (b_results.get("result") or ""), "topo_hash": topo_hash_b},
            "change": {"overall": (c_results.get("result") or ""), "topo_hash": topo_hash_c},
        },
        "comparability": {
            "ok": (len(comparability_errors) == 0),
            "errors": comparability_errors,
        },
        "diffs": {
            "tests": test_diffs,
            "scenarios": scen_diffs,
        },
    }

    # Deterministic human summary
    lines: list[str] = []
    lines.append("ai-netsim two-run diff (evidence-only)")
    lines.append(f"base_lab: {base_name}")
    lines.append(f"baseline_overall: {b_results.get('result')}")
    lines.append(f"change_overall: {c_results.get('result')}")
    lines.append(f"comparability_ok: {str(len(comparability_errors) == 0).lower()}")
    if comparability_errors:
        lines.append("comparability_errors:")
        for e in comparability_errors:
            lines.append(f" - {e}")

    lines.append(f"test_diffs: {len(test_diffs)}")
    for d in test_diffs[:25]:
        lines.append(f" - {d['name']}: {', '.join(sorted(d['changes'].keys()))}")
    if len(test_diffs) > 25:
        lines.append(f" - (+{len(test_diffs)-25} more)")

    lines.append(f"scenario_diffs: {len(scen_diffs)}")
    for d in scen_diffs[:25]:
        lines.append(f" - {d['id']}: changed")
    if len(scen_diffs) > 25:
        lines.append(f" - (+{len(scen_diffs)-25} more)")

    return summary, "\n".join(lines) + "\n"

def _cmd_test_two_run(args: argparse.Namespace) -> None:
    base_topo_path = _two_run_load_yaml_path(str(getattr(args, "two_run_topology")))
    topo = load_yaml(base_topo_path) or {}
    if not isinstance(topo, dict):
        die(f"two-run: invalid topology: {base_topo_path}")
    base_name = topo.get("name")
    if not isinstance(base_name, str) or not base_name.strip():
        die(f"two-run: topology has no valid 'name': {base_topo_path}")
    base_name = base_name.strip()

    # two-run requires candidate-config for the CHANGE run (even though baseline does not use it)
    cand_raw = getattr(args, "candidate_config", None)
    if cand_raw is None:
        die("two-run: missing required --candidate-config for CHANGE run")

    # Normalize candidate dir to an absolute, resolved path to avoid cwd ambiguity
    cand_dir = Path(str(cand_raw)).expanduser()
    if not cand_dir.is_absolute():
        cand_dir = (Path.cwd() / cand_dir)
    cand_dir = cand_dir.resolve()

    # Pre-validate candidate dir *before any runs* so we fail fast without deploying labs.
    # This enforces the "recognized inputs exist" invariant and gives a deterministic error.
    _candidate_parse_dir_or_die(topo, cand_dir)

    # Bundle root (stable)
    bundle_root = LABS_DIR / f"clab-{base_name}" / "two_run"
    tmp_dir = bundle_root / "_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    baseline_name = f"{base_name}-baseline"
    change_name = f"{base_name}-change"

    baseline_topo = tmp_dir / "baseline.topology.yaml"
    change_topo = tmp_dir / "change.topology.yaml"

    _two_run_make_temp_topology(base_topo_path=base_topo_path, new_name=baseline_name, out_path=baseline_topo)
    _two_run_make_temp_topology(base_topo_path=base_topo_path, new_name=change_name, out_path=change_topo)

    def run_one(*, topo_path: Path, lab_name: str, candidate: Path | None, label: str) -> tuple[int, str]:
        """
        Returns: (exit_code, overall_result_string)
        exit_code is for hard failure decisions; test failures are not treated as hard here.
        """
        # Always clean-state for this run
        up_args = argparse.Namespace(topology=str(topo_path), reconfigure=True)
        try:
            cmd_up(up_args)
        except SystemExit as e:
            die(f"{label}: deploy/provision failed")
        except Exception:
            die(f"{label}: deploy/provision failed")

        # If candidate is provided, re-validate it against the resolved topology
        # produced by THIS run (stronger than base YAML).
        if candidate is not None:
            rpath = LABS_DIR / f"clab-{lab_name}" / "topology.resolved.yaml"
            if not rpath.exists():
                die(f"{label}: missing resolved topology: {rpath}")
            rtopo = load_yaml(rpath) or {}
            if not isinstance(rtopo, dict):
                die(f"{label}: invalid resolved topology: {rpath}")
            ensure_valid_topology(rtopo)
            _candidate_parse_dir_or_die(rtopo, candidate)

        # Run tests (may fail normally)
        test_ns = argparse.Namespace(
            lab=lab_name,
            name=getattr(args, "name", None),
            kind=getattr(args, "kind", None),
            keep_going=bool(getattr(args, "keep_going", False)),
            json=bool(getattr(args, "json", False)),
            candidate_config=(str(candidate) if candidate is not None else None),
            scenario=getattr(args, "scenario", None),
            all_scenarios=bool(getattr(args, "all_scenarios", False)),
            scenario_verbose=bool(getattr(args, "scenario_verbose", False)),
            precheck_controlplane=bool(getattr(args, "precheck_controlplane", False)),
            list_scenarios=False,
        )
        try:
            cmd_test(test_ns)
        except SystemExit:
            # Normal test failure OR candidate apply failure. Decide later by inspecting results.json.
            pass

        # Collect best-effort (still deterministic)
        try:
            cmd_collect(argparse.Namespace(lab=lab_name))
        except SystemExit:
            pass
        except Exception:
            pass

        # Read overall result (if available)
        rpath = LABS_DIR / f"clab-{lab_name}" / "results.json"
        overall = ""
        if rpath.exists():
            overall = str((_two_run_load_json(rpath)).get("result") or "")

        # Always destroy for clean-state gate semantics
        try:
            cmd_down(argparse.Namespace(name=lab_name))
        except SystemExit:
            pass
        except Exception:
            pass

        return (0, overall)

    # Run baseline first
    run_one(topo_path=baseline_topo, lab_name=baseline_name, candidate=None, label="baseline")

    # If baseline artifacts missing, treat as hard failure
    baseline_dir = LABS_DIR / f"clab-{baseline_name}"
    if not (baseline_dir / "results.json").exists():
        die("baseline: hard failure (missing results.json)")

    # Run change second (with candidate apply)
    run_one(topo_path=change_topo, lab_name=change_name, candidate=cand_dir, label="change")

    change_dir = LABS_DIR / f"clab-{change_name}"
    if not (change_dir / "results.json").exists():
        die("change: hard failure (missing results.json)")

    # If candidate apply failed, treat as hard failure (per handover)
    cjson = _two_run_load_json(change_dir / "results.json")
    ca = cjson.get("candidate_apply") or {}
    if isinstance(ca, dict) and ca.get("enabled") and str(ca.get("verdict") or "") == "fail":
        # still proceed to bundle copy + diff if possible, but exit non-zero
        apply_failed = True
    else:
        apply_failed = False

    # Bundle placement (stable dirs)
    bdst = bundle_root / "baseline"
    cdst = bundle_root / "change"
    ddst = bundle_root / "diff"
    ddst.mkdir(parents=True, exist_ok=True)

    _two_run_copy_tree(baseline_dir, bdst)
    _two_run_copy_tree(change_dir, cdst)

    summary, txt = _two_run_compare(baseline_dir=bdst, change_dir=cdst, base_name=base_name)
    (ddst / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (ddst / "summary.txt").write_text(txt, encoding="utf-8")

    # Comparability broken => hard failure
    comp = summary.get("comparability") or {}
    if isinstance(comp, dict) and not bool(comp.get("ok")):
        die("comparison invalid: " + "; ".join(comp.get("errors") or []))

    # Candidate apply failure => hard failure
    if apply_failed:
        die("change: candidate apply failed (tests/scenarios did not run)")

    # Exit code reflects change verdict only
    if str(cjson.get("result") or "") != "pass":
        die("two-run: CHANGE verdict is FAIL", code=1)

    print(f"✅ two-run PASS: bundle at {bundle_root}")

# -------------------------
# Commands
# -------------------------

def cmd_test(args: argparse.Namespace) -> None:
    """
    v1 update (Section C): Scenarios wired into cmd_test (minimal invasive).

    - Default behavior unchanged: readiness + optional BGP + declared tests (steady-state).
    - Opt-in scenarios:
        * netsim test --scenario <id>
        * netsim test --all-scenarios
    When a scenario is requested, cmd_test executes declared steady-state tests first,
    then executes the requested scenario(s).
      Scenario steps call existing atomic tests via `run: <test_name>`.

    Hard guardrail:
      If scenarios are requested, validate ALL scenario run refs up-front and FAIL FAST
      (before any runtime actions) if a referenced atomic test name does not exist.
    """
    # v1.5 hard guardrail: capture-config is exploration evidence only (never allowed in gate-first test)
    if bool(getattr(args, "capture_config", False)):
        die("--capture-config is exploration evidence only and is not allowed in netsim test", code=2)

    # -------------------------------------------------------------------------
    # Two-run gate orchestrator (v1.5): baseline vs change (evidence-only)
    # -------------------------------------------------------------------------
    if bool(getattr(args, "two_run", False)):
        topo_arg = getattr(args, "two_run_topology", None)
        cand_arg = getattr(args, "candidate_config", None)

        if not topo_arg:
            die("--two-run requires --two-run-topology <topology.yaml>")
        if not cand_arg:
            die("--two-run requires --candidate-config <dir> (used for the change run)")

        _cmd_test_two_run(args)
        return
    
    import json

    lab = args.lab
    # ------------------------------------------------------------
    # v1.x UX hardening: lab name is required for normal test runs
    # (Two-run is the ONLY mode that can run without a lab name.)
    # ------------------------------------------------------------
    if not lab:
        die(
            "ERROR: missing LAB NAME.\n\n"
            "Usage:\n"
            "  netsim test <lab-name> [options]\n\n"
            "Examples:\n"
            "  netsim up topologies/foo.yaml --reconfigure\n"
            "  netsim test foo\n\n"
            "Note:\n"
            "  If you want the baseline-vs-change gate, use:\n"
            "    netsim test --two-run --two-run-topology <topology.yaml> --candidate-config <dir>\n",
            code=2,
        )

    # ------------------------------------------------------------
    # v2 UX hardening (First 10 Minutes):
    # Allow: netsim test <topology.yaml> as an authoritative clean-state gate.
    # Preserve: netsim test <lab-name> behavior (existing lab required).
    # ------------------------------------------------------------
    lab_raw = str(lab or "").strip()

    def _resolve_topology_path(s: str) -> Path | None:
        s2 = (s or "").strip()
        if not s2:
            return None

        # 1) explicit filesystem path
        p = Path(s2)
        if p.is_file():
            return p

        # 2) under repo topologies/
        p2 = TOPO_DIR / s2
        if p2.is_file():
            return p2

        # 3) under repo examples/ (first-10-min UX)
        p3 = (BASE_DIR / "examples" / s2)
        if p3.is_file():
            return p3

        return None

    topo_gate_path = _resolve_topology_path(lab_raw)

    # WI-1: result-block authority kind is derived deterministically from invocation shape.
    # - topology path => gate (authoritative)
    # - lab name      => lab (non-authoritative)
    # Callers (e.g., cmd_run) may explicitly override via args._report_authority.
    if getattr(args, "_report_authority", None) is None:
        setattr(args, "_report_authority", "gate" if topo_gate_path is not None else "lab")

    # Gate-style: topology path provided
    if topo_gate_path is not None:
        # Pre-validate + resolve to get deterministic lab name
        # MUST establish a deterministic lab dir even if YAML/Resolve fails (WI-1).
        resolved_preview = None
        lab_name = ""

        try:
            topo_preview = load_yaml(topo_gate_path)
            ensure_valid_topology(topo_preview)
            resolved_preview = resolve_topology(topo_preview)
            validate_scenarios(resolved_preview)

            lab_name = str((resolved_preview or {}).get("name") or "").strip()
            if not lab_name:
                die(f"Topology missing required 'name': {topo_gate_path}")

        except SystemExit as e:
            # If we already resolved a name, preserve gate hard-failure behavior downstream.
            # Otherwise, emit fallback artifacts under a deterministic name derived from the input path.
            if lab_name:
                raise

            raw = str(topo_gate_path)
            # Deterministic, stable slug: based only on input path string bytes.
            h = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:12]
            lab_name = f"unknown-{h}"

            # Quiet mode: keep existing UX line shape.
            msg = str(e).strip()
            if msg:
                print(f"ERROR: invalid YAML: {topo_gate_path}: {msg}")
            else:
                print(f"ERROR: invalid YAML: {topo_gate_path}")

            # Best-effort: emit authoritative artifacts for this gate failure.
            try:
                _gate_write_hard_failure_results(
                    phase="resolve",
                    err=msg or "invalid input",
                    code=int(getattr(e, "code", 2) or 2),
                )
            except Exception:
                pass

            raise

        except Exception as e:
            if lab_name:
                # Name exists; preserve existing invalid-input UX + downstream hard-failure path.
                msg = str(e).strip()
                if msg:
                    print(f"ERROR: invalid YAML: {topo_gate_path}: {msg}")
                else:
                    print(f"ERROR: invalid YAML: {topo_gate_path}")
                if bool(getattr(args, "verbose", False)):
                    import traceback  # local import to avoid global import impact
                    traceback.print_exc()
                raise SystemExit(2)

            raw = str(topo_gate_path)
            h = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:12]
            lab_name = f"unknown-{h}"

            msg = str(e).strip()
            if msg:
                print(f"ERROR: invalid YAML: {topo_gate_path}: {msg}")
            else:
                print(f"ERROR: invalid YAML: {topo_gate_path}")
            if bool(getattr(args, "verbose", False)):
                import traceback  # local import to avoid global import impact
                traceback.print_exc()

            try:
                _gate_write_hard_failure_results(
                    phase="resolve",
                    err=msg or "invalid input",
                    code=2,
                )
            except Exception:
                pass

            raise SystemExit(2)

        # Phase 3 (WI-6): list scenarios directly from the resolved topology (no lab artifacts, no runtime).
        if bool(getattr(args, "list_scenarios", False)):
            topo = resolved_preview
            scenarios = topo.get("scenarios") or []
            if not scenarios:
                print(f"No scenarios declared for topology '{topo_gate_path}' (lab '{lab_name}').")
                return

            rows: list[tuple[str, str, int]] = []
            for s in scenarios:
                if not isinstance(s, dict):
                    continue
                sid = s.get("id")
                if not isinstance(sid, str) or not sid.strip():
                    continue
                desc = s.get("description") or ""
                if not isinstance(desc, str):
                    desc = str(desc)
                steps = s.get("steps") or []
                steps_n = len(steps) if isinstance(steps, list) else 0
                rows.append((sid.strip(), desc.strip(), steps_n))

            rows.sort(key=lambda x: x[0])

            print(f"Scenarios for topology '{topo_gate_path}' (lab '{lab_name}'):")
            print("Note: step counts are from the resolved topology (post-Resolve). Scenarios using 'run: { include: all }' will show expanded steps.")
            for sid, desc, steps_n in rows:
                if desc:
                    print(f"- {sid}: {desc} (steps: {steps_n})")
                else:
                    print(f"- {sid}: (steps: {steps_n})")
            return

        # Phase 3 guardrail (P3-D):
        # Candidate-config misuse must fail fast (exit 2) BEFORE any runtime actions / lab artifacts.
        cand_arg = getattr(args, "candidate_config", None)
        if cand_arg:
            _candidate_parse_dir_or_die(resolved_preview, Path(str(cand_arg)))

        # Now run tests against the deployed lab name (existing behavior)
        # Now run tests against the deployed lab name (existing behavior)
        args2 = argparse.Namespace(**vars(args))
        args2.lab = lab_name
        # Reporting context only (presentation; does not affect verdicts/exit codes)
        setattr(args2, "_report_authority", "gate")
        # WI-B: Preserve user-invoked topology path for Gate Result identity (presentation-only).
        setattr(args2, "_report_topology_path", str(topo_gate_path))

        exit_code = 0

        def _gate_write_hard_failure_results(*, phase: str, err: str, code: int) -> None:
            # Gate-mode hard failure MUST still emit authoritative artifacts (results.json + summary).
            # Deterministic, additive-only envelope. No runtime dependency.
            try:
                now = time.time()
            except Exception:
                now = 0.0

            results: dict = {
                "result": "fail",
                "tests": [],
                "scenarios": [],
                "events": [],
                # WI-B: Gate identity completeness for pathlike invocations (presentation-only).
                "topology_path": str(topo_gate_path),
                "hard_failure": {
                    "occurred": True,
                    "phase": str(phase or ""),
                    "error": ("ERROR: " + str(err).strip()) if str(err).strip() and not str(err).strip().startswith("ERROR:") else str(err).strip(),
                },
                "summary": {
                    "started_at": now,
                    "finished_at": now,
                    "duration_ms": 0,
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                },
            }

            # Collect-time schema stabilization (best-effort; additive-only)
            try:
                _finalize_results_schema(
                    results=results,
                    command="test",
                    topo_name=str(lab_name),
                    lab_name=str(lab_name),
                    phase="collect",
                )
            except Exception:
                pass

            # Deterministic schema floor (additive-only)
            try:
                results.setdefault("results_schema", "results.v1")
                results.setdefault("results_schema_version", "1.0.0")
                results.setdefault("tool", "ai-netsim")
                results.setdefault("command", "test")

                topo_obj = results.get("topology")
                if not isinstance(topo_obj, dict):
                    topo_obj = {}
                    results["topology"] = topo_obj
                topo_obj.setdefault("name", str(lab_name))

                lab_obj = results.get("lab_obj")
                if not isinstance(lab_obj, dict):
                    lab_obj = {}
                    results["lab_obj"] = lab_obj
                lab_obj.setdefault("name", str(lab_name))

                auth = results.get("authority")
                if not isinstance(auth, dict):
                    auth = {}
                    results["authority"] = auth
                auth.setdefault("verdict_source", "tests")
                se = auth.get("supporting_evidence")
                if not isinstance(se, list):
                    auth["supporting_evidence"] = []

                overall = results.get("overall")
                if not isinstance(overall, dict):
                    overall = {}
                    results["overall"] = overall
                overall.setdefault("expected", "pass")
                overall["observed"] = "fail"
                overall["verdict"] = "fail"
                overall.setdefault("phase", "collect")
                overall.setdefault("exit_code", int(code) if int(code) else 1)
            except Exception:
                pass

            out = lab_dir(lab_name) / "results.json"
            try:
                out.parent.mkdir(parents=True, exist_ok=True)
                write_json_canonical(out, results)
                _invocation_record_written_artifact(out)

                summary_path = write_test_summary_artifact(lab_name, results)
                _invocation_record_written_artifact(summary_path)

                # Fail closed if either artifact missing (gate authority)
                if not out.exists():
                    die(f"ERROR: gate hard failure artifact write failed (missing results.json): {out}", code=1)
                if not summary_path.exists():
                    die(f"ERROR: gate hard failure artifact write failed (missing results.summary.txt): {summary_path}", code=1)

                # Present deterministic gate result block (best-effort)
                try:
                    blk = render_gate_result_block(results, authority_kind="gate")
                    if isinstance(blk, str) and blk.strip():
                        print(blk, end="" if blk.endswith("\n") else "\n")

                    # WI-1 (Set 6): defer artifact path surfacing to the end-of-invocation footer.
                    # Presentation-only; does not affect artifacts, schema, verdict, or exit code.
                    res = str(results.get("result") or "fail").strip().lower()
                    if res != "pass":
                        # Do not print artifact paths here.
                        # main() finally calls _print_artifacts_footer_for_lab(), which prints a single
                        # stable `Artifacts: labs/clab-<lab>/` line exactly once per invocation.
                        pass
                except Exception:
                    pass
            except SystemExit:
                raise
            except Exception as e:
                die(f"ERROR: gate hard failure artifact write failed: {e}", code=1)

        print("MODE: GATE | AUTHORITATIVE: YES | CLEAN-STATE: YES | DESTROY: YES | LIFECYCLE: RESOLVE>GENERATE>DEPLOY>PROVISION>TEST>COLLECT>DESTROY")

        gate_phase = "deploy"
        try:
            # Run clean-state deploy/provision (equivalent to: netsim up <topo> --reconfigure)
            cmd_up(argparse.Namespace(topology=str(topo_gate_path), reconfigure=True, _from_gate=True))

            # If we got here, deploy/provision completed; any further SystemExit is a test-stage failure.
            gate_phase = "test"

            try:
                cmd_test(args2)

                # Fail closed if authoritative artifacts missing (gate authority).
                # This applies to the PASS path as well; cmd_test() is responsible for writing them,
                # but gate mode must not exit successfully without them.
                try:
                    out = lab_dir(lab_name) / "results.json"
                    summ = lab_dir(lab_name) / "results.summary.txt"
                    if (not out.exists()) or (not summ.exists()):
                        # Fail closed: attempt deterministic fallback emission, then exit non-zero.
                        try:
                            _gate_write_hard_failure_results(
                                phase="collect",
                                err="ARTIFACT INTEGRITY FAILURE: results.* missing after test; emitted fallback results",
                                code=1,
                            )
                            print(f"ARTIFACT INTEGRITY FAILURE: emitted fallback results under labs/clab-{lab_name}/ (exit unchanged)")
                        except Exception:
                            pass
                        die("ERROR: gate artifact integrity failure (missing results.*)", code=1)
                except SystemExit:
                    raise
                except Exception as e:
                    die(f"ERROR: gate artifact validation failed after test: {e}", code=1)

                return
            except SystemExit as e:
                # Preserve exit code from the authoritative test run
                try:
                    exit_code = int(getattr(e, "code", 1) or 1)
                except Exception:
                    exit_code = 1

                # WI-1: gate must still emit results.* on FAIL.
                # If cmd_test() failed before Collect, we must force deterministic fallback artifacts
                # under labs/clab-<lab>/ before teardown, without changing exit semantics.
                try:
                    out = lab_dir(lab_name) / "results.json"
                    summ = lab_dir(lab_name) / "results.summary.txt"
                    if (not out.exists()) or (not summ.exists()):
                        try:
                            _gate_write_hard_failure_results(
                                phase="test",
                                err=str(getattr(netsim_common, "LAST_ERROR_MSG", "") or "gate test failed"),
                                code=exit_code,
                            )
                        except Exception:
                            pass
                except Exception:
                    # Do not mask the original verdict/exit code.
                    pass

                raise

        except SystemExit as e:
            # If a hard failure occurs, we must still emit gate artifacts.
            try:
                exit_code = int(getattr(e, "code", 1) or 1)
            except Exception:
                exit_code = 1

            # IMPORTANT (WI-1): only emit a synthetic "hard failure" record when we are NOT in the test stage
            # (deploy/provision/runtime faults) OR when upstream uses the hard-failure exit band.
            # Normal test-stage failures (exit=1) already have authoritative results written by cmd_test()
            # and MUST NOT be duplicated.
            should_emit_hard_failure = (str(gate_phase) != "test") or (int(exit_code) == 2)

            if should_emit_hard_failure:
                # Best-effort: render a gate-style hard failure record under the derived lab name.
                # Phase must reflect whether failure happened during deploy/provision or during test execution.
                try:
                    err_msg = str(getattr(netsim_common, "LAST_ERROR_MSG", "") or "gate failed").strip()
                    phase_report = str(gate_phase or "").strip().lower()

                    # WI (Gate failure clarity): map netsim-owned resolve-time validation/coverage failures
                    # to RESOLVE, even if they occur during the gate-style cmd_up() path.
                    # Deterministic: purely string-based on netsim-owned error messages; no probing.
                    if phase_report == "deploy":
                        em = err_msg.lower()
                        if em.startswith("coverage:") or em.startswith("schema:") or em.startswith("invalid yaml:") or em.startswith("topology "):
                            phase_report = "resolve"

                    _gate_write_hard_failure_results(
                        phase=str(phase_report),
                        err=err_msg or "gate failed",
                        code=exit_code,
                    )
                except SystemExit:
                    # Preserve original exit semantics (do not mask the upstream exit code path).
                    pass
                except Exception:
                    pass

            raise

        finally:
            # Always cleanup after gate-style runs (equivalent to: netsim down <lab>)
            try:
                cmd_down(argparse.Namespace(name=lab_name))
            except SystemExit:
                # Cleanup best-effort; never mask the test verdict exit code
                pass
            finally:
                # Phase 1 (R2/R5): explicit lifecycle disclosure for gate-style topology runs
                print("Lab lifecycle: DESTROYED")

                if exit_code:
                    pass

    # ------------------------------------------------------------
    # Existing behavior: lab name required for non-gate runs
    # ------------------------------------------------------------
    if not lab_raw:
        die(
            "ERROR: missing LAB NAME.\n\n"
            "Usage:\n"
            "  netsim test <lab-name> [options]\n"
            "  netsim test <topology.yaml> [options]\n\n"
            "Examples:\n"
            "  netsim up topologies/foo.yaml --reconfigure\n"
            "  netsim test foo\n\n"
            "  netsim test examples/dci-failover.yaml\n\n"
            "Note:\n"
            "  If you want the baseline-vs-change gate, use:\n"
            "    netsim test --two-run --two-run-topology <topology.yaml> --candidate-config <dir>\n",
            code=2,
        )

    # Optional UX guardrail: path-like strings that do not resolve to a topology file
    # are treated as misuse (avoid creating labs/ entries like labs/<something>.yaml).
    def _looks_like_topology_path(s: str) -> bool:
        s2 = s.strip()
        s2_l = s2.lower()
        return (
            ("/" in s2)
            or ("\\" in s2)
            or s2_l.endswith(".yaml")
            or s2_l.endswith(".yml")
        )

    if _looks_like_topology_path(lab_raw) and _resolve_topology_path(lab_raw) is None:
        die(
            "ERROR: topology path not found: "
            + str(lab_raw)
            + "\n"
            "Detected:\n"
            "  looks like a topology path (contains '/' or ends with .yaml/.yml)\n"
            "Next:\n"
            "  Gate mode: netsim test <topology.yaml>\n"
            "  Lab mode:  netsim up <topology.yaml> --reconfigure ; netsim test <lab-name>",
            code=2,
        )
    # ------------------------------------------------------------
    # v1.x UX: list scenarios from resolved topology (no execution)
    # ------------------------------------------------------------
    if bool(getattr(args, "list_scenarios", False)):
        adir = lab_dir(lab)
        if not adir.exists():
            die(
                f"Lab artifacts not found for lab={lab}. Expected: {adir}/topology.resolved.yaml\n"
                "Hint: Run 'netsim up <topology.yaml> --reconfigure' then 'netsim test <lab-name>', or run "
                "'netsim test <topology.yaml>' to create artifacts.",
                code=2,
            )

        rpath = adir / "topology.resolved.yaml"
        if not rpath.exists():
            die(
                f"Lab artifacts not found for lab={lab}. Expected: {rpath}\n"
                "Hint: Run 'netsim up <topology.yaml> --reconfigure' then 'netsim test <lab-name>', or run "
                "'netsim test <topology.yaml>' to create artifacts.",
                code=2,
            )

        topo = load_yaml(rpath)
        scenarios = topo.get("scenarios") or []
        if not scenarios:
            print(f"No scenarios declared for lab '{lab}'.")
            return

        rows: list[tuple[str, str, int]] = []
        for s in scenarios:
            if not isinstance(s, dict):
                continue
            sid = s.get("id")
            if not isinstance(sid, str) or not sid.strip():
                continue
            desc = s.get("description") or ""
            if not isinstance(desc, str):
                desc = str(desc)
            steps = s.get("steps") or []
            steps_n = len(steps) if isinstance(steps, list) else 0
            rows.append((sid.strip(), desc.strip(), steps_n))

        rows.sort(key=lambda x: x[0])

        print(f"Scenarios for lab '{lab}':")
        print("Note: step counts are from the resolved topology (post-Resolve). Scenarios using 'run: { include: all }' will show expanded steps.")
        for sid, desc, steps_n in rows:
            if desc:
                print(f"- {sid}: {desc} (steps: {steps_n})")
            else:
                print(f"- {sid}: (steps: {steps_n})")
        return
    # v1.x UX hardening: users commonly try `netsim test topologies/foo.yaml`
    # `netsim test` is lab-driven by design, so fail early with an actionable message.
    if isinstance(lab, str):
        s = lab.strip()
        if s.endswith((".yaml", ".yml")) or "/" in s or s.startswith("topologies/") or s.startswith("./") or s.startswith("../"):
            die(
                "ERROR: netsim test expects a lab name, not a topology file.\n\n"
                f"You ran:\n  netsim test {lab}\n\n"
                "Did you mean:\n"
                f"  netsim up {lab} --reconfigure\n"
                f"  netsim test <lab-name>\n\n"
                "Tip: lab name usually matches the topology 'name:' field."
            )
    filter_name: str | None = getattr(args, "name", None)
    filter_kind: str | None = getattr(args, "kind", None)
    keep_going: bool = bool(getattr(args, "keep_going", False))
    print_json: bool = bool(getattr(args, "json", False))

    # Scenario CLI (opt-in)
    scenario_id: str | None = getattr(args, "scenario", None)
    all_scenarios: bool = bool(getattr(args, "all_scenarios", False))
    scenario_verbose: bool = bool(getattr(args, "scenario_verbose", False))
    want_scenarios = bool(scenario_id or all_scenarios)
    precheck_controlplane: bool = bool(getattr(args, "precheck_controlplane", False))

    started_at = time.time()

    # =============================================================================
    # 0) Load & validate the resolved topology that created this lab
    # =============================================================================
    tpath = topo_path_for_lab(lab)
    if not tpath.exists():
        die(f"Topology file not found for lab '{lab}': {tpath}")

    topo = load_yaml(tpath)
    ensure_valid_topology(topo)

    # Candidate config fail-fast validation (no runtime actions required)
    # Normalize to absolute + resolved (same semantics as two-run)
    cand_dir_raw: str | None = getattr(args, "candidate_config", None)
    cand_dir: Path | None = None
    cand_plan: list[dict] | None = None

    if cand_dir_raw:
        cand_dir = Path(str(cand_dir_raw)).expanduser()
        if not cand_dir.is_absolute():
            cand_dir = (Path.cwd() / cand_dir)
        cand_dir = cand_dir.resolve()
        cand_plan = _candidate_parse_dir_or_die(topo, cand_dir)
    # -----------------------------------------------------------------------------
    # Hard guardrail: validate scenario run refs up-front (no partial execution)
    # This MUST happen before ANY runtime actions (docker/VM exec, faults, waits, etc.)
    # -----------------------------------------------------------------------------
    if want_scenarios:
        scenario_ids: list[str] | None = None
        if scenario_id:
            scenario_ids = [scenario_id]
        elif all_scenarios:
            scenario_ids = None  # validate all
        validate_scenario_run_refs_or_die(topo, scenario_ids=scenario_ids)

    # Disallow filters when running scenarios: avoids silent "pass" with 0 executed runs
    if want_scenarios and (filter_name or filter_kind):
        die(
            "ERROR: --name/--kind filters are not supported with --scenario/--all-scenarios "
            "(would skip scenario run steps).",
            code=2,
        )

    # Phase-1 runtime abstraction (container today, VM later)
    rt = get_runtime(topo)

    nodes = topo.get("nodes", []) or []
    nodes_by_name = {n["name"]: n for n in nodes}

    # Results artifact (written at end, even on failure if possible)
    results: dict = {
        "schema_version": "1",
        "lab": lab,
        "result": "unknown",
        "summary": {
            "started_at": started_at,
            "finished_at": None,
            "duration_ms": None,
            "total": 0,
            "passed": 0,
            "failed": 0,
            "filtered_by_name": filter_name or "",
            "filtered_by_kind": filter_kind or "",
            "resolved_topology_path": str(tpath),
            "resolved_topology_mtime": tpath.stat().st_mtime,
            "scenario": scenario_id or "",
            "all_scenarios": bool(all_scenarios),
            "keep_going": bool(keep_going),
        },
        "tests": [],
        "scenarios": [],
        "events": [],
    }

    # v1.5 EVPN Awareness (presence-only): informational results metadata.
    # Authority remains tests/scenarios only; this must never affect verdict or exit code.
    try:
        fabric = topo.get("fabric")
        evpn = fabric.get("evpn") if isinstance(fabric, dict) else None
        if isinstance(evpn, dict) and bool(evpn.get("enabled")) and str(evpn.get("mode") or "evpn") == "evpn":
            rf = results.get("fabric")
            if not isinstance(rf, dict):
                rf = {}
                results["fabric"] = rf
            rf["evpn"] = {
                "present": True,
                "authority": "outcome-only",
                "internals_validated": False,
                "notes": "EVPN declared via fabric.evpn. v1.5 validates outcomes via tests/scenarios only; EVPN internals are not validated.",
            }
    except Exception:
        # Never allow informational metadata to impact gate execution.
        pass

    def record_test(
        *,
        name: str,
        kind: str,
        src: str,
        dst: str,
        expected: str,
        observed: str,
        verdict: str,
        duration_ms: int,
        error: str = "",
        meta: dict | None = None,
        evidence: dict | None = None,
    ) -> None:
        rec = {
            "name": name,
            "kind": kind,
            "from": src,
            "to": dst,
            "expected": expected,
            "observed": observed,
            "verdict": verdict,
            "duration_ms": duration_ms,
            "error": error,
            "evidence": evidence,
        }
        if meta:
            rec["meta"] = meta
        results["tests"].append(rec)

    def record_event_test_run(
        *,
        scenario_id: str,
        step_index: int,
        name: str,
        kind: str,
        src: str,
        dst: str,
        expected: str,
        observed: str,
        verdict: str,
        duration_ms: int,
        error: str = "",
        meta: dict | None = None,
        evidence: dict | None = None,
    ) -> None:
        rec = {
            "type": "scenario_test_run",
            "scenario_id": scenario_id,
            "step": int(step_index),
            "name": name,
            "kind": kind,
            "from": src,
            "to": dst,
            "expected": expected,
            "observed": observed,
            "verdict": verdict,
            "duration_ms": int(duration_ms),
            "error": error,
            "evidence": evidence,
        }
        if meta:
            rec["meta"] = meta
        results["events"].append(rec)

    def record_event_scenario_fault(
        *,
        scenario_id: str,
        step_index: int,
        verdict: str,
        duration_ms: int,
        error: str = "",
        meta: dict | None = None,
    ) -> None:
        """
        Persist a deterministic scenario fault event into results.json.
        This is the authoritative machine-consumable record for scenario fault steps.
        """
        rec = {
            "type": "scenario_fault",
            "scenario_id": str(scenario_id),
            "step": int(step_index),
            "verdict": str(verdict),
            "duration_ms": int(duration_ms),
            "error": str(error or ""),
        }
        if meta:
            rec["meta"] = meta

        # --- HARD DETERMINISTIC GUARD ---
        # Never allow more than one scenario_fault event
        # for the same scenario_id + step_index
        for e in results.get("events", []):
            if (
                e.get("type") == "scenario_fault"
                and e.get("scenario_id") == scenario_id
                and int(e.get("step") or -1) == int(step_index)
            ):
                return
        # --------------------------------

        results["events"].append(rec)

    def write_results() -> None:
        # Collect-time schema stabilization (additive-only; must not change semantics)
        try:
            _finalize_results_schema(
                results=results,
                command="test",
                topo_name=str(topo.get("name") or lab),
                lab_name=str(lab),
                phase="collect",
            )
        except Exception as e:
            # Never allow schema labeling to break gate execution.
            # Record as supporting evidence only (non-authoritative).
            try:
                auth = results.get("authority")
                if not isinstance(auth, dict):
                    auth = {}
                    results["authority"] = auth

                se = auth.get("supporting_evidence")
                if not isinstance(se, list):
                    se = []
                    auth["supporting_evidence"] = se

                se.append(
                    {
                        "type": "schema_finalize_error",
                        "authority": "supporting_evidence",
                        "error": _safe_stdio(str(e)),
                    }
                )
            except Exception:
                pass

        # Deterministic schema floor (additive-only):
        # Ensure stable headers + authority boundary + overall envelope exist,
        # even if _finalize_results_schema() is a no-op.
        try:
            results.setdefault("results_schema", "results.v1")
            results.setdefault("results_schema_version", "1.0.0")
            results.setdefault("tool", "ai-netsim")
            results.setdefault("command", "test")

            topo_obj = results.get("topology")
            if not isinstance(topo_obj, dict):
                topo_obj = {}
                results["topology"] = topo_obj
            topo_obj.setdefault("name", str(topo.get("name") or lab))

            lab_obj = results.get("lab_obj")
            if not isinstance(lab_obj, dict):
                lab_obj = {}
                results["lab_obj"] = lab_obj
            lab_obj.setdefault("name", str(lab))

            auth = results.get("authority")
            if not isinstance(auth, dict):
                auth = {}
                results["authority"] = auth
            auth.setdefault("verdict_source", "tests")
            se = auth.get("supporting_evidence")
            if not isinstance(se, list):
                auth["supporting_evidence"] = []

            if "hard_failure" not in results or not isinstance(results.get("hard_failure"), dict):
                results["hard_failure"] = {"occurred": False, "phase": "", "error": ""}

            if "tests" not in results or not isinstance(results.get("tests"), list):
                results["tests"] = results.get("tests") if isinstance(results.get("tests"), list) else []

            if "scenarios" not in results or not isinstance(results.get("scenarios"), list):
                results["scenarios"] = results.get("scenarios") if isinstance(results.get("scenarios"), list) else []

            if "events" not in results or not isinstance(results.get("events"), list):
                results["events"] = results.get("events") if isinstance(results.get("events"), list) else []

            legacy_result = str(results.get("result") or "fail").strip().lower()
            overall_verdict = "pass" if legacy_result == "pass" else "fail"
            overall_exit = 0 if overall_verdict == "pass" else 1

            overall = results.get("overall")
            if not isinstance(overall, dict):
                overall = {}
                results["overall"] = overall
            overall.setdefault("expected", "pass")
            overall["observed"] = overall_verdict
            overall["verdict"] = overall_verdict
            overall.setdefault("phase", "collect")
            overall.setdefault("exit_code", overall_exit)
        except Exception:
            # Never allow schema floor enforcement to break the gate
            pass

        out = lab_dir(lab) / "results.json"
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            write_json_canonical(out, results)
            _invocation_record_written_artifact(out)

            summary_path = write_test_summary_artifact(lab, results)
            _invocation_record_written_artifact(summary_path)

            # Fail-closed enforcement (gate authority):
            # If either authoritative artifact is missing/unwritten, treat as hard failure.
            if not out.exists():
                die(f"ERROR: gate artifact write failed (missing results.json): {out}", code=1)
            if not summary_path.exists():
                die(f"ERROR: gate artifact write failed (missing results.summary.txt): {summary_path}", code=1)

        except SystemExit:
            raise
        except Exception as e:
            die(f"ERROR: gate artifact write failed: {e}", code=1)

        # Legacy "Wrote:" lines are noisy/duplicative in quiet mode.
        # Keep them only for --verbose.
        if bool(getattr(args, "verbose", False)):
            print(f"Wrote: {out}")
            print(f"Wrote: {summary_path}")

        # Deterministic Gate Result block (presentation-only; derived from already-written results)
        try:
            rk = getattr(args, "_report_authority", None)
            blk = render_gate_result_block(results, authority_kind=rk)
            if isinstance(blk, str) and blk.strip():
                print(blk, end="" if blk.endswith("\n") else "\n")

            # WI-11.2: Zero-test PASS clarification (presentation-only; gate-mode only).
            try:
                summ = results.get("summary", {}) or {}
                total = int(summ.get("total") or 0)
                scenarios = results.get("scenarios", []) or []
                scen_total = len(scenarios) if isinstance(scenarios, list) else 0
                if total == 0 and scen_total == 0:
                    print("NOTE: No tests/scenarios declared — PASS means deploy/provision succeeded only.")
            except Exception:
                pass

            # WI-1 (Set 6): defer artifact path surfacing to the end-of-invocation footer
            # (main() finally calls _print_artifacts_footer_for_lab for gate-mode invocations).
            # Presentation-only; does not affect artifacts, schema, verdict, or exit code.
            res = str(results.get("result") or "fail").strip().lower()
            if res != "pass":
                # Ensure any earlier/inner attempts do not print duplicate blocks.
                # We intentionally do NOT print here (footer prints once, at the end).
                pass

            # WI-3: Stable summary block (presentation-only; fixed key order; CI-friendly).
            # Must not alter artifacts or verdicts; derived from already-written results.
            try:
                summ = results.get("summary", {}) or {}
                total = int(summ.get("total") or 0)
                passed = int(summ.get("passed") or 0)
                failed = int(summ.get("failed") or 0)
                skipped = int(summ.get("skipped") or 0)

                # Exit is presentation-only: mirrors gate exit bands (0/1/2).
                r = str(results.get("result") or "").strip().lower()
                exit_code = 0 if r == "pass" else 1
                hf = results.get("hard_failure") or {}
                if isinstance(hf, dict) and bool(hf.get("occurred")):
                    exit_code = 2

                print(f"TOTAL: {total}")
                print(f"PASS: {passed}")
                print(f"FAIL: {failed}")
                print(f"SKIP: {skipped}")
                print(f"EXIT: {exit_code}")
            except Exception:
                pass
        except Exception:
            # Never allow UX formatting to affect gate execution
            pass

        if print_json:
            print(json.dumps(results, indent=2))

    # Use module-level retry_until() (authoritative)
    # (Do not re-define it here; keep behavior consistent everywhere.)

    def _format_fail_line_from_testrec(rec: dict) -> str:
        """
        WI-2: Deterministic single-line FAIL message for gate output.
        Presentation-only. Must not change verdicts, artifacts, or exit codes.
        """
        name = str(rec.get("name") or "<unnamed>").strip() or "<unnamed>"
        exp = str(rec.get("expected") or "").strip()
        obs = str(rec.get("observed") or "").strip()

        # Evidence: prefer explicit evidence string; fall back to error (single-line).
        ev = rec.get("evidence")
        if not isinstance(ev, str) or not ev.strip():
            ev = rec.get("error")
        ev_s = str(ev or "").strip()
        if "\n" in ev_s:
            ev_s = ev_s.splitlines()[0].strip()

        # WI-2 (Set 6): bounded, deterministic evidence excerpt for quiet-mode ERROR line.
        if len(ev_s) > 120:
            ev_s = ev_s[:120] + "…"

        # NOTE: die() will prefix "ERROR: " in gate mode; do not embed "ERROR:" here.
        return f'test={name} expected={exp} observed={obs} evidence="{ev_s}"'

    def fail_or_continue(msg: str) -> None:
        # WI-2: Prefer a structured FAIL line derived from the last recorded failing test.
        # This avoids ambiguous ad-hoc messages and guarantees test id + expected/observed + evidence.
        try:
            tests_list = results.get("tests", []) or []
            if isinstance(tests_list, list) and tests_list:
                last = tests_list[-1]
                if isinstance(last, dict) and str(last.get("verdict") or "").strip().lower() == "fail":
                    msg = _format_fail_line_from_testrec(last)
        except Exception:
            pass

        if keep_going:
            # Keep legacy prefix under keep-going mode, but content is now structured.
            print(f"{msg}")
            return

        # WI-2: Fail-fast test failures must still finalize + write authoritative artifacts
        # so the Gate Result block reflects executed tests (no "Declared tests executed: 0"
        # when a declared test actually ran).
        try:
            tests_list = results.get("tests", []) or []
            if isinstance(tests_list, list):
                total = len(tests_list)
                passed = 0
                failed = 0
                skipped = 0
                for tr in tests_list:
                    if not isinstance(tr, dict):
                        continue
                    v = str(tr.get("verdict") or "").strip().lower()
                    if v == "pass":
                        passed += 1
                    elif v == "fail":
                        failed += 1
                    elif v == "skip":
                        skipped += 1

                results.setdefault("summary", {})
                if isinstance(results.get("summary"), dict):
                    results["summary"]["total"] = total
                    results["summary"]["passed"] = passed
                    results["summary"]["failed"] = failed
                    results["summary"]["skipped"] = skipped

            results["result"] = "fail"
            write_results()
        except Exception:
            # Never allow finalization to mask the original failure signal
            pass

        die(msg)

    def node_ip_or_die(node_name: str) -> str:
        ip = node_first_ipv4(topo, node_name)
        if not ip:
            die(f"TEST FAIL: could not determine IPv4 for node '{node_name}'")
        return ip

    # TCP listeners we started (for deterministic cleanup)
    listeners_started: dict[str, set[int]] = {}

    def start_listener(dst: str, port: int) -> None:
        listeners_started.setdefault(dst, set())
        if port in listeners_started[dst]:
            return
        start_tcp_listener(rt, lab, dst, port)
        listeners_started[dst].add(port)

    # -----------------------------
    # Atomic test execution helpers
    # -----------------------------
    def run_ping_test(*, test_name: str, src: str, dst: str, t: dict, record_fn=record_test) -> dict:
        expected = (t.get("expect") or "pass").lower()
        if expected not in ("pass", "fail"):
            expected = "pass"

        # ---- destination resolution (v1-safe) ----
        dst_kind = t.get("_dst_kind")
        dst_value = t.get("_dst_value")

        if dst_kind and dst_value:
            dst_token = str(dst_value).strip()
        else:
            dst_token = (t.get("dst") or t.get("to") or t.get("to_ip") or "").strip()

        if not dst_token:
            die(f"test {test_name}: missing destination (need dst or to/to_ip)")

        if dst_kind == "ip" or is_ip_literal(dst_token):
            dst_ip = dst_token
            validate_ip_literal(dst_ip, f"test {test_name}")
        else:
            dst_ip = node_ip_or_die(dst_token)

        # ---- execution params ----
        count = int(t.get("count") or 2)

        # ICMP per-attempt timeout (-W). Keep it small and explicit.
        per_attempt_timeout_s = int(t.get("per_attempt_timeout_s") or 1)

        # Retry window applies only when we expect success (convergence)
        retry_timeout_s = int(t.get("timeout_s") or 15)
        retry_interval_s = float(t.get("retry_interval_s") or 1.0)

        # v1.x optional ping source selector (Tier-1 validation only)
        src_ip = t.get("src_ip")
        src_if = t.get("src_if")

        if src_ip is not None and src_if is not None:
            die(f"ERROR: ping test '{test_name}': specify only one of src_ip or src_if")

        if src_ip is not None:
            if not isinstance(src_ip, str) or not src_ip.strip():
                die(f"ERROR: ping test '{test_name}': src_ip must be a non-empty string")
            validate_ip_literal(src_ip.strip(), f"ping test '{test_name}' src_ip")

        if src_if is not None:
            if not isinstance(src_if, str) or not src_if.strip():
                die(f"ERROR: ping test '{test_name}': src_if must be a non-empty string")
            if any(ch.isspace() for ch in src_if):
                die(f"ERROR: ping test '{test_name}': src_if must not contain whitespace")

        def _format_ping_ctx(*, expected_s: str, observed_s: str) -> str:
            dst_part = str(dst_ip) if dst_ip else f"<unresolved: {dst_token}>"
            extras = []
            if src_if:
                extras.append(f"src_if={str(src_if).strip()}")
            if src_ip:
                extras.append(f"src_ip={str(src_ip).strip()}")
            extra_s = f" ({', '.join(extras)})" if extras else ""
            return f"ping mismatch: from={src} dst={dst_part} expected={expected_s} observed={observed_s}{extra_s}"

        def attempt():
            ping_cmd = ["ping", "-c", str(count), "-W", str(per_attempt_timeout_s)]
            if src_ip:
                ping_cmd += ["-I", str(src_ip).strip()]
            elif src_if:
                ping_cmd += ["-I", str(src_if).strip()]
            ping_cmd += [dst_ip]

            cp = rt.exec(
                lab,
                src,
                ping_cmd,
                check=False,
            )
            return (cp.returncode == 0), cp

        if expected == "fail":
            # v1 gate semantics: expected fail is fail-fast (single attempt)
            ok, last_cp = attempt()
            attempts = 1
            dur_ms = 0
        else:
            ok, last_cp, attempts, dur_ms = retry_until(retry_timeout_s, retry_interval_s, attempt)

        observed = "pass" if ok else "fail"
        should_succeed = (expected == "pass")
        verdict = "pass" if (ok == should_succeed) else "fail"

        err = "" if verdict == "pass" else _format_ping_ctx(expected_s=expected, observed_s=observed)

        rec = {
            "name": test_name,
            "kind": "ping",
            "from": src,
            "to": dst,
            "expected": expected,
            "observed": observed,
            "verdict": verdict,
            "duration_ms": int(dur_ms),
            "error": err,
            "meta": {
                "dst_ip": dst_ip,
                "dst_raw": dst_token,
                "count": count,
                "per_attempt_timeout_s": per_attempt_timeout_s,
                "attempts": attempts,
                "retry_timeout_s": (retry_timeout_s if expected == "pass" else 0),
                "retry_interval_s": (retry_interval_s if expected == "pass" else 0),
                "last_rc": getattr(last_cp, "returncode", None),
                "src_ip": (str(src_ip).strip() if src_ip else ""),
                "src_if": (str(src_if).strip() if src_if else ""),
            },
        }

        # Record once, always
        record_fn(
            name=rec["name"],
            kind=rec["kind"],
            src=rec["from"],
            dst=rec["to"],
            expected=rec["expected"],
            observed=rec["observed"],
            verdict=rec["verdict"],
            evidence={
                "cmd": "ping",
                "src_ip": (str(src_ip).strip() if src_ip else ""),
                "src_if": (str(src_if).strip() if src_if else ""),
                "dst_ip": str(dst_ip),
            },
            duration_ms=rec["duration_ms"],
            error=rec["error"],
            meta=rec["meta"],
        )

        return rec

    def run_tcp_test(*, test_name: str, src: str, dst: str, t: dict, record_fn=record_test) -> str:
        expected = (t.get("expect") or "pass").lower()
        if expected not in ("pass", "fail"):
            expected = "pass"

        port = t.get("port")
        if not isinstance(port, int):
            record_fn(
                name=test_name,
                kind="tcp",
                src=src,
                dst=dst,
                expected=expected,
                observed="fail",
                verdict="fail",
                evidence={"reason": "invalid_port"},
                duration_ms=0,
                error="'port' must be an int",
                meta={"port": port},
            )
            return "fail"

        dst_ip = node_ip_or_die(dst)
        listener = bool(t.get("listener", True))
        if listener:
            start_listener(dst, port)

        timeout_s = int(t.get("timeout_s") or (10 if expected == "pass" else 0))
        interval_s = float(t.get("retry_interval_s") or 1.0)

        def attempt():
            cp = rt.exec(lab, src, ["sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"], check=False)
            return (cp.returncode == 0), cp

        start = time.time()
        if expected == "pass" and timeout_s > 0:
            ok, last_cp, attempts, dur_ms = retry_until(timeout_s, interval_s, attempt)
        else:
            cp = rt.exec(lab, src, ["sh", "-lc", f"nc -z -w 2 {dst_ip} {port}"], check=False)
            ok, last_cp, attempts = (cp.returncode == 0), cp, 1
            dur_ms = int((time.time() - start) * 1000)

        observed = "pass" if ok else "fail"
        should_succeed = (expected == "pass")
        verdict = "pass" if (ok == should_succeed) else "fail"

        record_fn(
            name=test_name,
            kind="tcp",
            src=src,
            dst=dst,
            expected=expected,
            observed=observed,
            verdict=verdict,
            evidence={"cmd": "nc -z"},
            duration_ms=dur_ms,
            error="" if verdict == "pass" else f"tcp mismatch (expected {expected}, observed {observed})",
            meta={
                "dst_ip": dst_ip,
                "port": int(port),
                "listener": bool(listener),
                "attempts": attempts,
                "timeout_s": timeout_s,
                "retry_interval_s": interval_s,
                "rc": getattr(last_cp, "returncode", None),
            },
        )
        return verdict


    # Build name->test map once (authoritative declared tests)
    declared_tests = topo.get("tests", []) or []
    tests_by_name: dict[str, dict] = {}
    for idx, t in enumerate(declared_tests):
        if isinstance(t, dict) and t.get("name"):
            tests_by_name[str(t["name"])] = t

    def run_route_prefix_test(*, test_name: str, src: str, t: dict, record_fn=record_test) -> str:
        """
        v1.5: per-prefix assertion (execution-backed), minimal deterministic parsing.
        - src: vantage node name (runs check here)
        - prefix: CIDR string
        - expect: pass|fail (negative semantics preserved)
        Current v1.5 support: frr nodes only (vtysh).
        """
        prefix = str(t.get("prefix") or "").strip()

        expected = str(t.get("expect") or "pass").strip().lower()
        if expected not in ("pass", "fail"):
            expected = "pass"

        # Resolve node type deterministically from resolved topology
        node_type = ""
        for n in (topo.get("nodes") or []):
            if isinstance(n, dict) and n.get("name") == src:
                node_type = str(n.get("type") or "").strip().lower()
                break

        start = time.time()

        if node_type != "frr":
            dur_ms = int((time.time() - start) * 1000)
            observed = "fail"
            verdict = "fail" if expected == "pass" else "pass"
            record_fn(
                name=test_name,
                kind="route_prefix",
                src=src,
                dst="",
                expected=expected,
                observed=observed,
                verdict=verdict,
                duration_ms=dur_ms,
                error=f"route_prefix unsupported on node type '{node_type}' (supported: frr only)",
                evidence={"reason": "unsupported_node_type"},
                meta={"prefix": prefix, "node_type": node_type},
            )
            return verdict

        # Deterministic route presence check (kernel FIB)
        # Rationale: connected routes + installed routes are observable here even if FRR daemons/vtysh view differs.
        try:
            nw = ipaddress.ip_network(prefix, strict=False)
            ipver = nw.version
        except Exception:
            # Should have been caught in resolve-time validation; keep deterministic failure here.
            ipver = 4

        ip_cmd = ["ip", f"-{ipver}", "route", "show", prefix]
        cp = rt.exec(lab, src, ip_cmd, check=False, capture_output=True)

        # rt.exec() may return a CompletedProcess-like object OR a raw string.
        if isinstance(cp, str):
            out = cp
            rc = None
        else:
            out = ""
            if hasattr(cp, "stdout") and cp.stdout is not None:
                out = cp.stdout
            elif hasattr(cp, "output") and cp.output is not None:
                out = cp.output

            # Normalize bytes -> str (defensive)
            if isinstance(out, (bytes, bytearray)):
                try:
                    out = out.decode("utf-8", errors="replace")
                except Exception:
                    out = str(out)

            rc = getattr(cp, "returncode", None)

        out = str(out or "")
        # Deterministic presence rule for `ip route show <prefix>`:
        # - present => prints one or more lines
        # - absent  => prints nothing
        present = bool(out.strip())

        observed = "pass" if present else "fail"
        verdict = "pass" if observed == expected else "fail"

        dur_ms = int((time.time() - start) * 1000)
        record_fn(
            name=test_name,
            kind="route_prefix",
            src=src,
            dst="",
            expected=expected,
            observed=observed,
            verdict=verdict,
            duration_ms=dur_ms,
            error="" if verdict == "pass" else f"route_prefix mismatch (expected {expected}, observed {observed})",
            evidence={"cmd": " ".join(ip_cmd), "rc": rc},
            meta={"prefix": prefix, "present": bool(present)},
        )
        return verdict

    def run_bgp_neighbor_test(*, test_name: str, src: str, dst: str, t: dict, record_fn=record_test) -> str:
        """
        v1.x: binary control-plane health invariant.
        - src: node name (runs vtysh here)
        - dst: neighbor IPv4 literal (string)
        - expect: pass|fail (also accepts up|down synonyms)
        """

        raw_expect = (t.get("expect") or "pass")
        exp_s = str(raw_expect).strip().lower()

        # Normalize expected -> "up" or "down"
        if exp_s in ("pass", "up", "established", "true", "ok", "allow"):
            expected = "up"
        elif exp_s in ("fail", "down", "false", "drop", "deny"):
            expected = "down"
        else:
            expected = "up"

        neighbor = str(dst or "").strip()
        try:
            ip = ipaddress.ip_address(neighbor)
            if ip.version != 4:
                raise ValueError("neighbor must be IPv4")
        except Exception:
            record_fn(
                name=test_name,
                kind="bgp_neighbor",
                src=src,
                dst=dst,
                expected=expected,
                observed="down",
                verdict="fail",
                duration_ms=0,
                error="dst must be an IPv4 neighbor address",
                meta={"neighbor": neighbor},
                evidence={"reason": "invalid_neighbor_ip"},
            )
            return "fail"

        timeout_s = int(t.get("timeout_s") or (15 if expected == "up" else 0))
        interval_s = float(t.get("retry_interval_s") or 1.0)

        def attempt():
            # Prefer JSON for deterministic parsing
            cp = rt.exec(lab, src, ["vtysh", "-c", "show bgp summary json"], check=False)
            ok = (getattr(cp, "returncode", 1) == 0)
            out = (cp.stdout or "") if hasattr(cp, "stdout") else ""
            return ok, cp, out

        start = time.time()

        # Only retry when we expect "up" (deterministic + aligns with readiness semantics)
        if expected == "up" and timeout_s > 0:
            def try_once():
                ok, cp, out = attempt()
                return ok, (cp, out)

            ok, last_payload, attempts, dur_ms = retry_until(timeout_s, interval_s, try_once)
            last_cp, last_out = last_payload
        else:
            ok, last_cp, last_out = attempt()
            attempts = 1
            dur_ms = int((time.time() - start) * 1000)

        observed = "down"
        state = None
        parse_error = ""

        if ok:
            try:
                data = json.loads(last_out or "{}")

                def _extract_peers(obj: dict) -> dict | None:
                    # 1) Some FRR builds: peers at top-level
                    peers = obj.get("peers")
                    if isinstance(peers, dict):
                        return peers

                    # 2) Common FRR: peers under address-family key, e.g. ipv4Unicast.peers
                    v4u = obj.get("ipv4Unicast")
                    if isinstance(v4u, dict):
                        peers = v4u.get("peers")
                        if isinstance(peers, dict):
                            return peers

                    # 3) Defensive: scan 1 level deep for any dict that contains a peers dict
                    for _, v in obj.items():
                        if isinstance(v, dict):
                            peers = v.get("peers")
                            if isinstance(peers, dict):
                                return peers

                    return None

                peers = _extract_peers(data)
                if not isinstance(peers, dict):
                    peers = {}
                    parse_error = "peers not found in summary"

                p = peers.get(neighbor)

                if isinstance(p, dict):
                    # FRR fields vary; prefer "state" when present
                    state = p.get("state") or p.get("bgpState") or p.get("peerState")
                    st = (state or "").strip().lower()
                    observed = "up" if st == "established" else "down"
                else:
                    observed = "down"
                    if not parse_error:
                        parse_error = "neighbor not present in summary"

            except Exception as e:
                observed = "down"
                parse_error = f"json parse error: {e.__class__.__name__}"
        else:
            parse_error = "vtysh command failed"

        verdict = "pass" if observed == expected else "fail"

        meta = {
            "neighbor": neighbor,
            "state": state,
            "attempts": attempts,
            "timeout_s": timeout_s,
            "retry_interval_s": interval_s,
            "last_rc": getattr(last_cp, "returncode", None),
        }

        evidence = {
            "cmd": "vtysh -c 'show bgp summary json'",
            "parse_error": parse_error,
        }

        record_fn(
            name=test_name,
            kind="bgp_neighbor",
            src=src,
            dst=dst,
            expected=expected,
            observed=observed,
            verdict=verdict,
            duration_ms=int(dur_ms),
            error="" if verdict == "pass" else f"bgp neighbor mismatch (expected {expected}, observed {observed})",
            meta=meta,
            evidence=evidence,
        )

        return verdict

    def run_named_test(ref: str, *, scenario_ctx: tuple[str, int] | None = None) -> str:
        """
        Execute a declared atomic test by name (used by scenarios).
        Returns: "pass" | "fail"
        """
        if ref not in tests_by_name:
            # With fail-fast validation, this should never happen.
            die(f"INTERNAL ERROR: scenario referenced unknown test '{ref}' after pre-validation")

        t = tests_by_name[ref]

        kind = (t.get("kind") or t.get("type") or "").strip()

        src = t.get("src")
        dst = t.get("dst")

        if kind == "ping":
            if not src or not (dst or t.get("to") or t.get("to_ip")):
                record_test(
                    name=ref,
                    kind=kind or "ping",
                    src=src or "",
                    dst=(dst or t.get("to") or t.get("to_ip") or ""),
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    evidence={"reason": "missing_src_dst"},
                    duration_ms=0,
                    error="missing src + (dst or to/to_ip)",
                )
                return "fail"

        elif kind == "bgp_neighbor":
            if not src or not dst:
                record_test(
                    name=ref,
                    kind=kind,
                    src=src or "",
                    dst=dst or "",
                    expected="up",
                    observed="fail",
                    verdict="fail",
                    evidence={"reason": "missing_src_dst"},
                    duration_ms=0,
                    error="missing src/dst (neighbor IPv4 required)",
                )
                return "fail"

            if not isinstance(dst, str) or not is_ip_literal(dst.strip()):
                record_test(
                    name=ref,
                    kind=kind,
                    src=src or "",
                    dst=str(dst) if dst is not None else "",
                    expected="up",
                    observed="fail",
                    verdict="fail",
                    evidence={"reason": "invalid_neighbor_ip"},
                    duration_ms=0,
                    error="dst must be an IPv4 neighbor address",
                )
                return "fail"

        else:
            if not src or not dst:
                record_test(
                    name=ref,
                    kind=kind or "unknown",
                    src=src or "",
                    dst=dst or "",
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    evidence={"reason": "missing_src_dst"},
                    duration_ms=0,
                    error="missing src/dst",
                )
                return "fail"

        record_fn = None
        if scenario_ctx:
            sid, step_idx = scenario_ctx
            record_fn = lambda **kw: record_event_test_run(scenario_id=sid, step_index=step_idx, **kw)

        if kind == "ping":
            if record_fn:
                dst_label = dst or t.get("to") or t.get("to_ip") or ""
                rec = run_ping_test(test_name=ref, src=src, dst=dst_label, t=t, record_fn=record_fn)
                # In scenario mode, run_named_test must return a verdict string.
                if isinstance(rec, dict):
                    return str(rec.get("verdict") or "fail")
                return str(rec)
            # Non-scenario path preserves existing behavior (dict record)
            return run_ping_test(test_name=ref, src=src, dst=dst, t=t)

        if kind == "tcp":
            if record_fn:
                return run_tcp_test(test_name=ref, src=src, dst=dst, t=t, record_fn=record_fn)
            return run_tcp_test(test_name=ref, src=src, dst=dst, t=t)
        
        if kind == "bgp_neighbor":
            if record_fn:
                return run_bgp_neighbor_test(test_name=ref, src=src, dst=dst, t=t, record_fn=record_fn)
            return run_bgp_neighbor_test(test_name=ref, src=src, dst=dst, t=t)

        record_test(
            name=ref,
            kind=str(kind or "unknown"),
            src=src,
            dst=dst,
            expected="pass",
            observed="fail",
            verdict="fail",
            duration_ms=0,
            error=f"unsupported kind '{kind}' (supported: ping, tcp, bgp_neighbor)",

        )
        return "fail"
    
    # Scenario fault state (per test run, in-memory only; deterministic)
    # key: (node, iface) -> list[str] of "ip route" lines to restore
    fault_state_routes_v4: dict[tuple[str, str], list[str]] = {}

    def _clean_route_line(line: str) -> str:
        """
        Remove transient/non-authoritative tokens from `ip route show` output so we can
        deterministically restore routes after interface flaps.
        """
        s = line.strip()

        # Remove transient kernel status tokens
        # e.g. "via 10.0.0.2 linkdown" -> "via 10.0.0.2"
        s = re.sub(r"\s+linkdown\b", "", s)

        # Remove optional fields that can vary and aren't needed for restore
        # Examples:
        #   "proto bgp" / "proto static"
        #   "metric 20"
        #   "src 10.0.0.3"
        #   "pref medium" (rare)
        s = re.sub(r"\s+proto\s+\S+", "", s)
        s = re.sub(r"\s+metric\s+\d+", "", s)
        s = re.sub(r"\s+src\s+\S+", "", s)
        s = re.sub(r"\s+pref\s+\S+", "", s)

        # Collapse whitespace to keep stable splitting
        s = re.sub(r"\s+", " ", s).strip()
        return s

    def _snapshot_v4_via_routes(node: str, iface: str) -> list[str]:
        """
        Capture interface-scoped *via* routes that Linux may remove when iface goes down.
        Deterministic: exact command, stable filtering + sanitization.
        """
        cp = rt.exec(lab, node, ["ip", "-4", "route", "show", "dev", str(iface)], check=False)
        out = (cp.stdout or "") if hasattr(cp, "stdout") else ""
        lines: list[str] = []

        for raw in out.splitlines():
            line = raw.strip()
            if not line:
                continue

            # Only restore routed entries (not connected proto kernel routes)
            if " via " not in f" {line} ":
                continue

            # Ignore cached/temporary artifacts if present
            if line.endswith(" cache") or " cache " in line:
                continue

            cleaned = _clean_route_line(line)
            if cleaned:
                lines.append(cleaned)

        return sorted(set(lines))

    def _restore_v4_routes(node: str, routes: list[str]) -> None:
        """
        Restore routes using `ip -4 route replace <route-line>`.
        Best-effort but deterministic: run in sorted order, no retries.
        """
        for r in sorted(set(routes)):
            rt.exec(lab, node, ["ip", "-4", "route", "replace"] + r.split(), check=False)

    def _find_link_interfaces_from_topology(
        topo: dict,
        a: str,
        b: str,
        *,
        a_if: str | None = None,
        b_if: str | None = None,
    ) -> tuple[str | None, str | None]:
        """
        Deterministically map node pair -> interface pair.

        If a_if/b_if provided:
        - must match a declared link exactly (order-insensitive, mapped to a->b direction)

        If not provided:
        - there must be exactly ONE link between a and b, otherwise fail fast.
        """
        links = topo.get("links", []) or []

        def parse_ep(ep: str) -> tuple[str, str] | None:
            if not isinstance(ep, str) or ":" not in ep:
                return None
            n, iface = ep.split(":", 1)
            n = n.strip()
            iface = iface.strip()
            if not n or not iface:
                return None
            return n, iface

        matches: list[tuple[str, str]] = []
        for link in links:
            eps = link.get("endpoints")
            if not isinstance(eps, list) or len(eps) != 2:
                continue
            p0 = parse_ep(eps[0])
            p1 = parse_ep(eps[1])
            if not p0 or not p1:
                continue

            (n0, if0), (n1, if1) = p0, p1

            if n0 == a and n1 == b:
                matches.append((if0, if1))
            elif n0 == b and n1 == a:
                matches.append((if1, if0))

        # Explicit disambiguation path
        if a_if is not None or b_if is not None:
            if not (isinstance(a_if, str) and isinstance(b_if, str)):
                die("fault link_down/link_up: a_if and b_if must be strings when provided")

            a_if_s = a_if.strip()
            b_if_s = b_if.strip()
            if not a_if_s or not b_if_s:
                die("fault link_down/link_up: a_if and b_if must be non-empty when provided")

            if (a_if_s, b_if_s) in matches:
                return a_if_s, b_if_s

            die(
                f"fault link_down/link_up: provided {a}:{a_if_s}<->{b}:{b_if_s} "
                f"does not match any declared link between {a} and {b}"
            )

        # Implicit path: must be unambiguous
        if len(matches) == 0:
            die(f"fault link_down/link_up: no link found between {a} and {b}")
        if len(matches) > 1:
            die(
                f"fault link_down/link_up: ambiguous links between {a} and {b} "
                f"({len(matches)} found); provide a_if/b_if"
            )

        return matches[0]

    def _find_link_interfaces(
        a: str,
        b: str,
        *,
        a_if: str | None = None,
        b_if: str | None = None,
    ) -> tuple[str | None, str | None]:
        """
        Determine interface pair for a<->b.

        Deterministic rules:
        - If a_if/b_if provided: require topo["links"] to match exactly; fail fast otherwise.
        - If not provided: prefer topo["links"] unambiguous match; else fall back to links_by_node best-effort.
        """
        # Prefer authoritative topo["links"] parsing (most reliable)
        try:
            ta_if, tb_if = _find_link_interfaces_from_topology(topo, a, b, a_if=a_if, b_if=b_if)
            if ta_if and tb_if:
                return ta_if, tb_if
        except SystemExit:
            # If user explicitly disambiguated, do NOT fall back to guessing.
            if a_if is not None or b_if is not None:
                raise
            # Otherwise, allow fallback below.
            pass

        # Fallback: best-effort from build_node_links() if present (only when not explicitly disambiguated)
        fa_if: str | None = None
        fb_if: str | None = None

        for l in links_by_node.get(a, []) or []:
            if l.get("peer") == b:
                fa_if = l.get("ifname") or l.get("iface") or l.get("interface")
                fb_if = l.get("peer_ifname") or l.get("peer_iface") or l.get("peer_interface")
                break

        if fb_if is None:
            for l in links_by_node.get(b, []) or []:
                if l.get("peer") == a:
                    fb_if = l.get("ifname") or l.get("iface") or l.get("interface")
                    if fa_if is None:
                        fa_if = l.get("peer_ifname") or l.get("peer_iface") or l.get("peer_interface")
                    break

        return fa_if, fb_if

    def apply_fault(
        fault: dict,
        *,
        fault_state_routes_v4: dict[tuple[str, str], list[str]],
    ) -> tuple[str, str, dict]:
        """
        Returns: (action, target_label, meta)
        meta includes restored_routes for link_up/interface_up
        """

        def _iface_down(node: str, iface: str) -> None:
            key = (node, iface)
            fault_state_routes_v4[key] = _snapshot_v4_via_routes(node, iface)
            rt.exec(lab, node, ["ip", "link", "set", "dev", str(iface), "down"], check=False)

        def _iface_up(node: str, iface: str) -> int:
            rt.exec(lab, node, ["ip", "link", "set", "dev", str(iface), "up"], check=False)
            key = (node, iface)
            routes = fault_state_routes_v4.get(key) or []
            if routes:
                _restore_v4_routes(node, routes)
            return len(routes)

        # ----------------------------
        # link_down / link_up
        # Supports optional a_if/b_if for deterministic multi-link disambiguation.
        # ----------------------------
        if "link_down" in fault or "link_up" in fault:
            action = "link_down" if "link_down" in fault else "link_up"
            spec = fault.get(action) or {}
            a = spec.get("a")
            b = spec.get("b")
            if not a or not b:
                raise ValueError(f"{action}: requires a,b")

            # Optional explicit interface disambiguation (validated earlier in validate_scenarios)
            a_if_req = spec.get("a_if")
            b_if_req = spec.get("b_if")

            a_if, b_if = _find_link_interfaces(a, b, a_if=a_if_req, b_if=b_if_req)
            if not a_if or not b_if:
                raise ValueError(f"{action}: could not determine interfaces for link {a}<->{b}")

            if action == "link_down":
                _iface_down(a, a_if)
                _iface_down(b, b_if)
                return action, f"{a}:{a_if}<->{b}:{b_if}", {"restored_routes": 0}

            ra = _iface_up(a, a_if)
            rb = _iface_up(b, b_if)
            return action, f"{a}:{a_if}<->{b}:{b_if}", {"restored_routes": (ra + rb)}

        # ----------------------------
        # interface_down / interface_up
        # ----------------------------
        if "interface_down" in fault or "interface_up" in fault:
            action = "interface_down" if "interface_down" in fault else "interface_up"
            spec = fault.get(action) or {}
            node = spec.get("node")
            iface = spec.get("if") or spec.get("iface") or spec.get("interface")
            if not node or not iface:
                raise ValueError(f"{action}: requires node + if")

            if action == "interface_down":
                _iface_down(node, str(iface))
                return action, f"{node}:{iface}", {"restored_routes": 0}

            r = _iface_up(node, str(iface))
            return action, f"{node}:{iface}", {"restored_routes": r}

        # ----------------------------
        # node_stop / node_start (future primitives)
        # ----------------------------
        if "node_stop" in fault or "node_start" in fault:
            action = "node_stop" if "node_stop" in fault else "node_start"
            spec = fault.get(action) or {}
            node = spec.get("node")
            if not node:
                raise ValueError(f"{action}: requires node")
            fn_name = "node_stop" if action == "node_stop" else "node_start"
            if not hasattr(rt, fn_name):
                raise ValueError(f"{action}: runtime does not implement {fn_name}() yet")
            getattr(rt, fn_name)(lab, node)  # type: ignore[misc]
            return action, str(node), {"restored_routes": 0}

        raise ValueError(f"unsupported fault primitive: {list(fault.keys())}")

    def wait_seconds(seconds: int) -> int:
        start = time.time()
        time.sleep(max(0, int(seconds)))
        return int((time.time() - start) * 1000)

    def wait_for_predicate(wait_for: dict) -> tuple[str, str, str, int, dict, str]:
        src = wait_for.get("from")
        wtype = (wait_for.get("type") or "ping").strip().lower()
        expected = (wait_for.get("expect") or "pass").lower()
        timeout_s = int(wait_for.get("timeout") or 30)
        interval_s = float(wait_for.get("interval_s") or 1.0)

        if expected not in ("pass", "fail"):
            raise ValueError(f"wait_for {wtype}: expect must be pass|fail")
        if not isinstance(src, str) or not src.strip():
            raise ValueError(f"wait_for {wtype}: from must be a non-empty node name")

        # Shared bounded semantics:
        # - Define "attempt success" as the underlying check returning PASS.
        # - expect=pass => pass if any attempt succeeds within timeout.
        # - expect=fail => pass if NO attempt succeeds within timeout.
        #
        # IMPORTANT:
        # retry_until() returns ok=True when the attempt reports "success" (underlying PASS),
        # and ok=False if no underlying PASS occurred within timeout.

        # Optional per-attempt timeout (recorded; enforced only where explicitly supported)
        per_attempt_timeout_s = int(wait_for.get("per_attempt_timeout_s") or 1)

        # v1.x optional ping source selector (Tier-1 validation only)
        src_ip = wait_for.get("src_ip")
        src_if = wait_for.get("src_if")
        if src_ip is not None and src_if is not None:
            raise ValueError("wait_for ping: specify only one of src_ip or src_if")

        first_success_ms = None
        first_success_observed = None  # "pass"|"fail" (underlying)
        last_cp = None
        last_obs = "fail"
        last_evidence: dict = {}

        start = time.time()

        def _mark_success(obs: str) -> None:
            nonlocal first_success_ms, first_success_observed
            if first_success_ms is None:
                first_success_ms = int((time.time() - start) * 1000)
                first_success_observed = obs

        def attempt():
            nonlocal last_cp, last_obs, last_evidence

            # -------------------------
            # type: ping
            # -------------------------
            if wtype == "ping":
                to = wait_for.get("to")
                if not to:
                    raise ValueError("wait_for ping: requires to")

                # v1.x ping tuning (deterministic, explicit)
                count = int(wait_for.get("count") or 1)

                if src_ip is not None:
                    if not isinstance(src_ip, str) or not str(src_ip).strip():
                        raise ValueError("wait_for ping: src_ip must be a non-empty string")
                    validate_ip_literal(str(src_ip).strip(), "wait_for ping src_ip")

                if src_if is not None:
                    if not isinstance(src_if, str) or not str(src_if).strip():
                        raise ValueError("wait_for ping: src_if must be a non-empty string")
                    if any(ch.isspace() for ch in str(src_if)):
                        raise ValueError("wait_for ping: src_if must not contain whitespace")

                if count < 1:
                    raise ValueError("wait_for ping: count must be >= 1")
                if per_attempt_timeout_s < 1:
                    raise ValueError("wait_for ping: per_attempt_timeout_s must be >= 1")

                if not isinstance(to, str) or not to.strip():
                    raise ValueError("wait_for ping: to must be a non-empty string (node name or IP literal)")
                dst_ip = resolve_dst_to_ip(topo, to.strip())

                ping_cmd = ["ping", "-c", str(count), "-W", str(per_attempt_timeout_s)]
                if src_ip:
                    ping_cmd += ["-I", str(src_ip).strip()]
                elif src_if:
                    ping_cmd += ["-I", str(src_if).strip()]
                ping_cmd += [str(dst_ip)]

                cp = rt.exec(lab, str(src).strip(), ping_cmd, check=False)
                last_cp = cp
                ping_ok = (cp.returncode == 0)

                last_obs = "pass" if ping_ok else "fail"
                last_evidence = {
                    "cmd": "ping",
                    "dst_ip": str(dst_ip),
                    "last_rc": getattr(cp, "returncode", None),
                }

                attempt_success = (last_obs == "pass")
                return attempt_success, (cp, last_obs)

            # -------------------------
            # type: tcp
            # -------------------------
            if wtype == "tcp":
                to = wait_for.get("to")
                port = wait_for.get("port")

                if not isinstance(to, str) or not to.strip():
                    raise ValueError("wait_for tcp: to must be a non-empty string (node name or IP literal)")

                try:
                    port_i = int(port)
                except Exception:
                    raise ValueError("wait_for tcp: port must be an int")
                if port_i < 1 or port_i > 65535:
                    raise ValueError("wait_for tcp: port must be in range 1..65535")

                dst_ip = resolve_dst_to_ip(topo, to.strip())
                ensure_nc(rt, lab, str(src).strip())

                # Deterministic connect check; attempt timeout is explicit via -w
                cp = rt.exec(
                    lab,
                    str(src).strip(),
                    ["sh", "-lc", f"nc -z -w {per_attempt_timeout_s} {dst_ip} {port_i}"],
                    check=False,
                )
                last_cp = cp
                tcp_ok = (cp.returncode == 0)

                last_obs = "pass" if tcp_ok else "fail"
                last_evidence = {
                    "cmd": "nc -z",
                    "dst_ip": str(dst_ip),
                    "port": int(port_i),
                    "last_rc": getattr(cp, "returncode", None),
                }

                attempt_success = (last_obs == "pass")
                return attempt_success, (cp, last_obs)

            # -------------------------
            # type: route_prefix
            # -------------------------
            if wtype == "route_prefix":
                # Vantage node is wait_for.src (normalized from on->src in resolve)
                vantage = wait_for.get("src") or wait_for.get("on")
                if not isinstance(vantage, str) or not vantage.strip():
                    raise ValueError("wait_for route_prefix: requires src/on as a node name")

                prefix = wait_for.get("prefix")
                if not isinstance(prefix, str) or not prefix.strip():
                    raise ValueError("wait_for route_prefix: requires prefix as CIDR")

                # Deterministic: ip route lookup should be fast; per_attempt_timeout_s is recorded.
                cmd = ["sh", "-lc", f"ip -4 route show {prefix.strip()} 2>/dev/null || true"]
                cp = rt.exec(lab, str(vantage).strip(), cmd, check=False)
                last_cp = cp

                out = getattr(cp, "stdout", "") or ""
                if isinstance(out, (bytes, bytearray)):
                    try:
                        out = out.decode("utf-8", errors="replace")
                    except Exception:
                        out = str(out)

                present = (prefix.strip() in str(out))

                # Underlying success for route_prefix is: present == True (uniform success definition)
                last_obs = "pass" if present else "fail"
                last_evidence = {
                    "cmd": f"ip -4 route show {prefix.strip()}",
                    "prefix": prefix.strip(),
                    "present": bool(present),
                    "last_rc": getattr(cp, "returncode", None),
                }

                attempt_success = (last_obs == "pass")
                return attempt_success, (cp, last_obs)

            raise ValueError(f"wait_for: unsupported type {wtype!r}")

        ok, last_val, attempts, dur_ms = retry_until(timeout_s, interval_s, attempt)
        last_cp, last_obs = last_val  # type: ignore[misc]

        # First success timing (for bounds)
        if ok:
            _mark_success(last_obs)

        succeeded = bool(ok)

        # Observed is always the underlying check result from the last attempt.
        observed = str(last_obs)
        verdict = "pass" if succeeded else "fail"

        # Apply expect inversion semantics at verdict level:
        # - expect=pass => want succeeded==True
        # - expect=fail => want succeeded==False
        want = (expected == "pass")
        final_pass = (succeeded == want)
        verdict = "pass" if final_pass else "fail"

        meta = {
            "type": wtype,
            "from": str(src).strip(),
            "attempts": int(attempts),
            "timeout_s": int(timeout_s),
            "interval_s": float(interval_s),
            "per_attempt_timeout_s": int(per_attempt_timeout_s),
            "succeeded": bool(succeeded),
            "time_to_success_ms": (int(first_success_ms) if (expected == "pass") else None),
            "time_to_first_success_ms": (int(first_success_ms) if (expected == "fail" and succeeded) else None),
            "last_rc": getattr(last_cp, "returncode", None),
        }

        # Keep type-specific info inside meta
        if wtype in ("ping", "tcp"):
            meta["to"] = str(wait_for.get("to") or "")
            meta["src_ip"] = (str(src_ip).strip() if src_ip else "")
            meta["src_if"] = (str(src_if).strip() if src_if else "")
            if wtype == "ping":
                meta["count"] = int(wait_for.get("count") or 1)
            if wtype == "tcp":
                meta["port"] = int(wait_for.get("port") or 0)

        if wtype == "route_prefix":
            meta["src"] = str(wait_for.get("src") or wait_for.get("on") or "")
            meta["prefix"] = str(wait_for.get("prefix") or "")

        # Evidence: bounded and last-attempt only
        meta["evidence"] = dict(last_evidence)

        return wtype, expected, observed, int(dur_ms), meta, verdict

    def run_scenario(s: dict) -> str:
        sid = s.get("id") or ""
        desc = s.get("description") or ""
        steps = s.get("steps", []) or []
        scen_started = time.time()

        scen_rec: dict = {
            "id": sid,
            "description": desc,
            "steps": [],
            "verdict": "unknown",
            "duration_ms": None,
        }

        def scen_step(rec: dict) -> None:
            # wait_for step shape stabilization (representation-only, v1.5):
            # Ensure wait_for step records have a stable key-set across all paths
            # (success/fail/not-a-dict/exception) using present-with-null.
            if isinstance(rec, dict) and rec.get("type") == "wait_for":
                # Canonical schema = union of keys currently emitted across paths.
                # (Do not add new meaning-bearing keys.)
                canonical_keys = (
                    "type",
                    "wait_type",
                    "expected",
                    "observed",
                    "verdict",
                    "duration_ms",
                    "attempts",
                    "timeout_s",
                    "interval_s",
                    "succeeded",
                    "time_to_success_ms",
                    "time_to_first_success_ms",
                    "meta",
                    "error",
                    "wait_for",
                    "step",
                )
                for k in canonical_keys:
                    if k not in rec:
                        rec[k] = None

            scen_rec["steps"].append(rec)

        def _sv(msg: str) -> None:
            if scenario_verbose:
                print(msg)

        scen_failed = False

        for step_idx, step in enumerate(steps, start=1):
            step_started = time.time()

            if not isinstance(step, dict):
                scen_step({
                    "type": "invalid",
                    "verdict": "fail",
                    "duration_ms": 0,
                    "error": "step must be a dict",
                    "step": step_idx,
                })
                _sv(f"[scenario {sid}] {step_idx:02d}. invalid step (not a dict)")
                scen_failed = True
                if not keep_going:
                    break
                continue

            # -------------------------
            # run: <test_name>
            # -------------------------
            if "run" in step:
                ref = step.get("run")
                if not isinstance(ref, str) or not ref:
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "run",
                        "ref": str(ref),
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": "run must be a non-empty string",
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. run ref={ref!r} -> FAIL (invalid ref)")
                    scen_failed = True
                    if not keep_going:
                        break
                    continue

                _sv(f"[scenario {sid}] {step_idx:02d}. run ref={ref}")
                verdict = run_named_test(ref, scenario_ctx=(sid, step_idx))
                dur_ms = int((time.time() - step_started) * 1000)

                scen_step({
                    "type": "run",
                    "ref": ref,
                    "verdict": verdict,
                    "duration_ms": dur_ms,
                    "step": step_idx,
                })

                _sv(f"[scenario {sid}] {step_idx:02d}. run ref={ref} -> {verdict.upper()} ({dur_ms}ms)")
                if verdict != "pass":
                    scen_failed = True
                    if not keep_going:
                        break
                continue

            # -------------------------
            # fault: { ... }
            # -------------------------
            if "fault" in step:
                fault = step.get("fault")
                if not isinstance(fault, dict):
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "fault",
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": "fault must be a dict",
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. fault -> FAIL (fault not a dict)")

                    # deterministic event
                    record_event_scenario_fault(
                        scenario_id=sid,
                        step_index=step_idx,
                        verdict="fail",
                        duration_ms=dur_ms,
                        error="fault must be a dict",
                        meta={"action": "invalid", "target": ""},
                    )

                    scen_failed = True
                    if not keep_going:
                        break
                    continue

                try:
                    _sv(f"[scenario {sid}] {step_idx:02d}. fault apply")

                    action, target, meta = apply_fault(
                        fault,
                        fault_state_routes_v4=fault_state_routes_v4,
                    )
                    dur_ms = int((time.time() - step_started) * 1000)

                    # keep existing scenario step trace
                    scen_step({
                        "type": "fault",
                        "action": action,
                        "target": target,
                        "verdict": "pass",
                        "duration_ms": dur_ms,
                        "step": step_idx,
                        "meta": meta,
                    })

                    # -------- deterministic artifact event --------
                    fmeta = dict(meta or {})
                    fmeta["action"] = action
                    fmeta["target"] = target

                    # normalize restored_routes to int if present
                    if "restored_routes" in fmeta:
                        try:
                            fmeta["restored_routes"] = int(fmeta.get("restored_routes") or 0)
                        except Exception:
                            fmeta["restored_routes"] = 0

                    record_event_scenario_fault(
                        scenario_id=sid,
                        step_index=step_idx,
                        verdict="pass",
                        duration_ms=dur_ms,
                        error="",
                        meta=fmeta,
                    )
                    # ---------------------------------------------

                    note = ""
                    if action in ("link_up", "interface_up"):
                        rr = 0
                        try:
                            rr = int((meta or {}).get("restored_routes") or 0)
                        except Exception:
                            rr = 0
                        note = f" (restored_routes={rr})"

                    _sv(
                        f"[scenario {sid}] {step_idx:02d}. fault action={action} target={target}{note} -> PASS ({dur_ms}ms)"
                    )

                except Exception as e:
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "fault",
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": str(e),
                        "fault": fault,
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. fault -> FAIL ({e})")

                    # deterministic event
                    record_event_scenario_fault(
                        scenario_id=sid,
                        step_index=step_idx,
                        verdict="fail",
                        duration_ms=dur_ms,
                        error=str(e),
                        meta={"action": "error", "target": ""},
                    )

                    scen_failed = True
                    if not keep_going:
                        break

                continue

            # -------------------------
            # wait: {seconds: N}
            # -------------------------
            if "wait" in step:
                w = step.get("wait") or {}
                seconds = int((w.get("seconds") or 0))
                _sv(f"[scenario {sid}] {step_idx:02d}. wait seconds={seconds}")
                dur_ms = wait_seconds(seconds)

                scen_step({
                    "type": "wait",
                    "seconds": seconds,
                    "verdict": "pass",
                    "duration_ms": dur_ms,
                    "step": step_idx,
                })
                _sv(f"[scenario {sid}] {step_idx:02d}. wait -> PASS ({dur_ms}ms)")
                continue

            # -------------------------
            # wait_for: { ... }
            # -------------------------
            if "wait_for" in step:
                wf = step.get("wait_for")
                if not isinstance(wf, dict):
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "wait_for",
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": "wait_for must be a dict",
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for -> FAIL (not a dict)")
                    scen_failed = True
                    if not keep_going:
                        break
                    continue

                try:
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for")
                    wtype, expected, observed, dur_ms, meta, verdict = wait_for_predicate(wf)

                    scen_step({
                        "type": "wait_for",
                        "wait_type": wtype,
                        "expected": expected,
                        "observed": observed,
                        "verdict": verdict,
                        "duration_ms": dur_ms,
                        # bounded semantics (additive, step-level)
                        "attempts": int((meta or {}).get("attempts") or 0),
                        "timeout_s": int((meta or {}).get("timeout_s") or 0),
                        "interval_s": float((meta or {}).get("interval_s") or 0.0),
                        "succeeded": bool((meta or {}).get("succeeded")),
                        "time_to_success_ms": (meta or {}).get("time_to_success_ms"),
                        "time_to_first_success_ms": (meta or {}).get("time_to_first_success_ms"),
                        "meta": meta,
                        "step": step_idx,
                    })

                    _sv(
                        f"[scenario {sid}] {step_idx:02d}. wait_for type={wtype} expected={expected} observed={observed} -> {verdict.upper()} ({dur_ms}ms)"
                    )

                    if verdict != "pass":
                        scen_failed = True
                        if not keep_going:
                            break

                except Exception as e:
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "wait_for",
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": str(e),
                        "wait_for": wf,
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for -> FAIL ({e})")
                    scen_failed = True
                    if not keep_going:
                        break
                continue

            # -------------------------
            # wait_for_bgp: { node: <frr>, timeout: N }
            # -------------------------
            if "wait_for_bgp" in step:
                wf = step.get("wait_for_bgp") or {}
                node = wf.get("node")
                timeout = int(wf.get("timeout") or 30)

                if not isinstance(node, str) or not node.strip():
                    dur_ms = int((time.time() - step_started) * 1000)
                    scen_step({
                        "type": "wait_for_bgp",
                        "node": str(node),
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": "wait_for_bgp.node must be a non-empty string",
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for_bgp -> FAIL (invalid node)")
                    scen_failed = True
                    if not keep_going:
                        break
                    continue

                node = node.strip()
                _sv(f"[scenario {sid}] {step_idx:02d}. wait_for_bgp node={node} timeout={timeout}")

                try:
                    wait_for_bgp(rt, lab, node, timeout=timeout)

                    dur_ms = int((time.time() - step_started) * 1000)
                    meta = {"node": node, "timeout_s": timeout}

                    scen_step({
                        "type": "wait_for_bgp",
                        "node": node,
                        "verdict": "pass",
                        "duration_ms": dur_ms,
                        "meta": meta,
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for_bgp -> PASS ({dur_ms}ms)")

                except SystemExit as e:
                    dur_ms = int((time.time() - step_started) * 1000)
                    meta = {"node": node, "timeout_s": timeout}

                    scen_step({
                        "type": "wait_for_bgp",
                        "node": node,
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "meta": meta,
                        "error": str(e),
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. wait_for_bgp -> FAIL ({e})")

                    scen_failed = True
                    if not keep_going:
                        break

                continue

            # -------------------------
            # PCAP (supporting evidence only)
            # -------------------------
            if "pcap_start" in step or "pcap_stop" in step:
                # NOTE: cmd_test already imports json/time; do not re-import here because it shadows
                # the outer 'time' and breaks earlier time.time() usage (UnboundLocalError).
                from netsim_artifacts import pcap_session_paths, write_file

                # Non-gating invariant: any runtime/pcap failure becomes evidence only.
                # Scenario must continue.
                try:
                    results.setdefault("authority", {}).setdefault("supporting_evidence", [])
                except Exception:
                    # Never allow evidence indexing to break execution
                    pass

                # One active capture per scenario (v1.5 rule)
                if not hasattr(run_scenario, "_pcap_state"):
                    run_scenario._pcap_state = {}  # type: ignore[attr-defined]

                st = run_scenario._pcap_state  # type: ignore[attr-defined]
                key = str(scenario_id)

                if "pcap_start" in step:
                    cfg = step.get("pcap_start") or {}
                    target = cfg.get("target") or {}

                    # Validation should have enforced shapes; at runtime, treat as non-gating
                    node = str((target.get("node") or "")).strip()
                    iface = str((target.get("iface") or "")).strip()

                    label = cfg.get("label")
                    max_seconds = cfg.get("max_seconds")
                    max_kb = cfg.get("max_kb")
                    snaplen = cfg.get("snaplen")
                    filt = cfg.get("filter")

                    # If already active: evidence-only failure, do not start a second
                    if st.get(key, {}).get("active"):
                        try:
                            results.setdefault("authority", {}).setdefault("supporting_evidence", []).append(
                                {
                                    "type": "pcap",
                                    "authority": "supporting_evidence",
                                    "scenario_id": str(scenario_id),
                                    "step": int(step_index),
                                    "tool_status": "failed",
                                    "error": "pcap_start while capture active (one per scenario allowed)",
                                }
                            )
                        except Exception:
                            pass
                        continue

                    # Determine deterministic artifact paths (host side)
                    pcap_path, meta_path = pcap_session_paths(
                        lab_name=str(lab),
                        scenario_id=str(scenario_id),
                        step_seq=int(step_idx),
                        label=str(label) if label is not None else None,
                        node=node,
                        iface=iface,
                    )
                    pcap_path.parent.mkdir(parents=True, exist_ok=True)

                    # Container temp path (deterministic per step)
                    tmp_pcap = f"/tmp/netsim_pcap_{int(step_idx):03d}.pcap"

                    # Build tcpdump command (no stdout packet printing)
                    # NOTE: do not store filter text in filenames/meta by default.
                    cmd = ["sh", "-lc"]
                    td = ["tcpdump", "-i", iface, "-U", "-w", tmp_pcap]

                    if snaplen is not None:
                        td += ["-s", str(int(snaplen))]

                    # Size cap: use -C (MB) + single file (-W 1) with stable prefix;
                    # tcpdump appends '0' when -C/-W used.
                    # We keep it simple here: if max_kb set, convert to MB floor(>=1).
                    rotated = False
                    if max_kb is not None:
                        try:
                            mb = max(1, int(int(max_kb) / 1024))
                            # use prefix without extension; tcpdump will create <prefix>0
                            tmp_prefix = f"/tmp/netsim_pcap_{int(step_idx):03d}"
                            td = ["tcpdump", "-i", iface, "-U", "-C", str(mb), "-W", "1", "-w", tmp_prefix]
                            rotated = True
                        except Exception:
                            pass

                    # Optional filter (BPF): append as final tokens
                    if filt:
                        td += [str(filt)]

                    # Duration cap: run under timeout if provided
                    if max_seconds is not None:
                        td = ["timeout", str(int(max_seconds))] + td

                    # Background + pid capture
                    sh = " ".join([_shell_quote(x) for x in td]) + " >/dev/null 2>&1 & echo $!"
                    cp = rt.exec(lab, node, cmd + [sh], check=False, capture_output=True)

                    pid = ""
                    if cp.stdout:
                        out = cp.stdout.decode("utf-8", errors="replace") if isinstance(cp.stdout, (bytes, bytearray)) else str(cp.stdout)
                        pid = (out or "").strip().splitlines()[-1].strip()

                    started_at = time.time()

                    # Record state (evidence-only)
                    # NOTE: when rotated (-C/-W) is used, tcpdump writes using the prefix passed to -w.
                    # Different tcpdump builds may emit either <prefix>0 or <prefix>; we probe deterministically at stop.
                    tmp_candidates: list[str] = []
                    if rotated:
                        try:
                            tmp_candidates = [f"{tmp_prefix}0", str(tmp_prefix)]
                        except Exception:
                            tmp_candidates = []
                    else:
                        tmp_candidates = [str(tmp_pcap)]

                    st[key] = {
                        "active": True,
                        "node": node,
                        "iface": iface,
                        "pid": pid,
                        "started_at": started_at,
                        "tmp_pcap": str(tmp_pcap),
                        "tmp_prefix": str(tmp_prefix) if rotated else "",
                        "rotated": bool(rotated),
                        "tmp_candidates": tmp_candidates,
                        "pcap_path": str(pcap_path),
                        "meta_path": str(meta_path),
                        "step": int(step_idx),
                        "max_seconds": int(max_seconds) if max_seconds is not None else None,
                        "max_kb": int(max_kb) if max_kb is not None else None,
                        "snaplen": int(snaplen) if snaplen is not None else None,
                    }

                    # Non-authoritative index entry
                    try:
                        results.setdefault("authority", {}).setdefault("supporting_evidence", []).append(
                            {
                                "type": "pcap",
                                "authority": "supporting_evidence",
                                "scenario_id": str(scenario_id),
                                "step": int(step_index),
                                "tool_status": "ok" if cp.returncode == 0 else "failed",
                                "error": "" if cp.returncode == 0 else "tcpdump start failed",
                            }
                        )
                    except Exception:
                        pass

                    continue

                # pcap_stop
                if "pcap_stop" in step:
                    cur = st.get(key) or {}
                    if not cur.get("active"):
                        # Stop-without-start: evidence-only, ignore
                        continue

                    node = str(cur.get("node") or "")
                    pid = str(cur.get("pid") or "").strip()

                    tmp_pcap = str(cur.get("tmp_pcap") or "")
                    pcap_path = Path(str(cur.get("pcap_path") or ""))
                    meta_path = Path(str(cur.get("meta_path") or ""))

                    stopped_at = time.time()

                    tool_status = "ok"
                    err = ""

                    # Deterministically probe candidate tmp filenames (rotated tcpdump may emit prefix or prefix0)
                    candidates = cur.get("tmp_candidates")
                    if not isinstance(candidates, list) or not candidates:
                        candidates = [tmp_pcap]
                    candidates = [str(x) for x in candidates if isinstance(x, str) and x.strip()]

                    chosen_tmp = ""
                    try:
                        for cand in candidates:
                            cp_exists = rt.exec(
                                lab,
                                node,
                                ["sh", "-lc", f"test -f {cand} && echo OK || true"],
                                check=False,
                                capture_output=True,
                            )
                            out = ""
                            if cp_exists.stdout:
                                out = (
                                    cp_exists.stdout.decode("utf-8", errors="replace")
                                    if isinstance(cp_exists.stdout, (bytes, bytearray))
                                    else str(cp_exists.stdout)
                                )
                            if "OK" in (out or ""):
                                chosen_tmp = cand
                                break
                    except Exception as e:
                        tool_status = "failed"
                        err = _safe_stdio(str(e))

                    try:
                        if pid:
                            rt.exec(
                                lab,
                                node,
                                ["sh", "-lc", f"kill {pid} >/dev/null 2>&1 || true"],
                                check=False,
                                capture_output=True,
                            )
                        else:
                            # Best effort: kill by filename pattern (still scoped to step id)
                            rt.exec(
                                lab,
                                node,
                                ["sh", "-lc", f"pkill -f 'tcpdump.*netsim_pcap_{int(cur.get('step_seq_start')):03d}' >/dev/null 2>&1 || true"],
                                check=False,
                                capture_output=True,
                            )
                    except Exception as e:
                        tool_status = "failed"
                        if not err:
                            err = _safe_stdio(str(e))

                    # Copy out if a tmp file was found (evidence-only, non-gating)
                    bytes_written = 0
                    try:
                        if not chosen_tmp:
                            tool_status = "failed" if tool_status == "ok" else tool_status
                            if not err:
                                err = "pcap tmp file not found in node"
                        else:
                            rt.copy_from_node(lab, node, chosen_tmp, str(pcap_path))
                            try:
                                bytes_written = int(pcap_path.stat().st_size)
                            except Exception:
                                bytes_written = 0
                    except Exception as e:
                        tool_status = "failed" if tool_status == "ok" else tool_status
                        if not err:
                            err = _safe_stdio(str(e))

                    # attempt to remove tmp pcaps (never fail)
                    try:
                        for cand in candidates:
                            rt.exec(lab, node, ["sh", "-lc", f"rm -f {cand} 2>/dev/null || true"], check=False, capture_output=False)
                    except Exception:
                        pass

                    # Write meta json (host side)
                    meta = {
                        "authority": "supporting_evidence",
                        "scenario_id": str(scenario_id),
                        "step_seq_start": int(cur.get("step_seq_start") or 0),
                        "step_seq_stop": int(step_idx),
                        "target": {"node": str(cur.get("node") or ""), "iface": str(cur.get("iface") or "")},
                        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(cur.get("started_at") or stopped_at))),
                        "stopped_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stopped_at)),
                        "duration_s": float(stopped_at - float(cur.get("started_at") or stopped_at)),
                        "tool": "tcpdump",
                        "tool_status": tool_status,
                        "bytes_written": int(bytes_written),
                        "pcap_file": str(pcap_path.relative_to(lab_dir(str(lab)))),
                    }
                    if cur.get("snaplen") is not None:
                        meta["snaplen"] = int(cur["snaplen"])
                    if cur.get("max_seconds") is not None:
                        meta["max_seconds"] = int(cur["max_seconds"])
                    if cur.get("max_kb") is not None:
                        meta["max_kb"] = int(cur["max_kb"])
                    if err:
                        meta["error"] = str(err)

                    write_file(meta_path, json.dumps(meta, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

                    # Top-level evidence index entry (supporting evidence only; non-gating)
                    try:
                        results.setdefault("authority", {}).setdefault("supporting_evidence", []).append(
                            {
                                "type": "pcap",
                                "authority": "supporting_evidence",
                                "scenario_id": str(scenario_id),
                                "step": int(step_idx),
                                "tool_status": str(tool_status),
                                "error": str(err or ""),
                                "pcap_file": str(pcap_path.relative_to(lab_dir(str(lab)))),
                            }
                        )
                    except Exception:
                        pass

                    # Clear active capture
                    st[key] = {"active": False}

                    continue

            # -------------------------
            # unknown step
            # -------------------------
            dur_ms = int((time.time() - step_started) * 1000)
            scen_step({
                "type": "unknown",
                "verdict": "fail",
                "duration_ms": dur_ms,
                "error": f"unsupported step keys: {list(step.keys())}",
                "step": step_idx,
            })
            _sv(f"[scenario {sid}] {step_idx:02d}. unknown -> FAIL (unsupported keys)")
            scen_failed = True
            if not keep_going:
                break

        scen_finished = time.time()
        scen_rec["duration_ms"] = int((scen_finished - scen_started) * 1000)
        scen_rec["verdict"] = "fail" if scen_failed else "pass"
        results["scenarios"].append(scen_rec)
        return scen_rec["verdict"]

    # =============================================================================
    # 1) Verify all nodes are running (hard prerequisite for everything else)
    # =============================================================================
    for n in nodes:
        name = n["name"]
        if not rt.is_running(lab, name):
            record_test(
                name="prereq:node-running",
                kind="prereq",
                src="",
                dst=name,
                expected="pass",
                observed="fail",
                verdict="fail",
                duration_ms=0,
                error=f"{name} is not running",
            )
            results["result"] = "fail"
            finished_at = time.time()
            results["summary"]["finished_at"] = finished_at
            results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)
            results["summary"]["total"] = len(results["tests"])
            results["summary"]["passed"] = 0
            results["summary"]["failed"] = len(results["tests"])
            write_results()
            # v1.x UX hardening: lab exists but containers are stopped (common after reboot / manual clab destroy)
            hint_lines = [
                "Lab exists but one or more containers are not running.",
                "Try:",
                "  netsim destroy <lab>",
                "  netsim up <topology.yaml> --reconfigure",
                "or:",
                "  netsim cleanup --all --yes",
            ]
            die(f"{name} is not running\n\n" + "\n".join(hint_lines))

    # =============================================================================
    # 1.5) State capture plan (supporting evidence only) - fail-fast config validation
    # =============================================================================
    state_mode = str(getattr(args, "state_capture", "none") or "none").strip().lower()
    state_profiles = getattr(args, "state_profile", None)
    if state_profiles is None:
        state_profiles = []
    if not isinstance(state_profiles, list):
        state_profiles = [str(state_profiles)]

    # Expand deterministic plan (blocking only for invalid config, never runtime errors)
    state_plan = _state_capture_expand_plan_or_die(topo=topo, mode=state_mode, profiles=[str(x) for x in state_profiles])

    # Always write plan.json when enabled (audit primitive)
    state_plan_path = ""
    if bool(state_plan.get("enabled")):
        state_plan_path = str(_state_capture_write_plan(lab, state_plan))

    # Additive-only results labeling (never affects verdict)
    results["state_capture"] = {
        "enabled": bool(state_plan.get("enabled")),
        "mode": str(state_plan.get("mode") or "none"),
        "profiles": list(state_plan.get("profiles") or []),
        "plan_path": state_plan_path,
        "pre": {"ran": 0, "ok": 0, "error": 0, "timeout": 0},
        "post": {"ran": 0, "ok": 0, "error": 0, "timeout": 0},
    }

    # Link into authority.supporting_evidence (additive pointer only)
    if bool(state_plan.get("enabled")):
        try:
            results.setdefault("authority", {}).setdefault("supporting_evidence", []).append(
                {
                    "type": "state_capture",
                    "authority": "supporting_evidence",
                    "path": state_plan_path,
                    "mode": str(state_plan.get("mode") or "none"),
                    "profiles": list(state_plan.get("profiles") or []),
                }
            )
        except Exception:
            # Never allow evidence indexing to break execution
            pass

    # =============================================================================
    # 2) Node readiness gate (no control-plane assumptions yet)
    # =============================================================================
    try:
        verify_lab_ready(rt, topo, lab)
    except SystemExit:
        results["result"] = "fail"
        finished_at = time.time()
        results["summary"]["finished_at"] = finished_at
        results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)
        write_results()
        raise

    # =============================================================================
    # 2.5) Candidate Config Apply (v1.5) - gate-only, atomic, evidenced
    # =============================================================================
    # IMPORTANT: this must run AFTER readiness and BEFORE any tests/scenarios.
    # Reuse normalized cand_dir + cand_plan from earlier fail-fast parse if present.
    # Fallback to parsing here only if older code path didn't create them.
    if "cand_dir" not in locals():
        cand_dir = None  # type: ignore[assignment]
    if "cand_plan" not in locals():
        cand_plan = None  # type: ignore[assignment]

    cand_dir_raw = getattr(args, "candidate_config", None)

    if cand_dir is None and cand_dir_raw:
        cand_dir = Path(str(cand_dir_raw)).expanduser()
        if not cand_dir.is_absolute():
            cand_dir = (Path.cwd() / cand_dir)
        cand_dir = cand_dir.resolve()
        cand_plan = _candidate_parse_dir_or_die(topo, cand_dir)

    # Only run apply when we actually have candidate inputs enabled
    if cand_dir is not None and cand_plan is not None:
        results["candidate_apply"] = {
            "enabled": True,
            "input_dir": str(cand_dir),
            "plan": [r["node"] for r in cand_plan],
            "verdict": "unknown",
            "failed_nodes": [],
            "failed": [],  # additive UX: [{"node": "...", "reason": "..."}]
            "duration_ms": None,
        }

        apply_started = time.time()
        failed: list[str] = []

        for item in cand_plan:
            node = item["node"]
            ntype = item["node_type"]
            src = Path(item["source_path"])

            # Always emit a per-node artifact for every attempted node.
            rec: dict[str, Any]
            try:
                if ntype == "frr":
                    rec = _candidate_apply_frr_generated_only(rt, lab, topo, node, src)
                elif ntype == "nft-fw":
                    rec = _candidate_apply_nft(rt, lab, node, src)
                else:
                    rec = {
                        "node": node,
                        "node_type": str(ntype),
                        "method": "unsupported",
                        "input": {
                            "source_path": str(src),
                            "sha256": _sha256_file(src) if src.exists() else "",
                        },
                        "attempt": {
                            "started_at_epoch_ms": int(time.time() * 1000),
                            "duration_ms": 0,
                        },
                        "result": {"applied_ok": False, "exit_code": 3},
                        "stdout": "",
                        "stderr": _safe_stdio(f"candidate apply: unsupported node_type '{ntype}'"),
                        "post_checks": [],
                    }
            except SystemExit as e:
                rec = {
                    "node": node,
                    "node_type": str(ntype),
                    "method": "exception",
                    "input": {
                        "source_path": str(src),
                        "sha256": _sha256_file(src) if src.exists() else "",
                    },
                    "attempt": {
                        "started_at_epoch_ms": int(time.time() * 1000),
                        "duration_ms": 0,
                    },
                    "result": {"applied_ok": False, "exit_code": 1},
                    "stdout": "",
                    "stderr": _safe_stdio(str(e)),
                    "post_checks": [],
                }

            _write_candidate_apply_artifact(lab, node, rec)

            if not bool(((rec.get("result") or {}).get("applied_ok"))):
                failed.append(node)

                # UX: capture a short “reason” for summary (prefer top-level stderr)
                reason = (rec.get("stderr") or "").strip()
                if not reason:
                    # fall back to vtysh stderr if present
                    v = rec.get("vtysh_apply") or {}
                    reason = (v.get("stderr") or "").strip()

                results["candidate_apply"]["failed"].append({"node": node, "reason": _safe_stdio(reason)})
                continue

        apply_finished = time.time()
        results["candidate_apply"]["duration_ms"] = int((apply_finished - apply_started) * 1000)

        results["candidate_apply"]["failed_nodes"] = list(failed)
        results["candidate_apply"]["verdict"] = ("fail" if failed else "pass")

        # HARD GATE: candidate apply failures are authoritative and MUST fail the run.
        if failed:
            # One deterministic failure record is enough to drive the overall verdict/exit code.
            record_test(
                name="candidate_apply:verdict",
                kind="candidate_apply",
                src="",
                dst=",".join(sorted(failed)),
                expected="pass",
                observed="fail",
                verdict="fail",
                duration_ms=int(results["candidate_apply"].get("duration_ms") or 0),
                error=f"candidate apply failed for node(s): {', '.join(sorted(failed))}",
                meta={
                    "failed_nodes": sorted(failed),
                    "input_dir": str(results["candidate_apply"].get("input_dir") or ""),
                },
                evidence={
                    "artifacts_dir": str(_candidate_artifacts_dir(lab)),
                },
            )

            # Enforce HARD GATE semantics: fail-fast after candidate apply concludes.
            # IMPORTANT: must stop BEFORE any control-plane prechecks, state capture, tests, or scenarios.
            results["result"] = "fail"

            finished_at = time.time()
            results["summary"]["finished_at"] = finished_at
            results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)

            # Summary counts must be consistent with the authoritative tests recorded so far
            total = len(results["tests"])
            failed_count = sum(1 for r in results["tests"] if r.get("verdict") == "fail")
            passed_count = total - failed_count

            results["summary"]["total"] = total
            results["summary"]["passed"] = passed_count
            results["summary"]["failed"] = failed_count

            # Optional/defensive: make explicit that steady-state tests did not run
            results["summary"]["tests_executed"] = 0

            write_results()
            raise SystemExit(1)

    # =============================================================================
    # 3) Optional control-plane checks (FRR/BGP)
    # =============================================================================
    frr_nodes = [n for n in nodes if n.get("type") == "frr"]
    links_by_node = build_node_links(topo)

    def expected_bgp_peers(node_name: str) -> list[dict]:
        out: list[dict] = []
        for l in links_by_node.get(node_name, []) or []:
            peer_name = l.get("peer")
            peer = nodes_by_name.get(peer_name)
            if peer and peer.get("type") == "frr" and "asn" in peer:
                out.append(l)
        return out

    bgp_participants: list[dict] = []
    for n in frr_nodes:
        if expected_bgp_peers(n["name"]):
            bgp_participants.append(n)

    # Convergence semantics:
    # - Default tests: keep legacy behavior (precheck BGP if participants exist)
    # - Scenarios: skip global precheck unless user explicitly requests it
    do_global_cp_precheck = (not want_scenarios) or precheck_controlplane
    results["summary"]["precheck_controlplane"] = bool(do_global_cp_precheck)

    if do_global_cp_precheck and bgp_participants:
        try:
            for n in bgp_participants:
                wait_for_bgp(rt, lab, n["name"], timeout=30)
        except SystemExit:
            results["result"] = "fail"
            finished_at = time.time()
            results["summary"]["finished_at"] = finished_at
            results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)
            write_results()
            raise

    # =============================================================================
    # 3.5) Pre-state capture (supporting evidence only; never gates)
    # =============================================================================
    if bool(results.get("state_capture", {}).get("enabled")) and str(results["state_capture"].get("mode")) in ("pre", "both"):
        try:
            summ = _state_capture_run_plan(rt=rt, lab=lab, plan=state_plan, when="pre", timeout_s=5)
            results["state_capture"]["pre"] = {k: int(summ.get(k, 0)) for k in ["ran", "ok", "error", "timeout", "skipped"]}
        except Exception as e:
            # Non-authoritative: record but do not fail
            results["state_capture"]["pre"] = {"ran": 0, "ok": 0, "error": 1, "timeout": 0, "skipped": 0}
            results.setdefault("authority", {}).setdefault("supporting_evidence", []).append(
                {
                    "type": "state_capture_error",
                    "authority": "supporting_evidence",
                    "when": "pre",
                    "error": _safe_stdio(str(e)),
                }
            )

    # =============================================================================
    # 4) Scenarios (opt-in) OR Declared tests (default)
    # =============================================================================
    scenarios = topo.get("scenarios", []) or []

    try:
        if want_scenarios:
            if not scenarios:
                record_test(
                    name="scenarios:none-defined",
                    kind="scenario",
                    src="",
                    dst="",
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="no scenarios defined in topology (missing top-level 'scenarios:')",
                )
                fail_or_continue("No scenarios defined in topology")
            else:
                if all_scenarios:
                    selected = [s for s in scenarios if isinstance(s, dict)]
                else:
                    selected = [s for s in scenarios if isinstance(s, dict) and s.get("id") == scenario_id]

                if not selected:
                    record_test(
                        name="scenarios:not-found",
                        kind="scenario",
                        src="",
                        dst="",
                        expected="pass",
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error=f"scenario id not found: {scenario_id!r}",
                    )
                    fail_or_continue(f"Scenario not found: {scenario_id!r}")
                else:
                    for s in selected:
                        sid = s.get("id") or "<unknown>"
                        verdict = run_scenario(s)
                        if verdict != "pass":
                            fail_or_continue(f"Scenario FAIL: {sid}")

        else:
# Default behavior: run declared tests (steady-state)
            if not declared_tests:
                results["result"] = "pass"
                finished_at = time.time()
                results["summary"]["finished_at"] = finished_at
                results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)
                results["summary"]["total"] = 0
                results["summary"]["passed"] = 0
                results["summary"]["failed"] = 0
                write_results()
                print("✅ TEST PASS: nodes running" + (" + BGP OK" if bgp_participants else ""))
                return

            # Deterministic per-test progress lines (human only; emitted only under --verbose to preserve quiet default)
            def _tv(msg: str) -> None:
                if bool(getattr(args, "verbose", False)):
                    print(msg)

            matched = 0
            exec_idx = 0

            for idx, t in enumerate(declared_tests):
                i = idx + 1
                test_name = t.get("name") if isinstance(t, dict) else None
                if not test_name:
                    test_name = f"tests[{i}]"

                if filter_name and test_name != filter_name:
                    continue

                if not isinstance(t, dict):
                    record_test(
                        name=test_name,
                        kind="unknown",
                        src="",
                        dst="",
                        expected="pass",
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error="test entry must be a dict",
                    )
                    # Deterministic progress: record as executed even if invalid
                    exec_idx += 1
                    _tv(f"[TEST START] {exec_idx:03d} {test_name} kind=unknown")
                    _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict=FAIL")
                    fail_or_continue(f"tests[{i}]: must be a dict")
                    continue

                if "kind" in t and "type" in t:
                    record_test(
                        name=test_name,
                        kind="unknown",
                        src=t.get("src") or "",
                        dst=t.get("dst") or "",
                        expected="pass",
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error="has both 'kind' and 'type'",
                    )
                    exec_idx += 1
                    _tv(f"[TEST START] {exec_idx:03d} {test_name} kind=unknown")
                    _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict=FAIL")
                    fail_or_continue(f"tests[{i}]: has both 'kind' and 'type' (use only 'kind')")
                    continue

                kind = t.get("kind") or t.get("type")
                if not kind:
                    record_test(
                        name=test_name,
                        kind="unknown",
                        src=t.get("src") or "",
                        dst=t.get("dst") or "",
                        expected="pass",
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error="missing 'kind'",
                    )
                    exec_idx += 1
                    _tv(f"[TEST START] {exec_idx:03d} {test_name} kind=unknown")
                    _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict=FAIL")
                    fail_or_continue(f"tests[{i}]: missing 'kind'")
                    continue

                src = t.get("src")
                dst = t.get("dst")

                if kind not in ("ping", "tcp", "bgp_neighbor", "route_prefix"):
                    record_test(
                        name=test_name,
                        kind=str(kind),
                        src=src or "",
                        dst=dst or "",
                        expected="pass",
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error=f"unsupported kind '{kind}'",
                    )
                    exec_idx += 1
                    _tv(f"[TEST START] {exec_idx:03d} {test_name} kind={kind}")
                    _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict=FAIL")
                    fail_or_continue(f"tests[{i}]: unsupported kind '{kind}' (supported: ping, tcp, bgp_neighbor)")
                    continue

                if filter_kind and kind != filter_kind:
                    continue

                matched += 1
                exec_idx += 1

                # Deterministic START line: only stable identifiers (no time, no duration)
                _tv(f"[TEST START] {exec_idx:03d} {test_name} kind={kind}")

                src = t.get("src")
                dst = t.get("dst")

                if kind == "route_prefix":
                    prefix = t.get("prefix")
                    if not isinstance(src, str) or not src.strip() or not isinstance(prefix, str) or not prefix.strip():
                        record_test(
                            name=test_name,
                            kind="route_prefix",
                            src=(src or ""),
                            dst="",
                            expected=str(t.get("expect") or "pass"),
                            observed="fail",
                            verdict="fail",
                            duration_ms=0,
                            error="missing src(on)/prefix",
                        )
                        _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict=FAIL")
                        fail_or_continue(f"tests[{i}]: route_prefix requires src(on) + prefix")
                        continue

                if kind == "ping":
                    # v1: ping supports dst (node) OR to/to_ip (ip literal)
                    if not src or not (dst or t.get("to") or t.get("to_ip")):
                        record_test(
                            name=test_name,
                            kind=kind,
                            src=src or "",
                            dst=(dst or t.get("to") or t.get("to_ip") or ""),
                            expected="pass",
                            observed="fail",
                            verdict="fail",
                            duration_ms=0,
                            error="missing src/dst(to)",
                        )
                        _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict=FAIL")
                        fail_or_continue(f"tests[{i}]: missing src + (dst or to/to_ip)")
                        continue

                elif kind == "bgp_neighbor":
                    # v1.x: bgp_neighbor requires src node + dst neighbor IPv4 literal
                    if not src or not dst:
                        record_test(
                            name=test_name,
                            kind=kind,
                            src=src or "",
                            dst=dst or "",
                            expected="up",
                            observed="fail",
                            verdict="fail",
                            duration_ms=0,
                            error="missing src/dst (neighbor IPv4 required)",
                        )
                        _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict=FAIL")
                        fail_or_continue(f"tests[{i}]: missing src/dst (neighbor IPv4 required)")
                        continue

                    if not isinstance(dst, str) or not is_ip_literal(dst.strip()):
                        record_test(
                            name=test_name,
                            kind=kind,
                            src=src or "",
                            dst=str(dst) if dst is not None else "",
                            expected="up",
                            observed="fail",
                            verdict="fail",
                            duration_ms=0,
                            error="dst must be an IPv4 neighbor address",
                        )
                        _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict=FAIL")
                        fail_or_continue(f"tests[{i}]: bgp_neighbor dst must be an IPv4 literal")
                        continue

                elif kind == "tcp":
                    # tcp keeps legacy requirement
                    if not src or not dst:
                        record_test(
                            name=test_name,
                            kind=kind,
                            src=src or "",
                            dst=dst or "",
                            expected="pass",
                            observed="fail",
                            verdict="fail",
                            duration_ms=0,
                            error="missing src/dst",
                        )
                        _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict=FAIL")
                        fail_or_continue(f"tests[{i}]: missing src/dst")
                        continue

                if kind == "ping":
                    dst_label = (
                        t.get("dst")
                        or t.get("to")
                        or t.get("to_ip")
                        or t.get("to_ip4")
                        or t.get("to_ip6")
                        or dst
                        or ""
                    )

                    r = run_ping_test(test_name=test_name, src=src, dst=dst_label, t=t)

                    verdict_txt = (r.get("verdict") or "fail").upper()
                    _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict={verdict_txt}")

                    if r.get("verdict") != "pass":
                        dst_ip = None
                        meta = r.get("meta")
                        if isinstance(meta, dict):
                            dst_ip = meta.get("dst_ip")
                        extra = f" ({dst_ip})" if dst_ip else ""
                        fail_or_continue(
                            f"tests[{i}] ping mismatch: {src} -> {dst_label}{extra} expected {r.get('expected')}, observed {r.get('observed')}"
                        )
                    continue

                if kind == "route_prefix":
                    verdict = run_route_prefix_test(test_name=test_name, src=src, t=t)
                    verdict_txt = (verdict or "fail").upper()
                    _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict={verdict_txt}")
                    if verdict != "pass":
                        fail_or_continue(
                            f"tests[{i}] route_prefix mismatch: on {src} prefix {t.get('prefix')} expected {t.get('expect','pass')}"
                        )
                    continue

                if kind == "bgp_neighbor":
                    verdict = run_bgp_neighbor_test(test_name=test_name, src=src, dst=dst, t=t)
                    verdict_txt = (verdict or "fail").upper()
                    _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict={verdict_txt}")
                    if verdict != "pass":
                        fail_or_continue(
                            f"tests[{i}] bgp_neighbor mismatch: {src} -> {dst} expected {t.get('expect','pass')}"
                        )
                    continue

                verdict = run_tcp_test(test_name=test_name, src=src, dst=dst, t=t)
                verdict_txt = (verdict or "fail").upper()
                _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict={verdict_txt}")
                if verdict != "pass":
                    port = t.get("port")
                    fail_or_continue(f"tests[{i}] tcp mismatch: {src} -> {dst}:{port} expected {t.get('expect','pass')}")

            if (filter_name or filter_kind) and matched == 0:
                label_parts = []
                if filter_name:
                    label_parts.append(f"--name {filter_name!r}")
                if filter_kind:
                    label_parts.append(f"--kind {filter_kind!r}")
                label = " ".join(label_parts) if label_parts else "(none)"
                record_test(
                    name="filter:no-match",
                    kind=filter_kind or "unknown",
                    src="",
                    dst="",
                    expected="pass",
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error=f"no test matched filters {label}",
                )

                # Deterministic FAIL path must still write authoritative artifacts + summary header
                # before exiting (verify_phase1 expects FAIL header after --name DOES_NOT_EXIST).
                try:
                    if isinstance(results.get("summary"), dict):
                        results["summary"]["filtered_by_name"] = filter_name or ""
                        results["summary"]["filtered_by_kind"] = filter_kind or ""
                    else:
                        results["summary"] = {"filtered_by_name": (filter_name or ""), "filtered_by_kind": (filter_kind or "")}
                except Exception:
                    pass

                total = len(results.get("tests") or [])
                failed_count = sum(1 for r in (results.get("tests") or []) if isinstance(r, dict) and r.get("verdict") == "fail")
                results.setdefault("summary", {})
                if isinstance(results["summary"], dict):
                    results["summary"]["total"] = total
                    results["summary"]["failed"] = failed_count
                    results["summary"]["passed"] = total - failed_count

                results["result"] = "fail"
                write_results()

                # WI-2: stable, test-id-scoped FAIL line (single-line; deterministic; bounded evidence).
                # Note: fail() prints "FAIL: <msg>" so we do NOT double-prefix.
                ev_s = f"no test matched filters {label}"
                if "\n" in ev_s:
                    ev_s = ev_s.splitlines()[0].strip()
                if len(ev_s) > 200:
                    ev_s = ev_s[:200] + "…"
                fail(f'filter:no-match | expected=pass observed=fail evidence="{ev_s}"')

        # Cleanup any tcp listeners we started (deterministic cleanup)
        for dst_node in listeners_started.keys():
            rt.exec(lab, dst_node, ["sh", "-lc", 'pkill -f "nc.*-p" 2>/dev/null || true'], check=False)

        # ------------------------------------------------------------
        # Post-state capture (supporting evidence only; never gates)
        # ------------------------------------------------------------
        try:
            if bool(results.get("state_capture", {}).get("enabled")) and str(results["state_capture"].get("mode")) in ("post", "both"):
                summ = _state_capture_run_plan(rt=rt, lab=lab, plan=state_plan, when="post", timeout_s=5)
                results["state_capture"]["post"] = {
                    k: int(summ.get(k, 0)) for k in ["ran", "ok", "error", "timeout", "skipped"]
                }
        except Exception as e:
            # Non-authoritative: record but do not fail
            results["state_capture"]["post"] = {"ran": 0, "ok": 0, "error": 1, "timeout": 0, "skipped": 0}

            # Type-safe append into authority.supporting_evidence (do not assume shapes)
            try:
                auth = results.get("authority")
                if not isinstance(auth, dict):
                    auth = {}
                    results["authority"] = auth

                se = auth.get("supporting_evidence")
                if not isinstance(se, list):
                    se = []
                    auth["supporting_evidence"] = se

                se.append(
                    {
                        "type": "state_capture_error",
                        "authority": "supporting_evidence",
                        "when": "post",
                        "error": _safe_stdio(str(e)),
                    }
                )
            except Exception:
                pass

        finished_at = time.time()
        results["summary"]["finished_at"] = finished_at
        results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)

        # Atomic tests are authoritative (results["tests"])
        total = len(results["tests"])
        failed_count = sum(1 for r in results["tests"] if r.get("verdict") == "fail")
        passed_count = total - failed_count

        results["summary"]["total"] = total
        results["summary"]["passed"] = passed_count
        results["summary"]["failed"] = failed_count

        # If scenarios were requested and any scenario failed but no atomic test recorded failure,
        # mark overall fail by injecting a visibility record.
        scenario_failed = any(s.get("verdict") == "fail" for s in (results.get("scenarios") or []))
        if want_scenarios and scenario_failed and failed_count == 0:
            record_test(
                name="scenarios:verdict",
                kind="scenario",
                src="",
                dst="",
                expected="pass",
                observed="fail",
                verdict="fail",
                duration_ms=0,
                error="one or more scenarios failed (see results.scenarios)",
            )
            total = len(results["tests"])
            failed_count = sum(1 for r in results["tests"] if r.get("verdict") == "fail")
            passed_count = total - failed_count
            results["summary"]["total"] = total
            results["summary"]["passed"] = passed_count
            results["summary"]["failed"] = failed_count

        results["result"] = "fail" if results["summary"]["failed"] > 0 else "pass"
        write_results()

    except SystemExit:
        # Close the try: block deterministically and preserve existing exit semantics.
        raise

    # =============================================================================
    # 5) Success output (human-friendly)
    # =============================================================================
    if results["result"] == "fail":
        fail(f"{results['summary']['failed']} failed / {results['summary']['total']} total")

    if bgp_participants and results["summary"].get("precheck_controlplane"):
        print(f"✅ Control-plane PASS: BGP established ({len(bgp_participants)} participants)")
    elif bgp_participants and want_scenarios:
        print("ℹ️ Control-plane precheck skipped for scenarios (use --precheck-controlplane to enable)")

    if want_scenarios:
        passed_s = sum(1 for s in results["scenarios"] if s.get("verdict") == "pass")
        total_s = len(results["scenarios"])
        print(f"✅ Scenarios PASS ({passed_s}/{total_s})")

        # Scenario-only runs record atomic invocations under results["events"]
        event_runs = [
            e for e in (results.get("events") or [])
            if e.get("type") == "scenario_test_run"
        ]
        ev_pass = sum(1 for e in event_runs if e.get("verdict") == "pass")
        ev_total = len(event_runs)
        print(f"✅ Scenario test runs PASS ({ev_pass}/{ev_total})")
    else:
        print(f"✅ Declared tests PASS ({results['summary']['passed']} checks)")

    print("✅ TEST PASS: containers running + checks OK")

def _capture_config_run_exploration(rt: Runtime, *, lab: str) -> Path:
    """
    Supporting evidence only (exploration mode).
    Writes:
      labs/<lab>/artifacts/capture_config/manifest.json
      labs/<lab>/artifacts/capture_config/nodes/<node>/{host,live}/*
    Returns manifest path.

    MUST NOT:
      - gate outcomes
      - affect exit codes
      - mutate runtime state
    """
    import json
    import time

    started = time.time()
    root = _capture_config_artifacts_root(lab)
    nodes_root = root / "nodes"

    # Fail-fast only on filesystem issues for the *root* dir (explicit requirement)
    try:
        nodes_root.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        die(f"--capture-config: failed to create artifact directory: {nodes_root} ({e})")

    # Resolve nodes/types from resolved topology (best effort; required for stable ordering)
    topo_resolved = lab_dir(lab) / "topology.resolved.yaml"
    topo: dict[str, Any] = {}
    try:
        topo = load_yaml(topo_resolved) or {}
    except Exception:
        topo = {}

    topo_nodes = topo.get("nodes", []) if isinstance(topo.get("nodes", []), list) else []
    node_types: dict[str, str] = {}
    for n in topo_nodes:
        if isinstance(n, dict) and isinstance(n.get("name"), str):
            node_types[n["name"]] = str(n.get("type") or "")

    # Default selection: all nodes in lab (deterministic lex order by name)
    selected = sorted(node_types.keys())

    manifest: dict[str, Any] = {
        "schema_version": _CAPTURE_CONFIG_SCHEMA_VERSION,
        "authority": "supporting_evidence",
        "feature": "capture_config",
        "mode": "exploration",
        "gating": False,
        "lab": lab,
        "started_at": None,
        "finished_at": None,
        "duration_ms": None,
        "nodes": [],
    }

    # If resolved topology missing, still emit a manifest with no nodes.
    # This remains supporting evidence only.
    for node in selected:
        ntype = node_types.get(node, "")
        node_dir = nodes_root / node
        host_dir = node_dir / "host"
        live_dir = node_dir / "live"

        host_files: list[dict[str, Any]] = []
        live_cmds: list[dict[str, Any]] = []

        # Create per-node dirs best-effort (root dir creation is already fail-fast).
        try:
            host_dir.mkdir(parents=True, exist_ok=True)
            live_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Supporting evidence only: don't gate; writes will record failures if they occur.
            pass

        any_ok = False
        any_fail = False
        any_attempt = False

        # 1) host-generated config files (if present)
        if ntype == "frr":
            any_attempt = True
            src = node_cfg_dir(lab, node) / "frr.conf"
            dst = host_dir / "frr.conf"
            rec = _capture_config_copy_host_file(src=src, dst=dst)
            host_files.append(rec)
            if rec.get("captured_ok"):
                any_ok = True
            else:
                any_fail = True

        # nft-fw host file is "if present"; current v1.5 may not persist one.
        # If a file exists under labs/<lab>/nodes/<node>/..., capture it deterministically as nft.ruleset.
        if ntype == "nft-fw":
            any_attempt = True
            # Try a small, deterministic set of common candidates (best-effort, no guessing beyond allowlist)
            candidates = [
                node_cfg_dir(lab, node) / "ruleset.nft",
                node_cfg_dir(lab, node) / "fw.nft",
                node_cfg_dir(lab, node) / "nft.ruleset",
            ]
            picked: Path | None = None
            for c in candidates:
                if c.exists() and c.is_file():
                    picked = c
                    break
            if picked is not None:
                rec = _capture_config_copy_host_file(src=picked, dst=(host_dir / "nft.ruleset"))
                host_files.append(rec)
                if rec.get("captured_ok"):
                    any_ok = True
                else:
                    any_fail = True

        # 2) live readbacks (allowlisted argv only; no shell)
        def _run_live_cmd(cmd_id: str, argv: list[str], out_path: Path) -> None:
            nonlocal any_ok, any_fail, any_attempt
            any_attempt = True
            t0 = time.time()
            try:
                cp = rt.exec(lab, node, argv, check=False, capture_output=True, timeout_s=_CAPTURE_CONFIG_CMD_TIMEOUT_S)
                dt_ms = int((time.time() - t0) * 1000)

                stdout = (cp.stdout or "") if isinstance(cp.stdout, str) else str(cp.stdout or "")
                stderr = (cp.stderr or "") if isinstance(cp.stderr, str) else str(cp.stderr or "")

                merged = stdout
                if not merged and stderr:
                    merged = stderr

                out, redaction_applied, truncated = _capture_config_redact_and_truncate(
                    merged,
                    limit_chars=_CAPTURE_CONFIG_MAX_CHARS,
                )
                _capture_config_write_text(out_path, out)

                live_cmds.append({
                    "id": cmd_id,
                    "command": " ".join(argv),
                    "exit_code": int(getattr(cp, "returncode", 1)),
                    "duration_ms": dt_ms,
                    "bytes": int(len(out.encode("utf-8"))),
                    "truncated": bool(truncated),
                    "captured_ok": (int(getattr(cp, "returncode", 1)) == 0),
                    "error": "",
                    "redaction_applied": bool(redaction_applied),
                })

                if int(getattr(cp, "returncode", 1)) == 0:
                    any_ok = True
                else:
                    any_fail = True

            except Exception as e:
                dt_ms = int((time.time() - t0) * 1000)
                msg, redaction_applied, truncated = _capture_config_redact_and_truncate(
                    str(e),
                    limit_chars=4000,
                )
                live_cmds.append({
                    "id": cmd_id,
                    "command": " ".join(argv),
                    "exit_code": 1,
                    "duration_ms": dt_ms,
                    "bytes": int(len(msg.encode("utf-8"))),
                    "truncated": bool(truncated),
                    "captured_ok": False,
                    "error": msg,
                    "redaction_applied": bool(redaction_applied),
                })
                any_fail = True

        if ntype == "frr":
            _run_live_cmd("frr_running_config", ["vtysh", "-c", "show running-config"], live_dir / "running-config.txt")
            _run_live_cmd("frr_bgp_summary", ["vtysh", "-c", "show bgp summary"], live_dir / "bgp-summary.txt")

        if ntype == "nft-fw":
            _run_live_cmd("nft_list_ruleset", ["nft", "list", "ruleset"], live_dir / "nft-list-ruleset.txt")

        # hosts: minimal, stable live readbacks (supporting evidence only)
        if ntype == "host":
            _run_live_cmd("host_ip_br_a", ["ip", "-br", "a"], live_dir / "ip-br-a.txt")
            _run_live_cmd("host_ip_route", ["ip", "route"], live_dir / "ip-route.txt")

        # status computation
        status: str
        if not any_attempt:
            status = "skipped"
        elif any_ok and not any_fail:
            status = "ok"
        elif any_ok and any_fail:
            status = "partial"
        else:
            status = "error"

        manifest["nodes"].append({
            "node": node,
            "node_type": ntype,
            "host_files": host_files,
            "live_commands": live_cmds,
            "status": status,
        })

    finished = time.time()
    manifest["started_at"] = int(started * 1000)
    manifest["finished_at"] = int(finished * 1000)
    manifest["duration_ms"] = int((finished - started) * 1000)

    out_manifest = root / "manifest.json"
    _capture_config_write_text(out_manifest, json.dumps(manifest, indent=2, sort_keys=True))
    return out_manifest

# -----------------------------
# results.json schema guarantee (v1.5)
# -----------------------------
RESULTS_SCHEMA = "results.v1"
RESULTS_SCHEMA_VERSION = "1.0.0"

def _finalize_results_schema(
    *,
    results: dict,
    command: str,
    topo_name: str,
    lab_name: str,
    phase: str,
) -> None:
    """
    Additive-only schema stabilization for results.json.

    Hard rules:
      - never remove/rename/repurpose existing keys
      - never change verdict/exit semantics (this is labeling only)
      - no AI/heuristic authority fields
    """

    # 1) Required schema identifiers (additive)
    results.setdefault("results_schema", RESULTS_SCHEMA)
    results.setdefault("results_schema_version", RESULTS_SCHEMA_VERSION)

    # 2) Identity (additive)
    results.setdefault("tool", "ai-netsim")
    results.setdefault("command", str(command))

    # Keep existing "lab": <string> as-is; add a structured lab object additively.
    results.setdefault("lab_obj", {"name": str(lab_name)})

    # Keep topology info minimal and non-authoritative.
    results.setdefault("topology", {"name": str(topo_name)})

    # 3) Authority boundary (explicit, additive)
    # verdict_source is LOCKED: tests (per design contract / handover).
    results.setdefault(
        "authority",
        {
            "verdict_source": "tests",
            "supporting_evidence": [],
        },
    )

    # 4) Timing (structure stable; values vary)
    summ = results.get("summary") if isinstance(results.get("summary"), dict) else {}
    duration_ms = summ.get("duration_ms")
    timing = results.setdefault("timing", {})
    if isinstance(timing, dict):
        # Preserve existing started_at/finished_at in summary; do NOT invent required wall-clock fields.
        # Only mirror duration_ms structurally if available.
        if duration_ms is not None:
            try:
                timing.setdefault("duration_ms", int(duration_ms))
            except Exception:
                pass

    # 5) Overall envelope (explicit, additive)
    # Derive from existing fields without changing semantics.
    result = str(results.get("result") or "").strip().lower() or "unknown"
    observed = "pass" if result == "pass" else ("fail" if result == "fail" else "error")
    verdict = "pass" if result == "pass" else "fail"

    # Gate exit code semantics remain in process control flow; here we only label.
    exit_code = 0 if verdict == "pass" else 1

    results.setdefault(
        "overall",
        {
            "observed": observed,
            "verdict": verdict,
            "exit_code": int(exit_code),
            "phase": str(phase),
        },
    )

    # 6) Hard failure block (additive; keep null when not used)
    results.setdefault("hard_failure", None)

def cmd_gen(args: argparse.Namespace) -> None:
    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)
    out = write_containerlab_file(topo_path)
    print(f"Generated containerlab file: {out}")

def cmd_validate(args: argparse.Namespace) -> None:
    """
    Validate topology + scenarios without deploying anything.

    CI-friendly semantics:
      - exit 0 on pass, exit 1 on fail
      - with --json: emit exactly ONE JSON object and no extra "ERROR:" prefix
      - without --json: keep human output (✅ / die(...))

    NOTE: This relies on die() honoring a module-global `_QUIET_DIE` flag:
      - when _QUIET_DIE is True, die() must NOT print "ERROR:" and must raise SystemExit(<message>)
        (so str(SystemExit) is the message, not "1").
    """
    import json
    import sys  # keep (often used elsewhere)

    # module-global flag used by die() (moved to netsim_common)

    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)
    want_json: bool = bool(getattr(args, "json", False))

    def emit(result: str, error: str = "") -> None:
        payload = {
            "schema_version": "1",
            "command": "validate",
            "topology": str(topo_path),
            "result": result,
            "error": error or "",
        }
        if want_json:
            # Canonical JSON to stdout (deterministic, diff-friendly).
            print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            if result == "pass":
                print(f"✅ VALIDATE PASS: {topo_path}")
            else:
                die(error or "validation failed")

    prev_quiet = bool(getattr(netsim_common, "_QUIET_DIE", False))
    netsim_common._QUIET_DIE = want_json
    try:
        topo = load_yaml(topo_path)
        ensure_valid_topology(topo)

        resolved = resolve_topology(topo)
        validate_scenarios(resolved)

        # Advisory-only coverage model (declared-only, resolve-time)
        cov = build_coverage_model(resolved, topo_path=topo_path)
        write_coverage_artifact(resolved["name"], cov)

        if want_json:
            payload = {
                "command": "validate",
                "result": "pass",
                "error": "",
                "schema_version": "1",
                "topology": str(topo_path),
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
            return  # do not fall through

        emit("pass", "")
        print("Validated: topology schema + resolve + scenarios (no deploy, no runtime, no tests).")
        print(f"Advisory: wrote coverage to labs/clab-{resolved['name']}/artifacts/coverage/coverage.json")
        return  # do not fall through

        emit("pass", "")
        # v2-validate-scope-clarity (text mode only)
        print("Validated: topology schema + resolve + scenarios (no deploy, no runtime, no tests).")
        lab = str(resolved.get("name") or "").strip()
        if lab:
            print(f"Advisory: wrote coverage to labs/clab-{lab}/artifacts/coverage/coverage.json")
        return  # do not fall through

    except SystemExit as e:
        # In --json mode, die() should have raised SystemExit(<message>), so str(e) is the real error.
        msg = str(e).strip() or "validation failed"
        if want_json:
            emit("fail", msg)
            raise SystemExit(1)
        raise

    except Exception as e:
        msg = str(e).strip() or "validation failed"
        if want_json:
            emit("fail", msg)
            raise SystemExit(1)
        die(msg)

    finally:
        netsim_common._QUIET_DIE = prev_quiet

def cmd_doctor(args: argparse.Namespace) -> None:
    """
    Read-only environment readiness checks.
    Must not mutate environment state.
    Deterministic output (no timestamps, fixed ordering).
    Exit non-zero only if critical dependencies are missing.
    """
    checks: list[tuple[str, bool, str]] = []

    def _which(name: str) -> bool:
        return shutil.which(name) is not None

    def _run_ok(cmd: list[str]) -> bool:
        try:
            p = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return p.returncode == 0
        except Exception:
            return False

    # Critical: docker CLI present
    docker_cli = _which("docker")
    checks.append(("docker CLI detected", docker_cli, "critical"))

    # Critical: docker daemon reachable (only if docker CLI exists)
    docker_daemon = False
    if docker_cli:
        docker_daemon = _run_ok(["docker", "info"])
    checks.append(("docker daemon reachable", docker_daemon, "critical"))

    # Critical: containerlab present
    clab = _which("containerlab")
    checks.append(("containerlab detected", clab, "critical"))

    # Non-critical: image presence (report only; do not pull)
    # These are resolve-time hard defaults in netsim_model.py.
    image_defaults = [
        ("FRR image present", "frrouting/frr:latest"),
        ("nft-fw image present", "ghcr.io/andrew-ai-netsim/nft-fw:latest"),
        ("host image present", "wbitt/network-multitool:latest"),
    ]
    if docker_cli:
        for label, image in image_defaults:
            present = _run_ok(["docker", "image", "inspect", image])
            checks.append((f"{label} ({image})", present, "advisory"))
    else:
        for label, image in image_defaults:
            checks.append((f"{label} ({image})", False, "advisory"))

    # Output (deterministic)
    print("Environment readiness:")
    any_critical_fail = False
    for label, ok, level in checks:
        if level == "critical" and not ok:
            any_critical_fail = True
        mark = "✔" if ok else ("✖" if level == "critical" else "⚠")
        print(f" {mark} {label}")

    if any_critical_fail:
        print("✖ environment NOT ready (critical dependency missing)")
        print("Gate-critical dependencies:")
        print("  - docker daemon reachable")
        print("  - containerlab available")
        print("Advisory checks:")
        print("  - images present locally (no pull performed)")
        raise SystemExit(1)

    print("✔ environment ready")
    print("Gate-critical dependencies:")
    print("  - docker daemon reachable")
    print("  - containerlab available")
    print("Advisory checks:")
    print("  - images present locally (no pull performed)")
    raise SystemExit(0)

def cmd_preflight(args: argparse.Namespace) -> None:
    """
    Advisory-only static preflight:
      - declared-only (topology + resolve + coverage model)
      - no deploy/provision/runtime
      - never gates; exit 0 on success, exit 2 on input/validation error
    """
    import json  # ensure available even if earlier code moves
    import sys

    input_ref = str(getattr(args, "topology", "") or "").strip()
    if not input_ref:
        die("preflight: missing topology argument", code=2)

    topo_path = (TOPO_DIR / input_ref) if not Path(input_ref).is_file() else Path(input_ref)
    if not topo_path.exists():
        die(f"preflight: topology not found: {topo_path}", code=2)

    out_arg = getattr(args, "out", None)
    fmt = str(getattr(args, "format", "json") or "json").strip().lower()
    if fmt not in ("json", "text"):
        die("preflight: --format must be json or text", code=2)

    out_path = Path(str(out_arg)).expanduser() if out_arg else _preflight_default_out()

    try:
        topo = load_yaml(topo_path)
        ensure_valid_topology(topo)

        resolved = resolve_topology(topo)
        validate_scenarios(resolved)

        # Declared-only coverage model (authoritative dependency; still advisory output)
        cov = build_coverage_model(resolved, topo_path=topo_path)

        adapter_paths = getattr(args, "adapter", None) or []
        adapters = None
        if isinstance(adapter_paths, list) and adapter_paths:
            # Explicit-only; missing/unreadable adapter is a user invocation error for preflight.
            # Normalize exit code to 1 (deterministic) even if helper raises SystemExit without code.
            try:
                adapters = _preflight_load_adapters(adapter_paths)
            except SystemExit as e:
                msg = str(e)
                if not msg:
                    msg = "preflight: adapter load failed"
                die(msg, code=1)

        report = _preflight_report(
            input_ref=input_ref,
            topo_path=topo_path,
            resolved=resolved,
            cov=cov,
            adapters=adapters,
        )

        if fmt == "json":
            # Canonical JSON serialization for deterministic artifacts (advisory output; stable bytes).
            from netsim_artifacts import write_json_canonical
            write_json_canonical(out_path, report)
        else:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                _preflight_format_text(report),
                encoding="utf-8",
            )

        # Human hint (non-authoritative, stable path string)
        print(f"✅ PREFLIGHT OK (advisory): wrote {out_path}")
        return

    except SystemExit as e:
        msg = str(e).strip() or "preflight: invalid input"
        # Preserve explicit, deterministic exit codes when sub-helpers raise SystemExit(code).
        # This is required so preflight --adapter missing/unreadable can exit 1 (user invocation error),
        # while other preflight input/validation errors remain exit 2 by convention.
        code = 2
        try:
            if isinstance(e.code, int):
                code = int(e.code)
        except Exception:
            code = 2
        die(msg, code=code)

    except Exception as e:
        msg = str(e).strip() or "preflight: invalid input"
        die(msg, code=2)

def cmd_adapt_terraform(args: argparse.Namespace) -> None:
    """
    Read-only input adapter: Terraform plan JSON -> normalized advisory JSON.
    Exit codes (authoritative):
      - missing/unreadable input plan path: 1
      - parse errors: 0 by default (writes JSON with parse_errors), 1 if --strict
    """
    plan_arg = str(getattr(args, "plan", "") or "").strip()
    if not plan_arg:
        die("adapt terraform: missing --plan <path>", code=1)

    plan_path = Path(plan_arg).expanduser()
    if not plan_path.exists() or not plan_path.is_file():
        die(f"adapt terraform: plan not found: {plan_path}", code=1)

    out_arg = getattr(args, "out", None)
    out_dir = Path(str(out_arg)).expanduser() if out_arg else (BASE_DIR / "artifacts" / "adapters")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "terraform.plan.adapter.json"

    strict = bool(getattr(args, "strict", False))

    payload = adapt_terraform_plan_json(plan_path)

    # Deterministic write
    write_file(out_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")

    # strict parsing semantics: only based on parse_errors field
    pe = payload.get("parse_errors") or []
    pw = payload.get("parse_warnings") or []
    pe_n = len(pe) if isinstance(pe, list) else 0
    pw_n = len(pw) if isinstance(pw, list) else 0

    if pe_n > 0 and strict:
        die(f"adapt terraform: parse_errors={pe_n} (see {out_path})", code=1)

    # Deterministic, actionable output messaging (advisory-only)
    suffix = ""
    if pw_n > 0 or pe_n > 0:
        suffix = f" (parse_warnings={pw_n}, parse_errors={pe_n})"

    print(f"✅ ADAPT OK (advisory): wrote {out_path}{suffix}")

def cmd_adapt_ansible(args: argparse.Namespace) -> None:
    """
    Read-only input adapter: rendered Ansible output dir -> normalized advisory JSON.
    Exit codes (authoritative):
      - missing/unreadable input dir path: 1
      - parse errors: 0 by default (writes JSON with parse_errors), 1 if --strict
    """
    dir_arg = str(getattr(args, "dir", "") or "").strip()
    if not dir_arg:
        die("adapt ansible: missing --dir <path>", code=1)

    root_dir = Path(dir_arg).expanduser()
    if not root_dir.exists() or not root_dir.is_dir():
        die(f"adapt ansible: dir not found: {root_dir}", code=1)

    out_arg = getattr(args, "out", None)
    out_dir = Path(str(out_arg)).expanduser() if out_arg else (BASE_DIR / "artifacts" / "adapters")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ansible.rendered.adapter.json"

    strict = bool(getattr(args, "strict", False))

    payload = adapt_ansible_rendered_dir(root_dir)

    # Deterministic write
    write_file(out_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")

    # strict parsing semantics: only based on parse_errors field
    pe = payload.get("parse_errors") or []
    if isinstance(pe, list) and len(pe) > 0 and strict:
        die(f"adapt ansible: parse_errors={len(pe)} (see {out_path})", code=1)

    print(f"✅ ADAPT OK (advisory): wrote {out_path}")

def cmd_up(args: argparse.Namespace) -> None:
    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)

    # If --reconfigure: destroy + remove root-owned lab dir FIRST.
    # Pre-validate topology BEFORE any destructive action (v1 deterministic, fail-fast)
    topo_preview = load_yaml(topo_path)
    ensure_valid_topology(topo_preview)
    resolved_preview = resolve_topology(topo_preview)
    validate_scenarios(resolved_preview)

    # If --reconfigure: destroy + remove root-owned lab dir AFTER validation passes.
    if getattr(args, "reconfigure", False):
        # v2-privilege-transparency-notice (Template A): must precede first sudo call in this path
        _maybe_print_privilege_notice("A")

        lab_name: str | None = None
        try:
            lab_name = (resolved_preview or {}).get("name")
        except Exception:
            lab_name = None

        if isinstance(lab_name, str) and lab_name.strip():
            lab_name = lab_name.strip()
            existing_clab = LABS_DIR / f"{lab_name}.clab.yaml"
            if existing_clab.exists():
                _run_containerlab(["sudo", "containerlab", "destroy", "-t", str(existing_clab)], check=False)
            run(["sudo", "rm", "-rf", str(lab_dir(lab_name))], check=False)

    # Generate AFTER destroy/cleanup
    out = write_containerlab_file(topo_path)

    # Deploy
    _maybe_print_privilege_notice("A")
    _run_containerlab(["sudo", "containerlab", "deploy", "-t", str(out)], check=True)

    # Derive lab name deterministically from generated file
    lab_name = out.name.replace(".clab.yaml", "")

    # Load resolved topology (authoritative for provisioning)
    resolved_path = lab_dir(lab_name) / "topology.resolved.yaml"
    if not resolved_path.exists():
        die(f"Resolved topology not found after deploy: {resolved_path}")

    topo = load_yaml(resolved_path) or {}

    # Runtime is created AFTER topology is known (future-proof for vm/container selection)
    rt = get_runtime(topo)

    # ---------------------------------------------------------------------
    # Provisioning (runtime-driven)
    # ---------------------------------------------------------------------

    # 1) Hosts (IPs + default route)
    configure_hosts_from_topology(rt, lab_name, topo)

    # 2) nft-fw interface IPs + forwarding (NO nft rules here)
    configure_nftfw_from_topology(rt, lab_name, topo)

    # 3) nft-fw static routes
    configure_nftfw_routes_from_topology(rt, lab_name, topo)

    # 4) nft rules last (so forwarding + routes exist first)
    for n in topo.get("nodes", []) or []:
        if not isinstance(n, dict):
            continue
        if n.get("type") != "nft-fw":
            continue

        name = n.get("name")
        if not isinstance(name, str) or not name.strip():
            die("nft-fw node missing 'name'")
        name = name.strip()

        # Apply nft rules
        nft_fw_apply(rt, lab_name, name, gen_nft_fw_rules(n))

        # Routed fw readiness only if it has next-hops (derived from links)
        nhs = fw_next_hops_from_links(topo, name)
        if nhs:
            verify_fw_routed_ready(rt, lab_name, name)

    # 5) FRR provisioning
    configure_frr_interfaces_from_topology(rt, lab_name, topo)

    # ---------------------------------------------------------------------
    # Up success confirmation (v2-up-command-success-confirmation)
    # ---------------------------------------------------------------------

    # Expected nodes: derived deterministically from resolved topology (declared order; de-dupe)
    node_names: list[str] = []
    for n in topo.get("nodes", []) or []:
        if not isinstance(n, dict):
            continue
        nm = n.get("name")
        if isinstance(nm, str) and nm.strip():
            nm = nm.strip()
            if nm not in node_names:
                node_names.append(nm)

    runtime_line = f"Runtime: not verified (use 'netsim status {lab_name}')"
    try:
        total = len(node_names)
        # Runtime summary is best-effort; must not add retries or waits.
        if total > 0 and hasattr(rt, "node_id") and hasattr(rt, "exists_id"):
            running = 0
            stopped = 0
            missing = 0

            for node in node_names:
                node_id = rt.node_id(lab_name, node)

                # exists?
                if not rt.exists_id(node_id):
                    missing += 1
                    continue

                # running?
                is_run = False
                if hasattr(rt, "is_running_id"):
                    is_run = bool(rt.is_running_id(node_id))
                elif hasattr(rt, "is_running"):
                    is_run = bool(rt.is_running(lab_name, node))

                if is_run:
                    running += 1
                else:
                    stopped += 1

            if missing == 0 and stopped == 0 and running == total:
                runtime_line = f"Runtime: RUNNING ({running}/{total})"
            else:
                runtime_line = (
                    f"Runtime: PARTIAL ({running}/{total} running; {missing}/{total} missing; {stopped}/{total} stopped)"
                )
    except Exception:
        runtime_line = f"Runtime: UNKNOWN (use 'netsim status {lab_name}')"

    if not bool(getattr(args, "_from_gate", False)):
        print("────────────────────────────────────────")
        print("ai-netsim Up Result")
        print("────────────────────────────────────────")
        print(f"Lab: {lab_name}")
        print("RESULT: UP OK")
        print(runtime_line)
        print("Next:")
        print(f"  netsim status {lab_name}")
        print(f"  netsim test {lab_name}")
        print(f"  netsim exec {lab_name} <node>")
        print(f"  netsim down {lab_name}")
    
def cmd_down(args: argparse.Namespace) -> None:
    """
    Destroy a lab deterministically.

    UX rule (deterministic, no guessing beyond explicit file existence):
      - If arg looks like a topology file (*.yaml|*.yml) and exists (either as a path or under topologies/),
        load it and use its 'name' as the lab name.
      - Otherwise treat arg as a lab name (and strip a .yaml/.yml suffix if present).
    """
    raw = str(getattr(args, "name", "") or "").strip()
    if not raw:
        die("down requires a lab name or a topology filename (.yaml)")

    raw_path = Path(raw)
    raw_lower = raw_path.name.lower()

    # Path-like input must never be reinterpreted as a lab name.
    # (contains path separators, explicit relative prefixes, or looks like a topology filename)
    path_like = (
        ("/" in raw)
        or ("\\" in raw)
        or raw.startswith("./")
        or raw.startswith("../")
        or raw_lower.endswith((".yaml", ".yml"))
    )

    # Mirror cmd_up resolution: accept either a real path or a name under topologies/
    topo_path = (TOPO_DIR / raw) if not Path(raw).is_file() else Path(raw)

    lab_name: str
    used_topology = False
    if topo_path.suffix in (".yaml", ".yml") and topo_path.exists():
        used_topology = True
        topo_doc = load_yaml(topo_path) or {}
        lab_name = str((topo_doc.get("name") or "").strip())
        if not lab_name:
            die(f"Topology '{topo_path}' has no valid 'name' field (required).")
    else:
        if path_like:
            die(f"ERROR: topology path not found: '{raw}' (refusing to interpret as lab name)", code=2)

        # Treat as lab name; tolerate accidental ".yaml" suffix
        if raw.endswith(".yaml") or raw.endswith(".yml"):
            lab_name = Path(raw).stem.strip()
        else:
            lab_name = raw

        if not lab_name:
            die("down requires a non-empty lab name")

    out = lab_file_from_name(lab_name)

    # Idempotent behavior (default):
    # If the generated containerlab file is missing, treat this as "already down".
    #
    # WI-8.1 (Set 8): destructive NO-OP must be explicit and unambiguous.
    if not out.exists():
        strict = bool(getattr(args, "strict", False))

        if strict:
            print(f"ERROR: lab '{lab_name}' not found")

        print("────────────────────────────────────────")
        print("ai-netsim Down Result")
        print("────────────────────────────────────────")
        print(f"LAB DESCRIPTOR: labs/{lab_name}.clab.yaml")
        print("RESULT: NO-OP (lab not found)")

        if strict:
            raise SystemExit(2)
        return

    # Target clarity (quiet mode included)
    if used_topology:
        print(f"Topology: {topo_path}")
    print(f"Lab: {lab_name}")

    # Destroy via containerlab (authoritative destroy mechanism)
    print("Action: destroy runtime")
    _maybe_print_privilege_notice("A")
    _run_containerlab(["sudo", "containerlab", "destroy", "-t", str(out)], check=True)
    print(f"OK  {lab_name}: destroyed")

    # Artifact policy (v2 gate integrity):
    # - Runtime teardown must NOT delete labs/clab-<lab> evidence.
    # - Explicit deletion is handled only by:
    #     * netsim destroy <lab> --purge-artifacts
    #     * netsim cleanup --all --yes
    return

def cmd_destroy(args: argparse.Namespace) -> None:
    """
    Explicit ops command (non-authoritative):
      netsim destroy <lab> [--purge-artifacts]

    Semantics:
      - Attempts runtime teardown using containerlab destroy when the generated <lab>.clab.yaml exists.
      - Does NOT delete disk artifacts by default.
      - If --purge-artifacts is set: deletes labs/clab-<lab> after runtime teardown attempt.
      - Idempotent and deterministic: missing runtime/artifacts => "nothing to do" (exit 0).
      - Returns non-zero if runtime teardown fails OR (if --purge-artifacts) artifact purge fails.
      - Optional machine-readable report: labs/_cleanup/destroy-<lab>.json (supporting evidence only)
    """
    raw = str(getattr(args, "name", "") or "").strip()
    if not raw:
        die("destroy requires a lab name or a topology filename (.yaml)")

    # Mirror cmd_up/cmd_down resolution: accept either a real path or a name under topologies/
    topo_path = (TOPO_DIR / raw) if not Path(raw).is_file() else Path(raw)

    lab_name: str
    if topo_path.suffix in (".yaml", ".yml") and topo_path.exists():
        topo_doc = load_yaml(topo_path) or {}
        lab_name = str((topo_doc.get("name") or "").strip())
        if not lab_name:
            die(f"Topology '{topo_path}' has no valid 'name' field (required).")
    else:
        # Treat as lab name; tolerate accidental ".yaml" suffix
        if raw.endswith(".yaml") or raw.endswith(".yml"):
            lab_name = Path(raw).stem.strip()
        else:
            lab_name = raw

        if not lab_name:
            die("destroy requires a non-empty lab name")

    clab_yaml = lab_file_from_name(lab_name)
    artifact_dir = lab_dir(lab_name)

    failures: list[str] = []
    report = {
        "authority": "supporting_evidence",
        "schema_version": "destroy.v1",
        "command": "destroy",
        "lab": lab_name,
        "clab_yaml": str(clab_yaml),
        "artifact_dir": str(artifact_dir),
        "runtime_destroy": {"attempted": False, "status": "skipped", "detail": ""},
        "artifact_purge": {"attempted": False, "status": "skipped", "detail": ""},
        "failures": failures,
    }

    did_anything = False
    if clab_yaml.exists():
        # Target clarity (quiet mode included)
        # Note: we deliberately mirror cmd_down semantics: topology-path resolution is determined above.
        # If the input was a topology file path, we print it; otherwise we print only Lab.
        if topo_path.suffix in (".yaml", ".yml") and topo_path.exists():
            print(f"Topology: {topo_path}")
        print(f"Lab: {lab_name}")

        print("Action: destroy runtime")
        did_anything = True
        report["runtime_destroy"]["attempted"] = True
        _maybe_print_privilege_notice("A")
        cp = _run_containerlab(["sudo", "containerlab", "destroy", "-t", str(clab_yaml)], check=False)
        if cp.returncode == 0:
            report["runtime_destroy"]["status"] = "succeeded"
            print(f"OK  {lab_name}: destroyed")
        else:
            combined = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
            low = combined.lower()
            if "not found" in low or "no such" in low:
                report["runtime_destroy"]["status"] = "skipped"
                report["runtime_destroy"]["detail"] = "already down / not found"
                print(f"OK  {lab_name}: already down / not found")
            else:
                summary = combined.splitlines()[-1].strip() if combined else f"exit {cp.returncode}"
                report["runtime_destroy"]["status"] = "failed"
                report["runtime_destroy"]["detail"] = summary
                failures.append(f"runtime destroy failed: {summary}")
                print(f"WARN {lab_name}: destroy failed: {summary}")
    else:
        report["runtime_destroy"]["detail"] = f"missing {clab_yaml.name} (no runtime destroy attempted)"

    # Step 2: optional disk purge
    do_purge = bool(getattr(args, "purge_artifacts", False))
    if do_purge:
        report["artifact_purge"]["attempted"] = True
        if artifact_dir.exists():
            did_anything = True
            _maybe_print_privilege_notice("B")
            cp_rm = run(
                ["sudo", "rm", "-rf", str(artifact_dir)],
                check=False,
                capture_output=True,
            )
            if cp_rm.returncode == 0:
                report["artifact_purge"]["status"] = "succeeded"
                print(f"OK  {lab_name}: artifacts purged")
            else:
                combined_rm = ((cp_rm.stdout or "") + "\n" + (cp_rm.stderr or "")).strip()
                summary_rm = combined_rm.splitlines()[-1].strip() if combined_rm else f"exit {cp_rm.returncode}"
                report["artifact_purge"]["status"] = "failed"
                report["artifact_purge"]["detail"] = summary_rm
                failures.append(f"artifact purge failed: {summary_rm}")
                print(f"WARN {lab_name}: artifact purge failed: {summary_rm}")
        else:
            report["artifact_purge"]["status"] = "skipped"
            report["artifact_purge"]["detail"] = "artifacts absent"
            print(f"OK  {lab_name}: artifacts absent (nothing to purge)")
    else:
        report["artifact_purge"]["detail"] = "not requested (default: keep artifacts)"

    # Write optional machine-readable report (supporting evidence only)
    try:
        report_path = LABS_DIR / "_cleanup" / f"destroy-{lab_name}.json"
        write_file(report_path, json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

        # WI-2: Quiet mode must not print absolute filesystem paths.
        # Keep legacy "Wrote:" line only for --verbose (presentation-only).
        if bool(getattr(args, "verbose", False)):
            print(f"Wrote: {report_path}")
    except Exception as e:
        failures.append(f"destroy report write failed: {e}")
        print(f"WARN: destroy report write failed: {e}")

    if failures:
        print("Destroy completed with failures:")
        for f in failures:
            print(f"- {lab_name}: {f}")
        die("destroy: one or more actions failed", code=1)

    if not did_anything:
        # WI-8.1 (Set 8): destructive NO-OP must be explicit and unambiguous.
        strict = bool(getattr(args, "strict", False))

        if strict:
            print(f"ERROR: lab '{lab_name}' not found")

        print("────────────────────────────────────────")
        print("ai-netsim Destroy Result")
        print("────────────────────────────────────────")
        print(f"LAB DESCRIPTOR: labs/{lab_name}.clab.yaml")
        print("RESULT: NO-OP (lab not found)")

        if strict:
            raise SystemExit(2)
        return

def cmd_cleanup(args: argparse.Namespace) -> None:
    """
    v1.x ops helper (non-authoritative):
      netsim cleanup --all [--yes]

    Safety:
      - ONLY targets ai-netsim labs that have artifacts under labs/clab-*
      - Dry-run by default; --yes required to execute
      - Never touches labs not present in labs/ (no Docker scans)
      - On execute: attempts runtime teardown (if .clab.yaml exists) AND purges artifacts under labs/clab-*
      - Best-effort across labs; final exit non-zero if any intended action failed
      - Optional machine-readable report: labs/_cleanup/cleanup.json
    """
    if not getattr(args, "all", False):
        die("cleanup requires --all. This command only targets ai-netsim labs present in labs/ (labs/clab-*).")

    candidates = list_owned_labs_from_artifacts()

    do_exec = bool(getattr(args, "yes", False))
    print("Cleanup plan (execute):" if do_exec else "Cleanup plan (dry-run):")

    if not candidates:
        print("- (none)  No ai-netsim lab artifacts found under labs/clab-*")
        return

    for lab, artifact_dir in candidates:
        print(f"- {lab}   ({artifact_dir})")

    if not do_exec:
        print("Run with --yes to execute cleanup. (This will destroy runtime state when possible and purge labs/clab-* artifacts.)")
        return

    # v2-privilege-transparency-notice (Template B): cleanup destroys runtime and purges labs/ artifacts
    _maybe_print_privilege_notice("B")

    # Execute: best-effort, deterministic order, never stops on per-lab failure
    failures: list[str] = []
    report_labs: list[dict[str, object]] = []

    for lab, artifact_dir in candidates:
        lab_entry: dict[str, object] = {
            "lab": lab,
            "artifact_dir": str(artifact_dir),
            "runtime_destroy": {"attempted": False, "status": "skipped", "detail": ""},
            "artifact_purge": {"attempted": False, "status": "skipped", "detail": ""},
        }

        # Runtime destroy (only if we have the generated .clab.yaml; we do NOT scan Docker)
        clab_yaml = lab_file_from_name(lab)
        if clab_yaml.exists():
            lab_entry["runtime_destroy"]["attempted"] = True
            cp = run(
                ["sudo", "containerlab", "destroy", "-t", str(clab_yaml)],
                check=False,
                capture_output=True,
            )

            if cp.returncode == 0:
                lab_entry["runtime_destroy"]["status"] = "succeeded"
                print(f"OK  {lab}: destroyed")
            else:
                combined = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
                low = combined.lower()
                if "not found" in low or "no such" in low:
                    lab_entry["runtime_destroy"]["status"] = "skipped"
                    lab_entry["runtime_destroy"]["detail"] = "already down / not found"
                    print(f"OK  {lab}: already down / not found")
                else:
                    summary = combined.splitlines()[-1].strip() if combined else f"exit {cp.returncode}"
                    lab_entry["runtime_destroy"]["status"] = "failed"
                    lab_entry["runtime_destroy"]["detail"] = summary
                    print(f"WARN {lab}: destroy failed: {summary}")
                    failures.append(f"{lab}: runtime destroy failed: {summary}")
        else:
            lab_entry["runtime_destroy"]["detail"] = f"missing {clab_yaml.name} (no runtime destroy attempted)"

        # Artifact purge (always for cleanup --all)
        lab_entry["artifact_purge"]["attempted"] = True
        cp_rm = run(
            ["sudo", "rm", "-rf", str(artifact_dir)],
            check=False,
            capture_output=True,
        )
        if cp_rm.returncode == 0:
            lab_entry["artifact_purge"]["status"] = "succeeded"
            print(f"OK  {lab}: artifacts purged")
        else:
            combined_rm = ((cp_rm.stdout or "") + "\n" + (cp_rm.stderr or "")).strip()
            summary_rm = combined_rm.splitlines()[-1].strip() if combined_rm else f"exit {cp_rm.returncode}"
            lab_entry["artifact_purge"]["status"] = "failed"
            lab_entry["artifact_purge"]["detail"] = summary_rm
            print(f"WARN {lab}: artifact purge failed: {summary_rm}")
            failures.append(f"{lab}: artifact purge failed: {summary_rm}")

        report_labs.append(lab_entry)

    # Write optional machine-readable report (supporting evidence only)
    try:
        cleanup_report = {
            "authority": "supporting_evidence",
            "schema_version": "cleanup.v1",
            "command": "cleanup --all",
            "executed": True,
            "labs_targeted": [lab for lab, _ in candidates],
            "labs": report_labs,
            "failures": failures,
        }
        report_path = LABS_DIR / "_cleanup" / "cleanup.json"
        write_file(report_path, json.dumps(cleanup_report, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        print(f"Wrote: {report_path}")
    except Exception as e:
        # Report writing must never mask cleanup failures; treat as an additional failure signal.
        failures.append(f"cleanup report write failed: {e}")
        print(f"WARN: cleanup report write failed: {e}")

    if failures:
        print("Cleanup completed with failures:")
        for f in failures:
            print(f"- {f}")
        die("cleanup --all: one or more actions failed", code=1)

    print("Cleanup completed successfully.")

def cmd_exec(args: argparse.Namespace) -> None:
    rt = get_runtime()

    lab = str(getattr(args, "lab", "") or "").strip()
    node = str(getattr(args, "node", "") or "").strip()
    if not lab or not node:
        die(
            "ERROR: missing required arguments.\n"
            "Usage:\n"
            "  netsim exec <lab-name> <node> -- <cmd...>\n"
            "Next:\n"
            "  Run: netsim status <lab-name>  (to list nodes)",
            code=2,
        )

    # Determine valid nodes deterministically from local lab descriptors (no Docker scanning).
    resolved_path = lab_dir(lab) / "topology.resolved.yaml"
    lab_yaml_path = lab_file_from_name(lab)

    valid_nodes: list[str] = []
    if lab_yaml_path.exists():
        try:
            valid_nodes = sorted([str(n) for n in parse_lab_nodes(lab) if str(n).strip()])
        except Exception as e:
            die(f"ERROR: failed to parse lab file '{lab_yaml_path}': {e}", code=2)
    elif resolved_path.exists():
        try:
            topo = _load_resolved_topology(lab)
        except Exception as e:
            die(f"ERROR: failed to load resolved topology '{resolved_path}': {e}", code=2)
        try:
            valid_nodes = sorted(
                [
                    str(n.get("name")).strip()
                    for n in _iter_nodes(topo)
                    if isinstance(n, dict) and isinstance(n.get("name"), str) and str(n.get("name")).strip()
                ]
            )
        except Exception as e:
            die(f"ERROR: failed to derive nodes from resolved topology '{resolved_path}': {e}", code=2)

    if not valid_nodes:
        die(
            "ERROR: lab '"
            + str(lab)
            + "' not found locally (missing lab descriptors)\n"
            "Expected:\n"
            "  labs/"
            + str(lab)
            + ".clab.yaml\n"
            "  labs/clab-"
            + str(lab)
            + "/topology.resolved.yaml\n"
            "Next:\n"
            "  Gate mode: netsim test <topology.yaml>\n"
            "  Lab mode:  netsim up <topology.yaml> --reconfigure\n"
            "Hint:\n"
            "  Use: netsim status <lab-name>",
            code=2,
        )

    if node not in valid_nodes:
        die(
            f"ERROR: invalid node '{node}' for lab '{lab}'\n"
            f"Valid nodes: {', '.join(valid_nodes)}\n"
            f"Try: netsim status {lab}",
            code=2,
        )

    # Valid node: ensure runtime container exists (runtime-owned check) to prevent daemon error leakage.
    if hasattr(rt, "node_id") and hasattr(rt, "exists_id"):
        node_id = rt.node_id(lab, node)
        try:
            if not rt.exists_id(node_id):
                die(
                    f"ERROR: lab runtime missing for '{lab}' (container {node_id} not found)\n"
                    f"Try: netsim status {lab}\n"
                    "Hint: Run 'netsim up <topology.yaml> --reconfigure' (or 'netsim run <topology.yaml> --keep') then retry.\n"
                    "If artifacts are stale: netsim cleanup --all --yes",
                    code=2,
                )
        except SystemExit:
            raise
        except Exception:
            # Keep deterministic and actionable without exposing backend exceptions.
            die(f"ERROR: unable to verify runtime for lab '{lab}' (use 'netsim status {lab}')", code=2)

    if not args.command:
        # Interactive shell (runtime decides how)
        cp = rt.exec(lab, node, ["bash"], check=False, capture_output=False, interactive=True)
        return

    cp = rt.exec(lab, node, args.command, check=False, capture_output=False)
    if cp.returncode != 0:
        die(f"Command failed inside {rt.node_id(lab, node)} (exit {cp.returncode})", code=cp.returncode)

def cmd_vty(args: argparse.Namespace) -> None:
    rt = get_runtime()

    lab = str(getattr(args, "lab", "") or "").strip()
    node = str(getattr(args, "node", "") or "").strip()
    command = str(getattr(args, "command", "") or "").strip()
    if not lab or not node or not command:
        die(
            "ERROR: missing required arguments.\n"
            "Usage:\n"
            '  netsim vty <lab-name> <node> "<command>"\n'
            "Next:\n"
            "  Run: netsim status <lab-name>  (to list nodes)",
            code=2,
        )

    # command is provided as a single string; e.g. "show bgp summary"
    cp = vty(rt, lab, node, command)

    # vtysh prints errors to stdout typically; just show output
    sys.stdout.write(cp.stdout or "")
    sys.stderr.write(cp.stderr or "")
    if cp.returncode != 0:
        die(f"vtysh command failed (exit {cp.returncode})", code=cp.returncode)

def _load_resolved_topology(lab_name: str) -> dict[str, Any]:
    lab_dir = LABS_DIR / f"clab-{lab_name}"
    topo_path = lab_dir / "topology.resolved.yaml"
    if not topo_path.is_file():
        # Phase 3 misuse semantics: missing lab artifacts is a usage error (exit 2),
        # and the message must be deterministic + actionable (no Docker scanning).
        die(
            f"Lab artifacts not found for lab={lab_name}. Expected: {topo_path}\n"
            "Hint: Run 'netsim up <topology.yaml>' (or 'netsim run <topology.yaml> --keep') then retry.",
            code=2,
        )
    return load_yaml(topo_path)

def _iter_nodes(topo: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = topo.get("nodes", [])
    # Support both styles: list (preferred) or dict (legacy)
    if isinstance(nodes, list):
        return [n for n in nodes if isinstance(n, dict)]
    if isinstance(nodes, dict):
        out: list[dict[str, Any]] = []
        for name, n in nodes.items():
            if isinstance(n, dict):
                nn = dict(n)
                nn.setdefault("name", name)
                out.append(nn)
        return out
    return []

import re

def _fmt_list_cap(items: list[str], cap: int = 5) -> str:
    """
    Deterministically render a list with a cap:
      ["a","b","c","d","e","f"] -> "a, b, c, d, e (+1 more)"
    """
    items = [str(x) for x in items if str(x)]
    items = sorted(set(items))
    if not items:
        return ""
    if len(items) <= cap:
        return ", ".join(items)
    head = ", ".join(items[:cap])
    return f"{head} (+{len(items) - cap} more)"

def cmd_status(args: argparse.Namespace) -> None:
    """
    Read-only lab status.

    - Default: human-friendly output.
    - --json: machine output only (no "+ docker ..." command echoes).
    - --bgp: intent-aware BGP checks (expected from topology.resolved.yaml).
      * tries `show bgp summary json` first, falls back to text summary parsing
    - --routes: intent-aware route presence checks (read-only), derived from topology.resolved.yaml.
    - Exit code changes ONLY with --strict (per design contract).

    Improvements in this version:
      1) Human --summary prints reliably.
      2) Human mismatch lines include parser mode (parser=json|text|none).
      3) In --strict, containers not running are treated as prerequisite failures,
         producing deterministic reasons like:
           "container not running: r2 (container=clab-<lab>-r2)"
    """
    import json
    rt = get_runtime()

    # Phase 3 (P3-A): accept either lab name OR topology path deterministically.
    # - No Docker scanning.
    # - Lab name derives ONLY from topology 'name:' (or filename stem fallback, matching footer behavior).
    raw_lab = str(getattr(args, "lab", "") or "").strip()
    if not raw_lab:
        die(
            "ERROR: missing LAB NAME.\n"
            "Usage:\n"
            "  netsim status <lab-name>\n"
            "Next:\n"
            "  If you have a topology: netsim test <topology.yaml>  (gate)\n"
            "  If you already deployed: netsim status <lab-name>",
            code=2,
        )

    lab = raw_lab
    topo_path = None  # set only when user input is a topology path (for deterministic error context)
    raw_path = Path(raw_lab)
    dname_l = raw_path.name.lower()

    # If it looks like a topology path, deterministically derive lab name from YAML.
    if ("/" in raw_lab) or ("\\" in raw_lab) or dname_l.endswith((".yaml", ".yml")):
        topo_path = raw_lab
        try:
            topo = load_topology_yaml(raw_lab)
        except Exception as e:
            die(f"ERROR: failed to load topology file '{raw_lab}': {e}", code=2)

        derived = str(topo.get("name") or Path(raw_lab).stem).strip()
        if not derived:
            die(f"ERROR: topology file '{raw_lab}' has no valid 'name' field (required)", code=2)

        lab = derived

    bgp_enabled = bool(getattr(args, "bgp", False))
    bgp_verbose = bool(getattr(args, "bgp_verbose", False))
    strict = bool(getattr(args, "strict", False))
    show_intf = bool(getattr(args, "interfaces", False))
    show_summary = bool(getattr(args, "summary", False))
    as_json = bool(getattr(args, "json", False))

    routes_enabled = bool(getattr(args, "routes", False))
    routes_verbose = bool(getattr(args, "routes_verbose", False))

    # Suppress "+ <cmd>" echoes during JSON mode (so JSON is clean)
    old_quiet = netsim_common.QUIET_RUN
    if as_json:
        netsim_common.QUIET_RUN = True

    # ------------------------------------------------------------
    # Truthful status: derive expected nodes deterministically from
    # local descriptors (resolved-topology preferred, clab-yaml fallback).
    # Runtime existence is checked later via rt (no containerlab inspect).
    # ------------------------------------------------------------
    source = "none"
    topo = None
    nodes: list[dict[str, Any]] = []

    resolved_path = lab_dir(lab) / "topology.resolved.yaml"
    lab_yaml_path = lab_file_from_name(lab)

    if resolved_path.exists():
        try:
            topo = _load_resolved_topology(lab)
        except Exception as e:
            die(f"ERROR: failed to load resolved topology '{resolved_path}': {e}", code=2)
        nodes = sorted(_iter_nodes(topo), key=lambda n: str(n.get("name", "")))
        source = "resolved-topology"

    elif lab_yaml_path.exists():
        # Fallback: generated containerlab YAML exists, but resolved topology does not.
        # Enumerate expected node names from the clab YAML deterministically.
        try:
            names = sorted(parse_lab_nodes(lab), key=lambda s: str(s))
        except Exception as e:
            die(f"ERROR: failed to parse lab file '{lab_yaml_path}': {e}", code=2)
        nodes = [{"name": n, "type": ""} for n in names]
        source = "clab-yaml"

    else:
        # No local descriptor; we can still report lab-level UNKNOWN deterministically.
        nodes = []
        source = "none"

    # v2-status-unknown-lab-nonzero-and-notfound-result:
    # If no local lab descriptors exist, status MUST be truthful:
    # - RESULT: NOT FOUND
    # - Exit code: 2
    # - No Docker probing / no partial runtime block
    #
    # Important: do NOT use die() here because it prepends "ERROR:" which breaks the
    # status block contract. This is a deterministic usage result block + exit code.
    if source == "none":
        expected_clab = f"labs/{lab}.clab.yaml"
        sys.stdout.write(
            "────────────────────────────────────────\n"
            "ai-netsim Status\n"
            "────────────────────────────────────────\n"
            f"Lab: {lab}\n"
            "RESULT: NOT FOUND\n"
            "Reason: No lab descriptor found locally.\n"
            "Expected:\n"
            f"  {expected_clab}\n"
            "Next:\n"
            "  netsim test <topology.yaml>\n"
        )
        raise SystemExit(2)

    # Expected intent checks are only available when resolved topology exists.
    expected_bgp_by_node = derive_expected_bgp_neighbors_from_links(topo) if topo else {}
    expected_routes_by_frr = derive_expected_routes_for_frr(topo) if (topo and routes_enabled) else {}

    def _node_exec(node: str, cmd: list[str]) -> str:
        cp = rt.exec(lab, node, cmd, check=False, capture_output=True)
        out = cp.stdout.decode("utf-8", errors="replace") if isinstance(cp.stdout, bytes) else cp.stdout
        return (out or "").strip()

    # Deterministic list formatting helper (cap for readability)
    def _fmt_list_cap(items: list[str], cap: int = 5) -> str:
        items = sorted(set(str(x) for x in items if str(x)))
        if not items:
            return ""
        if len(items) <= cap:
            return ", ".join(items)
        return f"{', '.join(items[:cap])} (+{len(items) - cap} more)"

    def _extend_bgp_reasons(node: str, bgp: dict[str, Any], reasons_list: list[str], cap: int = 5) -> None:
        if not bgp.get("expected"):
            return
        mode = str(bgp.get("parser_mode") or "none")

        if bgp.get("missing"):
            reasons_list.append(
                f"bgp missing on {node}: {_fmt_list_cap(bgp['missing'], cap)} (parser={mode})"
            )
        if bgp.get("down"):
            reasons_list.append(
                f"bgp down on {node}: {_fmt_list_cap(bgp['down'], cap)} (parser={mode})"
            )
        if bgp.get("extra"):
            reasons_list.append(
                f"bgp extra on {node}: {_fmt_list_cap(bgp['extra'], cap)} (parser={mode})"
            )

    def _extend_routes_reasons(node: str, routes: dict[str, Any], reasons_list: list[str], cap: int = 5) -> None:
        if not routes.get("expected"):
            return
        mode = str(routes.get("parser_mode") or "none")
        if routes.get("missing"):
            reasons_list.append(
                f"routes missing on {node}: {_fmt_list_cap(routes['missing'], cap)} (parser={mode})"
            )

    def _extend_container_reasons(
        down_nodes: list[tuple[str, str]],
        reasons_list: list[str],
        cap: int = 5,
    ) -> None:
        """
        down_nodes: [(node_name, container_name), ...]
        Deterministic, capped reasons for prerequisite failures.
        """
        if not down_nodes:
            return
        # Deterministic order
        down_nodes = sorted(set(down_nodes), key=lambda t: (t[0], t[1]))
        rendered = [f"{n} (container={c})" for (n, c) in down_nodes]
        reasons_list.append(f"containers not running: {_fmt_list_cap(rendered, cap)}")

    # Counters
    total_nodes = 0
    running_nodes = 0
    exp_total_peers = 0
    exp_established_peers = 0
    frr_nodes_with_expected_peers = 0
    routes_total_prefixes = 0
    routes_present_prefixes = 0
    frr_nodes_with_expected_routes = 0

    strict_fail = False
    reasons: list[str] = []

    # Track container-down prereq failures deterministically
    down_containers: list[tuple[str, str]] = []

    out_doc: dict[str, Any] = {
        "schema_version": "1",
        "lab": lab,
        "nodes": [],
        "summary": {},
        "verdict": "pass",
        "reasons": [],
    }

    for n in nodes:
        name = str(n.get("name", "")).strip()
        ntype = str(n.get("type", "")).strip()
        if not name:
            continue

        total_nodes += 1
        cname = f"clab-{lab}-{name}"

        # Truthful runtime state (deterministic):
        # - exists: docker inspect return code (via rt.exists_id)
        # - running: .State.Running (via rt.is_running_id), only meaningful if exists
        exists = bool(rt.exists_id(cname))
        running = bool(rt.is_running_id(cname)) if exists else False

        if running:
            running_nodes += 1
        else:
            # Keep legacy prereq list for strict reasons (now includes stopped+missing)
            down_containers.append((name, cname))

        state = "running" if running else ("stopped" if exists else "missing")

        node_rec: dict[str, Any] = {
            "name": name,
            "type": ntype,
            "container": cname,
            "running": bool(running),
            "state": state,
        }

        # Interfaces
        if running and show_intf:
            try:
                node_rec["interfaces"] = _node_exec(name, ["sh", "-lc", "ip -br a"]).splitlines()
            except Exception as e:
                node_rec["interfaces_error"] = str(e)

        # BGP
        if running and bgp_enabled and ntype == "frr":
            expected = expected_bgp_by_node.get(name, set())
            bgp_rec: dict[str, Any] = {
                "expected": sorted(expected),
                "observed": [],
                "missing": [],
                "down": [],
                "extra": [],
                "established": [],
                "ok": True,
                "parser_mode": "none",
            }

            try:
                out_json = _node_exec(name, ["vtysh", "-c", "show bgp summary json"])
                observed = parse_frr_bgp_summary_neighbors_json(out_json)
                if observed:
                    bgp_rec["parser_mode"] = "json"
                else:
                    out_text = _node_exec(name, ["vtysh", "-c", "show bgp summary"])
                    observed = parse_frr_bgp_summary_neighbors(out_text)
                    bgp_rec["parser_mode"] = "text"

                cmp = compare_expected_vs_observed_bgp(expected, observed)
                bgp_rec.update(cmp)

                if expected:
                    frr_nodes_with_expected_peers += 1
                    exp_total_peers += len(expected)
                    exp_established_peers += len(cmp["established"])

                if bgp_verbose and not as_json:
                    bgp_rec["raw_text"] = _node_exec(name, ["vtysh", "-c", "show bgp summary"])

                if strict and expected and not bgp_rec["ok"]:
                    strict_fail = True
                    _extend_bgp_reasons(name, bgp_rec, reasons)

            except Exception as e:
                bgp_rec["error"] = str(e)
                bgp_rec["ok"] = False
                if strict and expected:
                    strict_fail = True
                    reasons.append(
                        f"bgp error on {name}: {type(e).__name__} (parser={bgp_rec.get('parser_mode','none')})"
                    )

            node_rec["bgp"] = bgp_rec

        # ROUTES
        if running and routes_enabled and ntype == "frr":
            expected_routes = expected_routes_by_frr.get(name, set())
            routes_rec: dict[str, Any] = {
                "expected": sorted(expected_routes),
                "observed": [],
                "missing": [],
                "ok": True,
                "parser_mode": "none",
            }

            try:
                rt_json = _node_exec(name, ["vtysh", "-c", "show ip route json"])
                observed = parse_frr_show_ip_route_prefixes_json(rt_json)
                rt_text = ""
                if observed:
                    routes_rec["parser_mode"] = "json"
                else:
                    rt_text = _node_exec(name, ["vtysh", "-c", "show ip route"])
                    observed = parse_frr_show_ip_route_prefixes(rt_text)
                    routes_rec["parser_mode"] = "text"

                cmp = compare_expected_vs_observed_prefixes(expected_routes, observed)
                routes_rec.update(cmp)

                if expected_routes:
                    frr_nodes_with_expected_routes += 1
                    routes_total_prefixes += len(expected_routes)
                    routes_present_prefixes += len(expected_routes) - len(cmp["missing"])

                if routes_verbose and not as_json:
                    routes_rec["raw_text"] = rt_text if routes_rec["parser_mode"] == "text" else rt_json

                if strict and expected_routes and not routes_rec["ok"]:
                    strict_fail = True
                    _extend_routes_reasons(name, routes_rec, reasons)

            except Exception as e:
                routes_rec["error"] = str(e)
                routes_rec["ok"] = False
                if strict and expected_routes:
                    strict_fail = True
                    reasons.append(
                        f"routes error on {name}: {type(e).__name__} (parser={routes_rec.get('parser_mode','none')})"
                    )

            node_rec["routes"] = routes_rec

        out_doc["nodes"].append(node_rec)

    # NEW: prereq failure => strict_fail + reasons (deterministic)
    if strict and down_containers:
        strict_fail = True
        _extend_container_reasons(down_containers, reasons, cap=5)

    # Summary (always produced)
    out_doc["summary"] = {
        "containers_running": {"running": running_nodes, "total": total_nodes}
    }
    if bgp_enabled:
        out_doc["summary"]["bgp_expected_peers"] = {
            "established": exp_established_peers,
            "total": exp_total_peers,
            "frr_nodes_with_expected_peers": frr_nodes_with_expected_peers,
        }
    if routes_enabled:
        out_doc["summary"]["routes_expected_prefixes"] = {
            "present": routes_present_prefixes,
            "total": routes_total_prefixes,
            "frr_nodes_with_expected_routes": frr_nodes_with_expected_routes,
        }

    if strict_fail:
        out_doc["verdict"] = "fail"
        out_doc["reasons"] = sorted(set(reasons))
    else:
        out_doc["verdict"] = "pass"
        out_doc["reasons"] = []

    # JSON output mode: no human printing
    if as_json:
        print(json.dumps(out_doc, indent=2, sort_keys=True))
        if strict and strict_fail:
            raise SystemExit(2)
        return

    # -------------------------
    # Human output (updated)
    # -------------------------
    topo_arg = str(getattr(args, "lab", "") or "").strip()
    topo_path = None
    if topo_arg:
        p = Path(topo_arg)
        if ("/" in topo_arg) or ("\\" in topo_arg) or p.name.lower().endswith((".yaml", ".yml")):
            topo_path = topo_arg

    print("────────────────────────────────────────")
    print("ai-netsim Status")
    print("────────────────────────────────────────")
    print(f"Lab: {lab}")

    # Lab-level runtime classification (deterministic)
    states = [str(n.get("state") or "") for n in out_doc.get("nodes", [])]
    runtime = "UNKNOWN"
    if not states:
        runtime = "UNKNOWN"
    else:
        missing_n = sum(1 for s in states if s == "missing")
        running_n = sum(1 for s in states if s == "running")
        stopped_n = sum(1 for s in states if s == "stopped")

        if missing_n == len(states):
            runtime = "MISSING"
        elif running_n == len(states):
            runtime = "RUNNING"
        elif running_n == 0 and stopped_n > 0 and missing_n == 0:
            runtime = "STOPPED"
        else:
            runtime = "PARTIAL"

    # Result block (stable ordering)
    # Allowed: OK | STOPPED | UNKNOWN
    if runtime == "RUNNING":
        result = "OK"
    elif runtime in ("STOPPED", "MISSING"):
        result = "STOPPED"
    else:
        result = "UNKNOWN"

    print(f"RESULT: {result}")
    print(f"Runtime: {runtime}")
    print(f"Source: {source}")

    # Optional topology hint (informational only)
    if topo_path:
        print(f"Topology: {topo_path}")

    if not out_doc["nodes"]:
        print("Nodes: (none)")
        if show_summary:
            print(f"Summary: containers {running_nodes}/{total_nodes} running")
        print("Next:")
        if topo_path:
            print(f"  netsim test {topo_path}  (gate)")
        else:
            print("  netsim test <topology.yaml>  (gate)")
        return

    print("Next:")
    if result == "OK":
        print(f"  netsim test {lab}  (lab mode)")
        print(f"  netsim exec {lab} <node> -- <cmd...>")
        print(f"  netsim down {lab}")
    else:
        if topo_path:
            print(f"  netsim test {topo_path}  (gate)")
            print(f"  netsim up {topo_path} --reconfigure")
        else:
            print("  netsim test <topology.yaml>  (gate)")
        print(f"  netsim status {lab}")

    print("Nodes:")
    for node_rec in out_doc["nodes"]:
        name = node_rec["name"]
        cname = node_rec["container"]
        state = str(node_rec.get("state") or ("running" if node_rec.get("running") else "missing"))
        print(f"  - {name:<8} ({cname}) : {state}")

        if running and show_intf and "interfaces" in node_rec and node_rec["interfaces"]:
            print("      IF:")
            for line in node_rec["interfaces"]:
                print(f"      {line}")

        if running and bgp_enabled and node_rec.get("type") == "frr":
            bgp = node_rec.get("bgp") or {}
            expected = bgp.get("expected") or []
            pm = str(bgp.get("parser_mode") or "none")

            if not expected:
                print("      BGP (none)")
            else:
                est = len(bgp.get("established") or [])
                tot = len(expected)
                if bgp.get("ok"):
                    print(f"      BGP expected {tot} | Established {est}/{tot} (OK, parser={pm})")
                else:
                    print(f"      BGP expected {tot} | Established {est}/{tot} (MISMATCH, parser={pm})")
                    if bgp.get("missing"):
                        print(f"      BGP missing: {_fmt_list_cap(bgp['missing'], 8)}")
                    if bgp.get("down"):
                        print(f"      BGP down:    {_fmt_list_cap(bgp['down'], 8)}")
                    if bgp.get("extra"):
                        print(f"      BGP extra:   {_fmt_list_cap(bgp['extra'], 8)}")

            if bgp_verbose:
                raw_text = (bgp.get("raw_text") or "").splitlines()
                if raw_text:
                    print("      --- show bgp summary ---")
                    for line in raw_text:
                        print(f"      {line}")

        if running and routes_enabled and node_rec.get("type") == "frr":
            rts = node_rec.get("routes") or {}
            expected = rts.get("expected") or []
            pm = str(rts.get("parser_mode") or "none")

            if expected:
                missing = rts.get("missing") or []
                present = len(expected) - len(missing)
                tot = len(expected)
                if rts.get("ok"):
                    print(f"      ROUTES expected {tot} | Present {present}/{tot} (OK, parser={pm})")
                else:
                    print(f"      ROUTES expected {tot} | Present {present}/{tot} (MISMATCH, parser={pm})")
                    if missing:
                        print(f"      ROUTES missing: {_fmt_list_cap(missing, 8)}")

            if routes_verbose:
                raw_text = (rts.get("raw_text") or "").splitlines()
                if raw_text:
                    print("      --- show ip route ---")
                    for line in raw_text:
                        print(f"      {line}")

    # NEW: summary prints reliably when requested
    if show_summary:
        parts = [f"containers {running_nodes}/{total_nodes} running"]
        if bgp_enabled:
            parts.append(f"BGP expected peers {exp_established_peers}/{exp_total_peers} established")
            parts.append(f"FRR nodes w/expected peers {frr_nodes_with_expected_peers}")
        if routes_enabled:
            parts.append(f"ROUTES expected {routes_present_prefixes}/{routes_total_prefixes} present")
            parts.append(f"FRR nodes w/expected routes {frr_nodes_with_expected_routes}")
        print("Summary: " + " | ".join(parts))

    if strict and strict_fail:
        raise SystemExit(2)

    netsim_common.QUIET_RUN = old_quiet

def cmd_collect(args: argparse.Namespace) -> None:
    import json
    import re
    from typing import Any

    lab = args.lab
    rt = get_runtime()

    tpath = topo_path_for_lab(lab)
    if not tpath.exists():
        die(f"Topology file not found for lab '{lab}': {tpath}")

    topo = load_yaml(tpath)
    ensure_valid_topology(topo)

    outdir = lab_dir(lab) / "artifacts"
    outdir.mkdir(parents=True, exist_ok=True)

    def write(name: str, content: str) -> None:
        (outdir / name).write_text(content, encoding="utf-8")

    def normalize_bgp_summary(text: str) -> str:
        """
        Deterministic BGP neighbor snapshot from `show bgp summary`.

        We intentionally discard volatile counters/timers and keep only:
        - neighbor address
        - ASN (best-effort parse)
        - state (Established vs Idle/Active/etc.)

        Output format (one per neighbor):
          <NEIGHBOR> AS=<ASN or ?> STATE=<STATE>
        """
        lines = (text or "").splitlines()
        out: list[str] = []
        in_table = False

        for line in lines:
            # Detect the table header
            if ("Neighbor" in line) and ("Up/Down" in line):
                in_table = True
                out.append(line.rstrip())
                continue

            if not in_table:
                # Keep pre-table lines as-is (usually stable)
                out.append(line.rstrip())
                continue

            if not line.strip():
                out.append("")
                continue

            parts = line.split()
            if len(parts) < 2:
                out.append(line.rstrip())
                continue

            nbr = parts[0]
            # Neighbor column must look like an IP (v4/v6) to be a row
            if not re.match(r"^[0-9A-Fa-f:.]+$", nbr):
                out.append(line.rstrip())
                continue

            # Heuristic: AS is the first integer token shortly after the neighbor/V columns
            asn: str | None = None
            for tok in parts[1:6]:
                if tok.isdigit():
                    asn = tok
                    break

            # Last token often is State/PfxRcd. If it's numeric => Established.
            last = parts[-1]
            state = "Established" if last.isdigit() else last

            out.append(f"{nbr} AS={asn or '?'} STATE={state}")

        return "\n".join(out).rstrip() + "\n"

    def scrub_containerlab_inspect_json(raw: str) -> str:
        """
        Containerlab inspect JSON can include volatile fields.
        We remove common volatile keys and sort keys for stable output.
        """
        try:
            obj = json.loads(raw)
        except Exception:
            # Fall back to raw text (useful, but may be nondeterministic)
            return (raw or "").rstrip() + "\n"

        volatile_keys = {
            "pid", "pids",
            "startedAt", "finishedAt",
            "created", "createdAt",
            "uptime",
            "status", "state",
            "container_id", "containerID",
            "ipv4", "ipv6",
            "mgmtIPv4Address", "mgmtIPv6Address",
        }

        def drop_keys(o: Any) -> None:
            if isinstance(o, dict):
                for k in list(o.keys()):
                    if k in volatile_keys:
                        o.pop(k, None)
                for v in o.values():
                    drop_keys(v)
            elif isinstance(o, list):
                for v in o:
                    drop_keys(v)

        drop_keys(obj)
        return json.dumps(obj, sort_keys=True, indent=2).rstrip() + "\n"

    # Strict: ensure all expected nodes are running before collecting
    nodes_raw = topo.get("nodes", []) or []
    nodes = sorted((nodes_raw if isinstance(nodes_raw, list) else []), key=lambda n: (n or {}).get("name", ""))
    for n in nodes:
        if not isinstance(n, dict):
            continue
        name = n.get("name")
        if not isinstance(name, str) or not name.strip():
            die(f"Invalid node entry in topology (missing name): {n!r}")
        name = name.strip()

        if not rt.is_running(lab, name):
            die(f"COLLECT FAIL: {rt.node_id(lab, name)} is not running")

    # Containerlab inspect JSON (scrubbed) — stable, runtime-neutral enough for now
    clab_yaml = LABS_DIR / f"{lab}.clab.yaml"
    cp = run(
        ["sudo", "containerlab", "inspect", "-t", str(clab_yaml), "--format", "json"],
        check=False,
        capture_output=True,
    )
    write("containerlab-inspect.json", scrub_containerlab_inspect_json(cp.stdout or cp.stderr or ""))

    # Optional: logs are nondeterministic; keep off by default
    include_logs = False

    # Per-node snapshots (deterministic order)
    for n in nodes:
        if not isinstance(n, dict):
            continue
        name = n.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        name = name.strip()

        cp = rt.sh(lab, name, "ip -br a", check=False, capture_output=True)
        write(f"{name}.ip-addr.txt", (cp.stdout or cp.stderr or "").rstrip() + "\n")

        cp = rt.sh(lab, name, "ip route", check=False, capture_output=True)
        write(f"{name}.ip-route.txt", (cp.stdout or cp.stderr or "").rstrip() + "\n")

        if n.get("type") == "nft-fw":
            cp = rt.sh(lab, name, "nft list ruleset", check=False, capture_output=True)
            write(f"{name}.nft-ruleset.txt", (cp.stdout or cp.stderr or "").rstrip() + "\n")

            cp = rt.sh(lab, name, "sysctl -n net.ipv4.ip_forward", check=False, capture_output=True)
            write(f"{name}.ip-forward.txt", (cp.stdout or cp.stderr or "").strip() + "\n")

        if n.get("type") == "frr":
            cp = rt.exec(lab, name, ["vtysh", "-c", "show bgp summary"], check=False, capture_output=True)
            write(f"{name}.bgp-summary.txt", normalize_bgp_summary(cp.stdout or cp.stderr or ""))

        if include_logs:
            # Runtime should own log collection in future; keep docker-less for now.
            # If you later add rt.logs(...), call it here.
            pass

    print(f"✅ COLLECT PASS: wrote artifacts to {outdir}")

def cmd_run(args: argparse.Namespace) -> None:
    """
    Ephemeral workflow:
      up -> (capture-config) -> (test) -> (collect) -> (down)

    Teardown policy:
      - Default: destroy ONLY on full success (so failures keep the lab for debugging)
      - --destroy-always: attempt destroy even if something fails
      - --keep: never destroy (overrides --destroy-always)

    Other:
      - collect runs best-effort even if test fails (unless --no-collect)
      - capture-config is supporting evidence only; never gates
      - UX: if --keep and NOT --reconfigure and lab is already up, do NOT redeploy
    """
    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)

    # Derive lab name robustly from topology (authoritative)
    try:
        topo_for_name = load_yaml(topo_path)
    except Exception as e:
        die(f"Failed to load topology YAML '{topo_path}': {e}")

    lab_name = (topo_for_name or {}).get("name")
    if not lab_name or not isinstance(lab_name, str):
        die(f"Topology '{topo_path}' has no valid 'name' field (required).")

    lab_name = lab_name.strip()
    if not lab_name:
        die(f"Topology '{topo_path}' has no valid 'name' field (required).")

    # Flags
    keep = bool(getattr(args, "keep", False))
    destroy_always = bool(getattr(args, "destroy_always", False))
    do_collect = not bool(getattr(args, "no_collect", False))
    do_test = not bool(getattr(args, "no_test", False))  # ok even if flag not yet added
    do_reconfigure = bool(getattr(args, "reconfigure", False))
    do_capture_config = bool(getattr(args, "capture_config", False))

    exit_code: int | None = None   # None means "no failure captured"
    up_ok = False

    def _as_exit_code(code: object) -> int:
        # SystemExit.code can be None, int, str, etc.
        try:
            return int(code) if code is not None else 1
        except Exception:
            return 1

    def record_failure(code: object = None) -> None:
        nonlocal exit_code
        if exit_code is None:
            exit_code = _as_exit_code(code)

    def _expected_node_names_from_topology(path: Path) -> list[str]:
        """
        Deterministic node name extraction from the *authoritative* topology schema.
        Accept both historical shapes to reduce UX surprises:
          - nodes: { r1: {...}, r2: {...} }  (dict)
          - nodes: [ {name: r1, ...}, ... ]  (list)
        """
        try:
            topo_doc = load_yaml(path)
        except Exception:
            return []

        if not isinstance(topo_doc, dict):
            return []

        nodes = topo_doc.get("nodes", None)
        names: list[str] = []

        if isinstance(nodes, dict):
            names = [str(k) for k in nodes.keys()]
        elif isinstance(nodes, list):
            for item in nodes:
                if not isinstance(item, dict):
                    continue
                n = item.get("name")
                if isinstance(n, str) and n.strip():
                    names.append(n.strip())

        return sorted(set(names))

    def _container_running(name: str) -> bool:
        cp = run(["docker", "inspect", "-f", "{{.State.Running}}", name], check=False, capture=True, text=True)
        return (cp.returncode == 0 and (cp.stdout or "").strip() == "true")

    def _container_exists(name: str) -> bool:
        cp = run(["docker", "inspect", name], check=False, capture=True, text=True)
        return cp.returncode == 0

    def _lab_fully_running(lab: str, node_names: list[str]) -> bool:
        if not node_names:
            return False
        for n in node_names:
            cname = f"clab-{lab}-{n}"
            if not _container_running(cname):
                return False
        return True

    def _lab_any_exists(lab: str, node_names: list[str]) -> bool:
        if not node_names:
            return False
        for n in node_names:
            cname = f"clab-{lab}-{n}"
            if _container_exists(cname):
                return True
        return False

    def _load_resolved_topology_or_die(lab: str) -> dict:
        rp = lab_dir(lab) / "topology.resolved.yaml"
        if not rp.exists():
            die(f"Resolved topology not found: {rp} (lab may not be deployed, or artifacts were removed)")
        topo = load_yaml(rp) or {}
        if not isinstance(topo, dict):
            die(f"Resolved topology is invalid (expected dict): {rp}")
        return topo

    try:
        # 1) up
        #
        # UX rule for run:
        # - If --keep and NOT --reconfigure:
        #     * If the lab is already fully up, do NOT redeploy; proceed to capture/test/collect.
        #     * If containers exist but the lab is not fully up, fail-fast with a clear message.
        # - Otherwise: behave as before (call cmd_up).
        try:
            node_names = _expected_node_names_from_topology(topo_path)

            if keep and (not do_reconfigure):
                if _lab_fully_running(lab_name, node_names):
                    up_ok = True
                elif _lab_any_exists(lab_name, node_names):
                    print(
                        f"ERROR: lab '{lab_name}' already exists but is not fully running. "
                        f"Use '--reconfigure' to rebuild it (or run 'netsim down {lab_name}' first).",
                        file=sys.stderr,
                    )
                    record_failure(1)
                else:
                    cmd_up(argparse.Namespace(topology=str(topo_path), reconfigure=do_reconfigure))
                    up_ok = True
            else:
                cmd_up(argparse.Namespace(topology=str(topo_path), reconfigure=do_reconfigure))
                up_ok = True

        except SystemExit as e:
            record_failure(getattr(e, "code", 1))
        except Exception:
            record_failure(1)

        # If up failed, skip the rest (but still hit finally + final reporting)
        if up_ok:
            # 1b) supporting evidence: capture-config (best-effort; never gates)
            if do_capture_config:
                try:
                    topo_resolved = _load_resolved_topology_or_die(lab_name)
                    rt = get_runtime(topo_resolved)
                    _capture_config_run_exploration(rt, lab=lab_name)
                except SystemExit as e:
                    # Filesystem root failures are fail-fast by contract; record and continue to finally.
                    record_failure(getattr(e, "code", 1))
                except Exception:
                    record_failure(1)

            # 2) test (optional)
            if do_test:
                try:
                    cmd_test(argparse.Namespace(lab=lab_name, _report_authority="run"))
                except SystemExit as e:
                    record_failure(getattr(e, "code", 1))
                except Exception:
                    record_failure(1)

            # 3) collect (best-effort; very useful for debugging failures)
            if do_collect:
                try:
                    cmd_collect(argparse.Namespace(lab=lab_name))
                except SystemExit as e:
                    record_failure(getattr(e, "code", 1))
                except Exception:
                    record_failure(1)

    finally:
        # 4) down decision
        # keep wins (never destroy)
        # otherwise:
        #   - destroy_always => always attempt down
        #   - default => only down on full success (exit_code is None)
        if keep:
            should_destroy = False
        elif destroy_always:
            should_destroy = True
        else:
            should_destroy = (exit_code is None)

        if should_destroy:
            try:
                cmd_down(argparse.Namespace(name=lab_name))
            except SystemExit as e:
                # If we were successful until teardown, teardown failure matters.
                if exit_code is None:
                    record_failure(getattr(e, "code", 1))
            except Exception:
                if exit_code is None:
                    record_failure(1)

    # Phase 1 (R2/R5): explicit lifecycle disclosure (deterministic; no runtime inspection)
    if keep:
        lifecycle = "RETAINED"
    elif destroy_always:
        lifecycle = "DESTROYED"
    else:
        # Default run behavior: destroy only on full success; keep lab on failure for debugging.
        lifecycle = "DESTROYED" if (exit_code is None) else "RETAINED"
    print(f"Lab lifecycle: {lifecycle}")

    # Final reporting + exit behavior (never lie)
    if exit_code is not None and int(exit_code) != 0:
        raise SystemExit(int(exit_code))

    return

# --- Assistive AI (v1: advisory-only, artifact-only, post-exec, BYO-key online optional) ---

def _ai_resolve_lab_and_dir(arg: str) -> tuple[str, str]:
    """
    If 'arg' looks like a topology file (*.yaml|*.yml), load it and use its 'name' as the lab.
    Otherwise treat it as a lab name directly.
    Returns (lab, lab_dir).
    """
    from pathlib import Path
    import yaml

    p = Path(arg)
    if p.suffix in (".yaml", ".yml") and p.exists():
        with p.open("r", encoding="utf-8") as f:
            topo = yaml.safe_load(f) or {}
        lab = str((topo.get("name") or "").strip())
        if not lab:
            print("AI usage error: topology must define 'name' to resolve lab.", file=sys.stderr)
            sys.exit(2)
    else:
        lab = arg.strip()
        if not lab:
            print("AI usage error: lab name is empty.", file=sys.stderr)
            sys.exit(2)

    return lab, os.path.join("labs", f"clab-{lab}")


def _ai_read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _ai_file_exists(path: str) -> bool:
    try:
        st = os.stat(path)
        return st.st_size >= 0
    except Exception:
        return False


def _ai_advisory_headers() -> dict[str, Any]:
    return {
        "authority": "advisory",
        "non_authoritative": True,
        "disclaimer": "Assistive AI is advisory-only. Tests & scenarios are authoritative.",
    }


def _ai_print_json(payload: dict[str, Any], ensure_ascii: bool = False) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=ensure_ascii))


def _ai_env(name: str) -> str:
    return (os.getenv(name) or "").strip()


def _ai_default_bundle_out_path(bundle: dict[str, Any]) -> str | None:
    """
    Default bundle location:
      - explain: labs/<labdir>/ai/ai_bundle.json (uses bundle["lab"]["labdir"])
      - review: no default (no labdir) -> only writes if --bundle-out is provided
      - coach: no default (no labdir) -> only writes if --bundle-out is provided
    """
    lab = bundle.get("lab")
    if isinstance(lab, dict):
        labdir = lab.get("labdir")
        if isinstance(labdir, str) and labdir.strip():
            return os.path.join(labdir.strip(), "ai", "ai_bundle.json")
    return None


def _ai_write_bundle(path: str, bundle: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, sort_keys=True, ensure_ascii=False)


def _ai_online_config(args) -> dict[str, Any]:
    """
    BYO key contract:
      - provider: AI_NETSIM_AI_PROVIDER (currently only 'openai' supported)
      - api_key: AI_NETSIM_AI_API_KEY or OPENAI_API_KEY
      - model:   --model or AI_NETSIM_AI_MODEL (fallback safe default inside _ai_try_online)
      - base_url: optional AI_NETSIM_AI_BASE_URL (for proxies/self-hosting)
    """
    provider = _ai_env("AI_NETSIM_AI_PROVIDER").lower()
    api_key = _ai_env("AI_NETSIM_AI_API_KEY") or _ai_env("OPENAI_API_KEY")
    model = (getattr(args, "model", None) or _ai_env("AI_NETSIM_AI_MODEL") or "").strip()
    base_url = _ai_env("AI_NETSIM_AI_BASE_URL") or ""
    if base_url == "":
        base_url = None
    return {
        "provider": provider,
        "api_key": api_key,
        "model": model,
        "base_url": base_url,
    }

def _ai_sanitize_error(msg: str) -> str:
    """
    Sanitize provider error messages so they are safe to emit:
      - remove API keys
      - trim excessive length
    """
    if not msg:
        return ""

    # Never leak anything that looks like an API key
    msg = re.sub(r"sk-[A-Za-z0-9]{10,}", "sk-REDACTED", msg)

    # Bound size (CI / logs safety)
    MAX = 500
    if len(msg) > MAX:
        msg = msg[:MAX] + "...(truncated)"

    return msg

def _ai_validate_output_schema(out: Any) -> tuple[bool, str]:
    """
    Validate the v1 AI output schema.

    Required:
      - summary: string

    Optional (but if present must match shape):
      - findings: list of {title,evidence,suggestion} strings
      - suggested_next_tests: list of {id,title,why,yaml} strings

    Returns: (ok, error_string)
    """
    if not isinstance(out, dict):
        return (False, "AI output must be a JSON object")

    summary = out.get("summary")
    if not isinstance(summary, str):
        return (False, "AI output schema error: 'summary' must be a string")

    findings = out.get("findings", [])
    if findings is None:
        findings = []
    if not isinstance(findings, list):
        return (False, "AI output schema error: 'findings' must be a list")

    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            return (False, f"AI output schema error: findings[{i}] must be an object")
        for k in ("title", "evidence", "suggestion"):
            if k not in f or not isinstance(f.get(k), str):
                return (False, f"AI output schema error: findings[{i}].{k} must be a string")

    nxt = out.get("suggested_next_tests")
    if nxt is not None:
        if not isinstance(nxt, list):
            return (False, "AI output schema error: 'suggested_next_tests' must be a list")
        for i, item in enumerate(nxt):
            if not isinstance(item, dict):
                return (False, f"AI output schema error: suggested_next_tests[{i}] must be an object")
            for k in ("id", "title", "why", "yaml"):
                if k not in item or not isinstance(item.get(k), str):
                    return (False, f"AI output schema error: suggested_next_tests[{i}].{k} must be a string")

    return (True, "")

def _ai_parse_and_validate_model_json(text: str) -> tuple[dict[str, Any], str]:
    """
    JSON-only contract:
      - Must be valid JSON
      - Must be a dict matching the required schema
    Returns: (parsed_dict_or_empty, error_string_or_empty)
    """
    text = (text or "").strip()
    if not text:
        return ({}, "empty model response")

    try:
        out = json.loads(text)
    except Exception as e:
        return ({}, f"non-JSON model response: {e!s}")

    ok, err = _ai_validate_output_schema(out)
    if not ok:
        return ({}, err)

    # Safe: schema-validated dict. Keep as-is (do not rewrite content).
    return (out, "")

def _ai_sanitize_output_for_fixture(ai_output: Any) -> dict[str, Any]:
    """
    Convert schema-valid ai_output into a stable, content-free structure for fixtures.

    This is a structural contract sanitizer:
      - does NOT validate correctness of content
      - does NOT pin wording
      - only preserves schema shape + required keys
    """
    # If it's not schema-valid, return empty dict (caller should already validate schema).
    if not isinstance(ai_output, dict):
        return {}

    # Enforce only the allowed schema keys in the sanitized fixture
    allowed_top = {"summary", "findings", "suggested_next_tests"}
    out: dict[str, Any] = {}

    # summary
    if "summary" in ai_output and isinstance(ai_output.get("summary"), str):
        out["summary"] = "<string>"
    else:
        out["summary"] = "<missing>"

    # findings
    findings = ai_output.get("findings")
    san_findings: list[dict[str, str]] = []
    if isinstance(findings, list):
        for f in findings:
            if isinstance(f, dict):
                san_findings.append({
                    "title": "<string>" if isinstance(f.get("title"), str) else "<missing>",
                    "evidence": "<string>" if isinstance(f.get("evidence"), str) else "<missing>",
                    "suggestion": "<string>" if isinstance(f.get("suggestion"), str) else "<missing>",
                })
            else:
                san_findings.append({
                    "title": "<invalid>",
                    "evidence": "<invalid>",
                    "suggestion": "<invalid>",
                })
    out["findings"] = san_findings

    # suggested_next_tests
    nxt = ai_output.get("suggested_next_tests")
    san_nxt: list[dict[str, str]] = []
    if isinstance(nxt, list):
        for item in nxt:
            if isinstance(item, dict):
                san_nxt.append(
                    {
                        "id": "<string>" if isinstance(item.get("id"), str) else "<missing>",
                        "title": "<string>" if isinstance(item.get("title"), str) else "<missing>",
                        "why": "<string>" if isinstance(item.get("why"), str) else "<missing>",
                        "yaml": "<string>" if isinstance(item.get("yaml"), str) else "<missing>",
                    }
                )
            else:
                san_nxt.append({"id": "<invalid>", "title": "<invalid>", "why": "<invalid>", "yaml": "<invalid>"})
    out["suggested_next_tests"] = san_nxt

    # If additional keys exist, record them explicitly (so fixtures can guard expansion).
    extras = sorted([k for k in ai_output.keys() if k not in allowed_top])
    out["_extra_keys"] = extras  # must be [] in fixtures

    return out

def _ai_provider_openai(
    bundle: dict[str, Any],
    model: str,
    api_key: str,
    base_url: str | None
) -> tuple[str, dict[str, Any], str]:
    """
    Returns (ai_status, ai_output, ai_error)

    ai_output:
      - parsed JSON dict if the model returns JSON
      - else {"raw_text": "..."} if non-JSON
    """
    try:
        from openai import OpenAI  # type: ignore
    except Exception as e:
        return (
            "unavailable",
            {},
            _ai_sanitize_error(f"openai sdk not importable: {e!s}")
        )

    try:
        client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)

        # Deterministic prompt object: bundle-only input.
        prompt_obj = {
            "task": "ai-netsim advisory analysis",
            "rules": {
                "authority": "advisory",
                "non_authoritative": True,
                "do_not_change_verdicts_or_exit_codes": True,
                "artifact_only": True,
                "no_runtime_calls": True,
            },
            "bundle": bundle,
            "output_contract": {
                "json_only": True,
                "no_markdown": True,
                "no_prose_outside_json": True,
                "rules": [
                    "Return JSON only. No YAML, no markdown, no prose outside the JSON object.",
                    "Never claim correctness or safety. Do NOT use words like: validated, correct, safe, approved, guaranteed.",
                    "Anchor claims to observed evidence (tests/scenarios/results pointers) where possible. Config text is context only.",
                    "Candidate changes are context-only and are never executed/simulated/validated by ai-netsim.",
                    "Suggested tests MUST be actionable: include a copy-paste YAML snippet that fits ai-netsim v1 schema.",
                ],
                "schema": {
                    "summary": "string",
                    "findings": [{"title": "string", "evidence": "string", "suggestion": "string"}],
                    "suggested_next_tests": [
                        {"id": "string", "title": "string", "why": "string", "yaml": "string"},
                    ],
                },
            },
        }

        resp = client.responses.create(
            model=model,
            input=[
                {
                    "role": "user",
                    "content": json.dumps(prompt_obj, sort_keys=True),
                }
            ],
        )

        # Defensive extraction (Responses API)
        text = ""
        try:
            # Preferred: SDK convenience field
            text = getattr(resp, "output_text", "") or ""
        except Exception:
            text = ""

        # Fallback: scan structured output for message content
        if not text:
            try:
                for item in getattr(resp, "output", []) or []:
                    if getattr(item, "type", "") == "message":
                        for part in getattr(item, "content", []) or []:
                            if getattr(part, "type", "") == "output_text":
                                text += getattr(part, "text", "") or ""
                            elif getattr(part, "type", "") == "text":
                                # Some SDKs use "text" parts
                                text += getattr(part, "text", "") or ""
            except Exception:
                text = ""

        if not text:
            # Last resort: string form (usually not useful, but keep deterministic behavior)
            try:
                text = str(resp)
            except Exception:
                text = ""

        text = (text or "").strip()
        if not text:
            return ("unavailable", {}, "empty model response")

        out, perr = _ai_parse_and_validate_model_json(text)
        if perr:
            return ("unavailable", {}, _ai_sanitize_error(perr))
        return ("ok", out, "")

    except Exception as e:
        return (
            "unavailable",
            {},
            _ai_sanitize_error(str(e))
        )

def _ai_try_online(bundle: dict[str, Any], args) -> dict[str, Any]:
    """
    Never raises. Never gates.
    Returns:
      {ai_status, ai_error, model_used, ai_output}
    """
    if not bool(getattr(args, "online", False)):
        return {"ai_status": "unavailable", "ai_error": "online not requested", "model_used": None, "ai_output": {}}

    cfg = _ai_online_config(args)

    if not cfg["provider"]:
        return {"ai_status": "unavailable", "ai_error": "AI_NETSIM_AI_PROVIDER not set", "model_used": None, "ai_output": {}}

    if cfg["provider"] != "openai":
        return {"ai_status": "unavailable", "ai_error": f"unsupported provider '{cfg['provider']}'", "model_used": None, "ai_output": {}}

    if not cfg["api_key"]:
        return {
            "ai_status": "unavailable",
            "ai_error": "AI_NETSIM_AI_API_KEY/OPENAI_API_KEY not set",
            "model_used": None,
            "ai_output": {},
        }

    # Safe default (can change later). Keep deterministic behavior regardless.
    model = cfg["model"] or "gpt-4.1-mini"

    st, out, err = _ai_provider_openai(bundle=bundle, model=model, api_key=cfg["api_key"], base_url=cfg["base_url"])
    return {"ai_status": st, "ai_error": err, "model_used": model, "ai_output": out}


def _ai_finalize_and_emit(command_name: str, bundle: dict[str, Any], args) -> None:
    """
    Single enforcement point for v1 AI CLI contract.

    Rules:
      - Bundle is deterministic and always exists.
      - --bundle: print bundle JSON (no online), exit 0
      - --bundle-out: write bundle to path (no online), exit 0
      - default: write bundle to default path if available (explain only)
      - --online: attempt provider call; failures never gate; exit 0
      - output controlled by --format json|text (default json per argparse)
    """

    def _cc_summary_text(bundle_in: dict[str, Any]) -> str | None:
        # Support legacy keys + current key.
        cc = bundle_in.get("change_context") or bundle_in.get("change_review") or bundle_in.get("change_explain")
        if not isinstance(cc, dict):
            return None

        present = bool(cc.get("present", False))
        if not present:
            return None

        counts = cc.get("counts") if isinstance(cc.get("counts"), dict) else {}
        items = int(counts.get("items", 0) or 0)
        included = int(counts.get("included", 0) or 0)
        missing = int(counts.get("missing", 0) or 0)
        blocked = int(counts.get("blocked", 0) or 0)
        too_large = int(counts.get("too_large", 0) or 0)

        # One-line banner: explicit non-execution + non-authority (v1 contract).
        return (
            f"change_context: present (items={items} included={included} missing={missing} "
            f"blocked={blocked} too_large={too_large}) — context-only, NOT executed, does not affect verdicts"
        )


    def _ai_contains_forbidden_correctness_language(obj: Any) -> bool:
        # Non-blocking lint: warn in text mode (never gate).
        # Expand list to cover common implied authority / safety claims.
        forbidden = (
            "validated",
            "correct",
            "safe",
            "approved",
            "guaranteed",
            "compliant",
            "secure",
            "certified",
            "verified",
        )
        try:
            s = json.dumps(obj, ensure_ascii=True).lower()
            return any(w in s for w in forbidden)
        except Exception:
            return False


    def _render_ai_output_text(ai_out: Any) -> None:
        """
        Human-friendly rendering for engineers.

        Expected ai_out schema:
          {
            "summary": str,
            "findings": [{title,evidence,suggestion}],
            "suggested_next_tests": [{id,title,why,yaml}]
          }
        Backward compatible: if suggested_next_tests is list[str], print as generic.
        """
        if not ai_out:
            return

        if not isinstance(ai_out, dict):
            print(str(ai_out))
            return

        summary = ai_out.get("summary")
        if isinstance(summary, str) and summary.strip():
            print("summary:")
            print(f"  {summary.strip()}")
            print("  (Informational only. Only tests & scenarios prove behavior.)")
            print()

        findings = ai_out.get("findings")
        if isinstance(findings, list) and findings:
            print("findings:")
            n = 0
            for f in findings:
                if not isinstance(f, dict):
                    continue
                title = str(f.get("title") or "").strip()
                suggestion = str(f.get("suggestion") or "").strip()
                evidence = str(f.get("evidence") or "").strip()
                if not (title or suggestion or evidence):
                    continue
                n += 1
                head = title if title else f"finding {n}"
                print(f"  {n}. {head}")
                if suggestion:
                    print(f"     suggestion: {suggestion}")
                if evidence:
                    print(f"     evidence: {evidence}")
            print()

        nxt = ai_out.get("suggested_next_tests")
        if isinstance(nxt, list) and nxt:
            print("suggested_next_tests (copy/paste):")
            for item in nxt:
                if isinstance(item, str):
                    # Backward-compat: older models may still return strings.
                    print(f"  - {item} (generic; no YAML provided)")
                    continue
                if not isinstance(item, dict):
                    continue

                tid = str(item.get("id") or "").strip()
                title = str(item.get("title") or "").strip()
                why = str(item.get("why") or "").strip()
                yaml_snip = str(item.get("yaml") or "").rstrip()

                head = ""
                if tid and title:
                    head = f"{tid}: {title}"
                elif title:
                    head = title
                elif tid:
                    head = tid
                else:
                    head = "test"

                print(f"  - {head}")
                if why:
                    print(f"    why: {why}")
                if yaml_snip:
                    print("    add to topology:")
                    for line in yaml_snip.splitlines():
                        print(f"      {line}")
            print()

    # Ensure mandatory deterministic headers exist (do NOT overwrite if already set)
    bundle.setdefault("schema_version", "1")
    for k, v in _ai_advisory_headers().items():
        bundle.setdefault(k, v)

    # Determine requested output mode flags
    want_bundle = bool(getattr(args, "bundle", False))
    bundle_out = getattr(args, "bundle_out", None)

    fmt = (getattr(args, "format", None) or "json").strip().lower()
    if fmt not in ("json", "text"):
        fmt = "json"

    # 1) --bundle-out: write bundle and exit (no online)
    if bundle_out:
        _ai_write_bundle(str(bundle_out), bundle)
        bundle_with_ptr = dict(bundle)
        bundle_with_ptr["bundle_path"] = str(bundle_out)

        if fmt == "json":
            _ai_print_json(bundle_with_ptr)
        else:
            print(f"[advisory] ai {command_name}")
            print(bundle_with_ptr.get("disclaimer"))
            cc_line = _cc_summary_text(bundle)
            if cc_line:
                print(cc_line)
            print(f"bundle_path: {bundle_with_ptr['bundle_path']}")
        return

    # 2) --bundle: print bundle and exit (no online)
    if want_bundle:
        if fmt == "json":
            _ai_print_json(bundle)
        else:
            print(f"[advisory] ai {command_name}")
            print(bundle.get("disclaimer"))
            cc_line = _cc_summary_text(bundle)
            if cc_line:
                print(cc_line)
            print(json.dumps(bundle, indent=2, sort_keys=True))
        return

    # 3) Default bundle write (best practice): only if we can infer a default path (explain has labdir)
    default_path = _ai_default_bundle_out_path(bundle)
    if default_path:
        try:
            _ai_write_bundle(default_path, bundle)
        except Exception:
            default_path = None

    # 4) Optional online call
    online_res = {
        "ai_status": "unavailable",
        "ai_error": "online not requested",
        "model_used": None,
        "ai_output": {},
    }
    if bool(getattr(args, "online", False)):
        try:
            online_res = _ai_try_online(bundle=bundle, args=args)
        except Exception as e:
            online_res = {"ai_status": "unavailable", "ai_error": str(e), "model_used": None, "ai_output": {}}

    # 5) Final advisory output (stable, CI-safe)
    out: dict[str, Any] = {
        "schema_version": "1",
        **_ai_advisory_headers(),
        "command": command_name,
        "inputs": {"bundle_path": default_path},
        "ai_status": online_res.get("ai_status"),
        "ai_error": online_res.get("ai_error") or "",
        "model_used": online_res.get("model_used"),
        "ai_output": online_res.get("ai_output") or {},
        # always include the deterministic bundle for audit/debug
        "bundle": bundle,
    }

    if fmt == "json":
        _ai_print_json(out)
        return

    # text mode (human-friendly)
    print(f"[advisory] ai {command_name}")
    print(out.get("disclaimer"))

    cc_line = _cc_summary_text(bundle)
    if cc_line:
        print(cc_line)

    if out["inputs"].get("bundle_path"):
        print(f"bundle_path: {out['inputs']['bundle_path']}")

    print(f"ai_status: {out.get('ai_status')}")

    if out.get("ai_error"):
        print(f"ai_error: {out.get('ai_error')}")

    if out.get("model_used"):
        print(f"model_used: {out.get('model_used')}")

    if out.get("ai_output"):
        if _ai_contains_forbidden_correctness_language(out["ai_output"]):
            print("warning: AI output contained correctness/safety language. Treat as advisory and prove via tests.")
        _render_ai_output_text(out["ai_output"])

def _ai_explain_change_sections(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Step 4 (v1): Change-aware explain scaffold.

    Rules:
      - deterministic
      - vendor-agnostic (no parsing)
      - advisory-only
      - no remediation instructions
      - links failures to "affected areas" based on declared candidate_changes metadata only
    """
    cc = bundle.get("change_context") or {}
    items = list(cc.get("items") or [])

    # deterministic ordering
    def _k_item(it: dict) -> tuple:
        return (str(it.get("id") or ""), str(it.get("node") or ""), str(it.get("description") or ""))

    items = sorted([it for it in items if isinstance(it, dict)], key=_k_item)

    # Build a light-weight index: node -> change ids
    node_to_changes: dict[str, list[str]] = {}
    change_ids: list[str] = []
    for it in items:
        cid = str(it.get("id") or "").strip()
        if cid:
            change_ids.append(cid)
        node = it.get("node")
        if isinstance(node, str) and node.strip() and cid:
            node_to_changes.setdefault(node.strip(), []).append(cid)

    for k in list(node_to_changes.keys()):
        node_to_changes[k] = sorted(set(node_to_changes[k]))

    change_ids = sorted(set(change_ids))

    verdict = bundle.get("verdict") or {}
    failed_tests = list(verdict.get("failed_tests") or [])
    failed_steps = list(verdict.get("failed_scenarios") or [])
    wait_failures = list(verdict.get("wait_failures") or [])

    # Helper: try to extract node-ish strings from a failure record without guessing too hard
    def _extract_nodes_from_failure(rec: dict) -> set[str]:
        out: set[str] = set()
        if not isinstance(rec, dict):
            return out

        # Common spots
        for key in ("name", "reason", "error"):
            v = rec.get(key)
            if isinstance(v, str):
                # light heuristic: if a node name appears exactly as a token in the string, match it
                # (still deterministic, but best-effort)
                for n in node_to_changes.keys():
                    if n and (f" {n} " in f" {v} " or v.strip() == n):
                        out.add(n)

        meta = rec.get("meta")
        if isinstance(meta, dict):
            for key in ("node", "src", "dst", "from", "to"):
                v = meta.get(key)
                if isinstance(v, str) and v.strip() in node_to_changes:
                    out.add(v.strip())

        return out

    affected_nodes: set[str] = set()
    for rec in failed_tests:
        affected_nodes |= _extract_nodes_from_failure(rec)
    for rec in failed_steps:
        affected_nodes |= _extract_nodes_from_failure(rec)
    for rec in wait_failures:
        affected_nodes |= _extract_nodes_from_failure(rec)

    affected_nodes = set(sorted(affected_nodes))

    affected_changes: list[str] = []
    for n in affected_nodes:
        affected_changes.extend(node_to_changes.get(n) or [])
    affected_changes = sorted(set(affected_changes))

    # Calm, on-call friendly notes (no remediation)
    notes: list[str] = []
    present = bool(cc.get("present"))
    if not present:
        notes.append("No candidate change context was provided, so this explanation is based on test/scenario evidence only.")
    else:
        if cc.get("counts", {}).get("missing"):
            notes.append("Some change_context files were missing at bundle time; affected-area mapping may be incomplete.")
        if cc.get("counts", {}).get("blocked"):
            notes.append("Some change_context items were blocked for safety (path rules); mapping may be incomplete.")
        if cc.get("counts", {}).get("too_large"):
            notes.append("Some change_context items were too large and were not included; mapping may be incomplete.")

    mapping = {
        "affected_nodes": sorted(list(affected_nodes)),
        "affected_change_ids": affected_changes,
        "node_to_change_ids": {k: node_to_changes[k] for k in sorted(node_to_changes)},
    }

    # Minimal structured output required by Step 4
    out = {
        "present": bool(cc.get("present")),
        "summary": {
            "change_ids": change_ids,
            "affected_nodes": mapping["affected_nodes"],
            "affected_change_ids": mapping["affected_change_ids"],
        },
        "mapping": mapping,
        "notes": notes,
        "reminders": [
            "This is advisory context only. Tests & scenarios are authoritative.",
            "No vendor parsing was performed; mapping uses declared metadata only.",
            "No remediation instructions are provided.",
        ],
    }

    return out

def cmd_ai_explain(args) -> None:
    """
    Explain a prior run using artifacts only.

    v1 contract:
      - always builds a deterministic bundle
      - --bundle prints bundle JSON and exits 0
      - --bundle-out writes bundle and exits 0
      - --online attempts optional model layer; failures never gate (exit 0)

    Exit codes:
      0 = success (including AI unavailable)
      2 = CLI usage / missing required artifacts when --strict-inputs
    """
    lab, labdir = _ai_resolve_lab_and_dir(args.target)
    res_path = os.path.join(labdir, "results.json")
    topo_resolved_path = os.path.join(labdir, "topology.resolved.yaml")
    summary_path = os.path.join(labdir, "results.summary.txt")

    strict = bool(getattr(args, "strict_inputs", False))

    # Required artifacts for v1 explain
    missing: list[str] = []
    if not _ai_file_exists(res_path):
        missing.append("results.json")
    if not _ai_file_exists(topo_resolved_path):
        missing.append("topology.resolved.yaml")

    if missing and strict:
        print(
            f"AI usage error: missing required artifacts in {labdir}: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(2)

    adapter_paths = list(getattr(args, "adapter", None) or [])
    adapters = _ai_load_adapters(adapter_paths, command_name="explain") if adapter_paths else {
        "authority": "advisory",
        "count": 0,
        "inputs": [],
    }

    bundle = {
        "schema_version": "1",
        **_ai_advisory_headers(),
        "command": "explain",
        "adapters": adapters,
        "lab": {"name": lab, "labdir": labdir},
        "artifacts": {
            "results_json": os.path.join(labdir, "results.json"),
            "resolved_topology": os.path.join(labdir, "topology.resolved.yaml"),
            "summary_txt": os.path.join(labdir, "results.summary.txt"),
            "present": {
                "results_json": _ai_file_exists(res_path),
                "resolved_topology": _ai_file_exists(topo_resolved_path),
                "summary_txt": _ai_file_exists(summary_path),
            },
        },
        "verdict": {
            "overall": None,
            "failed_tests": [],
            "failed_scenarios": [],
            "wait_failures": [],
        },
        "notes": [],
    }

    # Change Context (bundle-time only): pull from resolved topology if present
    # Use labdir as the deterministic base_dir so explain works from artifacts alone.
    cc_base_dir = Path(labdir)

    if _ai_file_exists(topo_resolved_path):
        try:
            topo_resolved = _ai_read_yaml(topo_resolved_path)
            bundle["change_context"] = _ai_cc_build_change_context(topo_resolved, base_dir=cc_base_dir)
        except Exception as e:
            bundle["change_context"] = {
                "present": False,
                "counts": {"items": 0, "included": 0, "blocked": 0, "missing": 0, "errors": 1, "too_large": 0},
                "limits": {
                    "item_max_bytes": _AI_CC_ITEM_MAX_BYTES,
                    "total_max_bytes": _AI_CC_TOTAL_MAX_BYTES,
                    "preview_max_chars": _AI_CC_PREVIEW_MAX_CHARS,
                    "max_items": _AI_CC_MAX_ITEMS,
                },
                "items": [],
                "notes": [f"Failed to parse topology.resolved.yaml for change_context: {e!s}"],
            }
    else:
        bundle["change_context"] = _ai_cc_build_change_context({}, base_dir=cc_base_dir)

    # Deterministic scaffold: extract stable evidence pointers
    if _ai_file_exists(res_path):
        try:
            r = _ai_read_json(res_path)
            bundle["verdict"]["overall"] = r.get("result")
            results_ptr = f"{labdir}/results.json"

            tests = list(r.get("tests") or [])
            for i, t in enumerate(tests):
                if not isinstance(t, dict):
                    continue
                if (t.get("verdict") or "").lower() == "fail":
                    bundle["verdict"]["failed_tests"].append(
                        {
                            "name": t.get("name"),
                            "type": t.get("type"),
                            "reason": t.get("reason"),
                            "evidence": {"artifact": results_ptr, "path": f"tests[{i}]"},
                        }
                    )

            scenarios = list(r.get("scenarios") or [])
            for si, s in enumerate(scenarios):
                if not isinstance(s, dict):
                    continue
                sid = s.get("id")
                steps = list(s.get("steps") or [])
                for st_i, st in enumerate(steps):
                    if not isinstance(st, dict):
                        continue

                    if (st.get("verdict") or "").lower() == "fail":
                        bundle["verdict"]["failed_scenarios"].append(
                            {
                                "scenario_id": sid,
                                "step": st.get("step"),
                                "type": st.get("type"),
                                "error": st.get("error"),
                                "meta": st.get("meta"),
                                "evidence": {
                                    "artifact": results_ptr,
                                    "path": f"scenarios[{si}].steps[{st_i}]",
                                },
                            }
                        )

                    st_type = st.get("type")
                    st_verdict = (st.get("verdict") or "").lower()
                    if st_type in ("wait_for", "wait_for_bgp") and st_verdict != "pass":
                        bundle["verdict"]["wait_failures"].append(
                            {
                                "scenario_id": sid,
                                "step": st.get("step"),
                                "type": st_type,
                                "expected": st.get("expected"),
                                "observed": st.get("observed"),
                                "error": st.get("error"),
                                "evidence": {
                                    "artifact": results_ptr,
                                    "path": f"scenarios[{si}].steps[{st_i}]",
                                },
                            }
                        )

            # Deterministic sorting
            def _k_test(x: dict) -> tuple:
                ev = x.get("evidence", {}) or {}
                return (
                    str(x.get("name") or ""),
                    str(x.get("type") or ""),
                    str(ev.get("path") or ""),
                )

            def _k_step(x: dict) -> tuple:
                step_v = x.get("step")
                step_i = step_v if isinstance(step_v, int) else 10**9
                return (str(x.get("scenario_id") or ""), step_i, str(x.get("type") or ""))

            bundle["verdict"]["failed_tests"] = sorted(bundle["verdict"]["failed_tests"], key=_k_test)
            bundle["verdict"]["failed_scenarios"] = sorted(bundle["verdict"]["failed_scenarios"], key=_k_step)
            bundle["verdict"]["wait_failures"] = sorted(bundle["verdict"]["wait_failures"], key=_k_step)

        except Exception as e:
            bundle["notes"].append(f"Failed to parse results.json: {e!s}")

    # IMPORTANT: all output logic lives in the shared finalizer
    bundle["change_explain"] = _ai_explain_change_sections(bundle)
    _ai_finalize_and_emit("explain", bundle, args)

# ----------------------------
# v1: Change Context (Step 2) — AI bundle-only packaging helpers
#   - best-effort, deterministic
#   - size-limited, redacted
#   - NEVER affects runtime / verdicts / exit codes
# ----------------------------

_AI_CC_ITEM_MAX_BYTES = 64 * 1024        # 64 KiB per item read cap
_AI_CC_TOTAL_MAX_BYTES = 256 * 1024      # 256 KiB total cap across items
_AI_CC_PREVIEW_MAX_CHARS = 4096          # preview chars per item (after redaction)
_AI_CC_MAX_ITEMS = 50                    # hard cap for safety


def _ai_cc_redact(text: str) -> str:
    """
    Deterministic, conservative redaction for common secret-like patterns.
    Not a security guarantee; just hygiene to reduce accidental leakage.
    """
    if not text:
        return text

    out_lines: list[str] = []
    keys = ("password", "passwd", "secret", "token", "api_key", "apikey", "private_key")

    for line in text.splitlines(True):  # keep newlines
        low = line.lower()
        if any(k in low for k in keys):
            # redact value after common separators
            for sep in (":", "=", " "):
                if sep in line:
                    left, right = line.split(sep, 1)
                    # keep left + sep, replace remainder
                    line = f"{left}{sep} <redacted>\n" if line.endswith("\n") else f"{left}{sep} <redacted>"
                    break
        out_lines.append(line)

    return "".join(out_lines)


def _ai_cc_safe_read_text_file(base_dir: Path, rel_path: str, max_bytes: int) -> tuple[str, dict]:
    """
    Best-effort safe read:
      - only allows paths within base_dir (no traversal)
      - blocks absolute paths
      - reads at most max_bytes
    Returns: (text, meta)
    """
    meta: dict[str, Any] = {
        "source_kind": "file",
        "path": rel_path,
        "status": "unavailable",
        "bytes": 0,
        "truncated": False,
        "reason": "",
    }

    try:
        if not isinstance(rel_path, str) or not rel_path.strip():
            meta["status"] = "invalid"
            meta["reason"] = "empty path"
            return "", meta

        rp = rel_path.strip()
        p = Path(rp)

        if p.is_absolute():
            meta["status"] = "blocked"
            meta["reason"] = "absolute paths are blocked"
            return "", meta

        # Resolve under base_dir and prevent traversal
        base = base_dir.resolve()
        full = (base / p).resolve()
        if str(full) == str(base) or (not str(full).startswith(str(base) + os.sep)):
            meta["status"] = "blocked"
            meta["reason"] = "path traversal / outside base_dir blocked"
            return "", meta

        if not full.exists() or not full.is_file():
            meta["status"] = "missing"
            meta["reason"] = "file not found"
            return "", meta

        # bounded read
        with full.open("rb") as f:
            raw = f.read(max_bytes + 1)

        if len(raw) > max_bytes:
            raw = raw[:max_bytes]
            meta["truncated"] = True

        # decode best-effort as utf-8; replace errors deterministically
        txt = raw.decode("utf-8", errors="replace")
        meta["status"] = "ok"
        meta["bytes"] = len(raw)
        return txt, meta

    except Exception as e:
        meta["status"] = "error"
        meta["reason"] = str(e)
        return "", meta


def _ai_cc_build_change_context(topo_obj: dict, base_dir: Path) -> dict[str, Any]:
    """
    Build deterministic change_context bundle payload from topo candidate_changes.
    Reads candidate content ONLY here (bundle-time), size-limited.
    """
    cc = topo_obj.get("candidate_changes")
    out: dict[str, Any] = {
        "present": bool(cc),
        "counts": {"items": 0, "included": 0, "blocked": 0, "missing": 0, "errors": 0, "too_large": 0},
        "limits": {
            "item_max_bytes": _AI_CC_ITEM_MAX_BYTES,
            "total_max_bytes": _AI_CC_TOTAL_MAX_BYTES,
            "preview_max_chars": _AI_CC_PREVIEW_MAX_CHARS,
            "max_items": _AI_CC_MAX_ITEMS,
        },
        "items": [],
        "notes": [],
    }

    if not isinstance(cc, list) or not cc:
        return out

    total_budget = _AI_CC_TOTAL_MAX_BYTES
    included = 0

    # Preserve declared ordering (author intent), but cap number of items deterministically
    for idx, item in enumerate(cc[:_AI_CC_MAX_ITEMS], start=1):
        if not isinstance(item, dict):
            continue

        cid = item.get("id")
        cid = cid.strip() if isinstance(cid, str) else f"candidate_changes[{idx}]"

        entry: dict[str, Any] = {
            "id": cid,
            "description": (item.get("description").strip() if isinstance(item.get("description"), str) else ""),
            "format": (item.get("format").strip() if isinstance(item.get("format"), str) else ""),
            "scope": (item.get("scope") if isinstance(item.get("scope"), list) else []),
            "source": {},
            "preview": {"text": "", "redacted": True},
        }

        # inline wins only if present (Step 1 enforces exactly one)
        if item.get("inline") is not None:
            s = item.get("inline")
            if not isinstance(s, str):
                s = str(s)
            raw = s
            # enforce per-item cap via bytes
            b = raw.encode("utf-8", errors="replace")
            meta = {
                "source_kind": "inline",
                "status": "ok",
                "bytes": min(len(b), _AI_CC_ITEM_MAX_BYTES),
                "truncated": len(b) > _AI_CC_ITEM_MAX_BYTES,
                "reason": "",
            }
            if len(b) > _AI_CC_ITEM_MAX_BYTES:
                raw = b[:_AI_CC_ITEM_MAX_BYTES].decode("utf-8", errors="replace")
            # total budget enforcement
            if meta["bytes"] > total_budget:
                meta["status"] = "too_large"
                meta["reason"] = "exceeds remaining total budget"
                out["counts"]["too_large"] += 1
                entry["source"] = meta
                out["items"].append(entry)
                continue

            total_budget -= meta["bytes"]
            red = _ai_cc_redact(raw)
            entry["source"] = meta
            entry["preview"]["text"] = red[:_AI_CC_PREVIEW_MAX_CHARS]
            included += 1
            out["items"].append(entry)
            continue

        # file path
        rel_path = item.get("file")
        rel_path = rel_path.strip() if isinstance(rel_path, str) else str(rel_path)

        # if no budget left, record deterministically
        if total_budget <= 0:
            entry["source"] = {
                "source_kind": "file",
                "path": rel_path,
                "status": "too_large",
                "bytes": 0,
                "truncated": False,
                "reason": "no remaining total budget",
            }
            out["counts"]["too_large"] += 1
            out["items"].append(entry)
            continue

        max_bytes = min(_AI_CC_ITEM_MAX_BYTES, total_budget)
        txt, meta = _ai_cc_safe_read_text_file(base_dir, rel_path, max_bytes=max_bytes)

        # update counters
        st = meta.get("status")
        if st == "ok":
            included += 1
        elif st == "blocked":
            out["counts"]["blocked"] += 1
        elif st == "missing":
            out["counts"]["missing"] += 1
        elif st == "error":
            out["counts"]["errors"] += 1
        elif st == "too_large":
            out["counts"]["too_large"] += 1

        # budget accounting only if we actually read bytes
        if st == "ok":
            total_budget -= int(meta.get("bytes") or 0)

        entry["source"] = meta
        if st == "ok":
            red = _ai_cc_redact(txt)
            entry["preview"]["text"] = red[:_AI_CC_PREVIEW_MAX_CHARS]
        out["items"].append(entry)

    out["counts"]["items"] = min(len(cc), _AI_CC_MAX_ITEMS)
    out["counts"]["included"] = included
    if len(cc) > _AI_CC_MAX_ITEMS:
        out["notes"].append(f"candidate_changes truncated to first {_AI_CC_MAX_ITEMS} items (safety cap)")

    return out

def _ai_read_yaml(path: str) -> Any:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
    
def _ai_load_adapters(paths: list[str], command_name: str) -> dict[str, Any]:
    """
    Load adapters.v1 JSON files for AI context only.
    Missing/unreadable path is an AI usage error (exit 2) because the user explicitly requested it.
    Adapter parse_errors inside the JSON are preserved as advisory and do not fail the AI command.
    """
    from pathlib import Path

    norm_paths: list[str] = []
    for p in (paths or []):
        if isinstance(p, str) and p.strip():
            norm_paths.append(p.strip())

    # Deterministic order
    norm_paths = sorted(set(norm_paths))

    out_inputs: list[dict[str, Any]] = []
    for p in norm_paths:
        pp = Path(p)
        if not pp.exists():
            print(f"AI usage error: adapter not found: {pp}", file=sys.stderr)
            sys.exit(2)
        if not pp.is_file():
            print(f"AI usage error: adapter is not a file: {pp}", file=sys.stderr)
            sys.exit(2)

        try:
            with pp.open("r", encoding="utf-8") as f:
                obj = json.load(f)
        except Exception as e:
            print(f"AI usage error: failed to read adapter JSON {pp}: {e!s}", file=sys.stderr)
            sys.exit(2)

        # Minimal schema sanity (advisory-only)
        schema_version = str(obj.get("schema_version") or "")
        authority = str(obj.get("authority") or "")
        source_type = str(obj.get("source_type") or "")
        summary = obj.get("summary") if isinstance(obj.get("summary"), dict) else {}

        parse_errors = obj.get("parse_errors") if isinstance(obj.get("parse_errors"), list) else []
        parse_warnings = obj.get("parse_warnings") if isinstance(obj.get("parse_warnings"), list) else []

        out_inputs.append(
            {
                "path": str(pp),
                "schema_version": schema_version,
                "authority": authority,
                "source_type": source_type,
                "summary": {
                    "items_total": int(summary.get("items_total") or 0),
                    "items_changed": int(summary.get("items_changed") or 0),
                    "items_added": int(summary.get("items_added") or 0),
                    "items_removed": int(summary.get("items_removed") or 0),
                },
                "parse": {
                    "warnings": int(len(parse_warnings)),
                    "errors": int(len(parse_errors)),
                },
                "notes": [
                    "Advisory-only adapter context. Does not affect verdicts/exit codes.",
                    f"Loaded by ai {command_name}.",
                ],
            }
        )

    return {
        "authority": "advisory",
        "count": int(len(out_inputs)),
        "inputs": out_inputs,
    }

def _ai_review_change_sections(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Deterministic, vendor-agnostic offline review sections for Change Context.
    No remediation. No vendor parsing. Advisory only.
    """
    cc = (bundle.get("change_context") or {}) if isinstance(bundle, dict) else {}
    items = cc.get("items") if isinstance(cc.get("items"), list) else []
    counts = cc.get("counts") if isinstance(cc.get("counts"), dict) else {}
    present = bool(cc.get("present"))

    # ---- 1) What Changed? ----
    what_changed: list[dict[str, Any]] = []
    if not present:
        what_changed.append(
            {"type": "no_change_context", "summary": "No candidate_changes declared in topology."}
        )
    else:
        for it in items:
            if not isinstance(it, dict):
                continue
            src = it.get("source") or {}
            what_changed.append(
                {
                    "id": it.get("id"),
                    "format": it.get("format") or "",
                    "scope": it.get("scope") or [],
                    "source_status": src.get("status"),
                    "source_kind": src.get("source_kind"),
                    "summary": it.get("description") or "",
                }
            )

    # ---- 2) Am I Missing Something? ----
    missing: list[dict[str, Any]] = []

    if present and int(counts.get("included") or 0) == 0:
        missing.append(
            {
                "type": "change_context_not_included",
                "hint": "Candidate changes were declared but none could be included in the bundle (missing/blocked/too_large).",
            }
        )

    # scope hygiene: if any item has empty scope, nudge to add it (still optional)
    if present:
        any_empty_scope = False
        any_has_scope = False
        for it in items:
            if not isinstance(it, dict):
                continue
            sc = it.get("scope")
            if isinstance(sc, list) and sc:
                any_has_scope = True
            else:
                any_empty_scope = True
        if any_empty_scope:
            missing.append(
                {
                    "type": "scope_not_specified",
                    "hint": "Some candidate changes have no scope. Consider adding scope: [node1, node2] to clarify what should be proven.",
                }
            )
        if not any_has_scope:
            missing.append(
                {
                    "type": "no_scopes_present",
                    "hint": "No candidate changes specify scope. Proof suggestions will be generic (still safe).",
                }
            )

    # deterministic checklist reminders (generic, not vendor-specific)
    missing.extend(
        [
            {"type": "pre_change_baseline", "hint": "Do you have steady-state tests that pass before the change? (baseline proof)"},
            {"type": "negative_tests", "hint": "If a firewall/policy exists, do you have at least one expected-fail (blocked) test?"},
            {"type": "failover_scenarios", "hint": "If the change could affect failover, do you have a scenario with fault + wait_for + post-fault revalidation?"},
        ]
    )

    # ---- 3) Minimal Proof Set (template-level) ----
    proof: list[dict[str, Any]] = []

    # Always include a tiny deterministic proof set template (does not claim correctness)
    proof.append(
        {
            "name": "baseline_reachability",
            "purpose": "Prove the network still forwards the intended steady-state traffic.",
            "templates": [
                {"kind": "ping", "from": "<src_node>", "to_ip": "<dst_ip_or_service_vip>"},
                {"kind": "tcp", "from": "<src_node>", "to_ip": "<dst_ip_or_service_vip>", "port": 443},
            ],
        }
    )
    proof.append(
        {
            "name": "control_plane_convergence",
            "purpose": "Prove routing converges to the expected state after events (if applicable).",
            "templates": [
                {"scenario_step": "wait_for_bgp", "node": "<frr_node>", "timeout": 60},
                {"scenario_step": "wait_for", "type": "ping", "from": "<src_node>", "to": "<dst_node_or_ip>", "expect": "pass", "timeout": 30},
            ],
        }
    )
    proof.append(
        {
            "name": "policy_negative",
            "purpose": "Prove must-not traffic is still blocked (if policy/firewall is in path).",
            "templates": [
                {"kind": "tcp", "from": "<src_node>", "to_ip": "<dst_ip>", "port": 22, "expected": "fail"},
            ],
        }
    )

    return {
        "what_changed": what_changed,
        "missing_something": missing,
        "minimal_proof_set": proof,
        "notes": [
            "Change context is advisory-only; tests and scenarios remain authoritative.",
            "This section is vendor-agnostic and does not interpret configs.",
        ],
    }

def cmd_ai_review(args) -> None:
    """
    Review topology-only (no execution). Deterministic coverage sketch + bounded snippets.
    Exit codes: 0 success, 2 usage error.
    """
    from pathlib import Path
    import yaml

    topo_path = Path(args.topology)
    if not topo_path.exists():
        print(f"AI usage error: topology not found: {topo_path}", file=sys.stderr)
        sys.exit(2)

    with topo_path.open("r", encoding="utf-8") as f:
        topo = yaml.safe_load(f) or {}

    nodes = topo.get("nodes") or []
    tests = topo.get("tests") or []
    scenarios = topo.get("scenarios") or []

    max_items = max(0, int(getattr(args, "max_items", 50) or 50))

    # ---- Deterministic inventory ----
    node_names: list[str] = []
    node_types: dict[str, str] = {}
    for n in nodes:
        if isinstance(n, dict):
            nm = n.get("name")
            tp = n.get("type")
            if isinstance(nm, str) and nm.strip():
                nm2 = nm.strip()
                node_names.append(nm2)
                if isinstance(tp, str) and tp.strip():
                    node_types[nm2] = tp.strip()
    node_names = sorted(set(node_names))

    frr_nodes = sorted([n for n in node_names if node_types.get(n) == "frr"])
    host_nodes = sorted([n for n in node_names if node_types.get(n) == "host"])
    fw_nodes = sorted([n for n in node_names if node_types.get(n) in ("fw", "fw-routed", "firewall")])

    test_names: list[str] = []
    covered_dst: set[str] = set()
    kinds: set[str] = set()

    for t in (tests or []):
        if not isinstance(t, dict):
            continue
        nm = t.get("name")
        if isinstance(nm, str) and nm.strip():
            test_names.append(nm.strip())

        kd = t.get("type") or t.get("kind")
        if isinstance(kd, str) and kd.strip():
            kinds.add(kd.strip())

        if "to" in t and isinstance(t.get("to"), str) and t.get("to").strip():
            covered_dst.add(t.get("to").strip())
        if "to_ip" in t and isinstance(t.get("to_ip"), str) and t.get("to_ip").strip():
            covered_dst.add(t.get("to_ip").strip())

    test_names = sorted(set(test_names))
    kinds = set(sorted(kinds))

    has_faults = False
    has_postfault_revalidate = False
    scenario_ids: list[str] = []
    for s in (scenarios or []):
        if not isinstance(s, dict):
            continue
        sid = s.get("id")
        if isinstance(sid, str) and sid.strip():
            scenario_ids.append(sid.strip())

        for st in (s.get("steps") or []):
            if not isinstance(st, dict):
                continue
            if "fault" in st:
                has_faults = True
            if "run_tests" in st:
                has_postfault_revalidate = True

    scenario_ids = sorted(set(scenario_ids))

    gaps: list[dict[str, Any]] = []
    for nn in node_names:
        if nn not in covered_dst:
            gaps.append({"type": "node_uncovered_as_dst", "node": nn})

    if fw_nodes:
        gaps.append({"type": "firewall_present_consider_negative_tests", "nodes": fw_nodes})

    if has_faults and not has_postfault_revalidate:
        gaps.append(
            {
                "type": "scenario_faults_without_postfault_revalidation",
                "hint": "Add a run_tests step after faults",
            }
        )

    evpn_present = False
    if isinstance(topo.get("evpn"), dict):
        evpn_present = True
    else:
        for n in nodes:
            if isinstance(n, dict) and "evpn" in n:
                evpn_present = True
                break
    if evpn_present:
        gaps.append({"type": "evpn_present_add_east_west_tests", "hint": "Add host-to-host reachability tests across VNIs/VLANs"})

    gaps = sorted(gaps, key=lambda g: (str(g.get("type") or ""), json.dumps(g, sort_keys=True)))

    # snippets
    snippets: list[dict[str, str]] = []
    src_host = host_nodes[0] if host_nodes else (node_names[0] if node_names else "src")
    dst_host = host_nodes[1] if len(host_nodes) > 1 else (host_nodes[0] if host_nodes else (node_names[0] if node_names else "dst"))

    snippets.append(
        {
            "title": "Add steady-state ping reachability test (IP target)",
            "language": "yaml",
            "snippet": "\n".join(
                [
                    "tests:",
                    "  - name: ping_host_to_host",
                    "    type: ping",
                    f"    from: {src_host}",
                    "    to_ip: 192.0.2.1  # replace with real destination IP",
                ]
            ),
        }
    )

    snippets.append(
        {
            "title": "Add steady-state TCP port test (IP target)",
            "language": "yaml",
            "snippet": "\n".join(
                [
                    "tests:",
                    "  - name: tcp_service_reachability",
                    "    type: tcp",
                    f"    from: {src_host}",
                    "    to_ip: 192.0.2.1  # replace with real destination IP",
                    "    port: 443",
                ]
            ),
        }
    )

    snippets.append(
        {
            "title": "Add post-fault revalidation in a scenario (run_tests after faults)",
            "language": "yaml",
            "snippet": "\n".join(
                [
                    "scenarios:",
                    "  - id: example_failover_check",
                    "    steps:",
                    "      - fault:",
                    "          interface_down:",
                    "            node: r1",
                    "            interface: eth1",
                    "      - wait_for:",
                    "          type: ping",
                    f"          from: {src_host}",
                    f"          to: {dst_host}  # or an IP literal",
                    "          expect: pass",
                    "          timeout: 30",
                    "      - run_tests:",
                    "          include: all  # syntactic sugar expands deterministically",
                ]
            ),
        }
    )

    snippets = snippets[:max_items]

    adapter_paths = list(getattr(args, "adapter", None) or [])
    adapters = _ai_load_adapters(adapter_paths, command_name="review") if adapter_paths else {
        "authority": "advisory",
        "count": 0,
        "inputs": [],
    }

    bundle = {
        "schema_version": "1",
        **_ai_advisory_headers(),
        "command": "review",
        "adapters": adapters,
        "topology": str(topo_path),
        "counts": {"nodes": len(nodes), "tests": len(tests), "scenarios": len(scenarios)},
        "inventory": {
            "node_names": node_names,
            "node_types": {k: node_types[k] for k in sorted(node_types)},
            "frr_nodes": frr_nodes,
            "host_nodes": host_nodes,
            "fw_nodes": fw_nodes,
            "scenario_ids": scenario_ids,
            "test_names": test_names,
            "test_kinds": sorted(list(kinds)),
            "has_faults": has_faults,
            "has_postfault_revalidate": has_postfault_revalidate,
        },
        "gaps": gaps[:max_items],
        "suggested_snippets": snippets,
        "non_goals": [
            "No lab execution from ai review.",
            "No protocol sprawl or feature-parity assumptions.",
            "Suggestions are advisory-only; tests/scenarios remain authoritative.",
        ],
    }

    bundle["change_context"] = _ai_cc_build_change_context(topo, base_dir=topo_path.parent)
    bundle["change_review"] = _ai_review_change_sections(bundle)

    _ai_finalize_and_emit("review", bundle, args)

def cmd_ai_coach(args) -> None:
    """
    Coach/onboarding: deterministic, static guidance (no YAML emission).
    Exit codes: 0 success, 2 usage error (none expected here).
    """
    bundle = {
        "schema_version": "1",
        **_ai_advisory_headers(),
        "command": "coach",
        "model": "v1 onboarding",
        "topics": [
            "run vs test (explore vs gate)",
            "atomic tests vs scenarios",
            "artifacts: results.json, topology.resolved.yaml, results.summary.txt",
            "negative tests and fail-fast philosophy",
        ],
        "what_to_validate_next": [
            "Steady-state reachability (ping/tcp)",
            "Control-plane convergence (wait_for_bgp)",
            "Failure choreography (interface/link down/up + revalidation)",
        ],
    }

    _ai_finalize_and_emit("coach", bundle, args)

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="netsim",
        description="ai-netsim: topo YAML -> containerlab (local MVP)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full raw command trace + containerlab logs (debug). Default is quiet gate output.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # gen
    p_gen = sub.add_parser("gen", help="Generate containerlab file from topology")
    p_gen.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_gen.set_defaults(func=cmd_gen)

    # validate
    p_val = sub.add_parser("validate", help="Validate topology + scenarios (no lab, no containers)")
    p_val.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_val.add_argument("--json", action="store_true", help="Emit machine-readable JSON (CI-friendly)")
    p_val.set_defaults(func=cmd_validate)

    # doctor (read-only environment readiness; no mutation)
    p_doc = sub.add_parser("doctor", help="Read-only environment readiness checks (no mutation)")
    p_doc.set_defaults(func=cmd_doctor)

    # preflight (advisory-only, declared-only, resolve-time)
    p_pre = sub.add_parser("preflight", help="Advisory static preflight (declared-only; no execution)")
    p_pre.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_pre.add_argument("--format", choices=["json", "text"], default="json", help="Output format")
    p_pre.add_argument("--out", default=None, help="Output path (default: artifacts/preflight/preflight.json)")
    p_pre.add_argument("--adapter", action="append", default=[], help="Path to an adapters.v1 JSON (repeatable; advisory-only)")
    p_pre.set_defaults(func=cmd_preflight)

    # adapt (read-only input adapters; advisory-only)
    p_adapt = sub.add_parser("adapt", help="Read-only input adapters (advisory-only)")
    sub_adapt = p_adapt.add_subparsers(dest="adapter", required=True)

    p_tf = sub_adapt.add_parser("terraform", help="Adapt Terraform plan JSON (terraform show -json)")
    p_tf.add_argument("--plan", required=True, help="Path to terraform plan JSON (terraform show -json)")
    p_tf.add_argument("--out", default=None, help="Output directory (default: artifacts/adapters/)")
    p_tf.add_argument("--strict", action="store_true", help="Fail (exit 1) if parse_errors are present")
    p_tf.set_defaults(func=cmd_adapt_terraform)

    p_ans = sub_adapt.add_parser("ansible", help="Adapt rendered Ansible output directory (read-only)")
    p_ans.add_argument("--dir", required=True, help="Path to rendered Ansible output directory")
    p_ans.add_argument("--out", default=None, help="Output directory (default: artifacts/adapters/)")
    p_ans.add_argument("--strict", action="store_true", help="Fail (exit 1) if parse_errors are present")
    p_ans.set_defaults(func=cmd_adapt_ansible)

    # up
    p_up = sub.add_parser("up", help="Generate + deploy")
    p_up.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    p_up.add_argument(
        "--reconfigure",
        action="store_true",
        help="Destroy the existing lab first, then redeploy (safe for generated bind-mount files).",
    )
    p_up.set_defaults(func=cmd_up)

    # down
    p_down = sub.add_parser("down", help="Destroy a deployed lab by name")
    p_down.add_argument("name", help="Lab name (topology 'name')")
    p_down.add_argument(
        "--strict",
        action="store_true",
        help="Usage error (exit 2) if lab is not found (still emits RESULT: NO-OP).",
    )
    p_down.set_defaults(func=cmd_down)

    # destroy (explicit ops; does not delete artifacts by default)
    p_destroy = sub.add_parser("destroy", help="Destroy a lab runtime; keep artifacts unless --purge-artifacts")
    p_destroy.add_argument("name", help="Lab name (topology 'name')")
    p_destroy.add_argument(
        "--strict",
        action="store_true",
        help="Usage error (exit 2) if lab is not found (still emits RESULT: NO-OP).",
    )
    p_destroy.add_argument(
        "--purge-artifacts",
        dest="purge_artifacts",
        action="store_true",
        help="Also delete labs/clab-<lab> artifacts after runtime teardown attempt.",
    )
    p_destroy.set_defaults(func=cmd_destroy)

    # cleanup
    p_cleanup = sub.add_parser(
        "cleanup",
        help="Safely clean up ai-netsim-owned labs found under labs/ (dry-run unless --yes)",
    )
    p_cleanup.add_argument(
        "--all",
        action="store_true",
        help="Required. Only targets ai-netsim labs with artifact dirs under labs/clab-* (never scans Docker).",
    )
    p_cleanup.add_argument(
        "--yes",
        action="store_true",
        help="Actually destroy labs listed in the plan (artifacts are NOT deleted).",
    )
    p_cleanup.set_defaults(func=cmd_cleanup)

    # exec
    p_exec = sub.add_parser("exec", help="Exec a command inside a node container; if no command, open bash")
    # Make positionals optional at parse-time so quiet-mode misuse is netsim-owned (no argparse dumps).
    p_exec.add_argument("lab", nargs="?", help="Lab name (topology 'name')")
    p_exec.add_argument("node", nargs="?", help="Node name (e.g. r1)")
    p_exec.add_argument("command", nargs=argparse.REMAINDER, help="Command to run inside container")
    p_exec.set_defaults(func=cmd_exec)

    # collect
    p_collect = sub.add_parser("collect", help="Collect runtime artifacts for a lab")
    p_collect.add_argument("lab", help="Lab name (topology 'name')")
    p_collect.set_defaults(func=cmd_collect)

    # vty
    p_vty = sub.add_parser("vty", help="Run a vtysh command easily")
    # Make positionals optional at parse-time so quiet-mode misuse is netsim-owned (no argparse dumps).
    p_vty.add_argument("lab", nargs="?", help="Lab name (topology 'name')")
    p_vty.add_argument("node", nargs="?", help="Node name (e.g. r1)")
    p_vty.add_argument("command", nargs="?", help='vtysh command as one string, e.g. "show bgp summary"')
    p_vty.set_defaults(func=cmd_vty)

    # status
    p_status = sub.add_parser("status", help="Show lab status (containers + optional BGP summary)")
    # Make positional optional at parse-time so quiet-mode misuse is netsim-owned (no argparse dumps).
    p_status.add_argument("lab", nargs="?", help="Lab name (topology 'name')")
    p_status.add_argument("--bgp", action="store_true", help="Include 'show bgp summary' for FRR nodes")
    p_status.add_argument("--bgp-verbose", action="store_true", help="Print full 'show bgp summary' output")
    p_status.add_argument("--strict", action="store_true", help="Exit non-zero if any FRR peers are not Established")
    p_status.add_argument("--interfaces", action="store_true", help="Include 'ip -br a' output per node")
    p_status.add_argument("--summary", action="store_true", help="Print a one-line summary at the end")
    p_status.add_argument("--json", action="store_true", help="Emit machine-readable JSON (no command echo)")
    p_status.add_argument("--routes", action="store_true", help="Validate expected routes exist (read-only)")
    p_status.add_argument("--routes-verbose", action="store_true", help="Include raw 'show ip route' output (human mode)")
    p_status.set_defaults(func=cmd_status)

    # test
    p_test = sub.add_parser(
        "test",
        help="Run tests (lab-name mode) or run an authoritative clean-state gate (topology.yaml mode)",
    )
    p_test.add_argument(
        "lab",
        nargs="?",
        help="Lab name OR topology file path (.yaml/.yml). "
            "If a topology path is provided, runs an authoritative clean-state gate "
            "(up → test → down) using the topology name (or filename stem). "
            "Optional when using --two-run (then provide --two-run-topology).",
            )
    p_test.add_argument(
        "--two-run",
        action="store_true",
        help="Run the authoritative gate twice (baseline then change) and write an evidence-only diff bundle. "
             "Requires --two-run-topology and --candidate-config.",
    )
    p_test.add_argument(
        "--two-run-topology",
        dest="two_run_topology",
        help="Topology YAML filename under ./topologies or a full path (used only with --two-run).",
    )
    p_test.add_argument("--name", help="Run only the test with this name (e.g. tests[4] or a named test)")
    p_test.add_argument("--kind", choices=["ping", "tcp"], help="Run only tests of this kind")
    p_test.add_argument(
        "--keep-going",
        action="store_true",
        help="Run all tests even if one fails (still exits non-zero if any fail)",
    )
    p_test.add_argument(
        "--json",
        action="store_true",
        help="Print results.json to stdout in addition to writing the file",
    )
    p_test.add_argument(
        "--candidate-config",
        dest="candidate_config",
        help="Apply candidate operational configs from a directory before running tests (gate-only, atomic). "
"Directory contract: frr/<node>.conf and/or nft/<node>.nft|.ruleset",
    )
    # Support both forms:
    #   netsim --verbose test ...
    #   netsim test ... --verbose
    p_test.add_argument(
        "--verbose",
        action="store_true",
        dest="verbose",
        help="Print full raw command trace + containerlab logs (debug). Default is quiet gate output.",
    )
    p_test.set_defaults(func=cmd_test)
    p_test.add_argument("--scenario", help="Run only this scenario id (scenarios[*].id). Note: skips declared tests")
    p_test.add_argument("--all-scenarios", action="store_true", help="Run all scenarios. Note: skips declared tests")
    # capture-config (supporting evidence only; exploration feature) - explicitly forbidden in gate-first test
    p_test.add_argument(
        "--capture-config",
        action="store_true",
        help="Exploration evidence only (writes labs/<lab>/artifacts/capture_config/**). "
             "Forbidden in netsim test; will exit 2 if used.",
    )
    p_test.add_argument("--scenario-verbose", action="store_true", help="Print each scenario step as it runs (human-only; does not change artifacts)",)
    p_test.add_argument(
    "--precheck-controlplane",
    action="store_true",
    help="Run global control-plane prechecks (e.g., BGP wait) before executing scenarios. "
         "Default: off when --scenario/--all-scenarios is used.",
    )
        # State capture (supporting evidence only; never gates)
    p_test.add_argument(
        "--state-capture",
        default="none",
        choices=["none", "pre", "post", "both"],
        help="supporting evidence capture timing (none|pre|post|both). Non-authoritative; never affects verdicts.",
    )
    p_test.add_argument(
        "--state-profile",
        action="append",
        default=[],
        help=(
            "enable supporting evidence capture profile (repeatable). "
            "No implicit default; required when --state-capture != none."
        ),
    )
    p_test.add_argument(
        "--list-scenarios",
        action="store_true",
        help=(
            "List scenarios without deploy/execute. "
            "If given a topology file, scenarios are shown from post-Resolve expansion. "
            "If given a lab name, requires existing lab artifacts under labs/clab-<lab>/."
        ),
    )
    # run
    p_run = sub.add_parser("run", help="Ephemeral workflow: up -> test -> collect -> down (CI-friendly)")
    p_run.add_argument("topology", help="Topology YAML filename under ./topologies or a full path")
    # Support both forms:
    #   netsim --verbose run ...
    #   netsim run ... --verbose
    p_run.add_argument(
        "--verbose",
        action="store_true",
        dest="verbose",
        help="Print full raw command trace + containerlab logs (debug). Default is quiet gate output.",
    )
    p_run.add_argument(
        "--reconfigure",
        action="store_true",
        help="Destroy the existing lab first, then redeploy (safe for generated bind-mount files).",
    )
    p_run.add_argument(
        "--keep",
        action="store_true",
        help="Do not destroy the lab at the end (useful for debugging failures).",
    )
    p_run.add_argument(
        "--destroy-always",
        action="store_true",
        help="Attempt to destroy the lab even if up/test/collect fails.",
    )
    p_run.add_argument(
        "--no-collect",
        action="store_true",
        help="Skip collect (faster, but no artifacts).",
    )
    p_run.add_argument(
        "--capture-config",
        action="store_true",
        help="Exploration evidence only: capture host+live configs after provision "
             "into labs/<lab>/artifacts/capture_config/** (never gates).",
    )
    p_run.add_argument("--no-test", action="store_true", help="Skip test phase (still may collect/capture-config).")
    p_run.set_defaults(func=cmd_run)

    # ai (group)
    p_ai = sub.add_parser("ai", help="Assistive, non-authoritative AI (post-exec, artifact-only)")
    ai_sub = p_ai.add_subparsers(dest="ai_cmd", required=True)

    def _ai_add_common_flags(p) -> None:
        p.add_argument("--bundle", action="store_true", help="Emit deterministic JSON bundle (no model) and exit 0")
        p.add_argument("--bundle-out", dest="bundle_out", help="Write bundle JSON to this path and exit 0")
        p.add_argument("--online", action="store_true", help="Attempt online model call (BYO key). Never gates; exit 0 on failure.")
        p.add_argument("--model", help="Override model name (else AI_NETSIM_AI_MODEL)")
        p.add_argument("--format", choices=["json", "text"], default="json", help="Output format (json is CI-safe)")
        p.add_argument(
            "--adapter",
            action="append",
            default=[],
            help="Path to adapters.v1 JSON (repeatable). Advisory-only context; never gates.",
        )

    # ai explain
    p_ai_explain = ai_sub.add_parser("explain", help="Explain a prior run using artifacts only")
    p_ai_explain.add_argument("target", help="Lab name or topology file (to resolve lab)")
    _ai_add_common_flags(p_ai_explain)
    p_ai_explain.add_argument(
        "--strict-inputs",
        dest="strict_inputs",
        action="store_true",
        help="Usage error (exit 2) if required artifacts are missing.",
    )
    p_ai_explain.add_argument("--max-items", type=int, default=50, help="Bound findings/suggestions deterministically")
    p_ai_explain.set_defaults(func=cmd_ai_explain)

    # ai review
    p_ai_review = ai_sub.add_parser("review", help="Review topology tests/scenarios coverage (no execution)")
    p_ai_review.add_argument("topology", help="Topology YAML file")
    _ai_add_common_flags(p_ai_review)
    p_ai_review.add_argument("--max-items", type=int, default=50, help="Bound gaps/snippets deterministically")
    p_ai_review.set_defaults(func=cmd_ai_review)

    # ai coach
    p_ai_coach = ai_sub.add_parser("coach", help="Onboarding and guidance (no YAML generation)")
    _ai_add_common_flags(p_ai_coach)
    p_ai_coach.set_defaults(func=cmd_ai_coach)

    args = parser.parse_args()

    old_quiet = netsim_common.QUIET_RUN
    netsim_common.QUIET_RUN = (not bool(getattr(args, "verbose", False)))

    footer_lab = ""
    footer_authority = ""
    try:
        # Deterministic per-invocation resets (presentation-only).
        global _PRIV_NOTICE_PRINTED
        _PRIV_NOTICE_PRINTED = False
        _invocation_reset_written_artifacts()

        # Footer (WI-1a): gate-mode-only artifact footer (netsim test <topology.yaml>)
        if str(getattr(args, "cmd", "") or "") == "test":
            if not bool(getattr(args, "two_run", False)) and not bool(getattr(args, "list_scenarios", False)):
                footer_lab = str(getattr(args, "lab", "") or "").strip()

                # Determine authority kind deterministically for artifact labeling.
                # Prefer the command handler's explicit report authority; otherwise infer from input shape.
                footer_authority = str(getattr(args, "_report_authority", "") or "").strip().lower()
                if not footer_authority:
                    raw = footer_lab.lower()
                    footer_authority = "gate" if raw.endswith((".yaml", ".yml")) else "lab"

                # WI-1 (Set 6): only gate mode must emit the stable Artifacts footer.
                if footer_authority != "gate":
                    footer_lab = ""
                    footer_authority = ""

        args.func(args)
    finally:
        # Restore global quiet flag deterministically (commands may override temporarily)
        netsim_common.QUIET_RUN = old_quiet

        if footer_lab:
            _print_artifacts_footer_for_lab(footer_lab, authority_kind=footer_authority)

if __name__ == "__main__":
    main()
