from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

from cassian_common import die
from cassian_artifacts import lab_dir, load_yaml, node_cfg_dir
from cassian_runtime_container import Runtime

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
    from cassian import _sanitize_text, _truncate
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
    from cassian import _sha256_file
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

STATE_CAPTURE_SCHEMA = "state_capture.v1"
STATE_CAPTURE_PLAN_VERSION = "1.0.0"

# Deterministic truncation for state outputs (bytes)
_STATE_CAPTURE_MAX_BYTES = 64 * 1024  # 65536

# Built-in profiles (LOCKED list — expanded under Phase 1a §4.5)
# Each command is argv (no shell). Default deny everywhere else.
STATE_CAPTURE_PROFILES: dict[str, dict] = {
    # FRR
    "frr-routing-basic": {
        "node_types": ["frr"],
        "commands": [
            ["vtysh", "-c", "show ip route json"],
            ["vtysh", "-c", "show ipv6 route json"],
        ],
    },
    "frr-bgp-basic": {
        "node_types": ["frr"],
        "commands": [
            ["vtysh", "-c", "show bgp summary json"],
            ["vtysh", "-c", "show bgp neighbors json"],
            ["vtysh", "-c", "show bgp ipv4 unicast json"],
        ],
    },
    "frr-ospf-basic": {
        "node_types": ["frr"],
        "commands": [
            ["vtysh", "-c", "show ip ospf neighbor json"],
            ["vtysh", "-c", "show ip ospf interface json"],
            ["vtysh", "-c", "show ip ospf database json"],
        ],
    },
    "frr-interfaces-basic": {
        "node_types": ["frr"],
        "commands": [
            ["ip", "-j", "link", "show"],
            ["ip", "-j", "addr", "show"],
        ],
    },
    "frr-comprehensive": {
        "node_types": ["frr"],
        "commands": [
            ["vtysh", "-c", "show ip route json"],
            ["vtysh", "-c", "show ipv6 route json"],
            ["vtysh", "-c", "show bgp summary json"],
            ["vtysh", "-c", "show bgp neighbors json"],
            ["vtysh", "-c", "show bgp ipv4 unicast json"],
            ["vtysh", "-c", "show ip ospf neighbor json"],
            ["vtysh", "-c", "show ip ospf interface json"],
            ["vtysh", "-c", "show ip ospf database json"],
            ["ip", "-j", "link", "show"],
            ["ip", "-j", "addr", "show"],
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
            "Use one or more: --state-profile <n>",
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
    from cassian import _safe_stdio, _sanitize_text
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
