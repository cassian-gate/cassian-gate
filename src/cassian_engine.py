from __future__ import annotations

import selectors
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import cassian_common
from cassian_common import BASE_DIR, LABS_DIR, TOPO_DIR, die
from cassian_artifacts import lab_dir, load_yaml

import argparse
import json
import shutil

from cassian_artifacts import write_file
from cassian_model import (
    ensure_valid_topology,
    resolve_topology,
    validate_contrib_path,
    adapt_terraform_plan_json,
    adapt_ansible_rendered_dir,
)
from cassian_tests import (
    validate_scenarios,
    _preflight_default_out,
    _preflight_load_adapters,
    _preflight_report,
    _preflight_format_text,
)
from cassian_runtime_container import (
    write_containerlab_file,
    build_coverage_model,
    write_coverage_artifact,
)

import re

import yaml

from cassian_common import assert_vm_runtime_supported, run
from cassian_artifacts import topo_path_for_lab
from cassian_state import _capture_config_run_exploration
from cassian_runtime_container import (
    get_runtime,
    parse_lab_nodes,
    list_owned_labs_from_artifacts,
    lab_file_from_name,
    configure_frr_interfaces_from_topology,
    configure_hosts_from_topology,
    configure_nftfw_from_topology,
    evpn_leaf_setup_vxlan_from_topology,
    fw_next_hops_from_links,
    gen_nft_fw_rules,
    nft_fw_apply,
    compare_expected_vs_observed_prefixes,
)
from cassian_tests import (
    parse_frr_show_ip_route_prefixes,
    parse_frr_bgp_summary_neighbors,
    parse_frr_bgp_summary_neighbors_json,
    parse_frr_show_ip_route_prefixes_json,
    compare_expected_vs_observed_bgp,
    verify_fw_routed_ready,
    derive_expected_bgp_neighbors_from_links,
    derive_expected_routes_for_frr,
    configure_nftfw_routes_from_topology,
)

import hashlib
import ipaddress
import time

from cassian_common import fail, is_ip_literal, validate_ip_literal
from cassian_artifacts import write_json_canonical
from cassian_state import (
    _state_capture_expand_plan_or_die,
    _state_capture_run_plan,
    _state_capture_write_plan,
)
from cassian_candidate import (
    _candidate_apply_frr_generated_only,
    _candidate_apply_nft,
    _candidate_artifacts_dir,
    _candidate_parse_dir_or_die,
    _write_candidate_apply_artifact,
)
from cassian_two_run import _cmd_test_two_run
from cassian_runtime_container import _normalize_prefix, verify_lab_ready
from cassian_model import build_node_links
from cassian_tests import (
    ensure_nc,
    node_first_ipv4,
    render_gate_result_block,
    resolve_dst_to_ip,
    retry_until,
    run_tcp_test,
    start_tcp_listener,
    validate_scenario_run_refs_or_die,
    wait_for_bgp,
    write_test_summary_artifact,
)

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
    - Verbose: preserve current raw streaming behavior (delegates to cassian_common.run).
    """
    # Verbose mode: stream containerlab stdout/stderr, filtering only known non-fatal banners.
    # Command echo must remain transparent.
    if not cassian_common.QUIET_RUN:
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


_CANDIDATE_STDIO_TRUNC = 8_000  # must match previous value exactly

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

def _command_uses_workspace_labs(cmd: str) -> bool:
    return str(cmd or "").strip() in {
        "up",
        "down",
        "status",
        "exec",
        "vty",
        "collect",
        "test",
        "run",
        "gen",
        "cleanup",
    }

def _bind_workspace_labs_dir(workspace: Path) -> None:
    labs_dir = Path(workspace) / "labs"
    cassian_common.LABS_DIR = labs_dir
    globals()["LABS_DIR"] = labs_dir

    import cassian_artifacts as _cassian_artifacts
    import cassian_runtime_container as _cassian_runtime_container

    _cassian_artifacts.LABS_DIR = labs_dir
    _cassian_runtime_container.LABS_DIR = labs_dir

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

        # WI-5: Never resolve topology-path footer inputs unless this invocation
        # actually wrote artifact files. This avoids a second owned invalid-input
        # emission on malformed-YAML gate failures where no footer can be printed.
        w = [str(x).replace("\\", "/") for x in (_INVOCATION_WRITTEN_ARTIFACTS or [])]
        wrote_json = any(s.endswith("/results.json") or s.endswith("results.json") for s in w)
        wrote_sum = any(s.endswith("/results.summary.txt") or s.endswith("results.summary.txt") for s in w)

        # Default: assume caller gave us a lab name or a labs/* path.
        adir: Path | None = None

        # If it's already a labs/clab-* dir, use it as-is.
        if raw.startswith("labs/") or raw.startswith("labs\\"):
            adir = raw_path

        # If it looks like a topology path (examples/foo.yaml), resolve to lab name and
        # print labs/clab-<labname>/...
        if wrote_json or wrote_sum:
            if adir is None and ("/" in raw or "\\" in raw or dname_l.endswith((".yaml", ".yml"))):
                try:
                    topo = load_topology_yaml(raw)
                    lab_name = str(topo.get("name") or Path(raw).stem).strip()
                    if lab_name:
                        adir = lab_dir(lab_name)  # from netsim_artifacts.py
                except SystemExit:
                    # WI-5: do not re-emit owned invalid-input errors during final footer rendering.
                    # If topology loading already failed earlier in the invocation, suppress footer resolution only.
                    adir = None
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

            if is_gate:
                rel_root = rel_labs(adir).replace("\\", "/")
                if not rel_root.endswith("/"):
                    rel_root += "/"
                print(f"Artifacts: {rel_root}")
                print("  - topology.resolved.yaml (generated execution model used for execution; non-authoritative)")
                print("  - results.json (authoritative verdict artifact)")
                print("  - results.summary.txt (human-readable summary only; non-authoritative)")
            else:
                print("Artifacts:")
                if wrote_json:
                    print(f"* {rel_labs(p_json)} (authoritative verdict artifact)")
                if wrote_sum:
                    print(f"* {rel_labs(p_sum)} (human-readable summary only; non-authoritative)")
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

    # module-global flag used by die() (moved to cassian_common)

    want_json: bool = bool(getattr(args, "json", False))
    contrib_path_arg = getattr(args, "contrib_path", None)

    if contrib_path_arg is not None:
        contrib_path = Path(str(contrib_path_arg))
        prev_quiet = bool(getattr(cassian_common, "_QUIET_DIE", False))
        cassian_common._QUIET_DIE = want_json
        try:
            validate_contrib_path(contrib_path)
            if want_json:
                payload = {
                    "command": "validate-contrib",
                    "result": "pass",
                    "error": "",
                    "schema_version": "1",
                    "path": str(contrib_path),
                }
                print(json.dumps(payload, indent=2, sort_keys=True))
                return
            return
        except SystemExit as e:
            raw_code = e.code
            code = raw_code if isinstance(raw_code, int) else 2
            msg = str(e).strip() or "contrib validation failed"
            if code == 1:
                code = 2
            if want_json:
                payload = {
                    "command": "validate-contrib",
                    "result": "fail",
                    "error": msg,
                    "schema_version": "1",
                    "path": str(contrib_path),
                }
                print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
            else:
                print(f"ERROR: {msg}", file=sys.stderr)
            raise SystemExit(code)
        finally:
            cassian_common._QUIET_DIE = prev_quiet

    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)

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

    prev_quiet = bool(getattr(cassian_common, "_QUIET_DIE", False))
    cassian_common._QUIET_DIE = want_json
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
        # v2-validate-scope-clarity (text mode only)
        print("Validated: topology schema + resolve + scenarios (no deploy, no runtime, no tests).")
        lab = str(resolved.get("name") or "").strip()
        if lab:
            print(f"Advisory: wrote coverage to labs/clab-{lab}/artifacts/coverage/coverage.json")
        return  # do not fall through

    except SystemExit as e:
        # In --json mode, die() may raise either SystemExit(<message>) or SystemExit(<code>).
        raw_code = e.code
        code = raw_code if isinstance(raw_code, int) else 2
        msg = str(e).strip() or "validation failed"
        if code == 1:
            code = 2
        if want_json:
            emit("fail", msg)
        raise SystemExit(code)

    except Exception as e:
        msg = str(e).strip() or "validation failed"
        if want_json:
            emit("fail", msg)
            raise SystemExit(1)

        # Set C: netsim-owned failure surface. Never print Python tracebacks by default.
        die(msg)

    finally:
        cassian_common._QUIET_DIE = prev_quiet

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
        ("nft-fw image present", "ghcr.io/cassian-gate/nft-fw:latest"),
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
            from cassian_artifacts import write_json_canonical
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

# Privilege transparency notice (v2-privilege-transparency-notice)
# Presentation-only: deterministic; must not probe; must not affect exit codes.
_PRIV_NOTICE_PRINTED = False

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

RESULTS_SCHEMA = "results.v1"
RESULTS_SCHEMA_VERSION = "1.0.0"

# Frozen byte ceiling for a single invariant test record's observed_state.
# When canonical JSON serialization exceeds this ceiling,
# _observed_state_truncate deterministically suffix-drops list-tail entries
# from the longest list field (alpha tie-break on key) until the
# serialization fits.
_OBSERVED_STATE_MAX_BYTES = 8192


def _observed_state_serialized_bytes(state: dict) -> int:
    """
    Canonical byte count for a single observed_state payload.

    Mirrors cassian_artifacts.write_json_canonical's serialization policy at
    the object level (sort_keys=True, ensure_ascii=False, indent=2) so that
    truncation decisions track the on-disk size closely.
    """
    try:
        s = json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False)
    except Exception:
        return 0
    return len(s.encode("utf-8", errors="replace"))


def _observed_state_truncate(state: dict) -> tuple[bool, int]:
    """
    Deterministic suffix-drop truncation for a single observed_state payload.

    Returns (truncated, original_bytes).

    Algorithm:
      - Compute pre-truncation canonical byte count.
      - If <= _OBSERVED_STATE_MAX_BYTES, return (False, original_bytes).
      - Otherwise, repeatedly drop the trailing entry of the longest list
        field (ties broken alphabetically by key) until the serialization
        fits or no droppable list-tail entry remains. Required keys are
        never removed; only list contents are shortened.
    """
    original = _observed_state_serialized_bytes(state)
    if original <= _OBSERVED_STATE_MAX_BYTES:
        return False, original

    while _observed_state_serialized_bytes(state) > _OBSERVED_STATE_MAX_BYTES:
        candidates = [
            (k, v) for k, v in state.items()
            if isinstance(v, list) and len(v) > 0
        ]
        if not candidates:
            break
        candidates.sort(key=lambda kv: (-len(kv[1]), str(kv[0])))
        longest_key = candidates[0][0]
        state[longest_key] = state[longest_key][:-1]

    return True, original


def _observed_state_finalize_in_results(results: dict) -> None:
    """
    Collect-time observed_state stabilization (additive-only).

    Hard rules:
      - never alter verdict
      - never alter the existing 'observed' string field
      - never alter any other existing record field
      - strip observed_state from passing invariant records
      - strip observed_state from non-invariant records (defensive)
      - apply deterministic suffix-drop truncation when present payload
        exceeds _OBSERVED_STATE_MAX_BYTES

    Emits 'observed_state_truncated' (bool) and
    'observed_state_truncation_original_bytes' (int) only when truncation
    actually occurred. Never emits these flags otherwise.
    """
    if not isinstance(results, dict):
        return

    def _stabilize_record(rec: dict) -> None:
        if not isinstance(rec, dict):
            return

        kind = str(rec.get("kind") or "").strip().lower()
        verdict = str(rec.get("verdict") or "").strip().lower()

        if kind != "invariant" or verdict != "fail":
            # observed_state belongs only on failed invariant records.
            for k in (
                "observed_state",
                "observed_state_truncated",
                "observed_state_truncation_original_bytes",
            ):
                if k in rec:
                    rec.pop(k, None)
            return

        state = rec.get("observed_state")
        if not isinstance(state, dict):
            # Failed invariant with no populated observed_state; evaluator
            # call sites are responsible for population. Strip stray
            # truncation flags if any.
            for k in (
                "observed_state_truncated",
                "observed_state_truncation_original_bytes",
            ):
                if k in rec:
                    rec.pop(k, None)
            return

        truncated, original_bytes = _observed_state_truncate(state)
        if truncated:
            rec["observed_state_truncated"] = True
            rec["observed_state_truncation_original_bytes"] = int(original_bytes)
        else:
            for k in (
                "observed_state_truncated",
                "observed_state_truncation_original_bytes",
            ):
                if k in rec:
                    rec.pop(k, None)

    tests = results.get("tests")
    if isinstance(tests, list):
        for rec in tests:
            _stabilize_record(rec)

    events = results.get("events")
    if isinstance(events, list):
        for ev in events:
            if not isinstance(ev, dict):
                continue
            if str(ev.get("type") or "").strip().lower() != "scenario_test_run":
                continue
            _stabilize_record(ev)


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
    results.setdefault("tool", "cassian-gate")
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


def cmd_up(args: argparse.Namespace) -> None:
    topo_path = (TOPO_DIR / args.topology) if not Path(args.topology).is_file() else Path(args.topology)

    # If --reconfigure: destroy + remove root-owned lab dir FIRST.
    # Pre-validate topology BEFORE any destructive action (v1 deterministic, fail-fast)
    topo_preview = load_yaml(topo_path)
    ensure_valid_topology(topo_preview)

    # Deterministic Replay support:
    # If the input is a resolved topology artifact, treat it as authoritative input and SKIP resolve.
    # This prevents double-resolve drift and preserves replay semantics.
    is_resolved_input = (topo_path.name == "topology.resolved.yaml")
    if is_resolved_input:
        resolved_preview = topo_preview
    else:
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
    vm_nodes = [
        n for n in (resolved_preview or {}).get("nodes", [])
        if isinstance(n, dict) and (str(n.get("runtime") or "").strip().lower() == "vm")
    ]
    if vm_nodes:
        first_vm = vm_nodes[0]
        first_name = str(first_vm.get("name") or "<unnamed>").strip()
        assert_vm_runtime_supported(first_name)
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
    evpn_leaf_setup_vxlan_from_topology(rt, lab_name, topo)

    # Deterministic EVPN host-attachment stimulation for MAC learning
    evpn_leaf_setup_vxlan_from_topology(rt, lab_name, topo)

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

    runtime_line = f"Runtime: not verified (use 'cassian status {lab_name}')"
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
        runtime_line = f"Runtime: UNKNOWN (use 'cassian status {lab_name}')"

    if not bool(getattr(args, "_from_gate", False)):
        print("────────────────────────────────────────")
        print("Cassian Gate Up Result")
        print("────────────────────────────────────────")
        print(f"Lab: {lab_name}")
        print("RESULT: UP OK")
        print(runtime_line)
        print("Next:")
        print(f"  cassian status {lab_name}")
        print(f"  cassian test {lab_name}")
        print(f"  cassian exec {lab_name} <node>")
        print(f"  cassian down {lab_name}")

def cmd_replay(args: argparse.Namespace) -> None:
    from cassian import cmd_test
    """
    Deterministic Replay (v2):
      - Consume an explicit artifact directory containing:
          topology.resolved.yaml
          results.json
      - Re-execute deterministically using the resolved topology as input.
      - Resolve is skipped (write_containerlab_file treats topology.resolved.yaml as resolved input).
      - --gate delegates to the existing authoritative gate path (cmd_test topology-mode).
    """
    src = str(getattr(args, "artifacts", "") or "").strip()
    if not src:
        die("ERROR: Replay artifacts invalid or incomplete", code=2)

    src_dir = Path(src)

    # Deterministic path normalization:
    # If called from a non-repo CWD, accept artifact paths relative to repo root.
    if (not src_dir.exists()) and (not src_dir.is_absolute()):
        repo_root = Path(__file__).resolve().parent.parent
        alt = (repo_root / src_dir).resolve()
        if alt.exists() and alt.is_dir():
            src_dir = alt

    if (not src_dir.exists()) or (not src_dir.is_dir()):
        die("ERROR: Replay artifacts invalid or incomplete", code=2)

    p_resolved = src_dir / "topology.resolved.yaml"
    p_results = src_dir / "results.json"

    # Replay dependencies (authoritative inputs) are ONLY:
    #   - topology.resolved.yaml
    #   - results.json
    # results.summary.txt is non-authoritative and MUST NOT be required.
    if (
        (not p_resolved.exists())
        or (not p_resolved.is_file())
        or (not p_results.exists())
        or (not p_results.is_file())
    ):
        die("ERROR: Replay artifacts invalid or incomplete", code=2)

    # WI-6: Replay must refuse non-artifact directories deterministically (before any runtime work).
    # Identity check: results.json must be a valid Cassian Gate results payload (schema-stable keys only).
    import json

    try:
        src_results = json.loads(p_results.read_text(encoding="utf-8"))
    except Exception:
        die("ERROR: Replay artifacts invalid or incomplete", code=2)

    if not isinstance(src_results, dict):
        die("ERROR: Replay artifacts invalid or incomplete", code=2)

    # These keys are present in current authoritative results.json (v2) and are stable identity markers.
    # Require schema identity fields to exist (do not hard-bind to local constants; artifact may come from
    # a compatible build that still produces valid replay inputs).
    rs = src_results.get("results_schema")
    rsv = src_results.get("results_schema_version")
    if (not isinstance(rs, str)) or (not rs.strip()):
        die("ERROR: Replay artifacts invalid or incomplete", code=2)
    if (not isinstance(rsv, str)) or (not rsv.strip()):
        die("ERROR: Replay artifacts invalid or incomplete", code=2)

    if not str(src_results.get("lab") or "").strip():
        die("ERROR: Replay artifacts invalid or incomplete", code=2)

    # Additional stable-shape guardrails (present in current artifacts) to reject random JSON:
    if not isinstance(src_results.get("overall"), dict):
        die("ERROR: Replay artifacts invalid or incomplete", code=2)

    cmd = src_results.get("command")
    if (not isinstance(cmd, str)) or (not cmd.strip()):
        die("ERROR: Replay artifacts invalid or incomplete", code=2)

    import shlex

    replay_scenario: str | None = None
    replay_all_scenarios = False

    try:
        cmd_tokens = shlex.split(cmd)
    except Exception:
        cmd_tokens = []

    i = 0
    while i < len(cmd_tokens):
        tok = cmd_tokens[i]
        if tok == "--all-scenarios":
            replay_all_scenarios = True
        elif tok == "--scenario" and (i + 1) < len(cmd_tokens):
            replay_scenario = str(cmd_tokens[i + 1]).strip() or None
            i += 1
        i += 1

    if replay_scenario is None:
        raw = src_results.get("scenario")
        if isinstance(raw, str) and raw.strip():
            replay_scenario = raw.strip()

    if not replay_all_scenarios:
        raw_all = src_results.get("all_scenarios")
        if isinstance(raw_all, bool):
            replay_all_scenarios = raw_all

    if replay_scenario is None and not replay_all_scenarios:
        src_scenarios = src_results.get("scenarios")
        if isinstance(src_scenarios, list):
            scen_ids = []
            for s in src_scenarios:
                if isinstance(s, dict):
                    sid = str(s.get("id") or "").strip()
                    if sid:
                        scen_ids.append(sid)
            scen_ids = list(dict.fromkeys(scen_ids))
            if len(scen_ids) == 1:
                replay_scenario = scen_ids[0]

    # Minimal stable banner (quiet-mode safe).
    print("Cassian Gate Replay Run")
    print("")
    print(f"Run Source: {src}")
    if bool(getattr(args, "gate", False)):
        print("Mode: replay (authoritative gate context)")
        print("Authority: GATE (authoritative)")
        # Authoritative replay:
        # IMPORTANT: Gate-mode enforces clean-state destroy by LAB NAME. If we pass the source resolved
        # topology directly, the destroy step may purge the very source artifacts we're replaying from.
        #
        # Deterministic fix:
        # - Derive a deterministic replay lab name from the source resolved YAML bytes.
        # - Write a temporary resolved topology file (named topology.resolved.yaml) with ONLY 'name' changed.
        # - Delegate to cmd_test topology-mode using that temp resolved topology as the input.
        import hashlib

        resolved_bytes = p_resolved.read_bytes()
        h8 = hashlib.sha256(resolved_bytes).hexdigest()[:8]

        src_doc = load_yaml(p_resolved) or {}
        orig_name = str((src_doc.get("name") or "").strip()) or "replay"
        base = orig_name[:40]  # deterministic clamp (avoid overly long names)
        replay_name = f"{base}-replay-{h8}"

        # Write temp resolved topology input under labs/_replay_inputs/<replay_name>/topology.resolved.yaml
        tmp_dir = LABS_DIR / "_replay_inputs" / replay_name
        tmp_dir.mkdir(parents=True, exist_ok=True)
        tmp_resolved = tmp_dir / "topology.resolved.yaml"

        src_doc2 = dict(src_doc)
        src_doc2["name"] = replay_name

        replay_precheck_controlplane = False

        write_file(tmp_resolved, yaml.safe_dump(src_doc2, sort_keys=False))

        # Delegate to the existing authoritative gate-style topology-mode handler.
        # write_containerlab_file() will skip resolve because the filename is topology.resolved.yaml,
        # and cmd_up pre-validation now also skips resolve for resolved inputs.
        cmd_test(
            argparse.Namespace(
                lab=str(tmp_resolved),
                two_run=False,
                two_run_topology=None,
                name=None,
                kind=None,
                keep_going=False,
                json=False,
                candidate_config=None,
                verbose=bool(getattr(args, "verbose", False)),
                scenario=None if replay_all_scenarios else replay_scenario,
                all_scenarios=replay_all_scenarios,
                capture_config=False,
                list_scenarios=False,
                precheck_controlplane=False,
                _report_authority="gate",
            )
        )

        # Optional determinism verification (opt-in):
        # - Default behavior is unchanged (replay may legitimately differ; replay never restores old verdicts).
        # - If explicitly requested, enforce byte-identical results.json to the source.
        if bool(getattr(args, "verify_results", False)):
            import json

            replay_results = LABS_DIR / f"clab-{replay_name}" / "results.json"
            if (not replay_results.exists()) or (not replay_results.is_file()):
                die("ERROR: Replay determinism verification missing replay results.json", code=2)

            def _get(d: dict, *keys, default=None):
                for k in keys:
                    if k in d:
                        return d[k]
                return default

            def _canon_test(t: dict) -> dict:
                # Verdict-core only: evidence may vary (container names, command strings, timing).
                return {
                    "name": _get(t, "name", default=""),
                    "kind": _get(t, "kind", "type", default=""),
                    "expected": _get(t, "expected", "expect", default=None),
                    "observed": _get(t, "observed", default=None),
                    "verdict": _get(t, "verdict", default=""),
                }

            def _canon_scenario(s: dict) -> dict:
                # Minimal stable scenario identity + step verdict structure.
                steps = _get(s, "steps", default=[]) or []
                out_steps = []
                for st in steps:
                    if not isinstance(st, dict):
                        continue
                    out_steps.append(
                        {
                            "id": _get(st, "id", default=""),
                            "type": _get(st, "type", default=""),
                            "expected": _get(st, "expected", default=None),
                            "observed": _get(st, "observed", default=None),
                            "verdict": _get(st, "verdict", default=""),
                        }
                    )
                return {
                    "id": _get(s, "id", default=""),
                    "verdict": _get(s, "verdict", default=""),
                    "steps": out_steps,
                }

            def _extract_verdict_core(obj: dict) -> dict:
                tests = _get(obj, "tests", default=[]) or []
                scenarios = _get(obj, "scenarios", default=[]) or []

                tests_core = []
                for t in tests:
                    if isinstance(t, dict):
                        tests_core.append(_canon_test(t))

                scenarios_core = []
                for s in scenarios:
                    if isinstance(s, dict):
                        scenarios_core.append(_canon_scenario(s))

                # Summary counts (stable intent-level)
                return {
                    "result": _get(obj, "result", "RESULT", default=""),
                    "exit": _get(obj, "exit_code", "exit", "EXIT", default=None),
                    "counts": {
                        "tests_total": _get(obj, "tests_total", default=None),
                        "tests_pass": _get(obj, "tests_pass", default=None),
                        "tests_fail": _get(obj, "tests_fail", default=None),
                        "tests_skip": _get(obj, "tests_skip", default=None),
                        "scenarios_total": _get(obj, "scenarios_total", default=None),
                    },
                    "tests": tests_core,
                    "scenarios": scenarios_core,
                }

            src_obj = json.loads(p_results.read_text(encoding="utf-8"))
            rep_obj = json.loads(replay_results.read_text(encoding="utf-8"))

            src_core = json.dumps(_extract_verdict_core(src_obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            rep_core = json.dumps(_extract_verdict_core(rep_obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

            if src_core != rep_core:
                die("ERROR: Replay determinism verification failed (verdict core differs)", code=1)

        # WI-5: Gate-mode replay must emit the deterministic Artifacts footer, same as `netsim test`.
        # NOTE: main() prints the footer for `test`, but replay is a different command path.
        _print_artifacts_footer_for_lab(replay_name, authority_kind="gate")

        return

    print("Mode: replay (exploration artifacts)")
    print("Authority: RUN (non-authoritative)")

    # Non-gate replay: deploy/provision using the resolved topology artifact; keep lab running.
    # IMPORTANT: reconfigure=True triggers destroy by LAB NAME. If we use the source resolved topology
    # directly, we may purge the source artifacts. Use a deterministic replay lab name and a temp
    # resolved topology input, mirroring the --gate safety fix.
    import hashlib

    resolved_bytes = p_resolved.read_bytes()
    h8 = hashlib.sha256(resolved_bytes).hexdigest()[:8]

    src_doc = load_yaml(p_resolved) or {}
    orig_name = str((src_doc.get("name") or "").strip()) or "replay"
    base = orig_name[:40]  # deterministic clamp (avoid overly long names)
    replay_name = f"{base}-replay-{h8}"

    tmp_dir = LABS_DIR / "_replay_inputs" / replay_name
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_resolved = tmp_dir / "topology.resolved.yaml"

    src_doc2 = dict(src_doc)
    src_doc2["name"] = replay_name
    write_file(tmp_resolved, yaml.safe_dump(src_doc2, sort_keys=False))

    print("Replay Context: non-gate replay keeps runtime up for inspection")
    print("")

    cmd_up(argparse.Namespace(topology=str(tmp_resolved), reconfigure=True, _from_gate=False))

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

        print("────────────────────────────────────────")
        print("Cassian Down Result")
        print("────────────────────────────────────────")
        if used_topology:
            print(f"Topology: {topo_path}")
        print(f"Lab: {lab_name}")
        print(f"LAB DESCRIPTOR: labs/{lab_name}.clab.yaml")
        print("RESULT: NO-OP (lab not found)")
        print("Meaning: nothing was destroyed")

        if strict:
            print(f"ERROR: lab '{lab_name}' not found")
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
    print("RESULT: DESTROYED")
    print(f"OK  {lab_name}: destroyed")

    # Artifact policy (v2 gate integrity):
    # - Runtime teardown must NOT delete labs/clab-<lab> evidence.
    # - Explicit deletion is handled only by:
    #     * cassian destroy <lab> --purge-artifacts
    #     * cassian cleanup --all --yes
    return

def cmd_destroy(args: argparse.Namespace) -> None:
    """
    Explicit ops command (non-authoritative):
      cassian destroy <lab> [--purge-artifacts]

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
                print(f"WARN: {lab_name}: destroy failed: {summary}")
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
                print(f"WARN: {lab_name}: artifact purge failed: {summary_rm}")
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

        print("────────────────────────────────────────")
        print("Cassian Gate Destroy Result")
        print("────────────────────────────────────────")
        print(f"Lab: {lab_name}")
        print(f"LAB DESCRIPTOR: labs/{lab_name}.clab.yaml")
        print("RESULT: NO-OP (lab not found)")
        print("Meaning: nothing was destroyed")

        if strict:
            print(f"ERROR: lab '{lab_name}' not found")
            raise SystemExit(2)
        return

def cmd_cleanup(args: argparse.Namespace) -> None:
    """
    v1.x ops helper (non-authoritative):
      cassian cleanup --all [--yes]

    Safety:
      - ONLY targets Cassian Gate labs that have artifacts under labs/clab-*
      - Dry-run by default; --yes required to execute
      - Never touches labs not present in labs/ (no Docker scans)
      - On execute: attempts runtime teardown (if .clab.yaml exists) AND purges artifacts under labs/clab-*
      - Best-effort across labs; final exit non-zero if any intended action failed
      - Optional machine-readable report: labs/_cleanup/cleanup.json
    """
    if not getattr(args, "all", False):
        die("cleanup requires --all. This command only targets Cassian Gate labs present in labs/ (labs/clab-*).")

    candidates = list_owned_labs_from_artifacts()

    do_exec = bool(getattr(args, "yes", False))
    print("Cleanup plan (execute):" if do_exec else "Cleanup plan (dry-run):")

    if not candidates:
        print("- (none)  No Cassian Gate lab artifacts found under labs/clab-*")
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
                    print(f"WARN: {lab}: destroy failed: {summary}")
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
            print(f"WARN: {lab}: artifact purge failed: {summary_rm}")
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
            "  cassian exec <lab-name> <node> -- <cmd...>\n"
            "Next:\n"
            "  Run: cassian status <lab-name>  (to list nodes)",
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
            "  Gate mode: cassian test <topology.yaml>\n"
            "  Lab mode:  cassian up <topology.yaml> --reconfigure\n"
            "Hint:\n"
            "  If artifacts are stale: cassian cleanup --all --yes",
            code=2,
        )

    if node not in valid_nodes:
        die(
            f"ERROR: invalid node '{node}' for lab '{lab}'\n"
            f"Valid nodes: {', '.join(valid_nodes)}\n"
            f"Try: cassian status {lab}",
            code=2,
        )

    # Valid node: ensure runtime container exists (runtime-owned check) to prevent daemon error leakage.
    if hasattr(rt, "node_id") and hasattr(rt, "exists_id"):
        node_id = rt.node_id(lab, node)
        try:
            if not rt.exists_id(node_id):
                die(
                    f"ERROR: lab runtime missing for '{lab}' (container {node_id} not found)\n"
                    f"Try: cassian status {lab}\n"
                    "Hint: Run 'cassian up <topology.yaml> --reconfigure' (or 'cassian run <topology.yaml> --keep') then retry.\n"
                    "If artifacts are stale: cassian cleanup --all --yes",
                    code=2,
                )
        except SystemExit:
            raise
        except Exception:
            # Keep deterministic and actionable without exposing backend exceptions.
            die(f"ERROR: unable to verify runtime for lab '{lab}' (use 'cassian status {lab}')", code=2)

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
            '  cassian vty <lab-name> <node> "<command>"\n'
            "Next:\n"
            "  Run: cassian status <lab-name>  (to list nodes)",
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
            "Hint: Run 'cassian up <topology.yaml>' (or 'cassian run <topology.yaml> --keep') then retry.",
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
            "  cassian status <lab-name>\n"
            "Next:\n"
            "  If you have a topology: cassian test <topology.yaml>  (gate)\n"
            "  If you already deployed: cassian status <lab-name>",
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
    old_quiet = cassian_common.QUIET_RUN
    if as_json:
        cassian_common.QUIET_RUN = True

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
            "Cassian Gate Status\n"
            "────────────────────────────────────────\n"
            f"Lab: {lab}\n"
            "RESULT: NOT FOUND\n"
            "Reason: No lab descriptor found locally.\n"
            "Expected:\n"
            f"  {expected_clab}\n"
            "Next:\n"
            "  cassian test <topology.yaml>\n"
            "Hint:\n"
            "  If artifacts are stale: cassian cleanup --all --yes\n"
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
    print("Cassian Status")
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
            print(f"  cassian test {topo_path}  (gate)")
        else:
            print("  cassian test <topology.yaml>  (gate)")
        return

    print("Next:")
    if result == "OK":
        print(f"  cassian test {lab}  (lab mode)")
        print(f"  cassian exec {lab} <node> -- <cmd...>")
        print(f"  cassian down {lab}")
    else:
        if topo_path:
            print(f"  cassian test {topo_path}  (gate)")
            print(f"  cassian up {topo_path} --reconfigure")
        else:
            print("  cassian test <topology.yaml>  (gate)")
        print(f"  cassian status {lab}")

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

    cassian_common.QUIET_RUN = old_quiet

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
    from cassian import cmd_test
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
    scenario = getattr(args, "scenario", None)
    all_scenarios = bool(getattr(args, "all_scenarios", False))

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
                        f"Use '--reconfigure' to rebuild it (or run 'cassian down {lab_name}' first).",
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
            code = getattr(e, "code", 1)
            if isinstance(code, str):
                raise SystemExit(2)
            if code == 2:
                raise SystemExit(2)
            record_failure(code)
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
                    code = getattr(e, "code", 1)
                    if isinstance(code, str):
                        raise SystemExit(2)
                    if code == 2:
                        raise SystemExit(2)
                    record_failure(code)
                except Exception:
                    record_failure(1)

            # 2) test (optional)
            if do_test:
                try:
                    cmd_test(
                        argparse.Namespace(
                            lab=lab_name,
                            _report_authority="run",
                            scenario=scenario,
                            all_scenarios=all_scenarios,
                            list_scenarios=False,
                            scenario_verbose=False,
                            precheck_controlplane=False,
                            keep_going=False,
                            json=False,
                            candidate_config=None,
                            name=None,
                            kind=None,
                        )
                    )
                except SystemExit as e:
                    code = getattr(e, "code", 1)
                    if isinstance(code, str):
                        raise SystemExit(2)
                    if code == 2:
                        raise SystemExit(2)
                    record_failure(code)
                except Exception:
                    record_failure(1)

            # 3) collect (best-effort; very useful for debugging failures)
            if do_collect:
                try:
                    cmd_collect(argparse.Namespace(lab=lab_name))
                except SystemExit as e:
                    code = getattr(e, "code", 1)
                    if isinstance(code, str):
                        raise SystemExit(2)
                    if code == 2:
                        raise SystemExit(2)
                    record_failure(code)
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
    print(f"Mode: run (exploration)")
    print("Authority: RUN (non-authoritative)")
    print(f"Lab lifecycle: {lifecycle}")

    # Final reporting + exit behavior (never lie)
    if exit_code is not None and int(exit_code) != 0:
        code = int(exit_code)
        if code == 1:
            last_msg = str(getattr(cassian_common, "LAST_ERROR_MSG", "") or "").strip().lower()
            if (
                last_msg.startswith("topology invalid:")
                or last_msg.startswith("invalid yaml:")
                or last_msg.startswith("coverage:")
                or last_msg.startswith("schema:")
                or last_msg.startswith("scenario ")
            ):
                code = 2
        raise SystemExit(code)

    return

def cmd_test(args: argparse.Namespace) -> None:
    """
    v1 update (Section C): Scenarios wired into cmd_test (minimal invasive).

    - Default behavior unchanged: readiness + optional BGP + declared tests (steady-state).
    - Opt-in scenarios:
        * cassian test --scenario <id>
        * cassian test --all-scenarios
    When a scenario is requested, cmd_test executes declared steady-state tests first,
    then executes the requested scenario(s).
      Scenario steps call existing atomic tests via `run: <test_name>`.

    Hard guardrail:
      If scenarios are requested, validate ALL scenario run refs up-front and FAIL FAST
      (before any runtime actions) if a referenced atomic test name does not exist.
    """
    # v1.5 hard guardrail: capture-config is exploration evidence only (never allowed in gate-first test)
    if bool(getattr(args, "capture_config", False)):
        die("--capture-config is exploration evidence only and is not allowed in cassian test", code=2)

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
            "  cassian test <lab-name> [options]\n\n"
            "Examples:\n"
            "  cassian up topologies/foo.yaml --reconfigure\n"
            "  cassian test foo\n\n"
            "Note:\n"
            "  If you want the baseline-vs-change gate, use:\n"
            "    cassian test --two-run --two-run-topology <topology.yaml> --candidate-config <dir>\n",
            code=2,
        )

    # ------------------------------------------------------------
    # v2 UX hardening (First 10 Minutes):
    # Allow: cassian test <topology.yaml> as an authoritative clean-state gate.
    # Preserve: cassian test <lab-name> behavior (existing lab required).
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
        except SystemExit as e:
            raw_code = getattr(e, "code", 1)
            preview_code = raw_code if isinstance(raw_code, int) else 2
            if preview_code == 1:
                preview_code = 2
            raise SystemExit(preview_code)

        lab_name = str((resolved_preview or {}).get("name") or "").strip()
        if not lab_name:
            die(f"Topology missing required 'name': {topo_gate_path}", code=2)

        tests_preview = resolved_preview.get("tests") or []
        scenarios_preview = resolved_preview.get("scenarios") or []
        if (not args.list_scenarios) and (len(tests_preview) == 0) and (len(scenarios_preview) == 0):
            die(
                "no assertions defined\n\n"
                "A validation gate must include at least one test or scenario.\n"
                "This run would produce a vacuous PASS and is therefore rejected.",
                code=2,
            )

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
                results.setdefault("tool", "cassian-gate")
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

                    try:
                        rj = load_yaml(out)
                    except Exception:
                        rj = None

                    if isinstance(rj, dict):
                        tests_n = len(rj.get("tests") or [])
                        scenarios_n = len(rj.get("scenarios") or [])
                        if tests_n == 0 and scenarios_n == 0:
                            print("Proof Scope: smoke-only deployment validation")
                            print("Validated: resolve, generate, deploy, provision, collect, destroy")
                            print("Not validated: connectivity, routing, policy, scenario behavior")
                            print("Next: add declared tests or scenarios to prove behavior beyond smoke")
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
                                err=str(getattr(cassian_common, "LAST_ERROR_MSG", "") or "gate test failed"),
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

            try:
                err_msg = str(getattr(cassian_common, "LAST_ERROR_MSG", "") or "").strip()
            except Exception:
                err_msg = ""

            err_msg_l = err_msg.lower()

            if exit_code == 1 and (
                err_msg_l.startswith("topology invalid:")
                or err_msg_l.startswith("invalid yaml:")
                or err_msg_l.startswith("coverage:")
                or err_msg_l.startswith("schema:")
                or err_msg_l.startswith("scenario ")
            ):
                exit_code = 2

            # IMPORTANT (WI-1): only emit a synthetic "hard failure" record when we are NOT in the test stage
            # (deploy/provision/runtime faults) OR when upstream uses the hard-failure exit band.
            # Normal test-stage failures (exit=1) already have authoritative results written by cmd_test()
            # and MUST NOT be duplicated.
            #
            # WI-5: resolve-time invalid-input paths already print a cassian-owned error message via die().
            # Do not emit the synthetic hard-failure gate record for those resolve-time misuse/invalid-input
            # cases, or quiet mode will print the same owned error twice.
            is_resolve_invalid_input = (
                err_msg_l.startswith("invalid yaml:")
                or err_msg_l.startswith("topology invalid:")
                or err_msg_l.startswith("coverage:")
                or err_msg_l.startswith("schema:")
                or err_msg_l.startswith("scenario ")
            )

            should_emit_hard_failure = (
                (str(gate_phase) != "test")
                and (not is_resolve_invalid_input)
                and (int(exit_code) != 2)
            )

            if should_emit_hard_failure:
                # Best-effort: render a gate-style hard failure record under the derived lab name.
                # Phase must reflect whether failure happened during deploy/provision or during test execution.
                try:
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

            raise SystemExit(exit_code)

        finally:
            # Always cleanup after gate-style runs (equivalent to: cassian down <lab>)
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
            "  cassian test <lab-name> [options]\n"
            "  cassian test <topology.yaml> [options]\n\n"
            "Examples:\n"
            "  cassian up topologies/foo.yaml --reconfigure\n"
            "  cassian test foo\n\n"
            "  cassian test examples/dci-failover.yaml\n\n"
            "Note:\n"
            "  If you want the baseline-vs-change gate, use:\n"
            "    cassian test --two-run --two-run-topology <topology.yaml> --candidate-config <dir>\n",
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
            "  Gate mode: cassian test <topology.yaml>\n"
            "  Lab mode:  cassian up <topology.yaml> --reconfigure ; cassian test <lab-name>",
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
                "Hint: Run 'cassian up <topology.yaml> --reconfigure' then 'cassian test <lab-name>', or run "
                "'cassian test <topology.yaml>' to create artifacts.",
                code=2,
            )

        rpath = adir / "topology.resolved.yaml"
        if not rpath.exists():
            die(
                f"Lab artifacts not found for lab={lab}. Expected: {rpath}\n"
                "Hint: Run 'cassian up <topology.yaml> --reconfigure' then 'cassian test <lab-name>', or run "
                "'cassian test <topology.yaml>' to create artifacts.",
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
                "ERROR: cassian test expects a lab name, not a topology file.\n\n"
                f"You ran:\n  cassian test {lab}\n\n"
                "Did you mean:\n"
                f"  cassian up {lab} --reconfigure\n"
                f"  cassian test <lab-name>\n\n"
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
        observed_state: dict | None = None,
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
        if observed_state is not None:
            rec["observed_state"] = observed_state
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
        observed_state: dict | None = None,
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
        if observed_state is not None:
            rec["observed_state"] = observed_state
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

    def _blast_radius_link_id_from_fields(a: str, a_if: str, b: str, b_if: str) -> str:
        ends = sorted([f"{a}:{a_if}", f"{b}:{b_if}"])
        return " -- ".join(ends)

    def _blast_radius_build_graph_or_die(topo_obj: dict[str, Any]) -> dict[str, Any]:
        nodes_decl = topo_obj.get("nodes") or []
        links_decl = topo_obj.get("links") or []

        node_names: list[str] = []
        node_set: set[str] = set()
        adjacency: dict[str, set[str]] = {}
        node_links: dict[str, set[str]] = {}

        for idx, node in enumerate(nodes_decl, start=1):
            if not isinstance(node, dict):
                die(f"blast-radius: invalid node declaration at index {idx}", code=2)
            name = str(node.get("name") or "").strip()
            if not name:
                die(f"blast-radius: node at index {idx} missing name", code=2)
            if name in node_set:
                die(f"blast-radius: duplicate node name '{name}'", code=2)
            node_set.add(name)
            node_names.append(name)
            adjacency[name] = set()
            node_links[name] = set()

        links_by_id: dict[str, dict[str, Any]] = {}
        for idx, link in enumerate(links_decl, start=1):
            if not isinstance(link, dict):
                die(f"blast-radius: invalid link declaration at index {idx}", code=2)
            endpoints = link.get("endpoints")
            if not isinstance(endpoints, list) or len(endpoints) != 2:
                die(f"blast-radius: link at index {idx} must declare exactly two endpoints", code=2)

            parsed: list[tuple[str, str]] = []
            for ep in endpoints:
                ep_s = str(ep or "").strip()
                if ":" not in ep_s:
                    die(f"blast-radius: invalid link endpoint {ep_s!r} at index {idx}", code=2)
                node_name, if_name = ep_s.split(":", 1)
                node_name = node_name.strip()
                if_name = if_name.strip()
                if not node_name or not if_name:
                    die(f"blast-radius: invalid link endpoint {ep_s!r} at index {idx}", code=2)
                if node_name not in node_set:
                    die(f"blast-radius: link endpoint references unknown node '{node_name}'", code=2)
                parsed.append((node_name, if_name))

            (a, a_if), (b, b_if) = parsed
            link_id = _blast_radius_link_id_from_fields(a, a_if, b, b_if)
            if link_id in links_by_id:
                die(f"blast-radius: duplicate canonical link identity '{link_id}'", code=2)

            links_by_id[link_id] = {
                "id": link_id,
                "nodes": sorted([a, b]),
                "endpoints": sorted([f"{a}:{a_if}", f"{b}:{b_if}"]),
            }
            adjacency[a].add(b)
            adjacency[b].add(a)
            node_links[a].add(link_id)
            node_links[b].add(link_id)

        return {
            "nodes": sorted(node_names),
            "node_set": set(node_set),
            "adjacency": {k: sorted(v) for k, v in sorted(adjacency.items())},
            "node_links": {k: sorted(v) for k, v in sorted(node_links.items())},
            "links": dict(sorted(links_by_id.items())),
        }

    def _blast_radius_collect_coverage_or_die(
        topo_obj: dict[str, Any],
        graph: dict[str, Any],
    ) -> dict[str, list[str]]:
        covered_nodes: set[str] = set()
        covered_links: set[str] = set()
        coverage_basis: list[str] = []

        def _add_node(name: str, context: str) -> None:
            node_name = str(name or "").strip()
            if not node_name:
                return
            if node_name not in graph["node_set"]:
                die(f"blast-radius: {context} references unknown node '{node_name}'", code=2)
            covered_nodes.add(node_name)

        def _add_link(a: str, a_if: str, b: str, b_if: str, context: str) -> None:
            link_id = _blast_radius_link_id_from_fields(
                str(a or "").strip(),
                str(a_if or "").strip(),
                str(b or "").strip(),
                str(b_if or "").strip(),
            )
            if link_id not in graph["links"]:
                die(f"blast-radius: {context} references unknown link '{link_id}'", code=2)
            covered_links.add(link_id)

        def _collect_test(test_obj: dict[str, Any], basis_label: str) -> None:
            kind = str(test_obj.get("kind") or "").strip()
            if not kind:
                die(f"blast-radius: {basis_label} missing kind", code=2)

            coverage_basis.append(basis_label)

            if kind in ("ping", "tcp"):
                if test_obj.get("src") is not None:
                    _add_node(str(test_obj.get("src") or ""), f"{basis_label}.src")

                dst = test_obj.get("dst")
                if isinstance(dst, str) and dst.strip() and dst.strip() in graph["node_set"]:
                    _add_node(dst.strip(), f"{basis_label}.dst")

                for fld in ("to", "to_ip"):
                    val = test_obj.get(fld)
                    if isinstance(val, str) and val.strip():
                        if val.strip() in graph["node_set"]:
                            _add_node(val.strip(), f"{basis_label}.{fld}")
                        elif not is_ip_literal(val.strip()):
                            die(
                                f"blast-radius: unsupported non-canonical target {val!r} in {basis_label}.{fld}",
                                code=2,
                            )
                return

            if kind == "invariant":
                for fld in ("node", "peer"):
                    if test_obj.get(fld) is not None:
                        _add_node(str(test_obj.get(fld) or ""), f"{basis_label}.{fld}")
                return

            die(f"blast-radius: unsupported test kind '{kind}' in {basis_label}", code=2)

        tests_decl = topo_obj.get("tests") or []
        tests_by_name: dict[str, dict[str, Any]] = {}
        for idx, test_obj in enumerate(tests_decl, start=1):
            if not isinstance(test_obj, dict):
                die(f"blast-radius: invalid test declaration at index {idx}", code=2)
            test_name = str(test_obj.get("name") or "").strip() or f"test_{idx}"
            if test_name in tests_by_name:
                die(f"blast-radius: duplicate test name '{test_name}'", code=2)
            tests_by_name[test_name] = test_obj
            _collect_test(test_obj, f"test:{test_name}")

        scenarios_decl = topo_obj.get("scenarios") or []
        for sidx, scenario in enumerate(scenarios_decl, start=1):
            if not isinstance(scenario, dict):
                die(f"blast-radius: invalid scenario declaration at index {sidx}", code=2)
            scenario_id = str(scenario.get("id") or "").strip() or f"scenario_{sidx}"
            steps = scenario.get("steps") or []
            if not isinstance(steps, list):
                die(f"blast-radius: scenario '{scenario_id}' steps must be a list", code=2)

            for step_idx, step in enumerate(steps, start=1):
                if not isinstance(step, dict) or len(step) != 1:
                    die(
                        f"blast-radius: scenario '{scenario_id}' step {step_idx} must contain exactly one action",
                        code=2,
                    )
                action, payload = next(iter(step.items()))
                coverage_basis.append(f"scenario:{scenario_id}:step:{step_idx}:{action}")

                if action == "run":
                    if isinstance(payload, str):
                        if payload not in tests_by_name:
                            die(
                                f"blast-radius: scenario '{scenario_id}' step {step_idx} references unknown test '{payload}'",
                                code=2,
                            )
                    elif isinstance(payload, dict):
                        include_val = str(payload.get("include") or "").strip()
                        if include_val and include_val != "all":
                            die(
                                f"blast-radius: unsupported run include value '{include_val}' in scenario '{scenario_id}' step {step_idx}",
                                code=2,
                            )
                    else:
                        die(
                            f"blast-radius: unsupported run payload in scenario '{scenario_id}' step {step_idx}",
                            code=2,
                        )
                    continue

                if action == "fault":
                    if not isinstance(payload, dict) or len(payload) != 1:
                        die(
                            f"blast-radius: scenario '{scenario_id}' step {step_idx} fault must contain exactly one action",
                            code=2,
                        )
                    fault_name, fault_body = next(iter(payload.items()))
                    if not isinstance(fault_body, dict):
                        die(
                            f"blast-radius: scenario '{scenario_id}' step {step_idx} fault payload must be a mapping",
                            code=2,
                        )

                    if fault_name in ("link_down", "link_up"):
                        _add_link(
                            str(fault_body.get("a") or ""),
                            str(fault_body.get("a_if") or ""),
                            str(fault_body.get("b") or ""),
                            str(fault_body.get("b_if") or ""),
                            f"scenario:{scenario_id}:step:{step_idx}:{fault_name}",
                        )
                        continue

                    if fault_name in ("interface_down", "interface_up", "prefix_blackhole"):
                        _add_node(
                            str(fault_body.get("node") or ""),
                            f"scenario:{scenario_id}:step:{step_idx}:{fault_name}.node",
                        )
                        continue

                    if fault_name in ("packet_loss", "latency", "bandwidth_cap"):
                        has_node_target = bool(str(fault_body.get("node") or "").strip()) and bool(
                            str(fault_body.get("if") or "").strip()
                        )
                        has_link_target = all(
                            bool(str(fault_body.get(k) or "").strip()) for k in ("a", "a_if", "b", "b_if")
                        )
                        if has_node_target and has_link_target:
                            die(
                                f"blast-radius: ambiguous target in scenario '{scenario_id}' step {step_idx} fault '{fault_name}'",
                                code=2,
                            )
                        if has_node_target:
                            _add_node(
                                str(fault_body.get("node") or ""),
                                f"scenario:{scenario_id}:step:{step_idx}:{fault_name}.node",
                            )
                            continue
                        if has_link_target:
                            _add_link(
                                str(fault_body.get("a") or ""),
                                str(fault_body.get("a_if") or ""),
                                str(fault_body.get("b") or ""),
                                str(fault_body.get("b_if") or ""),
                                f"scenario:{scenario_id}:step:{step_idx}:{fault_name}",
                            )
                            continue
                        die(
                            f"blast-radius: unsupported target in scenario '{scenario_id}' step {step_idx} fault '{fault_name}'",
                            code=2,
                        )

                    die(
                        f"blast-radius: unsupported fault action '{fault_name}' in scenario '{scenario_id}' step {step_idx}",
                        code=2,
                    )

                if action == "wait_for":
                    if not isinstance(payload, dict):
                        die(f"blast-radius: scenario '{scenario_id}' step {step_idx} wait_for must be a mapping", code=2)
                    if payload.get("from") is not None:
                        _add_node(str(payload.get("from") or ""), f"scenario:{scenario_id}:step:{step_idx}:wait_for.from")
                    to_val = payload.get("to")
                    if isinstance(to_val, str) and to_val.strip():
                        if to_val.strip() in graph["node_set"]:
                            _add_node(to_val.strip(), f"scenario:{scenario_id}:step:{step_idx}:wait_for.to")
                        elif not is_ip_literal(to_val.strip()):
                            die(
                                f"blast-radius: unsupported wait_for target {to_val!r} in scenario '{scenario_id}' step {step_idx}",
                                code=2,
                            )
                    continue

                if action == "wait":
                    if not isinstance(payload, dict):
                        die(
                            f"blast-radius: scenario '{scenario_id}' step {step_idx} wait must be a mapping",
                            code=2,
                        )
                    seconds = payload.get("seconds")
                    if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 1:
                        die(
                            f"blast-radius: scenario '{scenario_id}' step {step_idx} wait.seconds must be a positive integer",
                            code=2,
                        )
                    continue

                if action == "wait_for_bgp":
                    if not isinstance(payload, dict):
                        die(
                            f"blast-radius: scenario '{scenario_id}' step {step_idx} wait_for_bgp must be a mapping",
                            code=2,
                        )
                    _add_node(str(payload.get("node") or ""), f"scenario:{scenario_id}:step:{step_idx}:wait_for_bgp.node")
                    continue

                if action == "pcap_start":
                    if not isinstance(payload, dict):
                        die(
                            f"blast-radius: scenario '{scenario_id}' step {step_idx} pcap_start must be a mapping",
                            code=2,
                        )
                    target = payload.get("target")
                    if not isinstance(target, dict):
                        die(
                            f"blast-radius: scenario '{scenario_id}' step {step_idx} pcap_start.target must be a mapping",
                            code=2,
                        )
                    _add_node(str(target.get("node") or ""), f"scenario:{scenario_id}:step:{step_idx}:pcap_start.target.node")
                    continue

                if action == "pcap_stop":
                    continue

                die(f"blast-radius: unsupported scenario action '{action}' in scenario '{scenario_id}' step {step_idx}", code=2)

        return {
            "coverage_basis": sorted(coverage_basis),
            "covered_nodes": sorted(covered_nodes),
            "covered_links": sorted(covered_links),
        }

    def _blast_radius_compute_or_die(topo_obj: dict[str, Any]) -> dict[str, Any]:
        graph = _blast_radius_build_graph_or_die(topo_obj)
        coverage = _blast_radius_collect_coverage_or_die(topo_obj, graph)

        seed_nodes: set[str] = set(coverage["covered_nodes"])
        for link_id in coverage["covered_links"]:
            seed_nodes.update(graph["links"][link_id]["nodes"])

        visited: set[str] = set()
        queue = sorted(seed_nodes)
        while queue:
            node_name = queue.pop(0)
            if node_name in visited:
                continue
            visited.add(node_name)
            for peer_name in graph["adjacency"].get(node_name, []):
                if peer_name not in visited:
                    queue.append(peer_name)
            queue = sorted(set(queue))

        affected_nodes = [
            {"id": node_name, "reason": "graph_connected_to_covered_scope"}
            for node_name in sorted(visited)
            if node_name not in set(coverage["covered_nodes"])
        ]

        affected_links = []
        covered_link_set = set(coverage["covered_links"])
        for link_id, link_rec in sorted(graph["links"].items()):
            node_a, node_b = link_rec["nodes"]
            if node_a in visited and node_b in visited and link_id not in covered_link_set:
                affected_links.append(
                    {
                        "id": link_id,
                        "reason": "component_touching_covered_scope",
                    }
                )

        return {
            "schema": "blast_radius.v1",
            "authority": "supporting_evidence",
            "topology": {"name": str(topo_obj.get("name") or lab)},
            "coverage_basis": list(coverage["coverage_basis"]),
            "directly_covered": {
                "nodes": list(coverage["covered_nodes"]),
                "links": list(coverage["covered_links"]),
            },
            "potentially_affected": {
                "nodes": affected_nodes,
                "links": affected_links,
            },
            "counts": {
                "directly_covered_nodes": int(len(coverage["covered_nodes"])),
                "directly_covered_links": int(len(coverage["covered_links"])),
                "potentially_affected_nodes": int(len(affected_nodes)),
                "potentially_affected_links": int(len(affected_links)),
            },
        }

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
            results.setdefault("tool", "cassian-gate")
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
            try:
                _observed_state_finalize_in_results(results)
            except Exception:
                # Never allow observed_state stabilization to break gate execution.
                pass
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

    def _evaluate_invariant_attempt(
        *,
        inv_type: str,
        t: dict,
        src: str,
    ) -> tuple[bool, bool, dict, dict]:
        """
        Single-attempt evaluator for invariant types implemented by
        run_invariant_test. Returns (vtysh_ok, predicate_ok, observed_state, evidence).

          vtysh_ok       True if the runtime probe succeeded (vtysh exit 0 and
                         output captured). Used by TEST-path retry loops to
                         skip transient runtime failures.
          predicate_ok   True if the invariant condition is satisfied. Used by
                         the wait-for-path retry_until driver in
                         cassian_tests.py:wait_for_condition.
          observed_state Per-type structured payload conforming to the
                         schema documented in docs/topology-schema-v1.5.md
                         §4. Suitable for record_fn(observed_state=...) on
                         the TEST-path. The TEST-path caller is responsible
                         for selecting which fields are exposed in
                         results.json[tests] vs. results.json[scenarios]
                         (Handover 2 / REQ-WF-16 contracts).
          evidence       Diagnostic dict (cmd, parse_error, returncode, ...)
                         suitable for record_fn(evidence=...) on the
                         TEST-path.

        No retry. No recording. No input validation. Backend errors are
        caught inside the helper and surfaced as vtysh_ok=False with
        diagnostic content in evidence; the helper does not raise.

        For invariant types where vtysh-success implies the predicate (most
        types), vtysh_ok and predicate_ok return identical values. They
        differ for bgp_session_up and evpn_bgp_session_up, where vtysh
        running successfully does not imply the BGP session has reached
        Established.
        """
        if inv_type == "bgp_session_up":
            neighbor = str(t.get("dst") or "").strip()
            cp = rt.exec(lab, src, ["vtysh", "-c", "show bgp summary json"], check=False)
            vtysh_ok = (getattr(cp, "returncode", 1) == 0)
            out = (cp.stdout or "") if hasattr(cp, "stdout") else ""

            observed_state_str: str = "Unknown"
            last_error: str = ""
            parse_error: str = ""
            peer_present: bool = False

            if vtysh_ok:
                try:
                    data = json.loads(out or "{}")
                    peers = None
                    top_peers = data.get("peers")
                    if isinstance(top_peers, dict):
                        peers = top_peers
                    else:
                        v4u = data.get("ipv4Unicast")
                        if isinstance(v4u, dict):
                            inner = v4u.get("peers")
                            if isinstance(inner, dict):
                                peers = inner
                    if peers is None:
                        for _, v in sorted(data.items()):
                            if isinstance(v, dict):
                                inner = v.get("peers")
                                if isinstance(inner, dict):
                                    peers = inner
                                    break
                    if isinstance(peers, dict):
                        p = peers.get(neighbor)
                        if isinstance(p, dict):
                            peer_present = True
                            raw_state = p.get("state") or p.get("bgpState") or p.get("peerState")
                            if raw_state:
                                observed_state_str = str(raw_state)
                            reset_reason = p.get("lastResetReason")
                            if reset_reason:
                                last_error = str(reset_reason)
                        else:
                            observed_state_str = "NotConfigured"
                            last_error = "neighbor not present in summary"
                            parse_error = "neighbor not present in summary"
                    else:
                        observed_state_str = "Unknown"
                        last_error = "peers not found in summary"
                        parse_error = "peers not found in summary"
                except Exception:
                    observed_state_str = "Unknown"
                    last_error = "vtysh output not parseable as JSON"
                    parse_error = "vtysh output not parseable as JSON"
            else:
                observed_state_str = "Unknown"
                last_error = "vtysh command failed"
                parse_error = "vtysh command failed"

            st_norm = observed_state_str.strip().lower()
            predicate_ok = bool(peer_present and st_norm == "established")

            observed_state = {
                "peer_present": peer_present,
                "state": observed_state_str,
                "last_error": last_error,
            }
            evidence = {
                "cmd": "vtysh -c 'show bgp summary json'",
                "parse_error": parse_error,
                "returncode": getattr(cp, "returncode", None),
            }
            return vtysh_ok, predicate_ok, observed_state, evidence

        if inv_type == "evpn_bgp_session_up":
            peer = str(t.get("peer") or "").strip()
            cp = rt.exec(
                lab,
                src,
                ["vtysh", "-c", "show bgp l2vpn evpn summary json"],
                check=False,
                capture_output=True,
            )

            if isinstance(cp, str):
                out = cp
                rc = None
            else:
                out = getattr(cp, "stdout", "") or getattr(cp, "output", "") or ""
                if isinstance(out, (bytes, bytearray)):
                    try:
                        out = out.decode("utf-8", errors="replace")
                    except Exception:
                        out = str(out)
                rc = getattr(cp, "returncode", None)

            vtysh_ok = (rc in (0, None))

            evidence_entries: list = []
            parse_error: str = ""
            present: bool = False

            try:
                doc = json.loads(str(out or "").strip()) if str(out or "").strip() else {}
                peers = {}
                if isinstance(doc, dict):
                    peers = doc.get("peers", {})
                    if not isinstance(peers, dict):
                        peers = {}
                else:
                    raise ValueError("unexpected_evpn_bgp_summary_json_shape")

                peer_ips: set = set()
                for link in (topo.get("links") or []):
                    endpoints = list(link.get("endpoints") or [])
                    if len(endpoints) != 2:
                        continue
                    try:
                        a_node, _a_if = str(endpoints[0]).split(":", 1)
                        b_node, _b_if = str(endpoints[1]).split(":", 1)
                    except Exception:
                        continue
                    if a_node == src and b_node == peer:
                        ips = list(link.get("ipv4") or [])
                        if len(ips) >= 2:
                            try:
                                peer_ips.add(str(ipaddress.ip_interface(ips[0]).ip))
                            except Exception:
                                pass
                    elif b_node == src and a_node == peer:
                        ips = list(link.get("ipv4") or [])
                        if len(ips) >= 2:
                            try:
                                peer_ips.add(str(ipaddress.ip_interface(ips[0]).ip))
                            except Exception:
                                pass

                for nbr_ip, pdata in peers.items():
                    if not isinstance(pdata, dict):
                        continue
                    rec = {
                        "neighbor": str(nbr_ip or "").strip(),
                        "peerName": str(pdata.get("peerName") or "").strip(),
                        "state": str(pdata.get("state") or "").strip(),
                        "node": src,
                    }
                    evidence_entries.append(rec)
                    if rec["state"].lower() != "established":
                        continue
                    if rec["peerName"] == peer:
                        present = True
                    elif rec["neighbor"] in peer_ips:
                        present = True
            except Exception as e:
                parse_error = str(e)

            evidence_entries = sorted(
                evidence_entries,
                key=lambda x: (
                    str(x.get("neighbor") or ""),
                    str(x.get("peerName") or ""),
                    str(x.get("state") or ""),
                    str(x.get("node") or ""),
                ),
            )

            predicate_ok = bool(present)

            observed_state = {
                "peer": peer,
                "present": present,
                "neighbors": evidence_entries,
            }
            evidence = {
                "cmd": "vtysh -c 'show bgp l2vpn evpn summary json'",
                "rc": rc,
                "parse_error": parse_error,
                "neighbors": evidence_entries,
            }
            return vtysh_ok, predicate_ok, observed_state, evidence

        if inv_type in ("route_present", "route_absent"):
            norm_prefix = str(t.get("_norm_prefix") or "").strip()
            cp = rt.exec(
                lab,
                src,
                ["vtysh", "-c", "show ip route json"],
                check=False,
                capture_output=True,
            )

            if isinstance(cp, str):
                out = cp
                rc = None
            else:
                out = getattr(cp, "stdout", "") or getattr(cp, "output", "") or ""
                if isinstance(out, (bytes, bytearray)):
                    try:
                        out = out.decode("utf-8", errors="replace")
                    except Exception:
                        out = str(out)
                rc = getattr(cp, "returncode", None)

            vtysh_ok = (rc in (0, None))

            observed_prefixes = parse_frr_show_ip_route_prefixes_json(str(out or ""))
            present = norm_prefix in set(observed_prefixes or [])

            if inv_type == "route_present":
                predicate_ok = bool(present)
            else:
                predicate_ok = not bool(present)

            observed_state = {
                "norm_prefix": norm_prefix,
                "present": present,
                "observed_prefixes": list(observed_prefixes or []),
            }
            evidence = {
                "cmd": "vtysh -c 'show ip route json'",
                "rc": rc,
            }
            return vtysh_ok, predicate_ok, observed_state, evidence

        if inv_type == "bgp_med_equals":
            norm_prefix = str(t.get("_norm_prefix") or "").strip()
            cp = rt.exec(
                lab,
                src,
                ["vtysh", "-c", f"show ip bgp {norm_prefix} json"],
                check=False,
                capture_output=True,
            )

            if isinstance(cp, str):
                out = cp
                rc = None
            else:
                out = getattr(cp, "stdout", "") or getattr(cp, "output", "") or ""
                if isinstance(out, (bytes, bytearray)):
                    try:
                        out = out.decode("utf-8", errors="replace")
                    except Exception:
                        out = str(out)
                rc = getattr(cp, "returncode", None)

            vtysh_ok = (rc in (0, None))

            parse_error = ""
            observed_med = None
            empty_first_doc = (str(out or "").strip() in ("", "{}"))

            try:
                doc = json.loads(str(out or "").strip()) if str(out or "").strip() else {}
                route_obj = None

                if isinstance(doc, dict):
                    cand = doc.get(norm_prefix)
                    if isinstance(cand, list) and cand:
                        route_obj = cand[0]
                    elif isinstance(cand, dict):
                        route_obj = cand
                    elif (
                        doc.get("prefix") is not None
                        and (_normalize_prefix(str(doc.get("prefix"))) or str(doc.get("prefix"))) == norm_prefix
                    ):
                        route_obj = doc
                    else:
                        routes = doc.get("routes")
                        if isinstance(routes, dict):
                            cand = routes.get(norm_prefix)
                            if isinstance(cand, list) and cand:
                                route_obj = cand[0]
                            elif isinstance(cand, dict):
                                route_obj = cand
                            else:
                                for k, v in routes.items():
                                    nk = _normalize_prefix(str(k)) or str(k)
                                    if nk != norm_prefix:
                                        continue
                                    if isinstance(v, list) and v:
                                        route_obj = v[0]
                                        break
                                    if isinstance(v, dict):
                                        route_obj = v
                                        break
                        if route_obj is None:
                            for k, v in doc.items():
                                nk = _normalize_prefix(str(k)) or str(k)
                                if nk != norm_prefix:
                                    continue
                                if isinstance(v, list) and v:
                                    route_obj = v[0]
                                    break
                                if isinstance(v, dict):
                                    route_obj = v
                                    break
                else:
                    raise ValueError("unexpected_bgp_prefix_json_shape")

                if not isinstance(route_obj, dict):
                    parse_error = "prefix not present in bgp json"
                else:
                    for key in ("med", "metric"):
                        val = route_obj.get(key)
                        if val is None or str(val).strip() == "":
                            continue
                        try:
                            observed_med = int(val)
                            break
                        except Exception:
                            continue

                    if observed_med is None:
                        paths = route_obj.get("paths")
                        if isinstance(paths, list):
                            for path in paths:
                                if not isinstance(path, dict):
                                    continue
                                for key in ("med", "metric"):
                                    val = path.get(key)
                                    if val is None or str(val).strip() == "":
                                        continue
                                    try:
                                        observed_med = int(val)
                                        break
                                    except Exception:
                                        continue
                                if observed_med is not None:
                                    break

                    if observed_med is None:
                        parse_error = "med not present in bgp json"
            except Exception as e:
                parse_error = str(e)

            predicate_ok = (observed_med is not None)

            observed_state = {
                "norm_prefix": norm_prefix,
                "observed_med": observed_med,
            }
            evidence = {
                "cmd": f"vtysh -c 'show ip bgp {norm_prefix} json'",
                "rc": rc,
                "parse_error": parse_error,
                "empty_first_doc": empty_first_doc,
            }
            return vtysh_ok, predicate_ok, observed_state, evidence

        if inv_type in ("evpn_mac_route_present", "evpn_mac_route_absent", "evpn_vni_route_present"):
            mac = str(t.get("_mac") or "").strip().lower()
            vni_i = t.get("_vni_i")
            cp = rt.exec(
                lab,
                src,
                ["vtysh", "-c", "show bgp l2vpn evpn route json"],
                check=False,
                capture_output=True,
            )

            if isinstance(cp, str):
                out = cp
                rc = None
            else:
                out = getattr(cp, "stdout", "") or getattr(cp, "output", "") or ""
                if isinstance(out, (bytes, bytearray)):
                    try:
                        out = out.decode("utf-8", errors="replace")
                    except Exception:
                        out = str(out)
                rc = getattr(cp, "returncode", None)

            vtysh_ok = (rc in (0, None))

            raw = str(out or "").strip()
            evidence_entries: list = []
            present = False
            parse_error = ""

            def _append_entry(mac_val, vni_val, state_val):
                nonlocal present
                rec = {
                    "mac": str(mac_val or "").strip().lower(),
                    "vni": vni_val,
                    "route_type": state_val,
                    "node": src,
                }
                if inv_type in ("evpn_mac_route_present", "evpn_mac_route_absent") and not rec["mac"]:
                    return
                evidence_entries.append(rec)
                if inv_type == "evpn_vni_route_present":
                    if rec["vni"] == vni_i:
                        present = True
                else:
                    if rec["mac"] == mac and rec["vni"] == vni_i:
                        if state_val is None or str(state_val).lower() in ("2", "2-evpn", "macip", "type2"):
                            present = True

            try:
                doc = json.loads(raw) if raw else {}
                seen = set()

                if isinstance(doc, dict):
                    for rd_key, rd_val in doc.items():
                        if rd_key in ("numPrefix", "numPaths"):
                            continue
                        if not isinstance(rd_val, dict):
                            continue

                        vni_ctx = None
                        m_rt = re.search(r"RT:\d+:(\d+)", json.dumps(rd_val), flags=re.IGNORECASE)
                        if m_rt:
                            try:
                                vni_ctx = int(m_rt.group(1))
                            except Exception:
                                vni_ctx = None

                        for prefix_key, prefix_val in rd_val.items():
                            if prefix_key == "rd":
                                continue
                            if not isinstance(prefix_val, dict):
                                continue
                            for path_group in list(prefix_val.get("paths") or []):
                                if not isinstance(path_group, list):
                                    continue
                                for entry in path_group:
                                    if not isinstance(entry, dict):
                                        continue

                                    mac_val = None
                                    for key in ("mac", "macAddr", "macaddr"):
                                        val = entry.get(key)
                                        if isinstance(val, str) and val.strip():
                                            mac_val = val.strip().lower()
                                            break

                                    vni_val = None
                                    for key in ("vni",):
                                        val = entry.get(key)
                                        if val is None or str(val).strip() == "":
                                            continue
                                        try:
                                            vni_val = int(val)
                                            break
                                        except Exception:
                                            continue
                                    if vni_val is None:
                                        vni_val = vni_ctx

                                    state_val = entry.get("routeType")
                                    if state_val is None:
                                        state_val = entry.get("type")
                                    if isinstance(state_val, str):
                                        state_val = state_val.strip()

                                    if inv_type == "evpn_vni_route_present" and vni_val is None:
                                        continue
                                    if inv_type in ("evpn_mac_route_present", "evpn_mac_route_absent") and not mac_val:
                                        continue

                                    sig = (mac_val, vni_val, state_val, src)
                                    if sig in seen:
                                        continue
                                    seen.add(sig)
                                    _append_entry(mac_val, vni_val, state_val)
                else:
                    raise ValueError("unexpected_evpn_json_shape")

            except Exception as e:
                parse_error = str(e)

            predicate_ok = bool(present)

            observed_state = {
                "mac": mac,
                "vni_i": vni_i,
                "present": present,
                "evidence_entries": evidence_entries,
            }
            evidence = {
                "cmd": "vtysh -c 'show bgp l2vpn evpn route json'",
                "rc": rc,
                "parse_error": parse_error,
            }
            return vtysh_ok, predicate_ok, observed_state, evidence

        if inv_type in ("route_advertised_to", "route_not_advertised_to"):
            node = str(t.get("node") or "")
            peer_ip = str(t.get("_peer_ip") or "").strip()
            prefix = str(t.get("_norm_prefix") or "").strip()

            cp = rt.exec(
                lab,
                node,
                ["vtysh", "-c", f"show ip bgp neighbor {peer_ip} advertised-routes json"],
                check=False,
            )
            out = cp.stdout or ""
            rc = cp.returncode
            if isinstance(out, (bytes, bytearray)):
                try:
                    out = out.decode("utf-8", errors="replace")
                except Exception:
                    out = str(out)

            vtysh_ok = (rc == 0)

            raw = str(out or "").strip()
            parse_error = ""
            advertised_prefixes: list = []

            def _collect_adv_prefixes(obj):
                found = []
                if isinstance(obj, dict):
                    for container_key in ("advertisedRoutes", "routes"):
                        container = obj.get(container_key)
                        if isinstance(container, dict):
                            for k, v in container.items():
                                if isinstance(v, (dict, list)):
                                    nk = _normalize_prefix(str(k)) or str(k)
                                    if nk:
                                        found.append(nk)
                    for k, v in obj.items():
                        if isinstance(v, (dict, list)):
                            nk = _normalize_prefix(str(k)) or str(k)
                            if nk and "/" in nk:
                                found.append(nk)
                    for key in ("prefix", "network"):
                        val = obj.get(key)
                        nk = _normalize_prefix(str(val)) or str(val or "")
                        if nk:
                            found.append(nk)
                    paths = obj.get("paths")
                    if isinstance(paths, list):
                        for path in paths:
                            found.extend(_collect_adv_prefixes(path))
                elif isinstance(obj, list):
                    for item in obj:
                        found.extend(_collect_adv_prefixes(item))
                return found

            try:
                doc = json.loads(raw) if raw else {}
                advertised_prefixes = sorted(set(_collect_adv_prefixes(doc)))
            except Exception as e:
                parse_error = str(e)

            present = prefix in advertised_prefixes

            if inv_type == "route_advertised_to":
                predicate_ok = bool(present)
            else:
                predicate_ok = not bool(present)

            observed_state = {
                "norm_prefix": prefix,
                "present": present,
                "advertised_prefixes": advertised_prefixes,
            }
            evidence = {
                "cmd": f"vtysh -c 'show ip bgp neighbor {peer_ip} advertised-routes json'",
                "rc": rc,
                "parse_error": parse_error,
            }
            return vtysh_ok, predicate_ok, observed_state, evidence

        if inv_type == "bgp_localpref_equals":
            node = str(t.get("node") or "")
            prefix = str(t.get("_norm_prefix") or "").strip()

            cp = rt.exec(lab, node, ["vtysh", "-c", f"show ip bgp {prefix} json"], check=False)
            out = cp.stdout or ""
            rc = cp.returncode
            if isinstance(out, (bytes, bytearray)):
                try:
                    out = out.decode("utf-8", errors="replace")
                except Exception:
                    out = str(out)

            vtysh_ok = (rc == 0)

            parse_error = ""
            observed_localpref = None
            try:
                doc = json.loads(str(out or "").strip()) if str(out or "").strip() else {}
                route_obj = None
                if isinstance(doc, dict):
                    cand = doc.get(prefix)
                    if isinstance(cand, list) and cand:
                        route_obj = cand[0]
                    elif isinstance(cand, dict):
                        route_obj = cand
                    elif (
                        doc.get("prefix") is not None
                        and (_normalize_prefix(str(doc.get("prefix"))) or str(doc.get("prefix"))) == prefix
                    ):
                        route_obj = doc
                    else:
                        routes = doc.get("routes")
                        if isinstance(routes, dict):
                            cand = routes.get(prefix)
                            if isinstance(cand, list) and cand:
                                route_obj = cand[0]
                            elif isinstance(cand, dict):
                                route_obj = cand
                            else:
                                for k, v in routes.items():
                                    nk = _normalize_prefix(str(k)) or str(k)
                                    if nk != prefix:
                                        continue
                                    if isinstance(v, list) and v:
                                        route_obj = v[0]
                                        break
                                    if isinstance(v, dict):
                                        route_obj = v
                                        break
                        if route_obj is None:
                            for k, v in doc.items():
                                nk = _normalize_prefix(str(k)) or str(k)
                                if nk != prefix:
                                    continue
                                if isinstance(v, list) and v:
                                    route_obj = v[0]
                                    break
                                if isinstance(v, dict):
                                    route_obj = v
                                    break
                else:
                    raise ValueError("unexpected_bgp_prefix_json_shape")

                if not isinstance(route_obj, dict):
                    parse_error = "prefix not present in bgp json"
                else:
                    for key in ("locPrf", "localpref", "localPref", "local_preference"):
                        val = route_obj.get(key)
                        if val is None or str(val).strip() == "":
                            continue
                        try:
                            observed_localpref = int(val)
                            break
                        except Exception:
                            continue

                    if observed_localpref is None:
                        paths = route_obj.get("paths")
                        if isinstance(paths, list):
                            for path in paths:
                                if not isinstance(path, dict):
                                    continue
                                for key in ("locPrf", "localpref", "localPref", "local_preference"):
                                    val = path.get(key)
                                    if val is None or str(val).strip() == "":
                                        continue
                                    try:
                                        observed_localpref = int(val)
                                        break
                                    except Exception:
                                        continue
                                if observed_localpref is not None:
                                    break

                    if observed_localpref is None:
                        parse_error = "localpref not present in bgp json"
            except Exception as e:
                parse_error = str(e)

            predicate_ok = (observed_localpref is not None)

            observed_state = {
                "norm_prefix": prefix,
                "observed_localpref": observed_localpref,
            }
            evidence = {
                "cmd": f"vtysh -c 'show ip bgp {prefix} json'",
                "rc": rc,
                "parse_error": parse_error,
            }
            return vtysh_ok, predicate_ok, observed_state, evidence

        if inv_type == "ospf_neighbor_up":
            # H4: OSPF neighbor-state evaluator (REQ-H4-7 / B07).
            # FRR JSON shape: {"neighbors": {"<router-id>": [{"nbrState": ...}]}}.
            # Neighbor key is the OSPF router-ID literal (validated as IPv4
            # at WI-1). FSM state may carry a role qualifier suffix
            # ("Full/DR", "Full/Backup", "Full/DROther", "2-Way/DROther");
            # the parser splits on '/' and maps to D-1's closed declarable
            # set, with any outside-set literal mapped to "Unknown" with
            # empty last_error per B07.
            neighbor = str(t.get("neighbor") or "").strip()
            cp = rt.exec(lab, src, ["vtysh", "-c", "show ip ospf neighbor json"], check=False)
            vtysh_ok = (getattr(cp, "returncode", 1) == 0)
            out = (cp.stdout or "") if hasattr(cp, "stdout") else ""

            declarable_states = (
                "Down",
                "Attempt",
                "Init",
                "2-Way",
                "ExStart",
                "Exchange",
                "Loading",
                "Full",
            )
            observed_state_str: str = "Unknown"
            last_error: str = ""
            parse_error: str = ""
            neighbor_present: bool = False

            if vtysh_ok:
                try:
                    data = json.loads(out or "{}")
                    nbrs = data.get("neighbors")
                    if isinstance(nbrs, dict):
                        if not nbrs:
                            observed_state_str = "NotConfigured"
                            last_error = "ospf neighbor table empty"
                            parse_error = "ospf neighbor table empty"
                        else:
                            entries = nbrs.get(neighbor)
                            if isinstance(entries, list) and entries:
                                first = entries[0] if isinstance(entries[0], dict) else None
                                if isinstance(first, dict):
                                    neighbor_present = True
                                    raw_state = first.get("nbrState")
                                    if raw_state:
                                        base = str(raw_state).split("/", 1)[0].strip()
                                        if base in declarable_states:
                                            observed_state_str = base
                                        else:
                                            observed_state_str = "Unknown"
                                            last_error = ""
                            else:
                                observed_state_str = "NotConfigured"
                                last_error = "neighbor not present in ospf neighbor table"
                                parse_error = "neighbor not present in ospf neighbor table"
                    else:
                        observed_state_str = "NotConfigured"
                        last_error = "ospf neighbor table empty"
                        parse_error = "ospf neighbor table empty"
                except Exception:
                    observed_state_str = "Unknown"
                    last_error = "vtysh output not parseable as JSON"
                    parse_error = "vtysh output not parseable as JSON"
            else:
                observed_state_str = "Unknown"
                last_error = "vtysh command failed"
                parse_error = "vtysh command failed"

            # Predicate: neighbor present AND observed FSM state matches the
            # declared expected state. Test record's 'state' is defaulted to
            # "Full" by WI-2 per LD-2 if omitted.
            expected_state = str(t.get("state") or "Full").strip()
            predicate_ok = bool(neighbor_present and observed_state_str == expected_state)

            observed_state = {
                "neighbor_present": neighbor_present,
                "state": observed_state_str,
                "last_error": last_error,
                "expected_state": expected_state,
            }
            evidence = {
                "cmd": "vtysh -c 'show ip ospf neighbor json'",
                "parse_error": parse_error,
                "returncode": getattr(cp, "returncode", None),
            }
            return vtysh_ok, predicate_ok, observed_state, evidence

        # WI-1 Repair Set complete: all 12 invariant types now wire through
        # this helper. This fallback is reached only if a new invariant type
        # is added to the type-system without being wired here; in that
        # case raising surfaces the omission deterministically rather than
        # silently returning an incorrect result.
        raise NotImplementedError(
            f"_evaluate_invariant_attempt: inv_type={inv_type!r} is not implemented "
            f"in the shared invariant evaluator. Add a new branch to wire it."
        )

    def run_invariant_test(*, test_name: str, src: str, t: dict, record_fn=record_test) -> str:
        inv_type = str(t.get("type") or "").strip().lower()
        expected = str(t.get("expect") or "pass").strip().lower()
        if expected not in ("pass", "fail"):
            expected = "pass"

        start = time.time()

        if inv_type == "evpn_bgp_session_up":
            peer = str(t.get("peer") or "").strip()
            if not peer:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=src,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="evpn_bgp_session_up requires peer",
                    evidence={"reason": "missing_peer"},
                    meta={"type": inv_type, "peer": peer},
                )
                return "fail"

            _vtysh_ok, predicate_ok, last_state, last_evidence = (
                _evaluate_invariant_attempt(inv_type="evpn_bgp_session_up", t=t, src=src)
            )

            rc = last_evidence.get("rc")
            parse_error = str(last_evidence.get("parse_error") or "")
            evidence_entries = list(last_evidence.get("neighbors") or [])
            present = bool(last_state.get("present"))

            if rc not in (0, None):
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=src,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="unsupported EVPN BGP-session evidence provider capability",
                    evidence={
                        "cmd": "vtysh -c 'show bgp l2vpn evpn summary json'",
                        "rc": rc,
                    },
                    meta={
                        "type": inv_type,
                        "peer": peer,
                        "misuse": True,
                    },
                )
                raise SystemExit(2)

            if parse_error and not evidence_entries:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=src,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="unsupported EVPN BGP-session evidence normalization",
                    evidence={
                        "cmd": "vtysh -c 'show bgp l2vpn evpn summary json'",
                        "rc": rc,
                    },
                    meta={
                        "type": inv_type,
                        "peer": peer,
                        "misuse": True,
                    },
                )
                raise SystemExit(2)

            observed = "pass" if present else "fail"
            verdict = "pass" if observed == expected else "fail"

            observed_state_payload = None
            if verdict == "fail":
                state_value = "Unknown"
                last_reset_reason_value = ""
                for _e in evidence_entries:
                    if not isinstance(_e, dict):
                        continue
                    if str(_e.get("peerName") or "") == peer:
                        st = str(_e.get("state") or "").strip()
                        if st:
                            state_value = st
                        break
                observed_state_payload = {
                    "type": "evpn_bgp_session_up",
                    "peer": peer,
                    "state": state_value,
                    "last_reset_reason": last_reset_reason_value,
                    "source_node": src,
                }
                if parse_error:
                    observed_state_payload["parse_error"] = str(parse_error)

            record_fn(
                name=test_name,
                kind="invariant",
                src=src,
                dst="",
                expected=expected,
                observed=observed,
                verdict=verdict,
                duration_ms=int((time.time() - start) * 1000),
                error="" if verdict == "pass" else f"{inv_type} mismatch (expected {expected}, observed {observed})",
                evidence={
                    "cmd": "vtysh -c 'show bgp l2vpn evpn summary json'",
                    "rc": rc,
                    "neighbors": evidence_entries,
                },
                meta={
                    "type": inv_type,
                    "peer": peer,
                    "present": bool(present),
                    "observed_neighbor_count": len(evidence_entries),
                },
                observed_state=observed_state_payload,
            )
            return verdict

        if inv_type in ("route_present", "route_absent", "bgp_med_equals"):
            prefix = str(t.get("prefix") or "").strip()
            if not prefix:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=src,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error=f"{inv_type} requires prefix",
                    evidence={"reason": "missing_prefix"},
                    meta={"type": inv_type, "prefix": prefix},
                )
                return "fail"

            norm_prefix = _normalize_prefix(prefix) or prefix

            if inv_type == "bgp_med_equals":
                exp_med = t.get("expected")
                if exp_med is None or str(exp_med).strip() == "":
                    record_fn(
                        name=test_name,
                        kind="invariant",
                        src=src,
                        dst="",
                        expected=expected,
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error=f"{inv_type} requires expected",
                        evidence={"reason": "missing_expected"},
                        meta={"type": inv_type, "prefix": prefix},
                    )
                    return "fail"

                try:
                    exp_med_i = int(exp_med)
                except Exception:
                    record_fn(
                        name=test_name,
                        kind="invariant",
                        src=src,
                        dst="",
                        expected=expected,
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error=f"{inv_type}.expected must be an integer",
                        evidence={"reason": "invalid_expected"},
                        meta={"type": inv_type, "prefix": prefix, "expected": exp_med},
                    )
                    return "fail"

                t["_norm_prefix"] = norm_prefix
                _vtysh_ok, _pred_ok, last_state, last_evidence = (
                    _evaluate_invariant_attempt(inv_type="bgp_med_equals", t=t, src=src)
                )
                rc = last_evidence.get("rc")
                parse_error = str(last_evidence.get("parse_error") or "")
                observed_med = last_state.get("observed_med")
                empty_first_doc = bool(last_evidence.get("empty_first_doc"))

                if rc not in (0, None):
                    record_fn(
                        name=test_name,
                        kind="invariant",
                        src=src,
                        dst="",
                        expected=expected,
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error="unsupported BGP MED evidence provider capability",
                        evidence={
                            "cmd": f"vtysh -c 'show ip bgp {norm_prefix} json'",
                            "rc": rc,
                        },
                        meta={
                            "type": inv_type,
                            "prefix": norm_prefix,
                            "misuse": True,
                        },
                    )
                    raise SystemExit(2)

                if observed_med is None and empty_first_doc:
                    time.sleep(2)
                    _vtysh_ok2, _pred_ok2, last_state2, last_evidence2 = (
                        _evaluate_invariant_attempt(inv_type="bgp_med_equals", t=t, src=src)
                    )
                    if last_state2.get("observed_med") is not None:
                        last_state = last_state2
                        last_evidence = last_evidence2
                        rc = last_evidence.get("rc")
                        parse_error = str(last_evidence.get("parse_error") or "")
                        observed_med = last_state.get("observed_med")

                if observed_med is None:
                    record_fn(
                        name=test_name,
                        kind="invariant",
                        src=src,
                        dst="",
                        expected=expected,
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error="unsupported BGP MED evidence normalization",
                        evidence={
                            "cmd": f"vtysh -c 'show ip bgp {norm_prefix} json'",
                            "rc": rc,
                            "parse_error": parse_error,
                        },
                        meta={
                            "type": inv_type,
                            "prefix": norm_prefix,
                            "misuse": True,
                        },
                    )
                    raise SystemExit(2)

                observed = "pass" if observed_med == exp_med_i else "fail"
                verdict = "pass" if observed == expected else "fail"

                observed_state_payload = None
                if verdict == "fail":
                    observed_state_payload = {
                        "type": "bgp_med_equals",
                        "prefix": norm_prefix,
                        "peer": "",
                        "expected_med": int(exp_med_i),
                        "actual_med": int(observed_med) if observed_med is not None else None,
                        "source_node": src,
                    }
                    if parse_error:
                        observed_state_payload["parse_error"] = str(parse_error)

                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=src,
                    dst="",
                    expected=expected,
                    observed=observed,
                    verdict=verdict,
                    duration_ms=int((time.time() - start) * 1000),
                    error="" if verdict == "pass" else f"{inv_type} mismatch (expected {expected}, observed {observed})",
                    evidence={
                        "cmd": f"vtysh -c 'show ip bgp {norm_prefix} json'",
                        "rc": rc,
                        "prefix": norm_prefix,
                        "med": observed_med,
                    },
                    meta={
                        "type": inv_type,
                        "prefix": norm_prefix,
                        "expected_value": exp_med_i,
                        "observed_value": observed_med,
                    },
                    observed_state=observed_state_payload,
                )
                return verdict

            t["_norm_prefix"] = norm_prefix
            _vtysh_ok, _pred_ok, last_state, last_evidence = (
                _evaluate_invariant_attempt(inv_type=inv_type, t=t, src=src)
            )
            rc = last_evidence.get("rc")
            present = bool(last_state.get("present"))
            observed_prefixes = list(last_state.get("observed_prefixes") or [])

            if inv_type == "route_present":
                observed = "pass" if present else "fail"
            else:
                observed = "pass" if not present else "fail"

            verdict = "pass" if observed == expected else "fail"

            observed_state_payload = None
            if verdict == "fail":
                if inv_type == "route_present":
                    routes_value: list = []
                else:
                    routes_value = [
                        {
                            "prefix": norm_prefix,
                            "next_hop": "",
                            "protocol": "",
                            "metric": None,
                            "as_path": "",
                        }
                    ] if present else []
                observed_state_payload = {
                    "type": inv_type,
                    "prefix": norm_prefix,
                    "routes": routes_value,
                    "source_node": src,
                }

            record_fn(
                name=test_name,
                kind="invariant",
                src=src,
                dst="",
                expected=expected,
                observed=observed,
                verdict=verdict,
                duration_ms=int((time.time() - start) * 1000),
                error="" if verdict == "pass" else f"{inv_type} mismatch (expected {expected}, observed {observed})",
                evidence={
                    "cmd": "vtysh -c 'show ip route json'",
                    "rc": rc,
                },
                meta={
                    "type": inv_type,
                    "prefix": norm_prefix,
                    "present": bool(present),
                    "observed_prefix_count": len(set(observed_prefixes or [])),
                },
                observed_state=observed_state_payload,
            )
            return verdict

        if inv_type in ("evpn_mac_route_present", "evpn_mac_route_absent", "evpn_vni_route_present"):
            mac = str(t.get("mac") or "").strip().lower()
            vni = t.get("vni")
            try:
                vni_i = int(vni)
            except Exception:
                vni_i = None

            if inv_type in ("evpn_mac_route_present", "evpn_mac_route_absent"):
                if not mac or vni_i is None:
                    record_fn(
                        name=test_name,
                        kind="invariant",
                        src=src,
                        dst="",
                        expected=expected,
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error=f"{inv_type} requires mac and vni",
                        evidence={"reason": "missing_mac_or_vni"},
                        meta={"type": inv_type, "mac": mac, "vni": vni},
                    )
                    return "fail"
            else:
                if vni_i is None:
                    record_fn(
                        name=test_name,
                        kind="invariant",
                        src=src,
                        dst="",
                        expected=expected,
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error=f"{inv_type} requires vni",
                        evidence={"reason": "missing_vni"},
                        meta={"type": inv_type, "vni": vni},
                    )
                    return "fail"

            t["_mac"] = mac
            t["_vni_i"] = vni_i
            _vtysh_ok, _pred_ok, last_state, last_evidence = (
                _evaluate_invariant_attempt(inv_type=inv_type, t=t, src=src)
            )
            rc = last_evidence.get("rc")
            parse_error = str(last_evidence.get("parse_error") or "")
            evidence_entries = list(last_state.get("evidence_entries") or [])
            present = bool(last_state.get("present"))

            if rc not in (0, None):
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=src,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="unsupported EVPN VNI/MAC-route evidence provider capability",
                    evidence={
                        "cmd": "vtysh -c 'show bgp l2vpn evpn route json'",
                        "rc": rc,
                    },
                    meta={
                        "type": inv_type,
                        "mac": mac,
                        "vni": vni_i,
                        "misuse": True,
                    },
                )
                raise SystemExit(2)

            if not present and inv_type in ("evpn_mac_route_present", "evpn_mac_route_absent"):
                cp_text = rt.exec(
                    lab,
                    src,
                    ["vtysh", "-c", "show bgp l2vpn evpn route"],
                    check=False,
                    capture_output=True,
                )

                if isinstance(cp_text, str):
                    out_text = cp_text
                    rc_text = None
                else:
                    out_text = getattr(cp_text, "stdout", "") or getattr(cp_text, "output", "") or ""
                    if isinstance(out_text, (bytes, bytearray)):
                        try:
                            out_text = out_text.decode("utf-8", errors="replace")
                        except Exception:
                            out_text = str(out_text)
                    rc_text = getattr(cp_text, "returncode", None)

                if rc_text not in (0, None):
                    record_fn(
                        name=test_name,
                        kind="invariant",
                        src=src,
                        dst="",
                        expected=expected,
                        observed="fail",
                        verdict="fail",
                        duration_ms=0,
                        error="unsupported EVPN VNI/MAC-route evidence provider capability",
                        evidence={
                            "cmd": "vtysh -c 'show bgp l2vpn evpn route'",
                            "rc": rc_text,
                            "json_rc": rc,
                        },
                        meta={
                            "type": inv_type,
                            "mac": mac,
                            "vni": vni_i,
                            "misuse": True,
                        },
                    )
                    raise SystemExit(2)

                try:
                    import re as _re

                    text = str(out_text or "")
                    for line in text.splitlines():
                        m = _re.search(r"\[2\]:\[0\]:\[48\]:\[([0-9a-f:]{17})\]", line, flags=_re.IGNORECASE)
                        if not m:
                            continue
                        mac_val = m.group(1).lower()
                        rec = {
                            "mac": str(mac_val or "").strip().lower(),
                            "vni": vni_i,
                            "route_type": "2",
                            "node": src,
                        }
                        if not rec["mac"]:
                            continue
                        evidence_entries.append(rec)
                        if rec["mac"] == mac and rec["vni"] == vni_i:
                            present = True
                except Exception as e:
                    if parse_error:
                        parse_error = f"{parse_error}; text_parse={e}"
                    else:
                        parse_error = f"text_parse={e}"

            if parse_error and not evidence_entries:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=src,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="unsupported EVPN VNI/MAC-route evidence normalization",
                    evidence={
                        "cmd": "vtysh -c 'show bgp l2vpn evpn route json'",
                        "rc": rc,
                    },
                    meta={
                        "type": inv_type,
                        "mac": mac,
                        "vni": vni_i,
                        "misuse": True,
                    },
                )
                raise SystemExit(2)

            dedup = {}
            for rec in evidence_entries:
                sig = (
                    rec.get("mac"),
                    rec.get("vni"),
                    rec.get("route_type"),
                    rec.get("node"),
                )
                dedup[sig] = rec
            evidence_entries = sorted(
                dedup.values(),
                key=lambda x: (
                    str(x.get("mac") or ""),
                    -1 if x.get("vni") is None else int(x.get("vni")),
                    str(x.get("route_type") or ""),
                    str(x.get("node") or ""),
                ),
            )

            if inv_type == "evpn_mac_route_present":
                observed = "pass" if present else "fail"
            elif inv_type == "evpn_mac_route_absent":
                observed = "pass" if not present else "fail"
            else:
                observed = "pass" if present else "fail"

            verdict = "pass" if observed == expected else "fail"

            observed_state_payload = None
            if verdict == "fail":
                # WI-1 Patch 4 (D06): Filter observed_state.evpn_routes to
                # MACs declared as host node `mac:` fields in the resolved
                # topology. The existing evidence_entries collection
                # captures every MAC the EVPN substrate has learned in its
                # type-2 routes, which under containerlab includes
                # auto-allocated veth MACs that vary across runs. Those
                # tokens are explicitly disallowed from observed_state's
                # required keys per the determinism surface declared in the
                # handover (D06: "environmental nondeterminism MUST NOT
                # enter observed_state's required keys. Such tokens MAY
                # appear in the existing evidence channel"). The unfiltered
                # list remains in `evidence` (the supporting evidence
                # channel that already tolerates non-determinism); only the
                # observed_state surface is filtered.
                _declared_host_macs: set[str] = set()
                for _n in (topo.get("nodes") or []):
                    if not isinstance(_n, dict):
                        continue
                    if str(_n.get("type") or "") != "host":
                        continue
                    _m = _n.get("mac")
                    if isinstance(_m, str) and _m.strip():
                        _declared_host_macs.add(_m.strip().lower())

                evpn_routes_value: list = []
                for _e in evidence_entries:
                    if not isinstance(_e, dict):
                        continue
                    _e_mac = str(_e.get("mac") or "").strip().lower()
                    if _e_mac and _e_mac not in _declared_host_macs:
                        continue
                    evpn_routes_value.append(
                        {
                            "rd": "",
                            "prefix": "",
                            "mac": str(_e.get("mac") or ""),
                            "vni": _e.get("vni"),
                            "route_type": _e.get("route_type"),
                        }
                    )
                if inv_type == "evpn_vni_route_present":
                    observed_state_payload = {
                        "type": "evpn_vni_route_present",
                        "vni": int(vni_i) if vni_i is not None else None,
                        "evpn_routes": evpn_routes_value,
                        "source_node": src,
                    }
                else:
                    observed_state_payload = {
                        "type": inv_type,
                        "mac": mac,
                        "vni": int(vni_i) if vni_i is not None else None,
                        "evpn_routes": evpn_routes_value,
                        "source_node": src,
                    }
                if parse_error:
                    observed_state_payload["parse_error"] = str(parse_error)

            record_fn(
                name=test_name,
                kind="invariant",
                src=src,
                dst="",
                expected=expected,
                observed=observed,
                verdict=verdict,
                duration_ms=int((time.time() - start) * 1000),
                error="" if verdict == "pass" else f"{inv_type} mismatch (expected {expected}, observed {observed})",
                evidence={
                    "cmd": "vtysh -c 'show bgp l2vpn evpn route json'",
                    "rc": rc,
                    "routes": evidence_entries,
                },
                meta={
                    "type": inv_type,
                    "mac": mac,
                    "vni": vni_i,
                    "present": bool(present),
                    "observed_route_count": len(evidence_entries),
                },
                observed_state=observed_state_payload,
            )
            return verdict

        if inv_type in ("route_advertised_to", "route_not_advertised_to"):
            node = str(t.get("node") or "")
            peer = str(t.get("peer") or "").strip()
            prefix = _normalize_prefix(str(t.get("prefix") or ""))

            if not peer:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=node,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error=f"{inv_type} requires peer",
                    evidence={"reason": "missing_peer"},
                    meta={"type": inv_type, "prefix": prefix},
                )
                return "fail"

            peer_ips = []
            for link in (topo.get("links") or []):
                endpoints = list(link.get("endpoints") or [])
                if len(endpoints) != 2:
                    continue
                try:
                    a_node, _ = str(endpoints[0]).split(":", 1)
                    b_node, _ = str(endpoints[1]).split(":", 1)
                except Exception:
                    continue
                ips = list(link.get("ipv4") or [])
                if len(ips) != 2:
                    continue
                if a_node == node and b_node == peer:
                    try:
                        peer_ips.append(str(ipaddress.ip_interface(ips[1]).ip))
                    except Exception:
                        continue
                elif b_node == node and a_node == peer:
                    try:
                        peer_ips.append(str(ipaddress.ip_interface(ips[0]).ip))
                    except Exception:
                        continue

            peer_ips = sorted(set(peer_ips))
            if not peer_ips:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=node,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="unsupported route advertisement peer mapping",
                    evidence={"reason": "unsupported_peer_mapping", "peer": peer},
                    meta={"type": inv_type, "prefix": prefix, "peer": peer, "misuse": True},
                )
                raise SystemExit(2)

            t["_peer_ip"] = peer_ips[0]
            t["_norm_prefix"] = prefix
            _vtysh_ok, _pred_ok, last_state, last_evidence = (
                _evaluate_invariant_attempt(inv_type=inv_type, t=t, src=node)
            )
            rc = last_evidence.get("rc")
            parse_error = str(last_evidence.get("parse_error") or "")
            advertised_prefixes = list(last_state.get("advertised_prefixes") or [])
            present = bool(last_state.get("present"))

            if rc != 0:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=node,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="unsupported route advertisement evidence provider capability",
                    evidence={
                        "cmd": f"vtysh -c 'show ip bgp neighbor {peer_ips[0]} advertised-routes json'",
                        "rc": rc,
                    },
                    meta={
                        "type": inv_type,
                        "prefix": prefix,
                        "peer": peer,
                        "misuse": True,
                    },
                )
                raise SystemExit(2)

            if parse_error and not advertised_prefixes:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=node,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="unsupported route advertisement evidence normalization",
                    evidence={
                        "cmd": f"vtysh -c 'show ip bgp neighbor {peer_ips[0]} advertised-routes json'",
                        "rc": rc,
                        "parse_error": parse_error,
                    },
                    meta={
                        "type": inv_type,
                        "prefix": prefix,
                        "peer": peer,
                        "misuse": True,
                    },
                )
                raise SystemExit(2)

            observed = "pass" if present else "fail"
            if inv_type == "route_not_advertised_to":
                observed = "pass" if not present else "fail"
            verdict = "pass" if observed == expected else "fail"

            observed_state_payload = None
            if verdict == "fail":
                if inv_type == "route_advertised_to":
                    advertised_routes_value: list = [
                        {
                            "prefix": _p,
                            "next_hop": "",
                            "protocol": "",
                            "metric": None,
                            "as_path": "",
                        }
                        for _p in advertised_prefixes
                    ]
                    observed_state_payload = {
                        "type": "route_advertised_to",
                        "prefix": prefix,
                        "peer": peer,
                        "advertised_routes": advertised_routes_value,
                        "none_advertised": (len(advertised_routes_value) == 0),
                        "source_node": node,
                    }
                else:
                    advertised_routes_value = [
                        {
                            "prefix": prefix,
                            "next_hop": "",
                            "protocol": "",
                            "metric": None,
                            "as_path": "",
                        }
                    ] if present else []
                    observed_state_payload = {
                        "type": "route_not_advertised_to",
                        "prefix": prefix,
                        "peer": peer,
                        "advertised_routes": advertised_routes_value,
                        "source_node": node,
                    }
                if parse_error:
                    observed_state_payload["parse_error"] = str(parse_error)

            record_fn(
                name=test_name,
                kind="invariant",
                src=node,
                dst="",
                expected=expected,
                observed=observed,
                verdict=verdict,
                duration_ms=int((time.time() - start) * 1000),
                error="" if verdict == "pass" else f"{inv_type} mismatch (expected {expected}, observed {observed})",
                evidence={
                    "cmd": f"vtysh -c 'show ip bgp neighbor {peer_ips[0]} advertised-routes json'",
                    "rc": rc,
                    "prefixes": advertised_prefixes,
                },
                meta={
                    "type": inv_type,
                    "prefix": prefix,
                    "peer": peer,
                    "present": bool(present),
                    "observed_prefix_count": len(advertised_prefixes),
                },
                observed_state=observed_state_payload,
            )
            return verdict

        if inv_type == "bgp_localpref_equals":
            node = str(t.get("node") or "")
            prefix = _normalize_prefix(str(t.get("prefix") or ""))
            expv = t.get("expected")
            exp_localpref_i = int(expv)

            t["_norm_prefix"] = prefix
            _vtysh_ok, _pred_ok, last_state, last_evidence = (
                _evaluate_invariant_attempt(inv_type="bgp_localpref_equals", t=t, src=node)
            )
            rc = last_evidence.get("rc")
            parse_error = str(last_evidence.get("parse_error") or "")
            observed_localpref = last_state.get("observed_localpref")

            if observed_localpref is None:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=node,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=0,
                    error="unsupported BGP LOCALPREF evidence normalization",
                    evidence={
                        "cmd": f"vtysh -c 'show ip bgp {prefix} json'",
                        "rc": rc,
                        "parse_error": parse_error,
                    },
                    meta={
                        "type": inv_type,
                        "prefix": prefix,
                        "misuse": True,
                    },
                )
                raise SystemExit(2)

            observed = "pass" if observed_localpref == exp_localpref_i else "fail"
            verdict = "pass" if observed == expected else "fail"

            observed_state_payload = None
            if verdict == "fail":
                observed_state_payload = {
                    "type": "bgp_localpref_equals",
                    "prefix": prefix,
                    "peer": "",
                    "expected_localpref": int(exp_localpref_i),
                    "actual_localpref": int(observed_localpref) if observed_localpref is not None else None,
                    "source_node": node,
                }
                if parse_error:
                    observed_state_payload["parse_error"] = str(parse_error)

            record_fn(
                name=test_name,
                kind="invariant",
                src=node,
                dst="",
                expected=expected,
                observed=observed,
                verdict=verdict,
                duration_ms=int((time.time() - start) * 1000),
                error="" if verdict == "pass" else f"{inv_type} mismatch (expected {expected}, observed {observed})",
                evidence={
                    "cmd": f"vtysh -c 'show ip bgp {prefix} json'",
                    "rc": rc,
                    "prefix": prefix,
                    "localpref": observed_localpref,
                },
                meta={
                    "type": inv_type,
                    "prefix": prefix,
                    "expected_value": exp_localpref_i,
                    "observed_value": observed_localpref,
                },
                observed_state=observed_state_payload,
            )
            return verdict

        if inv_type == "bgp_session_up":
            neighbor = str(t.get("dst") or "").strip()
            try:
                ip = ipaddress.ip_address(neighbor)
                if ip.version != 4:
                    raise ValueError("dst must be IPv4")
            except Exception:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=src,
                    dst=str(t.get("dst") or ""),
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=int((time.time() - start) * 1000),
                    error="dst missing or invalid (expected non-empty IPv4 literal)",
                    evidence={
                        "cmd": "vtysh -c 'show bgp summary json'",
                        "parse_error": "dst missing or invalid (expected non-empty IPv4 literal)",
                    },
                    meta={
                        "type": "bgp_session_up",
                        "neighbor": neighbor,
                        "state": "Unknown",
                        "attempts": 0,
                        "timeout_s": 0,
                        "retry_interval_s": 0.0,
                        "last_rc": None,
                    },
                    observed_state={
                        "type": "bgp_session_up",
                        "peer": neighbor,
                        "state": "Unknown",
                        "last_error": "dst missing or invalid (expected non-empty IPv4 literal)",
                        "source_node": src,
                    },
                )
                return "fail"

            if not src:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=src,
                    dst=neighbor,
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=int((time.time() - start) * 1000),
                    error="src missing or empty",
                    evidence={
                        "cmd": "vtysh -c 'show bgp summary json'",
                        "parse_error": "src missing or empty",
                    },
                    meta={
                        "type": "bgp_session_up",
                        "neighbor": neighbor,
                        "state": "Unknown",
                        "attempts": 0,
                        "timeout_s": 0,
                        "retry_interval_s": 0.0,
                        "last_rc": None,
                    },
                    observed_state={
                        "type": "bgp_session_up",
                        "peer": neighbor,
                        "state": "Unknown",
                        "last_error": "src missing or empty",
                        "source_node": src,
                    },
                )
                return "fail"

            timeout_s = int(t.get("timeout_s") or (15 if expected == "pass" else 0))
            interval_s = float(t.get("retry_interval_s") or 1.0)

            def attempt():
                vtysh_ok, _predicate_ok, attempt_state, attempt_evidence = (
                    _evaluate_invariant_attempt(inv_type="bgp_session_up", t=t, src=src)
                )
                return vtysh_ok, (attempt_state, attempt_evidence)

            if expected == "pass" and timeout_s > 0:
                ok, last_payload, attempts, dur_ms = retry_until(timeout_s, interval_s, attempt)
                last_state, last_evidence = last_payload
            else:
                ok_a, payload_a = attempt()
                last_state, last_evidence = payload_a
                attempts = 1
                dur_ms = int((time.time() - start) * 1000)
                ok = ok_a

            observed_state_str = str(last_state.get("state") or "Unknown")
            last_error = str(last_state.get("last_error") or "")
            parse_error = str(last_evidence.get("parse_error") or "")
            peer_present = bool(last_state.get("peer_present"))

            st_norm = observed_state_str.strip().lower()
            observed = "pass" if (peer_present and st_norm == "established") else "fail"
            verdict = "pass" if observed == expected else "fail"

            evidence = {
                "cmd": "vtysh -c 'show bgp summary json'",
                "parse_error": parse_error,
            }
            meta = {
                "type": "bgp_session_up",
                "neighbor": neighbor,
                "state": observed_state_str,
                "attempts": int(attempts),
                "timeout_s": int(timeout_s),
                "retry_interval_s": float(interval_s),
                "last_rc": last_evidence.get("returncode"),
            }

            if verdict == "pass":
                observed_state_record = None
            else:
                observed_state_record = {
                    "type": "bgp_session_up",
                    "peer": neighbor,
                    "state": observed_state_str,
                    "last_error": last_error,
                    "source_node": src,
                }

            record_fn(
                name=test_name,
                kind="invariant",
                src=src,
                dst=neighbor,
                expected=expected,
                observed=observed,
                verdict=verdict,
                duration_ms=int(dur_ms),
                error="" if verdict == "pass" else f"bgp_session_up mismatch (expected {expected}, observed {observed})",
                evidence=evidence,
                meta=meta,
                observed_state=observed_state_record,
            )
            return verdict

        if inv_type == "ospf_neighbor_up":
            # H4: OSPF neighbor-state dispatch (REQ-H4-8 / B08, REQ-H4-9 / B09,
            # REQ-H4-25). LD-4 retry defaults: timeout_s=60, retry_interval_s=1.0.
            # P8: observed_state emitted on FAIL records only, with §7 six-key
            # shape (expected_state, last_error, neighbor, source_node, state,
            # type). meta emitted on every record (PASS or FAIL).
            neighbor = str(t.get("neighbor") or "").strip()
            expected_state = str(t.get("state") or "Full").strip()

            # Defensive validation (WI-1 Resolve already enforces these; here
            # to keep the dispatch self-defending against any future Resolve
            # regression).
            try:
                _ip = ipaddress.ip_address(neighbor)
                if _ip.version != 4:
                    raise ValueError("neighbor must be IPv4")
            except Exception:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=src,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=int((time.time() - start) * 1000),
                    error="neighbor missing or invalid (expected non-empty IPv4 router-id literal)",
                    evidence={
                        "cmd": "vtysh -c 'show ip ospf neighbor json'",
                        "parse_error": "neighbor missing or invalid (expected non-empty IPv4 router-id literal)",
                    },
                    meta={
                        "type": "ospf_neighbor_up",
                        "neighbor": neighbor,
                        "expected_state": expected_state,
                        "state": "Unknown",
                        "attempts": 0,
                        "timeout_s": 0,
                        "retry_interval_s": 0.0,
                        "last_rc": None,
                    },
                    observed_state={
                        "type": "ospf_neighbor_up",
                        "neighbor": neighbor,
                        "state": "Unknown",
                        "expected_state": expected_state,
                        "last_error": "neighbor missing or invalid (expected non-empty IPv4 router-id literal)",
                        "source_node": src,
                    },
                )
                return "fail"

            if not src:
                record_fn(
                    name=test_name,
                    kind="invariant",
                    src=src,
                    dst="",
                    expected=expected,
                    observed="fail",
                    verdict="fail",
                    duration_ms=int((time.time() - start) * 1000),
                    error="src missing or empty",
                    evidence={
                        "cmd": "vtysh -c 'show ip ospf neighbor json'",
                        "parse_error": "src missing or empty",
                    },
                    meta={
                        "type": "ospf_neighbor_up",
                        "neighbor": neighbor,
                        "expected_state": expected_state,
                        "state": "Unknown",
                        "attempts": 0,
                        "timeout_s": 0,
                        "retry_interval_s": 0.0,
                        "last_rc": None,
                    },
                    observed_state={
                        "type": "ospf_neighbor_up",
                        "neighbor": neighbor,
                        "state": "Unknown",
                        "expected_state": expected_state,
                        "last_error": "src missing or empty",
                        "source_node": src,
                    },
                )
                return "fail"

            # LD-4 retry defaults; per-test overrides accepted for both keys.
            timeout_s = int(t.get("timeout_s") or (60 if expected == "pass" else 0))
            interval_s = float(t.get("retry_interval_s") or 1.0)

            def attempt():
                _vtysh_ok, _predicate_ok, attempt_state, attempt_evidence = (
                    _evaluate_invariant_attempt(inv_type="ospf_neighbor_up", t=t, src=src)
                )
                # Drive retry on the predicate (state == expected), not on
                # vtysh-success alone: NotConfigured with vtysh-success is
                # not yet a pass.
                return _predicate_ok, (attempt_state, attempt_evidence)

            if expected == "pass" and timeout_s > 0:
                ok, last_payload, attempts, dur_ms = retry_until(timeout_s, interval_s, attempt)
                last_state, last_evidence = last_payload
            else:
                ok_a, payload_a = attempt()
                last_state, last_evidence = payload_a
                attempts = 1
                dur_ms = int((time.time() - start) * 1000)
                ok = ok_a

            observed_state_str = str(last_state.get("state") or "Unknown")
            last_error = str(last_state.get("last_error") or "")
            parse_error = str(last_evidence.get("parse_error") or "")
            neighbor_present = bool(last_state.get("neighbor_present"))

            observed = "pass" if (neighbor_present and observed_state_str == expected_state) else "fail"
            verdict = "pass" if observed == expected else "fail"

            evidence = {
                "cmd": "vtysh -c 'show ip ospf neighbor json'",
                "parse_error": parse_error,
            }
            meta = {
                "type": "ospf_neighbor_up",
                "neighbor": neighbor,
                "expected_state": expected_state,
                "state": observed_state_str,
                "attempts": int(attempts),
                "timeout_s": int(timeout_s),
                "retry_interval_s": float(interval_s),
                "last_rc": last_evidence.get("returncode"),
            }

            if verdict == "pass":
                observed_state_record = None
            else:
                observed_state_record = {
                    "type": "ospf_neighbor_up",
                    "neighbor": neighbor,
                    "state": observed_state_str,
                    "expected_state": expected_state,
                    "last_error": last_error,
                    "source_node": src,
                }

            record_fn(
                name=test_name,
                kind="invariant",
                src=src,
                dst=neighbor,
                expected=expected,
                observed=observed,
                verdict=verdict,
                duration_ms=int(dur_ms),
                error="" if verdict == "pass" else f"ospf_neighbor_up mismatch (expected {expected}, observed {observed})",
                evidence=evidence,
                meta=meta,
                observed_state=observed_state_record,
            )
            return verdict

        observed_state_payload: dict | None = None
        if inv_type == "bgp_session_up":
            observed_state_payload = {
                "type": "bgp_session_up",
                "peer": str(t.get("dst") or ""),
                "state": "Unknown",
                "last_error": "",
                "source_node": src,
            }
        else:
            observed_state_payload = {
                "type": str(inv_type or ""),
                "source_node": src,
                "parse_error": f"unsupported invariant type '{inv_type}'",
            }

        record_fn(
            name=test_name,
            kind="invariant",
            src=src,
            dst=str(t.get("dst") or ""),
            expected=expected,
            observed="fail",
            verdict="fail",
            duration_ms=0,
            error=f"unsupported invariant type '{inv_type}'",
            evidence={"reason": "unsupported_invariant_type"},
            meta={"type": inv_type},
            observed_state=observed_state_payload,
        )
        return "fail"

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

        if kind == "invariant":
            inv_type = str(t.get("type") or "").strip().lower()
            if not src:
                record_test(
                    name=ref,
                    kind="invariant",
                    src=src or "",
                    dst=dst or "",
                    expected=str(t.get("expect") or "pass"),
                    observed="fail",
                    verdict="fail",
                    evidence={"reason": "missing_src"},
                    duration_ms=0,
                    error="missing node/src",
                    meta={"type": inv_type},
                )
                return "fail"

            if inv_type == "bgp_session_up":
                if not dst or not isinstance(dst, str) or not is_ip_literal(dst.strip()):
                    record_test(
                        name=ref,
                        kind="invariant",
                        src=src or "",
                        dst=str(dst) if dst is not None else "",
                        expected=str(t.get("expect") or "pass"),
                        observed="fail",
                        verdict="fail",
                        evidence={"reason": "invalid_neighbor_ip"},
                        duration_ms=0,
                        error="bgp_session_up requires neighbor/dst as an IPv4 literal",
                        meta={"type": inv_type},
                    )
                    return "fail"

            elif inv_type in ("route_present", "route_absent", "bgp_med_equals", "bgp_localpref_equals", "route_advertised_to", "route_not_advertised_to"):
                prefix = t.get("prefix")
                if not isinstance(prefix, str) or not prefix.strip():
                    record_test(
                        name=ref,
                        kind="invariant",
                        src=src or "",
                        dst="",
                        expected=str(t.get("expect") or "pass"),
                        observed="fail",
                        verdict="fail",
                        evidence={"reason": "missing_prefix"},
                        duration_ms=0,
                        error=f"{inv_type} requires prefix",
                        meta={"type": inv_type},
                    )
                    return "fail"

                if inv_type in ("route_advertised_to", "route_not_advertised_to"):
                    peer = t.get("peer")
                    if not isinstance(peer, str) or not peer.strip():
                        record_test(
                            name=ref,
                            kind="invariant",
                            src=src or "",
                            dst="",
                            expected=str(t.get("expect") or "pass"),
                            observed="fail",
                            verdict="fail",
                            evidence={"reason": "missing_peer"},
                            duration_ms=0,
                            error=f"{inv_type} requires peer",
                            meta={"type": inv_type},
                        )
                        return "fail"

                if inv_type in ("bgp_med_equals", "bgp_localpref_equals"):
                    expv = t.get("expected")
                    if expv is None or str(expv).strip() == "":
                        record_test(
                            name=ref,
                            kind="invariant",
                            src=src or "",
                            dst="",
                            expected=str(t.get("expect") or "pass"),
                            observed="fail",
                            verdict="fail",
                            evidence={"reason": "missing_expected"},
                            duration_ms=0,
                            error=f"{inv_type} requires expected",
                            meta={"type": inv_type},
                        )
                        return "fail"
                    try:
                        int(expv)
                    except Exception:
                        record_test(
                            name=ref,
                            kind="invariant",
                            src=src or "",
                            dst="",
                            expected=str(t.get("expect") or "pass"),
                            observed="fail",
                            verdict="fail",
                            evidence={"reason": "invalid_expected"},
                            duration_ms=0,
                            error=f"{inv_type}.expected must be an integer",
                            meta={"type": inv_type, "expected": expv},
                        )
                        return "fail"

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

        def _must_ok(cp: subprocess.CompletedProcess, what: str) -> None:
            if cp.returncode != 0:
                raise ValueError(what)

        def _iface_down(node: str, iface: str) -> None:
            key = (node, iface)
            fault_state_routes_v4[key] = _snapshot_v4_via_routes(node, iface)
            cp = rt.exec(
                lab,
                node,
                ["ip", "link", "set", "dev", str(iface), "down"],
                check=False,
            )
            _must_ok(cp, f"failed to set link down on {node}:{iface}")

        def _iface_up(node: str, iface: str) -> int:
            cp = rt.exec(
                lab,
                node,
                ["ip", "link", "set", "dev", str(iface), "up"],
                check=False,
            )
            _must_ok(cp, f"failed to set link up on {node}:{iface}")
            key = (node, iface)
            routes = fault_state_routes_v4.get(key) or []
            if routes:
                _restore_v4_routes(node, routes)
            return len(routes)

        def _iface_netem_loss(node: str, iface: str, loss_percent: int) -> None:
            cp = rt.exec(
                lab,
                node,
                ["tc", "qdisc", "replace", "dev", str(iface), "root", "netem", "loss", f"{loss_percent}%"],
                check=False,
            )
            _must_ok(cp, f"failed to apply packet loss on {node}:{iface}")

        def _iface_netem_delay(node: str, iface: str, latency_ms: int) -> None:
            cp = rt.exec(
                lab,
                node,
                ["tc", "qdisc", "replace", "dev", str(iface), "root", "netem", "delay", f"{latency_ms}ms"],
                check=False,
            )
            _must_ok(cp, f"failed to apply latency on {node}:{iface}")

        def _iface_tbf(node: str, iface: str, bandwidth_mbps: int) -> None:
            cp = rt.exec(
                lab,
                node,
                [
                    "tc",
                    "qdisc",
                    "replace",
                    "dev",
                    str(iface),
                    "root",
                    "tbf",
                    "rate",
                    f"{bandwidth_mbps}mbit",
                    "burst",
                    "32kbit",
                    "latency",
                    "400ms",
                ],
                check=False,
            )
            _must_ok(cp, f"failed to apply bandwidth cap on {node}:{iface}")

        def _resolve_link_or_interface_targets(
            action: str,
            spec: dict[str, Any],
        ) -> tuple[list[tuple[str, str]], str]:
            node = str(spec.get("node") or "").strip()
            iface = str(spec.get("if") or spec.get("iface") or spec.get("interface") or "").strip()

            a = str(spec.get("a") or "").strip()
            b = str(spec.get("b") or "").strip()
            a_if_req = spec.get("a_if")
            b_if_req = spec.get("b_if")

            has_iface_target = bool(node or iface)
            has_link_target = bool(a or b or a_if_req or b_if_req)

            if has_iface_target and has_link_target:
                raise ValueError(f"{action}: target is ambiguous (choose node+if OR a/b link form)")

            if has_iface_target:
                if not node or not iface:
                    raise ValueError(f"{action}: requires node + if")
                return [(node, iface)], f"{node}:{iface}"

            if not a or not b:
                raise ValueError(f"{action}: requires a,b")

            a_if, b_if = _find_link_interfaces(a, b, a_if=a_if_req, b_if=b_if_req)
            if not a_if or not b_if:
                raise ValueError(f"{action}: could not determine interfaces for link {a}<->{b}")

            return [(a, a_if), (b, b_if)], f"{a}:{a_if}<->{b}:{b_if}"

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
        # packet_loss / latency / bandwidth_cap
        # ----------------------------
        if "packet_loss" in fault:
            spec = fault.get("packet_loss") or {}
            loss = spec.get("loss_percent")
            if loss is None:
                loss = spec.get("loss")
            if not isinstance(loss, int) or loss < 0 or loss > 100:
                raise ValueError("invalid packet loss value")

            targets, label = _resolve_link_or_interface_targets("packet_loss", spec)
            for node, iface in targets:
                _iface_netem_loss(node, iface, loss)
            return "packet_loss", label, {"loss_percent": loss}

        if "latency" in fault:
            spec = fault.get("latency") or {}
            latency_ms = spec.get("latency_ms")
            if not isinstance(latency_ms, int) or latency_ms < 0:
                raise ValueError("invalid latency value")

            targets, label = _resolve_link_or_interface_targets("latency", spec)
            for node, iface in targets:
                _iface_netem_delay(node, iface, latency_ms)
            return "latency", label, {"latency_ms": latency_ms}

        if "bandwidth_cap" in fault:
            spec = fault.get("bandwidth_cap") or {}
            bandwidth_mbps = spec.get("bandwidth_mbps")
            if not isinstance(bandwidth_mbps, int) or bandwidth_mbps < 1:
                raise ValueError("invalid bandwidth cap value")

            targets, label = _resolve_link_or_interface_targets("bandwidth_cap", spec)
            for node, iface in targets:
                _iface_tbf(node, iface, bandwidth_mbps)
            return "bandwidth_cap", label, {"bandwidth_mbps": bandwidth_mbps}

        if "prefix_blackhole" in fault:
            spec = fault.get("prefix_blackhole") or {}
            node = str(spec.get("node") or "").strip()
            prefix = str(spec.get("prefix") or "").strip()
            if not node:
                raise ValueError("prefix_blackhole: requires node")
            if not prefix:
                raise ValueError("prefix_blackhole: requires prefix")

            cp = rt.exec(
                lab,
                node,
                ["ip", "route", "replace", "blackhole", prefix],
                check=False,
            )
            _must_ok(cp, f"failed to install blackhole route {prefix} on {node}")
            return "prefix_blackhole", f"{node}:{prefix}", {"prefix": prefix}

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

            # -------------------------
            # type: bgp_session_up (REQ-WF-1)
            # -------------------------
            if wtype == "bgp_session_up":
                # Construct helper-input t-dict from wait_for.
                # The helper reads t.get("dst") for the peer IP.
                t_for_helper = {"dst": wait_for.get("dst")}
                vtysh_ok, predicate_ok, observed_state, evidence = (
                    _evaluate_invariant_attempt(
                        inv_type="bgp_session_up",
                        t=t_for_helper,
                        src=str(src).strip(),
                    )
                )
                last_cp = None
                last_obs = "pass" if predicate_ok else "fail"
                last_evidence = dict(evidence or {})
                last_evidence["observed_state"] = dict(observed_state or {})
                attempt_success = (last_obs == "pass")
                return attempt_success, (last_cp, last_obs)

            # -------------------------
            # type: route_present (REQ-WF-2)
            # -------------------------
            if wtype == "route_present":
                pfx = wait_for.get("prefix")
                if not isinstance(pfx, str) or not pfx.strip():
                    raise ValueError("wait_for route_present: requires prefix as CIDR")
                norm_prefix = _normalize_prefix(pfx.strip()) or pfx.strip()
                t_for_helper = {"_norm_prefix": norm_prefix}
                vtysh_ok, predicate_ok, observed_state, evidence = (
                    _evaluate_invariant_attempt(
                        inv_type="route_present",
                        t=t_for_helper,
                        src=str(src).strip(),
                    )
                )
                last_cp = None
                last_obs = "pass" if predicate_ok else "fail"
                last_evidence = dict(evidence or {})
                last_evidence["observed_state"] = dict(observed_state or {})
                attempt_success = (last_obs == "pass")
                return attempt_success, (last_cp, last_obs)

            # -------------------------
            # type: route_advertised_to (REQ-WF-3)
            # -------------------------
            if wtype == "route_advertised_to":
                peer = wait_for.get("peer")
                if not isinstance(peer, str) or not peer.strip():
                    raise ValueError("wait_for route_advertised_to: requires peer as a node name")
                pfx = wait_for.get("prefix")
                if not isinstance(pfx, str) or not pfx.strip():
                    raise ValueError("wait_for route_advertised_to: requires prefix as CIDR")
                norm_prefix = _normalize_prefix(pfx.strip()) or pfx.strip()

                # Resolve peer-IP from topology links (TEST-path-equivalent policy).
                node_s = str(src).strip()
                peer_s = peer.strip()
                peer_ips: list = []
                for link in (topo.get("links") or []):
                    endpoints = list(link.get("endpoints") or [])
                    if len(endpoints) != 2:
                        continue
                    try:
                        a_node, _ = str(endpoints[0]).split(":", 1)
                        b_node, _ = str(endpoints[1]).split(":", 1)
                    except Exception:
                        continue
                    ips = list(link.get("ipv4") or [])
                    if len(ips) != 2:
                        continue
                    if a_node == node_s and b_node == peer_s:
                        try:
                            peer_ips.append(str(ipaddress.ip_interface(ips[1]).ip))
                        except Exception:
                            continue
                    elif b_node == node_s and a_node == peer_s:
                        try:
                            peer_ips.append(str(ipaddress.ip_interface(ips[0]).ip))
                        except Exception:
                            continue
                peer_ips = sorted(set(peer_ips))
                if not peer_ips:
                    raise ValueError(
                        f"wait_for route_advertised_to: unsupported peer mapping for "
                        f"node={node_s!r} peer={peer_s!r} (no direct IPv4 link)"
                    )

                t_for_helper = {
                    "node": node_s,
                    "_peer_ip": peer_ips[0],
                    "_norm_prefix": norm_prefix,
                }
                vtysh_ok, predicate_ok, observed_state, evidence = (
                    _evaluate_invariant_attempt(
                        inv_type="route_advertised_to",
                        t=t_for_helper,
                        src=node_s,
                    )
                )
                last_cp = None
                last_obs = "pass" if predicate_ok else "fail"
                last_evidence = dict(evidence or {})
                last_evidence["observed_state"] = dict(observed_state or {})
                attempt_success = (last_obs == "pass")
                return attempt_success, (last_cp, last_obs)

            # -------------------------
            # type: evpn_bgp_session_up (REQ-WF-4)
            # -------------------------
            if wtype == "evpn_bgp_session_up":
                peer = wait_for.get("peer")
                if not isinstance(peer, str) or not peer.strip():
                    raise ValueError("wait_for evpn_bgp_session_up: requires peer as a node name")
                t_for_helper = {"peer": peer.strip()}
                vtysh_ok, predicate_ok, observed_state, evidence = (
                    _evaluate_invariant_attempt(
                        inv_type="evpn_bgp_session_up",
                        t=t_for_helper,
                        src=str(src).strip(),
                    )
                )
                last_cp = None
                last_obs = "pass" if predicate_ok else "fail"
                last_evidence = dict(evidence or {})
                last_evidence["observed_state"] = dict(observed_state or {})
                attempt_success = (last_obs == "pass")
                return attempt_success, (last_cp, last_obs)

            # -------------------------
            # type: evpn_vni_route_present (REQ-WF-5)
            # -------------------------
            if wtype == "evpn_vni_route_present":
                vni_v = wait_for.get("vni")
                if not isinstance(vni_v, int) or isinstance(vni_v, bool):
                    raise ValueError("wait_for evpn_vni_route_present: requires vni as an int")
                t_for_helper = {"_mac": "", "_vni_i": int(vni_v)}
                vtysh_ok, predicate_ok, observed_state, evidence = (
                    _evaluate_invariant_attempt(
                        inv_type="evpn_vni_route_present",
                        t=t_for_helper,
                        src=str(src).strip(),
                    )
                )
                last_cp = None
                last_obs = "pass" if predicate_ok else "fail"
                last_evidence = dict(evidence or {})
                last_evidence["observed_state"] = dict(observed_state or {})
                attempt_success = (last_obs == "pass")
                return attempt_success, (last_cp, last_obs)

            # -------------------------
            # type: evpn_mac_route_present (REQ-WF-6)
            # -------------------------
            if wtype == "evpn_mac_route_present":
                mac_v = wait_for.get("mac")
                vni_v = wait_for.get("vni")
                if not isinstance(mac_v, str) or not mac_v.strip():
                    raise ValueError("wait_for evpn_mac_route_present: requires mac as a string")
                if not isinstance(vni_v, int) or isinstance(vni_v, bool):
                    raise ValueError("wait_for evpn_mac_route_present: requires vni as an int")
                t_for_helper = {"_mac": str(mac_v).strip().lower(), "_vni_i": int(vni_v)}
                vtysh_ok, predicate_ok, observed_state, evidence = (
                    _evaluate_invariant_attempt(
                        inv_type="evpn_mac_route_present",
                        t=t_for_helper,
                        src=str(src).strip(),
                    )
                )
                last_cp = None
                last_obs = "pass" if predicate_ok else "fail"
                last_evidence = dict(evidence or {})
                last_evidence["observed_state"] = dict(observed_state or {})
                attempt_success = (last_obs == "pass")
                return attempt_success, (last_cp, last_obs)

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

        if wtype == "bgp_session_up":
            meta["dst"] = str(wait_for.get("dst") or "")

        if wtype == "route_present":
            meta["prefix"] = str(wait_for.get("prefix") or "")

        if wtype == "route_advertised_to":
            meta["peer"] = str(wait_for.get("peer") or "")
            meta["prefix"] = str(wait_for.get("prefix") or "")

        if wtype == "evpn_bgp_session_up":
            meta["peer"] = str(wait_for.get("peer") or "")

        if wtype == "evpn_vni_route_present":
            meta["vni"] = int(wait_for.get("vni") or 0)

        if wtype == "evpn_mac_route_present":
            meta["mac"] = str(wait_for.get("mac") or "")
            meta["vni"] = int(wait_for.get("vni") or 0)

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

                except SystemExit as e:
                    dur_ms = int((time.time() - step_started) * 1000)
                    err = f"fault step failed (exit={e.code})"
                    scen_step({
                        "type": "fault",
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": err,
                        "fault": fault,
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. fault -> FAIL ({err})")

                    record_event_scenario_fault(
                        scenario_id=sid,
                        step_index=step_idx,
                        verdict="fail",
                        duration_ms=dur_ms,
                        error=err,
                        meta={"action": "error", "target": "", "fault": fault},
                    )

                    raise

                except ValueError as e:
                    dur_ms = int((time.time() - step_started) * 1000)
                    err = str(e)
                    scen_step({
                        "type": "fault",
                        "verdict": "fail",
                        "duration_ms": dur_ms,
                        "error": err,
                        "fault": fault,
                        "step": step_idx,
                    })
                    _sv(f"[scenario {sid}] {step_idx:02d}. fault -> FAIL ({err})")

                    record_event_scenario_fault(
                        scenario_id=sid,
                        step_index=step_idx,
                        verdict="fail",
                        duration_ms=dur_ms,
                        error=err,
                        meta={"action": "error", "target": "", "fault": fault},
                    )

                    die(f"ERROR: {err}", code=2)

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
                        meta={"action": "error", "target": "", "fault": fault},
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
                    "observed": "completed",
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
                from cassian_artifacts import pcap_session_paths, write_file

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

                    start_step_seq = int(step_idx)
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
                        "step_seq_start": start_step_seq,
                        "step_seq_stop": None,
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
                                "step": start_step_seq,
                                "step_seq_start": start_step_seq,
                                "step_seq_stop": None,
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
                    stop_step_seq = int(cur.get("step_seq_stop") or step_idx)
                    meta = {
                        "authority": "supporting_evidence",
                        "scenario_id": str(scenario_id),
                        "step_seq_start": int(cur.get("step_seq_start") or 0),
                        "step_seq_stop": stop_step_seq,
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
                                "step": stop_step_seq,
                                "step_seq_start": int(cur.get("step_seq_start") or 0),
                                "step_seq_stop": stop_step_seq,
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
                "  cassian destroy <lab>",
                "  cassian up <topology.yaml> --reconfigure",
                "or:",
                "  cassian cleanup --all --yes",
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
    state_diff_enabled = bool(state_plan.get("enabled")) and str(state_plan.get("mode") or "none") == "both"
    state_diff_path = str(lab_dir(lab) / "artifacts" / "state-diff" / "state_diff.json") if state_diff_enabled else ""
    blast_radius_path = str(lab_dir(lab) / "artifacts" / "blast-radius" / "blast_radius.json")
    results["state_capture"] = {
        "enabled": bool(state_plan.get("enabled")),
        "mode": str(state_plan.get("mode") or "none"),
        "profiles": list(state_plan.get("profiles") or []),
        "plan_path": state_plan_path,
        "pre": {"ran": 0, "ok": 0, "error": 0, "timeout": 0},
        "post": {"ran": 0, "ok": 0, "error": 0, "timeout": 0},
        "state_diff": {
            "enabled": bool(state_diff_enabled),
            "authority": "supporting_evidence",
            "path": state_diff_path,
            "compared": 0,
            "added": 0,
            "removed": 0,
            "changed": 0,
        },
    }
    results["blast_radius"] = {
        "enabled": True,
        "authority": "supporting_evidence",
        "path": blast_radius_path,
        "directly_covered": {"nodes": 0, "links": 0},
        "potentially_affected": {"nodes": 0, "links": 0},
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

            if not (results.get("tests") or []):
                for t in declared_tests:
                    if not isinstance(t, dict):
                        continue
                    results["tests"].append(
                        {
                            "name": str(t.get("name") or "<unnamed>"),
                            "kind": str(t.get("kind") or t.get("type") or ""),
                            "expected": str(t.get("expect") or "pass"),
                            "observed": "blocked",
                            "verdict": "fail",
                            "error": "blocked before execution",
                            "duration_ms": 0,
                        }
                    )

            if want_scenarios and not (results.get("scenarios") or []):
                scenario_items = []
                if selected_scenario:
                    scenario_items = [s for s in (scenarios or []) if isinstance(s, dict) and str(s.get("id") or "").strip() == selected_scenario]
                elif run_all_scenarios:
                    scenario_items = [s for s in (scenarios or []) if isinstance(s, dict)]
                for s in scenario_items:
                    results["scenarios"].append(
                        {
                            "id": str(s.get("id") or ""),
                            "description": str(s.get("description") or ""),
                            "steps": [],
                            "verdict": "fail",
                            "status": "blocked",
                            "error": "blocked before execution",
                            "duration_ms": 0,
                        }
                    )

            test_total = len(results["tests"])
            test_failed = sum(1 for r in results["tests"] if r.get("verdict") == "fail")
            test_passed = test_total - test_failed

            scenario_results = results.get("scenarios") or []
            if not isinstance(scenario_results, list):
                scenario_results = []

            scenario_total = len(scenario_results)
            scenario_failed = sum(1 for s in scenario_results if isinstance(s, dict) and s.get("verdict") == "fail")
            scenario_passed = scenario_total - scenario_failed

            total = test_total + scenario_total
            failed_count = test_failed + scenario_failed
            passed_count = test_passed + scenario_passed

            results["summary"]["total"] = total
            results["summary"]["passed"] = passed_count
            results["summary"]["failed"] = failed_count
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
            require_evpn_bgp = bool((((topo.get("fabric") or {}).get("evpn") or {}).get("enabled")))
            is_replay_lab = "-replay-" in str(topo.get("name", ""))
            precheck_timeout = 60 if (require_evpn_bgp and is_replay_lab) else 30
            post_precheck_sleep = 15 if (require_evpn_bgp and is_replay_lab) else (10 if require_evpn_bgp else 5)
            for n in bgp_participants:
                wait_for_bgp(rt, lab, n["name"], timeout=precheck_timeout, require_evpn=require_evpn_bgp)
            time.sleep(post_precheck_sleep)
        except SystemExit:
            results["result"] = "fail"
            finished_at = time.time()
            results["summary"]["finished_at"] = finished_at
            results["summary"]["duration_ms"] = int((finished_at - started_at) * 1000)

            if not (results.get("tests") or []):
                for t in declared_tests:
                    if not isinstance(t, dict):
                        continue
                    results["tests"].append(
                        {
                            "name": str(t.get("name") or "<unnamed>"),
                            "kind": str(t.get("kind") or t.get("type") or ""),
                            "expected": str(t.get("expect") or "pass"),
                            "observed": "blocked",
                            "verdict": "fail",
                            "error": "blocked before execution",
                            "duration_ms": 0,
                        }
                    )

            if want_scenarios and not (results.get("scenarios") or []):
                scenario_items = []
                if selected_scenario:
                    scenario_items = [
                        s for s in (scenarios or [])
                        if isinstance(s, dict) and str(s.get("id") or "").strip() == selected_scenario
                    ]
                elif run_all_scenarios:
                    scenario_items = [s for s in (scenarios or []) if isinstance(s, dict)]
                for s in scenario_items:
                    results["scenarios"].append(
                        {
                            "id": str(s.get("id") or ""),
                            "description": str(s.get("description") or ""),
                            "steps": [],
                            "verdict": "fail",
                            "status": "blocked",
                            "error": "blocked before execution",
                            "duration_ms": 0,
                        }
                    )

            test_total = len(results["tests"])
            test_failed = sum(1 for r in results["tests"] if r.get("verdict") == "fail")
            test_passed = test_total - test_failed

            scenario_results = results.get("scenarios") or []
            if not isinstance(scenario_results, list):
                scenario_results = []

            scenario_total = len(scenario_results)
            scenario_failed = sum(1 for s in scenario_results if isinstance(s, dict) and s.get("verdict") == "fail")
            scenario_passed = scenario_total - scenario_failed

            total = test_total + scenario_total
            failed_count = test_failed + scenario_failed
            passed_count = test_passed + scenario_passed

            results["summary"]["total"] = total
            results["summary"]["passed"] = passed_count
            results["summary"]["failed"] = failed_count
            results["summary"]["tests_executed"] = 0

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
            if not declared_tests and not want_scenarios:
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
                    kind_raw = str(t.get("kind") or "").strip().lower()
                    # v2 invariant reservation:
                    #   kind: invariant
                    #   type: <invariant subtype>
                    # This combination is valid and already normalized during resolve.
                    if kind_raw != "invariant":
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

                if kind not in ("ping", "tcp", "bgp_neighbor", "route_prefix", "invariant"):
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
                    fail_or_continue(
                        f"tests[{i}]: unsupported kind '{kind}' "
                        f"(supported: ping, tcp, bgp_neighbor, route_prefix, invariant)"
                    )
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

                if kind == "invariant":
                    verdict = run_invariant_test(test_name=test_name, src=src, t=t)
                    verdict_txt = (verdict or "fail").upper()
                    _tv(f"[TEST END]   {exec_idx:03d} {test_name} verdict={verdict_txt}")
                    if verdict != "pass":
                        inv_type = str(t.get("type") or "").strip().lower()
                        if inv_type == "bgp_session_up":
                            fail_or_continue(
                                f"tests[{i}] invariant {inv_type} mismatch: {src} -> {dst} expected {t.get('expect','pass')}"
                            )
                        else:
                            fail_or_continue(
                                f"tests[{i}] invariant {inv_type} mismatch: on {src} prefix {t.get('prefix')} expected {t.get('expect','pass')}"
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

                if bool(results.get("state_capture", {}).get("state_diff", {}).get("enabled")):
                    def _state_diff_collect(root: Path) -> dict[str, dict]:
                        coll: dict[str, dict] = {}
                        if not root.exists():
                            return coll

                        for meta_path in sorted(root.rglob("*.json"), key=lambda p: p.as_posix()):
                            rel = meta_path.relative_to(root)
                            rel_s = rel.as_posix()
                            if rel_s == "plan.json":
                                continue

                            try:
                                rec = json.loads(meta_path.read_text(encoding="utf-8"))
                            except Exception:
                                rec = {}

                            out_path = meta_path.with_suffix(".out.txt")
                            stdout_text = ""
                            if out_path.exists() and out_path.is_file():
                                try:
                                    stdout_text = out_path.read_text(encoding="utf-8")
                                except Exception:
                                    stdout_text = ""

                            result_rec = rec.get("result") if isinstance(rec.get("result"), dict) else {}
                            node = str(rec.get("node") or rel.parent.name)
                            command_id = str(rec.get("command_id") or meta_path.stem)
                            key = f"{node}/{command_id}"

                            coll[key] = {
                                "profile": str(rec.get("profile") or ""),
                                "node": node,
                                "node_type": str(rec.get("node_type") or ""),
                                "command_id": command_id,
                                "argv": list(rec.get("argv") or []),
                                "result": {
                                    "status": str(result_rec.get("status") or ""),
                                    "exit_code": int(result_rec.get("exit_code") or 0),
                                },
                                "stdout_sha256": hashlib.sha256(stdout_text.encode("utf-8", errors="replace")).hexdigest(),
                            }

                        return coll

            blast_cfg = results.get("blast_radius")
            if isinstance(blast_cfg, dict) and bool(blast_cfg.get("enabled")):
                blast_path_s = str(blast_cfg.get("path") or "").strip()
                if blast_path_s:
                    blast_obj = _blast_radius_compute_or_die(topo)
                    write_json_canonical(Path(blast_path_s), blast_obj)

                    blast_cfg["directly_covered"] = {
                        "nodes": int(blast_obj.get("counts", {}).get("directly_covered_nodes") or 0),
                        "links": int(blast_obj.get("counts", {}).get("directly_covered_links") or 0),
                    }
                    blast_cfg["potentially_affected"] = {
                        "nodes": int(blast_obj.get("counts", {}).get("potentially_affected_nodes") or 0),
                        "links": int(blast_obj.get("counts", {}).get("potentially_affected_links") or 0),
                    }

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
                                "type": "blast_radius",
                                "authority": "supporting_evidence",
                                "path": blast_path_s,
                                "counts": dict(blast_obj.get("counts") or {}),
                            }
                        )
                    except Exception:
                        pass

            diff_path_s = str(results.get("state_capture", {}).get("state_diff", {}).get("path") or "").strip()
            if diff_path_s:
                pre_root = lab_dir(lab) / "artifacts" / "state_capture" / "pre"
                post_root = lab_dir(lab) / "artifacts" / "state_capture" / "post"

                pre_objs = _state_diff_collect(pre_root)
                post_objs = _state_diff_collect(post_root)

                compared_keys = sorted(set(pre_objs.keys()) | set(post_objs.keys()))
                added = []
                removed = []
                changed = []

                for key in compared_keys:
                    in_pre = key in pre_objs
                    in_post = key in post_objs
                    if in_pre and in_post:
                        if pre_objs[key] != post_objs[key]:
                            changed.append(
                                {
                                    "key": key,
                                    "pre": pre_objs[key],
                                    "post": post_objs[key],
                                }
                            )
                    elif in_post:
                        added.append({"key": key, "post": post_objs[key]})
                    else:
                        removed.append({"key": key, "pre": pre_objs[key]})

                diff_obj = {
                    "schema": "state_diff.v1",
                    "authority": "supporting_evidence",
                    "capture_profiles": list(results.get("state_capture", {}).get("profiles") or []),
                    "pre_state_ref_identity": "artifacts/state_capture/pre",
                    "post_state_ref_identity": "artifacts/state_capture/post",
                    "compared_objects": compared_keys,
                    "added": added,
                    "removed": removed,
                    "changed": changed,
                    "counts": {
                        "compared": int(len(compared_keys)),
                        "added": int(len(added)),
                        "removed": int(len(removed)),
                        "changed": int(len(changed)),
                    },
                }

                write_json_canonical(Path(diff_path_s), diff_obj)

                scd = results.setdefault("state_capture", {}).setdefault("state_diff", {})
                scd["compared"] = int(len(compared_keys))
                scd["added"] = int(len(added))
                scd["removed"] = int(len(removed))
                scd["changed"] = int(len(changed))

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
                            "type": "state_diff",
                            "authority": "supporting_evidence",
                            "path": diff_path_s,
                            "profiles": list(results.get("state_capture", {}).get("profiles") or []),
                        }
                    )
                except Exception:
                    pass
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

        test_total = len(results["tests"])
        test_failed = sum(1 for r in results["tests"] if r.get("verdict") == "fail")
        test_passed = test_total - test_failed

        scenario_results = results.get("scenarios") or []
        if not isinstance(scenario_results, list):
            scenario_results = []

        scenario_total = len(scenario_results)
        scenario_failed = sum(1 for s in scenario_results if isinstance(s, dict) and s.get("verdict") == "fail")
        scenario_passed = scenario_total - scenario_failed

        total = test_total + scenario_total
        failed_count = test_failed + scenario_failed
        passed_count = test_passed + scenario_passed

        results["summary"]["total"] = total
        results["summary"]["passed"] = passed_count
        results["summary"]["failed"] = failed_count

        results["result"] = "fail" if failed_count > 0 else "pass"
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
    elif bgp_participants and results["summary"].get("precheck_controlplane") is False:
        print("ℹ️ Control-plane precheck skipped by explicit execution policy")
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
