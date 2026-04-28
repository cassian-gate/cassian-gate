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
