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
