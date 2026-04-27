from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import yaml

from cassian_common import LABS_DIR, TOPO_DIR, die
from cassian_artifacts import load_yaml

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
    lines.append("Cassian Gate two-run diff (evidence-only)")
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
    from cassian import cmd_up, cmd_test, cmd_collect, cmd_down, _candidate_parse_dir_or_die, ensure_valid_topology
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
