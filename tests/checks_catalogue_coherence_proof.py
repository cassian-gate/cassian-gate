#!/usr/bin/env python3
"""HS-2 -- catalogue coherence proof (Stage-1 gap item (d)(2), WI-7 script 2).

Proof obligations: PO-10 to PO-15 (with PO-12's E8 leg and PO-15's aliasing leg), PO-22 (legs (i) to (vi)),
PO-23, PO-24 and PO-28 (handover v9-rev3 section 15.1). Requirements: REQ-S1D2-6 to -11, -13, -28, -32 and -33.
Acceptance check: C-4.
Founder rulings applied: SLD-1, SLD-14 and SLD-27 (every hand-declared element bound to its code source);
PBR-1 and PBR-7 (the label reasons whose code facts PO-22 binds); PBR-3 (the interface_state limitation);
PBR-8 (PO-23, PO-24 and PO-28 sit in HS-2); PBR-10 (CAP_VERIFY: (a) a message gives `not implemented`, (b) none
fails the build, E9); S1D2-S21-R2 (WI-7's second script).

What it proves: each part of the catalogue that is written by hand, or that mirrors a code literal, agrees with
the code it describes. The code is read live: the provider registry, capability_for, the model's validate gate,
the engine's and the AI module's source (by AST), the builtin packs and the CLI parser. Nothing under src/ is
changed on disk; every doctored source is a string in memory and every synthetic provider is patched into the
registry for one build and removed.

Legs
  P10 PO-10  for each check, validate (cmd_validate's four calls, in process) accepts a minimal test whose vantage
             is the sonic-vm node of topologies/sonic-bgp-session-live.yaml iff the catalogue's sonic-vm cell is
             `implemented`; each rejection names that node. Non-vacuous by construction: both outcomes occur.
  P11 PO-11  every seam-decided cell (class seam, or a vm-gated kind on a vm-runtime type) equals
             capability_for(provider, check); the engine's _nos_collect calls capability_for (AST).
  P12 PO-12  the status classes partition the checks (seam is the rest), name only checks, and no provider
             without runtime_requirement "vm" declares IMPL for a core-class check.
  P13 PO-13  the catalogue's vm-gated tuple equals the `_eig_set` literal in cassian_model.py (AST).
  P14 PO-14  the catalogue's kinds plus `invariant` equal the engine's kind literal (AST), in order.
  P15 PO-15  the profiles are exactly the packs whose member types lie in supported_pack_invariant_types, with
             content equal to the module literal; resolving topologies/pack_resolve_expansion.yaml expands
             exactly the listed invariants; topologies/neg/pack_incompatible_contents.yaml stays rejected; the
             canonical JSON of the pack table and of the sorted type set is unchanged after two resolves and one
             catalogue build (aliasing, D16).
  P22 PO-22  label reasons that cite a code fact: (i) cmd_replay's call to cmd_test carries
             _report_authority="gate"; (ii) cmd_test and cmd_replay call cmd_up with reconfigure=True, and
             cmd_up's reconfigure branch runs `containerlab destroy` and `rm -rf` on lab_dir; (iii) each flag a
             reason names is registered on that command's live subparser; (iv) topo_to_containerlab writes
             daemons, vtysh.conf and frr.conf under node_cfg_dir and binds each `:ro`; (v) from cmd_ai_review,
             no function of cassian_ai.py reachable by name writes a file; (vi) the interface_state probe argv
             ["ip", "-j", "link", "show", "lo"] is in _interface_state_capability_check.
  P23 PO-23  every `not implemented` cell's reason is its code source's text, verbatim (capability_for's message;
             for exec, _exec_command_allowed("x", type)[1]); no such reason is empty; every `implemented` cell's
             reason is null.
  P24 PO-24  node_types equals nos_known_types() in order, each runtime_requirement equals the provider's, and
             neither `host` nor `linux` is a node type.
  P28 PO-28  the provenance block equals section 7.6 exactly, and every part named declared_proof_bound maps to
             a proof leg that exists (MAPPING below: HS-2's own legs, or a leg label present in HS-3 or HS-4).
  N   MUTANTS each leg above is shown capable of failing: a copy of the catalogue with one sonic-vm cell flipped
             (P10); one provider disposition patched, the cell follows, and a doctored engine without the
             capability_for call (P11); E8's two forms (P12); doctored model and engine sources (P13, P14); a seeded
             in-place mutation of the pack table, caught by the aliasing comparator (P15); a doctored engine
             without _report_authority="gate" and a doctored cassian_ai.py calling _ai_finalize_and_emit from
             cmd_ai_review (P22); a synthetic provider with a deferred exec rule, one with a CAP_VERIFY message
             and one with CAP_VERIFY and no message, E9 (P23); a synthetic registry entry (P24); one name dropped
             from a copy of the mapping table (P28).

Coverage limits (PBE-P2-8 / PBE-P2-14), stated so a PASS is not read as more than it is:
  1. P10 uses one fixture and one minimal instance per check (the declared required parameters, the first member
     of each exactly_one_of); a rejection by another rule that also names the vantage node would be counted as
     the gate's. It is the behavioural defence for P13.
  2. P13 and P14 read one literal each, found by AST shape (an assignment to `_eig_set`; a `kind not in (...)`
     comparison whose tuple holds "ping" and "invariant"). Another literal elsewhere, or a gate rebuilt another
     way, is not seen (PBE-P2-8). Each must be found exactly once.
  3. P11's and P22's AST legs bind calls by name in the named functions only (PBE-P2-14): a call reached through
     an alias, a getattr or another module is not seen. P22 (v) is name-based and intra-module: it follows calls
     by bare name between cassian_ai.py's top-level functions; a write through another module is not seen.
  4. P22 binds these reasons only. NOT bound: the "writes nothing" of doctor, status and validate-contrib; the
     output paths of the advisory commands; the runtime effects of exec, vty and down; import's exception; the
     AI-endpoint clause of ai's exception, read from _ai_provider_openai.
  5. P15's expansion is checked on one fixture; the aliasing comparator compares canonical JSON, so a change
     that keeps the JSON equal (an object replaced by an equal copy) is not seen.
  6. P23's synthetic providers are patched into the registry for one in-memory build each.
  7. P28 checks that a mapped leg exists (HS-2's own result list, or the label text in HS-3's or HS-4's file),
     not what that leg proves.

usage: PYTHONPATH=src python tests/checks_catalogue_coherence_proof.py   (from the repo root; writes nothing)
"""
import argparse
import ast
import contextlib
import copy
import dataclasses
import io
import json
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import yaml  # noqa: E402

import cassian_catalogue as C  # noqa: E402
import cassian_cli  # noqa: E402
import cassian_common as cc  # noqa: E402
import cassian_engine as E  # noqa: E402
import cassian_model as M  # noqa: E402
import cassian_nos_types as T  # noqa: E402

SONIC_FIXTURE = ROOT / "topologies" / "sonic-bgp-session-live.yaml"
SONIC_TYPE, VANTAGE, OTHER = "sonic-vm", "s1", "r1"  # s1:eth1 -- r1:eth1, directly linked
PACK_FIXTURE = ROOT / "topologies" / "pack_resolve_expansion.yaml"
PACK_NEG = ROOT / "topologies" / "neg" / "pack_incompatible_contents.yaml"
HS3_FILE = ROOT / "tests" / "checks_param_conformance_proof.py"
HS4_FILE = ROOT / "tests" / "checks_command_surface_proof.py"
SYNTH = "zz-synth"

# Section 7.6, verbatim.
PROVENANCE_7_6 = {
    "declared_proof_bound": ["checks.limitations", "checks.parameters", "commands.effects",
                             "commands.exception", "notices", "status_classes"],
    "derived_from_code": ["checks.id", "checks.kind", "checks.status", "commands.command",
                          "gate_release", "node_types", "profiles", "provisional", "schema_version"],
}
# PO-28's mapping: each declared, proof-bound part -> (proof file, leg label). An HS-2 leg is checked against this
# run's own results; an HS-3 or HS-4 leg against the label text in that file.
MAPPING = {
    "checks.limitations": (("HS-2", "P22 PO-22 (vi)"),),
    "checks.parameters": (("HS-3", "M marker:"), ("HS-3", "X discovery:")),
    "commands.effects": (("HS-4", "A assignment:"), ("HS-2", "P22 PO-22 (i)"), ("HS-2", "P22 PO-22 (ii)")),
    "commands.exception": (("HS-4", "A assignment:"), ("HS-2", "P22 PO-22 (v)")),
    "notices": (("HS-4", "V vocabulary:"),),
    "status_classes": (("HS-2", "P12 PO-12"), ("HS-2", "P13 PO-13")),
}
# PO-22 (iii): the flags the label reasons name, by command.
REASON_FLAGS = (("replay", "--gate"), ("up", "--reconfigure"), ("run", "--reconfigure"), ("cleanup", "--yes"),
                ("destroy", "--purge-artifacts"), ("ai", "--online"))
PROBE_ARGV = ["ip", "-j", "link", "show", "lo"]
WRITE_CALLS = ("_ai_write_bundle", "write_text", "write_bytes", "makedirs", "mkdir")

# One valid value per type token for the minimal instances of P10, with parameter-specific overrides.
VALUES = {
    "as_path_regex": "^65001$", "boolean": True, "cidr": "10.10.10.0/24", "community": "65000:1",
    "community_list": ["65000:1", "65000:2"], "exec_assertion": {"contains": "x"}, "integer": 1,
    "ip": "198.51.100.28", "ipv4": "198.51.100.28", "mac": "00:11:22:33:44:55", "node": OTHER,
    "number": 1.5, "string": "x", "string_list": ["t1"],
}
BY_NAME = {("node", "node"): VANTAGE, ("node", "src"): VANTAGE, ("integer", "port"): 179, ("integer", "vni"): 10100,
           ("integer", "expected"): 100, ("integer", "timeout_s"): 5, ("string", "command"): 'vtysh -c "show version"',
           ("string", "interface"): "eth1"}

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" | {detail}" if detail else ""), flush=True)


def report(name, bad, ok_detail):
    check(name, not bad, ("; ".join(bad[:3]) + (f" (+{len(bad) - 3} more)" if len(bad) > 3 else "")) if bad
          else ok_detail)


def build():
    return C.build_catalogue(cassian_cli.build_parser(), release_version="0+hs2")


def build_as_cli():
    """build_catalogue as `cassian checks` runs it: (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    prev = cc._QUIET_DIE
    cc._QUIET_DIE = False
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            build()
        return 0, out.getvalue(), err.getvalue()
    except SystemExit as e:
        return e.code, out.getvalue(), err.getvalue()
    finally:
        cc._QUIET_DIE = prev


@contextlib.contextmanager
def patched(obj, name, value):
    old = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, old)


def registry_with(**providers):
    reg = dict(M.NOS_PROVIDERS)
    reg.update(providers)
    return patched(M, "NOS_PROVIDERS", types.MappingProxyType(reg))


def synthetic(**fields):
    base = M.NOS_PROVIDERS["frr"]
    return dataclasses.replace(base, **dict({"node_type": SYNTH}, **fields))


def functions(tree):
    return {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def call_names(node):
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            out.append(f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None)
    return out


def edit_in(source, fn_name, old, new):
    """Replace `old` inside function fn_name's own lines only; None unless it occurs there exactly once."""
    fn = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name == fn_name]
    if len(fn) != 1:
        return None
    lines = source.splitlines(keepends=True)
    body = "".join(lines[fn[0].lineno - 1:fn[0].end_lineno])
    if body.count(old) != 1:
        return None
    return "".join(lines[:fn[0].lineno - 1]) + body.replace(old, new) + "".join(lines[fn[0].end_lineno:])


# ---------------------------------------------------------------------------------------------------------------
# PO-10: validate on a sonic-vm vantage
# ---------------------------------------------------------------------------------------------------------------

SONIC_BASE = yaml.safe_load(SONIC_FIXTURE.read_text(encoding="utf-8"))
SONIC_BASE["tests"] = []
SONIC_BASE.pop("scenarios", None)


def validate(topo):
    prev = cc._QUIET_DIE
    cc._QUIET_DIE = True  # as cmd_validate --json: die() raises SystemExit(<message>)
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            E.ensure_valid_topology(topo)
            resolved = E.resolve_topology(topo, topo_path=None)
            E.validate_scenarios(resolved)
            E.build_coverage_model(resolved, topo_path=None)
        return True, "", resolved
    except SystemExit as e:
        return False, str(e).strip(), None
    finally:
        cc._QUIET_DIE = prev


def value(p):
    tok = p["types"][0]
    if (tok, p["name"]) in BY_NAME:
        return copy.deepcopy(BY_NAME[(tok, p["name"])])
    if tok == "enum":
        return "pass" if "pass" in p["values"] else p["values"][0]
    return copy.deepcopy(VALUES[tok])


def minimal_test(entry):
    spec = entry["parameters"]
    t = {"name": f"t_{entry['id']}", "kind": entry["kind"]}
    if entry["kind"] == "invariant":
        t["type"] = entry["id"]
    by = {p["name"]: p for p in spec["params"]}
    for p in spec["params"]:
        if p["required"]:
            t[p["name"]] = value(p)
    for c in spec["constraints"]:
        if c["operator"] == "exactly_one_of":
            first = by[c["params"][0]]
            t[first["name"]] = OTHER if "node" in first["types"] else value(first)
    return t


def leg_po10(cat):
    bad, outcomes = [], {True: 0, False: 0}
    for entry in cat["checks"]:
        topo = copy.deepcopy(SONIC_BASE)
        topo["tests"] = [minimal_test(entry)]
        ok, msg, _r = validate(topo)
        want = entry["status"][SONIC_TYPE]["state"] == "implemented"
        outcomes[ok] += 1
        if ok != want:
            bad.append(f"{entry['id']}: catalogue {entry['status'][SONIC_TYPE]['state']}, validate "
                       f"{'accepts' if ok else 'rejects'}{(': ' + msg[:100]) if msg else ''}")
        elif not ok and f"'{VANTAGE}'" not in msg and f" {VANTAGE} " not in msg:
            bad.append(f"{entry['id']}: rejected, but the message does not name {VANTAGE}: {msg[:100]}")
    return bad, outcomes


# ---------------------------------------------------------------------------------------------------------------
# PO-11, PO-12, PO-23, PO-24: cells, classes, reasons, axis
# ---------------------------------------------------------------------------------------------------------------

def classes():
    out = {}
    for cls, members in C.STATUS_CLASSES.items():
        for cid in members:
            out.setdefault(cid, []).append(cls)
    return out


def seam_decided(entry, provider):
    cls = classes().get(entry["id"], ["seam"])
    if cls == ["exec"]:
        return False
    if provider.runtime_requirement == "vm" and entry["kind"] in C.VM_GATED:
        return True
    return cls == ["seam"]


def leg_po11(cat, engine_source):
    bad, n = [], 0
    for entry in cat["checks"]:
        for ntype, cell in entry["status"].items():
            provider = M.NOS_PROVIDERS[ntype]
            if not seam_decided(entry, provider):
                continue
            n += 1
            d = T.capability_for(provider, entry["id"])
            want = ("implemented", None) if d.state == T.CAP_IMPL else ("not implemented", d.message)
            if (cell["state"], cell["reason"]) != want:
                bad.append(f"{entry['id']} on {ntype}: {cell['state']!r} {cell['reason']!r} != capability_for {want}")
    fn = functions(ast.parse(engine_source)).get("_nos_collect")
    if fn is None or "capability_for" not in call_names(fn):
        bad.append("the engine's _nos_collect does not call capability_for")
    return bad, n


def leg_po12(cat):
    bad = []
    ids = {e["id"] for e in cat["checks"]}
    for cid, cls in classes().items():
        if cid not in ids:
            bad.append(f"status class {cls[0]!r} names {cid!r}, which is not a check")
        if len(cls) > 1:
            bad.append(f"{cid} is in classes {cls}")
    for ntype in M.nos_known_types():
        p = M.NOS_PROVIDERS[ntype]
        if p.runtime_requirement == "vm":
            continue
        for cid in C.STATUS_CLASSES.get("core", ()):
            d = p.capabilities.get(cid)
            if d is not None and d.state == T.CAP_IMPL:
                bad.append(f"{ntype} (runtime {p.runtime_requirement}) declares IMPL for core-class {cid}")
    return bad


def code_reason(entry, ntype):
    provider = M.NOS_PROVIDERS[ntype]
    if classes().get(entry["id"]) == ["exec"]:
        if T.is_deferred(provider.exec_command_rule):
            return M._exec_command_allowed("x", ntype)[1]
        return None
    if seam_decided(entry, provider):
        d = T.capability_for(provider, entry["id"])
        return None if d.state == T.CAP_IMPL else d.message
    return None


def leg_po23(cat):
    bad, n = [], 0
    for entry in cat["checks"]:
        for ntype, cell in entry["status"].items():
            if cell["state"] == "implemented":
                if cell["reason"] is not None:
                    bad.append(f"{entry['id']} on {ntype}: implemented with reason {cell['reason']!r}")
                continue
            n += 1
            if not isinstance(cell["reason"], str) or not cell["reason"].strip():
                bad.append(f"{entry['id']} on {ntype}: not implemented with no reason")
            elif cell["reason"] != code_reason(entry, ntype):
                bad.append(f"{entry['id']} on {ntype}: reason {cell['reason'][:50]!r} is not its code source's text")
    return bad, n


def leg_po24(cat):
    bad = []
    got = [nt["type"] for nt in cat["node_types"]]
    if got != list(M.nos_known_types()):
        bad.append(f"node_types {got} != nos_known_types() {list(M.nos_known_types())}")
    for nt in cat["node_types"]:
        p = M.NOS_PROVIDERS.get(nt["type"])
        if p is None or nt["runtime_requirement"] != p.runtime_requirement:
            bad.append(f"{nt['type']}: runtime_requirement {nt['runtime_requirement']!r}")
    for t in ("host", "linux"):
        if t in got:
            bad.append(f"{t!r} is a node type")
    return bad


# ---------------------------------------------------------------------------------------------------------------
# PO-13, PO-14: mirrors of code literals
# ---------------------------------------------------------------------------------------------------------------

def str_tuple(node):
    if isinstance(node, ast.Tuple) and all(isinstance(e, ast.Constant) and isinstance(e.value, str)
                                           for e in node.elts):
        return tuple(e.value for e in node.elts)
    return None


def eig_set_literals(model_source):
    out = []
    for n in ast.walk(ast.parse(model_source)):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_eig_set" for t in n.targets):
            out.append(str_tuple(n.value))
    return out


def kind_literals(engine_source):
    out = []
    for n in ast.walk(ast.parse(engine_source)):
        if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name) and n.left.id == "kind" \
                and len(n.ops) == 1 and isinstance(n.ops[0], ast.NotIn):
            tup = str_tuple(n.comparators[0])
            if tup and "ping" in tup and "invariant" in tup:
                out.append(tup)
    return out


def leg_po13(cat_vm_gated, model_source):
    found = eig_set_literals(model_source)
    if len(found) != 1:
        return [f"`_eig_set = (...)` found {len(found)} times in cassian_model.py, expected once"]
    return [] if tuple(cat_vm_gated) == found[0] else [f"vm-gated mirror {tuple(cat_vm_gated)} != _eig_set {found[0]}"]


def leg_po14(cat, kind_mirror, engine_source):
    found = kind_literals(engine_source)
    if len(found) != 1:
        return [f"the engine's `kind not in (...)` literal found {len(found)} times, expected once"]
    bad = []
    kinds = {e["kind"] for e in cat["checks"]} | {"invariant"}
    if kinds != set(found[0]):
        bad.append(f"catalogue kinds plus invariant {sorted(kinds)} != the engine literal {sorted(found[0])}")
    if tuple(kind_mirror) != found[0]:
        bad.append(f"KIND_MIRROR {tuple(kind_mirror)} != the engine literal {found[0]}")
    return bad


# ---------------------------------------------------------------------------------------------------------------
# PO-15: profiles
# ---------------------------------------------------------------------------------------------------------------

def pack_state():
    return json.dumps({"packs": M.builtin_invariant_packs,
                       "types": sorted(M.supported_pack_invariant_types)}, sort_keys=True, indent=2)


def leg_po15(cat):
    bad = []
    supported = M.supported_pack_invariant_types
    want = sorted(pid for pid, pack in M.builtin_invariant_packs.items()
                  if isinstance(pack, dict) and isinstance(pack.get("invariants"), list)
                  and all(isinstance(i, dict) and i.get("type") in supported for i in pack["invariants"]))
    got = [p["id"] for p in cat["profiles"]]
    if got != want:
        bad.append(f"profiles {got} != packs within the supported set {want}")
    for p in cat["profiles"]:
        if p["content"] != M.builtin_invariant_packs.get(p["id"]) or p["versioned"] is not False:
            bad.append(f"profile {p['id']}: content or versioned differs from the module literal")
    excluded = sorted(set(M.builtin_invariant_packs) - set(got))
    topo = yaml.safe_load(PACK_FIXTURE.read_text(encoding="utf-8"))
    ok, msg, resolved = validate(topo)
    listed = {p["id"]: p for p in cat["profiles"]}
    named = [pid for pid in topo.get("packs") or []]
    if not ok:
        bad.append(f"{PACK_FIXTURE.relative_to(ROOT)} rejected: {msg[:100]}")
    else:
        want_tests = [i["name"] for pid in named for i in listed.get(pid, {"content": {"invariants": []}})["content"]
                      ["invariants"]]
        got_tests = [t.get("name") for t in resolved.get("tests") or []]
        if not named or any(pid not in listed for pid in named) or got_tests != want_tests:
            bad.append(f"resolving {PACK_FIXTURE.name} gives tests {got_tests}, the listed invariants are {want_tests}")
    ok, msg, _r = validate(yaml.safe_load(PACK_NEG.read_text(encoding="utf-8")))
    if ok:
        bad.append(f"{PACK_NEG.relative_to(ROOT)} is accepted")
    return bad, got, excluded


def leg_aliasing(before):
    after = pack_state()
    return [] if after == before else ["the pack table or the supported type set changed in memory"]


# ---------------------------------------------------------------------------------------------------------------
# PO-22: label reasons that cite a code fact
# ---------------------------------------------------------------------------------------------------------------

def kw_in(node, name, value):
    return any(isinstance(n, ast.keyword) and n.arg == name and isinstance(n.value, ast.Constant)
               and n.value.value == value for n in ast.walk(node))


def calls_to(fn, name):
    return [n for n in ast.walk(fn) if isinstance(n, ast.Call)
            and ((isinstance(n.func, ast.Name) and n.func.id == name)
                 or (isinstance(n.func, ast.Attribute) and n.func.attr == name))]


def list_consts(node):
    return [[e.value for e in n.elts if isinstance(e, ast.Constant)] for n in ast.walk(node) if isinstance(n, ast.List)]


def po22_i(engine_source):
    fn = functions(ast.parse(engine_source)).get("cmd_replay")
    ok = fn is not None and any(kw_in(c, "_report_authority", "gate") for c in calls_to(fn, "cmd_test"))
    return [] if ok else ["cmd_replay's call to cmd_test does not carry _report_authority=\"gate\""]


def po22_ii(engine_source):
    fns, bad = functions(ast.parse(engine_source)), []
    for caller in ("cmd_test", "cmd_replay"):
        fn = fns.get(caller)
        if fn is None or not any(kw_in(c, "reconfigure", True) for c in calls_to(fn, "cmd_up")):
            bad.append(f"{caller} does not call cmd_up with reconfigure=True")
    up = fns.get("cmd_up")
    branch = [n for n in ast.walk(up) if isinstance(n, ast.If) and "reconfigure" in ast.unparse(n.test)] if up else []
    lists = [ls for b in branch for ls in list_consts(b)]
    rm = [n for b in branch for n in ast.walk(b) if isinstance(n, ast.List)
          and [e.value for e in n.elts if isinstance(e, ast.Constant)][-2:] == ["rm", "-rf"]
          and any(isinstance(e, ast.Call) and "lab_dir" in call_names(e) for e in ast.walk(n))]
    if not any("containerlab" in ls and "destroy" in ls for ls in lists):
        bad.append("cmd_up's reconfigure branch does not run `containerlab destroy`")
    if not rm:
        bad.append("cmd_up's reconfigure branch does not run `rm -rf` on lab_dir")
    return bad


def subparser(parser, path):
    p = parser
    for word in path.split():
        sub = next(a for a in p._actions if isinstance(a, argparse._SubParsersAction))
        p = sub.choices[word]
    return p


def po22_iii(parser):
    bad = []
    for cmd, flag in REASON_FLAGS:
        opts = {s for a in subparser(parser, cmd)._actions for s in a.option_strings}
        if flag not in opts:
            bad.append(f"{cmd} does not register {flag}")
    return bad


def po22_iv(model_source):
    fn = functions(ast.parse(model_source)).get("topo_to_containerlab")
    if fn is None:
        return ["topo_to_containerlab not found"]
    bad = []
    cfg = [n for n in ast.walk(fn) if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
           and "node_cfg_dir" in call_names(n.value) and any(isinstance(t, ast.Name) for t in n.targets)]
    var = cfg[0].targets[0].id if cfg else None
    binds = [ast.unparse(n) for n in ast.walk(fn) if isinstance(n, ast.JoinedStr)]
    for name in ("daemons", "vtysh.conf", "frr.conf"):
        writes = [c for c in calls_to(fn, "write_file") if c.args and isinstance(c.args[0], ast.BinOp)
                  and isinstance(c.args[0].left, ast.Name) and c.args[0].left.id == var
                  and isinstance(c.args[0].right, ast.Constant) and c.args[0].right.value == name]
        if var is None or not writes:
            bad.append(f"{name} is not written under node_cfg_dir")
        if not any(re.search(r"\{" + str(var) + r"\}/" + re.escape(name) + r":[^'\"]*:ro['\"]$", b) for b in binds):
            bad.append(f"{name} is not bound :ro")
    return bad


def po22_v(ai_source):
    tree = ast.parse(ai_source)
    fns = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    seen, stack = set(), ["cmd_ai_review"]
    while stack:
        f = stack.pop()
        if f in seen or f not in fns:
            continue
        seen.add(f)
        stack += [c for c in call_names(fns[f]) if c in fns]
    bad = []
    for f in sorted(seen):
        names = call_names(fns[f])
        hits = sorted({c for c in names if c in WRITE_CALLS})
        for c in calls_to(fns[f], "dump"):
            if isinstance(c.func, ast.Attribute) and isinstance(c.func.value, ast.Name) and c.func.value.id == "json":
                hits.append("json.dump")
        for c in calls_to(fns[f], "open"):
            mode = c.args[1] if len(c.args) > 1 else next((k.value for k in c.keywords if k.arg == "mode"), None)
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and set(mode.value) & set("wax"):
                hits.append(f"open(..., {mode.value!r})")
        if hits:
            bad.append(f"{f} (reachable from cmd_ai_review) calls {', '.join(hits)}")
    if "cmd_ai_review" not in seen:
        bad.append("cmd_ai_review not found")
    return bad, len(seen)


def po22_vi(engine_source):
    fn = functions(ast.parse(engine_source)).get("_interface_state_capability_check")
    if fn is None or PROBE_ARGV not in list_consts(fn):
        return [f"{PROBE_ARGV} is not in _interface_state_capability_check"]
    return []


# ---------------------------------------------------------------------------------------------------------------
# PO-28: provenance and its proof legs
# ---------------------------------------------------------------------------------------------------------------

def leg_po28(cat, mapping, hs2_results):
    bad = []
    if cat["provenance"] != PROVENANCE_7_6:
        bad.append("the provenance block differs from section 7.6")
    texts = {"HS-3": HS3_FILE.read_text(encoding="utf-8") if HS3_FILE.is_file() else "",
             "HS-4": HS4_FILE.read_text(encoding="utf-8") if HS4_FILE.is_file() else ""}
    for part in cat["provenance"]["declared_proof_bound"]:
        legs = mapping.get(part, ())
        if not legs:
            bad.append(f"declared, proof-bound part {part!r} maps to no proof leg")
        for proof, label in legs:
            present = any(n.startswith(label) for n in hs2_results) if proof == "HS-2" else label in texts[proof]
            if not present:
                bad.append(f"{part}: {proof} leg {label!r} not found")
    return bad


# ---------------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------------

def main():
    cat = build()
    engine_source = (SRC / "cassian_engine.py").read_text(encoding="utf-8")
    model_source = (SRC / "cassian_model.py").read_text(encoding="utf-8")
    ai_source = (SRC / "cassian_ai.py").read_text(encoding="utf-8")
    packs_before = pack_state()

    # P10
    bad, outcomes = leg_po10(cat)
    check("P10 PO-10 sonic-vm: validate accepts the minimal test iff the catalogue cell is implemented",
          not bad and outcomes[True] and outcomes[False],
          "; ".join(bad[:3]) if bad else f"{outcomes[True]} accepted = implemented, {outcomes[False]} rejected = "
                                         f"not implemented, each rejection naming {VANTAGE}")
    flipped = copy.deepcopy(cat)
    cell = next(e for e in flipped["checks"] if e["status"][SONIC_TYPE]["state"] == "implemented")
    cell["status"][SONIC_TYPE]["state"] = "not implemented"
    bad, _o = leg_po10(flipped)
    check("N P10 PO-10 a copy of the catalogue with one sonic-vm cell flipped is reported",
          len(bad) == 1 and bad[0].startswith(cell["id"] + ":"), "; ".join(bad) or "leg held")

    # P11
    bad, n = leg_po11(cat, engine_source)
    report("P11 PO-11 every seam-decided cell equals capability_for; _nos_collect calls capability_for", bad,
           f"{n} cells")
    sonic = M.NOS_PROVIDERS[SONIC_TYPE]
    token = sorted(t for t, d in sonic.capabilities.items() if d.state == T.CAP_IMPL)[0]
    caps = dict(sonic.capabilities, **{token: T.unsup("zz patched by HS-2")})
    with registry_with(**{SONIC_TYPE: dataclasses.replace(sonic, capabilities=caps)}):
        pcat = build()
        bad, _n = leg_po11(pcat, engine_source)
    pcell = next(e for e in pcat["checks"] if e["id"] == token)["status"][SONIC_TYPE]
    check(f"N P11 PO-11 sonic-vm's '{token}' patched to UNSUP: the cell follows and the leg still holds",
          pcell == {"state": "not implemented", "reason": "zz patched by HS-2", "detail": None} and not bad,
          f"cell {pcell['state']!r} {pcell['reason']!r}")
    doctored = edit_in(engine_source, "_nos_collect", "capability_for(provider, request.kind)",
                       "_zz(provider, request.kind)")
    bad = leg_po11(cat, doctored)[0] if doctored else ["anchor not found once in _nos_collect"]
    check("N P11 PO-11 a doctored engine whose _nos_collect no longer calls capability_for is reported",
          bad == ["the engine's _nos_collect does not call capability_for"], "; ".join(bad) or "leg held")

    # P12
    report("P12 PO-12 the status classes partition the checks; no non-vm provider declares a core check IMPL",
           leg_po12(cat), f"core {len(C.STATUS_CLASSES['core'])}, exec {len(C.STATUS_CLASSES['exec'])}, "
                          f"seam {len(cat['checks']) - sum(len(v) for v in C.STATUS_CLASSES.values())}")
    for desc, table, want in (
            ("route_present in both core and exec", dict(C.STATUS_CLASSES, core=C.STATUS_CLASSES["core"] + (
                "route_present",), exec=C.STATUS_CLASSES["exec"] + ("route_present",)),
             "ERROR: checks: check 'route_present' is in status classes core and exec\n"),
            ("a class member outside the universe", dict(C.STATUS_CLASSES, core=C.STATUS_CLASSES["core"] + (
                "zz_not_a_check",)), "ERROR: checks: status class 'core' names 'zz_not_a_check', which is not a "
                                    "check\n")):
        with patched(C, "STATUS_CLASSES", table):
            rc, out, err = build_as_cli()
        check(f"N P12 PO-12 E8, {desc}: exit 1, empty stdout, the E8 message", rc == 1 and out == "" and err == want,
              f"rc={rc} stderr={err.strip()!r}")

    # P13, P14
    bad = leg_po13(C.VM_GATED, model_source)
    report("P13 PO-13 the vm-gated mirror equals cassian_model.py's _eig_set literal", bad, str(C.VM_GATED))
    doctored = model_source.replace('_eig_set = ("tcp", "bgp_neighbor", "invariant", "route_prefix")',
                                    '_eig_set = ("tcp", "bgp_neighbor", "invariant", "route_prefix", "ping")')
    bad = leg_po13(C.VM_GATED, doctored) if doctored != model_source else ["anchor not found"]
    check("N P13 PO-13 a doctored model source with a fifth gated kind is reported",
          len(bad) == 1 and "!=" in bad[0], "; ".join(bad) or "leg held")
    bad = leg_po14(cat, C.KIND_MIRROR, engine_source)
    report("P14 PO-14 the catalogue's kinds plus invariant equal the engine's kind literal, in order", bad,
           str(C.KIND_MIRROR))
    lit = '("ping", "tcp", "bgp_neighbor", "route_prefix", "invariant", "exec")'
    doctored = engine_source.replace(lit, '("ping", "tcp", "bgp_neighbor", "route_prefix", "invariant", "exec", '
                                          '"zz_kind")') if engine_source.count(lit) == 1 else engine_source
    bad = leg_po14(cat, C.KIND_MIRROR, doctored) if doctored != engine_source else ["anchor not found once"]
    check("N P14 PO-14 a doctored engine with a seventh kind is reported", len(bad) == 2, "; ".join(bad) or "leg held")

    # P15
    bad, listed, excluded = leg_po15(cat)
    build()
    bad += leg_po15(cat)[0]
    bad += leg_aliasing(packs_before)
    report("P15 PO-15 profiles: the rule, the content, the expansion, the negative fixture, no aliasing", bad,
           f"listed {listed}; excluded by the rule {excluded}; two resolves and two builds, pack state unchanged")
    pack = M.builtin_invariant_packs[listed[0]]
    saved = copy.deepcopy(pack["invariants"][0])
    try:
        pack["invariants"][0]["expect"] = "fail" if saved.get("expect") != "fail" else "pass"
        bad = leg_aliasing(packs_before)
    finally:
        pack["invariants"][0].clear()
        pack["invariants"][0].update(saved)
    check("N P15 PO-15 a seeded in-place mutation of the pack table is caught by the aliasing comparator",
          bad and not leg_aliasing(packs_before), "; ".join(bad) or "comparator held")

    # P22
    parser = cassian_cli.build_parser()
    report("P22 PO-22 (i) cmd_replay's cmd_test call carries _report_authority=\"gate\"", po22_i(engine_source),
           "replay's authoritative reason")
    report("P22 PO-22 (ii) cmd_test and cmd_replay call cmd_up(reconfigure=True); its branch destroys and rm -rf's",
           po22_ii(engine_source), "replay's, test's, up's and run's destructive reasons")
    report("P22 PO-22 (iii) each flag a reason names is registered on its command", po22_iii(parser),
           ", ".join(f"{c} {f}" for c, f in REASON_FLAGS))
    report("P22 PO-22 (iv) gen: daemons, vtysh.conf, frr.conf written under node_cfg_dir and bound :ro",
           po22_iv(model_source), "gen's lab-mutating reason")
    bad, nreach = po22_v(ai_source)
    report("P22 PO-22 (v) ai: no function reachable by name from cmd_ai_review writes a file", bad,
           f"{nreach} functions reachable")
    report("P22 PO-22 (vi) interface_state: the probe argv is in _interface_state_capability_check",
           po22_vi(engine_source), "the limitation note's code fact")
    doctored = edit_in(engine_source, "cmd_replay", '_report_authority="gate"', '_report_authority="lab"')
    bad = po22_i(doctored) if doctored else ["anchor not found once in cmd_replay"]
    check("N P22 PO-22 (i) a doctored engine without _report_authority=\"gate\" in cmd_replay is reported",
          bool(bad) and "anchor" not in bad[0], "; ".join(bad) or "leg held")
    doctored = ai_source.replace("\ndef cmd_ai_review(args) -> None:\n",
                                 "\ndef cmd_ai_review(args) -> None:\n    _ai_finalize_and_emit('review', {}, args)\n", 1)
    bad = po22_v(doctored)[0] if doctored != ai_source else ["anchor not found"]
    check("N P22 PO-22 (v) a doctored cassian_ai.py calling _ai_finalize_and_emit from cmd_ai_review is reported",
          any("_ai_write_bundle" in b for b in bad), "; ".join(bad) or "leg held")

    # P23
    bad, n = leg_po23(cat)
    report("P23 PO-23 every not-implemented reason is its code source's text, verbatim; implemented has none",
           bad, f"{n} not-implemented cells")
    seam_id = next(e["id"] for e in cat["checks"] if classes().get(e["id"]) is None)
    deferred = T.deferred_leg("zz_exec", "HS-2 synthetic")
    with registry_with(**{SYNTH: synthetic(exec_command_rule=deferred, runtime_requirement=None)}):
        scat = build()
        bad, _n = leg_po23(scat)
        floor = M._exec_command_allowed("x", SYNTH)[1]
    xcell = next(e for e in scat["checks"] if e["id"] == "exec")["status"][SYNTH]
    check("N P23 PO-23 a synthetic provider with a deferred exec rule gives the floor message",
          xcell == {"state": "not implemented", "reason": floor, "detail": None} and not bad, f"{xcell['reason']!r}")
    caps = dict(M.NOS_PROVIDERS["frr"].capabilities, **{seam_id: T.CapabilityDisposition(T.CAP_VERIFY, "zz verify")})
    with registry_with(**{SYNTH: synthetic(capabilities=caps)}):
        vcat = build()
        bad, _n = leg_po23(vcat)
    vcell = next(e for e in vcat["checks"] if e["id"] == seam_id)["status"][SYNTH]
    check(f"N P23 PO-23 a synthetic CAP_VERIFY disposition with a message ('{seam_id}') gives not implemented with "
          f"it", vcell == {"state": "not implemented", "reason": "zz verify", "detail": None} and not bad,
          f"{vcell['state']!r} {vcell['reason']!r}")
    caps = dict(M.NOS_PROVIDERS["frr"].capabilities, **{seam_id: T.CapabilityDisposition(T.CAP_VERIFY, None)})
    with registry_with(**{SYNTH: synthetic(capabilities=caps)}):
        rc, out, err = build_as_cli()
    want = f"ERROR: checks: node type '{SYNTH}' declares '{seam_id}' as {T.CAP_VERIFY} with no message"
    check("N P23 PO-23 E9: a CAP_VERIFY disposition with no message stops the build", rc == 1 and out == ""
          and err.startswith(want), f"rc={rc} stderr={err[:90]!r}")

    # P24
    report("P24 PO-24 node_types equals nos_known_types() with each provider's runtime_requirement; no host, linux",
           leg_po24(cat), ", ".join(f"{nt['type']}:{nt['runtime_requirement']}" for nt in cat["node_types"]))
    with registry_with(**{SYNTH: synthetic()}):
        axis = [nt["type"] for nt in build()["node_types"]]
        bad = leg_po24(cat)
    check("N P24 PO-24 a synthetic registry entry appears in the axis, and the unpatched catalogue is reported",
          SYNTH in axis and axis == list(sorted(axis)) and bool(bad), "; ".join(bad[:1]) or "leg held")

    # P28
    names = [n for n, _ok in checks]
    bad = leg_po28(cat, MAPPING, names)
    report("P28 PO-28 provenance equals section 7.6; every declared, proof-bound part maps to an existing leg", bad,
           f"{len(cat['provenance']['declared_proof_bound'])} parts mapped")
    for part in ("notices", "status_classes"):
        bad = leg_po28(cat, {k: v for k, v in MAPPING.items() if k != part}, names)
        check(f"N P28 PO-28 a copy of the mapping table without {part!r} is reported",
              bad == [f"declared, proof-bound part {part!r} maps to no proof leg"], "; ".join(bad) or "leg held")
    bad = leg_po28(dict(cat, provenance=dict(cat["provenance"], derived_from_code=["checks.id"])), MAPPING, names)
    check("N P28 PO-28 a catalogue copy with a shortened provenance block is reported",
          bad == ["the provenance block differs from section 7.6"], "; ".join(bad) or "leg held")

    fails = [n for n, ok in checks if not ok]
    print("RESULT: %s (%d checks, %d failed)" % ("PASS" if not fails else "FAIL", len(checks), len(fails)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
