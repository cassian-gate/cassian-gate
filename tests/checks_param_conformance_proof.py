#!/usr/bin/env python3
"""HS-3 -- parameter conformance proof (Stage-1 gap item (d)(2), WI-7 script 1).

Proof obligations: PO-09 (handover v9-rev3 section 15.1), PO-29 (rulings note 1 section 5) and PO-34
(rulings note 14 section 2). Requirements: REQ-S1D2-7, -27 and -33 (its PO-09 marker leg), REQ-S1D2-39 and
REQ-S1D2-44. Acceptance checks: C-5, C-29 and handover C-34.
Founder rulings applied: SLD-2 with both conditions and OPEN-18 (section 0.4); S1D2-S1-R4 and -R5 (tokens
`number` and `boolean`; "HS-3 names every enforced: run parameter"); S1D2-S1-R6 (PO-29); S1D2-S3-R1 (token
`ipv4`); S1D2-S3-R2 and S1D2-S5-R2 (the `constraints` list, four operators; `at_most_one_of` bound on its
validate half only); S1D2-S3-R3 and S1D2-S5-R1 (names and aliases); S1D2-S6-R1 and -R2 (PO-34);
S1D2-S7-R6 (the fixture targets an adjacent node); S1D2-S22-R1 (rulings note 34: the discovery leg's reading of
"declared required").

What it proves: the parameter lists the catalogue declares for each check agree with what `cassian validate`
accepts and rejects, in both directions. The spec is the catalogue `cassian checks` builds from the live code;
validate is the code itself, called in process in cmd_validate's order.

Legs
  M  MARKER     the catalogue's provenance marks `checks.parameters` as declared and proof-bound (REQ-S1D2-33).
  V  SHAPE      every parameter entry has exactly the keys of section 7.2; its types are non-empty and drawn
                from the closed vocabulary VOCAB; `values` is non-null iff `enum` is a type; `enforced` is
                validate or run; `unknown_keys` is accepted or rejected; every constraint uses one of the four
                ruled operators with the `enforced` value its ruling gives it.
  B  BINDING    cmd_validate's body calls ensure_valid_topology, resolve_topology, validate_scenarios and
                build_coverage_model in that order (AST, by name). The mirror below makes the same four calls.
  D2 REQUIRED   per check, the instance built from exactly the declared required parameters (canonical names,
                valid values, nothing else; plus the first member of each exactly_one_of) is accepted.
  D1 OMIT       omitting a required parameter is rejected if it is `enforced: validate`, accepted if `run`.
     ALIAS      each declared alias, given in place of its parameter, is accepted.
     OPTIONAL   each optional parameter added with a valid value is accepted, unless a declared constraint
                forbids it (then rejected).
     TYPE       each further type token of a parameter, given as its value, gives the predicted outcome.
     IPV6       an IPv6 literal on an `enforced: validate` parameter is accepted iff `ip` is among its types.
     UNKNOWN    an undeclared key is accepted iff `unknown_keys` is `accepted`.
  K  CONSTRAINT each `enforced: validate` constraint, over its parameters' presence (and its `when`): the
                predicted outcome. `at_most_one_of` (`enforced: run`) is accepted at validate in every
                combination (its validate half; S1D2-S5-R2).
  X  DISCOVERY  from the envelope and the vantage only, follow validate's "requires ... '<key>'" messages
                until acceptance; each named key must be a declared required parameter, an alias of one, or a
                member of a declared exactly_one_of constraint; no other operator counts (S1D2-S22-R1, reading
                PO-09 under S1D2-S3-R2).
  P29           every `enforced: validate` parameter typed `enum` or `boolean` rejects a value outside its
                domain (`zz_out_of_domain`; also the string "false" for a boolean).
  P34           evpn_bgp_session_up: a `peer` that is an IP literal, an undeclared name, or the test's own
                node is rejected with the ruled text; a declared other node, also padded, is accepted.
  L  OPEN-18    the `enforced: run` parameters are named, with the legs that reach them.
  N  MUTANTS    each leg above is shown capable of failing: the spec mutated in memory (a required parameter
                dropped; a spurious required parameter; one unknown_keys flipped; a constraint dropped; a
                `when` flipped; a validate-required parameter demoted; the marker dropped; an unknown token),
                the model's source edited in memory (exec removed from the WI-12 expect rule; WI-17's
                node-membership test disabled; WI-17's self-peer test disabled), and cmd_validate's source
                edited in memory (the resolve_topology call removed). Each mutant must fail its target leg.

Coverage limits (PBE-P2-8 / PBE-P2-14), stated so a PASS is not read as more than it is:
  1. OPEN-18: `enforced: run` parameters are checked on their validate half only: omitting one is accepted, and
     its type is not tested. Leg L names each. The run's own refusal of a missing or wrong value is not
     exercised (no lab; rows BL-P2-S1D2-2, -10, -33 and -36 record known run-only refusals).
  2. `at_most_one_of` is bound on its validate half only (S1D2-S5-R2): both members present is accepted at
     validate; the run's refusal of the pair is not exercised (row BL-P2-S1D2-36).
  3. One base topology, `topologies/evpn_mac_route_present.yaml` (frr nodes). The vantage is leaf1 and a node
     destination or peer is spine1, which is directly linked to it, so the multi-hop ping rule does not engage
     (S1D2-S7-R6, row BL-P2-S1D2-40). A ping whose destination is an IP literal carries `expect: fail` for the
     same reason. Topology-context rules beyond these (the sonic-vm validate gate, PO-10) are HS-2's.
  4. One representative value per token (VALUES). A validator that accepts that value and rejects another in
     the same token's domain is not caught; the tokens' meanings are bound only through these values.
  5. The mirror builds each topology in memory: cmd_validate's `load_yaml` (parsing) and
     `write_coverage_artifact` (an advisory write that rejects nothing) are not exercised. Leg B binds the
     order of the four calls by name only (PBE-P2-14); a rejection added elsewhere in cmd_validate is not seen.
  6. Leg X reads only messages of the form "requires ... '<key>'"; any other rejection ends the leg as a
     failure, never as a pass.
  7. P29 sweeps the out-of-domain values above only; P34 sweeps the five peers above only.
  8. A spec mutant shows a leg can fail on a doctored spec; it does not show the leg catches every possible
     doctoring.

usage: PYTHONPATH=src python tests/checks_param_conformance_proof.py   (from the repo root; writes nothing)
"""
import ast
import contextlib
import copy
import io
import ipaddress
import itertools
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

BASE_TOPOLOGY = ROOT / "topologies" / "evpn_mac_route_present.yaml"
VANTAGE = "leaf1"
OTHER = "spine1"  # directly linked to VANTAGE (spine1:eth1 -- leaf1:eth1)
KINDS = ("ping", "tcp", "bgp_neighbor", "route_prefix", "exec")

# Section 7.2's closed vocabulary, as amended by S1D2-S1-R4 (number), S1D2-S1-R5 (boolean; `string` loses its
# catch-all) and S1D2-S3-R1 (ipv4). Fifteen tokens.
VOCAB = ("as_path_regex", "boolean", "cidr", "community", "community_list", "enum", "exec_assertion", "integer",
         "ip", "ipv4", "mac", "node", "number", "string", "string_list")
PARAM_KEYS = ("aliases", "enforced", "name", "required", "types", "values")
CONSTRAINT_KEYS = ("enforced", "operator", "params", "when")
# The four ruled operators and the `enforced` value each carries (S1D2-S3-R2; S1D2-S5-R2).
OPERATORS = {"exactly_one_of": "validate", "forbidden_if": "validate", "required_iff": "validate",
             "at_most_one_of": "run"}

# One valid value per token (coverage limit 4), with parameter-specific overrides.
VALUES = {
    "as_path_regex": "^65001$",
    "boolean": True,
    "cidr": "10.10.10.0/24",
    "community": "65000:1",
    "community_list": ["65000:1", "65000:2"],
    "exec_assertion": {"contains": "x"},
    "integer": 1,
    "ip": "172.16.0.0",
    "ipv4": "172.16.0.0",
    "mac": "00:11:22:33:44:55",
    "node": VANTAGE,
    "number": 1.5,
    "string": "x",
    "string_list": ["t1"],
}
BY_NAME = {
    ("integer", "count"): 1, ("integer", "port"): 179, ("integer", "vni"): 10100, ("integer", "expected"): 100,
    ("integer", "timeout_s"): 5, ("integer", "per_attempt_timeout_s"): 1,
    ("node", "dst"): OTHER, ("node", "peer"): OTHER,
    ("string", "command"): 'vtysh -c "show version"', ("string", "interface"): "eth1", ("string", "src_if"): "eth1",
}
ENUM_PICK = {"expect": "pass", "match": "all"}
IP_DESTINATIONS = ("dst", "to", "to_ip")  # on ping: an IP literal here takes expect: fail (coverage limit 3)

PO34_IP = "172.16.0.0"
PO34_UNKNOWN = "nosuchnode"
PO34_TEXT_UNKNOWN = "invariant 'evpn_bgp_session_up' references unknown 'peer' value '%s' (node not declared in " \
                    "topology 'nodes:' section)"
PO34_TEXT_SELF = "invariant 'evpn_bgp_session_up' 'peer' value '%s' is the test's own 'node' (an EVPN session " \
                 "needs a different node)"

# In-memory source edits for leg N. Each anchor must occur exactly once in the live source.
MODEL_MUTANTS = {
    "P29": ('if (t.get("kind") or "").strip() in ("ping", "tcp", "bgp_neighbor", "exec"):',
            'if (t.get("kind") or "").strip() in ("ping", "tcp", "bgp_neighbor"):'),
    "P34-unknown": ('if t["peer"] not in nodes_by_name:', 'if False:'),
    "P34-self": ('if t["peer"] == src.strip():', 'if False:'),
}
BINDING_CALLS = ("ensure_valid_topology", "resolve_topology", "validate_scenarios", "build_coverage_model")
BINDING_MUTANT = ("resolved = resolve_topology(topo, topo_path=topo_path)", "resolved = topo")  # in cmd_validate

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" | {detail}" if detail else ""), flush=True)


# ---------------------------------------------------------------------------------------------------------------
# The validator: cmd_validate's four calls, in its order, in process (leg B binds the order)
# ---------------------------------------------------------------------------------------------------------------

BASE = yaml.safe_load(BASE_TOPOLOGY.read_text(encoding="utf-8"))
BASE["tests"] = []


class Validator:
    def __init__(self, model=None):
        self.ensure = model.ensure_valid_topology if model else E.ensure_valid_topology
        self.resolve = model.resolve_topology if model else E.resolve_topology
        self.runs = 0

    def __call__(self, test):
        topo = copy.deepcopy(BASE)
        topo["tests"] = [copy.deepcopy(test)]
        self.runs += 1
        prev = cc._QUIET_DIE
        cc._QUIET_DIE = True  # as cmd_validate --json: die() raises SystemExit(<message>)
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.ensure(topo)
                resolved = self.resolve(topo, topo_path=None)
                E.validate_scenarios(resolved)
                E.build_coverage_model(resolved, topo_path=None)
            return True, ""
        except SystemExit as e:
            return False, str(e).strip()
        finally:
            cc._QUIET_DIE = prev


def model_mutant(key):
    old, new = MODEL_MUTANTS[key]
    text = (SRC / "cassian_model.py").read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"mutant {key}: anchor found {text.count(old)} times, expected 1: {old}")
    name = "cassian_model_hs3_" + key.replace("-", "_")
    mod = types.ModuleType(name)
    mod.__file__ = str(SRC / "cassian_model.py")
    sys.modules[name] = mod
    try:
        exec(compile(text.replace(old, new), f"<{name}>", "exec"), mod.__dict__)
    finally:
        sys.modules.pop(name, None)
    return mod


# ---------------------------------------------------------------------------------------------------------------
# Instances
# ---------------------------------------------------------------------------------------------------------------

def envelope(cid):
    if cid in KINDS:
        return {"name": f"t_{cid}", "kind": cid}
    return {"name": f"t_{cid}", "kind": "invariant", "type": cid}


def value(cid, p, token=None, v6=False):
    token = token or p["types"][0]
    if v6 and token in ("ip", "ipv4"):
        return "2001:db8::1"
    if token == "enum":
        return ENUM_PICK.get(p["name"], p["values"][0]) if p["values"] else "x"
    return copy.deepcopy(BY_NAME.get((token, p["name"]), VALUES[token]))


def is_ip_literal(v):
    try:
        ipaddress.ip_address(str(v))
        return True
    except ValueError:
        return False


def finish(cid, inst):
    """Coverage limit 3: a ping whose destination is an IP literal carries expect: fail."""
    if cid == "ping" and "expect" not in inst and any(is_ip_literal(inst.get(k)) for k in IP_DESTINATIONS):
        inst["expect"] = "fail"
    return inst


def params_of(spec):
    return {p["name"]: p for p in spec["params"]}


def required_instance(cid, spec):
    params = params_of(spec)
    inst = envelope(cid)
    for p in spec["params"]:
        if p["required"]:
            inst[p["name"]] = value(cid, p)
    for c in spec["constraints"]:
        if c["operator"] == "exactly_one_of":
            first = params[c["params"][0]]
            inst[first["name"]] = value(cid, first, token="node" if "node" in first["types"] else None)
    return inst


def when_holds(w, inst):
    if w is None or w["param"] not in inst:
        return False
    v = inst[w["param"]]
    if w["equals"] is not None:
        return str(v).strip().lower() == w["equals"]
    if w["type"] == "community_list":
        return isinstance(v, list)
    if w["type"] == "community":
        return isinstance(v, str)
    raise SystemExit(f"`when` type not modelled: {w}")


def predict(spec, inst):
    """Accept iff every validate-required parameter is present and every validate constraint holds."""
    for p in spec["params"]:
        if p["required"] and p["enforced"] == "validate":
            if p["name"] not in inst and not any(a in inst for a in p["aliases"]):
                return False
    for c in spec["constraints"]:
        if c["enforced"] != "validate":
            continue
        present = [x for x in c["params"] if x in inst]
        if c["operator"] == "exactly_one_of" and len(present) != 1:
            return False
        if c["operator"] == "at_most_one_of" and len(present) > 1:
            return False
        if c["operator"] == "forbidden_if" and when_holds(c["when"], inst) and present:
            return False
        if c["operator"] == "required_iff":
            holds = when_holds(c["when"], inst)
            if (holds and len(present) != len(c["params"])) or (not holds and present):
                return False
    return True


# ---------------------------------------------------------------------------------------------------------------
# Legs. Each returns a list of failure descriptions; empty means the leg holds.
# ---------------------------------------------------------------------------------------------------------------

def leg_marker(cat):
    bound = (cat.get("provenance") or {}).get("declared_proof_bound") or []
    return [] if "checks.parameters" in bound else ["provenance.declared_proof_bound lacks checks.parameters"]


def leg_shape(specs):
    bad = []
    for cid, spec in specs.items():
        if spec.get("unknown_keys") not in ("accepted", "rejected"):
            bad.append(f"{cid}: unknown_keys {spec.get('unknown_keys')!r}")
        for p in spec["params"]:
            where = f"{cid}.{p.get('name')}"
            if tuple(sorted(p)) != PARAM_KEYS:
                bad.append(f"{where}: keys {sorted(p)}")
                continue
            if not p["types"]:
                bad.append(f"{where}: no type")
            for tok in p["types"]:
                if tok not in VOCAB:
                    bad.append(f"{where}: token {tok!r} outside the vocabulary")
            if (p["values"] is not None) != ("enum" in p["types"]):
                bad.append(f"{where}: values {p['values']!r} with types {p['types']}")
            if p["enforced"] not in ("validate", "run"):
                bad.append(f"{where}: enforced {p['enforced']!r}")
        for c in spec["constraints"]:
            if tuple(sorted(c)) != CONSTRAINT_KEYS or OPERATORS.get(c.get("operator")) != c.get("enforced"):
                bad.append(f"{cid}: constraint {c}")
    return bad


def called_names(fn_node):
    """Names called in fn_node's body, first occurrence, in source order."""
    calls = [n for n in ast.walk(fn_node) if isinstance(n, ast.Call)]
    calls.sort(key=lambda n: (n.lineno, n.col_offset))
    out = []
    for n in calls:
        f = n.func
        name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
        if name and name not in out:
            out.append(name)
    return out


def leg_binding(engine_source):
    fns = [n for n in ast.walk(ast.parse(engine_source)) if isinstance(n, ast.FunctionDef) and n.name == "cmd_validate"]
    if len(fns) != 1:
        return [f"cmd_validate defined {len(fns)} times"]
    seq = [n for n in called_names(fns[0]) if n in BINDING_CALLS]
    return [] if tuple(seq) == BINDING_CALLS else [f"cmd_validate calls {seq}, mirror calls {list(BINDING_CALLS)}"]


def edit_in_cmd_validate(engine_source, old, new):
    """Replace `old` inside cmd_validate's own lines only; None unless it occurs there exactly once."""
    fn = [n for n in ast.walk(ast.parse(engine_source)) if isinstance(n, ast.FunctionDef) and n.name == "cmd_validate"]
    if len(fn) != 1:
        return None
    lines = engine_source.splitlines(keepends=True)
    body = "".join(lines[fn[0].lineno - 1:fn[0].end_lineno])
    if body.count(old) != 1:
        return None
    return "".join(lines[:fn[0].lineno - 1]) + body.replace(old, new) + "".join(lines[fn[0].end_lineno:])


def leg_d2(specs, validate):
    bad = []
    for cid, spec in specs.items():
        inst = finish(cid, required_instance(cid, spec))
        ok, msg = validate(inst)
        if not ok:
            bad.append(f"{cid}: required set rejected: {msg}")
    return bad


def leg_d1(specs, validate):
    bad = []

    def expect(cid, desc, inst, want):
        ok, msg = validate(inst)
        if ok != want:
            bad.append(f"{cid}: {desc}: expected {'accept' if want else 'reject'}, got "
                       f"{'accept' if ok else 'reject'}{(': ' + msg) if msg else ''}")

    for cid, spec in specs.items():
        d2 = required_instance(cid, spec)
        for p in spec["params"]:
            name = p["name"]
            if p["required"]:
                t = copy.deepcopy(d2)
                t.pop(name, None)
                expect(cid, f"omit {name} (enforced {p['enforced']})", finish(cid, t), p["enforced"] == "run")
            for alias in p["aliases"]:
                t = copy.deepcopy(d2)
                was = t.pop(name, None)
                t[alias] = copy.deepcopy(was) if was is not None else value(cid, p)
                expect(cid, f"alias {alias} for {name}", finish(cid, t), True)
            if not p["required"] and name not in d2:
                t = copy.deepcopy(d2)
                t[name] = value(cid, p)
                t = finish(cid, t)
                expect(cid, f"optional {name}", t, predict(spec, t))
            for token in p["types"][1:]:
                t = copy.deepcopy(d2)
                t[name] = value(cid, p, token=token)
                t = finish(cid, t)
                expect(cid, f"{name} as {token}", t, predict(spec, t))
            if p["enforced"] == "validate" and any(x in p["types"] for x in ("ip", "ipv4")):
                t = copy.deepcopy(d2)
                for c in spec["constraints"]:
                    if c["operator"] == "exactly_one_of" and name in c["params"]:
                        for x in c["params"]:
                            t.pop(x, None)
                t[name] = value(cid, p, v6=True)
                t = finish(cid, t)
                expect(cid, f"{name} = 2001:db8::1 (types {p['types']})", t, "ip" in p["types"])
        t = copy.deepcopy(d2)
        t["zz_unknown_key"] = 1
        expect(cid, "unknown key", finish(cid, t), spec["unknown_keys"] == "accepted")
    return bad


def leg_constraints(specs, validate):
    bad = []
    for cid, spec in specs.items():
        params = params_of(spec)
        d2 = required_instance(cid, spec)
        for c in spec["constraints"]:
            op, ps = c["operator"], c["params"]
            core = {k: v for k, v in d2.items() if k not in ps}
            cases = []
            if op in ("exactly_one_of", "at_most_one_of"):
                for n in range(0, len(ps) + 1):
                    for combo in itertools.combinations(ps, n):
                        t = copy.deepcopy(core)
                        for x in combo:
                            t[x] = value(cid, params[x], token="node" if "node" in params[x]["types"] else None)
                        cases.append(("+".join(combo) or "none", finish(cid, t)))
            else:
                w = c["when"]
                wparam = params[w["param"]]
                holds_v = w["equals"] if w["equals"] is not None else value(cid, wparam, token=w["type"])
                other_v = next(v for v in (wparam["values"] or []) if v != w["equals"]) if w["equals"] is not None \
                    else value(cid, wparam, token=next(t for t in wparam["types"] if t != w["type"]))
                for wv, label in ((holds_v, "holds"), (other_v, "does not hold")):
                    for with_params in (False, True):
                        t = copy.deepcopy(core)
                        t[w["param"]] = copy.deepcopy(wv)
                        if with_params:
                            for x in ps:
                                t[x] = value(cid, params[x])
                        cases.append((f"when {label}, params {'present' if with_params else 'absent'}",
                                      finish(cid, t)))
            for desc, t in cases:
                want = True if c["enforced"] == "run" else predict(spec, t)
                ok, msg = validate(t)
                if ok != want:
                    bad.append(f"{cid}: {op} {desc}: expected {'accept' if want else 'reject'}, got "
                               f"{'accept' if ok else 'reject'}{(': ' + msg) if msg else ''}")
    return bad


REQUIRES = re.compile(r"requires\b[^']*'([^']+)'")


def vantage_of(spec):
    for p in spec["params"]:
        if p["required"] and p["types"] == ["node"] and p["name"] in ("src", "node"):
            return p
    return None


def leg_discovery(specs, validate):
    bad = []
    for cid, spec in specs.items():
        params = spec["params"]
        inst = envelope(cid)
        v = vantage_of(spec)
        if v is not None:
            inst[v["name"]] = VANTAGE
        for _step in range(12):
            ok, msg = validate(finish(cid, copy.deepcopy(inst)))
            if ok:
                break
            m = REQUIRES.search(msg)
            if not m:
                bad.append(f"{cid}: rejected without a 'requires' message: {msg}")
                break
            named = set(m.group(1).split("/"))
            hit = [p for p in params if p["name"] in named or named & set(p["aliases"])]
            if not hit:
                bad.append(f"{cid}: validate requires {sorted(named)}, which no declared parameter names")
                break
            p = hit[0]
            one_of = any(c["operator"] == "exactly_one_of" and p["name"] in c["params"]
                         for c in spec["constraints"])
            if not p["required"] and not one_of:
                bad.append(f"{cid}: validate requires '{p['name']}', which the spec declares optional")
                break
            if p["name"] in inst:
                bad.append(f"{cid}: validate still requires '{p['name']}' when it is given: {msg}")
                break
            inst[p["name"]] = value(cid, p, token="node" if "node" in p["types"] else None)
        else:
            bad.append(f"{cid}: discovery did not reach acceptance in 12 steps")
    return bad


def leg_po29(specs, validate):
    bad, swept = [], 0
    for cid, spec in specs.items():
        d2 = required_instance(cid, spec)
        for p in spec["params"]:
            if p["enforced"] != "validate":
                continue
            outs = []
            if "enum" in p["types"]:
                outs.append("zz_out_of_domain")
            if "boolean" in p["types"]:
                outs += ["zz_out_of_domain", "false"]
            for out in dict.fromkeys(outs):
                t = copy.deepcopy(d2)
                t[p["name"]] = out
                swept += 1
                ok, _msg = validate(finish(cid, t))
                if ok:
                    bad.append(f"{cid}.{p['name']} = {out!r} accepted")
    return bad, swept


def leg_po34(validate):
    bad = []
    base = {"name": "t_evpn_bgp_session_up", "kind": "invariant", "type": "evpn_bgp_session_up", "node": VANTAGE}
    cases = (
        (PO34_IP, False, PO34_TEXT_UNKNOWN % PO34_IP),
        (PO34_UNKNOWN, False, PO34_TEXT_UNKNOWN % PO34_UNKNOWN),
        (VANTAGE, False, PO34_TEXT_SELF % VANTAGE),
        (OTHER, True, ""),
        (f"  {OTHER}  ", True, ""),
    )
    for peer, want, text in cases:
        for exp in (None, "fail"):
            t = dict(base, peer=peer)
            if exp:
                t["expect"] = exp
            ok, msg = validate(t)
            if ok != want or (text and text not in msg):
                bad.append(f"peer {peer!r} expect {exp}: got {'accept' if ok else 'reject'}: {msg}")
    return bad


# ---------------------------------------------------------------------------------------------------------------
# Spec mutants (leg N). Each returns a mutated deep copy of the catalogue.
# ---------------------------------------------------------------------------------------------------------------

def find(cat, cid):
    return next(c for c in cat["checks"] if c["id"] == cid)["parameters"]


def mut_drop_required(cat):
    spec = find(cat, "route_present")
    spec["params"] = [p for p in spec["params"] if p["name"] != "prefix"]


def mut_spurious_required(cat):
    find(cat, "route_present")["params"].append(
        {"name": "zz_spurious", "aliases": [], "types": ["string"], "values": None, "required": True,
         "enforced": "validate"})


def mut_flip_unknown(cat):
    spec = find(cat, "exec")
    spec["unknown_keys"] = "accepted" if spec["unknown_keys"] == "rejected" else "rejected"


def mut_drop_constraint(cat):
    spec = find(cat, "ping")
    spec["constraints"] = [c for c in spec["constraints"] if c["operator"] != "exactly_one_of"]


def mut_flip_when(cat):
    for c in find(cat, "ping")["constraints"]:
        if c["operator"] == "forbidden_if":
            c["when"]["equals"] = "pass"


def mut_demote_required(cat):
    for p in find(cat, "route_present")["params"]:
        if p["name"] == "prefix":
            p["required"] = False


def mut_bogus_alias(cat):
    for p in find(cat, "route_present")["params"]:
        if p["name"] == "node":
            p["aliases"].append("zz_alias")


def mut_bogus_optional(cat):
    find(cat, "exec")["params"].append(
        {"name": "zz_opt", "aliases": [], "types": ["string"], "values": None, "required": False,
         "enforced": "validate"})


def mut_extra_type(cat):
    for p in find(cat, "route_present")["params"]:
        if p["name"] == "prefix":
            p["types"].append("integer")


def mut_ipv6_widen(cat):
    for p in find(cat, "ospf_neighbor_up")["params"]:
        if p["name"] == "neighbor":
            p["types"] = ["ip"]


def mut_at_most_validate(cat):
    for c in find(cat, "ping")["constraints"]:
        if c["operator"] == "at_most_one_of":
            c["enforced"] = "validate"


def mut_flip_required_iff(cat):
    for c in find(cat, "bgp_community")["constraints"]:
        if c["operator"] == "required_iff":
            c["when"]["type"] = "community"


def mut_drop_marker(cat):
    cat["provenance"]["declared_proof_bound"].remove("checks.parameters")


def mut_bad_token(cat):
    find(cat, "route_present")["params"][0]["types"].append("zz_token")


# (description, mutation, target leg, text every failure it causes must contain)
SPEC_MUTANTS = (
    ("drop a required parameter (route_present.prefix)", mut_drop_required, "D2", "route_present"),
    ("add a spurious required parameter (route_present.zz_spurious)", mut_spurious_required, "D1", "zz_spurious"),
    ("flip exec's unknown_keys", mut_flip_unknown, "D1", "exec: unknown key"),
    ("drop ping's exactly_one_of", mut_drop_constraint, "D2", "ping"),
    ("flip ping's forbidden_if when (fail -> pass)", mut_flip_when, "K", "ping: forbidden_if"),
    ("demote route_present.prefix to optional", mut_demote_required, "X", "route_present"),
    ("declare a bogus alias (route_present zz_alias for node)", mut_bogus_alias, "D1", "route_present: alias zz_alias"),
    ("declare a bogus optional parameter (exec.zz_opt)", mut_bogus_optional, "D1", "exec: optional zz_opt"),
    ("declare an extra type (route_present.prefix as integer)", mut_extra_type, "D1",
     "route_present: prefix as integer"),
    ("widen ospf_neighbor_up.neighbor from ipv4 to ip", mut_ipv6_widen, "D1",
     "ospf_neighbor_up: neighbor = 2001:db8::1"),
    ("make ping's at_most_one_of validate-enforced", mut_at_most_validate, "K", "ping: at_most_one_of"),
    ("flip bgp_community's required_iff when type", mut_flip_required_iff, "K", "bgp_community: required_iff"),
    ("drop the parameter-list marker", mut_drop_marker, "M", "checks.parameters"),
    ("add a token outside the vocabulary", mut_bad_token, "V", "zz_token"),
)


def specs_of(cat):
    return {c["id"]: c["parameters"] for c in cat["checks"]}


def run_leg(leg, cat, validate):
    specs = specs_of(cat)
    return {
        "M": lambda: leg_marker(cat),
        "V": lambda: leg_shape(specs),
        "D2": lambda: leg_d2(specs, validate),
        "D1": lambda: leg_d1(specs, validate),
        "K": lambda: leg_constraints(specs, validate),
        "X": lambda: leg_discovery(specs, validate),
    }[leg]()


def main():
    cat = C.build_catalogue(cassian_cli.build_parser(), release_version="0+hs3")
    specs = specs_of(cat)
    validate = Validator()
    engine_source = (SRC / "cassian_engine.py").read_text(encoding="utf-8")

    def report(name, bad, ok_detail):
        check(name, not bad, ("; ".join(bad[:4]) + (f" (+{len(bad) - 4} more)" if len(bad) > 4 else "")) if bad
              else ok_detail)

    report("M marker: provenance names checks.parameters as declared and proof-bound", leg_marker(cat),
           "declared_proof_bound=%s" % cat["provenance"]["declared_proof_bound"])
    n_params = sum(len(s["params"]) for s in specs.values())
    n_cons = sum(len(s["constraints"]) for s in specs.values())
    tokens = sorted({t for s in specs.values() for p in s["params"] for t in p["types"]})
    report("V shape: section 7.2 keys, closed vocabulary, values iff enum, ruled operators", leg_shape(specs),
           "%d checks, %d parameters, %d constraints; tokens in use %d of %d" % (len(specs), n_params, n_cons,
                                                                                len(tokens), len(VOCAB)))
    report("B binding: cmd_validate calls the mirror's four functions in the mirror's order",
           leg_binding(engine_source), " -> ".join(BINDING_CALLS))
    report("D2 required set: each check's declared required instance is accepted", leg_d2(specs, validate),
           "%d checks" % len(specs))
    before = validate.runs
    report("D1 omit / alias / optional / type / IPv6 / unknown key: validate agrees with the spec",
           leg_d1(specs, validate), "%d validate runs" % (validate.runs - before))
    before = validate.runs
    report("K constraints: every combination gives the predicted outcome (at_most_one_of: validate half)",
           leg_constraints(specs, validate), "%d validate runs over %d constraints" % (validate.runs - before, n_cons))
    report("X discovery: every key validate requires is a declared required parameter",
           leg_discovery(specs, validate), "%d checks" % len(specs))
    bad29, swept29 = leg_po29(specs, validate)
    check("P29 out-of-domain enum and boolean values are rejected (REQ-S1D2-39)", not bad29 and swept29 > 0,
          "; ".join(bad29) if bad29 else "%d values rejected" % swept29)
    report("P34 evpn_bgp_session_up peer: IP literal, unknown name and own node rejected with the ruled text; "
           "a declared other node accepted (REQ-S1D2-44)", leg_po34(validate), "5 peers x 2 expects")

    run_params = sorted(f"{cid}.{p['name']}" for cid, s in specs.items() for p in s["params"]
                        if p["enforced"] == "run")
    check("L OPEN-18: the enforced: run parameters, checked on their validate half only", bool(run_params),
          "%d: %s" % (len(run_params), ", ".join(run_params)))

    # Leg N: every leg above can fail.
    for desc, mutate, leg, names in SPEC_MUTANTS:
        mcat = copy.deepcopy(cat)
        mutate(mcat)
        bad = run_leg(leg, mcat, validate)
        check(f"N spec mutant, {desc}: leg {leg} fails, on the mutated item only",
              bool(bad) and all(names in b for b in bad), "; ".join(bad[:2]) if bad else "leg held")
    # (mutant, texts: every failure it causes must contain one, and each must be met)
    for key, names in (("P29", ("exec.expect",)),
                       ("P34-unknown", (f"peer {PO34_IP!r}", f"peer {PO34_UNKNOWN!r}")),
                       ("P34-self", (f"peer {VANTAGE!r}",))):
        mvalidate = Validator(model_mutant(key))
        bad = leg_po29(specs, mvalidate)[0] if key == "P29" else leg_po34(mvalidate)
        on_rule = all(any(n in b for n in names) for b in bad) and all(any(n in b for b in bad) for n in names)
        check(f"N model mutant {key} (model source edited in memory): its leg fails, on the mutated rule only",
              bool(bad) and on_rule, "; ".join(bad[:2]) if bad else "leg held")
    doctored = edit_in_cmd_validate(engine_source, *BINDING_MUTANT)
    if doctored is None:
        check("N binding mutant: anchor found once in cmd_validate", False, BINDING_MUTANT[0])
    else:
        bad = leg_binding(doctored)
        check("N binding mutant (resolve_topology call removed from cmd_validate in memory): leg B fails",
              bool(bad), bad[0] if bad else "leg held")

    fails = [n for n, ok in checks if not ok]
    print("validate runs: %d" % validate.runs)
    print("RESULT: %s (%d checks, %d failed)" % ("PASS" if not fails else "FAIL", len(checks), len(fails)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
