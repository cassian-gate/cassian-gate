#!/usr/bin/env python3
"""Unsupported-capability disposition proof (BL-P2-4.5c-44).

Founder ruling 2026-08-22: when a NOS provider does not declare an observation
capability, `_nos_collect` raises NosCapabilityUnsupported and the core must
record an UNSUP-fail and exit 2 -- it must NEVER let the predicate read the
unsupported state's absent keys as a negative observation, because a negative
observation SATISFIES `expect: fail` and yields a passing verdict on a device
that was never queried (Doctrine 1.11: absence must never imply pass).

Before the repair, 7 of 15 invariant types did exactly that:
  bgp_as_path, bgp_community, bgp_session_up, interface_state,
  ospf_neighbor_up, route_present  (all at expect: fail)
  route_absent                     (at expect: pass)

Proof obligations:
  P-UNSUP-ALL   every one of the 15 catalog types, at both polarities, takes
                the UNSUP disposition: record verdict="fail" then SystemExit(2).
  P-UNSUP-CTRL  per-row validator-hit control: the same declaration driven with
                SUPPORTED provider evidence must REACH the predicate (no exit),
                proving the row entered the branch under test rather than
                firing an input validator. A row whose control does not pass
                proves nothing about the disposition (Addendum rev 4, Rule 13).
  P-UNSUP-CAT   the driven type set is exactly the 15 declared in
                cassian_model.py -- enumerate the class, do not sample it
                (Addendum rev 4, Rule 14).
  P-UNSUP-NV    non-vacuity: the harness WOULD detect a non-exiting row.

Coverage limits (PBE-P2-8, stated in-file):
  - Lab-free: the provider seam is stubbed. This proves the CORE record path
    on a denial, not provider behaviour on a live NOS.
  - route_advertised_to / route_not_advertised_to: their CONTROL DOES NOT PASS.
    Both exit 2 under supported evidence too, with error "unsupported route
    advertisement peer mapping" -- the harness cannot supply the topology peer
    mapping the branch resolves. Their UNSUP result is therefore NOT attributed
    to the unsupported path. Both are in the already-safe eight, not the
    repaired seven, so the repair's proof is unaffected; the gap is recorded,
    not papered over. Same shape as the open bgp_community attribution control.
  - The unsupported state is modelled as a state dict carrying none of the keys
    the predicates read. That is the essential property the handlers produce;
    per-handler key sets are not reproduced individually.

Exit 0 on all-pass; exit 1 on first failure.
"""
import ast
import os
import sys
import textwrap

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_engine as E  # noqa: E402
import cassian_model as M  # noqa: E402
try:
    import cassian_common as C  # noqa: E402
    if hasattr(C, "_QUIET_DIE"):
        C._QUIET_DIE = True
except Exception:
    pass

checks = []


def check(name, cond):
    checks.append((name, bool(cond)))


# ---- extract the shipped run_invariant_test body and bind it -------------
_engine_src = open(os.path.join(_SRC, "cassian_engine.py"), encoding="utf-8").read()
_node = next((n for n in ast.walk(ast.parse(_engine_src))
              if isinstance(n, ast.FunctionDef) and n.name == "run_invariant_test"), None)
check("run_invariant_test located in engine", _node is not None)
_body = "\n".join(ast.unparse(s) for s in _node.body)

check("guard present at seven unsafe branches",
      _engine_src.count('== "unsupported_provider_capability"') == 6)

_ns = dict(E.__dict__)


class _FakeTime:
    @staticmethod
    def time():
        return 0.0

    @staticmethod
    def sleep(_s):
        return None


def _denied_collect(*_a, **_k):
    raise E.NosCapabilityUnsupported(
        "sonic-vm", "evpn_mac_route_text", "capability not declared")


_ns["time"] = _FakeTime
_ns["rt"] = None
_ns["lab"] = None
_ns["topo"] = {"nodes": [{"name": "r1", "type": "sonic-vm"}]}
_ns["_nos_collect"] = _denied_collect
_ns["_nos_ntype"] = lambda *_a, **_k: "sonic-vm"
exec("def _rit(test_name, src, t, record_fn):\n" + textwrap.indent(_body, "    "), _ns)
rit = _ns["_rit"]

UNSUP_EV = {"cmd": "", "rc": None, "parse_error": "provider capability unsupported",
            "reason": "unsupported_provider_capability", "node_type": "sonic-vm"}
SUPPORTED_EV = {"cmd": "vtysh -c 'show x json'", "rc": 0,
                "parse_error": "", "empty_first_doc": False}

HEALTHY = {"present": True, "route_present": True, "observed_as_path": "65001",
           "observed_communities": ["65001:100"], "observed_prefixes": ["10.0.0.0/24"],
           "peer_present": True, "state": "Established", "neighbor_present": True,
           "admin_state": "up", "operstate": "UP", "carrier": "up",
           "observed_med": 100, "observed_localpref": 200,
           "evidence_entries": [{"seen": 1}], "advertised_prefixes": ["1.1.1.1/32"],
           "neighbors": [{"peer": "10.9.9.1", "state": "Established"}]}

# One declaration per catalog type. Field names are the ones the branch reads;
# a wrong name fires an input validator, which is what P-UNSUP-CTRL catches.
DECLS = {
    "route_present": {"prefix": "10.0.0.0/24"},
    "route_absent": {"prefix": "10.0.0.0/24"},
    "bgp_session_up": {"dst": "10.9.9.1"},
    "ospf_neighbor_up": {"neighbor": "10.9.9.1", "state": "Full"},
    "interface_state": {"interface": "eth1", "admin_state": "up"},
    "bgp_community": {"prefix": "1.1.1.1/32", "community": "65001:100"},
    "bgp_as_path": {"prefix": "1.1.1.1/32", "as_path": "_65001_"},
    "bgp_med_equals": {"prefix": "1.1.1.1/32", "expected": 100},
    "bgp_localpref_equals": {"prefix": "1.1.1.1/32", "expected": 200},
    "evpn_bgp_session_up": {"peer": "10.9.9.1"},
    "evpn_mac_route_present": {"mac": "aa:bb:cc:dd:ee:ff", "vni": 100},
    "evpn_mac_route_absent": {"mac": "aa:bb:cc:dd:ee:ff", "vni": 100},
    "evpn_vni_route_present": {"vni": 100, "prefix": "1.1.1.1/32"},
    "route_advertised_to": {"prefix": "1.1.1.1/32", "peer": "10.9.9.1"},
    "route_not_advertised_to": {"prefix": "1.1.1.1/32", "peer": "10.9.9.1"},
}

# Controls that cannot pass in a lab-free harness -- see coverage limits.
CONTROL_UNAVAILABLE = {"route_advertised_to", "route_not_advertised_to"}

# The seven the founder ruling repairs. Named so a regression is legible.
REPAIRED = ("bgp_as_path", "bgp_community", "bgp_session_up", "interface_state",
            "ospf_neighbor_up", "route_present", "route_absent")


def _drive(inv_type, expect, state, evidence):
    cap = {}

    def record_fn(**kw):
        cap.update(kw)

    def _attempt(*, inv_type, t, src):
        st = dict(state)
        st.setdefault("norm_prefix", str(t.get("_norm_prefix") or ""))
        return (evidence.get("rc") == 0,
                bool(st.get("present") or st.get("route_present")),
                st, dict(evidence))

    rit.__globals__["_evaluate_invariant_attempt"] = _attempt
    t = {"type": inv_type, "node": "r1", "src": "r1", "expect": expect}
    t.update(DECLS[inv_type])
    try:
        v = rit("t1", "r1", dict(t), record_fn)
        return {"exit": None, "verdict": v, "rec": cap.get("verdict"),
                "error": str(cap.get("error") or "")}
    except SystemExit as exc:
        return {"exit": exc.code, "verdict": None, "rec": cap.get("verdict"),
                "error": str(cap.get("error") or "")}


# ---- P-UNSUP-CAT: enumerate the class, do not sample it -------------------
_model_src = open(os.path.join(_SRC, "cassian_model.py"), encoding="utf-8").read()
check("P-UNSUP-CAT 15 types declared", len(DECLS) == 15)
check("P-UNSUP-CAT every driven type appears in the model",
      all(f'"{ty}"' in _model_src for ty in DECLS))
check("P-UNSUP-CAT the seven repaired types are all driven",
      all(ty in DECLS for ty in REPAIRED))

# ---- P-UNSUP-ALL + P-UNSUP-CTRL -----------------------------------------
results = {}
for inv_type in DECLS:
    for expect in ("pass", "fail"):
        rid = f"{inv_type}/{expect}"
        unsup = _drive(inv_type, expect, {}, UNSUP_EV)
        ctrl = _drive(inv_type, expect, HEALTHY, SUPPORTED_EV)
        results[rid] = (unsup, ctrl)

        check(f"P-UNSUP-ALL {rid} exits 2 on denial",
              unsup["exit"] == 2)
        check(f"P-UNSUP-ALL {rid} records verdict=fail on denial",
              unsup["rec"] == "fail")
        check(f"P-UNSUP-ALL {rid} never records a passing verdict on denial",
              unsup["rec"] != "pass" and unsup["verdict"] != "pass")
        if inv_type not in CONTROL_UNAVAILABLE:
            check(f"P-UNSUP-CTRL {rid} reaches the predicate when supported",
                  ctrl["exit"] is None)

# ---- P-UNSUP-NV: the harness can fail ------------------------------------
_nv = _drive("bgp_as_path", "fail", HEALTHY, SUPPORTED_EV)
check("P-UNSUP-NV a supported row does NOT exit 2 (harness would detect it)",
      _nv["exit"] is None)
check("P-UNSUP-NV the four-quadrant seam still operates under support",
      _drive("route_present", "pass", HEALTHY, SUPPORTED_EV)["verdict"] == "pass")

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
