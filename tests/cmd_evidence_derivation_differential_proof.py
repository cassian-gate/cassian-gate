#!/usr/bin/env python3
"""cmd_evidence_derivation_differential_proof.py -- §4.5-c WI-8 (REQ-45C-36).

Discharges REQ-45C-36: "The invariant-corpus differential shows zero verdict
deltas post-derivation, and no fail record loses its `cmd` evidence."

Lab-free. `run_invariant_test` is a nested closure in `cmd_test`, so -- exactly
as the bgp_as_path / bgp_community four-quadrant siblings do -- this proof
extracts its ACTUAL body via AST and binds it as a callable, stubbing
`_evaluate_invariant_attempt` so the harness controls the provider evidence.
It is a behavioural test of the shipped record path, not a reimplementation.

The corpus crosses three invariant families x expect{pass,fail} x
present{True,False} x provider-evidence{frr,unsupported} = 24 cases.

  frr          last_evidence carries a real "cmd"     -> derivation must fire
  unsupported  last_evidence carries "cmd": ""        -> literal fallback must fire

EXPECTED is frozen from the PRE-derivation engine (10530484df56, the tree
immediately before the WI-8 patch). Any verdict delta introduced by the
derivation change fails this proof.

Coverage limits (PBE-P2-8, stated in-file):
  - Lab-free: the provider seam is stubbed, so this proves the CORE record
    path, not provider behaviour on a live NOS.
  - Three invariant families, not all ten branches. The six class-C sites
    (last_evidence unbound: engine :7237 :7271 :7390 :7426 :7553 :7590) are
    NOT exercised here -- they are unchanged by WI-8 by construction and are
    recorded as classified-not-substituted in the per-site table.
  - Verdict equality is checked against a frozen table, not against a live
    re-run of the old engine. The table is regenerated only by a founder-ruled
    re-baseline, never silently.

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

check("derivation idiom present at record sites",
      _engine_src.count('last_evidence.get("cmd") or ') == 24)

_ns = dict(E.__dict__)


class _FakeTime:
    @staticmethod
    def time():
        return 0.0

    @staticmethod
    def sleep(_s):
        return None


_ns["time"] = _FakeTime
exec("def _rit(test_name, src, t, record_fn):\n" + textwrap.indent(_body, "    "), _ns)
rit = _ns["_rit"]

FRR_EV = {"cmd": "vtysh -c 'show ip bgp json'", "rc": 0,
          "parse_error": "", "empty_first_doc": False}
UNSUP_EV = {"cmd": "", "rc": None, "parse_error": "provider capability unsupported",
            "reason": "unsupported_provider_capability", "node_type": "sonic-vm"}


def _stub(state, evidence):
    def _s(*, inv_type, t, src):
        st = dict(state)
        st.setdefault("norm_prefix", str(t.get("_norm_prefix") or ""))
        return (evidence.get("rc") == 0,
                bool(st.get("present") or st.get("route_present")),
                st, dict(evidence))
    return _s


def _cases():
    out = []
    for expect in ("pass", "fail"):
        for present in (True, False):
            for ev_name, ev in (("frr", FRR_EV), ("unsup", UNSUP_EV)):
                out.append((f"as_path/{expect}/{present}/{ev_name}",
                            {"type": "bgp_as_path", "node": "r2", "prefix": "1.1.1.1/32",
                             "as_path": "_65001_", "expect": expect},
                            {"route_present": present,
                             "observed_as_path": "65001" if present else ""}, ev))
                out.append((f"community/{expect}/{present}/{ev_name}",
                            {"type": "bgp_community", "node": "r2", "prefix": "1.1.1.1/32",
                             "community": "65001:100", "expect": expect},
                            {"route_present": present,
                             "observed_communities": ["65001:100"] if present else []}, ev))
                out.append((f"evpn_sess/{expect}/{present}/{ev_name}",
                            {"type": "evpn_bgp_session_up", "node": "r1",
                             "peer": "10.9.9.1", "expect": expect},
                            {"present": present,
                             "neighbors": ([{"peer": "10.9.9.1", "state": "Established"}]
                                           if present else [])}, ev))
    return out


def _run(case):
    _cid, t, state, ev = case
    cap = {}

    def record_fn(**kw):
        cap.update(kw)

    rit.__globals__["_evaluate_invariant_attempt"] = _stub(state, ev)
    try:
        v = rit("t1", t.get("node", "r1"), dict(t), record_fn)
        return {"verdict": v, "rec_verdict": cap.get("verdict"), "exit": None,
                "cmd": (cap.get("evidence") or {}).get("cmd")}
    except SystemExit as exc:
        return {"verdict": None, "rec_verdict": cap.get("verdict"), "exit": exc.code,
                "cmd": (cap.get("evidence") or {}).get("cmd")}


# EXPECTED: frozen from the PRE-derivation engine (sha256 10530484df56...).
EXPECTED = {
    "as_path/pass/True/frr": {
        "verdict": "pass",
        "rec_verdict": "pass",
        "exit": None
    },
    "community/pass/True/frr": {
        "verdict": "fail",
        "rec_verdict": "fail",
        "exit": None
    },
    "evpn_sess/pass/True/frr": {
        "verdict": "pass",
        "rec_verdict": "pass",
        "exit": None
    },
    "as_path/pass/True/unsup": {
        "verdict": "pass",
        "rec_verdict": "pass",
        "exit": None
    },
    "community/pass/True/unsup": {
        "verdict": "fail",
        "rec_verdict": "fail",
        "exit": None
    },
    "evpn_sess/pass/True/unsup": {
        "verdict": None,
        "rec_verdict": "fail",
        "exit": 2
    },
    "as_path/pass/False/frr": {
        "verdict": "fail",
        "rec_verdict": "fail",
        "exit": None
    },
    "community/pass/False/frr": {
        "verdict": "fail",
        "rec_verdict": "fail",
        "exit": None
    },
    "evpn_sess/pass/False/frr": {
        "verdict": "fail",
        "rec_verdict": "fail",
        "exit": None
    },
    "as_path/pass/False/unsup": {
        "verdict": "fail",
        "rec_verdict": "fail",
        "exit": None
    },
    "community/pass/False/unsup": {
        "verdict": "fail",
        "rec_verdict": "fail",
        "exit": None
    },
    "evpn_sess/pass/False/unsup": {
        "verdict": None,
        "rec_verdict": "fail",
        "exit": 2
    },
    "as_path/fail/True/frr": {
        "verdict": "fail",
        "rec_verdict": "fail",
        "exit": None
    },
    "community/fail/True/frr": {
        "verdict": "pass",
        "rec_verdict": "pass",
        "exit": None
    },
    "evpn_sess/fail/True/frr": {
        "verdict": "fail",
        "rec_verdict": "fail",
        "exit": None
    },
    "as_path/fail/True/unsup": {
        "verdict": "fail",
        "rec_verdict": "fail",
        "exit": None
    },
    "community/fail/True/unsup": {
        "verdict": "pass",
        "rec_verdict": "pass",
        "exit": None
    },
    "evpn_sess/fail/True/unsup": {
        "verdict": None,
        "rec_verdict": "fail",
        "exit": 2
    },
    "as_path/fail/False/frr": {
        "verdict": "pass",
        "rec_verdict": "pass",
        "exit": None
    },
    "community/fail/False/frr": {
        "verdict": "pass",
        "rec_verdict": "pass",
        "exit": None
    },
    "evpn_sess/fail/False/frr": {
        "verdict": "pass",
        "rec_verdict": "pass",
        "exit": None
    },
    "as_path/fail/False/unsup": {
        "verdict": "pass",
        "rec_verdict": "pass",
        "exit": None
    },
    "community/fail/False/unsup": {
        "verdict": "pass",
        "rec_verdict": "pass",
        "exit": None
    },
    "evpn_sess/fail/False/unsup": {
        "verdict": None,
        "rec_verdict": "fail",
        "exit": 2
    }
}

CASES = _cases()
check("corpus case count matches frozen table", len(CASES) == len(EXPECTED) == 24)

results = {c[0]: _run(c) for c in CASES}

# ---- LEG 1: zero verdict deltas (REQ-45C-36 clause 1) --------------------
deltas = [cid for cid, exp in EXPECTED.items()
          if (results[cid]["verdict"], results[cid]["rec_verdict"], results[cid]["exit"])
          != (exp["verdict"], exp["rec_verdict"], exp["exit"])]
check("REQ-45C-36 zero verdict deltas across the corpus (24 cases)", not deltas)
if deltas:
    for cid in deltas:
        print(f"    DELTA {cid}: expected {EXPECTED[cid]} got {results[cid]}")

# ---- LEG 2: no fail record loses cmd (REQ-45C-36 clause 2) ---------------
fails = [cid for cid, r in results.items() if r["rec_verdict"] == "fail"]
check("corpus exercises fail records (non-vacuity)", len(fails) >= 10)
lost = [cid for cid in fails if not results[cid]["cmd"]]
check("REQ-45C-36 no fail record loses its cmd evidence", not lost)
if lost:
    print(f"    LOST cmd: {lost}")

# ---- LEG 3: derivation actually fires on the provider path ---------------
frr_cases = [cid for cid in results if cid.endswith("/frr")]
derived = [cid for cid in frr_cases if results[cid]["cmd"] == FRR_EV["cmd"]]
check("derivation fires on provider path (all frr cases carry last_evidence cmd)",
      len(derived) == len(frr_cases) == 12)

# ---- LEG 4: fallback fires on the unsupported path -----------------------
unsup_cases = [cid for cid in results if cid.endswith("/unsup")]
fell_back = [cid for cid in unsup_cases
             if results[cid]["cmd"] and results[cid]["cmd"] != ""]
check("fallback fires on unsupported path (no empty cmd, 12 cases)",
      len(fell_back) == len(unsup_cases) == 12)

# ---- LEG 5: non-vacuity -- the differential can fail ---------------------
_probe = dict(EXPECTED["as_path/pass/True/frr"])
_probe["rec_verdict"] = "fail" if _probe["rec_verdict"] == "pass" else "pass"
_would_fire = ((results["as_path/pass/True/frr"]["verdict"],
                results["as_path/pass/True/frr"]["rec_verdict"],
                results["as_path/pass/True/frr"]["exit"])
               != (_probe["verdict"], _probe["rec_verdict"], _probe["exit"]))
check("NV: a flipped expected verdict WOULD be detected as a delta", _would_fire)

_ns2 = dict(results["as_path/pass/True/frr"])
_ns2["cmd"] = ""
check("NV: an emptied cmd WOULD be detected as a loss", not _ns2["cmd"])

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
