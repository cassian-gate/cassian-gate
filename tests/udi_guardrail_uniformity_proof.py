#!/usr/bin/env python3
"""
§4.7 User-Defined Invariants (`exec`) -- guardrail single-canonical-site
uniformity proof (SP #4-pattern; handover §15 / §6.7.2; A5).

Proves the exec guardrails are enforced UNIFORMLY from single canonical decision
sites rather than per-call-site or coincidental logic (DOCTRINE-1/2/3):

  * the read-only allow-list decision lives ONLY in _exec_command_allowed
    (DOCTRINE-1) -- defined once, invoked once, command tokenization (shlex.split)
    at exactly one site; the exec resolve block delegates and inlines no
    allow-list logic of its own;
  * the typed-predicate assertion gate lives ONLY in _validate_exec_assertion
    (DOCTRINE-2) -- defined once, invoked once, the closed operator set declared
    once; freeform grep impossible by construction;
  * non-deterministic output is bounded by the typed assertion schema
    (extract-then-compare), never by accepting a non-deterministic command shape
    (DOCTRINE-3);
  * both decisions are pure (no time/random/uuid/datetime/env surface) and
    uniform across the src/node/on/from target aliases.

Like the bl6_* / h53_* / h57_* / expf_* per-handover proofs, this is LAB-FREE:
source validation of the canonical sites (drift-guarded against future
divergence) plus a behavioral model driven through the real resolve seam
(cassian_common._QUIET_DIE = True mirrors cassian validate's quiet-die capture).
SP #4-pattern is borrowed for the drift-guarded uniformity shape; verify-and-lock
preconditions are NOT claimed (the engine is modified by design, REQ-UDI-PRES-1).

Proof obligations:
  D-ALLOW   _exec_command_allowed defined once, called once; shlex.split at one
            site (single canonical allow-list decision -- DOCTRINE-1).
  D-ASSERT  _validate_exec_assertion defined once, called once; closed operator
            tuple declared once (single canonical typed gate -- DOCTRINE-2).
  D-DELEG   the exec resolve block inlines no allow-list/assertion decision
            (no shlex/argv/re.compile), delegating to the canonical helpers.
  D-PURE    neither helper carries a non-deterministic surface
            (time/random/uuid/datetime/env) -- decisions are pure.
  U-ALIAS   src / node / on / from naming the same node yield an IDENTICAL
            decision (good accepted, bad rejected) -- uniform target contract.
  U-DET     identical (command, type, assertion) yields byte-identical outcomes
            across repeated resolves.
  D3-BOUND  count/field require the extract-then-compare sub-schema; a
            non-deterministic command shape (pipe / raw shell) is rejected, never
            accepted as-is (DOCTRINE-3).

Exit 0 on all-pass; exit 1 on first failed assertion.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_common as _cc
_cc._QUIET_DIE = True  # mirror cmd_validate: die raises SystemExit(str(msg))
import cassian_model as cm

_MODEL_PATH = os.path.join(_SRC, "cassian_model.py")


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _exec_block(text):
    """Slice the `elif kind_norm == "exec":` resolve block up to its dispatch `else:`."""
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines)
                  if l.strip() == 'elif kind_norm == "exec":'), None)
    if start is None:
        return ""
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].rstrip() == "        else:"), len(lines))
    return "\n".join(lines[start:end])


def _func(text, name):
    """Slice a top-level `def name(...)` body up to the next top-level def."""
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith(f"def {name}(")), None)
    if start is None:
        return ""
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("def ")),
               len(lines))
    return "\n".join(lines[start:end])


_NODES = [
    {"name": "r1", "type": "frr"},
    {"name": "fw1", "type": "nft-fw"},
]


def _topo(test):
    return {"name": "udi-uniformity-proof", "nodes": [dict(n) for n in _NODES],
            "links": [], "tests": [test]}


def _resolve(topo):
    try:
        cm.resolve_topology(topo)
        return ("ok", "")
    except SystemExit as e:
        return ("die", str(e))


def main():
    src = _read(_MODEL_PATH)
    blk = _exec_block(src)
    fa = _func(src, "_exec_command_allowed")
    fv = _func(src, "_validate_exec_assertion")
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # --- D-ALLOW: single canonical allow-list decision (DOCTRINE-1) ---
    check("D-ALLOW _exec_command_allowed defined exactly once",
          src.count("def _exec_command_allowed(") == 1)
    check("D-ALLOW _exec_command_allowed invoked exactly once (1 def + 1 call)",
          src.count("_exec_command_allowed(") == 2)
    check("D-ALLOW shlex.split at exactly one site",
          src.count("shlex.split(") == 1)

    # --- D-ASSERT: single canonical typed gate (DOCTRINE-2) ---
    check("D-ASSERT _validate_exec_assertion defined exactly once",
          src.count("def _validate_exec_assertion(") == 1)
    check("D-ASSERT _validate_exec_assertion invoked exactly once (1 def + 1 call)",
          src.count("_validate_exec_assertion(") == 2)
    check("D-ASSERT closed operator set declared exactly once",
          src.count('"contains", "not_contains", "equals", "matches", "count", "field"') == 1)

    # --- D-DELEG: exec block delegates, inlines no decision logic ---
    check("D-DELEG exec block located", bool(blk))
    check("D-DELEG exec block inlines no shlex", "shlex" not in blk)
    check("D-DELEG exec block inlines no argv", "argv" not in blk)
    check("D-DELEG exec block inlines no re.compile", "re.compile" not in blk)
    check("D-DELEG exec block calls allow-list helper once",
          blk.count("_exec_command_allowed(") == 1)
    check("D-DELEG exec block calls assertion gate once",
          blk.count("_validate_exec_assertion(") == 1)

    # --- D-PURE: helpers carry no non-deterministic surface ---
    _nd = ("time.", "random.", "uuid", "datetime", "os.environ", "getenv")
    check("D-PURE _exec_command_allowed is pure (no nondeterministic surface)",
          bool(fa) and not any(tok in fa for tok in _nd))
    check("D-PURE _validate_exec_assertion is pure (no nondeterministic surface)",
          bool(fv) and not any(tok in fv for tok in _nd))

    # --- U-ALIAS: uniform decision across src/node/on/from ---
    good = 'vtysh -c "show ip route"'
    bad = "nft flush ruleset"  # wrong backend for frr + mutation verb
    good_out, bad_out = set(), set()
    for alias in ("src", "node", "on", "from"):
        good_out.add(_resolve(_topo({"name": "g", "kind": "exec", alias: "r1",
                                     "command": good,
                                     "assertion": {"contains": "0.0.0.0/0"}}))[0])
        bad_out.add(_resolve(_topo({"name": "b", "kind": "exec", alias: "r1",
                                    "command": bad,
                                    "assertion": {"contains": "x"}}))[0])
    check("U-ALIAS good command accepted uniformly across all 4 aliases",
          good_out == {"ok"})
    check("U-ALIAS bad command rejected uniformly across all 4 aliases",
          bad_out == {"die"})

    # --- U-DET: identical input -> byte-identical outcome ---
    t = {"name": "d", "kind": "exec", "src": "r1",
         "command": 'vtysh -c "configure terminal"', "assertion": {"contains": "x"}}
    r1 = _resolve(_topo(dict(t)))
    r2 = _resolve(_topo(dict(t)))
    check("U-DET identical input -> byte-identical rejection", r1 == r2 and r1[0] == "die")

    # --- D3-BOUND: extract-then-compare bounding (DOCTRINE-3) ---
    check("D3-BOUND count without op/value rejected (schema-bounded)",
          _resolve(_topo({"name": "c", "kind": "exec", "src": "r1", "command": good,
                          "assertion": {"count": {"pattern": "x"}}}))[0] == "die")
    check("D3-BOUND non-deterministic command shape (pipe) rejected, not accepted",
          _resolve(_topo({"name": "p", "kind": "exec", "src": "fw1",
                          "command": "nft list ruleset | head",
                          "assertion": {"contains": "x"}}))[0] == "die")

    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=" * 60)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
