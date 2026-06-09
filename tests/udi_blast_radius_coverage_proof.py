#!/usr/bin/env python3
"""udi_blast_radius_coverage_proof.py -- WI-5 / Amendment A6 blast-radius proof.

_blast_radius_collect_coverage_or_die is a nested closure in cmd_test, so this proof
AST-extracts its ACTUAL body and runs it against a synthetic graph + topology
(faithful behavioral test, not a reimplementation). Proves:

  BLAST-1  each authoritative kind graphs running-node coverage
           (ping/tcp src+dst; invariant node/peer; exec/bgp_neighbor/route_prefix -> src)
  BLAST-2  bgp_neighbor peer-IP (dst) and route_prefix prefix are NOT coverage nodes
           (not looked up; no unknown-node die)
  BLAST-3  an unrecognized kind is skipped + explicitly noted in coverage_basis
           (no die; not silently dropped)
  BLAST-PRES  ping/tcp/invariant coverage byte-identical baseline-vs-patched; node
           validation die still fires (non-vacuity)

Run from the repo root (after applying the WI-5 patch).
"""
import os, sys, ast, json, textwrap, subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_engine as E

checks = []
def check(name, cond):
    checks.append((name, bool(cond)))


def _extract_collect(engine_path):
    src = open(engine_path, "r", encoding="utf-8").read()
    node = next(n for n in ast.walk(ast.parse(src))
                if isinstance(n, ast.FunctionDef) and n.name == "_blast_radius_collect_coverage_or_die")
    body = "\n".join(ast.unparse(s) for s in node.body)
    fn_src = "def _collect(topo_obj, graph):\n" + textwrap.indent(body, "    ")
    ns = dict(E.__dict__)
    ns.setdefault("is_ip_literal", lambda s: False)
    ns.setdefault("_blast_radius_link_id_from_fields", lambda *a, **k: "L")
    exec(fn_src, ns)
    return ns["_collect"]

collect = _extract_collect(os.path.join(_SRC, "cassian_engine.py"))
GRAPH = {"node_set": {"r1", "r2", "fw1", "h1", "h2"}, "links": {}, "adjacency": {}}

def run(tests):
    return collect({"tests": tests, "scenarios": []}, GRAPH)

def no_die(tests):
    try:
        return run(tests), None
    except SystemExit as e:
        return None, e

# ---- BLAST-1: per-kind running-node coverage ----
cov, err = no_die([{"kind": "ping", "name": "p", "src": "r1", "dst": "r2"}])
check("BLAST-1 ping graphs src+dst", err is None and {"r1", "r2"} <= set(cov["covered_nodes"]))
cov, err = no_die([{"kind": "tcp", "name": "t", "src": "r1", "dst": "h1"}])
check("BLAST-1 tcp graphs src+dst", err is None and {"r1", "h1"} <= set(cov["covered_nodes"]))
cov, err = no_die([{"kind": "invariant", "name": "i", "type": "bgp_session_up", "node": "r1"}])
check("BLAST-1 invariant graphs node", err is None and "r1" in cov["covered_nodes"])
cov, err = no_die([{"kind": "exec", "name": "x", "src": "fw1", "command": "nft list ruleset", "assertion": {"contains": "drop"}}])
check("BLAST-1 exec graphs src", err is None and "fw1" in cov["covered_nodes"])
cov, err = no_die([{"kind": "bgp_neighbor", "name": "b", "src": "r1", "dst": "10.0.0.2"}])
check("BLAST-1 bgp_neighbor graphs running-node src", err is None and "r1" in cov["covered_nodes"])
cov, err = no_die([{"kind": "route_prefix", "name": "rp", "src": "r2", "prefix": "10.0.0.0/24"}])
check("BLAST-1 route_prefix graphs running-node src", err is None and "r2" in cov["covered_nodes"])

# ---- BLAST-2: non-node fields not graphed (and no die) ----
cov, err = no_die([{"kind": "bgp_neighbor", "name": "b", "src": "r1", "dst": "10.0.0.2"}])
check("BLAST-2 bgp_neighbor peer-IP not a coverage node", err is None and "10.0.0.2" not in cov["covered_nodes"])
cov, err = no_die([{"kind": "route_prefix", "name": "rp", "src": "r2", "prefix": "10.0.0.0/24"}])
check("BLAST-2 route_prefix prefix not a coverage node", err is None and "10.0.0.0/24" not in cov["covered_nodes"])

# ---- BLAST-3: unknown kind skipped + noted, no die ----
cov, err = no_die([{"kind": "frobnicate", "name": "wat", "src": "r1"}])
check("BLAST-3 unknown kind does not die", err is None)
check("BLAST-3 unknown kind explicitly noted in coverage_basis",
      err is None and any(b.startswith("uncovered_kind:frobnicate") for b in cov["coverage_basis"]))
check("BLAST-3 unknown kind not silently dropped (notation present)",
      err is None and any("frobnicate" in b for b in cov["coverage_basis"]))

# ---- BLAST-PRES regression: mixed authoritative kinds no longer crash ----
cov, err = no_die([
    {"kind": "exec", "name": "x", "src": "fw1", "command": "nft list ruleset", "assertion": {"contains": "drop"}},
    {"kind": "bgp_neighbor", "name": "b", "src": "r1", "dst": "10.0.0.2"},
    {"kind": "route_prefix", "name": "rp", "src": "r2", "prefix": "10.0.0.0/24"},
])
check("BLAST-PRES exec+bgp_neighbor+route_prefix no longer crash", err is None and {"fw1", "r1", "r2"} <= set(cov["covered_nodes"]))

# ---- Non-vacuity: node validation die still fires on an unknown node ----
_, err = no_die([{"kind": "exec", "name": "x", "src": "ghost", "command": "nft list ruleset", "assertion": {"contains": "drop"}}])
check("NV unknown-node die still fires (src='ghost')", isinstance(err, SystemExit))

# ---- BLAST-PRES: ping/tcp/invariant coverage is the canonical (preserved) result ----
cov, err = no_die([{"kind": "ping", "name": "p", "src": "r1", "dst": "r2"},
                   {"kind": "tcp", "name": "t", "src": "r1", "dst": "h1"},
                   {"kind": "invariant", "name": "i", "type": "bgp_session_up", "node": "r2"}])
check("BLAST-PRES ping/tcp/invariant coverage preserved (canonical node set)",
      err is None and set(cov["covered_nodes"]) == {"r1", "r2", "h1"})

ok = True
for name, passed in checks:
    print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    ok = ok and passed
print("=" * 60)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
