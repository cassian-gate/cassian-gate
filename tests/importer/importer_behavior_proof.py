#!/usr/bin/env python3
"""importer_behavior_proof.py -- §4.14 WI-3 (PO-1..PO-4), lab-free.

Proves the brownfield importer's behavioral Req-IDs against committed fixtures,
with no lab and no containers (cassian-test-alone CI posture):

  PO-1  Determinism (REQ-414-IF-4, D01/D02). Importing the same fixture twice
        yields byte-identical topology.yaml and starter_invariants.yaml.
  PO-2  Round-trip conformance (REQ-414-NB-3, INV-3, VAL-2). The emitted
        topology passes ensure_valid_topology + resolve_topology unchanged.
  PO-3  §13(a) input-rejection sufficiency (REQ-414-VAL-1/-2/-3). Each negative
        fixture hard-fails at the exit-2 band with a message naming the
        offending field/source, the issue, and the corrective action.
  PO-4  Starter-invariant boundedness + allowlist + exec-validation seam
        (REQ-414-INV-1/-2/-3, BR-3). Invariants are generated only from
        unambiguous declarations, are allowlist-typed, sort deterministically,
        and the reused exec-assertion validator accepts a typed predicate while
        rejecting freeform text (INV-2).

Exit 0 on all-pass; loud exit 1 on any failure. Run from the repo root:
    python tests/importer/importer_behavior_proof.py
"""
import os
import subprocess
import sys
import tempfile
import shutil

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import yaml  # noqa: E402
import cassian_common as _cc  # noqa: E402
_cc._QUIET_DIE = True  # mirror cmd_validate: die -> SystemExit(str(msg))

from cassian_import import (  # noqa: E402
    run_import,
    produce_pair,
    generate_starter_invariants,
    _validate_emitted_pair,
)
from cassian_model import ensure_valid_topology, resolve_topology  # noqa: E402

FIX = os.path.join(_ROOT, "tests", "importer", "fixtures")
POS = os.path.join(FIX, "siteA")
NEG_DIR = os.path.join(FIX, "neg")

# Each negative: (fixture subdir, substrings the §13(a) message must contain).
NEGATIVES = [
    ("undefined_node", ["undefined node", "allowed", "re-run"]),
    ("unsupported_platform", ["platform", "unsupported", "re-run"]),
    ("malformed_json", ["not", "JSON", "re-run"]),
    ("missing_site", ["site.name", "required", "re-run"]),
]

checks = []


def record(name, ok, detail=""):
    checks.append((name, ok, detail))


def po1_determinism():
    scratch = tempfile.mkdtemp(prefix="po1_")
    try:
        a, b = os.path.join(scratch, "a"), os.path.join(scratch, "b")
        run_import(POS, a, backend="netbox")
        run_import(POS, b, backend="netbox")
        t = (open(os.path.join(a, "topology.yaml"), "rb").read()
             == open(os.path.join(b, "topology.yaml"), "rb").read())
        i = (open(os.path.join(a, "tests", "starter_invariants.yaml"), "rb").read()
             == open(os.path.join(b, "tests", "starter_invariants.yaml"), "rb").read())
        record("PO-1 topology byte-identical (IF-4)", t)
        record("PO-1 invariants byte-identical (IF-4)", i)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def po2_roundtrip():
    scratch = tempfile.mkdtemp(prefix="po2_")
    try:
        run_import(POS, scratch, backend="netbox")
        topo = yaml.safe_load(open(os.path.join(scratch, "topology.yaml")))
        try:
            ensure_valid_topology(topo)
            resolve_topology(topo)
            record("PO-2 emitted topology validate+resolve (NB-3/VAL-2)", True)
        except SystemExit as e:
            record("PO-2 emitted topology validate+resolve (NB-3/VAL-2)", False,
                   "rejected: " + str(e))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def po3_rejection():
    for sub, needles in NEGATIVES:
        src = os.path.join(NEG_DIR, sub)
        out = tempfile.mkdtemp(prefix="po3_")
        try:
            r = subprocess.run(
                [sys.executable, "-c",
                 "import sys,os;sys.path.insert(0,%r);"
                 "from cassian_import import run_import;"
                 "run_import(%r,%r)" % (_SRC, src, out)],
                capture_output=True, text=True,
            )
            msg = (r.stderr or r.stdout)
            band = (r.returncode == 2)
            sufficient = all(n.lower() in msg.lower() for n in needles)
            record("PO-3 " + sub + " exits 2 (VAL-1)", band, "rc=" + str(r.returncode))
            record("PO-3 " + sub + " message field/issue/corrective (VAL-1)",
                   sufficient, msg.strip()[:120])
        finally:
            shutil.rmtree(out, ignore_errors=True)


def po4_boundedness():
    topo, invs = produce_pair(POS, backend="netbox")
    recognized = {
        "bgp_session_up", "route_present", "route_absent", "bgp_med_equals",
        "bgp_localpref_equals", "bgp_community", "bgp_as_path",
        "route_advertised_to", "route_not_advertised_to", "evpn_mac_route_present",
        "evpn_mac_route_absent", "evpn_vni_route_present", "evpn_bgp_session_up",
        "ospf_neighbor_up", "interface_state",
    }
    record("PO-4 all invariant kinds == 'invariant' (INV-1)",
           all(t.get("kind") == "invariant" for t in invs))
    record("PO-4 all invariant types in recognized allowlist (INV-1)",
           all(t.get("type") in recognized for t in invs),
           "types=" + str(sorted({t.get("type") for t in invs})))
    # Boundedness: an empty declaration set yields zero invariants (no synthesis).
    record("PO-4 empty declarations -> zero invariants (BR-3 no synthesis)",
           generate_starter_invariants({}) == [])
    # Determinism: generation is sorted by name and stable across calls.
    a = generate_starter_invariants({"bgp_session": [("n2", "10.0.0.9"), ("n1", "10.0.0.1")]})
    names = [t["name"] for t in a]
    record("PO-4 generation deterministically sorted (D01)", names == sorted(names))
    # INV-2 exec-validation seam: typed predicate accepted, freeform rejected.
    exec_ok = {"name": "x", "kind": "exec", "src": "n1",
               "command": 'vtysh -c "show ip bgp summary"',
               "assertion": {"contains": "Established"}}
    try:
        _validate_emitted_pair({"name": "t", "nodes": [{"name": "n1", "type": "frr"}],
                                "links": [], "tests": [exec_ok]})
        record("PO-4 exec instance validates under existing schema (INV-2)", True)
    except SystemExit as e:
        record("PO-4 exec instance validates under existing schema (INV-2)", False, str(e))
    rejected = False
    try:
        _validate_emitted_pair({"name": "t", "nodes": [{"name": "n1", "type": "frr"}],
                                "links": [], "tests": [dict(exec_ok, assertion="freeform")]})
    except SystemExit:
        rejected = True
    record("PO-4 freeform exec assertion rejected (INV-2)", rejected)


def main():
    po1_determinism()
    po2_roundtrip()
    po3_rejection()
    po4_boundedness()
    failed = [n for n, ok, _ in checks if not ok]
    for n, ok, detail in checks:
        print(("PASS" if ok else "FAIL") + "  " + n + (("  -- " + detail) if detail else ""))
    if failed:
        print("\nBEHAVIOR PROOF FAIL: " + str(len(failed)) + " check(s)")
        sys.exit(1)
    print("\nRESULT: PASS -- " + str(len(checks)) + " checks (PO-1..PO-4)")
    sys.exit(0)


if __name__ == "__main__":
    main()
