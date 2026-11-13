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
  PF-2  §4.6 stage 1 (handover §15.2), contract backend. Each malformed,
        ambiguous or out-of-contract declaration hard-fails at exit 2 with
        the file, the entry, the issue and the fix named, and nothing written.
  PF-4  Each out-of-scope session is excluded and named on output, exit 0,
        with no neighbour and no starter check (page legs: stage 6).
  PF-5  siteA's pair equals the committed golden; the success block; the
        set-aside section; the contract positives of §15.2.

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


# --------------------------------------------------------------------------- #
# §4.6 stage 1, contract backend: PF-2, PF-4, PF-5 (handover §15), lab-free.   #
# Each case is a literal mutation of siteA's netbox_export.json, copied with   #
# rendered/ (unless the case says otherwise) into a scratch directory; no      #
# committed fixture is edited (§15.1). Rejections run in a subprocess, as PO-3 #
# does, so the exit code is observed. PF-4's page legs land with stage 6.      #
# --------------------------------------------------------------------------- #
import copy as _copy  # noqa: E402
import json as _json  # noqa: E402

GOLDEN_SITEA = os.path.join(FIX, "golden", "siteA")
PRE_CHANGE_DIGESTS = (
    "c98e7a508e2ad141743e6eb6a78b553b3ce8be841438a33d77b633bfae969f37  topology.yaml\n"
    "55a41af354a6c11d0c7b30c152ad3d8300bebc73ff23bd1defac78aaa97af6e2  "
    "tests/starter_invariants.yaml\n"
)
SET_ASIDE_REASON = (
    "route_present checks for declared static routes. Cassian Gate does not "
    "configure static routes on the nodes it generates, so these pass only "
    "where routing comes from device configuration. They are not in "
    "topology.yaml."
)
N18_WALKTHROUGH = (
    "ERROR: Invalid NetBox import: <source>/netbox_export.json: bgp_sessions[0] "
    "(local_device 'leaf1', peer_ip '10.0.0.1'): 10.0.0.1 lies inside the subnet "
    "of link leaf1:eth1<->spine1:eth1 but is not its far-end address (10.0.0.2); "
    "is the peer address mistyped? Correct the export and re-run."
)


def _rec(name, ok, detail=""):
    """record(), with the detail kept only for a failure (one line per check)."""
    record(name, ok, "" if ok else " ".join(str(detail).split()))


def _site_a():
    with open(os.path.join(POS, "netbox_export.json"), encoding="utf-8") as f:
        return _json.load(f)


def _mutated(mutate):
    export = _site_a()
    mutate(export)
    return export


def _import_case(export, rendered=True):
    """Write the case to a scratch source, import it in a subprocess, and
    return (result, scratch, source, out)."""
    scratch = tempfile.mkdtemp(prefix="pf46_")
    src = os.path.join(scratch, "src")
    out = os.path.join(scratch, "out")
    os.makedirs(src)
    with open(os.path.join(src, "netbox_export.json"), "w", encoding="utf-8") as f:
        _json.dump(export, f, indent=1)
    if rendered:
        shutil.copytree(os.path.join(POS, "rendered"), os.path.join(src, "rendered"))
    r = subprocess.run(
        [sys.executable, "-c",
         "import sys;sys.path.insert(0,%r);"
         "from cassian_import import run_import;"
         "run_import(%r,%r)" % (_SRC, src, out)],
        capture_output=True, text=True,
    )
    return r, scratch, src, out


def _files_under(path):
    return [os.path.join(d, n) for d, _, ns in os.walk(path) for n in ns]


def _add_device(e, name, **fields):
    e["devices"].append(dict({"name": name, "platform": "frr"}, **fields))


def _add_cable(e, a, b, a_ip=None, b_ip=None):
    cable = {"a": {"device": a[0], "interface": a[1]},
             "b": {"device": b[0], "interface": b[1]}}
    if a_ip:
        cable["a_ip"] = a_ip
    if b_ip:
        cable["b_ip"] = b_ip
    e["cables"].append(cable)


def _set(path, value):
    """A mutation setting export[path...] = value (path of keys and indexes)."""
    def mutate(e):
        node = e
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
    return mutate


def _drop(path):
    def mutate(e):
        node = e
        for k in path[:-1]:
            node = node[k]
        del node[path[-1]]
    return mutate


def _n16(e):
    _add_device(e, "spine2")
    _add_cable(e, ("leaf1", "eth2"), ("spine2", "eth1"), "10.0.0.1/30", "10.0.0.2/30")


def _n17(e):
    _add_cable(e, ("leaf1", "eth2"), ("spine1", "eth2"), "10.0.0.5/30", "10.0.0.6/30")


def _n20(e):
    _add_device(e, "spine2")
    _add_cable(e, ("spine1", "eth2"), ("spine2", "eth1"), "10.0.1.1/29", "10.0.1.2/29")
    e["bgp_sessions"].append(
        {"local_device": "leaf1", "peer_ip": "10.0.1.3", "remote_asn": 65003})


def _n22(e):
    _add_device(e, "spine2")
    _add_device(e, "spine3")
    _add_cable(e, ("spine2", "eth1"), ("spine3", "eth1"), "10.0.0.2/30", "10.0.0.1/30")


def _n24c(e):
    _add_device(e, "leaf2", asn=65003)
    e["bgp_sessions"].append(
        {"local_device": "leaf2", "peer_ip": "198.51.100.1", "remote_asn": 65010})


def _both_ips(a_ip, b_ip):
    def mutate(e):
        e["cables"][0]["a_ip"] = a_ip
        e["cables"][0]["b_ip"] = b_ip
    return mutate


def _append_copy(key):
    def mutate(e):
        e[key].append(_copy.deepcopy(e[key][0]))
    return mutate


# (case, mutation, needles, rendered/ copied?) -- handover §15.2, PF-2 contract.
PF2_CASES = [
    ("N-1a", _drop(["bgp_sessions", 0, "peer_ip"]),
     ["bgp_sessions[0]", "'peer_ip'", "not an IPv4 address"], True),
    ("N-1b", _set(["bgp_sessions", 0, "peer_ip"], ""),
     ["bgp_sessions[0]", "'peer_ip'", "not an IPv4 address"], True),
    ("N-1c", _set(["bgp_sessions", 0, "peer_ip"], "spine1"),
     ["bgp_sessions[0]", "'peer_ip'", "not an IPv4 address"], True),
    ("N-2", _drop(["static_routes", 0, "prefix"]),
     ["static_routes[0]", "'prefix' is missing"], True),
    ("N-3a", _set(["devices", 0, "asn"], "65001"),
     ["devices[0]", "'asn' must be an integer"], True),
    ("N-3b", _set(["devices", 0, "asn"], True),
     ["devices[0]", "'asn' must be an integer"], True),
    ("N-3c", _set(["devices", 0, "asn"], 65001.0),
     ["devices[0]", "'asn' must be an integer"], True),
    ("N-4a", _set(["bgp_sessions", 0, "remote_asn"], "65002"),
     ["bgp_sessions[0]", "'remote_asn' must be an integer"], True),
    ("N-4b", _set(["bgp_sessions", 0, "remote_asn"], False),
     ["bgp_sessions[0]", "'remote_asn' must be an integer"], True),
    ("N-5", _drop(["cables", 0, "b_ip"]), ["cables[0]", "without the other"], True),
    ("N-6a", _set(["cables", 0, "b_ip"], "10.0.1.2/30"),
     ["cables[0]", "not two distinct addresses of one IPv4 subnet"], True),
    ("N-6b", _set(["cables", 0, "b_ip"], "10.0.0.2/29"),
     ["cables[0]", "not two distinct addresses of one IPv4 subnet"], True),
    ("N-6c", _set(["cables", 0, "b_ip"], "10.0.0.1/30"),
     ["cables[0]", "not two distinct addresses of one IPv4 subnet"], True),
    ("N-7a", _set(["extra"], 1), ["top level", "unknown key 'extra'", "allowed:"], True),
    ("N-7b", _set(["site", "slug"], "site-a"), ["site", "unknown key 'slug'", "allowed:"], True),
    ("N-7c", _set(["devices", 0, "role"], "leaf"),
     ["devices[0]", "unknown key 'role'", "allowed:"], True),
    ("N-7d", _set(["cables", 0, "label"], "c1"),
     ["cables[0]", "unknown key 'label'", "allowed:"], True),
    ("N-7e", _set(["cables", 0, "a", "port"], 1),
     ["cables[0]", "end 'a'", "unknown key 'port'", "allowed:"], True),
    ("N-7f", _set(["bgp_sessions", 0, "local_as"], 65001),
     ["bgp_sessions[0]", "unknown key 'local_as'", "allowed:"], True),
    ("N-7g", _set(["static_routes", 0, "next_hop"], "10.0.0.2"),
     ["static_routes[0]", "unknown key 'next_hop'", "allowed:"], True),
    ("N-8", _append_copy("static_routes"),
     ["static_routes", "more than once", "[0] and [1]"], True),
    ("N-9", _append_copy("bgp_sessions"),
     ["bgp_sessions", "more than once", "[0] and [2]"], True),
    ("N-10a", _set(["cables", 0, "a", "interface"], "Gi0/0/1"),
     ["cables[0]", "not a valid Linux interface name"], True),
    ("N-10b", _set(["cables", 0, "a", "interface"], "eth1234567890123"),
     ["cables[0]", "not a valid Linux interface name"], True),
    ("N-10c", _set(["cables", 0, "a", "interface"], "eth:1"),
     ["cables[0]", "not a valid Linux interface name"], True),
    ("N-10d", _set(["cables", 0, "a", "interface"], "eth 1"),
     ["cables[0]", "not a valid Linux interface name"], True),
    ("N-10e", _set(["cables", 0, "a", "interface"], "."),
     ["cables[0]", "not a valid Linux interface name"], True),
    ("N-10f", _set(["cables", 0, "a", "interface"], ".."),
     ["cables[0]", "not a valid Linux interface name"], True),
    ("N-11a", _set(["static_routes", 0, "prefix"], "192.0.2.1/24"),
     ["static_routes[0]", "no host bits set"], True),
    ("N-11b", _set(["static_routes", 0, "prefix"], "192.0.2.0/33"),
     ["static_routes[0]", "no host bits set"], True),
    ("N-12a", _both_ips("10.0.0.1", "10.0.0.2"),
     ["cables[0]", "not an IPv4 interface address"], True),
    ("N-12b", _both_ips("2001:db8::1/64", "2001:db8::2/64"),
     ["cables[0]", "not an IPv4 interface address"], True),
    ("N-16", _n16, ["bgp_sessions[0]", "far-end address of more than one"], True),
    ("N-17", _n17, ["bgp_sessions[0]", "more than one link"], True),
    ("N-18", _set(["bgp_sessions", 0, "peer_ip"], "10.0.0.1"),
     ["bgp_sessions[0]", "is not its far-end address"], True),
    ("N-20", _n20, ["bgp_sessions[2]", "neither of its addresses"], True),
    ("N-22", _n22, ["bgp_sessions[0]", "in different ways"], True),
    ("N-23", _drop(["bgp_sessions", 0, "remote_asn"]),
     ["bgp_sessions[0]", "'remote_asn' is required"], True),
    ("N-24a", _drop(["devices", 0, "router_id"]),
     ["devices[0]", "has a BGP session but no 'router_id'"], False),
    ("N-24b", _drop(["devices", 0, "asn"]),
     ["devices[0]", "has a BGP session but no 'asn'"], False),
    ("N-24c", _n24c, ["devices[2]", "has a BGP session but no 'router_id'"], False),
]


def pf2_contract_rejections():
    """PF-2 (REQ-46-1 to -24, -13): each case exits 2 with the file, the entry,
    the needles and 're-run' named, and writes nothing."""
    for case, mutate, needles, rendered in PF2_CASES:
        r, scratch, src, out = _import_case(_mutated(mutate), rendered)
        try:
            msg = r.stderr
            missing = [n for n in needles + ["netbox_export.json", "re-run"]
                       if n not in msg]
            written = _files_under(out)
            _rec("PF-2 " + case + " rejected at exit 2, named, nothing written "
                 "(REQ-46-13)",
                 r.returncode == 2 and not missing and not written,
                 "rc=%d missing=%s written=%d msg=%s"
                 % (r.returncode, missing, len(written), msg.strip()[:200]))
            if case == "N-18":
                want = N18_WALKTHROUGH.replace("<source>", src)
                _rec("PF-2 N-18 message equals the §19.2 walkthrough (REQ-46-13)",
                     msg.strip() == want, msg.strip()[:240])
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


def _load_pair(out):
    with open(os.path.join(out, "topology.yaml"), encoding="utf-8") as f:
        topo = yaml.safe_load(f)
    with open(os.path.join(out, "tests", "starter_invariants.yaml"),
              encoding="utf-8") as f:
        starter = yaml.safe_load(f)
    return topo, starter


def _block(out, n, m, k):
    topo = os.path.join(out, "topology.yaml")
    inv = os.path.join(out, "tests", "starter_invariants.yaml")
    return [
        "✅ IMPORT OK (authoritative input; backend: netbox): wrote " + topo,
        "   starter invariants (%d): embedded in topology.yaml, copied to %s" % (n, inv),
        "   set aside, need device configuration (%d): %s" % (m, inv),
        "   excluded by filter (%d)" % k,
    ]


def _neighbours(topo, node):
    for n in topo.get("nodes") or []:
        if n.get("name") == node:
            return [nb.get("peer") for nb in (n.get("bgp") or {}).get("neighbors") or []]
    return None


def _e19(e):
    _add_device(e, "spine2")
    _add_cable(e, ("spine1", "eth2"), ("spine2", "eth1"), "10.0.1.1/30", "10.0.1.2/30")
    e["bgp_sessions"].append(
        {"local_device": "leaf1", "peer_ip": "10.0.1.2", "remote_asn": 65003})


def _e21(e):
    e["bgp_sessions"].append(
        {"local_device": "leaf1", "peer_ip": "198.51.100.1", "remote_asn": 65010})


# (case, mutation, X, exclusion line, embedded count) -- handover §15.2, PF-4.
PF4_CASES = [
    ("E-19", _e19, "10.0.1.2",
     "   excluded: bgp-session leaf1 -> 10.0.1.2: non-adjacent peer: 10.0.1.2 is "
     "an address of link spine1:eth2<->spine2:eth1, which leaf1 is not on; a "
     "generated lab configures a neighbour only over the node's own links", 6),
    ("E-21", _e21, "198.51.100.1",
     "   excluded: bgp-session leaf1 -> 198.51.100.1: peer outside the declared "
     "topology: 198.51.100.1 lies outside every declared link's subnet", 4),
]


def pf4_contract_exclusions():
    """PF-4, contract backend (REQ-46-19, -21, -25, -27): exit 0; the exact
    block and exclusion line; no neighbour and no starter check for the
    excluded session. The page legs land with stage 6 (handover §0.5)."""
    for case, mutate, x, line, n in PF4_CASES:
        r, scratch, src, out = _import_case(_mutated(mutate))
        try:
            want = _block(out, n, 1, 1) + [line]
            _rec("PF-4 " + case + " exit 0, block and exclusion line exact "
                 "(REQ-46-25, -27)",
                 r.returncode == 0 and r.stdout.splitlines() == want,
                 "rc=%d out=%s err=%s" % (r.returncode, r.stdout[-300:],
                                          r.stderr.strip()[:200]))
            if r.returncode != 0:
                continue
            topo, starter = _load_pair(out)
            check_name = "starter_bgp_session_up_leaf1_" + "".join(
                c if c.isalnum() else "_" for c in x)
            names = [t.get("name") for t in (topo.get("tests") or [])
                     + (starter.get("tests") or [])]
            _rec("PF-4 " + case + " no neighbour, no starter check for the "
                 "excluded session (REQ-46-19, -21)",
                 _neighbours(topo, "leaf1") == ["spine1"] and check_name not in names,
                 "leaf1 neighbours=%s" % _neighbours(topo, "leaf1"))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


def _no_sessions_no_ips(e):
    e["bgp_sessions"] = []
    del e["cables"][0]["a_ip"]
    del e["cables"][0]["b_ip"]


def _rename_eth1(e):
    e["cables"][0]["a"]["interface"] = "eth123456789012"
    e["cables"][0]["b"]["interface"] = "eth123456789012"


def pf5_golden_and_positives():
    """PF-5 (REQ-46-28): siteA's pair equals the committed golden, whose
    PRE_CHANGE.sha256 holds the d396d5a pair's digests; the success block for
    siteA (REQ-46-27); and the contract positives of §15.2."""
    scratch = tempfile.mkdtemp(prefix="pf5_")
    try:
        out = os.path.join(scratch, "out")
        r = subprocess.run(
            [sys.executable, "-c",
             "import sys;sys.path.insert(0,%r);"
             "from cassian_import import run_import;"
             "run_import(%r,%r)" % (_SRC, POS, out)],
            capture_output=True, text=True,
        )
        _rec("PF-5 siteA success block exact (REQ-46-27)",
             r.returncode == 0 and r.stdout.splitlines() == _block(out, 4, 1, 0),
             "rc=%d out=%s" % (r.returncode, r.stdout[-300:]))
        for rel in ("topology.yaml", os.path.join("tests", "starter_invariants.yaml")):
            got = open(os.path.join(out, rel), "rb").read() if r.returncode == 0 else b""
            want = open(os.path.join(GOLDEN_SITEA, rel), "rb").read()
            _rec("PF-5 siteA " + rel + " equals golden/siteA (REQ-46-28)", got == want)
        with open(os.path.join(GOLDEN_SITEA, "PRE_CHANGE.sha256"), encoding="utf-8") as f:
            _rec("PF-5 PRE_CHANGE.sha256 holds the d396d5a digests (REQ-46-28)",
                 f.read() == PRE_CHANGE_DIGESTS)
        if r.returncode == 0:
            topo, starter = _load_pair(out)
            section = starter.get("needs_device_configuration") or {}
            _rec("PF-5 route_present only in the set-aside section (REQ-46-26)",
                 [t.get("type") for t in section.get("tests") or []] == ["route_present"]
                 and section.get("reason") == SET_ASIDE_REASON
                 and all(t.get("type") != "route_present" for t in topo.get("tests") or [])
                 and starter.get("tests") == topo.get("tests"))
            _rec("PF-5 neighbours are far-end node names (REQ-46-15)",
                 _neighbours(topo, "leaf1") == ["spine1"]
                 and _neighbours(topo, "spine1") == ["leaf1"])
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    # Contract positives (§15.2): REQ-46-5, -10, -24, -26.
    positives = [
        ("REQ-46-5 no addresses and no sessions: link without ipv4",
         _no_sessions_no_ips, True,
         lambda t, s: "ipv4" not in t["links"][0]),
        ("REQ-46-10 a 15-byte interface name accepted",
         _rename_eth1, True,
         lambda t, s: t["links"][0]["endpoints"]
         == ["leaf1:eth123456789012", "spine1:eth123456789012"]),
        ("REQ-46-24 router_id from the rendered config",
         _drop(["devices", 0, "router_id"]), True,
         lambda t, s: [n.get("router_id") for n in t["nodes"]
                       if n["name"] == "leaf1"] == ["1.1.1.1"]),
        ("REQ-46-26 no static route: no section, starter file is tests only",
         _set(["static_routes"], []), True,
         lambda t, s: sorted(s) == ["tests"]),
    ]
    for label, mutate, rendered, ok in positives:
        r, scratch, src, out = _import_case(_mutated(mutate), rendered)
        try:
            good = r.returncode == 0
            if good:
                topo, starter = _load_pair(out)
                good = bool(ok(topo, starter))
            _rec("PF-5 positive " + label, good,
                 "rc=%d err=%s" % (r.returncode, r.stderr.strip()[:200]))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


def main():
    po1_determinism()
    po2_roundtrip()
    po3_rejection()
    po4_boundedness()
    pf2_contract_rejections()
    pf4_contract_exclusions()
    pf5_golden_and_positives()
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
