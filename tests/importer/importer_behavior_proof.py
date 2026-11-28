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
  PF-11 §4.6 stage 2: every session siteA's import resolves renders as
        ' neighbor <X> remote-as <AS>' through the model's gen_frr_conf.
  PF-10 §4.6 stage 5 piece (i): the module's key lists equal what
        contrib/netbox-seed/keylists.py derives from the committed schema,
        whose sha256 is the manifest's; the filter's fields and in-service
        values are the schema's; the manifest's schema source is consistent;
        each check is shown failing once on a mutated copy.
  PF-1  §4.6 stage 5 piece (ii): bundleA through the netbox-dump reader
        equals golden/siteA, with and without rendered/, under permutation
        of order, IDs, timestamps and URLs; the pair passes the model.
  PF-3  No URL, ID, timestamp or free-form sentinel reaches the pair.
  PF-2  The reader's rejections (N-36 to N-70) and the shared path's through
        the reader (R-n): exit 2, file and object named, nothing written.
  PF-4  The reader's exclusions (E-19 to E-edge-sort): exit 0, each object
        named once with its reason, sorted (page legs: stage 6).
  PF-8  §4.6 stage 5 piece (iii): the committed seeded export through the
        reader, with and without rendered/, equals golden/netbox-seeded; its
        manifest names the proven set.
  PF-11 The seeded export's resolved sessions render through gen_frr_conf.

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
    # 46-S7-R2 under 46-S8-R4 (session-8 rulings note 2): a present site or
    # cable end that is not a JSON object is rejected at exit 2.
    ("46-S7-R2a", _set(["site"], "x"),
     ["site: must be a JSON object with 'name' (got " + '"x"' + "). Correct the export"],
     True),
    ("46-S7-R2b", _set(["cables", 0, "a"], "leaf1:eth1"),
     ["cables[0]: 'a' must be a JSON object with 'device' and 'interface' (got "
      + '"leaf1:eth1"' + "). Correct the export"], True),
    # Ruling 1 of 2026-11-27 (Chat 4's DRAFT rev 5 §10.1): B-10 to B-12 apply
    # to the value as written; a padded interface name, prefix or link
    # address is rejected with its REQ text, the value printed as written.
    ("RP-1a", _set(["cables", 0, "a", "interface"], "eth1 "),
     ["cables[0]", "interface name 'eth1 ' is not a valid Linux interface name"], True),
    ("RP-1b", _set(["cables", 0, "a", "interface"], "\teth1"),
     ["cables[0]", "interface name '\teth1' is not a valid Linux interface name"], True),
    ("RP-3a", _set(["static_routes", 0, "prefix"], "192.0.2.0/24 "),
     ["static_routes[0]", "prefix '192.0.2.0/24 ' is not an IPv4 network with no host bits set"],
     True),
    ("RP-3b", _set(["static_routes", 0, "prefix"], " 192.0.2.0/24"),
     ["static_routes[0]", "prefix ' 192.0.2.0/24' is not an IPv4 network with no host bits set"],
     True),
    ("RP-5a", _set(["cables", 0, "a_ip"], " 10.0.0.1/30"),
     ["cables[0]", "a_ip ' 10.0.0.1/30' is not an IPv4 interface address"], True),
    ("RP-5b", _set(["cables", 0, "b_ip"], "10.0.0.2/30 "),
     ["cables[0]", "b_ip '10.0.0.2/30 ' is not an IPv4 interface address"], True),
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


# --------------------------------------------------------------------------- #
# §4.6 stage 2: PF-11 on siteA (handover REQ-46-29, B-29), lab-free. Every     #
# session the import resolves appears in its local node's FRR configuration    #
# as ' neighbor <X> remote-as <AS>', rendered by the model's own generator on  #
# a resolved deep copy, by import, with no model edit and no file written.     #
# --------------------------------------------------------------------------- #
from cassian_model import gen_frr_conf  # noqa: E402


def _pf11_missing(topo_path, triples):
    """The (L, X, AS) of ``triples`` whose ' neighbor X remote-as AS' line is
    absent from L's gen_frr_conf text (B-29)."""
    with open(topo_path, encoding="utf-8") as f:
        topo = yaml.safe_load(f)
    resolved = resolve_topology(_copy.deepcopy(topo))
    nodes = {n.get("name"): n for n in resolved.get("nodes") or []}
    missing = []
    for local, x, asn in triples:
        text = gen_frr_conf(nodes[local], resolved) if local in nodes else ""
        if " neighbor %s remote-as %s" % (x, asn) not in text.splitlines():
            missing.append((local, x, asn))
    return missing


def _pf11_site_a_triples():
    """(L, X, AS) of siteA's two sessions, from its export; both resolve (PF-5)."""
    return sorted((s["local_device"], s["peer_ip"], s["remote_asn"])
                  for s in _site_a()["bgp_sessions"])


def pf11_render_site_a():
    """PF-11, siteA leg (REQ-46-29): import siteA, render each node of a
    resolved session through gen_frr_conf, and find every session's line."""
    scratch = tempfile.mkdtemp(prefix="pf11_")
    try:
        out = os.path.join(scratch, "out")
        r = subprocess.run(
            [sys.executable, "-c",
             "import sys;sys.path.insert(0,%r);"
             "from cassian_import import run_import;"
             "run_import(%r,%r)" % (_SRC, POS, out)],
            capture_output=True, text=True,
        )
        triples = _pf11_site_a_triples()
        missing = (_pf11_missing(os.path.join(out, "topology.yaml"), triples)
                   if r.returncode == 0 else triples)
        _rec("PF-11 siteA: each resolved session renders ' neighbor <X> "
             "remote-as <AS>' through gen_frr_conf (REQ-46-29)",
             r.returncode == 0 and len(triples) == 2 and not missing,
             "rc=%d missing=%s err=%s" % (r.returncode, missing, r.stderr.strip()[:200]))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# --------------------------------------------------------------------------- #
# §4.6 stage 5 piece (i): PF-10 (handover REQ-46-34, -48, -69; B-48, B-69;    #
# ruling 46-S4-R1), lab-free and offline. contrib/netbox-seed/keylists.py     #
# derives the reader's key lists from the committed schema; they must equal   #
# the module's literals. Each check also runs once on a mutated copy, which   #
# it must reject (the §15.2 self-tests). REQ-46-47's legs come with the       #
# reader, in piece (ii).                                                      #
# --------------------------------------------------------------------------- #
import hashlib as _hashlib  # noqa: E402
import importlib.util as _ilu  # noqa: E402

SEEDED = os.path.join(FIX, "netbox-seeded")
KEYLISTS = os.path.join(_ROOT, "contrib", "netbox-seed", "keylists.py")


def _keylists():
    """contrib/netbox-seed/keylists.py, loaded from its path (B-48)."""
    spec = _ilu.spec_from_file_location("keylists", KEYLISTS)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _differing(module_lists, derived):
    """The labels whose two lists differ between the module's literals and the
    derivation, each list compared sorted (REQ-46-48)."""
    mine = {k: {"read": sorted(r), "known": sorted(n)}
            for k, (r, n) in module_lists.items()}
    return sorted(k for k in set(mine) | set(derived)
                  if mine.get(k) != derived.get(k))


def _filter_problems(kl, schema, fields, in_service):
    """REQ-46-69: each filter field present on its object, and each in-service
    value a member of its object's status.value enum, in the committed schema."""
    problems = []
    for ep in sorted(set(fields) | set(in_service)):
        _name, props = kl.resolve(schema, ("endpoint", ep))
        for field in fields.get(ep, ()):
            if field not in props:
                problems.append("%s: no field %s" % (ep, field))
        status = (props.get("status") or {}).get("properties") or {}
        enum = (status.get("value") or {}).get("enum") or []
        if in_service.get(ep) not in enum:
            problems.append("%s: in-service value %r not in %s"
                            % (ep, in_service.get(ep), enum))
    return problems


def _source_consistent(schema, manifest):
    """REQ-46-34: the manifest's schema.source is 'published' exactly when the
    schema holds the netbox-bgp session endpoint."""
    published = "/api/plugins/bgp/session/" in (schema.get("paths") or {})
    return (manifest["schema"]["source"] == "published") == published


def pf10_key_lists():
    """PF-10 (REQ-46-34, -48, -69; 46-S4-R1)."""
    import cassian_import as ci
    with open(os.path.join(SEEDED, "manifest.json"), encoding="utf-8") as f:
        manifest = _json.load(f)
    with open(os.path.join(SEEDED, "schema.json"), "rb") as f:
        raw = f.read()
    digest = _hashlib.sha256(raw).hexdigest()
    _rec("PF-10 sha256(schema.json) equals the manifest's and the module's "
         "(REQ-46-48)",
         digest == manifest["schema"]["sha256"] == ci.DUMP_SCHEMA_SHA256,
         "schema=%s manifest=%s module=%s"
         % (digest, manifest["schema"]["sha256"], ci.DUMP_SCHEMA_SHA256))
    schema = _json.loads(raw.decode("utf-8"))
    kl = _keylists()
    try:
        derived = kl.derive(schema)
    except Exception as exc:  # noqa: BLE001 -- recorded as the check's failure
        _rec("PF-10 keylists.py derives the lists from the committed schema "
             "(REQ-46-48)", False, repr(exc))
        return
    differ = _differing(ci.DUMP_KEY_LISTS, derived)
    _rec("PF-10 the module's key lists equal keylists.py's derivation "
         "(REQ-46-48, B-48)", not differ, "differ=%s" % differ)
    label = sorted(k for k in derived if derived[k]["known"])[0]
    removed = _copy.deepcopy(derived)
    removed[label]["known"] = removed[label]["known"][1:]
    _rec("PF-10 self-test: one entry removed from a copy of the derived lists "
         "is detected (REQ-46-48)",
         _differing(ci.DUMP_KEY_LISTS, removed) == [label], "label=%s" % label)
    _rec("PF-10 the interface's lists come from the schema's BriefInterface, "
         "selected by dcim.interface (46-S4-R1)",
         ci.DUMP_INTERFACE_TYPE == "dcim.interface"
         and kl.TYPED_OBJECTS == {"dcim.interface": "BriefInterface"}
         and kl.OBJECTS["interface"][0] == ("component", "BriefInterface")
         and "BriefInterface" in schema["components"]["schemas"])
    problems = _filter_problems(kl, schema, ci.DUMP_FILTER_FIELDS,
                                ci.DUMP_IN_SERVICE)
    _rec("PF-10 each filter field is on its object and each in-service value "
         "is in its enum (REQ-46-69, B-69)", not problems, problems)
    linked = dict(ci.DUMP_IN_SERVICE)
    linked["dcim/cables"] = "linked"
    caught = _filter_problems(kl, schema, ci.DUMP_FILTER_FIELDS, linked)
    _rec("PF-10 self-test: 'connected' changed to 'linked' is detected "
         "(REQ-46-69)", len(caught) == 1 and "'linked'" in caught[0], caught)
    _rec("PF-10 schema.source is 'published' exactly when the schema holds "
         "the session endpoint (REQ-46-34)", _source_consistent(schema, manifest))
    flipped = _copy.deepcopy(manifest)
    flipped["schema"]["source"] = (
        "plugin serializer" if manifest["schema"]["source"] == "published"
        else "published")
    _rec("PF-10 self-test: the source value flipped is detected (REQ-46-34)",
         not _source_consistent(schema, flipped))


# --------------------------------------------------------------------------- #
# §4.6 stage 5 piece (ii): the netbox-dump reader on bundleA                   #
# --------------------------------------------------------------------------- #
# Every case is a literal mutation of the committed bundleA, written to a
# scratch directory and imported in a subprocess (handover §15.1).

BUNDLE_A = os.path.join(FIX, "bundleA")
_BUNDLE_FILES = (
    ("manifest", "manifest.json"),
    ("devices", "dcim_devices.json"),
    ("cables", "dcim_cables.json"),
    ("ips", "ipam_ip_addresses.json"),
    ("sessions", "plugins_bgp_session.json"),
)
_NB = "http://netbox.example.test"


def _bundle():
    out = {}
    for key, name in _BUNDLE_FILES:
        with open(os.path.join(BUNDLE_A, name), encoding="utf-8") as f:
            out[key] = _json.load(f)
    return out


def _bundle_case(mutate=None, rendered=False, backend="netbox-dump", source=None):
    """Write bundleA, mutated, to a scratch source (a value None omits its
    file; a str is written raw), import it in a subprocess, and return
    (result, scratch, source, out)."""
    scratch = tempfile.mkdtemp(prefix="pf46b_")
    src = os.path.join(scratch, "src")
    out = os.path.join(scratch, "out")
    if source:
        shutil.copytree(source, src)
    else:
        os.makedirs(src)
        b = _bundle()
        if mutate:
            mutate(b)
        for key, name in _BUNDLE_FILES:
            if b[key] is None:
                continue
            with open(os.path.join(src, name), "w", encoding="utf-8") as f:
                f.write(b[key] if isinstance(b[key], str) else _json.dumps(b[key], indent=1))
    if rendered:
        shutil.copytree(os.path.join(POS, "rendered"), os.path.join(src, "rendered"))
    r = subprocess.run(
        [sys.executable, "-c",
         "import sys;sys.path.insert(0,%r);"
         "from cassian_import import run_import;"
         "run_import(%r,%r,backend=%r)" % (_SRC, src, out, backend)],
        capture_output=True, text=True,
    )
    return r, scratch, src, out


def _nb_dev(i, name):
    return {"description": "", "display": name, "id": i, "name": name,
            "url": "%s/api/dcim/devices/%d/" % (_NB, i)}


def _nb_iface(i, dev, name):
    return {"_occupied": True, "cable": None, "description": "",
            "device": _nb_dev(*dev), "display": name, "id": i, "name": name,
            "url": "%s/api/dcim/interfaces/%d/" % (_NB, i)}


def _nb_status(value):
    return {"label": value.title(), "value": value}


def _nb_device(i, name, status="active", lcd=None):
    d = _json.loads(_json.dumps(_bundle()["devices"][1]))
    d.update({"id": i, "name": name, "display": name, "status": _nb_status(status),
              "local_context_data": lcd, "url": "%s/api/dcim/devices/%d/" % (_NB, i)})
    return d


def _nb_term(obj, otype="dcim.interface"):
    return {"object": obj, "object_id": obj.get("id"), "object_type": otype}


def _nb_cable(i, a, b, status="connected"):
    """a and b: (interface id, (device id, device name), interface name), or a
    termination dict."""
    sides = []
    for end in (a, b):
        sides.append(end if isinstance(end, dict)
                     else _nb_term(_nb_iface(end[0], end[1], end[2])))
    c = _json.loads(_json.dumps(_bundle()["cables"][0]))
    c.update({"id": i, "a_terminations": [sides[0]], "b_terminations": [sides[1]],
              "status": _nb_status(status), "url": "%s/api/dcim/cables/%d/" % (_NB, i)})
    return c


def _nb_ip(i, address, iface, status="active", vrf=None):
    p = _json.loads(_json.dumps(_bundle()["ips"][0]))
    obj = _nb_iface(*iface)
    p.update({"id": i, "address": address, "display": address, "assigned_object": obj,
              "assigned_object_id": obj["id"], "status": _nb_status(status),
              "url": "%s/api/ipam/ip-addresses/%d/" % (_NB, i),
              "vrf": None if vrf is None else {"description": "", "display": vrf,
                                               "id": 1, "name": vrf, "rd": None,
                                               "url": _NB + "/api/ipam/vrfs/1/"}})
    return p


def _nb_session(i, dev, peer, local_as, remote_as, status="active", ra_id=None):
    s = _json.loads(_json.dumps(_bundle()["sessions"][0]))
    s.update({"id": i, "device": None if dev is None else _nb_dev(*dev),
              "local_as": {"asn": local_as, "description": "", "display": "AS%d" % local_as,
                           "id": local_as, "url": _NB + "/api/ipam/asns/1/"},
              "remote_as": {"asn": remote_as, "description": "", "display": "AS%d" % remote_as,
                            "id": remote_as, "url": _NB + "/api/ipam/asns/2/"},
              "remote_address": {"address": peer, "description": "", "display": peer,
                                 "id": 9000 + i if ra_id is None else ra_id,
                                 "url": _NB + "/api/ipam/ip-addresses/9/"},
              "status": _nb_status(status), "url": "%s/api/plugins/bgp/bgpsession/%d/" % (_NB, i)})
    return s


LEAF1, SPINE1, SPINE2, SPINE3, LEAF9 = (1, "leaf1"), (2, "spine1"), (3, "spine2"), (4, "spine3"), (9, "leaf9")
OUTSIDE = (99, "siteb-spine1")


def _add(key, *objs):
    def m(b):
        b[key].extend(_json.loads(_json.dumps(objs)))
    return m


def _all(*mutations):
    def m(b):
        for f in mutations:
            f(b)
    return m


def _at(path, value):
    """Set b[path...] = value, or delete the key when value is _DROP."""
    def m(b):
        node = b
        for p in path[:-1]:
            node = node[p]
        if value is _DROP:
            del node[path[-1]]
        else:
            node[path[-1]] = value
    return m


_DROP = object()


def _spine2():
    return _add("devices", _nb_device(3, "spine2", lcd={"cassian": {"router_id": "3.3.3.3"}}))


def _e19():
    return _all(
        _spine2(),
        _add("cables", _nb_cable(2, (22, SPINE1, "eth2"), (31, SPINE2, "eth1"))),
        _add("ips", _nb_ip(3, "10.0.1.1/30", (22, SPINE1, "eth2")),
             _nb_ip(4, "10.0.1.2/30", (31, SPINE2, "eth1"))),
        _add("sessions", _nb_session(3, LEAF1, "10.0.1.2/30", 65001, 65003)),
    )


def _circuit_term():
    return _nb_term({"circuit": {"cid": "CID-1001", "description": "", "display": "CID-1001",
                                 "id": 7, "provider": None, "url": _NB + "/api/circuits/circuits/7/"},
                     "display": "CID-1001: Termination A", "id": 501, "term_side": "A",
                     "url": _NB + "/api/circuits/circuit-terminations/501/"},
                    "circuits.circuittermination")


def _frontport_term():
    return _nb_term({"cable": None, "description": "", "device": _nb_dev(*SPINE1),
                     "display": "fp1", "id": 601, "name": "fp1",
                     "url": _NB + "/api/dcim/front-ports/601/"}, "dcim.frontport")


def _e64b():
    return _all(
        _add("devices", _nb_device(9, "leaf9", status="decommissioning")),
        _add("cables", _nb_cable(3, (91, LEAF9, "eth1"), (23, SPINE1, "eth3"))),
        _add("ips", _nb_ip(5, "10.0.9.1/30", (91, LEAF9, "eth1")),
             _nb_ip(6, "10.0.9.2/30", (23, SPINE1, "eth3"))),
        _add("sessions", _nb_session(5, LEAF9, "10.0.9.2/30", 65009, 65002)),
    )


def _e71(name="siteb-spine1"):
    out = (99, name)
    return _all(
        _add("cables", _nb_cable(4, (24, SPINE1, "eth4"), (991, out, "eth1"))),
        _add("ips", _nb_ip(7, "10.9.9.1/30", (24, SPINE1, "eth4"))),
    )


_E71B = _add("ips", _nb_ip(8, "10.9.9.2/30", (991, OUTSIDE, "eth1")))
_E71C = _add("sessions", _nb_session(7, OUTSIDE, "10.9.9.1/30", 65099, 65002))


def _e72(ra_id=777):
    return _add("sessions", _nb_session(8, LEAF1, "198.51.100.1/32", 65001, 65010, ra_id=ra_id))


_X = "   excluded: "
_L19 = (_X + "bgp-session leaf1 -> 10.0.1.2: non-adjacent peer: 10.0.1.2 is an address "
        "of link spine1:eth2<->spine2:eth1, which leaf1 is not on; a generated lab "
        "configures a neighbour only over the node's own links")
_L21 = (_X + "bgp-session leaf1 -> 198.51.100.1: peer outside the declared topology: "
        "198.51.100.1 lies outside every declared link's subnet")
_L45 = _X + "bgp-session leaf1 -> 198.51.100.7: status planned is not active"
_L43A = (_X + "cable leaf1:eth3 <-> circuits.circuittermination CID-1001 A: termination "
         "circuits.circuittermination is not an interface; links connect interfaces")
_L44A = (_X + "ip-address leaf1:eth1 2001:db8::1/64: IPv6 address; the importer reads "
         "IPv4 link addresses only")
_NO_LINK = "interface is on no imported link, so no link carries the address"

_E21 = _add("sessions", _nb_session(6, LEAF1, "198.51.100.1/32", 65001, 65010))
_E45 = _add("sessions", _nb_session(4, LEAF1, "198.51.100.7/32", 65001, 65010, status="planned"))
_E43A = _add("cables", _nb_cable(6, (13, LEAF1, "eth3"), _circuit_term()))
_E44A = _add("ips", _nb_ip(13, "2001:db8::1/64", (11, LEAF1, "eth1")))
_E65 = _add("cables", _nb_cable(5, (12, LEAF1, "eth2"), (22, SPINE1, "eth2"), status="planned"))
_E67 = _add("ips", _nb_ip(10, "172.16.0.1/24", (11, LEAF1, "eth1"), vrf="mgmt"))

# (case, mutation, the exclusion lines in order, embedded, set aside, pair is golden)
PF4_BUNDLE_CASES = [
    ("E-19", _e19(), [_L19], 6, False),
    ("E-21", _E21, [_L21], 4, True),
    ("E-45", _E45, [_L45], 4, True),
    ("E-43a", _E43A, [_L43A], 4, True),
    ("E-43b", _add("cables", _nb_cable(2, (13, LEAF1, "eth3"), _frontport_term())),
     [_X + "cable leaf1:eth3 <-> dcim.frontport spine1 fp1: termination dcim.frontport "
      "is not an interface; links connect interfaces"], 4, True),
    ("E-44a", _E44A, [_L44A], 4, True),
    ("E-44b", _add("ips", _nb_ip(3, "10.0.9.9/24", (19, LEAF1, "eth9"))),
     [_X + "ip-address leaf1:eth9 10.0.9.9/24: " + _NO_LINK], 4, True),
    ("E-sort", _all(_e19(), _E21, _E43A, _E44A, _E45), [_L19, _L21, _L45, _L43A, _L44A], 6, False),
    ("E-45b", _add("sessions", _nb_session(3, LEAF1, "2001:db8::2/64", 65001, 65010)),
     [_X + "bgp-session leaf1 -> 2001:db8::2: IPv6 peer; the importer reads IPv4 "
      "sessions only"], 4, True),
    ("E-64a", _add("devices", _nb_device(9, "leaf9", status="decommissioning")),
     [_X + "device leaf9: status decommissioning is not active"], 4, True),
    ("E-64b", _e64b(),
     [_X + "bgp-session leaf9 -> 10.0.9.2: device leaf9 is excluded",
      _X + "cable leaf9:eth1 <-> spine1:eth3: device leaf9 is excluded",
      _X + "device leaf9: status decommissioning is not active",
      _X + "ip-address leaf9:eth1 10.0.9.1/30: device leaf9 is excluded",
      _X + "ip-address spine1:eth3 10.0.9.2/30: " + _NO_LINK], 4, True),
    ("E-65", _E65, [_X + "cable leaf1:eth2 <-> spine1:eth2: status planned is not connected"],
     4, True),
    ("E-66", _add("ips", _nb_ip(3, "10.0.0.9/30", (11, LEAF1, "eth1"), status="deprecated")),
     [_X + "ip-address leaf1:eth1 10.0.0.9/30: status deprecated is not active"], 4, True),
    ("E-67", _E67, [_X + "ip-address leaf1:eth1 172.16.0.1/24: in VRF mgmt; the importer "
                    "models the global table only"], 4, True),
    ("E-AP6", _all(_add("devices", _nb_device(3, "leaf2")),
                   _add("sessions", _nb_session(3, (3, "leaf2"), "10.0.0.2/30", 65003, 65002,
                                                status="planned"))),
     [_X + "bgp-session leaf2 -> 10.0.0.2: status planned is not active"], 4, False),
    ("E-AP7", _add("sessions", _nb_session(3, LEAF1, "198.51.100.7/32", 65099, 65010,
                                           status="planned")),
     [_L45], 4, True),
    ("E-71a", _e71(),
     [_X + "cable spine1:eth4 <-> siteb-spine1:eth1: device siteb-spine1 is not in this "
      "site's bundle", _X + "ip-address spine1:eth4 10.9.9.1/30: " + _NO_LINK], 4, True),
    ("E-71a nested name", _e71("other-name"),
     [_X + "cable spine1:eth4 <-> other-name:eth1: device other-name is not in this "
      "site's bundle", _X + "ip-address spine1:eth4 10.9.9.1/30: " + _NO_LINK], 4, True),
    ("E-71b", _E71B, [_X + "ip-address siteb-spine1:eth1 10.9.9.2/30: device siteb-spine1 "
                      "is not in this site's bundle"], 4, True),
    ("E-71c", _E71C, [_X + "bgp-session siteb-spine1 -> 10.9.9.1: device siteb-spine1 is "
                      "not in this site's bundle"], 4, True),
    ("E-72", _e72(), [_L21], 4, True),
    ("E-72 address in the bundle", _e72(ra_id=1), [_L21], 4, True),
]

# §19.1b: E-64b, E-65 with addresses, and E-67, together (E-G-sort).
_E_G_SORT = _all(
    _e64b(), _E65, _E67,
    _add("ips", _nb_ip(11, "10.0.0.5/30", (12, LEAF1, "eth2")),
         _nb_ip(12, "10.0.0.6/30", (22, SPINE1, "eth2"))),
)
_G_LINES = [
    "bgp-session leaf9 -> 10.0.9.2: device leaf9 is excluded",
    "cable leaf1:eth2 <-> spine1:eth2: status planned is not connected",
    "cable leaf9:eth1 <-> spine1:eth3: device leaf9 is excluded",
    "device leaf9: status decommissioning is not active",
    "ip-address leaf1:eth1 172.16.0.1/24: in VRF mgmt; the importer models the global table only",
    "ip-address leaf1:eth2 10.0.0.5/30: " + _NO_LINK,
    "ip-address leaf9:eth1 10.0.9.1/30: device leaf9 is excluded",
    "ip-address spine1:eth2 10.0.0.6/30: " + _NO_LINK,
    "ip-address spine1:eth3 10.0.9.2/30: " + _NO_LINK,
]
PF4_BUNDLE_CASES += [
    ("E-G-sort", _E_G_SORT, [_X + x for x in _G_LINES], 4, True),
    ("E-edge-sort", _all(_e71(), _E71B, _E71C, _e72()),
     [_L21, _X + "bgp-session siteb-spine1 -> 10.9.9.1: device siteb-spine1 is not in "
      "this site's bundle",
      _X + "cable spine1:eth4 <-> siteb-spine1:eth1: device siteb-spine1 is not in this "
      "site's bundle",
      _X + "ip-address siteb-spine1:eth1 10.9.9.2/30: device siteb-spine1 is not in this "
      "site's bundle",
      _X + "ip-address spine1:eth4 10.9.9.1/30: " + _NO_LINK], 4, True),
]


def _dump_block(out, n, m, k):
    return [x.replace("backend: netbox)", "backend: netbox-dump)") for x in _block(out, n, m, k)]


def _golden_equal(out):
    for rel in ("topology.yaml", os.path.join("tests", "starter_invariants.yaml")):
        with open(os.path.join(out, rel), "rb") as f, \
                open(os.path.join(GOLDEN_SITEA, rel), "rb") as g:
            if f.read() != g.read():
                return False
    return True


def _node(topo, name):
    for n in topo.get("nodes") or []:
        if n.get("name") == name:
            return n
    return None


def pf4_bundle_exclusions():
    """PF-4, dump reader (REQ-46-19, -21, -25, -27, -43 to -45, -64 to -68,
    -71, -72): exit 0; the exact block and exclusion lines, sorted; the pair
    equals golden/siteA where the case adds nothing in scope. The page legs
    land with stage 6 (handover §0.5)."""
    for case, mutate, lines, n, golden in PF4_BUNDLE_CASES:
        r, scratch, src, out = _bundle_case(mutate)
        try:
            want = _dump_block(out, n, 1, len(lines)) + lines
            _rec("PF-4 " + case + " exit 0, block and exclusion lines exact "
                 "(REQ-46-25, -27)",
                 r.returncode == 0 and r.stdout.splitlines() == want,
                 "rc=%d out=%s err=%s" % (r.returncode, r.stdout[-400:], r.stderr.strip()[:300]))
            if r.returncode != 0:
                continue
            if golden:
                _rec("PF-4 " + case + " pair equals golden/siteA (nothing excluded "
                     "reaches the pair)", _golden_equal(out))
            topo, starter = _load_pair(out)
            if case == "E-64b":
                names = [t.get("name") for t in topo.get("tests") or []]
                _rec("PF-4 E-64b no node, link, session or starter check for leaf9 "
                     "(REQ-46-64)",
                     _node(topo, "leaf9") is None
                     and not any("leaf9" in e for k in topo.get("links") or []
                                 for e in k.get("endpoints"))
                     and not any("leaf9" in str(x) for x in names), str(names))
            if case == "E-AP6":
                leaf2 = _node(topo, "leaf2") or {}
                _rec("PF-4 E-AP6 leaf2 a node without asn, router_id or bgp (AP-6, R-3)",
                     leaf2.get("name") == "leaf2"
                     and not set(leaf2) & {"asn", "router_id", "bgp"}, str(leaf2))
            if case == "E-AP7":
                _rec("PF-4 E-AP7 leaf1's asn stays 65001 (AP-7)",
                     (_node(topo, "leaf1") or {}).get("asn") == 65001)
            if case == "E-sort":
                _rec("PF-4 E-sort output equals the §19.0b walkthrough",
                     r.stdout.replace(out, "/tmp/e-out").splitlines()
                     == E_SORT_WALKTHROUGH.splitlines())
            if case == "E-G-sort":
                _rec("PF-4 E-G-sort output equals the §19.1b walkthrough",
                     r.stdout.replace(out, "/tmp/g-out").splitlines()
                     == G_SORT_WALKTHROUGH.splitlines())
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    # E-72's negative leg: the remote-address object present in, or absent
    # from, ipam/ip-addresses gives the same pair and the same line (REQ-46-72).
    pairs = []
    for ra_id in (777, 1):
        r, scratch, src, out = _bundle_case(_e72(ra_id))
        try:
            pairs.append((r.returncode, r.stdout.replace(out, "<out>"),
                          open(os.path.join(out, "topology.yaml"), "rb").read()
                          if r.returncode == 0 else b""))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    _rec("PF-4 E-72 the reader opens no lookup: same pair and line either way "
         "(REQ-46-72)", pairs[0] == pairs[1] and pairs[0][0] == 0)


E_SORT_WALKTHROUGH = """\
✅ IMPORT OK (authoritative input; backend: netbox-dump): wrote /tmp/e-out/topology.yaml
   starter invariants (6): embedded in topology.yaml, copied to /tmp/e-out/tests/starter_invariants.yaml
   set aside, need device configuration (1): /tmp/e-out/tests/starter_invariants.yaml
   excluded by filter (5)
   excluded: bgp-session leaf1 -> 10.0.1.2: non-adjacent peer: 10.0.1.2 is an address of link spine1:eth2<->spine2:eth1, which leaf1 is not on; a generated lab configures a neighbour only over the node's own links
   excluded: bgp-session leaf1 -> 198.51.100.1: peer outside the declared topology: 198.51.100.1 lies outside every declared link's subnet
   excluded: bgp-session leaf1 -> 198.51.100.7: status planned is not active
   excluded: cable leaf1:eth3 <-> circuits.circuittermination CID-1001 A: termination circuits.circuittermination is not an interface; links connect interfaces
   excluded: ip-address leaf1:eth1 2001:db8::1/64: IPv6 address; the importer reads IPv4 link addresses only
"""
G_SORT_WALKTHROUGH = """\
✅ IMPORT OK (authoritative input; backend: netbox-dump): wrote /tmp/g-out/topology.yaml
   starter invariants (4): embedded in topology.yaml, copied to /tmp/g-out/tests/starter_invariants.yaml
   set aside, need device configuration (1): /tmp/g-out/tests/starter_invariants.yaml
   excluded by filter (9)
""" + "".join("   excluded: " + x + "\n" for x in _G_LINES)


_MANIFEST_KEYS = ["endpoints", "format", "netbox_version", "plugins", "schema", "site"]
_PROVEN = "the proven set is NetBox 4.6.8 with netbox-bgp 0.19.0"
_CASSIAN = ["allowed:", "checks only that a declared route is present"]
_DEV, _CAB, _IPS, _SES, _MAN = ("dcim_devices.json", "dcim_cables.json",
                                "ipam_ip_addresses.json", "plugins_bgp_session.json",
                                "manifest.json")


def _iface_name_ip(name):
    """The address's assigned interface carries the cable's interface ID
    under another name (REQ-46-40, N-40b)."""
    def m(b):
        b["ips"][0]["assigned_object"]["name"] = name
    return m



def _two_iface_eth1(b):
    b["ips"][0]["assigned_object"]["id"] = 12
    b["ips"][0]["assigned_object_id"] = 12


def _iface_name(name):
    def m(b):
        b["cables"][0]["a_terminations"][0]["object"]["name"] = name
        b["ips"][0]["assigned_object"]["name"] = name
    return m


# (case, mutation, needles, the file the rejection names). Every case also
# needs 're-run' and an empty --out (handover §15.1).
PF2_BUNDLE_CASES = [
    ("N-36", _at(("manifest",), None), [_MAN] + _MANIFEST_KEYS, _MAN),
    ("N-37a", _at(("manifest", "extra"), 1), [_PROVEN], _MAN),
    ("N-37b", _at(("manifest", "format"), 2), [_PROVEN], _MAN),
    ("N-37c", _at(("manifest", "netbox_version"), "4.7.0"), [_PROVEN], _MAN),
    ("N-37d", _at(("manifest", "plugins", "netbox_bgp"), "0.18.0"), [_PROVEN], _MAN),
    ("N-37e", _at(("manifest", "plugins", "netbox_ospf"), "1.0.0"), [_PROVEN], _MAN),
    ("N-38a", _at(("cables",), None), [], _CAB),
    ("N-38b", _at(("cables",), "{not json"), [], _CAB),
    ("N-38c", _at(("cables",), "{}"), [], _CAB),
    ("N-40a", _at(("devices", 1, "id"), 1), ["object id", "'id'"], _DEV),
    ("N-40b", _iface_name_ip("eth2"), ["object id", "interface id 11"], _IPS),
    ("N-40c", _at(("devices", 0, "local_context_data"), _DROP),
     ["object id", "'local_context_data'"], _DEV),
    ("N-40d", _at(("devices", 0, "local_context_data"), "x"),
     ["object id", "'local_context_data'"], _DEV),
    ("N-41a", _at(("devices", 1, "name"), "leaf1"), ["object id", "device name 'leaf1'"], _DEV),
    ("N-41b", _two_iface_eth1, ["object id", "two interfaces named eth1"], _IPS),
    ("N-42a", _at(("devices", 0, "platform"), None), ["platform", "unsupported"], _DEV),
    ("N-42b", _at(("devices", 0, "platform", "slug"), "eos"), ["platform", "unsupported"], _DEV),
    ("N-43", lambda b: b["cables"][0]["a_terminations"].append(
        _nb_term(_nb_iface(12, LEAF1, "eth2"))), ["object id", "2 terminations"], _CAB),
    ("N-44", _add("ips", _nb_ip(3, "10.0.0.5/30", (11, LEAF1, "eth1"))),
     ["object id", "two addresses"], _IPS),
    ("N-45a", _at(("sessions", 0, "device"), None), ["object id", "'device' is missing"], _SES),
    ("N-45b", _at(("sessions", 0, "remote_address"), None),
     ["object id", "'remote_address' is missing"], _SES),
    ("N-45c", _add("sessions", _nb_session(3, LEAF1, "198.51.100.1/32", 65099, 65010)),
     ["object id", "local_as 65099 disagrees"], _SES),
    ("N-46a", _at(("devices", 0, "local_context_data", "cassian", "next_hops"), []),
     _CASSIAN, _DEV),
    ("N-46b", _at(("devices", 0, "local_context_data", "cassian", "static_routes", 0,
                   "next_hop"), "10.0.0.2"), _CASSIAN, _DEV),
    ("N-46c", _at(("devices", 0, "local_context_data", "cassian", "static_routes", 0), {}),
     ["object id", "'prefix' is missing"], _DEV),
    ("N-46d", lambda b: b["devices"][0]["local_context_data"]["cassian"]["static_routes"]
     .append({"prefix": "192.0.2.0/24"}), ["object id", "more than once"], _DEV),
    ("N-47a", _at(("devices", 0, "rack_face"), "front"), ["object id", "unknown key 'rack_face'"],
     _DEV),
    ("N-47b", _at(("devices", 0, "platform", "color"), "red"),
     ["object id", "unknown key 'platform.color'"], _DEV),
    ("N-50a", _at(("devices",), []), ["'devices' must be a non-empty list"], _DEV),
    ("N-50b", _all(_at(("devices", 0, "status"), _nb_status("offline")),
                   _at(("devices", 1, "status"), _nb_status("offline"))),
     ["no device is in service after the filter", "leaf1"], _DEV),
    ("N-51", _at(("devices", 1, "site", "slug"), "siteB"), ["siteB", "siteA"], _DEV),
    ("N-68c", _all(_at(("devices", 1, "status"), _nb_status("planned")),
                   _at(("devices", 1, "rack_face"), "front")),
     ["object id", "unknown key 'rack_face'"], _DEV),
    ("N-70a", _at(("ips", 0, "status"), _nb_status("deprecated")),
     ["the filter excluded the address 10.0.0.1/30", "deprecated"], _CAB),
    ("N-70b", _at(("ips", 0, "vrf"), {"description": "", "display": "mgmt", "id": 1,
                                      "name": "mgmt", "rd": None, "url": _NB}),
     ["the filter excluded the address 10.0.0.1/30", "VRF"], _CAB),
    # 46-S8-R1 and 46-S8-R3 (session-8 rulings notes 1 and 2): an interface
    # object (by its type field) that is null or absent is rejected at load.
    ("46-S8-R1a", _at(("cables", 0, "a_terminations", 0, "object"), None),
     ["object id", "'a_terminations[0].object' must be an object",
      "Re-capture at the proven versions"], _CAB),
    ("46-S8-R1b", _at(("ips", 0, "assigned_object"), None),
     ["object id", "'assigned_object' must be an object",
      "Re-capture at the proven versions"], _IPS),
    ("46-S8-R3", _at(("cables", 0, "a_terminations", 0, "object"), _DROP),
     ["object id", "'a_terminations[0].object' must be an object",
      "Re-capture at the proven versions"], _CAB),
    # The shared path through the reader (R-n): N-n's needles, locator 'object id'.
    ("R-1", _at(("sessions", 0, "remote_address", "address"), "not-an-address"),
     ["object id", "not an IPv4 address"], _SES),
    ("R-2", _at(("devices", 0, "local_context_data", "cassian", "static_routes", 0, "prefix"), ""),
     ["object id", "'prefix' is missing"], _DEV),
    ("R-5", lambda b: b["ips"].pop(1), ["object id", "without the other"], _CAB),
    ("R-6", _at(("ips", 1, "address"), "10.0.1.2/30"),
     ["object id", "not two distinct addresses of one IPv4 subnet"], _CAB),
    ("R-9", _add("sessions", _nb_session(3, LEAF1, "10.0.0.2/30", 65001, 65002)),
     ["more than once"], _SES),
    ("R-10", _iface_name("Gi0/0/1"), ["object id", "not a valid Linux interface name"], _CAB),
    ("R-11", _at(("devices", 0, "local_context_data", "cassian", "static_routes", 0, "prefix"),
                 "192.0.2.1/24"), ["object id", "no host bits set"], _DEV),
    ("R-12", _at(("ips", 0, "address"), "10.0.0.1"),
     ["object id", "not an IPv4 interface address"], _CAB),
    # Ruling 1 (rev 5 §10.1) through the reader: a padded interface name of a
    # kept cable or address (RP-2), cassian route prefix (RP-4) or kept link
    # address (RP-6), each rejected with its REQ text, as written.
    ("RP-2a", _iface_name("eth1 "),
     ["object id", "interface name 'eth1 ' is not a valid Linux interface name"], _CAB),
    ("RP-2b", _at(("cables", 0, "a_terminations", 0, "object", "name"), "eth1 "),
     ["object id", "interface name 'eth1 ' is not a valid Linux interface name"], _CAB),
    ("RP-2c", _at(("ips", 0, "assigned_object", "name"), "eth1 "),
     ["object id", "interface name 'eth1 ' is not a valid Linux interface name"], _IPS),
    ("RP-4", _at(("devices", 0, "local_context_data", "cassian", "static_routes", 0, "prefix"),
                 " 192.0.2.0/24"),
     ["object id", "prefix ' 192.0.2.0/24' is not an IPv4 network with no host bits set"],
     _DEV),
    ("RP-6", _at(("ips", 0, "address"), "10.0.0.1/30 "),
     ["object id", "'10.0.0.1/30 ' is not an IPv4 interface address"], _CAB),
    ("R-16", _all(_spine2(), _add("cables", _nb_cable(2, (12, LEAF1, "eth2"), (31, SPINE2, "eth1"))),
                  _add("ips", _nb_ip(3, "10.0.0.1/30", (12, LEAF1, "eth2")),
                       _nb_ip(4, "10.0.0.2/30", (31, SPINE2, "eth1")))),
     ["object id", "far-end address of more than one"], _SES),
    ("R-17", _all(_add("cables", _nb_cable(2, (12, LEAF1, "eth2"), (22, SPINE1, "eth2"))),
                  _add("ips", _nb_ip(3, "10.0.0.5/30", (12, LEAF1, "eth2")),
                       _nb_ip(4, "10.0.0.6/30", (22, SPINE1, "eth2")))),
     ["object id", "more than one link"], _SES),
    ("R-18", _at(("sessions", 0, "remote_address", "address"), "10.0.0.1/30"),
     ["object id", "is not its far-end address"], _SES),
    ("R-20", _all(_spine2(), _add("cables", _nb_cable(2, (22, SPINE1, "eth2"), (31, SPINE2, "eth1"))),
                  _add("ips", _nb_ip(3, "10.0.1.1/29", (22, SPINE1, "eth2")),
                       _nb_ip(4, "10.0.1.2/29", (31, SPINE2, "eth1"))),
                  _add("sessions", _nb_session(3, LEAF1, "10.0.1.3/29", 65001, 65003))),
     ["object id", "neither of its addresses"], _SES),
    ("R-22", _all(_spine2(),
                  _add("devices", _nb_device(4, "spine3", lcd={"cassian": {"router_id": "4.4.4.4"}})),
                  _add("cables", _nb_cable(2, (31, SPINE2, "eth1"), (41, SPINE3, "eth1"))),
                  _add("ips", _nb_ip(3, "10.0.0.2/30", (31, SPINE2, "eth1")),
                       _nb_ip(4, "10.0.0.1/30", (41, SPINE3, "eth1")))),
     ["object id", "in different ways"], _SES),
    ("R-23", _at(("sessions", 0, "remote_as"), None), ["object id", "'remote_asn' is required"],
     _SES),
    ("R-24a", _at(("devices", 0, "local_context_data", "cassian", "router_id"), _DROP),
     ["object id", "has a BGP session but no 'router_id'"], _DEV),
    ("REQ-46-39 primary_ip4", _all(
        _at(("devices", 0, "local_context_data", "cassian", "router_id"), _DROP),
        _at(("devices", 0, "primary_ip4"), {"address": "1.1.1.1/32", "id": 50})),
     ["object id", "no 'router_id'"], _DEV),
]


def pf2_bundle_rejections():
    """PF-2, dump reader (REQ-46-36 to -51, -68, -70, and the shared path's
    rejections through the reader): exit 2, the file, the needles and
    're-run' named, nothing written."""
    cases = [(c, m, n, f, "netbox-dump", None) for c, m, n, f in PF2_BUNDLE_CASES] + [
        ("N-49a", None, ["netbox_export.json", "manifest.json",
                         "found no manifest.json here, and netbox_export.json is present"],
         "", "netbox-dump", POS),
        ("N-49b", None, ["netbox_export.json", "manifest.json",
                         "found no netbox_export.json here, and manifest.json is present"],
         "", "netbox", BUNDLE_A),
    ]
    for case, mutate, needles, file, backend, source in cases:
        r, scratch, src, out = _bundle_case(mutate, backend=backend, source=source)
        try:
            msg = r.stderr
            missing = [x for x in needles + [file, "re-run"] if x not in msg]
            written = _files_under(out)
            _rec("PF-2 " + case + " rejected at exit 2, named, nothing written",
                 r.returncode == 2 and not missing and not written,
                 "rc=%d missing=%s written=%d msg=%s"
                 % (r.returncode, missing, len(written), (msg.strip() or r.stdout)[:300]))
            if case == "N-37c":
                want = N37C_WALKTHROUGH.replace("<bundle>", src)
                _rec("PF-2 N-37c message equals the §19.2 walkthrough", msg.strip() == want,
                     msg.strip()[:240])
            if case == "N-70a":
                want = N70A_WALKTHROUGH.replace("<bundle>", src)
                _rec("PF-2 N-70a message equals the §19.2 walkthrough", msg.strip() == want,
                     msg.strip()[:300])
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    # N-68a and N-68b: a filtered object escapes the later checks (exit 0).
    for case, mutate, line in (
        ("N-68a", _all(_add("devices", _nb_device(3, "leaf3", status="planned")),
                       _at(("devices", 2, "platform", "slug"), "eos")),
         _X + "device leaf3: status planned is not active"),
        ("N-68b", _all(_E45, _at(("sessions", 2, "remote_address"), None)),
         _X + "bgp-session leaf1 -> -: status planned is not active"),
    ):
        r, scratch, src, out = _bundle_case(mutate)
        try:
            _rec("PF-2 " + case + " a filtered object takes no part in later checks, "
                 "exit 0 (REQ-46-68)",
                 r.returncode == 0 and r.stdout.splitlines()[-1:] == [line],
                 "rc=%d out=%s err=%s" % (r.returncode, r.stdout[-200:], r.stderr[:200]))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


N37C_WALKTHROUGH = (
    "ERROR: Invalid NetBox import: <bundle>/manifest.json: manifest: netbox_version "
    "'4.7.0' is not in the proven set; the proven set is NetBox 4.6.8 with netbox-bgp "
    "0.19.0. Capture the export at the proven versions and re-run."
)
N70A_WALKTHROUGH = (
    "ERROR: Invalid NetBox import: <bundle>/dcim_cables.json: dcim/cables object id 1 "
    "(leaf1:eth1<->spine1:eth1): the filter excluded the address 10.0.0.1/30 on "
    "leaf1:eth1 (status deprecated is not active), so the link keeps one address; a link "
    "needs both addresses or neither. Bring both addresses into service in the global "
    "table, or neither and re-run."
)


def _permuted(b):
    """REQ-46-52: every endpoint list reversed, every ID shifted by 1000
    consistently, every created/last_updated changed, every URL's host changed."""
    def walk(node):
        if isinstance(node, dict):
            for k, v in list(node.items()):
                if k in ("id", "object_id", "assigned_object_id") and type(v) is int:
                    node[k] = v + 1000
                elif k in ("created", "last_updated"):
                    node[k] = "2030-01-01T00:00:00.000000Z"
                elif k in ("url", "display_url") and isinstance(v, str):
                    node[k] = v.replace("netbox.example.test", "other.example.test")
                else:
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    for key in ("devices", "cables", "ips", "sessions"):
        b[key].reverse()
        walk(b[key])


_SENTINELS = ("sentinel-host.invalid", "987654321", "1999-12-31T23:59:59.424242Z",
              "SENTINEL-FREEFORM")


def _sentinels(b):
    """PF-3: sentinels in the URLs, an ID, the timestamps and a free-form field."""
    def walk(node):
        if isinstance(node, dict):
            for k, v in list(node.items()):
                if k in ("url", "display_url") and isinstance(v, str):
                    node[k] = v.replace("netbox.example.test", _SENTINELS[0])
                elif k in ("created", "last_updated"):
                    node[k] = _SENTINELS[2]
                elif k == "id" and v == 1 and node.get("name") == "leaf1":
                    node[k] = int(_SENTINELS[1])
                else:
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    for key in ("devices", "cables", "ips", "sessions"):
        walk(b[key])
    b["devices"][0]["custom_fields"] = {"note": _SENTINELS[3], "nested": {"deep": {"x": 1}}}
    b["devices"][0]["comments"] = _SENTINELS[3]


def pf1_pf3_bundle():
    """PF-1 (REQ-46-35 to -54 positives; P-7) and PF-3 (REQ-46-53) on bundleA."""
    for case, mutate, rendered in (
        ("bundleA", None, False),
        ("bundleA with rendered/ (P-7)", None, True),
        ("bundleA permuted: lists reversed, IDs +1000, timestamps and URL hosts "
         "changed (REQ-46-52)", _permuted, False),
        ("bundleA with local_context_data.other_tool (REQ-46-46, not inspected)",
         _at(("devices", 0, "local_context_data", "other_tool"), {"x": {"y": 1}}), False),
        ("bundleA with a planted object in custom_fields (REQ-46-47, not inspected)",
         _at(("devices", 0, "custom_fields"), {"x": {"unknown": {"deep": 1}}}), False),
    ):
        r, scratch, src, out = _bundle_case(mutate, rendered=rendered)
        try:
            ok = r.returncode == 0 and _golden_equal(out)
            if case == "bundleA":
                ok = ok and r.stdout.splitlines() == _dump_block(out, 4, 1, 0)
            _rec("PF-1 " + case + ": exit 0, pair equals golden/siteA (REQ-46-39)", ok,
                 "rc=%d err=%s" % (r.returncode, r.stderr.strip()[:300]))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    try:
        topo, _invs = produce_pair(BUNDLE_A, backend="netbox-dump")
        _validate_emitted_pair(topo)
        ensure_valid_topology(topo)
        resolve_topology(topo)
        _rec("PF-1 the reader's pair passes the model (REQ-46-54)", True)
    except SystemExit as exc:
        _rec("PF-1 the reader's pair passes the model (REQ-46-54)", False, str(exc))
    r, scratch, src, out = _bundle_case(_sentinels)
    try:
        text = "".join(open(p, encoding="utf-8").read() for p in sorted(_files_under(out)))
        found = [s for s in _SENTINELS if s in text]
        _rec("PF-3 no URL, ID, timestamp or free-form sentinel in either output file "
             "(REQ-46-53)", r.returncode == 0 and len(_files_under(out)) == 2 and not found,
             "rc=%d found=%s err=%s" % (r.returncode, found, r.stderr[:200]))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    def renamed(b):
        for key in ("devices", "cables", "ips", "sessions"):
            b[key] = _json.loads(_json.dumps(b[key]).replace('"leaf1"', '"sentinel9"'))
    r, scratch, src, out = _bundle_case(renamed)
    try:
        text = "".join(open(p, encoding="utf-8").read() for p in sorted(_files_under(out)))
        _rec("PF-3 self-test: a sentinel in a read field (a device name) is found",
             r.returncode == 0 and "sentinel9" in text, "rc=%d" % r.returncode)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def pf2_bundle_locators():
    """46-S5-R1 (REQ-46-13): a reader rejection names its bundle object as
    ``<endpoint> object id <id> (<name>)``, <name> being §6.1's object text
    built from names; a session's NetBox name is not printed."""
    for case, mutate, want in (
        ("a device", _at(("devices", 1, "site", "slug"), "siteB"),
         "dcim_devices.json: dcim/devices object id 2 (spine1): "),
        ("a cable", _at(("ips", 0, "status"), _nb_status("deprecated")),
         "dcim_cables.json: dcim/cables object id 1 (leaf1:eth1<->spine1:eth1): "),
        ("an IP address", _add("ips", _nb_ip(3, "10.0.0.5/30", (11, LEAF1, "eth1"))),
         "ipam_ip_addresses.json: ipam/ip-addresses object id 3 (leaf1:eth1 10.0.0.5/30): "),
        ("a session, a part missing", _at(("sessions", 0, "remote_address"), None),
         "plugins_bgp_session.json: plugins/bgp/session object id 1 (leaf1 -> -): "),
        ("a session through the shared path", _at(("sessions", 0, "remote_as"), None),
         "plugins_bgp_session.json: plugins/bgp/session object id 1 (leaf1 -> 10.0.0.2): "),
    ):
        r, scratch, src, out = _bundle_case(mutate)
        try:
            _rec("PF-2 locator of " + case + " rejection per 46-S5-R1 (REQ-46-13)",
                 r.returncode == 2 and want in r.stderr and "leaf1 session" not in r.stderr,
                 "rc=%d %s" % (r.returncode, r.stderr.strip()[:240]))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


# --------------------------------------------------------------------------- #
# §4.6 stage 5 piece (iii): PF-8 (handover REQ-46-55; scope §5 C; P-7) and    #
# PF-11's seeded leg (REQ-46-29, B-29), lab-free and offline. The reader takes#
# the committed seeded export (capture 1, scope 3.10.6) with and without a    #
# rendered/ copy; its pair equals golden/netbox-seeded/, generated from the   #
# reader on that export and checked, before it was committed, against the     #
# reader's pair from capture 2 (C-15; REQ-46-33's negative leg; REQ-46-52).   #
# The golden is never regenerated to turn PF-8 green.                         #
# --------------------------------------------------------------------------- #
GOLDEN_SEEDED = os.path.join(FIX, "golden", "netbox-seeded")
_PROVEN_VERSIONS = ("4.6.8", {"netbox_bgp": "0.19.0"})


def _pair_equals(out, golden):
    """True when both files of out's pair equal golden's, byte for byte."""
    for rel in ("topology.yaml", os.path.join("tests", "starter_invariants.yaml")):
        got = os.path.join(out, rel)
        if not os.path.isfile(got):
            return False
        with open(got, "rb") as f, open(os.path.join(golden, rel), "rb") as g:
            if f.read() != g.read():
                return False
    return True


def pf8_seeded_export():
    """PF-8 (REQ-46-55): the reader accepts the committed seeded export, with
    and without a rendered/ copy (P-7); its pair equals golden/netbox-seeded/;
    and the export's manifest names the proven set (REQ-46-37)."""
    for case, rendered in (("the seeded export", False),
                           ("the seeded export with rendered/ (P-7)", True)):
        r, scratch, src, out = _bundle_case(rendered=rendered, source=SEEDED)
        try:
            _rec("PF-8 " + case + ": exit 0, pair equals golden/netbox-seeded "
                 "(REQ-46-55)",
                 r.returncode == 0 and _pair_equals(out, GOLDEN_SEEDED),
                 "rc=%d err=%s" % (r.returncode, r.stderr.strip()[:300]))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    with open(os.path.join(SEEDED, "manifest.json"), encoding="utf-8") as f:
        manifest = _json.load(f)
    got = (manifest.get("netbox_version"), manifest.get("plugins"))
    _rec("PF-8 the seeded export's manifest names the proven set: NetBox 4.6.8 "
         "with netbox-bgp 0.19.0 (REQ-46-55, -37)",
         got == _PROVEN_VERSIONS, "netbox_version=%r plugins=%r" % got)


def _pf11_seeded_triples(stdout):
    """(L, X, AS) of each active session in the seeded export's sessions file,
    read from the file itself, less those the import names as excluded: the
    sessions the import resolves (B-29)."""
    with open(os.path.join(SEEDED, "plugins_bgp_session.json"), encoding="utf-8") as f:
        sessions = _json.load(f)
    excluded = set()
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("excluded: bgp-session "):
            local, _, rest = line[len("excluded: bgp-session "):].partition(" -> ")
            excluded.add((local, rest.split(": ", 1)[0]))
    triples = []
    for s in sessions:
        if (s.get("status") or {}).get("value") != "active":
            continue
        local = (s.get("device") or {}).get("name")
        x = ((s.get("remote_address") or {}).get("address") or "").split("/")[0]
        if (local, x) not in excluded:
            triples.append((local, x, (s.get("remote_as") or {}).get("asn")))
    return sorted(triples)


def pf11_render_seeded():
    """PF-11, seeded leg (REQ-46-29): import the committed seeded export,
    render each node of a resolved session through gen_frr_conf, and find
    every session's line."""
    scratch = tempfile.mkdtemp(prefix="pf11s_")
    try:
        out = os.path.join(scratch, "out")
        r = subprocess.run(
            [sys.executable, "-c",
             "import sys;sys.path.insert(0,%r);"
             "from cassian_import import run_import;"
             "run_import(%r,%r,backend='netbox-dump')" % (_SRC, SEEDED, out)],
            capture_output=True, text=True,
        )
        triples = _pf11_seeded_triples(r.stdout)
        missing = (_pf11_missing(os.path.join(out, "topology.yaml"), triples)
                   if r.returncode == 0 else triples)
        _rec("PF-11 the seeded export: each resolved session renders ' neighbor "
             "<X> remote-as <AS>' through gen_frr_conf (REQ-46-29)",
             r.returncode == 0 and len(triples) == 4 and not missing,
             "rc=%d n=%d missing=%s err=%s" % (r.returncode, len(triples), missing,
                                              r.stderr.strip()[:200]))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# --------------------------------------------------------------------------- #
# §4.6 stage 6: PF-4's page legs and REQ-46-25's docs leg (handover §0.5,     #
# D2-5; §15.2). The PF-4 legs above hold each exclusion line to the code's    #
# output; these hold the importer page's exclusion table to those lines.      #
# --------------------------------------------------------------------------- #
import re as _re  # noqa: E402

IMPORTER_PAGE = os.path.join(_ROOT, "docs", "brownfield-importer.md")
_PAGE_KINDS = ("bgp-session", "cable", "device", "ip-address")


def _page_reasons(text):
    """The importer page's exclusion table: (kind, reason) per row, in page
    order. A row is a four-cell table line whose first cell is a backticked
    kind and whose last cell is a Req-ID; its reason is the first backticked
    text of the third cell."""
    rows = []
    for line in text.splitlines():
        cells = [c.strip() for c in line.split("|")]
        if len(cells) != 6 or not cells[1].startswith("`") \
                or not cells[4].startswith("REQ-46-"):
            continue
        kind = cells[1].strip("`")
        if kind not in _PAGE_KINDS:
            continue
        m = _re.search(r"`([^`]+)`", cells[3])
        if m:
            rows.append((kind, m.group(1)))
    return rows


def _reason_fits(template, reason):
    """A page reason with its <...> parts filled equals the printed reason."""
    pattern = _re.sub(r"<[^<>]+>", ".+", _re.escape(template))
    return _re.fullmatch(pattern, reason) is not None


def _line_kind_reason(line):
    """'   excluded: <kind> <object>: <reason>' -> (kind, reason)."""
    body = line[len(_X):] if line.startswith(_X) else line
    kind, rest = body.split(" ", 1)
    return kind, rest.split(": ", 1)[1]


def pf4_page_and_docs_legs():
    """PF-4's page legs (REQ-46-25, -59; D2-5): for every PF-4 case, the
    importer page's exclusion table holds each printed line's kind and reason.
    REQ-46-25's docs leg (§15.2): every reason the page states is one the code
    prints in a PF-4 case, so a reason the page and the code disagree on fails
    one side or the other."""
    with open(IMPORTER_PAGE, encoding="utf-8") as f:
        rows = _page_reasons(f.read())
    cases = [("netbox " + c, [line]) for c, _m, _x, line, _n in PF4_CASES] + [
        ("netbox-dump " + c, lines) for c, _m, lines, _n, _g in PF4_BUNDLE_CASES]
    used = set()
    for case, lines in cases:
        if not lines:
            continue
        missing = []
        for line in lines:
            kind, reason = _line_kind_reason(line)
            hit = [i for i, (k, t) in enumerate(rows)
                   if k == kind and _reason_fits(t, reason)]
            used.update(hit)
            if not hit:
                missing.append(line.strip()[:120])
        _rec("PF-4 page, " + case + ": the importer page names each line's kind "
             "and reason (REQ-46-25, -59)", not missing, "missing=%s" % missing)
    unused = [rows[i] for i in range(len(rows)) if i not in used]
    _rec("REQ-46-25 docs leg: every reason on the importer page is one the code "
         "prints (%d rows)" % len(rows), bool(rows) and not unused, "unused=%s" % unused)


def main():
    po1_determinism()
    po2_roundtrip()
    po3_rejection()
    po4_boundedness()
    pf2_contract_rejections()
    pf4_contract_exclusions()
    pf5_golden_and_positives()
    pf11_render_site_a()
    pf10_key_lists()
    pf1_pf3_bundle()
    pf2_bundle_rejections()
    pf2_bundle_locators()
    pf4_bundle_exclusions()
    pf4_page_and_docs_legs()
    pf8_seeded_export()
    pf11_render_seeded()
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
