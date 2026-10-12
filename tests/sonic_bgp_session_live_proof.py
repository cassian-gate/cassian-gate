#!/usr/bin/env python3
"""Row-15 live proof: one declared FRR<->SONiC eBGP session (§4.5-d VM-1; scope §9 row 15).

One fixture, one boot (scope §2.1 rev 6; LD-45D-6): topologies/sonic-bgp-session-live.yaml.
Every converted live assertion rides the one declared session, in the handover's order
(§8 B04, B05), each through its Req's own path -- `cassian test --name <declared test>`
or `cassian status` -- never through a read this file makes itself:

  L1  REQ-45D-8  (B04)  row15_session_up on s1 toward r1: verdict pass, state Established.
                        ASSERTED FIRST. If it does not pass, L2-L6 are NOT ATTEMPTED and the
                        failure is a NEW finding against the rendering -- never folded into
                        BL-P2-4.5c-48, whose R1 says rendering works (scope §2.1).
  L2  REQ-45D-1  (B05)  row15_bgp_neighbor: observed up toward the declared peer.
  L3  REQ-45D-16 (B05)  row15_as_path: r1's declared network received on s1 with AS path
                        exactly r1's ASN.
  L4  REQ-45D-19 (B05)  founder ruling S29-R5 (2026-10-12), amending S29-R2 forward:
                        (i)   `cassian status --bgp --json`: s1's bgp record has parser_mode
                              json, no error, and the declared peer in `observed`;
                        (ii)  `cassian status --bgp`: s1's BGP line prints, without an error;
                        (iii) `cassian status --bgp --bgp-verbose`: s1's `show bgp summary`
                              block, fetched by SONiC's status leg, parsed with the provider's
                              own text parser, shows the declared peer established.
  L5  §15.2 -16 negative: row15_as_path_unadvertised (expect: fail) on a prefix nobody
                        advertises -- route absent, observed fail, verdict pass.
  L6  §15.2 -8 negative: r1's neighbour removed through the product's container runtime,
                        then scenario row15_neighbour_removed (expect: fail) -- the session
                        on s1 must not read Established. `--scenario` skips the global BGP
                        precheck, which would otherwise stop `cassian test` before the test.

Lab-free legs (always run):
  F   the fixture's shape, derived values only; the fixture validates.
  NV  REQ-45D-31 two-directional non-vacuity, per predicate this file applies to the
      product's output: a synthetic COMPLETE observation satisfies it, and a mutation in
      each direction -- too much (an extra or wrong item in place of the declared one) and
      too little (the declared item withheld or not established) -- is DETECTED. The
      control's subject is synthetic, so it is independent of device state
      (BL-P2-4.5c-169).

usage:
  sonic_bgp_session_live_proof.py                    lab-free legs; L1-L6 BLOCKED; exit 0 if green
  sonic_bgp_session_live_proof.py live <topo> <lab>  lab-free legs, then L1-L6 on a lab already up

Coverage limits, stated in-file (PBE-P2-8):
  - One boot of one fixture. A session that comes up here proves the shipped image and
    overlay can establish this declared session, not every declaration.
  - L6 mutates r1's running configuration; the lab is torn down after this file runs.
  - L5's control rests on L3 having read the same guest table on the same boot; an empty
    or failed read would also yield route_present False, which is why L5 runs only after L3.
  - The neighbour-removal wait is bounded (six scenario runs, five seconds apart).

Exit 0 when every check passes (BLOCKED or NOT ATTEMPTED legs are listed); exit 1 otherwise.
"""
import json
import os
import subprocess
import sys
import time

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))

import cassian_nos_frr as F  # noqa: E402
import cassian_nos_sonic as S  # noqa: E402

FIXTURE = os.path.join(ROOT, "topologies", "sonic-bgp-session-live.yaml")
T_SESSION = "row15_session_up"
T_NEIGHBOR = "row15_bgp_neighbor"
T_ASPATH = "row15_as_path"
T_UNADV = "row15_as_path_unadvertised"
T_REMOVED = "row15_session_after_neighbour_removed"
SCENARIO = "row15_neighbour_removed"
VERBOSE_MARK = "--- show bgp summary ---"
REMOVAL_TRIES, REMOVAL_GAP_S = 6, 5

checks, blocked = [], []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))
    return bool(ok)


# ---- declared values: derived from the fixture, never carried as literals -----------------
def declared(doc):
    nodes = {n.get("name"): n for n in (doc.get("nodes") or []) if isinstance(n, dict)}
    frr = [n for n in nodes.values() if str(n.get("type")) == "frr"]
    son = [n for n in nodes.values() if str(n.get("type")) == "sonic-vm"]
    if len(frr) != 1 or len(son) != 1:
        return None
    r, s = frr[0], son[0]
    link = [l for l in (doc.get("links") or [])
            if sorted(str(e).split(":")[0] for e in l.get("endpoints") or []) == sorted([r["name"], s["name"]])]
    if len(link) != 1 or len(link[0].get("ipv4") or []) != 2:
        return None
    ips = {str(e).split(":")[0]: str(ip).split("/")[0] for e, ip in zip(link[0]["endpoints"], link[0]["ipv4"])}
    tests = {t.get("name"): t for t in (doc.get("tests") or []) if isinstance(t, dict)}
    scen = {x.get("id"): x for x in (doc.get("scenarios") or []) if isinstance(x, dict)}
    return {"r": r, "s": s, "r_name": r["name"], "s_name": s["name"], "r_asn": int(r.get("asn")),
            "s_asn": int(s.get("asn")), "r_ip": ips[r["name"]], "s_ip": ips[s["name"]],
            "prefix": str((r.get("networks") or [None])[0]), "tests": tests, "scen": scen}


def nbrs(n):
    return [(x.get("peer"), x.get("remote_as")) for x in ((n.get("bgp") or {}).get("neighbors") or [])]


# ---- predicates applied to the product's output (each one has a two-directional NV) -------
def _m(rec):
    return rec.get("meta") or {}


def session_ok(rec, node, peer):
    return (rec.get("kind") == "invariant" and _m(rec).get("type") == "bgp_session_up"
            and rec.get("from") == node and rec.get("to") == peer and rec.get("expected") == "pass"
            and rec.get("observed") == "pass" and rec.get("verdict") == "pass"
            and str(_m(rec).get("state") or "").lower() == "established")


def neighbor_ok(rec, node, peer):
    return (rec.get("kind") == "bgp_neighbor" and rec.get("from") == node and rec.get("to") == peer
            and rec.get("expected") == "up" and rec.get("observed") == "up" and rec.get("verdict") == "pass"
            and str(_m(rec).get("state") or "").lower() == "established")


def as_path_ok(rec, node, prefix, asn):
    m = _m(rec)
    return (rec.get("kind") == "invariant" and m.get("type") == "bgp_as_path" and rec.get("from") == node
            and m.get("prefix") == prefix and m.get("route_present") is True
            and str(m.get("observed_as_path")) == str(asn) and rec.get("observed") == "pass"
            and rec.get("verdict") == "pass")


def unadvertised_ok(rec, node, prefix):
    m = _m(rec)
    return (rec.get("kind") == "invariant" and m.get("type") == "bgp_as_path" and rec.get("from") == node
            and m.get("prefix") == prefix and m.get("route_present") is False and not m.get("misuse")
            and rec.get("expected") == "fail" and rec.get("observed") == "fail" and rec.get("verdict") == "pass")


def removed_ok(rec, node, peer):
    return (rec.get("kind") == "invariant" and _m(rec).get("type") == "bgp_session_up" and not _m(rec).get("misuse")
            and rec.get("from") == node and rec.get("to") == peer and rec.get("expected") == "fail"
            and rec.get("observed") == "fail" and rec.get("verdict") == "pass"
            and str(_m(rec).get("state") or "").lower() != "established")


def status_json_ok(doc, node, peer):
    rec = {n.get("name"): n for n in (doc.get("nodes") or [])}.get(node) or {}
    bgp = rec.get("bgp") or {}
    return bgp.get("parser_mode") == "json" and "error" not in bgp and peer in (bgp.get("observed") or [])


def node_block(human, node):
    """The lines of `node`'s block in cassian status's human output (`  - <node> ...` up to the next node)."""
    out, inside = [], False
    for ln in human.split("\n"):
        if ln.startswith("  - "):
            inside = ln[4:].split(" ", 1)[0] == node
            continue
        if inside:
            if not ln.startswith("      ") and ln.strip():
                inside = False
                continue
            out.append(ln)
    return out


def human_line_ok(human, node):
    blk = node_block(human, node)
    return any(ln.strip().startswith("BGP ") for ln in blk) and not any("error" in ln.lower() for ln in blk)


def verbose_text(human, node):
    blk = node_block(human, node)
    if not any(ln.strip() == VERBOSE_MARK for ln in blk):
        return None
    i = [k for k, ln in enumerate(blk) if ln.strip() == VERBOSE_MARK][0]
    return "\n".join(ln[6:] for ln in blk[i + 1:])


def verbose_established(human, node, peer):
    txt = verbose_text(human, node)
    if txt is None:
        return False
    return S._sonic_parse_bgp_summary_text(txt).get(peer, {}).get("established") is True


# ---- F: the fixture --------------------------------------------------------------------
DOC = yaml.safe_load(open(FIXTURE, encoding="utf-8").read()) or {}
D = declared(DOC)
check("F one frr node and one sonic-vm node, linked once with a /31 pair", D is not None)
if D is not None:
    r, s = D["r"], D["s"]
    check("F each side declares the other, with the other's ASN as remote_as",
          nbrs(r) == [(D["s_name"], D["s_asn"])] and nbrs(s) == [(D["r_name"], D["r_asn"])],
          "r1 %s, s1 %s" % (nbrs(r), nbrs(s)))
    check("F only the FRR node declares networks (SONiC networks are -48 R2); one prefix",
          len(r.get("networks") or []) == 1 and not s.get("networks"), "r networks %s" % r.get("networks"))
    check("F the sonic-vm node runs as vm (one guest; single-SONiC-node ceiling)", s.get("runtime") == "vm")
    t = D["tests"]
    want = [T_SESSION, T_NEIGHBOR, T_ASPATH, T_UNADV, T_REMOVED]
    check("F the five declared tests, in the handover's order", list(t) == want, "%s" % list(t))
    if list(t) == want:
        check("F session tests target the declared peer from the SONiC node",
              all(t[n].get("node") == D["s_name"] and t[n].get("neighbor") == D["r_ip"] for n in (T_SESSION, T_REMOVED)))
        check("F bgp_neighbor targets the declared peer from the SONiC node",
              t[T_NEIGHBOR].get("kind") == "bgp_neighbor" and t[T_NEIGHBOR].get("src") == D["s_name"]
              and t[T_NEIGHBOR].get("dst") == D["r_ip"])
        check("F the AS-path test reads r1's declared network for r1's ASN",
              t[T_ASPATH].get("prefix") == D["prefix"] and str(D["r_asn"]) in str(t[T_ASPATH].get("as_path")))
        _unadv = str(t[T_UNADV].get("prefix"))
        _owned = {str(x).split("/")[0] for n in (r, s) for x in [n.get("router_id")] + list(n.get("networks") or [])}
        _owned |= {D["r_ip"], D["s_ip"]}
        check("F the unadvertised prefix is no address or network the fixture declares (parsed, not text)",
              _unadv.split("/")[0] not in _owned and _unadv != D["prefix"], "%s vs %s" % (_unadv, sorted(_owned)))
        check("F expectations: pass, pass, pass, fail, fail",
              [str(t[n].get("expect")) for n in want] == ["pass", "pass", "pass", "fail", "fail"])
        check("F the scenario runs only the neighbour-removed test",
              [st.get("run") for st in (D["scen"].get(SCENARIO) or {}).get("steps") or []] == [T_REMOVED])
_v = subprocess.run([sys.executable, os.path.join(ROOT, "src", "cassian.py"), "validate", FIXTURE], cwd=ROOT,
                    env=dict(os.environ, PYTHONPATH="src"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
check("F the fixture validates (R-O1 admits the three kinds on the vm node)", _v.returncode == 0,
      "rc=%d" % _v.returncode)

# ---- NV: two-directional non-vacuity per predicate (synthetic, device-independent) -------
P, SN, PFX, ASN = "198.51.100.28", "s1", "192.0.2.71/32", 65071
STOCK = ["10.0.0.%d" % k for k in range(1, 64, 2)]


def rec(**kw):
    base = {"kind": "invariant", "from": SN, "to": P, "expected": "pass", "observed": "pass", "verdict": "pass",
            "meta": {"type": "bgp_session_up", "state": "Established"}}
    meta = dict(base["meta"], **kw.pop("meta", {}))
    base.update(kw)
    base["meta"] = meta
    return base


def nv(label, pred, complete, too_much, too_little):
    a, b, c = pred(complete), pred(too_much), pred(too_little)
    ok = check("NV %s: complete passes, too-much and too-little are detected" % label, a and not b and not c,
               "complete=%s too-much=%s too-little=%s" % (a, b, c))
    if ok:
        print("  MUTATION-FAIL: %s too-much" % label)
        print("  MUTATION-FAIL: %s too-little" % label)


nv("session_ok", lambda x: session_ok(x, SN, P), rec(),
   rec(to=STOCK[0]), rec(observed="fail", verdict="fail", meta={"state": "Active"}))
nv("neighbor_ok", lambda x: neighbor_ok(x, SN, P),
   rec(kind="bgp_neighbor", expected="up", observed="up", meta={"type": None}),
   rec(kind="bgp_neighbor", expected="up", observed="up", to=STOCK[1], meta={"type": None}),
   rec(kind="bgp_neighbor", expected="up", observed="down", verdict="fail", meta={"type": None, "state": "Idle"}))
_ap = {"type": "bgp_as_path", "prefix": PFX, "route_present": True, "observed_as_path": str(ASN)}
nv("as_path_ok", lambda x: as_path_ok(x, SN, PFX, ASN), rec(to="", meta=_ap),
   rec(to="", meta=dict(_ap, observed_as_path="%d 65099" % ASN)),
   rec(to="", observed="fail", verdict="fail", meta=dict(_ap, route_present=False, observed_as_path="")))
_un = {"type": "bgp_as_path", "prefix": "203.0.113.77/32", "route_present": False, "observed_as_path": ""}
nv("unadvertised_ok", lambda x: unadvertised_ok(x, SN, "203.0.113.77/32"),
   rec(to="", expected="fail", observed="fail", verdict="pass", meta=_un),
   rec(to="", expected="fail", observed="pass", verdict="fail", meta=dict(_un, route_present=True, observed_as_path=str(ASN))),
   rec(to="", expected="fail", observed="fail", verdict="pass", meta=dict(_un, misuse=True)))
nv("removed_ok", lambda x: removed_ok(x, SN, P),
   rec(expected="fail", observed="fail", verdict="pass", meta={"state": "Active"}),
   rec(expected="fail", observed="pass", verdict="fail", meta={"state": "Established"}),
   rec(expected="fail", observed="fail", verdict="pass", to=STOCK[2], meta={"state": "NotConfigured"}))


def sdoc(observed, mode="json", err=None):
    bgp = {"parser_mode": mode, "observed": sorted(observed), "expected": [], "established": []}
    if err:
        bgp["error"] = err
    return {"nodes": [{"name": "r1", "bgp": {"parser_mode": "json", "observed": ["198.51.100.29"]}},
                      {"name": SN, "bgp": bgp}]}


nv("status_json_ok", lambda x: status_json_ok(x, SN, P), sdoc(STOCK + [P]),
   sdoc(STOCK + [P], err="vtysh: not found"), sdoc(STOCK))
_hdr = ("BGP router identifier 192.0.2.72, local AS number 65072 vrf-id 0\n\n"
        "Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc\n")
_stock_lines = "".join("%-15s 4      65200         0         0        0    0    0    never       Active        0 N/A\n" % ip
                       for ip in STOCK)
_peer_up = "%-15s 4      %d        12        12        0    0    0 00:01:02            1        1 r1\n" % (P, ASN)
_peer_dn = "%-15s 4      %d         0         0        0    0    0    never       Active        0 r1\n" % (P, ASN)
_stock_up = "%-15s 4      65200        12        12        0    0    0 00:01:02            3        2 N/A\n" % STOCK[3]


def human(summary):
    lines = ["Nodes:", "  - r1       (clab-x-r1) : running", "      BGP (none)",
             "  - %s       (clab-x-%s) : running" % (SN, SN), "      BGP (none)", "      " + VERBOSE_MARK]
    lines += ["      " + ln for ln in summary.split("\n")]
    return "\n".join(lines) + "\n"


nv("verbose_established", lambda x: verbose_established(x, SN, P), human(_hdr + _stock_lines + _peer_up),
   human(_hdr + _stock_lines + _stock_up + _peer_dn), human(_hdr + _stock_lines))
nv("human_line_ok", lambda x: human_line_ok(x, SN), human(_hdr + _peer_up),
   human(_hdr + _peer_up).replace("      BGP (none)\n      " + VERBOSE_MARK,
                                  "      bgp error on s1: TypeError (parser=none)\n      " + VERBOSE_MARK),
   "Nodes:\n  - r1       (clab-x-r1) : running\n      BGP (none)\n")


# ---- live legs ---------------------------------------------------------------------------
def cassian(*args, timeout=1800):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "src", "cassian.py")] + list(args), cwd=ROOT,
                       env=dict(os.environ, PYTHONPATH="src"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout)
    out = r.stdout.decode("utf-8", "replace") if isinstance(r.stdout, bytes) else (r.stdout or "")
    print("---- cassian %s -> rc=%d" % (" ".join(args), r.returncode))
    for ln in out.rstrip("\n").split("\n")[-25:]:
        print("     | " + ln)
    return r.returncode, out


def run_test(lab, name, scenario=None):
    path = os.path.join(ROOT, "labs", "clab-%s" % lab, "results.json")
    if os.path.exists(path):
        os.remove(path)  # never read a previous run's record
    rc, out = cassian("test", lab, "--scenario", scenario) if scenario else cassian("test", lab, "--name", name)
    try:
        res = json.load(open(path, encoding="utf-8"))
    except Exception:  # noqa: BLE001 -- a run that wrote nothing is judged by the caller
        res = {}
    hits = [t for t in res.get("tests") or [] if t.get("name") == name]
    r = hits[0] if len(hits) == 1 else None
    print("     record: %s" % json.dumps(r, sort_keys=True) if r else "     record: (none)")
    return rc, r


def live(topo, lab):
    if os.path.realpath(topo) != os.path.realpath(FIXTURE) or lab != DOC.get("name") or D is None:
        check("LIVE argv names the row-15 fixture and its lab", False, "%s %s" % (topo, lab))
        return
    sn, rn, rip, sip = D["s_name"], D["r_name"], D["r_ip"], D["s_ip"]
    later = ["L2 REQ-45D-1", "L3 REQ-45D-16", "L4 REQ-45D-19", "L5 -16 negative", "L6 -8 negative"]

    rc, r1 = run_test(lab, T_SESSION)
    if not check("L1 REQ-45D-8 (VM) B04 FIRST: bgp_session_up on %s toward %s passes, state Established" % (sn, rip),
                 rc == 0 and r1 is not None and session_ok(r1, sn, rip), "rc=%d" % rc):
        print("NEW FINDING (scope §2.1; REQ-45D-8): the declared FRR<->SONiC session did not reach Established "
              "on the shipped image and overlay. A finding against the rendering -- NOT BL-P2-4.5c-48.")
        for leg in later:
            blocked.append((leg, "NOT ATTEMPTED -- REQ-45D-8 did not pass on this boot"))
        return

    rc, r2 = run_test(lab, T_NEIGHBOR)
    check("L2 REQ-45D-1 (VM): bgp_neighbor %s -> %s observed up" % (sn, rip),
          rc == 0 and r2 is not None and neighbor_ok(r2, sn, rip), "rc=%d" % rc)

    rc, r3 = run_test(lab, T_ASPATH)
    check("L3 REQ-45D-16 (VM): %s received on %s with AS path exactly %d" % (D["prefix"], sn, D["r_asn"]),
          rc == 0 and r3 is not None and as_path_ok(r3, sn, D["prefix"], D["r_asn"]), "rc=%d" % rc)

    rc, out = cassian("status", lab, "--bgp", "--json")
    try:
        sdoc_live = json.loads(out[out.index("{"):])
    except Exception:  # noqa: BLE001
        sdoc_live = {}
    check("L4(i) REQ-45D-19 (VM, S29-R5): %s's JSON bgp record: parser json, no error, %s observed" % (sn, rip),
          rc == 0 and status_json_ok(sdoc_live, sn, rip), "rc=%d" % rc)
    rc, out = cassian("status", lab, "--bgp")
    check("L4(ii) REQ-45D-19 (VM, S29-R5): %s's human BGP line prints without an error" % sn,
          rc == 0 and human_line_ok(out, sn), "rc=%d; block %r" % (rc, node_block(out, sn)[:3]))
    rc, out = cassian("status", lab, "--bgp", "--bgp-verbose")
    check("L4(iii) REQ-45D-19 (VM, S29-R5): %s's verbose summary, parsed by the provider's text parser, "
          "shows %s established" % (sn, rip), rc == 0 and verbose_established(out, sn, rip), "rc=%d" % rc)

    rc, r5 = run_test(lab, T_UNADV)
    check("L5 §15.2 -16 negative (VM): an unadvertised prefix is absent; expect fail holds",
          rc == 0 and r5 is not None and unadvertised_ok(r5, sn, str(D["tests"][T_UNADV].get("prefix"))),
          "rc=%d" % rc)

    import cassian_runtime_vm as RV  # the product's runtime seam, as the other (VM) proofs use it
    rt = RV.build_runtime(DOC)

    def r_peers():
        cp = rt.exec(lab, rn, ["vtysh", "-c", "show bgp summary json"], check=False, capture_output=True)
        o = cp.stdout.decode("utf-8", "replace") if isinstance(cp.stdout, bytes) else (cp.stdout or "")
        return F.parse_frr_bgp_summary_neighbors_json(o)

    before = r_peers()
    cp = rt.exec(lab, rn, ["vtysh", "-c", "configure terminal", "-c", "router bgp %d" % D["r_asn"],
                           "-c", "no neighbor %s" % sip], check=False, capture_output=True)
    after = r_peers()
    print("     r1 peers before %s; after %s" % (sorted(before), sorted(after)))
    check("L6 the mutation applied: r1 held %s before and does not after (rc=%s)" % (sip, cp.returncode),
          cp.returncode == 0 and sip in before and sip not in after)
    r6, rc, tries = None, None, 0
    for tries in range(1, REMOVAL_TRIES + 1):
        time.sleep(REMOVAL_GAP_S)
        rc, r6 = run_test(lab, T_REMOVED, scenario=SCENARIO)
        if r6 is not None and removed_ok(r6, sn, rip):
            break
    check("L6 §15.2 -8 negative (VM): with r1's neighbour removed, bgp_session_up on %s does not read "
          "Established (expect fail holds)" % sn,
          rc == 0 and r6 is not None and removed_ok(r6, sn, rip), "rc=%s, scenario runs %d of %d" % (rc, tries, REMOVAL_TRIES))


argv = sys.argv[1:]
if not argv:
    for leg in ("L1 REQ-45D-8", "L2 REQ-45D-1", "L3 REQ-45D-16", "L4 REQ-45D-19", "L5 -16 negative", "L6 -8 negative"):
        blocked.append((leg, "no live argv: run `live <topo> <lab>` on a lab that is up"))
elif argv[0] == "live" and len(argv) == 3:
    live(argv[1], argv[2])
else:
    sys.exit("usage: sonic_bgp_session_live_proof.py [live <topo> <lab>]")

ok = True
for name, passed in checks:
    print("[%s] %s" % ("PASS" if passed else "FAIL", name))
    ok = ok and passed
for name, why in blocked:
    print("[BLOCKED] %s -- %s" % (name, why))
print("=" * 60)
print("cases:", len(checks), "blocked:", len(blocked))
print("RESULT:", "PASS" if ok else "FAIL", "(a BLOCKED or NOT ATTEMPTED leg is not a pass)")
sys.exit(0 if ok else 1)
