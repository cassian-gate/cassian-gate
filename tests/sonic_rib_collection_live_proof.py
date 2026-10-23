#!/usr/bin/env python3
"""RIB live proof: SONiC RIB collection through the seam (§4.5-d VM-2; scope §9 row 8).

One fixture, one boot (LD-45D-6): topologies/sonic-rib.yaml, declared under founder ruling
S29-R6 of 2026-10-12 -- three tests that pass at boot and one static-route scenario. Every
live assertion goes through the product's own path -- `cassian test` and its records --
except L2's control reads and L4's control, which use the provider's own reader and handler
on the product's runtime, never a read of this file's own design:

  L1  S29-R6 / handover §19 Walkthrough 1: a plain `cassian test <lab>` runs the three
      declared tests, every one passes, exit 0 (§19's "1/1" read as "every declared test
      passes"):
        REQ-45D-2   rib_route_prefix_loopback  route_prefix on the declared loopback /32 --
                    a connected prefix -- present through the seam
        REQ-45D-11  rib_route_present_link     route_present on the declared link /31
        REQ-45D-12  rib_route_absent_unused    route_absent on a prefix nothing declares and
                    the stock image does not carry, on a non-empty read
  L2  the static control: before configuration the guest RIB does not carry the static
      prefix; `ip route <static> blackhole` is configured on the guest through the
      product's runtime (the session-17 capture's command; SONiC renders no static route,
      so nothing declares one); after, the RIB carries it, protocol static.
  L3  REQ-45D-2 static: `cassian test <lab> --scenario rib_static` -- its wait_for
      route_prefix step reads the static prefix through the seam (founder ruling D-1):
      verdict pass, succeeded, present.
  L4  REQ-45D-11 / -12 negatives (VM), REQ-45D-31: a synthetic-complete control on the LIVE
      RIB bytes, through the provider's own handler: the complete read yields every
      declared prefix present and the absent prefix absent; the read truncated of a
      declared prefix does not yield it present; an empty read and a failed read are
      collection failures (probe_ok False) -- never present, never absent.

Lab-free legs (always run):
  F   the fixture's shape, derived values only; the fixture validates.
  NV  REQ-45D-31 two-directional non-vacuity, per predicate this file applies to the
      product's output: a synthetic COMPLETE observation satisfies it, and a mutation in
      each direction -- too much and too little -- is DETECTED. The RIB controls run on the
      committed capture of record (tests/fixtures/sonic-4_5d-h1b3/h1b3_rib_table_after.out,
      SONiC's own bytes) re-keyed to this fixture's prefixes, so the control's subject is
      independent of device state (BL-P2-4.5c-169).

usage:
  sonic_rib_collection_live_proof.py                    lab-free legs; L1-L4 BLOCKED; exit 0 if green
  sonic_rib_collection_live_proof.py live <topo> <lab>  lab-free legs, then L1-L4 on a lab already up

Coverage limits, stated in-file (PBE-P2-8):
  - One boot of one fixture. IPv4 only: an IPv6 prefix is a collection failure on sonic-vm
    (founder ruling (I) of 2026-10-01) and is not exercised here.
  - L2 mutates s1's running configuration (one static route); the lab is torn down after
    this file runs. The static-route read-back is bounded (ten reads, two seconds apart).
  - L4 runs the provider's handler on live bytes. That the engine turns a collection
    failure into verdict fail regardless of expect is the engine's code
    (run_route_prefix_test and the invariant collection-failure branch); it was exercised
    on a stubbed lab on the generator side, not here.
  - Walkthrough 1's "collect artifact for the SONiC node" line is not asserted: `cassian
    test` writes no collect artifact (cmd_collect is called by `cassian run` and two-run);
    REQ-45D-20's live leg belongs to the status/collect (VM) packet.
  - A wait_for whose expect is pass and which times out records a TypeError text in place
    of its result (F-S20-2, surfaced at session 20, no row); L3 runs the scenario only after
    L2 has read the static prefix back, so a timeout here means L2 already failed.

Exit 0 when every check passes (BLOCKED or NOT ATTEMPTED legs are listed); exit 1 otherwise.
"""
import copy
import ipaddress
import json
import os
import subprocess
import sys
import time

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))

import cassian_nos_sonic as S  # noqa: E402
from cassian_nos_types import ObservationRequest  # noqa: E402

FIXTURE = os.path.join(ROOT, "topologies", "sonic-rib.yaml")
CAPTURE = os.path.join(ROOT, "tests", "fixtures", "sonic-4_5d-h1b3", "h1b3_rib_table_after.out")
T_PREFIX = "rib_route_prefix_loopback"
T_PRESENT = "rib_route_present_link"
T_ABSENT = "rib_route_absent_unused"
SCENARIO = "rib_static"
READBACK_TRIES, READBACK_GAP_S = 10, 2

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
    cidr = {str(e).split(":")[0]: str(ip) for e, ip in zip(link[0]["endpoints"], link[0]["ipv4"])}
    tests = {t.get("name"): t for t in (doc.get("tests") or []) if isinstance(t, dict)}
    scen = {x.get("id"): x for x in (doc.get("scenarios") or []) if isinstance(x, dict)}
    s_net = str(ipaddress.ip_interface(cidr[s["name"]]).network)
    steps = (scen.get(SCENARIO) or {}).get("steps") or []
    wf = steps[0].get("wait_for") if len(steps) == 1 and isinstance(steps[0], dict) else None
    return {"r": r, "s": s, "s_name": s["name"], "r_name": r["name"],
            "loop": "%s/32" % str(s.get("router_id")), "link": s_net, "s_cidr": cidr[s["name"]],
            "r_cidr": cidr[r["name"]], "absent": str((tests.get(T_ABSENT) or {}).get("prefix")),
            "static": str((wf or {}).get("prefix")), "wf": wf, "tests": tests, "scen": scen}


def stock_hit(ip_or_net):
    """True if the address or network overlaps any of SONiC's stock prefixes (LD-45D-2(a))."""
    n = ipaddress.ip_network(str(ip_or_net), strict=False)
    return any(n.overlaps(ipaddress.ip_network(p)) for p in S.SONIC_STOCK_PREFIXES if p != "0.0.0.0/0")


# ---- predicates applied to the product's output (each one has a two-directional NV) -------
def _m(rec):
    return rec.get("meta") or {}


def _probe_clean(rec):
    ev = rec.get("evidence") or {}
    return ev.get("rc") == 0 and not ev.get("parse_error")


def prefix_ok(rec, node, prefix):
    return (rec.get("kind") == "route_prefix" and rec.get("from") == node and _m(rec).get("prefix") == prefix
            and _m(rec).get("present") is True and rec.get("expected") == "pass" and rec.get("observed") == "pass"
            and rec.get("verdict") == "pass" and _probe_clean(rec))


def present_ok(rec, node, prefix):
    return (rec.get("kind") == "invariant" and _m(rec).get("type") == "route_present" and rec.get("from") == node
            and _m(rec).get("prefix") == prefix and _m(rec).get("present") is True and rec.get("expected") == "pass"
            and rec.get("observed") == "pass" and rec.get("verdict") == "pass" and _probe_clean(rec))


def absent_ok(rec, node, prefix):
    # Absence is credited only on a clean, non-empty read (REQ-45D-12; BL-P2-4.5c-169).
    return (rec.get("kind") == "invariant" and _m(rec).get("type") == "route_absent" and rec.get("from") == node
            and _m(rec).get("prefix") == prefix and _m(rec).get("present") is False
            and int(_m(rec).get("observed_prefix_count") or 0) > 0 and rec.get("expected") == "pass"
            and rec.get("observed") == "pass" and rec.get("verdict") == "pass" and _probe_clean(rec))


def walkthrough_ok(res, names):
    """S29-R6: every declared test ran and passed, in declared order, and nothing else ran."""
    tests = res.get("tests") or []
    summ = res.get("summary") or {}
    return ([t.get("name") for t in tests] == list(names) and all(t.get("verdict") == "pass" for t in tests)
            and res.get("result") == "pass" and summ.get("total") == len(names) and summ.get("passed") == len(names)
            and not (res.get("scenarios") or []))


def find_test(res, name):
    hits = [t for t in res.get("tests") or [] if t.get("name") == name]
    return hits[0] if len(hits) == 1 else None


def static_ok(res, scenario, node, prefix):
    scen = [x for x in res.get("scenarios") or [] if x.get("id") == scenario]
    if len(scen) != 1 or scen[0].get("verdict") != "pass" or len(scen[0].get("steps") or []) != 1:
        return False
    st = scen[0]["steps"][0]
    m = st.get("meta") or {}
    ev = m.get("evidence") or {}
    return (st.get("type") == "wait_for" and st.get("wait_type") == "route_prefix" and st.get("expected") == "pass"
            and st.get("observed") == "pass" and st.get("verdict") == "pass" and m.get("prefix") == prefix
            and m.get("src") == node and m.get("succeeded") is True and ev.get("present") is True
            and ev.get("last_rc") == 0 and not (res.get("tests") or []))


class Replay:
    """A runtime whose one read returns given bytes and rc: the provider's handler runs unchanged on it."""

    def __init__(self, raw, rc=0):
        self.raw, self.rc = raw, rc

    def exec(self, lab, node, argv, check=False, capture_output=True, **kw):
        return subprocess.CompletedProcess(args=list(argv), returncode=self.rc, stdout=self.raw, stderr="")


def rib_obs(raw, rc, prefix, kind="route_present"):
    """(probe_ok, present) from the provider's own handler on the given bytes."""
    o = S._sonic_collect_route_table(Replay(raw, rc), "lab", "s1", ObservationRequest(kind=kind, params={"prefix": prefix}))
    return bool(o.evidence.get("probe_ok")), bool(o.data.get("present"))


def rib_present(raw, rc, prefix):
    ok, present = rib_obs(raw, rc, prefix)
    return ok and present


def rib_absent(raw, rc, prefix):
    """What route_absent needs to pass: a read the provider vouches for, without the prefix."""
    ok, present = rib_obs(raw, rc, prefix, kind="route_absent")
    return ok and not present


def truncate(raw, prefix):
    doc = json.loads(raw)
    doc.pop(prefix, None)
    return json.dumps(doc)


def rekey(doc, src, dst):
    e = copy.deepcopy(doc[src])
    for x in e:
        x["prefix"], x["prefixLen"] = dst, int(dst.split("/")[1])
    return e


# ---- F: the fixture --------------------------------------------------------------------
DOC = yaml.safe_load(open(FIXTURE, encoding="utf-8").read()) or {}
D = declared(DOC)
check("F one frr node and one sonic-vm node, linked once with a /31 pair", D is not None)
if D is not None:
    s, t = D["s"], D["tests"]
    check("F the sonic-vm node runs as vm and declares a router_id (its loopback)",
          s.get("runtime") == "vm" and bool(s.get("router_id")))
    check("F no BGP is declared (the RIB proof needs no session)",
          not any(n.get("asn") or n.get("bgp") or n.get("networks") for n in (D["r"], s)))
    want = [T_PREFIX, T_PRESENT, T_ABSENT]
    check("F S29-R6: the three declared tests, in order", list(t) == want, "%s" % list(t))
    if list(t) == want:
        check("F route_prefix on the declared loopback, from the SONiC node",
              t[T_PREFIX].get("kind") == "route_prefix" and t[T_PREFIX].get("src") == D["s_name"]
              and t[T_PREFIX].get("prefix") == D["loop"])
        check("F route_present on the declared link network, on the SONiC node",
              t[T_PRESENT].get("kind") == "invariant" and t[T_PRESENT].get("type") == "route_present"
              and t[T_PRESENT].get("node") == D["s_name"] and t[T_PRESENT].get("prefix") == D["link"])
        check("F route_absent on the SONiC node",
              t[T_ABSENT].get("kind") == "invariant" and t[T_ABSENT].get("type") == "route_absent"
              and t[T_ABSENT].get("node") == D["s_name"])
        check("F every declared test expects pass (S29-R6: all pass at boot)",
              [str(t[n].get("expect")) for n in want] == ["pass", "pass", "pass"])
    wf = D["wf"] or {}
    check("F the scenario is one wait_for route_prefix step from the SONiC node, expect pass",
          wf.get("type") == "route_prefix" and wf.get("src") == D["s_name"] and wf.get("expect") == "pass")
    _decl = {D["loop"], D["link"], str(ipaddress.ip_interface(D["r_cidr"]).network),
             "%s/32" % D["r"].get("router_id")}
    check("F the static and absent prefixes are distinct, IPv4, and no declared prefix overlaps them",
          D["static"] != D["absent"] and all(":" not in p for p in (D["static"], D["absent"]))
          and not any(ipaddress.ip_network(p).overlaps(ipaddress.ip_network(q))
                      for p in (D["static"], D["absent"]) for q in _decl),
          "static %s, absent %s, declared %s" % (D["static"], D["absent"], sorted(_decl)))
    _addr = [D["loop"], D["s_cidr"], D["r_cidr"], "%s/32" % D["r"].get("router_id"), D["static"], D["absent"]]
    check("F HALT-2 / LD-45D-2(a): no declared address and neither prefix overlaps SONiC's stock set",
          not any(stock_hit(a) for a in _addr), "%s" % _addr)
_v = subprocess.run([sys.executable, os.path.join(ROOT, "src", "cassian.py"), "validate", FIXTURE], cwd=ROOT,
                    env=dict(os.environ, PYTHONPATH="src"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
check("F the fixture validates (R-O1 admits the three kinds on the vm node; the absent prefix is not stock)",
      _v.returncode == 0, "rc=%d" % _v.returncode)

# ---- NV: two-directional non-vacuity per predicate (synthetic, device-independent) -------
SN, LOOP, LINK, ABS, STAT = "s1", "192.0.2.81/32", "198.51.100.32/31", "198.18.1.0/24", "198.18.0.0/24"


def nv(label, pred, complete, too_much, too_little):
    a, b, c = pred(complete), pred(too_much), pred(too_little)
    ok = check("NV %s: complete passes, too-much and too-little are detected" % label, a and not b and not c,
               "complete=%s too-much=%s too-little=%s" % (a, b, c))
    if ok:
        print("  MUTATION-FAIL: too-much (%s)" % label)
        print("  MUTATION-FAIL: too-little (%s)" % label)


def rec(**kw):
    base = {"kind": "invariant", "from": SN, "to": "", "expected": "pass", "observed": "pass", "verdict": "pass",
            "evidence": {"cmd": "vtysh -c 'show ip route json'", "rc": 0}, "meta": {}}
    meta = dict(base["meta"], **kw.pop("meta", {}))
    base.update(kw)
    base["meta"] = meta
    return base


_rp = {"prefix": LOOP, "present": True}
nv("prefix_ok", lambda x: prefix_ok(x, SN, LOOP), rec(kind="route_prefix", meta=_rp),
   rec(kind="route_prefix", meta=dict(_rp, prefix="192.0.2.81/31")),
   rec(kind="route_prefix", observed="fail", verdict="fail", meta=dict(_rp, present=False)))
_pp = {"type": "route_present", "prefix": LINK, "present": True, "observed_prefix_count": 37}
nv("present_ok", lambda x: present_ok(x, SN, LINK), rec(meta=_pp),
   rec(meta=dict(_pp, prefix="198.51.100.32/30")),
   rec(observed="fail", verdict="fail", evidence={"rc": 0, "parse_error": "empty RIB read"}, meta=dict(_pp, present=False)))
_ap = {"type": "route_absent", "prefix": ABS, "present": False, "observed_prefix_count": 37}
nv("absent_ok", lambda x: absent_ok(x, SN, ABS), rec(meta=_ap),
   rec(observed="fail", verdict="fail", meta=dict(_ap, present=True)),
   rec(meta=dict(_ap, observed_prefix_count=0)))
_names = [T_PREFIX, T_PRESENT, T_ABSENT]
_good = {"tests": [{"name": n, "verdict": "pass"} for n in _names], "result": "pass",
         "summary": {"total": 3, "passed": 3}, "scenarios": []}
nv("walkthrough_ok", lambda x: walkthrough_ok(x, _names), _good,
   dict(_good, tests=_good["tests"] + [{"name": "extra", "verdict": "pass"}], summary={"total": 4, "passed": 4}),
   dict(_good, tests=_good["tests"][:2], summary={"total": 2, "passed": 2}))
_step = {"type": "wait_for", "wait_type": "route_prefix", "expected": "pass", "observed": "pass", "verdict": "pass",
         "meta": {"prefix": STAT, "src": SN, "succeeded": True,
                  "evidence": {"cmd": "vtysh -c 'show ip route json'", "last_rc": 0, "prefix": STAT, "present": True}}}
_scen = lambda st, v="pass": {"tests": [], "scenarios": [{"id": SCENARIO, "verdict": v, "steps": [st]}]}  # noqa: E731
nv("static_ok", lambda x: static_ok(x, SCENARIO, SN, STAT), _scen(_step),
   _scen(dict(_step, meta=dict(_step["meta"], prefix=ABS))),
   _scen({"type": "wait_for", "verdict": "fail", "wait_type": None, "meta": None,
          "error": "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'"}, "fail"))
nv("find_test", lambda x: find_test(x, T_PREFIX) is not None,
   {"tests": [{"name": T_PREFIX}]}, {"tests": [{"name": T_PREFIX}, {"name": T_PREFIX}]}, {"tests": []})

# RIB controls on SONiC's own captured bytes, re-keyed to this fixture's prefixes.
_cap = json.load(open(CAPTURE, encoding="utf-8"))
_tbl = {k: v for k, v in _cap.items() if k not in ("198.51.100.0/31", "192.0.2.11/32", "192.0.2.12/32", "198.18.0.0/24")}
_tbl[LINK] = rekey(_cap, "198.51.100.0/31", LINK)
_tbl[LOOP] = rekey(_cap, "192.0.2.11/32", LOOP)
COMPLETE = json.dumps(_tbl)
check("NV the control table is SONiC's capture of record, re-keyed: the static and absent prefixes are not keys",
      STAT not in _tbl and ABS not in _tbl and len(_tbl) == len(_cap) - 2, "%d keys" % len(_tbl))
nv("rib_present (link)", lambda x: rib_present(x, 0, LINK), COMPLETE,
   json.dumps(dict({k: v for k, v in _tbl.items() if k != LINK}, **{"198.51.100.32/30": rekey(_tbl, LINK, "198.51.100.32/30")})),
   truncate(COMPLETE, LINK))
nv("rib_absent (absent prefix)", lambda x: rib_absent(x, 0, ABS), COMPLETE,
   json.dumps(dict(_tbl, **{ABS: rekey(_cap, "198.18.0.0/24", ABS)})), "")
check("NV rib_absent: a failed read (rc 1) of the complete table is not absence",
      rib_absent(COMPLETE, 0, ABS) and not rib_absent(COMPLETE, 1, ABS))
check("NV rib_present: an empty read is not presence", rib_present(COMPLETE, 0, LINK) and not rib_present("", 0, LINK))


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


def run(lab, *extra):
    path = os.path.join(ROOT, "labs", "clab-%s" % lab, "results.json")
    if os.path.exists(path):
        os.remove(path)  # never read a previous run's record
    rc, _ = cassian("test", lab, *extra)
    try:
        res = json.load(open(path, encoding="utf-8"))
    except Exception:  # noqa: BLE001 -- a run that wrote nothing is judged by the caller
        res = {}
    for t in res.get("tests") or []:
        print("     test: %s" % json.dumps(t, sort_keys=True))
    for x in res.get("scenarios") or []:
        print("     scenario: %s" % json.dumps(x, sort_keys=True))
    return rc, res


def live(topo, lab):
    if os.path.realpath(topo) != os.path.realpath(FIXTURE) or lab != DOC.get("name") or D is None:
        check("LIVE argv names the RIB fixture and its lab", False, "%s %s" % (topo, lab))
        return
    sn = D["s_name"]

    rc, res = run(lab)
    check("L1 S29-R6 / §19 Walkthrough 1: a plain `cassian test` runs the three declared tests, every one passes",
          rc == 0 and walkthrough_ok(res, [T_PREFIX, T_PRESENT, T_ABSENT]), "rc=%d" % rc)
    r1, r2, r3 = (find_test(res, n) or {} for n in (T_PREFIX, T_PRESENT, T_ABSENT))
    check("L1 REQ-45D-2 (VM): route_prefix %s (connected loopback) present through the seam" % D["loop"],
          prefix_ok(r1, sn, D["loop"]))
    check("L1 REQ-45D-11 (VM): route_present %s (connected link) on %s" % (D["link"], sn),
          present_ok(r2, sn, D["link"]))
    check("L1 REQ-45D-12 (VM): route_absent %s on %s, on a non-empty read" % (D["absent"], sn),
          absent_ok(r3, sn, D["absent"]))

    import cassian_runtime_vm as RV  # the product's runtime seam, as the other (VM) proofs use it
    rt = RV.build_runtime(DOC)

    def read():
        rc_, out_ = S._sonic_read(rt, lab, sn, S._RIB_ARGV)
        return rc_, out_

    rc0, raw0 = read()
    check("L2 control: before configuration the RIB is readable and does not carry %s" % D["static"],
          rc0 == 0 and rib_absent(raw0, rc0, D["static"]), "rc=%s" % rc0)
    cp = rt.exec(lab, sn, ["vtysh", "-c", "configure terminal", "-c", "ip route %s blackhole" % D["static"],
                           "-c", "end"], check=False, capture_output=True)
    rc1, raw1, proto, n = None, "", None, 0
    for n in range(1, READBACK_TRIES + 1):
        rc1, raw1 = read()
        if rc1 == 0 and rib_present(raw1, rc1, D["static"]):
            try:
                proto = [e.get("protocol") for e in json.loads(raw1)[D["static"]]]
            except Exception:  # noqa: BLE001
                proto = None
            break
        time.sleep(READBACK_GAP_S)
    check("L2 control: `ip route %s blackhole` configured through the product's runtime (rc=%s); the RIB then "
          "carries it, protocol static" % (D["static"], cp.returncode),
          cp.returncode == 0 and rc1 == 0 and rib_present(raw1, rc1, D["static"]) and proto == ["static"],
          "read %d of %d, protocols %s" % (n, READBACK_TRIES, proto))

    rc, res = run(lab, "--scenario", SCENARIO)
    check("L3 REQ-45D-2 (VM): the static prefix %s present through the seam (scenario wait_for route_prefix)"
          % D["static"], rc == 0 and static_ok(res, SCENARIO, sn, D["static"]), "rc=%d" % rc)

    rc2, live_raw = read()
    complete = (rc2 == 0 and all(rib_present(live_raw, rc2, p) for p in (D["loop"], D["link"], D["static"]))
                and rib_absent(live_raw, rc2, D["absent"]))
    check("L4 synthetic-complete control on the live RIB: every declared prefix and the static one present, "
          "the absent one absent", complete, "rc=%s" % rc2)
    check("L4 REQ-45D-11 negative (VM): the live read truncated of %s does not yield it present" % D["link"],
          complete and not rib_present(truncate(live_raw, D["link"]), 0, D["link"]))
    check("L4 REQ-45D-12 negative (VM): an empty read and a failed read of the live table are not absence",
          complete and not rib_absent("", 0, D["absent"]) and not rib_absent(live_raw, 1, D["absent"]))
    check("L4 REQ-45D-11 negative (VM): an empty read is not presence",
          complete and not rib_present("", 0, D["link"]))


argv = sys.argv[1:]
if not argv:
    for leg in ("L1 REQ-45D-2/-11/-12 (walkthrough)", "L2 static control", "L3 REQ-45D-2 static",
                "L4 -11/-12 negatives"):
        blocked.append((leg, "no live argv: run `live <topo> <lab>` on a lab that is up"))
elif argv[0] == "live" and len(argv) == 3:
    live(argv[1], argv[2])
else:
    sys.exit("usage: sonic_rib_collection_live_proof.py [live <topo> <lab>]")

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
