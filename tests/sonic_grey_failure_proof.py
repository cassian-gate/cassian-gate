#!/usr/bin/env python3
"""Grey failure on a SONiC guest (§4.5-d VM-8; scope §9 row 14): REQ-45D-22, with REQ-45D-31.

Founder rulings S37-R5 of 2026-10-20, its waiting step amended forward by S37-R6 (2026-10-20)
and its detection clause by S37-R14 (2026-10-22), with S37-R1 and S37-R2 (the session-37
rulings notes, Ledger §163 and §167). One fixture, one boot (LD-45D-6):
topologies/sonic-grey-failure.yaml -- r1 (frr) and s1 (sonic-vm) with one declared eBGP session
over r1:eth1 -- s1:eth1, shaped like row 15's.

REQ-45D-22 (handover §2): a grey failure induced on a SONiC container (vrnetlab wrapper) under
the existing scenario engine is detected by an existing invariant on a SONiC node and reported
with observed state; no new machinery. On one boot, as S37-R5 sets them out and in row 15's
pattern, each through the product's own `cassian test`:
  the control   `--name`: the declared bgp_session_up invariant on s1 passes before the fault
                (handover §15.2's -22 negative)
  the scenario  `--scenario`, the fixture's three steps:
    step 1  packet_loss, loss 100, on s1:eth1 -- the engine's own fault, which runs
            `tc qdisc replace dev eth1 root netem loss 100%` on the vrnetlab launcher
    step 2  wait N seconds (S37-R6), N declared in the fixture
    step 3  run the same invariant -- the detection: expect pass, observed fail
Before the control, the proof reads the negotiated hold time on the live boot and fails,
naming it, if it is not below N (S37-R6). The detection's observed state is asserted in
results.json, in the `scenario_test_run` event for step 3; results.summary.txt is asserted to
name the scenario failed and step 3 `verdict=fail`, with no claim that it shows the state
(S37-R14; Ledger BL-P2-4.5c-237).

N: the negotiated hold time read on s1 in the pre-run's first part (180 s on sonic-vm:202405,
keepalive 60 s) plus a 90 s margin, one keepalive interval and 30 s more. The fault drops what
the guest sends on eth1, its keepalives and TCP acknowledgements among them. There, on row
15's fixture, r1 left Established between 173.3 s and 174.3 s after the fault and s1 between
231.1 s and 232.3 s. Chat 3 reads that as s1's BGP taking in one more of r1's keepalives before
r1's TCP stalled on the acknowledgements it never received, so that s1's hold time ran from
that keepalive. On that reading s1 leaves Established within the hold time plus one keepalive
interval, 240 s, 30 s inside N; a reading of the measurement, not a measurement of the cause.

Lab-free legs (always run):
  F   the fixture's shape, derived values only: one frr and one sonic-vm node on one /31 link,
      each declaring the other; one declared test, the bgp_session_up invariant on the SONiC
      node toward the FRR node's link address, expect pass; one scenario whose steps are
      exactly the three above, the fault on the SONiC node's end of the declared link; the
      fixture validates.
  NV  REQ-45D-31 two-directional non-vacuity for each predicate this file applies to the
      product's output: a complete synthetic observation satisfies it, and a mutation in each
      direction -- too much and too little -- is detected; then, for each clause those
      mutations do not each isolate, one mutation rejected by that clause alone, printed only
      for the direction it tests. Not counted as clauses: the guards that only keep a missing or
      malformed record from raising (a type check, a count before an index). Printed in handover
      §18's literal form, `MUTATION-FAIL: too-much (<label>)` and `MUTATION-FAIL: too-little
      (<label>)` (S35-R3).

Live legs (`live <topo> <lab>`, on a lab already up). L1, L2, L3, L5 and L6 carry S37-R5, R6
and R14; L4 and L7 are verification legs beyond the rulings' text -- L4 checks that the
scenario's own fault took effect, L7 is the house pattern (S35-R1):
  L1  the guard (S37-R6): s1's neighbour reads Established within HOLD_READ_S, and its
      negotiated hold time, read with `vtysh -c "show bgp neighbors <ip> json"` on the guest, is
      below N. If it is not, L2-L7 are NOT ATTEMPTED. The hold time plus the negotiated
      keepalive interval is printed against N for information, not judged.
  L2  the control (§15.2 -22 negative): `cassian test <lab> --name <test>` exits 0, and
      results.json records the run passed, no scenario, and that one test passed, state
      Established. Without --scenario the run also passes through the global control-plane
      precheck first; a run it stops fails L2 like one the invariant fails, and the records are
      printed. If L2 fails, L3-L7 are NOT ATTEMPTED: no fault is applied.
  L3  the scenario: `cassian test <lab> --scenario <id>` exits 1, writes results.json with the
      result fail and no hard failure, and records the scenario failed with its three steps,
      numbered 1 to 3 -- fault pass, wait pass (N seconds, lasting at least N - 1 s by the wall
      clock), run fail.
  L4  the fault took effect: step 1's `scenario_fault` event passed, packet_loss on s1:eth1 at
      100; and, read after the scenario through substrate_exec, the launcher's eth1 carries the
      netem root qdisc with loss 100% and has dropped packets. The launcher's eth1 carrier and
      operstate are printed for information, not judged.
  L5  the detection (REQ-45D-22; S37-R14): step 3's `scenario_test_run` event expected pass,
      observed fail, verdict fail, its read parsed (no parse error), and its `observed_state`
      names the declared peer from s1 with a state other than Established and other than
      Unknown -- the state a read reports, not a read that failed. S37-R14 asks for a state other
      than Established; the parsed read, the Unknown exclusion and the peer, node and type are
      Chat 3's reading of what makes that state observed. s1's state and last reset reason, read
      from the guest after the scenario, are printed for information, not judged.
  L6  the summary (S37-R14): results.summary.txt names the scenario failed in its CI header,
      and renders step 3 `verdict=fail`. Whether it shows the observed state is printed for
      information, not judged (BL-P2-4.5c-237).
  L7  the guest-not-wrapper control (house pattern since S35-R1): through substrate_exec, the
      launcher answers a plain command, while the same BGP summary read sent there carries no
      peer entry for the declared neighbour -- so L1's and the invariant's reads can only have
      come from the guest.

usage:
  sonic_grey_failure_proof.py                    lab-free legs; L1-L7 BLOCKED; exit 0 if green
  sonic_grey_failure_proof.py live <topo> <lab>  lab-free legs, then L1-L7 on a lab already up

Coverage limits, stated in-file (PBE-P2-8):
  - One boot of one fixture on one image; one fault (loss 100) on one link.
  - The fault drops what the guest sends on eth1; what r1 sends still reaches the guest
    (measured in the pre-run's first part). The detection rests on BGP's hold timers. Carrier
    is not judged: netem does not change it, the launcher's eth1 carrier and operstate after
    the scenario are printed for information, and the drop times above are consistent with
    hold-timer expiry, not a link going down.
  - The drop times above were measured on row 15's fixture (topologies/
    sonic-bgp-session-live.yaml), not on this one; the pre-run's second part is this fixture's
    first boot.
  - N is declared in the fixture. The guard ties it to the boot's negotiated hold time (S37-R6:
    below N); it does not bound the keepalive interval's share of the drop, which the margin
    covers on the reading above.
  - The control and the detection are one read each: bgp_session_up retries a read that fails
    (timeout_s bounds those retries), not a session that is not Established, so the detection
    reads s1's state once, about N seconds after the fault. The control's run polls first, in
    the global precheck, which its one read follows.
  - The scenario's results.json replaces the control's; the control's record is printed here,
    as row 15's proof prints each run's.
  - L4 reads the qdisc after the scenario: the engine's scenario runner leaves the fault in
    place (it has no clearing step); the lab is torn down after this file runs.
  - L5 judges that the state read is not Established. That the fault caused the drop rests on
    L2 and L4; s1's last reset reason is printed, not judged.
  - The observed state is asserted in results.json, not in results.summary.txt (S37-R14).
  - L7 reads the launcher through substrate_exec; it does not inspect the wrapper chain.

Exit 0 when every check passes (BLOCKED or NOT ATTEMPTED legs are listed); exit 1 otherwise.
"""
import copy
import json
import os
import re
import subprocess
import sys
import time

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

import cassian_nos_sonic as S  # noqa: E402

FIXTURE = os.path.join(ROOT, "topologies", "sonic-grey-failure.yaml")
LAUNCHER_PROBE = ["uname", "-s"]
HOLD_READ_S = 120
LOSS = 100
UNREAD = ("established", "unknown")
RESET_KEYS = ("bgpState", "lastResetDueTo", "lastResetCode", "lastResetTimerMsecs")

checks, blocked = [], []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))
    return bool(ok)


def _text(x):
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")


# ---- declared values: derived from the fixture, never carried as literals -----------------
def declared(doc):
    nodes = {n.get("name"): n for n in (doc.get("nodes") or []) if isinstance(n, dict)}
    frr = [n for n in nodes.values() if str(n.get("type")) == "frr"]
    son = [n for n in nodes.values() if str(n.get("type")) == "sonic-vm"]
    links = [lk for lk in (doc.get("links") or []) if isinstance(lk, dict)]
    if len(frr) != 1 or len(son) != 1 or len(nodes) != 2 or len(links) != 1:
        return None
    r, s = frr[0], son[0]
    ends = [str(e).split(":") for e in links[0].get("endpoints") or []]
    ips = [str(ip).split("/") for ip in links[0].get("ipv4") or []]
    if sorted(e[0] for e in ends) != sorted([r["name"], s["name"]]) or len(ips) != 2 \
            or any(len(e) != 2 for e in ends) or any(len(i) != 2 or i[1] != "31" for i in ips):
        return None
    by = {e[0]: (e[1], ip[0]) for e, ip in zip(ends, ips)}
    tests = [t for t in (doc.get("tests") or []) if isinstance(t, dict)]
    scen = [x for x in (doc.get("scenarios") or []) if isinstance(x, dict)]
    return {"r": r, "s": s, "r_name": r["name"], "s_name": s["name"], "s_if": by[s["name"]][0],
            "r_ip": by[r["name"]][1], "s_ip": by[s["name"]][1], "tests": tests, "scen": scen}


def nbrs(n):
    return [(x.get("peer"), x.get("remote_as")) for x in ((n.get("bgp") or {}).get("neighbors") or [])]


def scenario_steps(d):
    """(test name, N) when the one scenario's steps are exactly the three S37-R5/R6 name, else None."""
    if len(d["tests"]) != 1 or len(d["scen"]) != 1:
        return None
    t, steps = d["tests"][0], d["scen"][0].get("steps")
    name = t.get("name")
    if not isinstance(steps, list) or len(steps) != 3:
        return None
    n = (steps[1].get("wait") or {}).get("seconds") if isinstance(steps[1], dict) else None
    want = [{"fault": {"packet_loss": {"node": d["s_name"], "if": d["s_if"], "loss": LOSS}}},
            {"wait": {"seconds": n}},
            {"run": name}]
    if steps != want or isinstance(n, bool) or not isinstance(n, int) or n < 1:
        return None
    return name, n


# ---- predicates applied to the product's output (each has a two-directional NV) -----------
def established_hold(raw, ip):
    """`show bgp neighbors <ip> json` on the guest: the negotiated hold time in ms when the
    neighbour reads Established and carries it as a positive integer, else None."""
    try:
        doc = json.loads(_text(raw).strip() or "null")
    except ValueError:
        return None
    nb = doc.get(ip) if isinstance(doc, dict) else None
    if not isinstance(nb, dict) or str(nb.get("bgpState") or "") != "Established":
        return None
    h = nb.get("bgpTimerHoldTimeMsecs")
    return h if isinstance(h, int) and not isinstance(h, bool) and h > 0 else None


def hold_below(hold_ms, n_s):
    """L1 (S37-R6): the negotiated hold time is below N."""
    return isinstance(hold_ms, int) and not isinstance(hold_ms, bool) and 0 < hold_ms < n_s * 1000


def _m(rec):
    return rec.get("meta") or {} if isinstance(rec, dict) else {}


def _session(rec, node, peer):
    return (isinstance(rec, dict) and rec.get("kind") == "invariant" and _m(rec).get("type") == "bgp_session_up"
            and not _m(rec).get("misuse") and rec.get("from") == node and rec.get("to") == peer
            and rec.get("expected") == "pass")


def control_ok(rc, res, name, node, peer):
    """L2: `cassian test --name` exited 0; the run passed, ran no scenario, and recorded one
    test -- the declared invariant on the node toward the peer -- passed, state Established."""
    tests = res.get("tests") or []
    t = tests[0] if len(tests) == 1 and isinstance(tests[0], dict) else {}
    return (rc == 0 and res.get("result") == "pass" and not (res.get("scenarios") or [])
            and t.get("name") == name and _session(t, node, peer)
            and t.get("observed") == "pass" and t.get("verdict") == "pass"
            and str(_m(t).get("state") or "").lower() == "established")


def find_event(res, scenario, name, step):
    """The one `scenario_test_run` event the scenario's step wrote for `name`, else None."""
    hits = [e for e in res.get("events") or [] if isinstance(e, dict) and e.get("type") == "scenario_test_run"
            and e.get("scenario_id") == scenario and e.get("name") == name and e.get("step") == step]
    return hits[0] if len(hits) == 1 else None


def detection_ok(ev, node, peer):
    """L5 (S37-R14): observed fail, verdict fail, its read parsed, and its observed_state names
    the declared peer from the node with a state a read reports, other than Established."""
    os_ = ev.get("observed_state") if isinstance(ev, dict) else None
    st = os_.get("state") if isinstance(os_, dict) else None
    return (_session(ev, node, peer) and ev.get("observed") == "fail" and ev.get("verdict") == "fail"
            and (ev.get("evidence") or {}).get("parse_error") == ""
            and isinstance(os_, dict) and os_.get("type") == "bgp_session_up" and os_.get("peer") == peer
            and os_.get("source_node") == node and isinstance(st, str) and bool(st.strip())
            and st.strip().lower() not in UNREAD)


def fault_ok(res, scenario, step, node, iface):
    """L4: the one `scenario_fault` event at the step passed: packet_loss on node:iface at LOSS."""
    hits = [e for e in res.get("events") or [] if isinstance(e, dict) and e.get("type") == "scenario_fault"
            and e.get("scenario_id") == scenario and e.get("step") == step]
    m = (hits[0].get("meta") or {}) if len(hits) == 1 else {}
    return (len(hits) == 1 and hits[0].get("verdict") == "pass" and m.get("action") == "packet_loss"
            and m.get("target") == "%s:%s" % (node, iface) and m.get("loss_percent") == LOSS)


def scenario_ok(rc, res, scenario, name, n_s):
    """L3: `cassian test --scenario` exited 1; the scenario failed, its three steps numbered 1 to 3
    -- fault pass, wait pass (N s, lasting at least N - 1 s by the wall clock), run of the test
    fail; and the run's result is fail with no hard failure."""
    sc = [x for x in res.get("scenarios") or [] if isinstance(x, dict) and x.get("id") == scenario]
    steps = sc[0].get("steps") or [] if len(sc) == 1 else []
    shape = [(st.get("type"), st.get("verdict"), st.get("step")) for st in steps if isinstance(st, dict)]
    hf = res.get("hard_failure") or {}
    return (rc == 1 and len(sc) == 1 and sc[0].get("verdict") == "fail" and res.get("result") == "fail"
            and not (isinstance(hf, dict) and hf.get("occurred"))
            and shape == [("fault", "pass", 1), ("wait", "pass", 2), ("run", "fail", 3)]
            and steps[2].get("ref") == name
            and steps[1].get("seconds") == n_s and int(steps[1].get("duration_ms") or 0) >= (n_s - 1) * 1000)


def summary_ok(txt, scenario, name):
    """L6 (S37-R14): the CI header names the scenario failed, and step 3 renders verdict=fail."""
    ls = _text(txt).split("\n")
    head = 'failed_scenarios: ["%s"]' % scenario
    s3 = [l for l in ls if l.startswith("    [3] run test=%s verdict=fail" % name)]
    return ls.count(head) == 1 and len(s3) == 1


def qdisc_ok(raw, loss):
    """L4: the root qdisc is netem with the loss, and it has dropped packets."""
    m = re.search(r"qdisc netem \S+ root .*?\bloss (\d+)%.*?\n\s*Sent \d+ bytes \d+ pkt \(dropped (\d+)",
                  _text(raw), re.S)
    return bool(m) and int(m.group(1)) == loss and int(m.group(2)) > 0


def launcher_lacks(probe, out, peer):
    """L7: the launcher answers a plain command (probe = (rc, text)), and its output for the BGP
    summary read carries no peer entry for the declared neighbour."""
    return probe[0] == 0 and bool(_text(probe[1]).strip()) and bool(peer) \
        and S._summary_peer(_text(out[1]), peer)[0] is None


def cassian(*args, timeout=1800):
    try:
        r = subprocess.run([sys.executable, os.path.join(SRC, "cassian.py")] + list(args), cwd=ROOT,
                           env=dict(os.environ, PYTHONPATH="src"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        print("---- cassian %s -> TIMEOUT after %s s" % (" ".join(args), exc.timeout))
        return -1, _text(exc.output)
    out = _text(r.stdout)
    print("---- cassian %s -> rc=%d" % (" ".join(args), r.returncode))
    for ln in out.rstrip("\n").split("\n")[-25:]:
        print("     | " + ln)
    return r.returncode, out


# ---- F: the fixture --------------------------------------------------------------------
DOC = (yaml.safe_load(open(FIXTURE, encoding="utf-8").read()) or {}) if os.path.isfile(FIXTURE) else {}
D = declared(DOC)
SC = None
check("F one frr node and one sonic-vm node, linked once with a /31 pair", D is not None)
if D is not None:
    r, s = D["r"], D["s"]
    check("F each side declares the other, with the other's ASN as remote_as",
          nbrs(r) == [(D["s_name"], s.get("asn"))] and nbrs(s) == [(D["r_name"], r.get("asn"))],
          "r %s, s %s" % (nbrs(r), nbrs(s)))
    check("F the sonic-vm node runs as vm (one guest) on the provider's default image",
          s.get("runtime") == "vm" and s.get("image") == S.SONIC_DEFAULT_IMAGE, "image=%s" % s.get("image"))
    t = D["tests"][0] if len(D["tests"]) == 1 else {}
    check("F one declared test: the bgp_session_up invariant on the SONiC node toward the FRR node's link "
          "address, expect pass",
          len(D["tests"]) == 1 and t.get("kind") == "invariant" and t.get("type") == "bgp_session_up"
          and t.get("node") == D["s_name"] and t.get("neighbor") == D["r_ip"] and t.get("expect") == "pass",
          "%s" % [x.get("name") for x in D["tests"]])
    SC = scenario_steps(D)
    check("F one scenario, exactly: packet_loss %d on the SONiC node's end of the link; wait N; run the test"
          % LOSS, SC is not None, "N=%s" % (SC[1] if SC else None))
_rc, _out = cassian("validate", FIXTURE)
check("F the fixture validates", _rc == 0, "rc=%d" % _rc)


# ---- NV: two-directional non-vacuity per predicate (synthetic, device-independent) -------
def nv(label, pred, complete, too_much, too_little):
    """REQ-45D-31: one predicate, both directions."""
    a, b, c = pred(complete), pred(too_much), pred(too_little)
    ok = check("NV %s: complete passes, too-much and too-little are detected" % label, a and not b and not c,
               "complete=%s too-much=%s too-little=%s" % (a, b, c))
    if ok:
        print("  MUTATION-FAIL: too-much (%s)" % label)
        print("  MUTATION-FAIL: too-little (%s)" % label)


def nvc(label, pred, complete, too_much=None, too_little=None):
    """One clause of a predicate nv() already covers: each mutation given is rejected by that
    clause alone, and only the direction tested prints."""
    a = pred(complete)
    got = [(d, m, pred(m)) for d, m in (("too-much", too_much), ("too-little", too_little)) if m is not None]
    ok = check("NV %s: complete passes, the %s mutation is detected" % (label, " and ".join(d for d, _m, _r in got)),
               a and bool(got) and not any(r for _d, _m, r in got),
               "complete=%s %s" % (a, " ".join("%s=%s" % (d, r) for d, _m, r in got)))
    if ok:
        for d, _m, _r in got:
            print("  MUTATION-FAIL: %s (%s)" % (d, label))


def _with(d, path, value):
    """A deep copy of d with the key at `path` set to value (or removed, for _GONE)."""
    m = copy.deepcopy(d)
    cur = m
    for k in path[:-1]:
        cur = cur[k]
    if value is _GONE:
        cur.pop(path[-1], None)
    else:
        cur[path[-1]] = value
    return m


_GONE = object()
SN, P, IF, SID, TN, NS = "s1", "198.51.100.76", "eth1", "grey_packet_loss", "grey_session_up", 270
_NB = {P: {"bgpState": "Established", "bgpTimerHoldTimeMsecs": 180000, "bgpTimerKeepAliveIntervalMsecs": 60000}}
_NBJ = json.dumps(_NB)
_REC = {"name": TN, "kind": "invariant", "from": SN, "to": P, "expected": "pass", "observed": "pass", "verdict": "pass",
        "duration_ms": 1000, "error": "", "evidence": {"cmd": "vtysh -c 'show bgp summary json'", "parse_error": ""},
        "meta": {"type": "bgp_session_up", "neighbor": P, "state": "Established", "attempts": 1}}
_CRES = {"result": "pass", "tests": [_REC], "scenarios": [], "events": []}
_CTL = (0, _CRES)
_DET = dict(copy.deepcopy(_REC), type="scenario_test_run", scenario_id=SID, step=3, observed="fail", verdict="fail",
            error="bgp_session_up mismatch (expected pass, observed fail)",
            meta={"type": "bgp_session_up", "neighbor": P, "state": "Connect", "attempts": 1},
            observed_state={"type": "bgp_session_up", "peer": P, "state": "Connect", "last_error": "",
                            "source_node": SN})
_FAULT = {"type": "scenario_fault", "scenario_id": SID, "step": 1, "verdict": "pass", "duration_ms": 40, "error": "",
          "meta": {"loss_percent": LOSS, "action": "packet_loss", "target": "%s:%s" % (SN, IF)}}
_RES = {"result": "fail", "tests": [], "events": [_FAULT, _DET],
        "scenarios": [{"id": SID, "verdict": "fail", "steps": [
            {"type": "fault", "action": "packet_loss", "target": "%s:%s" % (SN, IF), "verdict": "pass",
             "duration_ms": 40, "step": 1, "meta": {"loss_percent": LOSS}},
            {"type": "wait", "seconds": NS, "observed": "completed", "verdict": "pass", "duration_ms": NS * 1000 + 3,
             "step": 2},
            {"type": "run", "ref": TN, "verdict": "fail", "duration_ms": 1000, "step": 3}]}]}
_RUN = (1, _RES)
_SUM = ("=== CI SUMMARY ===\nverdict: FAIL\nfailed_tests: []\nfailed_scenarios: [\"%s\"]\n\n"
        "=== Scenarios ===\nscenario %s: FAIL (duration: 271.1s)\n    [1] fault packet_loss %s:%s verdict=pass dur=0.0s\n"
        "    [2] wait verdict=pass observed=completed dur=270.0s\n"
        "    [3] run test=%s verdict=fail dur=1.0s\n" % (SID, SID, SN, IF, TN))
_Q = ("qdisc netem 8001: root refcnt 5 limit 1000 loss 100%\n Sent 0 bytes 0 pkt (dropped 253, overlimits 0 requeues 0)\n"
      " backlog 0b 0p requeues 0\nqdisc clsact ffff: parent ffff:fff1\n")
_NF = (127, "OCI runtime exec failed: exec: \"vtysh\": executable file not found in $PATH")
_LSUM = json.dumps({"ipv4Unicast": {"peers": {P: {"state": "Established"}}}})


def _steps(res, i, key, value):
    return _with(res, ("scenarios", 0, "steps", i, key), value)


P_EH = lambda x: established_hold(x, P) == 180000  # noqa: E731 -- what L1 reads
P_EHN = lambda x: established_hold(x, P) is not None  # noqa: E731
P_HB = lambda x: hold_below(x, NS)  # noqa: E731
P_C = lambda x: control_ok(x[0], x[1], TN, SN, P)  # noqa: E731
P_FE = lambda x: find_event(x, SID, TN, 3) is not None  # noqa: E731
P_D = lambda x: detection_ok(x, SN, P)  # noqa: E731
P_F = lambda x: fault_ok(x, SID, 1, SN, IF)  # noqa: E731
P_S = lambda x: scenario_ok(x[0], x[1], SID, TN, NS)  # noqa: E731
P_SU = lambda x: summary_ok(x, SID, TN)  # noqa: E731
P_Q = lambda x: qdisc_ok(x, LOSS)  # noqa: E731
P_L = lambda x: launcher_lacks(x[0], x[1], P)  # noqa: E731

# one entry per predicate, both directions (REQ-45D-31)
nv("established_hold", P_EH, _NBJ, json.dumps(_with(_NB, (P, "bgpTimerHoldTimeMsecs"), 180000.0)),
   json.dumps(_with(_NB, (P, "bgpState"), "Active")))
nv("hold_below", P_HB, 180000, NS * 1000, None)
nv("control_ok", P_C, _CTL, (0, _with(_CRES, ("tests",), [_REC, _REC])),
   (0, _with(_CRES, ("tests", 0, "meta", "state"), "Active")))
nv("find_event", P_FE, _RES, _with(_RES, ("events",), [_FAULT, _DET, _DET]),
   _with(_RES, ("events",), [_FAULT, dict(_DET, step=2)]))
nv("detection_ok", P_D, _DET, _with(_DET, ("observed_state", "state"), "Established"),
   _with(_DET, ("observed_state",), _GONE))
nv("fault_ok", P_F, _RES, _with(_RES, ("events",), [_FAULT, dict(_FAULT), _DET]),
   _with(_RES, ("events",), [_with(_FAULT, ("meta", "loss_percent"), 50), _DET]))
nv("scenario_ok", P_S, _RUN, (1, _with(_RES, ("scenarios",), _RES["scenarios"] * 2)),
   (1, _with(_RES, ("scenarios", 0, "steps"), _RES["scenarios"][0]["steps"][:2])))
nv("summary_ok", P_SU, _SUM, _SUM + "    [3] run test=%s verdict=fail dur=1.0s\n" % TN,
   _SUM.replace('failed_scenarios: ["%s"]' % SID, "failed_scenarios: []"))
nv("qdisc_ok", P_Q, _Q, _Q.replace("loss 100%", "loss 30%"), _Q.replace("dropped 253", "dropped 0"))
nv("launcher_lacks", P_L, ((0, "Linux\n"), _NF), ((0, "Linux\n"), (0, _LSUM)), ((127, ""), _NF))

# clauses the entries above do not each isolate: one mutation per clause, rejected by it alone
nvc("established_hold: the neighbour's own entry", P_EH, _NBJ, too_much=json.dumps({"10.0.0.1": _NB[P]}))
nvc("established_hold: unparseable output is no read", P_EH, _NBJ, too_little=_NBJ[:-1])
nvc("established_hold: a hold time present", P_EH, _NBJ,
    too_little=json.dumps(_with(_NB, (P, "bgpTimerHoldTimeMsecs"), _GONE)))
nvc("established_hold: a boolean is no hold time", P_EHN, _NBJ,
    too_much=json.dumps(_with(_NB, (P, "bgpTimerHoldTimeMsecs"), True)))
nvc("established_hold: a hold time above zero", P_EHN, _NBJ,
    too_little=json.dumps(_with(_NB, (P, "bgpTimerHoldTimeMsecs"), 0)))
nvc("hold_below: a zero hold time is no read", P_HB, 180000, too_little=0)
nvc("hold_below: a boolean is no hold time", lambda x: hold_below(x, 2), 1000, too_much=True)
nvc("hold_below: a hold time above N", P_HB, 180000, too_much=NS * 1000 + 1)
nvc("control_ok: the run exits 0", P_C, _CTL, too_little=(1, _CRES))
nvc("control_ok: the run's result pass", P_C, _CTL, too_little=(0, dict(_CRES, result="fail")))
nvc("control_ok: no scenario run", P_C, _CTL, too_much=(0, dict(_CRES, scenarios=[{"id": SID}])))
nvc("control_ok: the declared test's own name", P_C, _CTL, too_much=(0, _with(_CRES, ("tests", 0, "name"), "other")))
nvc("control_ok: one test record, not a non-dict beside it", P_C, _CTL,
    too_much=(0, _with(_CRES, ("tests",), [_REC, "x"])))
nvc("control_ok: the invariant kind", P_C, _CTL, too_much=(0, _with(_CRES, ("tests", 0, "kind"), "bgp_neighbor")))
nvc("control_ok: the bgp_session_up type", P_C, _CTL,
    too_much=(0, _with(_CRES, ("tests", 0, "meta", "type"), "bgp_neighbor")))
nvc("control_ok: no misuse", P_C, _CTL, too_much=(0, _with(_CRES, ("tests", 0, "meta", "misuse"), True)))
nvc("control_ok: from the SONiC node", P_C, _CTL, too_much=(0, _with(_CRES, ("tests", 0, "from"), "r1")))
nvc("control_ok: toward the declared peer", P_C, _CTL, too_much=(0, _with(_CRES, ("tests", 0, "to"), "10.0.0.1")))
nvc("control_ok: expect pass", P_C, _CTL, too_much=(0, _with(_CRES, ("tests", 0, "expected"), "fail")))
nvc("control_ok: observed pass", P_C, _CTL, too_little=(0, _with(_CRES, ("tests", 0, "observed"), "fail")))
nvc("control_ok: verdict pass", P_C, _CTL, too_little=(0, _with(_CRES, ("tests", 0, "verdict"), "fail")))
nvc("find_event: the scenario's own id", P_FE, _RES,
    too_little=_with(_RES, ("events",), [_FAULT, dict(_DET, scenario_id="other")]))
nvc("find_event: the test's own name", P_FE, _RES, too_little=_with(_RES, ("events",), [_FAULT, dict(_DET, name="other")]))
nvc("find_event: a scenario_test_run event", P_FE, _RES,
    too_little=_with(_RES, ("events",), [_FAULT, dict(_DET, type="scenario_fault")]))
nvc("detection_ok: observed fail", P_D, _DET, too_much=dict(_DET, observed="pass"))
nvc("detection_ok: verdict fail", P_D, _DET, too_much=dict(_DET, verdict="pass"))
nvc("detection_ok: expect pass", P_D, _DET, too_much=dict(_DET, expected="fail"))
nvc("detection_ok: the read parsed", P_D, _DET,
    too_little=_with(_DET, ("evidence", "parse_error"), "vtysh command failed"))
nvc("detection_ok: an unread state is no detection", P_D, _DET,
    too_little=_with(_DET, ("observed_state", "state"), "Unknown"))
nvc("detection_ok: a state reported", P_D, _DET, too_little=_with(_DET, ("observed_state", "state"), " "))
nvc("detection_ok: the observed state's type", P_D, _DET,
    too_much=_with(_DET, ("observed_state", "type"), "bgp_neighbor"))
nvc("detection_ok: the declared peer", P_D, _DET, too_much=_with(_DET, ("observed_state", "peer"), "10.0.0.1"))
nvc("detection_ok: from the SONiC node", P_D, _DET,
    too_much=_with(_DET, ("observed_state", "source_node"), "r1"))
nvc("detection_ok: the event's peer", P_D, _DET, too_much=dict(_DET, to="10.0.0.1"))
nvc("detection_ok: no misuse", P_D, _DET, too_much=_with(_DET, ("meta", "misuse"), True))
nvc("fault_ok: the event passed", P_F, _RES, too_little=_with(_RES, ("events",), [dict(_FAULT, verdict="fail"), _DET]))
nvc("fault_ok: the packet_loss action", P_F, _RES,
    too_much=_with(_RES, ("events",), [_with(_FAULT, ("meta", "action"), "latency"), _DET]))
nvc("fault_ok: the SONiC node's interface", P_F, _RES,
    too_much=_with(_RES, ("events",), [_with(_FAULT, ("meta", "target"), "r1:eth1"), _DET]))
nvc("fault_ok: the step's own event", P_F, _RES, too_little=_with(_RES, ("events",), [dict(_FAULT, step=2), _DET]))
nvc("fault_ok: a scenario_fault event", P_F, _RES,
    too_little=_with(_RES, ("events",), [dict(_FAULT, type="scenario_test_run"), _DET]))
nvc("fault_ok: the scenario's own id", P_F, _RES,
    too_little=_with(_RES, ("events",), [dict(_FAULT, scenario_id="other"), _DET]))
nvc("scenario_ok: the run exits 1", P_S, _RUN, too_little=(0, _RES))
nvc("scenario_ok: the scenario's own id", P_S, _RUN, too_little=(1, _with(_RES, ("scenarios", 0, "id"), "other")))
nvc("scenario_ok: the scenario failed", P_S, _RUN, too_little=(1, _with(_RES, ("scenarios", 0, "verdict"), "pass")))
nvc("scenario_ok: the run's result fail", P_S, _RUN, too_little=(1, dict(_RES, result="pass")))
nvc("scenario_ok: no hard failure", P_S, _RUN, too_much=(1, dict(_RES, hard_failure={"occurred": True})))
nvc("scenario_ok: the steps numbered 1 to 3", P_S, _RUN,
    too_much=(1, _steps(_steps(_steps(_RES, 0, "step", 0), 1, "step", 1), 2, "step", 2)))
nvc("scenario_ok: the run step runs the declared test", P_S, _RUN, too_much=(1, _steps(_RES, 2, "ref", "other")))
nvc("scenario_ok: the wait is N seconds", P_S, _RUN, too_little=(1, _steps(_RES, 1, "seconds", NS - 1)))
nvc("scenario_ok: the wait lasted N seconds", P_S, _RUN,
    too_little=(1, _steps(_RES, 1, "duration_ms", (NS - 1) * 1000 - 1)))
nvc("summary_ok: step 3 rendered", P_SU, _SUM, too_little=_SUM.replace("    [3] run test=%s verdict=fail dur=1.0s\n" % TN, ""))
nvc("summary_ok: the scenario named once in the header", P_SU, _SUM,
    too_much=_SUM.replace("verdict: FAIL\n", "verdict: FAIL\nfailed_scenarios: [\"%s\"]\n" % SID))
nvc("qdisc_ok: the netem qdisc at the root", P_Q, _Q, too_little=_Q.replace("qdisc netem 8001: root", "qdisc netem 8001: parent 1:1"))
nvc("qdisc_ok: a loss stated", P_Q, _Q, too_little=_Q.replace(" loss 100%", ""))
nvc("launcher_lacks: the probe exits 0", P_L, ((0, "Linux\n"), _NF), too_little=((127, "Linux\n"), _NF))
nvc("launcher_lacks: the probe prints text", P_L, ((0, "Linux\n"), _NF), too_little=((0, " \n"), _NF))
nvc("launcher_lacks: a peer to look for", lambda x: launcher_lacks(x[0], x[1], x[2]), ((0, "Linux\n"), _NF, P),
    too_little=((0, "Linux\n"), _NF, ""))


# ---- live legs ---------------------------------------------------------------------------
def live(topo, lab):
    if os.path.realpath(topo) != os.path.realpath(FIXTURE) or lab != DOC.get("name") or D is None or SC is None:
        check("LIVE argv names the grey-failure fixture and its lab", False, "%s %s" % (topo, lab))
        return
    sn, rip, sif = D["s_name"], D["r_ip"], D["s_if"]
    name, n_s = SC
    sid = D["scen"][0].get("id")
    import cassian_runtime_vm as RV  # the product's runtime seam, as the other (VM) proofs use it
    rt = RV.build_runtime(DOC)
    labdir = os.path.join(ROOT, "labs", "clab-%s" % lab)

    def guest(cmd, lines=6):
        try:
            cp = rt.exec(lab, sn, list(cmd), check=False, capture_output=True, timeout_s=60)
        except subprocess.TimeoutExpired:
            print("     guest(%s)$ %s -> TIMEOUT" % (sn, " ".join(cmd)))
            return -1, ""
        out = _text(cp.stdout)
        print("     guest(%s)$ %s -> rc=%s\n%s" % (sn, " ".join(cmd), cp.returncode,
                                                 "\n".join("       " + l for l in out.rstrip("\n").split("\n")[:lines])))
        return cp.returncode, out

    def launcher(cmd, lines=6):
        try:
            cp = rt.substrate_exec(lab, sn, list(cmd), check=False, capture_output=True, timeout_s=30)
        except subprocess.TimeoutExpired:
            print("     launcher(%s)$ %s -> TIMEOUT" % (sn, " ".join(cmd)))
            return -1, ""
        out = _text(cp.stdout) + _text(getattr(cp, "stderr", ""))
        print("     launcher(%s)$ %s -> rc=%s\n%s" % (sn, " ".join(cmd), cp.returncode,
                                                    "\n".join("       " + l for l in out.rstrip("\n").split("\n")[:lines])))
        return cp.returncode, out

    def neighbour():
        _rc, raw = guest(["vtysh", "-c", "show bgp neighbors %s json" % rip], lines=0)
        try:
            nb = (json.loads(raw) or {}).get(rip) or {}
        except (ValueError, AttributeError):
            nb = {}
        return raw, nb if isinstance(nb, dict) else {}

    def run(*args):
        for f in ("results.json", "results.summary.txt"):
            if os.path.exists(os.path.join(labdir, f)):
                os.remove(os.path.join(labdir, f))  # never read a previous run's record
        rc, _out = cassian("test", lab, *args)
        try:
            res = json.load(open(os.path.join(labdir, "results.json"), encoding="utf-8"))
        except Exception:  # noqa: BLE001 -- a run that wrote nothing is judged by the caller
            res = {}
        return rc, res if isinstance(res, dict) else {}

    # L1 -- the guard (S37-R6)
    t0, hold, nb = time.time(), None, {}
    while time.time() - t0 < HOLD_READ_S:
        nb_raw, nb = neighbour()
        hold = established_hold(nb_raw, rip)
        if hold is not None:
            break
        time.sleep(2)
    ka = nb.get("bgpTimerKeepAliveIntervalMsecs")
    print("     information only, not judged: negotiated hold %s ms plus keepalive %s ms = %s ms, against N = %d ms; "
          "configured hold %s ms, keepalive %s ms"
          % (hold, ka, (hold + ka) if isinstance(hold, int) and isinstance(ka, int) else None, n_s * 1000,
             nb.get("bgpTimerConfiguredHoldTimeMsecs"), nb.get("bgpTimerConfiguredKeepAliveIntervalMsecs")))
    if not check("L1 the guard (S37-R6): %s's neighbour %s reads Established within %d s and its negotiated hold "
                 "time, %s ms, is below N = %d s" % (sn, rip, HOLD_READ_S, hold, n_s), hold_below(hold, n_s),
                 "after %.0f s" % (time.time() - t0)):
        print("FINDING (S37-R6): the negotiated hold time on this boot is %s ms, not below N = %d s, or the session "
              "did not come up; neither the control nor the scenario is run." % (hold, n_s))
        for leg in ("L2 the control", "L3 the scenario", "L4 the fault took effect", "L5 the detection",
                    "L6 the summary", "L7 the guest-not-wrapper control"):
            blocked.append((leg, "NOT ATTEMPTED -- the guard (L1) did not pass"))
        return

    # L2 -- the control, before the fault
    rc, cres = run("--name", name)
    for t in cres.get("tests") or []:
        print("     control record: %s" % json.dumps(t, sort_keys=True))
    seen = ["%s observed %s (%s)" % (t.get("name"), t.get("observed"), t.get("error") or "no error")
            for t in cres.get("tests") or [] if isinstance(t, dict)]
    if not check("L2 the control (§15.2 -22 negative): `cassian test %s --name %s` exits 0 and records %s passed on "
                 "%s toward %s, state Established, with no scenario run" % (lab, name, name, sn, rip),
                 control_ok(rc, cres, name, sn, rip), "rc=%d" % rc):
        print("FINDING (S37-R5): the control did not pass before the fault on this boot -- rc %d, result %s, "
              "records: %s. The invariant failed, or the run stopped before it ran; no fault is applied."
              % (rc, cres.get("result"), "; ".join(seen) or "none"))
        for leg in ("L3 the scenario", "L4 the fault took effect", "L5 the detection", "L6 the summary",
                    "L7 the guest-not-wrapper control"):
            blocked.append((leg, "NOT ATTEMPTED -- the control (L2) did not pass"))
        return

    # L3 -- the scenario
    rc, res = run("--scenario", sid)
    check("L3 the scenario: `cassian test %s --scenario %s` exits 1 and records the scenario failed -- fault pass, "
          "wait %d s pass, run fail, steps 1 to 3 -- with the result fail and no hard failure" % (lab, sid, n_s),
          scenario_ok(rc, res, sid, name, n_s), "rc=%d" % rc)
    for e in res.get("events") or []:
        print("     event: %s" % json.dumps(e, sort_keys=True))

    # L4 -- the fault took effect
    _rq, q = launcher(["tc", "-s", "qdisc", "show", "dev", sif], lines=8)
    _rl, link = launcher(["cat", "/sys/class/net/%s/carrier" % sif, "/sys/class/net/%s/operstate" % sif], lines=0)
    print("     information only, not judged: the launcher's %s carrier and operstate after the scenario: %s"
          % (sif, " ".join(link.split()) or "(none read)"))
    fault_took = fault_ok(res, sid, 1, sn, sif) and qdisc_ok(q, LOSS)
    check("L4 the fault took effect: step 1's scenario_fault event passed, packet_loss %d on %s:%s; the launcher's "
          "%s carries the netem root qdisc with loss %d%% and has dropped packets" % (LOSS, sn, sif, sif, LOSS),
          fault_took)

    # L5 -- the detection
    ev3 = find_event(res, sid, name, 3)
    ok5 = check("L5 REQ-45D-22 (VM), S37-R14: step 3's run of %s, expect pass, is observed fail with verdict fail, its "
                "read parsed, and its observed_state names %s from %s with a state other than Established"
                % (name, rip, sn), ev3 is not None and detection_ok(ev3, sn, rip),
                "observed_state %s" % json.dumps((ev3 or {}).get("observed_state"), sort_keys=True))
    _raw, nb_after = neighbour()
    print("     information only, not judged: after the scenario, %s's neighbour %s reads %s"
          % (sn, rip, ", ".join("%s=%s" % (k, json.dumps(nb_after.get(k))) for k in RESET_KEYS)))
    if not ok5 and ev3 is not None and ev3.get("verdict") == "pass" and fault_took:
        print("FINDING (S37-R1, S37-R5): the fault took effect and the session still read Established after %d s; "
              "nothing lands, and the result returns to the founder as a card." % n_s)

    # L6 -- the summary
    try:
        summ = open(os.path.join(labdir, "results.summary.txt"), encoding="utf-8").read()
    except OSError:
        summ = ""
    check("L6 S37-R14: results.summary.txt names %s failed in its CI header and renders step 3 verdict=fail"
          % sid, summary_ok(summ, sid, name))
    st = ((ev3 or {}).get("observed_state") or {}).get("state")
    shown = bool(st) and ("state: %s" % st) in [l.strip() for l in summ.split("\n")]
    print("     information only, not judged (BL-P2-4.5c-237): results.summary.txt %s a line `state: %s`"
          % ("carries" if shown else "does not carry", st))

    # L7 -- the guest-not-wrapper control
    probe = launcher(LAUNCHER_PROBE)
    out = launcher(list(S._BGP_SUMMARY_ARGV))
    check("L7 the guest-not-wrapper control: the launcher answers `%s`, and its output for the BGP summary read "
          "carries no peer entry for %s" % (" ".join(LAUNCHER_PROBE), rip), launcher_lacks(probe, out, rip),
          "probe rc=%s; summary rc=%s" % (probe[0], out[0]))


argv = sys.argv[1:]
if not argv:
    for leg in ("L1 the guard (S37-R6)", "L2 the control", "L3 the scenario", "L4 the fault took effect",
                "L5 REQ-45D-22 the detection", "L6 the summary", "L7 guest-not-wrapper control"):
        blocked.append((leg, "no live argv: run `live <topo> <lab>` on a lab that is up"))
elif argv[0] == "live" and len(argv) == 3:
    live(argv[1], argv[2])
else:
    sys.exit("usage: sonic_grey_failure_proof.py [live <topo> <lab>]")

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
