#!/usr/bin/env python3
"""Exec on a SONiC guest (§4.5-d VM-4; scope §9 row 9): REQ-45D-5's live leg, with REQ-45D-31.

Founder rulings S35-R1 to S35-R6 of 2026-10-19 (the session-35 rulings note,
cassian-gate-internal@7080d97, Ledger §156). One fixture, one boot (LD-45D-6):
topologies/sonic-exec-live.yaml -- one frr node and one sonic-vm guest, and three declared
exec tests on the guest.

REQ-45D-5's rule is decided once, at validate, in the model (PBE-1b-9): for a sonic-vm
node the SONiC provider admits `show …` and `vtysh -c "show …"` and refuses everything
else. This file proves the admitted forms run ON THE GUEST through the product's own
path -- `cassian test` -> run_exec_test -> rt.exec -> NodeDispatchingRuntime ->
VmRuntime.exec, over the wrapper chain to the guest -- with the guest's output recorded as
the test's evidence; and that a refused command stops at validate.

Lab-free legs (always run):
  F   the live fixture's shape, derived values only; the fixture validates (the control
      for V: the same node type, an admitted command, validate passes).
  V   REQ-45D-5 refused (handover §18 row -5, §19 Walkthrough 2; S35-R2): `cassian
      validate topologies/sonic-exec-refused.yaml` exits 2 with exactly one error line,
      the landed rejection line, byte for byte.
  NV  REQ-45D-31 two-directional non-vacuity for each predicate this file applies to the
      product's output: a complete synthetic observation satisfies it, and a mutation in
      each direction -- too much and too little -- is detected. Printed in handover §18's
      literal form, `MUTATION-FAIL: too-much (<label>)` and `MUTATION-FAIL: too-little
      (<label>)` (S35-R3).

Live legs (`live <topo> <lab>`, on a lab already up):
  L1  REQ-45D-5 (VM): exec_show_version, by `cassian test --name`: exit 0, verdict pass,
      and the record's evidence holds the guest's output -- return code 0, the SONiC
      version banner in stdout.
  L2  REQ-45D-5 (VM): exec_vtysh_show_version, likewise, with FRRouting's banner.
  L3  the guest-not-wrapper control (S35-R1): the same two commands sent through the
      product's substrate_exec, which reaches the vrnetlab launcher that wraps the guest,
      produce neither banner, while a plain command there succeeds -- so the banners in
      L1's and L2's evidence can only have come from the guest.
  L4  the live negative: exec_show_version_absent (expect fail): exit 0, observed fail,
      verdict pass, and its evidence carries the guest's version banner with return code
      0 -- the command ran on the guest and only the assertion failed.

usage:
  sonic_exec_live_proof.py                    lab-free legs; L1-L4 BLOCKED; exit 0 if green
  sonic_exec_live_proof.py live <topo> <lab>  lab-free legs, then L1-L4 on a lab already up

Coverage limits, stated in-file (PBE-P2-8):
  - One boot of one fixture, two commands, one in each admitted form. It proves the
    product's exec path reaches the shipped guest image and records its output; it does
    not prove every `show …` command completes inside the engine's 30-second exec
    timeout or without a prompt (none is run here).
  - The evidence is the engine's record, capped at 4096 characters per stream; the
    banners are near the start of each command's output.
  - L3 reads the launcher through substrate_exec; it does not inspect the wrapper chain.
  - V pins the landed line; a provider added to the registry changes its Allowed clause,
    and this file's pin with it.

Exit 0 when every check passes (BLOCKED or NOT ATTEMPTED legs are listed); exit 1 otherwise.
"""
import json
import os
import subprocess
import sys

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

FIXTURE = os.path.join(ROOT, "topologies", "sonic-exec-live.yaml")
REFUSED = os.path.join(ROOT, "topologies", "sonic-exec-refused.yaml")
T_SHOW, T_VTYSH, T_ABSENT = "exec_show_version", "exec_vtysh_show_version", "exec_show_version_absent"
ORDER = (T_SHOW, T_VTYSH, T_ABSENT)
SONIC_BANNER, FRR_BANNER = "SONiC Software Version", "FRRouting"
LAUNCHER_PROBE = ["uname", "-s"]
# The landed rejection line for topologies/sonic-exec-refused.yaml (S35-R2), measured on
# cassian-gate@28ea1fc in session 35 and pinned byte for byte.
REFUSED_LINE = ("ERROR: tests[1] (exec_refused): exec command rejected — 'config interface startup"
                " Ethernet0' is not read-only for node 's1' (type 'sonic-vm'): sonic-vm exec commands"
                " must be read-only 'show …' or 'vtysh -c \"show …\"'. Allowed: frr -> vtysh -c"
                " \"show …\"; nft-fw -> nft list …; sonic-vm -> show … or vtysh -c \"show …\""
                " (not show techsupport)")

checks, blocked = [], []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))
    return bool(ok)


def _text(x):
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")


# ---- declared values: derived from the fixture, never carried as literals -----------------
def declared(doc):
    nodes = {n.get("name"): n for n in (doc.get("nodes") or []) if isinstance(n, dict)}
    son = [n for n in nodes.values() if str(n.get("type")) == "sonic-vm"]
    frr = [n for n in nodes.values() if str(n.get("type")) == "frr"]
    if len(son) != 1 or len(frr) != 1 or len(nodes) != 2:
        return None
    tests = {t.get("name"): t for t in (doc.get("tests") or []) if isinstance(t, dict)}
    return {"s": son[0], "s_name": son[0]["name"], "r_name": frr[0]["name"], "tests": tests}


# ---- predicates applied to the product's output (each one has a two-directional NV) -------
def _ev(rec):
    return rec.get("evidence") or {}


def exec_ok(rec, node, command, banner):
    """An expect-pass exec record that passed on the guest, with the guest's output as evidence."""
    if not rec:
        return False
    ev = _ev(rec)
    return (rec.get("kind") == "exec" and rec.get("from") == node
            and ((rec.get("meta") or {}).get("exec") or {}).get("command") == command
            and rec.get("expected") == "pass" and rec.get("observed") == "pass" and rec.get("verdict") == "pass"
            and ev.get("returncode") == 0 and banner in _text(ev.get("stdout")))


def negative_ok(rec, node, command, banner):
    """An expect-fail exec record whose command ran on the guest (its output is the evidence)
    and whose assertion alone failed: observed fail, verdict pass."""
    if not rec:
        return False
    ev = _ev(rec)
    return (rec.get("kind") == "exec" and rec.get("from") == node
            and ((rec.get("meta") or {}).get("exec") or {}).get("command") == command
            and rec.get("expected") == "fail" and rec.get("observed") == "fail" and rec.get("verdict") == "pass"
            and ev.get("returncode") == 0 and banner in _text(ev.get("stdout")))


def launcher_lacks(probe, outs, banners):
    """The guest-not-wrapper control: the launcher answers a plain command (probe = (rc, text)),
    and none of its outputs for the guest's commands carries a guest banner."""
    return probe[0] == 0 and bool(probe[1].strip()) and all(
        b not in out for (_rc, out) in outs for b in banners)


def refused_ok(rc, out):
    """V: exit 2 and exactly one error line, the landed rejection line."""
    errs = [ln for ln in _text(out).splitlines() if ln.startswith("ERROR")]
    return rc == 2 and errs == [REFUSED_LINE]


def find_test(res, name):
    hits = [t for t in res.get("tests") or [] if t.get("name") == name]
    return hits[0] if len(hits) == 1 else None


def cassian(*args, timeout=1800):
    r = subprocess.run([sys.executable, os.path.join(SRC, "cassian.py")] + list(args), cwd=ROOT,
                       env=dict(os.environ, PYTHONPATH="src"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout)
    out = _text(r.stdout)
    print("---- cassian %s -> rc=%d" % (" ".join(args), r.returncode))
    for ln in out.rstrip("\n").split("\n")[-25:]:
        print("     | " + ln)
    return r.returncode, out


# ---- F: the fixture --------------------------------------------------------------------
DOC = yaml.safe_load(open(FIXTURE, encoding="utf-8").read()) or {}
D = declared(DOC)
check("F one frr node and one sonic-vm node, nothing else", D is not None)
if D is not None:
    t = D["tests"]
    check("F the sonic-vm node runs as vm (one guest; single-SONiC-node ceiling)", D["s"].get("runtime") == "vm")
    check("F the three declared tests, in order", list(t) == list(ORDER), "%s" % list(t))
    if list(t) == list(ORDER):
        check("F every test is an exec test on the SONiC node",
              all(t[n].get("kind") == "exec" and t[n].get("src") == D["s_name"] for n in ORDER))
        check("F the commands: show version; vtysh -c \"show version\"; show version again",
              [t[n].get("command") for n in ORDER] == ["show version", 'vtysh -c "show version"', "show version"])
        check("F the assertions: the SONiC banner; FRRouting's banner; a string absent from the first",
              t[T_SHOW].get("assertion") == {"contains": SONIC_BANNER}
              and t[T_VTYSH].get("assertion") == {"contains": FRR_BANNER}
              and list((t[T_ABSENT].get("assertion") or {}).keys()) == ["contains"]
              and str(t[T_ABSENT]["assertion"]["contains"]) not in (SONIC_BANNER, FRR_BANNER))
        check("F expectations: pass, pass, fail", [str(t[n].get("expect")) for n in ORDER] == ["pass", "pass", "fail"])
_rc, _out = cassian("validate", FIXTURE)
check("F the fixture validates: both admitted forms pass the model's rule for sonic-vm", _rc == 0, "rc=%d" % _rc)

# ---- V: the refused command stops at validate ------------------------------------------
_rdoc = yaml.safe_load(open(REFUSED, encoding="utf-8").read()) or {}
_rt = [x for x in (_rdoc.get("tests") or []) if isinstance(x, dict)]
check("V the refused fixture declares one exec test on its sonic-vm node, with a well-formed assertion",
      len(_rt) == 1 and _rt[0].get("kind") == "exec"
      and any(n.get("name") == _rt[0].get("src") and n.get("type") == "sonic-vm" for n in _rdoc.get("nodes") or [])
      and list((_rt[0].get("assertion") or {}).keys()) == ["contains"])
_vrc, _vout = cassian("validate", REFUSED)
check("V REQ-45D-5: `cassian validate topologies/sonic-exec-refused.yaml` exits 2 with the landed line, "
      "and no other error", refused_ok(_vrc, _vout), "rc=%d" % _vrc)


# ---- NV: two-directional non-vacuity per predicate (synthetic, device-independent) -------
def nv(label, pred, complete, too_much, too_little):
    a, b, c = pred(complete), pred(too_much), pred(too_little)
    ok = check("NV %s: complete passes, too-much and too-little are detected" % label, a and not b and not c,
               "complete=%s too-much=%s too-little=%s" % (a, b, c))
    if ok:
        print("  MUTATION-FAIL: too-much (%s)" % label)
        print("  MUTATION-FAIL: too-little (%s)" % label)


SN, CMD = "s1", "show version"
_OUT = "%s: SONiC.202405.0-synthetic\nDistribution: Debian 12\n" % SONIC_BANNER


def rec(**kw):
    base = {"name": T_SHOW, "kind": "exec", "from": SN, "to": "", "expected": "pass", "observed": "pass",
            "verdict": "pass", "meta": {"exec": {"command": CMD, "assertion": {"contains": SONIC_BANNER}}},
            "evidence": {"stdout": _OUT, "stderr": "", "returncode": 0, "truncated": False}}
    ev = dict(base["evidence"], **kw.pop("evidence", {}))
    meta = kw.pop("meta", None)
    base.update(kw)
    base["evidence"] = ev
    if meta is not None:
        base["meta"] = meta
    return base


nv("exec_ok", lambda x: exec_ok(x, SN, CMD, SONIC_BANNER), rec(),
   rec(meta={"exec": {"command": "show ip route", "assertion": {"contains": SONIC_BANNER}}}),
   rec(evidence={"stdout": "", "returncode": None}))
nv("exec_ok (node)", lambda x: exec_ok(x, SN, CMD, SONIC_BANNER), rec(), rec(**{"from": "r1"}),
   rec(observed="fail", verdict="fail", evidence={"stdout": "Usage: show [OPTIONS] COMMAND\n", "returncode": 2}))
nv("negative_ok", lambda x: negative_ok(x, SN, CMD, SONIC_BANNER),
   rec(expected="fail", observed="fail", verdict="pass"),
   rec(expected="fail", observed="pass", verdict="fail"),
   rec(expected="fail", observed="fail", verdict="pass", evidence={"stdout": "", "returncode": None}))
_NF = "OCI runtime exec failed: exec: \"show\": executable file not found in $PATH"
nv("launcher_lacks", lambda x: launcher_lacks(x[0], x[1], (SONIC_BANNER, FRR_BANNER)),
   ((0, "Linux\n"), [(127, _NF), (127, _NF.replace("show", "vtysh"))]),
   ((0, "Linux\n"), [(0, _OUT), (127, _NF.replace("show", "vtysh"))]),
   ((1, ""), [(127, ""), (127, "")]))
nv("refused_ok", lambda x: refused_ok(*x), (2, REFUSED_LINE + "\n"),
   (2, REFUSED_LINE.replace("; sonic-vm -> show … or vtysh -c \"show …\" (not show techsupport)", "") + "\n"),
   (0, "✅ VALIDATE PASS: topologies/sonic-exec-refused.yaml\n"))
nv("refused_ok (one line)", lambda x: refused_ok(*x), (2, REFUSED_LINE + "\n"),
   (2, REFUSED_LINE + "\nERROR: tests[2] (x): exec command rejected\n"), (1, REFUSED_LINE + "\n"))
nv("find_test", lambda x: find_test(x, T_SHOW) is not None, {"tests": [rec()]}, {"tests": [rec(), rec()]},
   {"tests": [rec(name=T_VTYSH)]})


# ---- live legs ---------------------------------------------------------------------------
def run_test(lab, name):
    path = os.path.join(ROOT, "labs", "clab-%s" % lab, "results.json")
    if os.path.exists(path):
        os.remove(path)  # never read a previous run's record
    rc, _ = cassian("test", lab, "--name", name)
    try:
        res = json.load(open(path, encoding="utf-8"))
    except Exception:  # noqa: BLE001 -- a run that wrote nothing is judged by the caller
        res = {}
    r = find_test(res, name)
    if r:
        shown = json.loads(json.dumps(r))
        so = _text((shown.get("evidence") or {}).get("stdout"))
        if len(so) > 600:
            shown["evidence"]["stdout"] = so[:600] + "...[%d chars]" % len(so)
        print("     record: %s" % json.dumps(shown, sort_keys=True))
    else:
        print("     record: (none)")
    return rc, r


def live(topo, lab):
    if os.path.realpath(topo) != os.path.realpath(FIXTURE) or lab != DOC.get("name") or D is None \
            or list(D["tests"]) != list(ORDER):
        check("LIVE argv names the exec-live fixture and its lab", False, "%s %s" % (topo, lab))
        return
    sn, t = D["s_name"], D["tests"]

    rc, r1 = run_test(lab, T_SHOW)
    check("L1 REQ-45D-5 (VM): `%s` on %s through the product's exec path: exit 0, verdict pass, the guest's "
          "output recorded (return code 0, %r in stdout)" % (t[T_SHOW]["command"], sn, SONIC_BANNER),
          rc == 0 and exec_ok(r1, sn, t[T_SHOW]["command"], SONIC_BANNER), "rc=%d" % rc)
    rc, r2 = run_test(lab, T_VTYSH)
    check("L2 REQ-45D-5 (VM): `%s` on %s through the product's exec path: exit 0, verdict pass, the guest's "
          "output recorded (return code 0, %r in stdout)" % (t[T_VTYSH]["command"], sn, FRR_BANNER),
          rc == 0 and exec_ok(r2, sn, t[T_VTYSH]["command"], FRR_BANNER), "rc=%d" % rc)

    import cassian_runtime_vm as RV  # the product's runtime seam, as the other (VM) proofs use it
    import shlex
    rt = RV.build_runtime(DOC)

    def launcher(cmd):
        cp = rt.substrate_exec(lab, sn, cmd, check=False, capture_output=True, timeout_s=30)
        out = _text(cp.stdout) + _text(getattr(cp, "stderr", ""))
        print("     launcher(%s)$ %s -> rc=%s\n%s" % (sn, " ".join(cmd), cp.returncode,
                                                    "\n".join("       " + l for l in out.rstrip("\n").split("\n"))))
        return cp.returncode, out

    probe = launcher(LAUNCHER_PROBE)
    outs = [launcher(shlex.split(t[n]["command"])) for n in (T_SHOW, T_VTYSH)]
    check("L3 the guest-not-wrapper control (S35-R1): the launcher answers `%s`, and the same two commands "
          "through substrate_exec carry neither banner" % " ".join(LAUNCHER_PROBE),
          launcher_lacks(probe, outs, (SONIC_BANNER, FRR_BANNER)),
          "probe rc=%s; rcs %s" % (probe[0], [o[0] for o in outs]))

    rc, r4 = run_test(lab, T_ABSENT)
    check("L4 the live negative: `%s` with an assertion its output never satisfies: exit 0, observed fail, "
          "verdict pass, and the guest's output recorded (return code 0, %r in stdout)"
          % (t[T_ABSENT]["command"], SONIC_BANNER),
          rc == 0 and negative_ok(r4, sn, t[T_ABSENT]["command"], SONIC_BANNER), "rc=%d" % rc)
    if not (r1 and exec_ok(r1, sn, t[T_SHOW]["command"], SONIC_BANNER)):
        print("FINDING (S35-R1): `%s` did not run on the guest with its output recorded on this boot; the "
              "packet stops and returns to the founder." % t[T_SHOW]["command"])


argv = sys.argv[1:]
if not argv:
    for leg in ("L1 REQ-45D-5 show", "L2 REQ-45D-5 vtysh show", "L3 guest-not-wrapper control",
                "L4 live negative"):
        blocked.append((leg, "no live argv: run `live <topo> <lab>` on a lab that is up"))
elif argv[0] == "live" and len(argv) == 3:
    live(argv[1], argv[2])
else:
    sys.exit("usage: sonic_exec_live_proof.py [live <topo> <lab>]")

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
