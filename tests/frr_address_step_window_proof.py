#!/usr/bin/env python3
"""BL-P2-4.5c-233 -- the FRR interface step's address window (§4.5-d, S33-R4).

Founder rulings S33-R1 to S33-R5 (the session-33 rulings note,
cassian-gate-internal@c0f00a5, Ledger §150). `cmd_up` runs
`configure_frr_interfaces_from_topology` right after deploy: for each FRR link
endpoint it brings the link up, flushes its addresses and sets the declared
address; for an FRR node with a router_id it does the same on `lo` with
router_id/32. The generated frr.conf configures the same addresses, so FRR's
zebra, starting in the same moments, can install an address between the
flush and the set. With `ip addr add ... check=True` that made the whole `up`
fail with `Address already assigned` (CI run 39054777900 attempt 1, run
39132619409 attempt 1). S33-R3: the set is `ip addr replace`, `check=True`,
the flush and the link-up calls unchanged; S33-R2: at the loopback call too.

Legs:
  (S) static, lab-free: in `configure_frr_interfaces_from_topology` the link
      and loopback address calls are `ip addr replace ... check=True`, the
      link-up and flush calls are unchanged, and no `ip addr add` remains in
      the function; the module's other two `ip addr add` calls
      (`host_configure`, `configure_nftfw_from_topology`) are untouched. A
      control re-runs the predicate on the source with `replace` turned back
      into `add` and requires it to fail.
  (F) lab-free, a recording runtime: the product issues, per FRR endpoint and
      for `lo`, link-up (check off), flush (check off), replace (check on), in
      that order; non-FRR endpoints and FRR nodes without a router_id get no
      call. It records argv only; it models nothing about `ip`.
  (D) Docker (S33-R4): the pinned FRR image (cassian_nos_frr.FRR_DEFAULT_IMAGE),
      started privileged (as frr_nos_ready_proof.py starts it), with a veth
      `eth1` created inside it. The product's own function is driven through
      the product's ContainerRuntime, wrapped so that right after the
      product's `ip addr flush dev <iface>` has run, the proof installs the
      identical address -- standing in for zebra -- and then lets the
      product's next call run. Every product call goes to the runtime with the
      product's own `check`, so a failure is raised by the runtime itself; the
      one flag the wrapper changes is output capture on the address call, so
      its error text can be read:
        (i)   control: under the same injection, the product's address call
              rewritten to `ip addr add` (the pre-fix form) fails with
              `Address already assigned` (CalledProcessError, rc 2);
        (ii)  fixed: the product's call completes and exactly one identical
              address is on the interface;
        (iii) no injection: the call completes, exactly one address;
        (iv)  missing device: an endpoint on an interface the container lacks
              makes the step fail loud (CalledProcessError, rc != 0);
        (v)   loopback: the same window at `flush dev lo`: the control fails,
              the fixed call completes, exactly one router_id/32 on lo.
      Every injected leg also checks that its injection was reached: the
      injected add returned 0 and the address was present immediately before
      the product's call. The image's `ip -V` is printed and must be iproute2.
      This leg needs a container runtime; it fails rather than skipping.

COVERAGE LIMIT (PBE-P2-8): the window is opened by the proof, deterministically;
this does NOT reproduce zebra's own start-up timing, nor prove anything about
`cmd_up` as a whole, other FRR images, or IPv6 (the step sets IPv4 only). It
proves the step tolerates an identical address present at its call, on the
pinned image's `ip`, and still fails loud where the call itself fails.
"""
import ast
import os
import shutil
import subprocess
import sys

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, _SRC)

import cassian_common as CM  # noqa: E402
import cassian_nos_frr as F  # noqa: E402
import cassian_runtime_container as RC  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


FUNC = "configure_frr_interfaces_from_topology"
LINK_CIDR, PEER_CIDR, RID = "198.51.100.1/31", "198.51.100.0/31", "192.0.2.21"
LINK_UP = 'rt.exec(lab, node, ["ip", "link", "set", iface, "up"], check=False, capture_output=False)'
LINK_FLUSH = 'rt.exec(lab, node, ["ip", "addr", "flush", "dev", iface], check=False, capture_output=False)'
LINK_SET = 'rt.exec(lab, node, ["ip", "addr", "replace", ipcidr, "dev", iface], check=True, capture_output=False)'
LO_UP = 'rt.exec(lab, node, ["ip", "link", "set", "lo", "up"], check=False, capture_output=False)'
LO_FLUSH = 'rt.exec(lab, node, ["ip", "addr", "flush", "dev", "lo"], check=False, capture_output=False)'
LO_SET = 'rt.exec(lab, node, ["ip", "addr", "replace", f"{rid}/32", "dev", "lo"], check=True, capture_output=False)'
ADD = '"ip", "addr", "add"'


# --- leg S: static ----------------------------------------------------------------

def _func_sources(text):
    tree = ast.parse(text)
    return {n.name: ast.get_source_segment(text, n) for n in tree.body
            if isinstance(n, ast.FunctionDef)}


def _static(text):
    """Return a list of failed predicate names (empty = all hold)."""
    bad = []
    fs = _func_sources(text)
    body = fs.get(FUNC) or ""
    for label, line in (("link-up", LINK_UP), ("link flush", LINK_FLUSH), ("link replace", LINK_SET),
                        ("lo up", LO_UP), ("lo flush", LO_FLUSH), ("lo replace", LO_SET)):
        if body.count(line) != 1:
            bad.append("%s call present once in %s" % (label, FUNC))
    if ADD in body:
        bad.append("no ip addr add left in %s" % FUNC)
    if text.count(ADD) != 2:
        bad.append("the module carries exactly two other ip addr add calls")
    for other in ("host_configure", "configure_nftfw_from_topology"):
        if (fs.get(other) or "").count(ADD) != 1:
            bad.append("one ip addr add in %s" % other)
    return bad


with open(os.path.join(_SRC, "cassian_runtime_container.py"), encoding="utf-8") as fh:
    _text = fh.read()
_bad = _static(_text)
check("(S) %s: link and loopback calls are `ip addr replace` with check=True; link-up and flush "
      "unchanged; no `ip addr add` left in it; host_configure and configure_nftfw_from_topology "
      "keep their one `ip addr add` each" % FUNC, not _bad, "; ".join(_bad))
_reverted = _text.replace('["ip", "addr", "replace",', '["ip", "addr", "add",')
check("(S) control: with `replace` turned back into `add`, the static predicate fails",
      _reverted != _text and len(_static(_reverted)) >= 3, repr(_static(_reverted))[:200])


# --- leg F: the call sequence, lab-free -------------------------------------------

class _CP:
    def __init__(self, rc=0):
        self.returncode, self.stdout, self.stderr, self.args = rc, "", "", []


class _Rec:
    def __init__(self):
        self.calls = []

    def exec(self, lab, node, cmd, check=False, capture_output=True, **kw):
        self.calls.append((node, list(cmd), check))
        return _CP(0)


_topo = {"nodes": [{"name": "r1", "type": "frr", "router_id": RID},
                   {"name": "r2", "type": "frr"},
                   {"name": "h1", "type": "linux"}],
         "links": [{"endpoints": ["r1:eth1", "h1:eth1"], "ipv4": [LINK_CIDR, PEER_CIDR]},
                   {"endpoints": ["r1:eth2", "r2:eth1"], "ipv4": ["198.51.100.2/31", "198.51.100.3/31"]}]}
_rec = _Rec()
RC.configure_frr_interfaces_from_topology(_rec, "lab", _topo)
_want = [
    ("r1", ["ip", "link", "set", "eth1", "up"], False),
    ("r1", ["ip", "addr", "flush", "dev", "eth1"], False),
    ("r1", ["ip", "addr", "replace", LINK_CIDR, "dev", "eth1"], True),
    ("r1", ["ip", "link", "set", "eth2", "up"], False),
    ("r1", ["ip", "addr", "flush", "dev", "eth2"], False),
    ("r1", ["ip", "addr", "replace", "198.51.100.2/31", "dev", "eth2"], True),
    ("r2", ["ip", "link", "set", "eth1", "up"], False),
    ("r2", ["ip", "addr", "flush", "dev", "eth1"], False),
    ("r2", ["ip", "addr", "replace", "198.51.100.3/31", "dev", "eth1"], True),
    ("r1", ["ip", "link", "set", "lo", "up"], False),
    ("r1", ["ip", "addr", "flush", "dev", "lo"], False),
    ("r1", ["ip", "addr", "replace", RID + "/32", "dev", "lo"], True),
]
check("(F) per FRR endpoint and for lo: link-up, flush (check off), replace (check on), in order; "
      "the linux endpoint and r2 (no router_id) get no other call", _rec.calls == _want,
      repr(_rec.calls)[:300])


# --- leg D: Docker ----------------------------------------------------------------

_LAB, _NODE = "frraddrwindowproof", "r1"
_CN = "clab-%s-%s" % (_LAB, _NODE)


class _Inject:
    """Wraps the product's runtime: after the product's flush of `iface` has run,
    install `cidr` on `iface` (zebra's part), then let the product's next call run.
    With `as_add`, the product's `ip addr replace` on `iface` is issued as `ip addr add`
    (the pre-fix form) -- the control."""

    def __init__(self, rt, iface, cidr=None, as_add=False):
        self.rt, self.iface, self.cidr, self.as_add = rt, iface, cidr, as_add
        self.injected = False
        self.present_before = None
        self._pending = False

    def _has(self, lab, node):
        cp = self.rt.exec(lab, node, ["ip", "-o", "-4", "addr", "show", "dev", self.iface],
                          check=False, capture_output=True)
        return cp.returncode == 0 and (" inet %s " % self.cidr) in (cp.stdout or "")

    def exec(self, lab, node, cmd, check=False, capture_output=True, **kw):
        cmd = list(cmd)
        is_set = cmd[:3] in (["ip", "addr", "add"], ["ip", "addr", "replace"]) and cmd[-1] == self.iface
        if self.as_add and is_set and cmd[2] == "replace":
            cmd[2] = "add"
        if self._pending and is_set:
            self.present_before = self._has(lab, node)
            self._pending = False
        # The product's call, through the product's runtime, with the product's own `check`:
        # a failure is raised by the runtime itself. Only the address call's output is
        # captured (the product passes capture_output=False), so its error text can be read.
        cp = self.rt.exec(lab, node, cmd, check=check, capture_output=capture_output or is_set, **kw)
        if self.cidr and cmd == ["ip", "addr", "flush", "dev", self.iface]:
            inj = self.rt.exec(lab, node, ["ip", "addr", "add", self.cidr, "dev", self.iface],
                               check=False, capture_output=True)
            self.injected = inj.returncode == 0
            self._pending = True
        return cp


def _dx(*cmd):
    return subprocess.run(["docker", "exec", _CN] + list(cmd), capture_output=True, text=True)


def _count(iface, cidr):
    cp = _dx("ip", "-o", "-4", "addr", "show", "dev", iface)
    return sum(1 for l in (cp.stdout or "").splitlines() if (" inet %s " % cidr) in l)


def _drive(rt, topo):
    """None when the product's function returns; otherwise the exception it raised."""
    try:
        RC.configure_frr_interfaces_from_topology(rt, _LAB, topo)
        return None
    except Exception as exc:  # recorded; the checks below require CalledProcessError
        return exc


def _cpe(e, rc=None):
    """`e` is the runtime's CalledProcessError (with return code `rc` when given)."""
    return isinstance(e, subprocess.CalledProcessError) and (rc is None or e.returncode == rc)


def _why(e):
    if e is None:
        return "completed"
    if isinstance(e, subprocess.CalledProcessError):
        return "rc=%d %s" % (e.returncode, (e.stderr or "").strip()[:120])
    return repr(e)[:160]


_LINK_TOPO = {"nodes": [{"name": _NODE, "type": "frr"}, {"name": "h1", "type": "linux"}],
              "links": [{"endpoints": ["%s:eth1" % _NODE, "h1:eth1"], "ipv4": [LINK_CIDR, PEER_CIDR]}]}
_MISSING_TOPO = {"nodes": [{"name": _NODE, "type": "frr"}, {"name": "h1", "type": "linux"}],
                 "links": [{"endpoints": ["%s:eth9" % _NODE, "h1:eth1"], "ipv4": [LINK_CIDR, PEER_CIDR]}]}
_LO_TOPO = {"nodes": [{"name": _NODE, "type": "frr", "router_id": RID}], "links": []}

if shutil.which("docker") is None:
    check("(D) Docker leg: docker not found. This leg needs a container runtime; "
          "it fails rather than skipping.", False)
else:
    subprocess.run(["docker", "rm", "-f", _CN], capture_output=True, text=True)
    _old_q = CM.QUIET_RUN
    try:
        _up = subprocess.run(["docker", "run", "-d", "--privileged", "--name", _CN, F.FRR_DEFAULT_IMAGE],
                             capture_output=True, text=True)
        check("(D) the pinned image started privileged (rc=%d) %s"
              % (_up.returncode, _up.stderr.strip()[:160]), _up.returncode == 0)
        if _up.returncode == 0:
            CM.QUIET_RUN = True
            _v = _dx("ip", "-V")
            print("INFO image ip: %s" % ((_v.stdout or _v.stderr).strip()[:120]))
            check("(D) the image's ip is iproute2", "iproute2" in (_v.stdout or "") + (_v.stderr or ""),
                  (_v.stdout or _v.stderr).strip()[:120])
            _veth = _dx("ip", "link", "add", "eth1", "type", "veth", "peer", "name", "eth1p")
            _peer = _dx("ip", "link", "set", "eth1p", "up")
            check("(D) a veth eth1 created in the container (rc=%d/%d) %s"
                  % (_veth.returncode, _peer.returncode, _veth.stderr.strip()[:120]),
                  _veth.returncode == 0 and _peer.returncode == 0)
            _rt = RC.get_runtime(None)
            check("(D) the product's runtime addresses the container by its lab name",
                  _rt.node_id(_LAB, _NODE) == _CN, _rt.node_id(_LAB, _NODE))

            # (i) control: link window, pre-fix `add`
            _w = _Inject(_rt, "eth1", LINK_CIDR, as_add=True)
            _e = _drive(_w, _LINK_TOPO)
            check("(i) injection reached at eth1 (injected add rc 0; present before the product's call)",
                  _w.injected and _w.present_before is True, "%r %r" % (_w.injected, _w.present_before))
            check("(i) control: pre-fix `ip addr add` under the window fails with `Address already "
                  "assigned` (rc 2)",
                  _cpe(_e, 2) and "Address already assigned" in (_e.stderr or ""), _why(_e))

            # (ii) fixed: link window, the product's own call
            _dx("ip", "addr", "flush", "dev", "eth1")
            _w = _Inject(_rt, "eth1", LINK_CIDR)
            _e = _drive(_w, _LINK_TOPO)
            check("(ii) injection reached at eth1", _w.injected and _w.present_before is True,
                  "%r %r" % (_w.injected, _w.present_before))
            check("(ii) fixed: the product's call completes under the window", _e is None, _why(_e))
            check("(ii) exactly one %s on eth1 afterwards" % LINK_CIDR, _count("eth1", LINK_CIDR) == 1,
                  str(_count("eth1", LINK_CIDR)))

            # (iii) no injection
            _dx("ip", "addr", "flush", "dev", "eth1")
            _w = _Inject(_rt, "eth1", None)
            _e = _drive(_w, _LINK_TOPO)
            check("(iii) no injection: nothing injected", not _w.injected, repr(_w.injected))
            check("(iii) no injection: the call completes, exactly one %s on eth1" % LINK_CIDR,
                  _e is None and _count("eth1", LINK_CIDR) == 1,
                  _why(_e) + " count=%d" % _count("eth1", LINK_CIDR))

            # (iv) missing device
            _w = _Inject(_rt, "eth9", None)
            _e = _drive(_w, _MISSING_TOPO)
            check("(iv) missing device eth9: the step fails loud (CalledProcessError, rc != 0)",
                  _cpe(_e) and _e.returncode != 0, _why(_e))

            # (v) loopback window: control, then fixed
            _rid = RID + "/32"
            _dx("ip", "addr", "flush", "dev", "lo")
            _w = _Inject(_rt, "lo", _rid, as_add=True)
            _e = _drive(_w, _LO_TOPO)
            check("(v) injection reached at lo", _w.injected and _w.present_before is True,
                  "%r %r" % (_w.injected, _w.present_before))
            check("(v) control: pre-fix `ip addr add` at lo under the window fails with `Address "
                  "already assigned` (rc 2)",
                  _cpe(_e, 2) and "Address already assigned" in (_e.stderr or ""), _why(_e))
            _dx("ip", "addr", "flush", "dev", "lo")
            _w = _Inject(_rt, "lo", _rid)
            _e = _drive(_w, _LO_TOPO)
            check("(v) injection reached at lo (fixed run)", _w.injected and _w.present_before is True,
                  "%r %r" % (_w.injected, _w.present_before))
            check("(v) fixed: the loopback call completes under the window, exactly one %s on lo" % _rid,
                  _e is None and _count("lo", _rid) == 1, _why(_e) + " count=%d" % _count("lo", _rid))
    finally:
        CM.QUIET_RUN = _old_q
        subprocess.run(["docker", "rm", "-f", _CN], capture_output=True, text=True)

_gone = subprocess.run(["docker", "inspect", _CN], capture_output=True, text=True) \
    if shutil.which("docker") else None
check("(D) the proof's container is removed", _gone is None or _gone.returncode != 0)

# --- report ----------------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _n, _ok, _d in _checks:
    print("%-4s %s%s" % ("PASS" if _ok else "FAIL", _n, ("  [%s]" % _d) if (_d and not _ok) else ""))
print("=" * 60)
if _failed:
    print("RESULT: FAIL -- %d of %d check(s) (BL-P2-4.5c-233 address-step window)"
          % (len(_failed), len(_checks)))
    sys.exit(1)
print("RESULT: PASS -- %d checks (BL-P2-4.5c-233 address-step window)" % len(_checks))
