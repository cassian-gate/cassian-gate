#!/usr/bin/env python3
"""Ping through SONiC (§4.5-d VM-3; scope §9 row 10): REQ-45D-3, REQ-45D-4, REQ-45D-26.

Founder rulings S34-R1 to S34-R4 of 2026-10-19 (the session-34 rulings note,
cassian-gate-internal@596499c, Ledger §153). One fixture, one boot (LD-45D-6):
topologies/sonic-ping-through.yaml -- one sonic-vm guest and two hosts, each attached
directly to it, and four declared ping tests from h1.

REQ-45D-26 travels with REQ-45D-3/-4 in one change (PBE-P2-11). Before it,
`configure_hosts_from_topology` configured a host only when its peer's type was in the
literal tuple ("frr", "linux", "nft-fw"), so a host on a sonic-vm peer kept nothing but
its management address -- and `verify_host_ready` still passed it, because it accepts
any global IPv4. The predicate is now registry-derived (LD-45D-3):
`set(nos_known_types()) | {"linux"}`, with `nos_known_types` added to the module's
existing `cassian_model` import under S34-R2's SP #1 amendment.

Lab-free legs (always run):
  F   the fixture's shape, derived values only; the fixture validates.
  S   static, -26: the two peer-type predicates in `configure_hosts_from_topology` read
      `set(nos_known_types()) | {"linux"}`; the module imports `nos_known_types` from
      `cassian_model`; no literal peer-type tuple is left (row -26's grep for
      `"nft-fw")` finds 0). A control runs the same predicate on the pre-fix text.
  R   behaviour, -26, through a recording runtime (it records argv and models nothing):
      a host on a frr, linux, nft-fw or sonic-vm peer, in either endpoint order, gets
      the product's host sequence -- link down, MAC, link up, flush, address, default
      route via the peer -- and a host on an unregistered type gets no call. Registry
      derivation, two-directional: with the registry read patched to add a type, a host
      on that type is configured; with sonic-vm withheld, a host on sonic-vm is not.
  T   the verify_host_ready trap, lab-free: the product's `verify_host_ready`, run on a
      simulated host holding only a management address, passes; this file's host
      predicate rejects the same host.
  NV  REQ-45D-31 two-directional non-vacuity for each predicate this file applies to
      the product's output: a complete synthetic observation satisfies it, and a
      mutation in each direction -- too much and too little -- is detected.

Live legs (`live <topo> <lab>`, on a lab already up):
  L1  REQ-45D-26 (VM): on each host, read through the product's runtime, the declared
      address on the link interface, the declared MAC, and exactly one default route,
      via the SONiC end of its link; from h1, the route to the far host and to the
      unused address goes via s1 on the link interface. Control: h1's live state does
      not satisfy h2's declaration.
  L2  REQ-45D-3/-4 (VM): the four declared tests, one `cassian test --name` each, in
      declared order. Each record's observed result and verdict must equal the table
      derived from the fixture -- observed pass iff the target is the far host's
      address; verdict by core's ping rule (S34-R3): pass iff observed equals expected
      -- and the exit code must be 0 iff the verdict is pass. The unreachable
      expect-fail quadrant is credited only when the reachable expect-pass quadrant
      passed on the same boot. An expect-fail ping makes one attempt.
  L3  the verify_host_ready trap, live: h1's link address is flushed through the
      product's runtime; h1 still holds a global IPv4 (its management address) and none
      on the link interface; the product's `verify_host_ready` passes it; this file's
      host predicate rejects it.

usage:
  sonic_ping_through_proof.py                    lab-free legs; L1-L3 BLOCKED; exit 0 if green
  sonic_ping_through_proof.py live <topo> <lab>  lab-free legs, then L1-L3 on a lab already up

Coverage limits, stated in-file (PBE-P2-8):
  - One boot of one fixture, IPv4 only, one direction of initiation (h1 to h2; the
    echo reply crosses s1 the other way). It proves the shipped image forwards between
    two of its front-panel ports for these declarations, not for every declaration.
  - S34-R3: the FRR-substrate verdict is read as core's ping rule, which takes no NOS
    input; no FRR lab is booted. The rule is restated here, not imported, so a change
    to the engine's rule shows up as a disagreement.
  - The trap leg's lab-free half simulates three `ip` outputs and the two shell probes
    `verify_host_ready` issues; its live half (L3) runs both on the real host.
  - L3 mutates h1 (its link address is flushed); it runs last, and the lab is torn
    down after this file runs.
  - `verify_host_ready` is never the instrument: no check here is credited by it.

Exit 0 when every check passes (BLOCKED or NOT ATTEMPTED legs are listed); exit 1 otherwise.
"""
import ast
import ipaddress
import json
import os
import subprocess
import sys

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

import cassian_model as M  # noqa: E402
import cassian_nos_sonic as S  # noqa: E402
import cassian_runtime_container as RC  # noqa: E402

FIXTURE = os.path.join(ROOT, "topologies", "sonic-ping-through.yaml")
RUNTIME_SRC = os.path.join(SRC, "cassian_runtime_container.py")
FUNC = "configure_hosts_from_topology"
T_RP, T_UF, T_RF, T_UP = "pt_reach_pass", "pt_unreach_fail", "pt_reach_fail", "pt_unreach_pass"
ORDER = (T_RP, T_UF, T_RF, T_UP)
DERIVED = 'in (set(nos_known_types()) | {"linux"})'
LITERAL = 'in ("frr", "linux", "nft-fw")'

checks, blocked = [], []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))
    return bool(ok)


def core_verdict(observed, expected):
    """S34-R3: core's ping rule, restated -- pass iff the observed result equals the expectation."""
    return "pass" if (observed == "pass") == (expected == "pass") else "fail"


# ---- declared values: derived from the fixture, never carried as literals -----------------
def declared(doc):
    nodes = {n.get("name"): n for n in (doc.get("nodes") or []) if isinstance(n, dict)}
    son = [n for n in nodes.values() if str(n.get("type")) == "sonic-vm"]
    hosts = [n for n in nodes.values() if str(n.get("type")) == "host"]
    if len(son) != 1 or len(hosts) != 2 or len(nodes) != 3:
        return None
    sn = son[0]["name"]
    att = {}
    for link in doc.get("links") or []:
        eps = [str(e) for e in link.get("endpoints") or []]
        ips = [str(i) for i in link.get("ipv4") or []]
        if len(eps) != 2 or len(ips) != 2:
            return None
        ends = {e.split(":", 1)[0]: (e.split(":", 1)[1], ip) for e, ip in zip(eps, ips)}
        hs = [h for h in ends if h != sn and h in (x["name"] for x in hosts)]
        if sn not in ends or len(hs) != 1:
            return None
        h = hs[0]
        att[h] = {"iface": ends[h][0], "cidr": ends[h][1], "gw": ends[sn][1].split("/")[0],
                  "s_iface": ends[sn][0], "s_cidr": ends[sn][1], "mac": str(nodes[h].get("mac") or "").lower()}
    tests = {t.get("name"): t for t in (doc.get("tests") or []) if isinstance(t, dict)}
    srcs = {str(t.get("src")) for t in tests.values()}
    if len(att) != 2 or len(srcs) != 1:
        return None
    near = srcs.pop()
    far = [h for h in att if h != near]
    if near not in att or len(far) != 1:
        return None
    far = far[0]
    tgt = {n: str(t.get("to_ip") or t.get("to") or "") for n, t in tests.items()}
    unreach = sorted({v for v in tgt.values() if v != att[far]["cidr"].split("/")[0]})
    return {"s": son[0], "s_name": sn, "near": near, "far": far, "att": att, "tests": tests, "tgt": tgt,
            "far_ip": att[far]["cidr"].split("/")[0], "unreach": unreach[0] if len(unreach) == 1 else None,
            "router_id": str(son[0].get("router_id") or "")}


def want_table(D):
    """{test: (expected, observed, verdict)} derived from the fixture: observed pass iff the
    target is the far host's address (the only address that answers); verdict by core's rule."""
    out = {}
    for n in ORDER:
        exp = str(D["tests"][n].get("expect") or "pass")
        obs = "pass" if D["tgt"][n] == D["far_ip"] else "fail"
        out[n] = (exp, obs, core_verdict(obs, exp))
    return out


def stock_hit(ip_or_net):
    n = ipaddress.ip_network(str(ip_or_net), strict=False)
    return any(n.overlaps(ipaddress.ip_network(p)) for p in S.SONIC_STOCK_PREFIXES if p != "0.0.0.0/0")


# ---- predicates applied to the product's output (each has a two-directional NV) ----------
def _text(x):
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")


def host_dataplane_ok(addr_out, route_out, link_out, iface, cidr, gw, mac):
    """REQ-45D-26: the declared address on the link interface (and only it there), exactly
    one default route, via the SONiC end on that interface, and the declared MAC."""
    inets = [l.split() for l in _text(addr_out).splitlines() if " inet " in l]
    on_if = [w[w.index("inet") + 1] for w in inets if len(w) > 1 and w[1] == iface and "inet" in w]
    defaults = [l.split() for l in _text(route_out).splitlines() if l.strip().startswith("default")]
    route_ok = (len(defaults) == 1 and "via" in defaults[0] and "dev" in defaults[0]
                and defaults[0][defaults[0].index("via") + 1] == gw
                and defaults[0][defaults[0].index("dev") + 1] == iface)
    lw = _text(link_out).split()
    mac_ok = "link/ether" in lw and lw[lw.index("link/ether") + 1].lower() == mac.lower()
    return on_if == [cidr] and route_ok and mac_ok


def route_via_ok(get_out, dst, gw, iface):
    """`ip -4 route get <dst>` on the near host: the first line names dst, via the SONiC
    end, out of the link interface."""
    lines = [l for l in _text(get_out).splitlines() if l.strip()]
    w = lines[0].split() if lines else []
    return (bool(w) and w[0] == dst and "via" in w and "dev" in w
            and w[w.index("via") + 1] == gw and w[w.index("dev") + 1] == iface)


def quadrant_ok(rec, near, dst_ip, want, rc):
    """One declared test's record: kind ping from the near host to the declared target;
    expected/observed/verdict as the derived table says; rc 0 iff verdict pass; an
    expect-fail ping makes exactly one attempt."""
    if not rec:
        return False
    exp, obs, ver = want
    m = rec.get("meta") or {}
    return (rec.get("kind") == "ping" and rec.get("from") == near and m.get("dst_ip") == dst_ip
            and rec.get("expected") == exp and rec.get("observed") == obs and rec.get("verdict") == ver
            and (rc == 0) == (ver == "pass") and (exp != "fail" or m.get("attempts") == 1))


def find_test(res, name):
    hits = [t for t in res.get("tests") or [] if t.get("name") == name]
    return hits[0] if len(hits) == 1 else None


def static_ok(text):
    """-26 static predicate over the runtime module's text: a list of failed clauses."""
    bad = []
    tree = ast.parse(text)
    imp = [n for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == "cassian_model"]
    if len(imp) != 1 or "nos_known_types" not in [a.name for a in imp[0].names]:
        bad.append("the module's one cassian_model import names nos_known_types")
    fs = {n.name: ast.get_source_segment(text, n) for n in tree.body if isinstance(n, ast.FunctionDef)}
    body = fs.get(FUNC) or ""
    if body.count(DERIVED) != 2:
        bad.append("two registry-derived peer-type predicates in %s" % FUNC)
    if LITERAL in body or '"nft-fw")' in text:
        bad.append("no literal peer-type tuple left (row -26's grep finds 0)")
    return bad


# ---- F: the fixture --------------------------------------------------------------------
DOC = yaml.safe_load(open(FIXTURE, encoding="utf-8").read()) or {}
D = declared(DOC)
check("F one sonic-vm node and two hosts, each attached directly to it by one link with "
      "both ends addressed; every test from the same host", D is not None)
if D is not None:
    s, t, A = D["s"], D["tests"], D["att"]
    n_att, f_att = A[D["near"]], A[D["far"]]
    check("F the sonic-vm node runs as vm and declares no BGP",
          s.get("runtime") == "vm" and not (s.get("asn") or s.get("bgp") or s.get("networks")))
    check("F each host declares a MAC", all(a["mac"] for a in A.values()), "%s" % {h: a["mac"] for h, a in A.items()})
    nets = {h: ipaddress.ip_interface(a["cidr"]).network for h, a in A.items()}
    check("F each host shares its link subnet with the SONiC end; the two subnets are disjoint",
          all(ipaddress.ip_interface(a["s_cidr"]).network == nets[h] for h, a in A.items())
          and not nets[D["near"]].overlaps(nets[D["far"]]), "%s" % nets)
    check("F S34 fixture: the four declared tests, in quadrant order", list(t) == list(ORDER), "%s" % list(t))
    if list(t) == list(ORDER):
        kinds = [(str(t[n].get("kind")), "to_ip" if "to_ip" in t[n] else "to" if "to" in t[n] else "?",
                  str(t[n].get("expect"))) for n in ORDER]
        check("F kinds, target spellings and expectations: reachable pass (to_ip), unreachable fail "
              "(to_ip), reachable fail (to), unreachable pass (to)",
              kinds == [("ping", "to_ip", "pass"), ("ping", "to_ip", "fail"), ("ping", "to", "fail"),
                        ("ping", "to", "pass")], "%s" % kinds)
        check("F the reachable tests target the far host's address; the unreachable ones one unused address",
              [D["tgt"][n] == D["far_ip"] for n in ORDER] == [True, False, True, False]
              and D["unreach"] is not None, "%s" % D["tgt"])
    u = D["unreach"]
    if u:
        ua = ipaddress.ip_address(u)
        decl = {ipaddress.ip_interface(a[k]).ip for a in A.values() for k in ("cidr", "s_cidr")}
        check("F the unused address is a host address inside the far link's subnet, declared nowhere",
              ua in nets[D["far"]] and ua not in (nets[D["far"]].network_address, nets[D["far"]].broadcast_address)
              and ua not in decl and u != D["router_id"], u)
    check("F the far host's address is outside the near host's subnet (the ping must leave its link)",
          ipaddress.ip_address(D["far_ip"]) not in nets[D["near"]])
    _addr = [a[k] for a in A.values() for k in ("cidr", "s_cidr")] + [D["router_id"]] + ([u] if u else [])
    check("F HALT-2 / LD-45D-2(a): no declared address and not the unused one overlaps SONiC's stock set",
          D["router_id"] and not any(stock_hit(a) for a in _addr), "%s" % _addr)
_v = subprocess.run([sys.executable, os.path.join(SRC, "cassian.py"), "validate", FIXTURE], cwd=ROOT,
                    env=dict(os.environ, PYTHONPATH="src"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
check("F the fixture validates", _v.returncode == 0, "rc=%d" % _v.returncode)

# ---- S: static, -26 ----------------------------------------------------------------------
with open(RUNTIME_SRC, encoding="utf-8") as fh:
    _rtext = fh.read()
_bad = static_ok(_rtext)
check("S -26: %s's two peer-type predicates read `set(nos_known_types()) | {\"linux\"}`; the module "
      "imports nos_known_types from cassian_model; no literal peer-type tuple is left" % FUNC,
      not _bad, "; ".join(_bad))
_pre = _rtext.replace(DERIVED, LITERAL).replace(" nos_known_types,", "")
check("S control: on the pre-fix text (literal tuple, three-name import) the predicate fails on every clause",
      _pre != _rtext and len(static_ok(_pre)) == 3, repr(static_ok(_pre))[:200])


# ---- R: behaviour, -26, through a recording runtime --------------------------------------
class _CP:
    def __init__(self, rc=0, out=""):
        self.returncode, self.stdout, self.stderr, self.args = rc, out, "", []


class _Rec:
    def __init__(self):
        self.calls = []

    def exec(self, lab, node, cmd, check=False, capture_output=True, **kw):
        self.calls.append((node, list(cmd), check))
        return _CP(0)


def _host_seq(h, iface, cidr, gw, mac):
    return [(h, ["ip", "link", "set", iface, "down"], False),
            (h, ["ip", "link", "set", "dev", iface, "address", mac], True),
            (h, ["ip", "link", "set", iface, "up"], False),
            (h, ["ip", "addr", "flush", "dev", iface], False),
            (h, ["ip", "addr", "add", cidr, "dev", iface], True),
            (h, ["ip", "route", "replace", "default", "via", gw], True)]


_PEERS = ("frr", "linux", "nft-fw", "sonic-vm", "xyz-unregistered")


def _rtopo(peer_types, flip=False):
    nodes, links, want = [], [], []
    for i, pt in enumerate(peer_types, 1):
        h, p, mac = "h%d" % i, "p%d" % i, "00:11:22:33:48:%02x" % i
        hc, pc = "198.51.100.%d/29" % (64 + 8 * i + 2), "198.51.100.%d/29" % (64 + 8 * i + 1)
        nodes += [{"name": h, "type": "host", "mac": mac}, {"name": p, "type": pt}]
        if flip and i % 2 == 0:
            links.append({"endpoints": ["%s:eth1" % p, "%s:eth1" % h], "ipv4": [pc, hc]})
        else:
            links.append({"endpoints": ["%s:eth1" % h, "%s:eth1" % p], "ipv4": [hc, pc]})
        want.append((pt, _host_seq(h, "eth1", hc, pc.split("/")[0], mac)))
    return {"nodes": nodes, "links": links}, want


def _configured(topo):
    rec = _Rec()
    RC.configure_hosts_from_topology(rec, "lab", topo)
    return rec.calls


for _flip in (False, True):
    _topo, _want = _rtopo(_PEERS, flip=_flip)
    _calls = _configured(_topo)
    _exp = [c for pt, seq in _want if pt != "xyz-unregistered" for c in seq]
    check("R -26 (%s endpoint order): a host on a frr, linux, nft-fw or sonic-vm peer gets link down, MAC, "
          "link up, flush, address, default route via the peer, in that order; a host on an unregistered "
          "type gets no call" % ("mixed" if _flip else "host-first"), _calls == _exp, repr(_calls)[:300])
check("R the registry's types plus linux are the old tuple's three plus sonic-vm, nothing else",
      set(M.nos_known_types()) | {"linux"} == {"frr", "linux", "nft-fw", "sonic-vm"},
      "%s" % sorted(set(M.nos_known_types()) | {"linux"}))
# The registry read is patched where the runtime module looks it up. On a module that
# does not bind the name (the pre-fix form) the patch is added and removed again, and
# the literal predicate ignores it -- so this check fails there, as it should.
_had = hasattr(RC, "nos_known_types")
_real = getattr(RC, "nos_known_types", M.nos_known_types)
try:
    RC.nos_known_types = lambda: tuple(sorted(set(_real()) | {"xyz-unregistered"}))
    _added = _configured(_rtopo(("xyz-unregistered",))[0])
    RC.nos_known_types = lambda: tuple(t for t in _real() if t != "sonic-vm")
    _withheld = _configured(_rtopo(("sonic-vm",))[0])
finally:
    if _had:
        RC.nos_known_types = _real
    else:
        delattr(RC, "nos_known_types")
check("R registry-derived, two-directional: a type added to the registry read is configured onto; "
      "sonic-vm withheld from it is not", len(_added) == 6 and _withheld == [],
      "added=%d withheld=%d" % (len(_added), len(_withheld)))


# ---- T: the verify_host_ready trap, lab-free ---------------------------------------------
class _FakeHost:
    """A host whose `ip` state is given: answers verify_host_ready's two shell probes and the
    three reads this file makes. Formats follow iproute2's one-line output."""

    def __init__(self, addrs, default=None, mac="02:42:ac:14:14:02"):
        self.addrs, self.default, self.mac = list(addrs), default, mac

    def addr_out(self, dev=None):
        return "\n".join("%d: %s    inet %s brd 0.0.0.0 scope global %s\\       valid_lft forever preferred_lft forever"
                         % (i + 2, d, c, d) for i, (d, c) in enumerate(self.addrs) if dev in (None, d))

    def route_out(self):
        return ("default via %s dev %s \n" % self.default) if self.default else ""

    def link_out(self, dev):
        return ("3: %s@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9500 qdisc noqueue state UP mode DEFAULT "
                "group default \\    link/ether %s brd ff:ff:ff:ff:ff:ff link-netnsid 1" % (dev, self.mac))

    def exec(self, lab, node, cmd, check=False, capture_output=True, **kw):
        if cmd == ["sh", "-lc", "command -v ip >/dev/null"]:
            return _CP(0)
        if cmd == ["sh", "-lc", "ip -4 -o addr show scope global | grep -q 'inet '"]:
            return _CP(0 if self.addrs else 1)
        if cmd[:2] == ["sh", "-lc"]:
            return _CP(0, self.addr_out())
        return _CP(1)


def _vhr_passes(host):
    try:
        RC.verify_host_ready(host, "lab", "h1")
        return True
    except SystemExit:
        return False


IF, CIDR, GW, MAC = "eth1", "198.51.100.42/29", "198.51.100.41", "00:11:22:33:47:01"
_mgmt = _FakeHost([("eth0", "172.20.20.3/24")], ("172.20.20.1", "eth0"))
_done = _FakeHost([("eth0", "172.20.20.3/24"), (IF, CIDR)], (GW, IF), MAC)


def _pred(h, dev=IF, cidr=CIDR, gw=GW, mac=MAC):
    return host_dataplane_ok(h.addr_out(), h.route_out(), h.link_out(dev), dev, cidr, gw, mac)


check("T the trap: the product's verify_host_ready passes a host holding only a management address; "
      "this file's host predicate rejects it", _vhr_passes(_mgmt) and not _pred(_mgmt))
print("  (the next line is the product's own refusal text for the no-address host, expected)")
check("T verify_host_ready's own floor is reached: a host with no global IPv4 at all fails it",
      not _vhr_passes(_FakeHost([])))
check("T the configured host satisfies the predicate (and verify_host_ready)", _pred(_done) and _vhr_passes(_done))


# ---- NV: two-directional non-vacuity per predicate --------------------------------------
def nv(label, pred, complete, too_much, too_little):
    a, b, c = pred(complete), pred(too_much), pred(too_little)
    ok = check("NV %s: complete passes, too-much and too-little are detected" % label, a and not b and not c,
               "complete=%s too-much=%s too-little=%s" % (a, b, c))
    if ok:
        print("  MUTATION-FAIL: %s too-much" % label)
        print("  MUTATION-FAIL: %s too-little" % label)


nv("host_dataplane_ok", _pred, _done,
   _FakeHost([("eth0", "172.20.20.3/24"), (IF, CIDR), (IF, "198.51.100.43/29")], (GW, IF), MAC), _mgmt)
nv("host_dataplane_ok (route)", _pred, _done,
   type("_Two", (_FakeHost,), {"route_out": lambda self: "default via %s dev %s \ndefault via 172.20.20.1 dev eth0 \n"
                               % (GW, IF)})([("eth0", "172.20.20.3/24"), (IF, CIDR)], (GW, IF), MAC),
   _FakeHost([("eth0", "172.20.20.3/24"), (IF, CIDR)], None, MAC))
nv("host_dataplane_ok (MAC)", _pred, _done, _FakeHost([("eth0", "172.20.20.3/24"), (IF, CIDR)], (GW, IF),
                                                       "00:11:22:33:47:02"),
   _FakeHost([("eth0", "172.20.20.3/24"), (IF, CIDR)], (GW, IF), ""))
_GET = "198.51.100.50 via 198.51.100.41 dev eth1 src 198.51.100.42 uid 0 \n    cache \n"
nv("route_via_ok", lambda x: route_via_ok(x, "198.51.100.50", GW, IF), _GET,
   _GET.replace("dev eth1", "dev eth0"), "198.51.100.50 dev eth1 src 198.51.100.42 uid 0 \n    cache \n")
_W = ("pass", "pass", "pass")
_REC = {"kind": "ping", "from": "h1", "expected": "pass", "observed": "pass", "verdict": "pass",
        "meta": {"dst_ip": "198.51.100.50", "attempts": 1}}
nv("quadrant_ok (reachable, expect pass)", lambda x: quadrant_ok(x[0], "h1", "198.51.100.50", _W, x[1]),
   (_REC, 0), (dict(_REC, meta={"dst_ip": "198.51.100.53", "attempts": 1}), 0),
   (dict(_REC, observed="fail", verdict="fail"), 1))
_WF = ("fail", "fail", "pass")
_RF = dict(_REC, expected="fail", observed="fail", verdict="pass", meta={"dst_ip": "198.51.100.53", "attempts": 1})
nv("quadrant_ok (unreachable, expect fail)", lambda x: quadrant_ok(x[0], "h1", "198.51.100.53", _WF, x[1]),
   (_RF, 0), (dict(_RF, meta={"dst_ip": "198.51.100.53", "attempts": 3}), 0), (_RF, 1))
nv("find_test", lambda x: find_test(x, T_RP) is not None,
   {"tests": [{"name": T_RP}]}, {"tests": [{"name": T_RP}, {"name": T_RP}]}, {"tests": []})
check("NV core_verdict is the four-quadrant table",
      [core_verdict(o, e) for o, e in (("pass", "pass"), ("fail", "fail"), ("pass", "fail"), ("fail", "pass"))]
      == ["pass", "pass", "fail", "fail"])
if D is not None and list(D["tests"]) == list(ORDER):
    check("NV the derived table has the four quadrants, two verdicts fail by design",
          want_table(D) == {T_RP: ("pass", "pass", "pass"), T_UF: ("fail", "fail", "pass"),
                            T_RF: ("fail", "pass", "fail"), T_UP: ("pass", "fail", "fail")},
          "%s" % want_table(D))


# ---- live legs ---------------------------------------------------------------------------
def cassian(*args, timeout=1800):
    r = subprocess.run([sys.executable, os.path.join(SRC, "cassian.py")] + list(args), cwd=ROOT,
                       env=dict(os.environ, PYTHONPATH="src"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout)
    out = _text(r.stdout)
    print("---- cassian %s -> rc=%d" % (" ".join(args), r.returncode))
    for ln in out.rstrip("\n").split("\n")[-25:]:
        print("     | " + ln)
    return r.returncode, out


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
    print("     record: %s" % (json.dumps(r, sort_keys=True) if r else "(none)"))
    return rc, r


def live(topo, lab):
    if os.path.realpath(topo) != os.path.realpath(FIXTURE) or lab != DOC.get("name") or D is None \
            or list(D["tests"]) != list(ORDER):
        check("LIVE argv names the ping-through fixture and its lab", False, "%s %s" % (topo, lab))
        return
    import cassian_runtime_vm as RV  # the product's runtime seam, as the other (VM) proofs use it
    rt = RV.build_runtime(DOC)
    A, near, far = D["att"], D["near"], D["far"]

    def sh(node, cmd):
        cp = rt.exec(lab, node, cmd, check=False, capture_output=True)
        out = _text(cp.stdout)
        print("     %s$ %s -> rc=%s\n%s" % (node, " ".join(cmd), cp.returncode,
                                           "\n".join("       " + l for l in out.rstrip("\n").split("\n"))))
        return cp.returncode, out

    def reads(h):
        a = A[h]
        return (sh(h, ["ip", "-4", "-o", "addr", "show"])[1], sh(h, ["ip", "-4", "route", "show", "default"])[1],
                sh(h, ["ip", "-o", "link", "show", "dev", a["iface"]])[1])

    st = {}
    for h in (near, far):
        a = A[h]
        st[h] = reads(h)
        check("L1 REQ-45D-26 (VM): %s holds %s on %s, MAC %s, and one default route via %s (the SONiC end)"
              % (h, a["cidr"], a["iface"], a["mac"], a["gw"]),
              host_dataplane_ok(*st[h], a["iface"], a["cidr"], a["gw"], a["mac"]))
    b = A[far]
    check("L1 control: %s's live state does not satisfy %s's declaration" % (near, far),
          not host_dataplane_ok(*st[near], b["iface"], b["cidr"], b["gw"], b["mac"]))
    for dst in (D["far_ip"], D["unreach"]):
        _, out = sh(near, ["ip", "-4", "route", "get", dst])
        check("L1 from %s, %s routes via %s on %s (through the SONiC node)" % (near, dst, A[near]["gw"],
                                                                              A[near]["iface"]),
              route_via_ok(out, dst, A[near]["gw"], A[near]["iface"]))

    want = want_table(D)
    got = {}
    for n in ORDER:
        rc, r = run_test(lab, n)
        got[n] = (rc, r)
        exp, obs, ver = want[n]
        ok = quadrant_ok(r, near, D["tgt"][n], want[n], rc)
        if n == T_UF:
            reach = got[T_RP][1] or {}
            ok = ok and reach.get("observed") == "pass"
        check("L2 REQ-45D-%s (VM): %s -- %s to %s, expect %s: observed %s, verdict %s, rc %s"
              % ("3" if n == T_RP else "4", n, near, D["tgt"][n], exp, obs, ver, "0" if ver == "pass" else "!=0"),
              ok, "rc=%s observed=%s verdict=%s" % (rc, (r or {}).get("observed"), (r or {}).get("verdict")))
    if (got[T_RP][1] or {}).get("observed") != "pass":
        print("FINDING (S34-R1): the reachable expect-pass ping from %s to %s did not succeed on this boot. "
              "Either the host was not configured (L1) or the SONiC node did not forward between its two "
              "front-panel ports; the packet stops and returns to the founder." % (near, D["far_ip"]))

    a = A[near]
    rc_f, _ = sh(near, ["ip", "addr", "flush", "dev", a["iface"]])
    addr_after, route_after, link_after = reads(near)
    glob = [l for l in addr_after.splitlines() if " inet " in l and "scope global" in l]
    check("L3 trap state: after the flush (rc=%s) %s holds a global IPv4 and none on %s"
          % (rc_f, near, a["iface"]),
          rc_f == 0 and bool(glob) and not any(l.split()[1] == a["iface"] for l in glob if len(l.split()) > 1),
          "%d global" % len(glob))
    try:
        RC.verify_host_ready(rt, lab, near)
        vhr = True
    except SystemExit:
        vhr = False
    check("L3 the trap, live: the product's verify_host_ready passes %s; this file's host predicate rejects it"
          % near, vhr and not host_dataplane_ok(addr_after, route_after, link_after, a["iface"], a["cidr"],
                                                a["gw"], a["mac"]))


argv = sys.argv[1:]
if not argv:
    for leg in ("L1 REQ-45D-26 host data plane", "L2 REQ-45D-3/-4 quadrants", "L3 verify_host_ready trap"):
        blocked.append((leg, "no live argv: run `live <topo> <lab>` on a lab that is up"))
elif argv[0] == "live" and len(argv) == 3:
    live(argv[1], argv[2])
else:
    sys.exit("usage: sonic_ping_through_proof.py [live <topo> <lab>]")

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
