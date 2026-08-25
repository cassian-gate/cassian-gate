#!/usr/bin/env python3
"""tests/sonic_lifecycle_proof.py -- 4.5-c WI-1 SONiC base lifecycle.

Req-IDs: REQ-45C-5  (interface provisioning; HALT-2 address discipline, S-9)
         REQ-45C-1  (routing-neutral baseline: hostname, interfaces, loopback)
         REQ-45C-22 (two-node eBGP convergence)   -- VM-BLOCKED, see below

Snapshot mapping (handover 6.7.2 preamble, mapping discipline): the module this
proof consumes is `cassian_nos_sonic` -> `src/cassian_nos_sonic.py`. Session
snapshot is v48 == branch `feature/4_5c-sonic-base-lifecycle`; the handover's
authoring pin was v45 == `b129510`, which the branch has since advanced past.

Lab-free legs run everywhere. VM legs are reported BLOCKED, never silently
skipped. Founder ruling 2026-08-18 (reading A): the blocked legs are
enumerated in the file that owns them.

CITATION CORRECTED (§4.5-c WI-2, founder ruling 2026-08-24, option C). These
legs previously cited Ledger row BL-P2-4.5c-6 and "two founder-owned host
blockers on ai-netsim". **BL-P2-4.5c-20 supersedes -6 and BOTH cited blockers
are discharged**, measured: (a) F-45C-C3-8 is false -- only the stale
`ghcr.io` tag resolves to `cb884fb5fc9d`; `local/sonic-vm:202405` is
`ffef3b5662b0`, a contrib-built vrnetlab image, re-measured independently on
2026-08-24; (b) F-45C-C3-13 is dissolved -- `/etc/sudoers.d/containerlab-runner`
has granted NOPASSWD containerlab since 2026-07-10 and CI deploys labs. The
remaining block is different in kind and is stated below per leg. Ledger row
`BL-P2-4.5c-35` records the correction; §4.8 bars editing -6 in place.

UNBLOCKING IS NOT THIS EDIT. Per the same ruling (option C), WI-2 carries the
citation correction only; clearing the legs is WI-3's, because legs 1-2 need a
pre-provisioning observation window that does not exist today -- provisioning
runs inside `cmd_up` (`src/cassian_engine.py:1317`, host leg `:1398`, provider
leg `:1435`) and no `--no-provision` path exists.

COVERAGE LIMITS (PBE-P2-8), stated rather than implied:
  * The address sweep tests DECLARED values parsed from YAML -- `links[].ipv4`
    and `nodes[].router_id`. It deliberately does not grep file text: prose
    naming the stock ranges (as the fixture's own header comment does) would
    false-positive, and worse, deleting that comment would silence a text
    guard. Constants live here, not in the fixture.
  * Registration is an explicit named list, not a glob. A glob over
    `topologies/sonic*` would have missed `vm-assertion-smoke.yaml`, exactly
    the narrow-glob family recorded at F-45C-C3-3. An unregistered SONiC
    fixture FAILS this proof rather than passing unseen.
  * Offline generation proves the positional contract GIVEN a port order. It
    cannot prove vrnetlab attaches container eth<N> to the N-th platform port.
    That is REQ-45C-5's pre/post VM pair, blocked above.
"""
import io
import ipaddress
import os
import sys

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cassian_nos_sonic as S  # noqa: E402

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_TOPO = os.path.join(_ROOT, "topologies")

# Stock canned ranges on sonic-vm:202405, measured 2026-08-15 (HALT-2 ruling).
STOCK_RANGES = (
    ipaddress.ip_network("10.0.0.0/26"),   # Ethernet0..124, sequential /31s
    ipaddress.ip_network("10.1.0.0/24"),   # Loopback0 10.1.0.1/32
)

# Fixtures this handover authored. Authority is this list, not a glob.
SECTION_45C_FIXTURES = (
    "sonic-base-lifecycle.yaml",
    # §4.5-c WI-2 endpoint recognition (REQ-45C-6, REQ-45C-7). Registered here
    # because LEG 2's enumeration-drop guard is an explicit list, not a glob:
    # an unregistered SONiC fixture FAILS this proof rather than passing
    # unseen (F-45C-C3-3). Registration also puts both under LEG 1's HALT-2
    # address sweep.
    "sonic-mixed-host.yaml",
    "sonic-mixed-linux.yaml",
    # §4.5-c WI-3 convergence probe (founder ruling 2026-08-25). A two-node
    # sonic-vm eBGP pair -- the shape §15.2's REQ-45C-22 row requires and the
    # first SONiC fixture in the tree to declare `asn` / `bgp.neighbors`.
    # Registered in the SAME commit that adds it, so CI never sees an
    # unregistered SONiC fixture (F-45C-C3-3): the guard below is an explicit
    # list, not a glob, and an unregistered fixture FAILS rather than passing
    # unseen. Registration also puts its six declared addresses under LEG 1's
    # HALT-2 sweep -- confirmed outside 10.0.0.0/26 and 10.1.0.0/24 before
    # delivery, with a non-vacuity control on the detector.
    #
    # PROBE ARTIFACT, disposition OPEN: whether this becomes packet 4's
    # permanent fixture depends on the probe's result, which is what it exists
    # to establish. It is committed because git is the transport to ai-netsim
    # (founder ruling 2026-08-25, superseding the no-Touch-Matrix clause).
    "probe-sonic-bgp-pair.yaml",
)

# SONiC fixtures inherited from 4.5-a. REQ-45C-5 states these collide with
# stock addressing and are NOT edited by this handover; they are named so an
# unregistered file is distinguishable from an inherited one.
INHERITED_SONIC_FIXTURES = (
    "vendor_nos_smoke.yaml",
    "vm-assertion-smoke.yaml",
    "vm-smoke.yaml",
    "vm-three-nodes-two-hosts-fw-outcomes.yaml",
)

_checks = []
_blocked = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


def blocked(name, reason):
    _blocked.append((name, reason))


def _declared_addresses(path):
    """Return [(where, ip)] for every address DECLARED in a topology."""
    doc = yaml.safe_load(io.open(path, encoding="utf-8").read()) or {}
    out = []
    for n in doc.get("nodes") or []:
        if not isinstance(n, dict):
            continue
        rid = n.get("router_id")
        if rid:
            out.append(("%s.router_id" % n.get("name"), str(rid).split("/")[0]))
    for i, link in enumerate(doc.get("links") or []):
        if not isinstance(link, dict):
            continue
        for j, ip in enumerate(link.get("ipv4") or []):
            out.append(("links[%d].ipv4[%d]" % (i, j), str(ip).split("/")[0]))
    return out


def _in_stock(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in STOCK_RANGES)


def _is_sonic_fixture(path):
    doc = yaml.safe_load(io.open(path, encoding="utf-8").read()) or {}
    for n in doc.get("nodes") or []:
        if isinstance(n, dict) and str(n.get("type") or "").strip().lower() == "sonic-vm":
            return True
    return False


# --- LEG 1 (REQ-45C-5 regression): no 4.5-c fixture uses a stock address -----
for _fx in SECTION_45C_FIXTURES:
    _p = os.path.join(_TOPO, _fx)
    check("REQ-45C-5 fixture exists: %s" % _fx, os.path.isfile(_p))
    if not os.path.isfile(_p):
        continue
    _hits = [(w, a) for (w, a) in _declared_addresses(_p) if _in_stock(a)]
    check("HALT-2 %s declares no address inside the stock ranges" % _fx,
          not _hits, "hits: %s" % (_hits or "none"))

# --- LEG 1 non-vacuity: the sweep discriminates ------------------------------
_ctl = os.path.join(_TOPO, "vm-assertion-smoke.yaml")
_ctl_hits = [a for (_w, a) in _declared_addresses(_ctl) if _in_stock(a)] \
    if os.path.isfile(_ctl) else []
check("REQ-45C-5 NON-VACUITY: the sweep fires on a known stock-range fixture",
      bool(_ctl_hits),
      "vm-assertion-smoke.yaml declared-in-stock: %s (4.5-a fixture, not edited "
      "here -- BL-P2-4.5c-12)" % (_ctl_hits or "none"))

# --- LEG 2 (enumeration drop guard): every SONiC fixture is registered -------
_registered = set(SECTION_45C_FIXTURES) | set(INHERITED_SONIC_FIXTURES)
_unregistered = sorted(
    f for f in os.listdir(_TOPO)
    if f.endswith(".yaml")
    and f not in _registered
    and os.path.isfile(os.path.join(_TOPO, f))
    and _is_sonic_fixture(os.path.join(_TOPO, f))
)
check("F-45C-C3-3 every SONiC fixture is registered in this proof",
      not _unregistered,
      "unregistered: %s -- add it to SECTION_45C_FIXTURES so the HALT-2 sweep "
      "covers it" % (_unregistered or "none"))

# --- LEG 3 (REQ-45C-1/-5 positional contract, offline) ----------------------
_fx = os.path.join(_TOPO, "sonic-base-lifecycle.yaml")
if os.path.isfile(_fx):
    _topo = yaml.safe_load(io.open(_fx, encoding="utf-8").read())
    _node = [n for n in _topo["nodes"] if n.get("name") == "s1"][0]
    _ports = S._SONIC_PORT_MAPS["Force10-S6000"]
    _gen = S.gen_node_config(_node, _topo, {"hwsku": "Force10-S6000",
                                            "port_order": _ports})
    _ov = _gen["config_db.json"]
    check("REQ-45C-1 generation returns a config_db.json overlay",
          list(_gen.keys()) == ["config_db.json"])
    check("REQ-45C-5 eth1 maps to the first platform port with its address",
          "Ethernet0|198.51.100.0/31" in (_ov.get("INTERFACE") or {}),
          "INTERFACE: %s" % sorted((_ov.get("INTERFACE") or {}).keys()))
    check("REQ-45C-5 loopback carries router_id/32",
          "Loopback0|192.0.2.11/32" in (_ov.get("LOOPBACK_INTERFACE") or {}))
    check("REQ-45C-1 routing-neutral: no BGP table at the base leg",
          "BGP_NEIGHBOR" not in _ov and "BGP_GLOBALS" not in _ov)
    check("REQ-45C-44a overlay authors no platform-owned table",
          not any(k in _ov for k in ("PORT", "hwsku", "platform", "mac")))
    _gen_addrs = [k.split("|", 1)[1].split("/")[0]
                  for k in (_ov.get("INTERFACE") or {}) if "|" in k]
    check("HALT-2 no GENERATED address falls inside the stock ranges",
          not any(_in_stock(a) for a in _gen_addrs),
          "generated: %s" % _gen_addrs)
else:
    check("REQ-45C-1/-5 offline generation leg ran", False,
          "fixture absent: topologies/sonic-base-lifecycle.yaml")

# --- VM legs: BLOCKED, enumerated, never silently absent --------------------
blocked("REQ-45C-5 pre-provisioning control (S-9): declared address and "
        "router_id/32 ABSENT on a booted, un-provisioned guest",
        "BL-P2-4.5c-35 -- environment binding, NOT a host blocker. §18(1) "
        "requires every §15 proof green in its bound environment; this proof "
        "runs in the lab-free CI step. Substantively demonstrated by the "
        "§18(8) probe. Clearing it needs a pre-provisioning window that does "
        "not exist (provisioning is inside cmd_up); routed to WI-3")
blocked("REQ-45C-5 post-provision positive: the address ABSENT in the control "
        "is PRESENT on the expected port",
        "BL-P2-4.5c-35 -- same environment binding; routed to WI-3")
blocked("REQ-45C-22 two-node eBGP pair reaches Established under generated "
        "configuration, with evidence recorded",
        "BL-P2-4.5c-35 -- same environment binding, AND the eBGP fixture is "
        "not yet authored; both are WI-3's")

# --- Report ------------------------------------------------------------------
_fails = [c for c in _checks if not c[1]]
for _n, _ok, _d in _checks:
    print("%s %s%s" % ("PASS" if _ok else "FAIL", _n,
                       ("  [%s]" % _d) if _d else ""))
for _n, _r in _blocked:
    print("BLOCKED %s  [%s]" % (_n, _r))
print("=" * 60)
print("RESULT: %s -- %d checks passed, %d BLOCKED (WI-1 SONiC base lifecycle)"
      % ("PASS" if not _fails else "FAIL", len(_checks) - len(_fails),
         len(_blocked)))
if _fails:
    sys.exit("sonic_lifecycle_proof FAILED (%d check(s))." % len(_fails))
if _blocked:
    print("NOTE: %d leg(s) BLOCKED on BL-P2-4.5c-35 (BL-P2-4.5c-6 is "
          "superseded by -20). A BLOCKED leg is not a "
          "pass; the closure report carries it as a condition (PBE-P2-5)."
          % len(_blocked))
