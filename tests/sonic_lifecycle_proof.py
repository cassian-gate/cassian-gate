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
    # §4.5-c WI-3 packet 4a — REQ-45C-24 negative fixture. One-sided BGP
    # declaration; both nodes are speakers and linked, so both enter the
    # participant set. CANNOT converge, by design. Registered in the SAME
    # commit that adds it so CI never sees an unregistered SONiC fixture
    # (F-45C-C3-3), which also puts its four addresses under LEG 1's HALT-2
    # sweep — confirmed outside 10.0.0.0/26 and 10.1.0.0/24 before delivery,
    # with a non-vacuity control on the detector.
    "sonic-bgp-asymmetric.yaml",
    # §4.5-c WI-3 packet 4b-i — REQ-45C-29's SYMMETRIC non-converging pair.
    # Founder ruling 2026-08-26 (two fixtures, not one): -29 gets its own
    # fixture so its timeout evidence is not causally dependent on asymmetry.
    # Both nodes declare each other BY NAME, so `_declaration_asymmetries`
    # (engine :10276, matching on node name via `_declared_neighbor_names`
    # :10252) returns EMPTY here; non-convergence comes from mismatched
    # `remote_as` on both sides. Registered in the SAME commit that adds it
    # (F-45C-C3-3), which also puts its four addresses under LEG 1's HALT-2
    # sweep.
    "sonic-bgp-nonconverging.yaml",
    # §4.5-c WI-3 packet 4b-i — REQ-45C-5's IMAGE-SCOPED control boot.
    # Founder ruling 2026-08-26: "a booted, un-provisioned sonic-vm guest" is
    # image-scoped, so the control is a same-image boot carrying none of the
    # addresses the 4b fixtures declare. It declares NO addresses at all, so
    # LEG 1's stock-range sweep passes over it vacuously — that is expected,
    # and LEG 1's non-vacuity control (vm-assertion-smoke.yaml) is what proves
    # the sweep discriminates. Registered same-commit (F-45C-C3-3).
    "sonic-control-unprovisioned.yaml",
    # §4.5-c WI-3 Unit A packet 2: REQ-45C-9 downed-daemon leg (LD-45C-R5).
    "sonic-bgp-daemon-stop.yaml",
    # §4.5-c WI-3 Unit B packet 5a: REQ-45C-10/-30's CONVERGING pair for
    # the scenario `wait_for_bgp` positive leg (LD-45C-R12 R1). Its own
    # fixture, not shared -- daemon-stop is reserved by its mutating leg.
    # Registered in the SAME commit that adds it so CI never sees an
    # unregistered SONiC fixture (F-45C-C3-3): LEG 2 below is an explicit
    # list, not a glob, and an unregistered fixture FAILS rather than
    # passing unseen. Registration also puts its six declared addresses
    # under LEG 1's HALT-2 sweep -- confirmed outside 10.0.0.0/26 and
    # 10.1.0.0/24 before delivery, with a non-vacuity control on the
    # detector.
    "sonic-bgp-scenario-wait.yaml",
    # §4.5-c WI-1 packet 2, §15.2 row 4 (REQ-45C-4): the mixed-MODE fixture.
    # Two sonic-vm nodes whose sonic_mode values differ, so the per-node
    # resolution REQ-45C-4 requires is demonstrable at all.
    #
    # ⚑ NEVER DEPLOYED (LD-45C-R29 R1/R2). Its evidence is
    # topology.resolved.yaml, written before deploy, so the single-SONiC-node
    # CI ceiling is not engaged. It is registered here anyway: registration is
    # about the HALT-2 address sweep and the enumeration-drop guard, neither
    # of which cares whether a fixture is ever brought up. An un-deployed
    # fixture is still a §4.5-c-authored SONiC fixture and is NOT exempt.
    "sonic-mode-mixed.yaml",
    # §4.5-c WI-1 packet 2, §15.2 row 26 (REQ-45C-26): the preconfigured-boot
    # fixture. ONE sonic-vm guest carrying the operator's complete
    # config_db.json, plus an frr node so the topology has a `links` entry --
    # `ensure_valid_topology` rejects a topology without one.
    #
    # DEPLOYED, unlike sonic-mode-mixed.yaml. Its evidence is what the guest
    # holds after `config reload -y -f` (LD-45C-R17 R3), so its CI step takes
    # up/down and joins the if:always() sweep (LD-45C-R14 R2/R3).
    #
    # Its declared addresses -- 192.0.2.61 and 198.51.100.24/31 -- come under
    # LEG 1's HALT-2 sweep by this registration. The operator artifact beside
    # it carries the same two addresses in INTERFACE and LOOPBACK_INTERFACE;
    # LEG 1 sweeps the TOPOLOGY file, so the artifact's addresses are checked
    # by tests/sonic_preconfigured_proof.py req26 instead. Stated because the
    # division is not obvious from either file alone.
    "sonic-preconfigured-boot.yaml",
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
# --- (VM) legs (BL-P2-4.5c-35) ----------------------------------------------
# LD-45C-R1 (2026-08-26, `e8da5c4`), extended generally the same day: a (VM)
# leg observes the device through the product's runtime seam. Nothing is
# recorded by the product and nothing in src/ changes.
#
# usage:
#   sonic_lifecycle_proof.py
#       -> lab-free only; the three legs below report BLOCKED; exit 0
#   sonic_lifecycle_proof.py req5 <control-topo> <control-lab> <subject-topo> <subject-lab>
#       -> BOTH REQ-45C-5 legs in one invocation. §15.2's positive row is
#          defined by reference to the control ("the same address that was
#          ABSENT in the control is now PRESENT"), so pairing them here makes
#          that structural instead of dependent on CI wiring.
#   sonic_lifecycle_proof.py req22 <topo> <lab>

try:
    import cassian_runtime_vm as _RV  # noqa: E402
    _rv_err = ""
except Exception as _e:  # pragma: no cover
    _RV = None
    _rv_err = repr(_e)

check("(VM) seam: cassian_runtime_vm.build_runtime is callable",
      _RV is not None and callable(getattr(_RV, "build_runtime", None)),
      _rv_err or "cassian_runtime_vm.py:406")
check("(VM) seam: cassian_nos_sonic._guest_stdout is callable",
      callable(getattr(S, "_guest_stdout", None)),
      "cassian_nos_sonic.py:457 -- stdout only; the guest SSH banner lands on "
      "stderr (F-45C-C3-20)")


def _sonic_nodes(doc):
    return [n.get("name") for n in (doc.get("nodes") or [])
            if isinstance(n, dict)
            and str(n.get("type") or "").strip().lower() == "sonic-vm"]


def _guest_v4(rt, lab, node):
    """Addresses present on the guest, via `ip -o -4 addr show`.

    REQ-45C-5's control row names this command. Parsed from column 4 of
    ip's one-line-per-address form.
    """
    out = S._guest_stdout(rt, lab, node, ["ip", "-o", "-4", "addr", "show"],
                          "REQ-45C-5 (VM) guest address read")
    found = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet":
            found.append(parts[3].split("/")[0])
    return sorted(set(found))


def _sonic_own_addresses(doc):
    """Addresses a topology declares FOR ITS sonic-vm nodes, and only those.

    Each sonic-vm node's own `router_id`, plus its own INDEXED end of every
    link it terminates -- `endpoints[i]` pairs with `ipv4[i]`. A peer's
    router_id and the far end of a link belong to the peer and are never
    provisioned onto the SONiC guest.
    """
    names = set(_sonic_nodes(doc))
    out = set()
    for n in doc.get("nodes") or []:
        if not isinstance(n, dict) or n.get("name") not in names:
            continue
        if n.get("router_id"):
            out.add(str(n["router_id"]).split("/")[0])
    for link in doc.get("links") or []:
        if not isinstance(link, dict):
            continue
        eps = [str(e).split(":")[0] for e in (link.get("endpoints") or [])]
        ips = [str(i).split("/")[0] for i in (link.get("ipv4") or [])]
        for i, ep in enumerate(eps):
            if ep in names and i < len(ips):
                out.add(ips[i])
    return sorted(out)


def _leg_req5(ctrl_topo, ctrl_lab, subj_topo, subj_lab):
    ctrl_doc = yaml.safe_load(io.open(ctrl_topo, encoding="utf-8").read()) or {}
    subj_doc = yaml.safe_load(io.open(subj_topo, encoding="utf-8").read()) or {}
    # NARROWED TO THE SONiC NODE'S OWN ADDRESSES (packet 4b-iv). The first
    # authoring took EVERY address in the subject topology, which on a
    # sonic-vm/FRR pair includes the FRR node's router_id and the far end of
    # the link. Run 33041629461 failed demanding r1's 192.0.2.21 and
    # 198.51.100.1 on the SONiC guest. Derived from the DECLARATION, never
    # from the guest -- narrowing to what the device happens to carry would
    # make the leg unfalsifiable.
    _all_declared = sorted({a for _w, a in _declared_addresses(subj_topo)})
    subject_addrs = _sonic_own_addresses(subj_doc)
    check("REQ-45C-5 (VM) NON-VACUITY: the subject fixture declares at least "
          "one address FOR ITS sonic-vm node(s) to assert on",
          bool(subject_addrs),
          "sonic-owned: %s; whole topology declares: %s (the difference "
          "belongs to non-SONiC peers and is never provisioned onto the "
          "guest)" % (subject_addrs, _all_declared))
    if not subject_addrs:
        return
    ctrl_nodes = _sonic_nodes(ctrl_doc)
    subj_nodes = _sonic_nodes(subj_doc)
    check("REQ-45C-5 (VM) NON-VACUITY: both fixtures carry a sonic-vm node",
          bool(ctrl_nodes) and bool(subj_nodes),
          "control: %s  subject: %s" % (ctrl_nodes, subj_nodes))
    if not ctrl_nodes or not subj_nodes:
        return

    rt_c = _RV.build_runtime(ctrl_doc)
    present_on_control = set()
    for node in ctrl_nodes:
        present_on_control |= set(_guest_v4(rt_c, ctrl_lab, node))
    collide = sorted(set(subject_addrs) & present_on_control)
    check("REQ-45C-5 (VM) pre-provisioning control (S-9): the subject's "
          "declared addresses are ABSENT on a booted, un-provisioned guest "
          "of this image",
          not collide,
          "subject declares %s; control guest carries %s; overlap %s"
          % (subject_addrs, sorted(present_on_control), collide or "none"))

    rt_s = _RV.build_runtime(subj_doc)
    present_on_subject = set()
    for node in subj_nodes:
        present_on_subject |= set(_guest_v4(rt_s, subj_lab, node))
    missing = sorted(set(subject_addrs) - present_on_subject)
    check("REQ-45C-5 (VM) post-provision positive: the address ABSENT in the "
          "control is PRESENT after provisioning",
          not missing,
          "expected %s; subject guest carries %s; missing %s"
          % (subject_addrs, sorted(present_on_subject), missing or "none"))


def _declared_peer_ips(doc):
    """{node: peer_ip} for every peer DECLARED under bgp.neighbors.

    Link-derived resolution of the declared peer NAME to the far end's ipv4,
    matching `_declaration_asymmetries`' reading that a declaration names its
    peer by node name (`cassian_engine.py:10252`).

    NEAR-DUPLICATE, DECLARED RATHER THAN HIDDEN: sonic_precheck_proof.py's
    `_declared_peers` computes the same relation in list form for REQ-45C-8.
    Two proof-local copies is not PBE-1b-9's subject (validate/exec-shared
    product helpers), but it is duplication and a consolidation candidate.
    Recorded here so a later reader meets it rather than discovering it.
    """
    by_pair = {}
    for link in doc.get("links") or []:
        if not isinstance(link, dict):
            continue
        eps = [str(e).split(":")[0] for e in (link.get("endpoints") or [])]
        ips = [str(i).split("/")[0] for i in (link.get("ipv4") or [])]
        if len(eps) == 2 and len(ips) == 2:
            by_pair[(eps[0], eps[1])] = ips[1]
            by_pair[(eps[1], eps[0])] = ips[0]
    out = {}
    for n in doc.get("nodes") or []:
        if not isinstance(n, dict):
            continue
        bgp = n.get("bgp") if isinstance(n.get("bgp"), dict) else {}
        for nbr in bgp.get("neighbors") or []:
            if not isinstance(nbr, dict):
                continue
            ip = by_pair.get((n.get("name"), nbr.get("peer")))
            if ip:
                out[n.get("name")] = ip
    return out


def _leg_req22(topo_path, lab):
    doc = yaml.safe_load(io.open(topo_path, encoding="utf-8").read()) or {}
    nodes = _sonic_nodes(doc)
    check("REQ-45C-22 (VM) NON-VACUITY: the fixture carries sonic-vm nodes",
          len(nodes) >= 2, "sonic-vm nodes: %s" % nodes)
    if len(nodes) < 2:
        return
    declared = _declared_peer_ips(doc)
    # The stock image ships 31-32 canned BGP_NEIGHBOR entries. Asserting that
    # SOME peer is Established would pass on those and prove nothing about
    # Cassian's rendering, which is what REQ-45C-22 is about. Each node's
    # DECLARED peer IP is the subject, matched exactly.
    missing_decl = sorted(n for n in nodes if n not in declared)
    check("REQ-45C-22 (VM) NON-VACUITY: every sonic-vm node declares a "
          "resolvable peer",
          not missing_decl,
          "declared peer IPs: %s; unresolved: %s"
          % (declared, missing_decl or "none"))
    if missing_decl:
        return
    states = {}
    rt = _RV.build_runtime(doc)
    for node in nodes:
        peer_ip = declared[node]
        out = S._guest_stdout(rt, lab, node,
                              ["vtysh", "-c", "show bgp summary"],
                              "REQ-45C-22 (VM) session state")
        state = ""
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] == peer_ip and len(parts) >= 10:
                state = parts[9]
                break
        states[node] = (peer_ip, state)

    def _up(s):
        return bool(s) and (s.isdigit() or s.lower() == "established")

    not_up = sorted("%s->%s:%s" % (n, ip, st or "(absent)")
                    for n, (ip, st) in states.items() if not _up(st))
    check("REQ-45C-22 (VM) the DECLARED peer is Established on every node, in "
          "both directions, under Cassian-generated configuration",
          not not_up,
          "per-node declared-peer state: " + "; ".join(
              "%s->%s:%s" % (n, ip, st or "(absent)")
              for n, (ip, st) in sorted(states.items())))


_vm_args = sys.argv[1:]
if not _vm_args:
    blocked("REQ-45C-5 (VM) pre-provisioning control (S-9) + post-provision "
            "positive",
            "no (VM) argv supplied; run: req5 <control-topo> <control-lab> "
            "<subject-topo> <subject-lab>. Wired at 4b-iii")
    blocked("REQ-45C-22 (VM) two-node eBGP pair reaches Established under "
            "generated configuration",
            "no (VM) argv supplied; run: req22 <topo> <lab>. Wired at 4b-iii")
elif _vm_args[0] == "req5" and len(_vm_args) == 5:
    _leg_req5(_vm_args[1], _vm_args[2], _vm_args[3], _vm_args[4])
elif _vm_args[0] == "req22" and len(_vm_args) == 3:
    _leg_req22(_vm_args[1], _vm_args[2])
else:
    sys.exit("usage: sonic_lifecycle_proof.py "
             "[req5 <control-topo> <control-lab> <subject-topo> <subject-lab> "
             "| req22 <topo> <lab>]  (no argv = lab-free legs only)")

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
