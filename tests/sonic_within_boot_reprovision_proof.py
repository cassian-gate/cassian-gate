#!/usr/bin/env python3
"""Within-boot reprovision on a SONiC guest (§4.5-d VM-6; scope §9 row 13): REQ-45D-30, with REQ-45D-31.

Founder rulings S37-R1 to S37-R3 of 2026-10-20 (the session-37 rulings note,
cassian-gate-internal@5c19e70, Ledger §163). One fixture, one boot (LD-45D-6):
topologies/sonic-within-boot.yaml -- one frr node and one sonic-vm guest in generated
mode, with a declared router_id and link addresses, and no BGP declared.

REQ-45D-30 (handover §2; Ledger BL-P2-4.5c-36): the `provision` docstring's claim that
the overlay leaves the PORT count, hwsku, platform and mac intact and
`/etc/sonic/config_db.json`'s md5 unchanged could not be tested across boots (mac and md5
vary per boot). This file measures it WITHIN one boot: `cmd_up` has already provisioned
the guest once (it always does; no `--no-provision` exists), so the "before" values are
read on that boot; the product's own `provision` is then re-run for the guest with its
declared router_id changed, and the values are read again. The changed LOOPBACK_INTERFACE
key is the sentinel that the re-injection took effect (S37-R3). The relation measured for
each value is compared with the claim the docstring states, so the docstring equals the
measured claim (handover §15.2 row -30).

Lab-free legs (always run):
  F   the live fixture's shape, derived values only; the fixture validates.
  D   the docstring: `provision`'s docstring states CLAIM's sentence and SCOPE's
      sentence, and no longer the unmeasured 2026-08-18 sentence.
  O   the sentinel, through the product's generator: for the declared router_id and the
      sentinel one, `gen_node_config`'s overlays differ in LOOPBACK_INTERFACE exactly by the
      loopback key, and neither authors PORT, hwsku, platform or mac (REQ-45C-44a).
  NV  REQ-45D-31 two-directional non-vacuity for each predicate this file applies to the
      product's output or the guest's: a complete synthetic observation satisfies it, and a
      mutation in each direction -- too much and too little -- is detected. Then, for each
      clause those mutations do not each isolate, one mutation rejected by that clause
      alone, printed only for the direction it tests. Printed in handover §18's literal
      form, `MUTATION-FAIL: too-much (<label>)` and `MUTATION-FAIL: too-little (<label>)`
      (S35-R3).

Live legs (`live <topo> <lab>`, on a lab already up):
  L1  before: the guest's DEVICE_METADATA (through the product's _DEVICE_METADATA_ARGV),
      its PORT table, `/etc/sonic/config_db.json`'s md5 and its LOOPBACK_INTERFACE table
      are read through the product's runtime (rt.exec, the guest); the declared loopback
      key is present and the sentinel key absent.
  L2  the re-injection: the product's own `provision` for the guest, with its declared
      router_id changed to the sentinel, completes, and the overlay it applied carries the
      sentinel loopback key.
  L3  after: the same four reads; the sentinel key is now present (the injection took
      effect) and the declared one still is (config load merges).
  L4  REQ-45D-30: on a re-injection that took effect (L3), the relation measured for each
      value (unchanged or changed) equals the relation CLAIM states, which is the relation D
      found the docstring states.
  L5  the guest-not-wrapper control (house pattern since S35-R1): through the product's
      substrate_exec, which reaches the vrnetlab launcher that wraps the guest, the launcher
      answers a plain command, while the same reads sent there carry none of L1's values
      (the md5, the mac, the declared loopback key) -- so L1's and L3's values can only
      have come from the guest.
  L6  the saved file's control, read-only (the pattern of
      tests/sonic_routing_mode_precondition_proof.py): `/etc/sonic/config_db.json`, read
      with `cat`, is a config_db (it carries a PORT table), and its LOOPBACK_INTERFACE lacks
      the sentinel key that ConfigDB carries after L2 -- the file and the running database
      are distinct, so an "unchanged" md5 in L4 is not one source read twice.

usage:
  sonic_within_boot_reprovision_proof.py                    lab-free legs; L1-L6 BLOCKED; exit 0 if green
  sonic_within_boot_reprovision_proof.py live <topo> <lab>  lab-free legs, then L1-L6 on a lab already up
  The live legs change the guest's ConfigDB (the sentinel loopback key), so a second live run
  needs a fresh `up --reconfigure`: L1 requires the sentinel key absent.

Coverage limits, stated in-file (PBE-P2-8):
  - One boot of one fixture on one image. It measures a SECOND injection (a re-injection
    into a booted, already-provisioned guest), not the first injection onto the stock
    config: `cmd_up` always provisions, so no pristine "before" exists on the product's
    path (topologies/sonic-control-unprovisioned.yaml).
  - mac is DEVICE_METADATA.localhost.mac in ConfigDB, as the product reads it; no kernel
    or hardware MAC is read.
  - The re-injection is the product's provision called by this file, not by `cmd_up`, so
    the run directory's nodes/<node>/config_db.json still holds the first overlay. It is
    given the fixture as declared, where `cmd_up` gives the resolved topology (resolution
    adds `_runtime`, the `sonic_mode` default and a top-level `tests` key); for this
    fixture the two overlays agree, but nothing here asserts it.
  - L5 reads the launcher through substrate_exec; it does not inspect the wrapper chain.
  - D finds the claim and the scope in the docstring and the old sentence gone; it does not
    find a contradicting sentence added elsewhere in it (the apply script's G-DOC does, at
    apply time).
  - REQ-45D-30 names the mac and md5 clauses; PORT count, hwsku and platform are read as
    well, because the docstring's sentence names them.
  - Every guest command this file runs is a read, apart from the product's own provision.

Exit 0 when every check passes (BLOCKED or NOT ATTEMPTED legs are listed); exit 1 otherwise.
"""
import ast
import copy
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

import cassian_nos_sonic as S  # noqa: E402

FIXTURE = os.path.join(ROOT, "topologies", "sonic-within-boot.yaml")
CONFIG_DB = "/etc/sonic/config_db.json"
SENTINEL_OFFSET = 2  # the sentinel router_id is the declared one plus 2 (unused by any fixture)
LAUNCHER_PROBE = ["uname", "-s"]
HEX32 = re.compile(r"^[0-9a-f]{32}$")
MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
OLD_SENTENCE = "Measured 2026-08-18 on sonic-vm:202405: PORT 32 -> 32, hwsku/platform/mac"

# The claim the docstring states, one relation per value. REQ-45D-30's measurement decides
# it: L4 fails if any measured relation differs, and D fails if the docstring does not
# state exactly this.
CLAIM = (("PORT count", "unchanged"), ("hwsku", "unchanged"), ("platform", "unchanged"),
         ("mac", "unchanged"), ("/etc/sonic/config_db.json md5", "unchanged"))
SCOPE = "A first injection onto a stock guest is not measured by that proof."


def claim_sentence(claim):
    return ("Measured by tests/sonic_within_boot_reprovision_proof.py on sonic-vm:202405"
            " (REQ-45D-30), re-injecting the overlay into an already-booted guest with a"
            " changed router_id as the sentinel: %s." % ", ".join("%s %s" % kv for kv in claim))


checks, blocked = [], []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))
    return bool(ok)


def _text(x):
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")


def norm(s):
    return " ".join(str(s or "").split())


# ---- declared values: derived from the fixture, never carried as literals -----------------
def declared(doc):
    nodes = {n.get("name"): n for n in (doc.get("nodes") or []) if isinstance(n, dict)}
    son = [n for n in nodes.values() if str(n.get("type")) == "sonic-vm"]
    frr = [n for n in nodes.values() if str(n.get("type")) == "frr"]
    links = [lk for lk in (doc.get("links") or []) if isinstance(lk, dict)]
    if len(son) != 1 or len(frr) != 1 or len(nodes) != 2 or len(links) != 1:
        return None
    try:
        rid = ipaddress.ip_address(str(son[0].get("router_id")))
    except ValueError:
        return None
    sentinel = ipaddress.ip_address(int(rid) + SENTINEL_OFFSET)
    return {"s": son[0], "s_name": son[0]["name"], "r_name": frr[0]["name"],
            "rid": str(rid), "sentinel": str(sentinel),
            "bgp_declared": sorted(str(n.get("name")) for n in nodes.values() if "asn" in n or "bgp" in n)}


def lo_key(rid):
    return "Loopback0|%s/32" % rid


# ---- predicates applied to the product's output or the guest's (each has a two-directional NV)
def parse_meta(raw):
    """DEVICE_METADATA['localhost'] as `sonic-cfggen -v` prints it (a Python literal):
    (hwsku, platform, mac), or None unless all three are present and mac is well formed."""
    try:
        d = ast.literal_eval(_text(raw).strip() or "{}")
    except (ValueError, SyntaxError):
        return None
    if not isinstance(d, dict):
        return None
    hw, pf, mac = d.get("hwsku"), d.get("platform"), str(d.get("mac") or "").lower()
    if not hw or not pf or not MAC.match(mac):
        return None
    return str(hw), str(pf), mac


def parse_md5(raw, path):
    """`md5sum <path>` output: the digest, or None unless it is exactly one line for path."""
    lines = [l for l in _text(raw).splitlines() if l.strip()]
    if len(lines) != 1:
        return None
    parts = lines[0].split()
    if len(parts) != 2 or parts[1] != path or not HEX32.match(parts[0]):
        return None
    return parts[0]


def parse_table(raw):
    """`sonic-cfggen -d --var-json <TABLE>`: a non-empty JSON object, or None."""
    try:
        d = json.loads(_text(raw).strip() or "null")
    except ValueError:
        return None
    return d if isinstance(d, dict) and d else None


def sentinel_ok(before_lo, after_lo, rid, sentinel):
    """L1+L3: the declared loopback key before and after; the sentinel key only after."""
    if not isinstance(before_lo, dict) or not isinstance(after_lo, dict):
        return False
    return (lo_key(rid) in before_lo and lo_key(sentinel) not in before_lo
            and lo_key(rid) in after_lo and lo_key(sentinel) in after_lo)


def authors_platform(ov):
    """Whether an overlay authors PORT or DEVICE_METADATA's hwsku, platform or mac (REQ-45C-44a)."""
    return "PORT" in ov or any(f in ((ov.get("DEVICE_METADATA") or {}).get("localhost") or {})
                               for f in ("hwsku", "platform", "mac"))


def applied_ok(applied, sentinel):
    """L2: the overlay `provision` returns as applied carries the sentinel loopback key and
    authors none of the values L4 measures."""
    if not isinstance(applied, dict):
        return False
    ov = applied.get("config_db.json") or {}
    return lo_key(sentinel) in (ov.get("LOOPBACK_INTERFACE") or {}) and not authors_platform(ov)


def values(meta, ports, md5):
    """The five values REQ-45D-30 measures, keyed as CLAIM names them, or None."""
    if meta is None or ports is None or md5 is None:
        return None
    return {"PORT count": len(ports), "hwsku": meta[0], "platform": meta[1], "mac": meta[2],
            "/etc/sonic/config_db.json md5": md5}


def relations(before, after):
    if not isinstance(before, dict) or not isinstance(after, dict) or set(before) != set(after):
        return None
    return tuple((k, "unchanged" if before[k] == after[k] else "changed") for k, _ in CLAIM
                 if k in before)


def claim_holds(before, after, claim):
    """L4: every value CLAIM names was read before and after, and its relation is CLAIM's."""
    r = relations(before, after)
    return r is not None and r == tuple(claim)


def doc_ok(doc, claim):
    """D: the docstring states the claim and its scope, and not the unmeasured sentence."""
    d = norm(doc)
    return norm(claim_sentence(claim)) in d and norm(SCOPE) in d and norm(OLD_SENTENCE) not in d


def overlay_ok(ov_a, ov_b, rid, sentinel):
    """O: the two overlays differ in LOOPBACK_INTERFACE exactly by the loopback key, and
    neither authors PORT or DEVICE_METADATA's hwsku, platform or mac."""
    if not isinstance(ov_a, dict) or not isinstance(ov_b, dict):
        return False
    la, lb = ov_a.get("LOOPBACK_INTERFACE") or {}, ov_b.get("LOOPBACK_INTERFACE") or {}
    rest_a = {k: v for k, v in ov_a.items() if k != "LOOPBACK_INTERFACE"}
    rest_b = {k: v for k, v in ov_b.items() if k != "LOOPBACK_INTERFACE"}
    authored = any(authors_platform(o) for o in (ov_a, ov_b))
    return (set(la) ^ set(lb) == {lo_key(rid), lo_key(sentinel)} and lo_key(rid) in la
            and lo_key(sentinel) in lb and rest_a == rest_b and not authored)


def launcher_lacks(probe, outs, values):
    """L5: the launcher answers a plain command (probe = (rc, text)), none of its outputs for
    the guest's reads carries a guest value (compared case-insensitively), and none of them
    parses as a DEVICE_METADATA answer."""
    return probe[0] == 0 and bool(probe[1].strip()) and all(values) and all(
        str(v).lower() not in out.lower() for (_rc, out) in outs for v in values) and all(
        parse_meta(out) is None for (_rc, out) in outs)


def saved_lacks(saved_raw, cfgdb_lo, sentinel):
    """L6: the saved file is a config_db (a JSON object with a PORT table), its
    LOOPBACK_INTERFACE lacks the sentinel key, and ConfigDB's carries it."""
    try:
        d = json.loads(_text(saved_raw).strip() or "null")
    except ValueError:
        return False
    if not isinstance(d, dict) or not d.get("PORT") or not isinstance(cfgdb_lo, dict):
        return False
    return lo_key(sentinel) not in (d.get("LOOPBACK_INTERFACE") or {}) and lo_key(sentinel) in cfgdb_lo


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
DOC = (yaml.safe_load(open(FIXTURE, encoding="utf-8").read()) or {}) if os.path.isfile(FIXTURE) else {}
D = declared(DOC)
check("F one frr node and one sonic-vm node, one link, a declared router_id on the guest", D is not None)
if D is not None:
    check("F the sonic-vm node runs as vm (one guest) in generated mode, on the provider's default image",
          D["s"].get("runtime") == "vm" and str(D["s"].get("sonic_mode") or "generated") == "generated"
          and D["s"].get("image") == S.SONIC_DEFAULT_IMAGE, "image=%s" % D["s"].get("image"))
    check("F no node declares BGP (no asn, no bgp)", not D["bgp_declared"], "%s" % D["bgp_declared"])
    _addrs = [str(n.get("router_id")) for n in DOC.get("nodes") or [] if n.get("router_id")]
    _addrs += [str(ip).split("/")[0] for lk in DOC.get("links") or [] for ip in lk.get("ipv4") or []]
    check("F the sentinel router_id is not a declared address", D["sentinel"] not in _addrs,
          "sentinel=%s" % D["sentinel"])
_rc, _out = cassian("validate", FIXTURE)
check("F the fixture validates", _rc == 0, "rc=%d" % _rc)

# ---- D: the docstring states the measured claim ----------------------------------------
check("D `provision`'s docstring states the claim and its scope, and not the 2026-08-18 sentence",
      doc_ok(S.provision.__doc__, CLAIM))

# ---- O: the sentinel, through the product's generator ----------------------------------
_PORTS = S.derive_port_order({"Ethernet%d" % (i * 4): {"index": str(i)} for i in range(32)}, "s1")
_FACTS = {"hwsku": "Force10-S6000", "port_order": _PORTS}
if D is not None:
    _t2 = copy.deepcopy(DOC)
    [n for n in _t2["nodes"] if n.get("name") == D["s_name"]][0]["router_id"] = D["sentinel"]
    _ova = S.gen_node_config(D["s"], DOC, _FACTS)["config_db.json"]
    _ovb = S.gen_node_config([n for n in _t2["nodes"] if n.get("name") == D["s_name"]][0], _t2,
                             _FACTS)["config_db.json"]
    check("O the generator's overlays for the declared and the sentinel router_id differ in "
          "LOOPBACK_INTERFACE exactly by the loopback key, and neither authors PORT, hwsku, platform "
          "or mac", overlay_ok(_ova, _ovb, D["rid"], D["sentinel"]))


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
    clause alone (a dropped clause turns this check red), and only the direction tested prints."""
    a = pred(complete)
    got = [(d, m, pred(m)) for d, m in (("too-much", too_much), ("too-little", too_little)) if m is not None]
    ok = check("NV %s: complete passes, the %s mutation is detected" % (label, " and ".join(d for d, _m, _r in got)),
               a and bool(got) and not any(r for _d, _m, r in got),
               "complete=%s %s" % (a, " ".join("%s=%s" % (d, r) for d, _m, r in got)))
    if ok:
        for d, _m, _r in got:
            print("  MUTATION-FAIL: %s (%s)" % (d, label))


RID, SEN = "192.0.2.250", "192.0.2.252"
_META = "{'hwsku': 'Force10-S6000', 'platform': 'x86_64-kvm_x86_64-r0', 'mac': '22:ce:bf:95:32:4d'}"
_MD5A, _MD5B = "a6024c1e" * 4, "67e278c4" * 4
_LB, _LA = {"Loopback0": {}, lo_key(RID): {}}, {"Loopback0": {}, lo_key(RID): {}, lo_key(SEN): {}}
_V = {"PORT count": 32, "hwsku": "Force10-S6000", "platform": "x86_64-kvm_x86_64-r0",
      "mac": "22:ce:bf:95:32:4d", "/etc/sonic/config_db.json md5": _MD5A}
_DM = {"localhost": {"hostname": "s1"}}
_MAC_DM = {"localhost": {"hostname": "s1", "mac": "22:ce:bf:95:32:4d"}}
_OVA = {"DEVICE_METADATA": _DM, "LOOPBACK_INTERFACE": {"Loopback0": {}, lo_key(RID): {}}}
_OVB = {"DEVICE_METADATA": _DM, "LOOPBACK_INTERFACE": {"Loopback0": {}, lo_key(SEN): {}}}
_NF = "OCI runtime exec failed: exec: \"sonic-cfggen\": executable file not found in $PATH"
_GV = (_MD5A, "22:ce:bf:95:32:4d", lo_key(RID))
_LOK = [(1, "md5sum: %s: No such file or directory\n" % CONFIG_DB), (127, _NF), (127, _NF)]
_SAVED = json.dumps({"PORT": {"Ethernet0": {"index": "0"}}, "LOOPBACK_INTERFACE": {"Loopback0": {}}})
_DOC = "    " + claim_sentence(CLAIM) + "\n    " + SCOPE + "\n"

P_META = lambda x: parse_meta(x) is not None  # noqa: E731
P_MD5 = lambda x: parse_md5(x, CONFIG_DB) is not None  # noqa: E731
P_SEN = lambda x: sentinel_ok(x[0], x[1], RID, SEN)  # noqa: E731
P_OV = lambda x: overlay_ok(x[0], x[1], RID, SEN)  # noqa: E731
P_L = lambda x: launcher_lacks(x[0], x[1], _GV)  # noqa: E731

# one entry per predicate, both directions (REQ-45D-31)
nv("parse_meta", P_META, _META, _META.replace("32:4d'", "32:4d:00'"), _META.replace(", 'mac': '22:ce:bf:95:32:4d'", ""))
nv("parse_md5", P_MD5, "%s  %s\n" % (_MD5A, CONFIG_DB),
   "%s  %s\n%s  /etc/sonic/init_cfg.json\n" % (_MD5A, CONFIG_DB, _MD5B), "md5sum: %s: No such file\n" % CONFIG_DB)
nv("parse_table", lambda x: parse_table(x) is not None, '{"Ethernet0": {"index": "0"}}',
   '{"Ethernet0": {"index": "0"}} {"Ethernet4": {"index": "1"}}', "{}")
nv("sentinel_ok", P_SEN, (_LB, _LA), (_LA, _LA), (_LB, _LB))
nv("applied_ok", lambda x: applied_ok(x, SEN), {"config_db.json": {"LOOPBACK_INTERFACE": _LA}},
   {"config_db.json": {"LOOPBACK_INTERFACE": _LA, "PORT": {"Ethernet0": {"index": "0"}}}},
   {"config_db.json": {"LOOPBACK_INTERFACE": _LB}})
nv("claim_holds", lambda x: claim_holds(x[0], x[1], CLAIM), (_V, dict(_V)),
   (_V, dict(_V, **{"/etc/sonic/config_db.json md5": _MD5B})),
   ({k: v for k, v in _V.items() if k != "mac"}, {k: v for k, v in _V.items() if k != "mac"}))
nv("doc_ok", lambda x: doc_ok(x, CLAIM), _DOC, _DOC + "    " + OLD_SENTENCE + "\n", "    " + SCOPE + "\n")
nv("overlay_ok", P_OV, (_OVA, _OVB), (_OVA, dict(_OVB, DEVICE_METADATA=_MAC_DM)),
   (_OVA, dict(_OVB, LOOPBACK_INTERFACE={"Loopback0": {}})))
nv("launcher_lacks", P_L, ((0, "Linux\n"), _LOK),
   ((0, "Linux\n"), [(0, "%s  %s\nwarning: x\n" % (_MD5A, CONFIG_DB)), (127, _NF), (127, _NF)]),
   ((1, ""), [(1, ""), (127, ""), (127, "")]))
nv("saved_lacks", lambda x: saved_lacks(x[0], x[1], SEN), (_SAVED, _LA),
   (json.dumps({"PORT": {"Ethernet0": {"index": "0"}}, "LOOPBACK_INTERFACE": _LA}), _LA),
   (json.dumps({"LOOPBACK_INTERFACE": {"Loopback0": {}}}), _LA))

# clauses the entries above do not each isolate: one mutation per clause, rejected by it alone
nvc("parse_meta: hwsku present", P_META, _META, too_little=_META.replace("'hwsku': 'Force10-S6000', ", ""))
nvc("parse_meta: platform present", P_META, _META,
    too_little=_META.replace(" 'platform': 'x86_64-kvm_x86_64-r0',", ""))
nvc("parse_md5: the line names the whole path", P_MD5, "%s  %s\n" % (_MD5A, CONFIG_DB),
    too_little="%s  %s\n" % (_MD5A, CONFIG_DB[:-len(".json")]))
nvc("parse_md5: a 32-hex digest", P_MD5, "%s  %s\n" % (_MD5A, CONFIG_DB),
    too_much="%s  %s\n" % (_MD5A + "0", CONFIG_DB), too_little="%s  %s\n" % (_MD5A[:-1], CONFIG_DB))
nvc("sentinel_ok: the declared key present before", P_SEN, (_LB, _LA), too_little=({"Loopback0": {}}, _LA))
nvc("sentinel_ok: the declared key kept after", P_SEN, (_LB, _LA),
    too_little=(_LB, {"Loopback0": {}, lo_key(SEN): {}}))
nvc("doc_ok: the scope stated", lambda x: doc_ok(x, CLAIM), _DOC, too_little="    " + claim_sentence(CLAIM) + "\n")
nvc("overlay_ok: the rest of the overlays equal", P_OV, (_OVA, _OVB),
    too_much=(_OVA, dict(_OVB, VLAN={"Vlan10": {"vlanid": "10"}})))
nvc("overlay_ok: the loopback tables differ by the two keys only", P_OV, (_OVA, _OVB),
    too_much=(dict(_OVA, LOOPBACK_INTERFACE=dict(_OVA["LOOPBACK_INTERFACE"], **{lo_key("192.0.2.9"): {}})), _OVB))
nvc("overlay_ok: the declared key in the declared overlay", P_OV, (_OVA, _OVB),
    too_little=(dict(_OVA, LOOPBACK_INTERFACE={"Loopback0": {}}), dict(_OVB, LOOPBACK_INTERFACE=_LA)))
nvc("overlay_ok: the sentinel key in the sentinel overlay", P_OV, (_OVA, _OVB),
    too_much=(dict(_OVA, LOOPBACK_INTERFACE=_LA), dict(_OVB, LOOPBACK_INTERFACE={"Loopback0": {}})))
nvc("overlay_ok: neither overlay authors a platform value", P_OV, (_OVA, _OVB),
    too_much=(dict(_OVA, DEVICE_METADATA=_MAC_DM), dict(_OVB, DEVICE_METADATA=_MAC_DM)))
nvc("launcher_lacks: the probe exits 0", P_L, ((0, "Linux\n"), _LOK),
    too_little=((127, "sh: 1: uname: not found\n"), _LOK))
nvc("launcher_lacks: the probe prints text", P_L, ((0, "Linux\n"), _LOK), too_little=((0, " \n"), _LOK))
nvc("launcher_lacks: values compared case-insensitively", P_L, ((0, "Linux\n"), _LOK),
    too_much=((0, "Linux\n"), [_LOK[0], (0, "{'mac': '22:CE:BF:95:32:4D'}\n"), _LOK[2]]))
nvc("launcher_lacks: no DEVICE_METADATA answer", P_L, ((0, "Linux\n"), _LOK),
    too_much=((0, "Linux\n"), [_LOK[0], (0, _META.replace("22:ce:bf:95:32:4d", "52:54:00:12:34:56") + "\n"), _LOK[2]]))
nvc("launcher_lacks: L1's values were read", lambda x: launcher_lacks(x[0], x[1], x[2]), ((0, "Linux\n"), _LOK, _GV),
    too_little=((0, "Linux\n"), _LOK, (None, None, lo_key(RID))))
nvc("saved_lacks: ConfigDB carries the sentinel", lambda x: saved_lacks(x[0], x[1], SEN), (_SAVED, _LA),
    too_little=(_SAVED, _LB))


# ---- live legs ---------------------------------------------------------------------------
def live(topo, lab):
    if os.path.realpath(topo) != os.path.realpath(FIXTURE) or lab != DOC.get("name") or D is None:
        check("LIVE argv names the within-boot fixture and its lab", False, "%s %s" % (topo, lab))
        return
    sn, rid, sen = D["s_name"], D["rid"], D["sentinel"]
    import cassian_runtime_vm as RV  # the product's runtime seam, as the other (VM) proofs use it
    rt = RV.build_runtime(DOC)

    def guest(cmd):
        cp = rt.exec(lab, sn, list(cmd), check=False, capture_output=True)
        out = _text(cp.stdout)
        print("     guest(%s)$ %s -> rc=%s\n%s" % (sn, " ".join(cmd), cp.returncode,
                                                 "\n".join("       " + l for l in out.rstrip("\n").split("\n")[:12])))
        return cp.returncode, out

    def launcher(cmd):
        cp = rt.substrate_exec(lab, sn, list(cmd), check=False, capture_output=True, timeout_s=30)
        out = _text(cp.stdout) + _text(getattr(cp, "stderr", ""))
        print("     launcher(%s)$ %s -> rc=%s\n%s" % (sn, " ".join(cmd), cp.returncode,
                                                    "\n".join("       " + l for l in out.rstrip("\n").split("\n")[:6])))
        return cp.returncode, out

    def read_all(tag):
        rm, om = guest(S._DEVICE_METADATA_ARGV)
        rp, op = guest(["sonic-cfggen", "-d", "--var-json", "PORT"])
        r5, o5 = guest(["md5sum", CONFIG_DB])
        rl, ol = guest(["sonic-cfggen", "-d", "--var-json", "LOOPBACK_INTERFACE"])
        meta = parse_meta(om) if rm == 0 else None
        ports = parse_table(op) if rp == 0 else None
        md5 = parse_md5(o5, CONFIG_DB) if r5 == 0 else None
        lo = parse_table(ol) if rl == 0 else None
        v = values(meta, ports, md5)
        print("     %s values: %s; LOOPBACK_INTERFACE keys: %s" % (tag, json.dumps(v, sort_keys=True),
                                                                sorted(lo) if lo else lo))
        return v, lo

    before, lo_b = read_all("before")
    rerun = isinstance(lo_b, dict) and lo_key(sen) in lo_b
    ok1 = check("L1 before: %s's DEVICE_METADATA (hwsku, platform, mac), PORT table, %s md5 and LOOPBACK_INTERFACE read "
          "on the guest; the declared loopback key present, the sentinel absent" % (sn, CONFIG_DB),
                before is not None and isinstance(lo_b, dict) and lo_key(rid) in lo_b and not rerun,
                "the sentinel is already present: a second live run needs a fresh `up --reconfigure`" if rerun else "")

    t2 = copy.deepcopy(DOC)
    n2 = [n for n in t2["nodes"] if n.get("name") == sn][0]
    n2["router_id"] = sen
    applied, err = None, ""
    try:
        applied = S.provision(rt, lab, sn, n2, t2)
    except SystemExit as exc:
        err = "provision exited: %r" % (exc.code,)
    except Exception as exc:  # noqa: BLE001 -- judged below
        err = "provision raised: %r" % exc
    print("     re-injection: router_id %s -> %s; %s" % (rid, sen, err or "provision returned"))
    ok2 = check("L2 the re-injection: the product's provision for %s with router_id %s completes, and the overlay "
                "it applied carries %s and authors no PORT, hwsku, platform or mac" % (sn, sen, lo_key(sen)),
                not err and applied_ok(applied, sen), err)
    if not ok2:
        print("FINDING (S37-R1): the product's provision did not complete the re-injection as stated; nothing "
              "lands, and the result returns to the founder as a card.")

    after, lo_a = read_all("after")
    ok3 = check("L3 after: the same reads; %s present (the injection took effect) and %s still present"
                % (lo_key(sen), lo_key(rid)), after is not None and sentinel_ok(lo_b, lo_a, rid, sen))
    if ok1 and ok2 and not ok3:
        print("FINDING (S37-R1): %s; nothing lands, and the result returns to the founder as a card."
              % ("the product's provision reported the re-injection applied, but the guest's reads after it "
                 "do not show it as L3 states" if after is not None and isinstance(lo_a, dict) else
                 "the guest's reads after the re-injection did not complete (see the read lines above)"))

    rel = relations(before, after)
    print("     measured relations: %s" % (", ".join("%s %s" % kv for kv in rel) if rel else rel))
    print("     claimed relations:  %s" % ", ".join("%s %s" % kv for kv in CLAIM))
    held = claim_holds(before, after, CLAIM)
    ok4 = check("L4 REQ-45D-30: on a re-injection that took effect (L3), each measured relation equals the "
                "docstring's claim (%s)" % ", ".join("%s %s" % kv for kv in CLAIM), ok3 and held,
                "" if ok3 else "not measured: the re-injection did not take effect")
    if ok3 and not held:
        print("FINDING (S37-R1, S37-R3): the measured relations differ from the docstring's claim on this boot; "
              "nothing lands, and the measured relations return to the founder as a card.")

    probe = launcher(LAUNCHER_PROBE)
    outs = [launcher(["md5sum", CONFIG_DB]), launcher(S._DEVICE_METADATA_ARGV),
            launcher(["sonic-cfggen", "-d", "--var-json", "LOOPBACK_INTERFACE"])]
    gv = ((before or {}).get("/etc/sonic/config_db.json md5"), (before or {}).get("mac"), lo_key(rid))
    check("L5 the guest-not-wrapper control: the launcher answers `%s`, and its outputs for the md5, "
          "DEVICE_METADATA and LOOPBACK_INTERFACE reads carry none of L1's md5, mac or declared loopback key"
          % " ".join(LAUNCHER_PROBE), launcher_lacks(probe, outs, gv),
          "probe rc=%s; rcs %s" % (probe[0], [o[0] for o in outs]))

    r6, o6 = guest(["cat", CONFIG_DB])
    print("     information only, not judged: md5 of the text `cat` returned %s; L3's md5 %s"
          % (hashlib.md5(o6.encode("utf-8")).hexdigest(), (after or {}).get("/etc/sonic/config_db.json md5")))
    check("L6 the saved file's control: %s (rc %s) is a config_db whose LOOPBACK_INTERFACE lacks %s, which "
          "ConfigDB carries after L2" % (CONFIG_DB, r6, lo_key(sen)), r6 == 0 and saved_lacks(o6, lo_a, sen))


argv = sys.argv[1:]
if not argv:
    for leg in ("L1 before", "L2 re-injection", "L3 after and sentinel", "L4 REQ-45D-30 claim",
                "L5 guest-not-wrapper control", "L6 saved-file control"):
        blocked.append((leg, "no live argv: run `live <topo> <lab>` on a lab that is up"))
elif argv[0] == "live" and len(argv) == 3:
    live(argv[1], argv[2])
else:
    sys.exit("usage: sonic_within_boot_reprovision_proof.py [live <topo> <lab>]")

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
