#!/usr/bin/env python3
"""init_cfg.json layering on a SONiC guest (§4.5-d VM-7; scope §9 row 12): REQ-45D-29, with REQ-45D-31.

Founder ruling S37-R4 of 2026-10-20, with S37-R1 and S37-R2 (the session-37 rulings note,
cassian-gate-internal@5c19e70, Ledger §163). One fixture, one boot (LD-45D-6):
topologies/sonic-init-cfg-layering.yaml -- one frr node and one sonic-vm guest in
preconfigured mode, whose operator artifact (topologies/sonic-init-cfg-layering-config-db.json)
`cassian up` applies with `config reload -y -f` (LD-45C-R17 R3). No BGP session is declared.

REQ-45D-29 (handover §2; Ledger BL-P2-4.5c-86): §4.5-c measured /etc/sonic/init_cfg.json's
layering at TABLE level only -- an omitted table returned (arm A) and declared sentinels
survived (arm D). Unmeasured were field-level containment (does init_cfg's DEVICE_METADATA
backfill fields an operator table omits?) and a table the operator declares empty (omission
or empty?). This file records both, with A and D re-measured on the same boot as controls.
The arms, chosen from the pre-run's read of init_cfg.json (S37-R4) and named below:
  F  DEVICE_METADATA.localhost omits ARM_F_FIELDS, which init_cfg.json carries.
  E  ARM_E_TABLE, which init_cfg.json carries, is declared {}.
  A  ARM_A_TABLE, which init_cfg.json carries, is omitted (control: expected to return).
  D  ARM_D's field, which init_cfg.json carries with another value, is declared as SENTINEL
     (control: expected to survive).
F and E are recorded whichever way they land. The live legs fail only if a read fails or a
control breaks (S37-R4), read here as follows -- a reading, not a ruling: a read fails when a
guest read exits non-zero or does not parse, when the premises do not hold (init_cfg.json on
this guest does not carry what the arms name), or when the absence signature does not read as
absent; a control breaks when arm A or arm D does, when the artifact did not take effect, or
when the guest-not-wrapper control does.

Lab-free legs (always run):
  F   the fixture's shape, derived values only; the fixture validates.
  A   the artifact's shape: exactly PORT, DEVICE_METADATA, ARM_E_TABLE and ARM_D's table;
      the PORT table naming exactly the product's port map for the declared hwsku;
      DEVICE_METADATA holding localhost alone, declaring hwsku, platform and mac and none of
      ARM_F_FIELDS; ARM_E_TABLE {}; ARM_D's table carrying the sentinel field alone.
  NV  REQ-45D-31 two-directional non-vacuity for each predicate function this file applies to
      the guest's output or the artifact: a complete synthetic observation satisfies it, and
      a mutation in each direction -- too much and too little -- is detected. Then, for each
      clause those mutations do not each isolate, one mutation rejected by that clause
      alone, printed only for the direction it tests. Printed in handover §18's literal
      form, `MUTATION-FAIL: too-much (<label>)` and `MUTATION-FAIL: too-little (<label>)`
      (S35-R3).

Live legs (`live <topo> <lab>`, on a lab already up):
  L1  the premises: /etc/sonic/init_cfg.json, read with `cat` on the guest (rt.exec), parses
      and carries each of ARM_F_FIELDS in DEVICE_METADATA.localhost, ARM_E_TABLE and
      ARM_A_TABLE non-empty, and ARM_D's field; it carries the sentinel nowhere.
  L2  the reads, through `sonic-cfggen -d --var-json <TABLE>` on the guest: DEVICE_METADATA,
      PORT, ARM_E_TABLE, ARM_A_TABLE and ARM_D's table, each exiting 0 and parsing as a
      table or as absent; and the absence signature -- the same read of a table no source
      declares (ABSENT_TABLE) exits 0 and reads as absent -- so "absent" is a measured
      shape, not an assumed one.
  L3  the controls, judged when L1 and L2 hold: ARM_A_TABLE, omitted, is present and equal
      to init_cfg's (arm A); ARM_D's field carries the sentinel (arm D); the artifact took
      effect -- every DEVICE_METADATA.localhost field it declares carries its value, and
      ConfigDB's PORT table names exactly the artifact's ports.
  L4  REQ-45D-29 arm F, recorded whenever L1 and the DEVICE_METADATA read succeed: for each
      of ARM_F_FIELDS, ConfigDB's value beside init_cfg's, classified as backfilled with
      init_cfg's value, absent, or present with another value.
  L5  REQ-45D-29 arm E, recorded whenever L1, the ARM_E_TABLE read and the absence signature
      succeed: ARM_E_TABLE in ConfigDB, classified as absent (the empty declaration held),
      equal to init_cfg's (the empty declaration read as an omission), or present and
      different from init_cfg's.
  L6  the guest-not-wrapper control (house pattern since S35-R1): through the product's
      substrate_exec, which reaches the vrnetlab launcher that wraps the guest, the launcher
      answers a plain command, while three of L2's reads sent there (DEVICE_METADATA, ARM_D's
      table, ARM_E_TABLE) carry neither the sentinel nor the artifact's mac and none parses as
      a DEVICE_METADATA table -- so L2's values can only have come from the guest.

usage:
  sonic_init_cfg_layering_proof.py                    lab-free legs; L1-L6 BLOCKED; exit 0 if green
  sonic_init_cfg_layering_proof.py live <topo> <lab>  lab-free legs, then L1-L6 on a lab already up

Coverage limits, stated in-file (PBE-P2-8):
  - One boot of one fixture on one image. The image's build and init_cfg.json's sha256 are
    printed, not judged.
  - Values are ConfigDB's, read through `sonic-cfggen -d --var-json`. A field ConfigDB carries
    with init_cfg's value is recorded as that; which writer put it there during `config
    reload` -- sonic-cfggen merging init_cfg.json under the artifact, or a later writer such
    as db_migrator -- is not attributed by this file. Likewise for arm E: "read as an
    omission" names the observed equality with init_cfg's table, not the mechanism behind it.
  - Arms A, E and F discriminate only because `config reload` flushes ConfigDB and rewrites it
    from init_cfg.json and the file it is given (LD-45C-R17 R3); this file does not observe
    that rewrite, and a value left over from the boot's first configuration would read the same.
    tests/sonic_preconfigured_proof.py pins the reload argv.
  - Arm F covers DEVICE_METADATA.localhost's scalar fields only; arm E covers one table
    declared {}. Nested keys, list-valued fields and other tables are not measured.
  - Arm D declares only ARM_D's field of its table; the table's other fields are printed for
    information (motd only in the raw read), not judged, and are not REQ-45D-29's.
  - Every guest command this file runs is a read; the artifact is applied by the product's
    `cassian up`, not by this file.
  - L6 reads the launcher through substrate_exec; it does not inspect the wrapper chain.

Exit 0 when every check passes (BLOCKED or NOT ATTEMPTED legs are listed); exit 1 otherwise.
"""
import copy
import json
import os
import subprocess
import sys

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

import cassian_nos_sonic as S  # noqa: E402

FIXTURE = os.path.join(ROOT, "topologies", "sonic-init-cfg-layering.yaml")
INIT_CFG = "/etc/sonic/init_cfg.json"
LAUNCHER_PROBE = ["uname", "-s"]

# The arms (S37-R4), chosen from the pre-run's read of init_cfg.json on sonic-vm:202405.
ARM_F_FIELDS = ("buffer_model", "default_bgp_status", "default_pfcwd_status", "timezone")
ARM_E_TABLE = "KDUMP"
ARM_A_TABLE = "NTP"
ARM_D = ("BANNER_MESSAGE", "global", "login")
SENTINEL = "CASSIAN-S37-R4-SENTINEL"
ABSENT_TABLE = "CASSIAN_S37_NO_SUCH_TABLE"
PLATFORM_FIELDS = ("hwsku", "platform", "mac")


class _Absent(object):
    def __repr__(self):
        return "ABSENT"


ABSENT = _Absent()

checks, blocked = [], []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))
    return bool(ok)


def _text(x):
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")


def _get(d, *keys):
    """d[k0][k1]..., or None as soon as a level is not a mapping or lacks the key."""
    for k in keys:
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def norm(v):
    """A table as ConfigDB returns it: every scalar a string."""
    if isinstance(v, dict):
        return {str(k): norm(w) for k, w in v.items()}
    if isinstance(v, list):
        return [norm(w) for w in v]
    return str(v)


def show(v):
    return "ABSENT" if v is ABSENT else json.dumps(v, sort_keys=True, separators=(",", ":"))


# ---- declared values: derived from the fixture, never carried as literals -----------------
def declared(doc):
    nodes = {n.get("name"): n for n in (doc.get("nodes") or []) if isinstance(n, dict)}
    son = [n for n in nodes.values() if str(n.get("type")) == "sonic-vm"]
    frr = [n for n in nodes.values() if str(n.get("type")) == "frr"]
    links = [lk for lk in (doc.get("links") or []) if isinstance(lk, dict)]
    if len(son) != 1 or len(frr) != 1 or len(nodes) != 2 or len(links) != 1 or not son[0].get("sonic_config_db"):
        return None
    return {"s": son[0], "s_name": son[0]["name"], "r_name": frr[0]["name"],
            "artifact": os.path.join(os.path.dirname(FIXTURE), str(son[0]["sonic_config_db"])),
            "bgp_declared": sorted(str(n.get("name")) for n in nodes.values() if "asn" in n or "bgp" in n)}


# ---- predicates applied to the artifact or the guest's output (each has a two-directional NV)
def parse_var_json(raw):
    """`sonic-cfggen -d --var-json <TABLE>` output: the table (a JSON object), ABSENT when the
    output is empty, or None when it is anything else."""
    t = _text(raw).strip()
    if not t:
        return ABSENT
    try:
        d = json.loads(t)
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def artifact_ok(art, port_names):
    """A: exactly PORT, DEVICE_METADATA, ARM_E_TABLE and ARM_D's table; PORT names exactly
    port_names; DEVICE_METADATA holds localhost alone, which declares hwsku, platform and mac
    and none of ARM_F_FIELDS; ARM_E_TABLE is {}; ARM_D's table carries the sentinel field
    alone."""
    if not isinstance(art, dict):
        return False
    dm = art.get("DEVICE_METADATA")
    lh = dm.get("localhost") if isinstance(dm, dict) else None
    return (set(art) == {"PORT", "DEVICE_METADATA", ARM_E_TABLE, ARM_D[0]}
            and isinstance(art.get("PORT"), dict) and bool(port_names)
            and sorted(art["PORT"]) == sorted(port_names)
            and isinstance(lh, dict) and list(dm) == ["localhost"]
            and all(lh.get(f) for f in PLATFORM_FIELDS)
            and not any(f in lh for f in ARM_F_FIELDS)
            and art.get(ARM_E_TABLE) == {}
            and art.get(ARM_D[0]) == {ARM_D[1]: {ARM_D[2]: SENTINEL}})


def init_ok(init):
    """L1: init_cfg.json carries each of ARM_F_FIELDS in DEVICE_METADATA.localhost,
    ARM_E_TABLE and ARM_A_TABLE non-empty, and ARM_D's field, and the sentinel nowhere."""
    if not isinstance(init, dict):
        return False
    lh = _get(init, "DEVICE_METADATA", "localhost")
    d = _get(init, ARM_D[0], ARM_D[1])
    return (isinstance(lh, dict) and all(f in lh for f in ARM_F_FIELDS)
            and isinstance(init.get(ARM_E_TABLE), dict) and bool(init[ARM_E_TABLE])
            and isinstance(init.get(ARM_A_TABLE), dict) and bool(init[ARM_A_TABLE])
            and isinstance(d, dict) and ARM_D[2] in d
            and SENTINEL not in json.dumps(init))


def control_a(init, db_a):
    """L3 arm A: the omitted table is present in ConfigDB and equal to init_cfg's."""
    return isinstance(init, dict) and isinstance(db_a, dict) and bool(db_a) \
        and norm(db_a) == norm(init.get(ARM_A_TABLE))


def control_d(db_d):
    """L3 arm D: ARM_D's field carries the sentinel."""
    return _get(db_d, ARM_D[1], ARM_D[2]) == SENTINEL


def applied_ok(art, db_dm, db_port):
    """L3: the artifact took effect -- every DEVICE_METADATA.localhost field it declares
    carries its value, and ConfigDB's PORT table names exactly the artifact's ports."""
    want = _get(art, "DEVICE_METADATA", "localhost") or {}
    got = _get(db_dm, "localhost")
    ports = _get(art, "PORT")
    return (bool(want) and isinstance(got, dict) and all(f in got and str(got[f]) == str(v) for f, v in want.items())
            and isinstance(ports, dict) and bool(ports)
            and isinstance(db_port, dict) and sorted(db_port) == sorted(ports))


F_BACKFILLED, F_ABSENT, F_OTHER = ("backfilled with init_cfg's value", "absent",
                                   "present with another value")
E_HELD, E_OMISSION, E_OTHER = ("absent: the empty declaration held",
                               "equal to init_cfg's: the empty declaration read as an omission",
                               "present and different from init_cfg's")


def classify_field(init_v, db_v):
    """L4: one omitted field, classified."""
    if db_v is None:
        return F_ABSENT
    return F_BACKFILLED if str(db_v) == str(init_v) else F_OTHER


def classify_table(init_t, db_t):
    """L5: the table declared {}, classified."""
    if db_t is ABSENT or db_t == {}:
        return E_HELD
    return E_OMISSION if isinstance(db_t, dict) and norm(db_t) == norm(init_t) else E_OTHER


def launcher_lacks(probe, outs, mac):
    """L6: the launcher answers a plain command (probe = (rc, text)); none of its outputs for
    the guest's reads carries the sentinel or the artifact's mac (compared case-insensitively),
    and none parses as a DEVICE_METADATA table."""
    def is_dm(out):
        d = parse_var_json(out)
        return isinstance(d, dict) and "localhost" in d
    return probe[0] == 0 and bool(probe[1].strip()) and bool(mac) and all(
        SENTINEL.lower() not in out.lower() and str(mac).lower() not in out.lower() for (_rc, out) in outs) \
        and not any(is_dm(out) for (_rc, out) in outs)


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
check("F one frr node and one sonic-vm node, one link, an operator artifact on the guest", D is not None)
ART = None
if D is not None:
    check("F the sonic-vm node runs as vm (one guest) in preconfigured mode, on the provider's default image",
          D["s"].get("runtime") == "vm" and str(D["s"].get("sonic_mode")) == "preconfigured"
          and D["s"].get("image") == S.SONIC_DEFAULT_IMAGE, "image=%s" % D["s"].get("image"))
    check("F no node declares BGP (no asn, no bgp)", not D["bgp_declared"], "%s" % D["bgp_declared"])
    try:
        ART = json.load(open(D["artifact"], encoding="utf-8"))
    except (OSError, ValueError) as exc:
        check("F the operator artifact is readable JSON", False, "%s" % exc)
_rc, _out = cassian("validate", FIXTURE)
check("F the fixture validates", _rc == 0, "rc=%d" % _rc)

# ---- A: the artifact's shape -----------------------------------------------------------
_HWSKU = _get(ART, "DEVICE_METADATA", "localhost", "hwsku")
_MAP = tuple(S._SONIC_PORT_MAPS.get(_HWSKU) or ()) if isinstance(_HWSKU, str) else ()
check("A the artifact carries exactly PORT (naming the product's %d-port map for %s), DEVICE_METADATA.localhost "
      "alone declaring hwsku, platform and mac and none of %s, %s {} and %s.%s.%s = %s alone"
      % (len(_MAP), _HWSKU, "/".join(ARM_F_FIELDS), ARM_E_TABLE, ARM_D[0], ARM_D[1], ARM_D[2], SENTINEL),
      artifact_ok(ART, _MAP))


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
    clause alone (dropping the clause turns this check red, or, for a type-guard clause, makes
    the run raise), and only the direction tested prints."""
    a = pred(complete)
    got = [(d, m, pred(m)) for d, m in (("too-much", too_much), ("too-little", too_little)) if m is not None]
    ok = check("NV %s: complete passes, the %s mutation is detected" % (label, " and ".join(d for d, _m, _r in got)),
               a and bool(got) and not any(r for _d, _m, r in got),
               "complete=%s %s" % (a, " ".join("%s=%s" % (d, r) for d, _m, r in got)))
    if ok:
        for d, _m, _r in got:
            print("  MUTATION-FAIL: %s (%s)" % (d, label))


def _with(d, path, value):
    """A deep copy of d with the key at `path` set to value (or removed, for ABSENT)."""
    m = copy.deepcopy(d)
    cur = m
    for k in path[:-1]:
        cur = cur[k]
    if value is ABSENT:
        cur.pop(path[-1], None)
    else:
        cur[path[-1]] = value
    return m


_MAC = "00:11:22:ab:44:01"  # hex letters, so the case-insensitive comparison is exercised
_MAC_UPPER, _SENTINEL_LOWER = _MAC.upper(), SENTINEL.lower()  # the two case mutations' data
_ART = {"DEVICE_METADATA": {"localhost": {"hwsku": "Force10-S6000", "platform": "x86_64-kvm_x86_64-r0",
                                          "mac": _MAC, "hostname": "sonic"}},
        "PORT": {"Ethernet%d" % (i * 4): {"index": str(i)} for i in range(4)},
        ARM_E_TABLE: {}, ARM_D[0]: {ARM_D[1]: {ARM_D[2]: SENTINEL}}}
_NAMES = tuple(_ART["PORT"])
_RENAMED = _with(_with(_ART, ("PORT", "Ethernet0"), ABSENT), ("PORT", "Ethernet999"), {"index": "0"})
_INIT = {"DEVICE_METADATA": {"localhost": {f: "v-%s" % f for f in ARM_F_FIELDS}},
         ARM_E_TABLE: {"config": {"enabled": "false", "num_dumps": "3"}},
         ARM_A_TABLE: {"global": {"vrf": "default", "admin_state": "enabled"}},
         ARM_D[0]: {ARM_D[1]: {ARM_D[2]: "Debian GNU/Linux 11", "state": "disabled"}},
         "FEATURE": {"bgp": {"has_global_scope": False}}}
_DB_DM = {"localhost": dict(_ART["DEVICE_METADATA"]["localhost"], **_INIT["DEVICE_METADATA"]["localhost"])}
_DB_PORT = copy.deepcopy(_ART["PORT"])
_DB_D = {ARM_D[1]: {ARM_D[2]: SENTINEL, "state": "disabled"}}
_E_JSON = json.dumps(_INIT[ARM_E_TABLE], indent=4)
_NF = "OCI runtime exec failed: exec: \"sonic-cfggen\": executable file not found in $PATH"
_LOK = [(127, _NF), (127, _NF), (127, _NF)]

P_VJ = lambda x: parse_var_json(x) is not None  # noqa: E731 -- what L2 applies to each read
P_ART = lambda x: artifact_ok(x, _NAMES)  # noqa: E731
P_APP = lambda x: applied_ok(x[0], x[1], x[2])  # noqa: E731
P_L = lambda x: launcher_lacks(x[0], x[1], _MAC)  # noqa: E731

# one entry per predicate, both directions (REQ-45D-31)
nv("parse_var_json", P_VJ, _E_JSON, _E_JSON + "\n" + _E_JSON, '{"config": ')
nv("artifact_ok", P_ART, _ART, _with(_ART, (ARM_A_TABLE,), {"global": {"vrf": "default"}}),
   _with(_ART, (ARM_E_TABLE,), ABSENT))
nv("init_ok", init_ok, _INIT, _with(_INIT, (ARM_D[0], ARM_D[1], ARM_D[2]), SENTINEL),
   _with(_INIT, ("DEVICE_METADATA", "localhost", ARM_F_FIELDS[0]), ABSENT))
nv("control_a", lambda x: control_a(_INIT, x), norm(_INIT[ARM_A_TABLE]),
   _with(norm(_INIT[ARM_A_TABLE]), ("global", "server_role"), "disabled"), ABSENT)
nv("control_d", control_d, _DB_D, _with(_DB_D, (ARM_D[1], ARM_D[2]), SENTINEL + "-x"),
   _with(_DB_D, (ARM_D[1], ARM_D[2]), "Debian GNU/Linux 11"))
nv("applied_ok", P_APP, (_ART, _DB_DM, _DB_PORT),
   (_ART, _with(_DB_DM, ("localhost", "mac"), "52:54:00:12:34:56"), _DB_PORT),
   (_ART, _with(_DB_DM, ("localhost", "hostname"), ABSENT), _DB_PORT))
nv("classify_field: backfilled", lambda x: classify_field("traditional", x) == F_BACKFILLED, "traditional",
   "traditional-x", None)
nv("classify_table: read as an omission", lambda x: classify_table(_INIT[ARM_E_TABLE], x) == E_OMISSION,
   norm(_INIT[ARM_E_TABLE]), _with(norm(_INIT[ARM_E_TABLE]), ("config", "memory"), "0M-2G:256M"), ABSENT)
nv("launcher_lacks", P_L, ((0, "Linux\n"), _LOK),
   ((0, "Linux\n"), [(0, '{"global": {"login": "%s"}}\n' % SENTINEL), (127, _NF), (127, _NF)]),
   ((1, ""), [(1, ""), (127, ""), (127, "")]))

# clauses the entries above do not each isolate: one mutation per clause, rejected by it alone
nvc("parse_var_json: empty output reads as absent", lambda x: parse_var_json(x) is ABSENT, "\n",
    too_much="{}")
nvc("parse_var_json: a non-object is not a table", P_VJ, _E_JSON, too_much='["%s"]' % ARM_E_TABLE)
nvc("artifact_ok: no arm F field declared", P_ART, _ART,
    too_much=_with(_ART, ("DEVICE_METADATA", "localhost", ARM_F_FIELDS[0]), "x"))
nvc("artifact_ok: arm E declared empty", P_ART, _ART, too_much=_with(_ART, (ARM_E_TABLE,), {"config": {}}))
nvc("artifact_ok: arm D the sentinel field alone", P_ART, _ART,
    too_much=_with(_ART, (ARM_D[0], ARM_D[1], "state"), "disabled"))
nvc("artifact_ok: the PORT table names the product's map", P_ART, _ART,
    too_much=_RENAMED, too_little=_with(_ART, ("PORT", "Ethernet12"), ABSENT))
nvc("artifact_ok: a port map to compare against", lambda x: artifact_ok(x[0], x[1]), (_ART, _NAMES),
    too_little=(_with(_ART, ("PORT",), {}), ()))
nvc("artifact_ok: hwsku, platform and mac declared", P_ART, _ART,
    too_little=_with(_ART, ("DEVICE_METADATA", "localhost", "mac"), ABSENT))
nvc("artifact_ok: DEVICE_METADATA holds localhost alone", P_ART, _ART,
    too_much=_with(_ART, ("DEVICE_METADATA", "spare"), {"hwsku": "x"}))
nvc("artifact_ok: no other table", P_ART, _ART, too_much=_with(_ART, ("LOOPBACK_INTERFACE",), {"Loopback0": {}}))
nvc("init_ok: arm E's table carried", init_ok, _INIT, too_little=_with(_INIT, (ARM_E_TABLE,), ABSENT))
nvc("init_ok: arm E's table not empty", init_ok, _INIT, too_little=_with(_INIT, (ARM_E_TABLE,), {}))
nvc("init_ok: arm E's table a table", init_ok, _INIT, too_little=_with(_INIT, (ARM_E_TABLE,), ["config"]))
nvc("init_ok: arm A's table carried", init_ok, _INIT, too_little=_with(_INIT, (ARM_A_TABLE,), ABSENT))
nvc("init_ok: arm A's table a table", init_ok, _INIT, too_little=_with(_INIT, (ARM_A_TABLE,), ["global"]))
nvc("init_ok: arm A's table not empty", init_ok, _INIT, too_little=_with(_INIT, (ARM_A_TABLE,), {}))
nvc("init_ok: arm D's field carried", init_ok, _INIT, too_little=_with(_INIT, (ARM_D[0], ARM_D[1], ARM_D[2]), ABSENT))
nvc("init_ok: the sentinel carried nowhere", init_ok, _INIT,
    too_much=_with(_INIT, (ARM_A_TABLE, "global", "vrf"), SENTINEL))
nvc("init_ok: a malformed DEVICE_METADATA is no premise", init_ok, _INIT,
    too_little=_with(_INIT, ("DEVICE_METADATA",), ["localhost"]))
nvc("control_a: the table not empty", lambda x: control_a(x[0], x[1]), (_INIT, norm(_INIT[ARM_A_TABLE])),
    too_little=({ARM_A_TABLE: {}}, {}))
nvc("control_a: scalars compared as ConfigDB strings", lambda x: control_a({ARM_A_TABLE: {"global": {"dhcp": True}}}, x),
    {"global": {"dhcp": "True"}}, too_much={"global": {"dhcp": "true"}})
nvc("applied_ok: something declared", P_APP, (_ART, _DB_DM, _DB_PORT),
    too_little=(_with(_ART, ("DEVICE_METADATA", "localhost"), {}), _DB_DM, _DB_PORT))
nvc("applied_ok: ConfigDB's localhost a table", P_APP, (_ART, _DB_DM, _DB_PORT),
    too_little=(_ART, {"localhost": "hwsku platform mac hostname"}, _DB_PORT))
nvc("applied_ok: ConfigDB's PORT table names the artifact's ports", P_APP, (_ART, _DB_DM, _DB_PORT),
    too_much=(_ART, _DB_DM, _with(_DB_PORT, ("Ethernet16",), {"index": "4"})),
    too_little=(_ART, _DB_DM, _with(_DB_PORT, ("Ethernet12",), ABSENT)))
nvc("applied_ok: the artifact declares ports", P_APP, (_ART, _DB_DM, _DB_PORT),
    too_little=(_with(_ART, ("PORT",), {}), _DB_DM, {}))
nvc("classify_field: absent", lambda x: classify_field("traditional", x) == F_ABSENT, None, too_much="traditional")
nvc("classify_field: scalars compared as ConfigDB strings", lambda x: classify_field(3, x) == F_BACKFILLED, "3",
    too_much="3.0")
nvc("classify_table: the empty declaration held", lambda x: classify_table(_INIT[ARM_E_TABLE], x) == E_HELD, ABSENT,
    too_much=norm(_INIT[ARM_E_TABLE]))
nvc("classify_table: an empty table read as held", lambda x: classify_table(_INIT[ARM_E_TABLE], x) == E_HELD, {},
    too_much=norm(_INIT[ARM_E_TABLE]))
nvc("classify_table: scalars compared as ConfigDB strings",
    lambda x: classify_table({"config": {"enabled": False, "num_dumps": 3}}, x) == E_OMISSION,
    {"config": {"enabled": "False", "num_dumps": "3"}}, too_much={"config": {"enabled": "false", "num_dumps": "3"}})
nvc("launcher_lacks: the probe exits 0", P_L, ((0, "Linux\n"), _LOK),
    too_little=((127, "sh: 1: uname: not found\n"), _LOK))
nvc("launcher_lacks: the probe prints text", P_L, ((0, "Linux\n"), _LOK), too_little=((0, " \n"), _LOK))
nvc("launcher_lacks: the artifact's mac known", lambda x: launcher_lacks(x[0], x[1], x[2]), ((0, "Linux\n"), _LOK, _MAC),
    too_little=((0, "Linux\n"), _LOK, None))
nvc("launcher_lacks: the sentinel compared case-insensitively", P_L, ((0, "Linux\n"), _LOK),
    too_much=((0, "Linux\n"), [_LOK[0], (0, 'login %s\n' % _SENTINEL_LOWER), _LOK[2]]))
nvc("launcher_lacks: the mac compared case-insensitively", P_L, ((0, "Linux\n"), _LOK),
    too_much=((0, "Linux\n"), [_LOK[0], (0, "mac %s\n" % _MAC_UPPER), _LOK[2]]))
check("NV the two case entries' data: each case mutation differs from its original (%s, %s), so neither entry is "
      "vacuous" % (_MAC_UPPER, _SENTINEL_LOWER), _MAC_UPPER != _MAC and _SENTINEL_LOWER != SENTINEL)
nvc("launcher_lacks: no DEVICE_METADATA table", P_L, ((0, "Linux\n"), _LOK),
    too_much=((0, "Linux\n"), [_LOK[0], (0, '{"localhost": {"hwsku": "Force10-S6000"}}\n'), _LOK[2]]))


# ---- live legs ---------------------------------------------------------------------------
def live(topo, lab):
    if os.path.realpath(topo) != os.path.realpath(FIXTURE) or lab != DOC.get("name") or D is None or ART is None:
        check("LIVE argv names the init_cfg layering fixture and its lab", False, "%s %s" % (topo, lab))
        return
    sn = D["s_name"]
    import cassian_runtime_vm as RV  # the product's runtime seam, as the other (VM) proofs use it
    rt = RV.build_runtime(DOC)

    def guest(cmd, lines=12):
        cp = rt.exec(lab, sn, list(cmd), check=False, capture_output=True)
        out = _text(cp.stdout)
        print("     guest(%s)$ %s -> rc=%s\n%s" % (sn, " ".join(cmd), cp.returncode,
                                                 "\n".join("       " + l for l in out.rstrip("\n").split("\n")[:lines])))
        return cp.returncode, out

    def launcher(cmd):
        cp = rt.substrate_exec(lab, sn, list(cmd), check=False, capture_output=True, timeout_s=30)
        out = _text(cp.stdout) + _text(getattr(cp, "stderr", ""))
        print("     launcher(%s)$ %s -> rc=%s\n%s" % (sn, " ".join(cmd), cp.returncode,
                                                    "\n".join("       " + l for l in out.rstrip("\n").split("\n")[:6])))
        return cp.returncode, out

    def var(table):
        rc, out = guest(["sonic-cfggen", "-d", "--var-json", table], lines=8)
        return rc, (parse_var_json(out) if rc == 0 else None)

    def brief(table):
        return {k: v for k, v in table.items() if k != "motd"} if isinstance(table, dict) else table

    # information only, not judged: the image and the file the premises are read from
    _rv, ov = guest(["cat", "/etc/sonic/sonic_version.yml"], lines=0)
    _rs, osha = guest(["sha256sum", INIT_CFG], lines=0)
    print("     information only, not judged: %s; %s" % (
        " ".join(l.strip() for l in ov.splitlines() if l.startswith("build_version:")) or "build_version unread",
        osha.strip() or "init_cfg.json sha256 unread"))

    r1, o1 = guest(["cat", INIT_CFG], lines=0)
    try:
        init = json.loads(o1) if r1 == 0 else None
    except ValueError:
        init = None
    premises = init_ok(init)
    check("L1 the premises: %s (rc %s) parses and carries %s in DEVICE_METADATA.localhost, %s and %s non-empty, "
          "and %s.%s.%s, and the sentinel nowhere"
          % (INIT_CFG, r1, "/".join(ARM_F_FIELDS), ARM_E_TABLE, ARM_A_TABLE, ARM_D[0], ARM_D[1], ARM_D[2]),
          premises)
    if isinstance(init, dict):
        print("     init_cfg.json: DEVICE_METADATA.localhost %s; %s %s; %s %s; %s.%s %s" % (
            show(_get(init, "DEVICE_METADATA", "localhost")), ARM_E_TABLE, show(init.get(ARM_E_TABLE)),
            ARM_A_TABLE, show(init.get(ARM_A_TABLE)), ARM_D[0], ARM_D[1], show(brief(_get(init, ARM_D[0], ARM_D[1])))))

    reads = {t: var(t) for t in ("DEVICE_METADATA", "PORT", ARM_E_TABLE, ARM_A_TABLE, ARM_D[0], ABSENT_TABLE)}
    got = {t: v for t, (_rc, v) in reads.items()}
    ok2 = check("L2 the reads: `sonic-cfggen -d --var-json` for DEVICE_METADATA, PORT, %s, %s and %s each exit 0 and "
                "parse as a table or as absent; the same read of %s, a table no source declares, exits 0 and reads "
                "as absent" % (ARM_E_TABLE, ARM_A_TABLE, ARM_D[0], ABSENT_TABLE),
                all(rc == 0 and v is not None for rc, v in reads.values()) and got[ABSENT_TABLE] is ABSENT,
                "rcs %s" % {t: rc for t, (rc, _v) in sorted(reads.items())})

    db_dm, db_e, db_a, db_d = got["DEVICE_METADATA"], got[ARM_E_TABLE], got[ARM_A_TABLE], got[ARM_D[0]]
    ca, cd, cp_ = control_a(init, db_a), control_d(db_d), applied_ok(ART, db_dm, got["PORT"])
    print("     ConfigDB: %s %s; %s.%s %s" % (ARM_A_TABLE, show(db_a), ARM_D[0], ARM_D[1],
                                             show(brief(_get(db_d, ARM_D[1]))) if isinstance(db_d, dict) else show(db_d)))
    ok3 = check("L3 the controls: %s, omitted, is present and equal to init_cfg's (arm A); %s.%s.%s carries the "
                "sentinel (arm D); the artifact took effect -- every DEVICE_METADATA.localhost field it declares "
                "carries its value, and ConfigDB's PORT table names exactly its ports"
                % (ARM_A_TABLE, ARM_D[0], ARM_D[1], ARM_D[2]), ok2 and premises and ca and cd and cp_,
                "arm A %s, arm D %s, artifact took effect %s" % (ca, cd, cp_) if ok2 and premises
                else "not judged: see L1 and L2")
    if ok2 and premises and not ok3:
        print("FINDING (S37-R1, S37-R4): a control broke on this boot -- the layering differs from §4.5-c's measured "
              "arms A and D, or the artifact did not take effect; nothing lands, and the result returns to the "
              "founder as a card.")

    lh_i = _get(init, "DEVICE_METADATA", "localhost") or {}
    lh_d = _get(db_dm, "localhost")
    measured = premises and reads["DEVICE_METADATA"][0] == 0 and isinstance(lh_d, dict)
    for f in ARM_F_FIELDS:
        if measured:
            print("  RECORDED (REQ-45D-29, arm F): DEVICE_METADATA.localhost.%s -- omitted by the artifact; init_cfg.json %r; "
                  "ConfigDB %s: %s" % (f, lh_i.get(f), repr(lh_d[f]) if f in lh_d else "absent",
                                       classify_field(lh_i.get(f), lh_d.get(f))))
    check("L4 REQ-45D-29 arm F: for each of %s, omitted by the artifact, ConfigDB's value read beside init_cfg's and "
          "recorded" % "/".join(ARM_F_FIELDS), measured, "" if measured else "not measured: see L1 and L2")

    measured_e = premises and reads[ARM_E_TABLE][0] == 0 and db_e is not None and got[ABSENT_TABLE] is ABSENT
    if measured_e:
        print("  RECORDED (REQ-45D-29, arm E): %s -- declared {} by the artifact; init_cfg.json %s; ConfigDB %s: %s"
              % (ARM_E_TABLE, show(init.get(ARM_E_TABLE)), show(db_e), classify_table(init.get(ARM_E_TABLE), db_e)))
    check("L5 REQ-45D-29 arm E: %s, declared {} by the artifact, read in ConfigDB beside init_cfg's and recorded"
          % ARM_E_TABLE, measured_e, "" if measured_e else "not measured: see L1 and L2")

    probe = launcher(LAUNCHER_PROBE)
    outs = [launcher(["sonic-cfggen", "-d", "--var-json", t]) for t in ("DEVICE_METADATA", ARM_D[0], ARM_E_TABLE)]
    mac = _get(ART, "DEVICE_METADATA", "localhost", "mac")
    check("L6 the guest-not-wrapper control: the launcher answers `%s`, and its outputs for the DEVICE_METADATA, %s "
          "and %s reads carry neither the sentinel nor the artifact's mac, and none is a DEVICE_METADATA table"
          % (" ".join(LAUNCHER_PROBE), ARM_D[0], ARM_E_TABLE), launcher_lacks(probe, outs, mac),
          "probe rc=%s; rcs %s" % (probe[0], [o[0] for o in outs]))


argv = sys.argv[1:]
if not argv:
    for leg in ("L1 premises", "L2 reads", "L3 controls (arms A and D, the artifact took effect)",
                "L4 REQ-45D-29 arm F", "L5 REQ-45D-29 arm E", "L6 guest-not-wrapper control"):
        blocked.append((leg, "no live argv: run `live <topo> <lab>` on a lab that is up"))
elif argv[0] == "live" and len(argv) == 3:
    live(argv[1], argv[2])
else:
    sys.exit("usage: sonic_init_cfg_layering_proof.py [live <topo> <lab>]")

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
