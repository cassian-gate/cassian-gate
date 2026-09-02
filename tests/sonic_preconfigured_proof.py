#!/usr/bin/env python3
"""tests/sonic_preconfigured_proof.py -- §4.5-c WI-1 packet 1.

Req-IDs: REQ-45C-4 (mode declared, resolved, visible), REQ-45C-26 (zero
generation), REQ-45C-27 (missing artifact -> §13-grade, exit 2).
Ledger row: BL-P2-4.5c-49. Rulings: LD-45C-R17 R1/R5/R6/R9/R10/R11,
LD-45C-R20 R1 (packet split), LD-45C-R21 R1/R3 (path resolution).

Snapshot mapping: `cassian_model` -> `src/cassian_model.py`;
`cassian_nos_sonic` -> `src/cassian_nos_sonic.py`. Session snapshot v63 ==
branch `feature/4_5c-sonic-base-lifecycle` @ `05aafc9` + this packet.

WHAT THIS COVERS -- §15.2's two preconfigured rows, and which is NOT here:
  :453  negative       Preconfigured declared, artifact missing
                       -> LEG 3, with the §6.6 #2 element set asserted
  :452  positive (VM)  Preconfigured node boots with supplied config;
                       probe-sequence evidence
                       -> NOT here. Packet 2's, on the runner. LEG 6 proves
                          the ZERO-GENERATION property lab-free by call
                          count; it does not establish that a guest boots.

LAB-FREE by construction. No guest is contacted. It reports no BLOCKED legs:
a (VM) row is not claimed by a lab-free proof, which is the defect
BL-P2-4.5c-35 records.

STATED COVERAGE LIMITS (PBE-P2-8):
  * LEG 6 counts calls to `probe_facts` and `gen_node_config` through
    monkeypatched module attributes. It proves the preconfigured branch does
    not invoke them BY NAME at module scope. A generation path reached by a
    different name, or by a local alias bound before patching, would not be
    seen. The count is the assertion (Rule 19), not the absence of an error.
  * LEG 5 proves path resolution against a real temporary directory. It does
    not establish behaviour on a filesystem where the topology's parent is
    unreadable, which is unmeasured.
  * `config reload`'s exit code is NOT asserted anywhere here, per
    LD-45C-R17 R5: measured 0 applying, 0 having applied nothing, and 1
    having applied nothing. Nothing in §4.5-c may gate on it.
  * The read-back verification (R11) is a GUEST property and is packet 2's.
    This proof asserts only that the apply argv carries no `-l` (LEG 7).
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cassian_model as cm            # noqa: E402
import cassian_nos_sonic as S         # noqa: E402

FAILURES = []
CHECKS = 0


def check(label, cond, detail=""):
    global CHECKS
    CHECKS += 1
    if cond:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s %s" % (label, detail))
        FAILURES.append(label)


def _node(**kw):
    n = {"name": "s1", "type": "sonic-vm", "runtime": "vm",
         "image": "local/sonic-vm:202405"}
    n.update(kw)
    return n


def _topo(node):
    return {"name": "t1", "nodes": [node], "links": []}


def _resolve(topo, topo_path=None):
    """Mirror cmd_validate's seam: resolve_topology, capturing SystemExit."""
    import copy
    t = copy.deepcopy(topo)
    try:
        return cm.resolve_topology(t, topo_path=topo_path), None
    except SystemExit as e:
        return None, e


def _complete_cfg():
    """The minimum LD-45C-R17 R9 requires: parses, has PORT and
    DEVICE_METADATA. Two tables, named by measurement, not a schema.

    PORT covers the same 32 ports the platform reports. LD-45C-R17 R11's
    read-back compares the guest's PORT key COUNT against the declared
    artifact's, so a one-port fixture would fail the comparison for a fixture
    reason. R7 is the substantive ground: preconfigured mode means the
    operator supplies the WHOLE file, platform tables included, so a complete
    artifact for a Force10-S6000 declares that platform's ports.
    """
    return {
        "PORT": _guest_port_table(),
        "DEVICE_METADATA": {"localhost": {"hwsku": _GUEST_HWSKU,
                                          "platform": "x86_64-kvm_x86_64-r0",
                                          "mac": "00:00:00:00:00:01"}},
    }


_GUEST_HWSKU = "Force10-S6000"


def _port_names():
    """The 32 port names `_SONIC_PORT_MAPS` records for Force10-S6000.

    Derived from the product's own recorded map rather than transcribed, so
    the fixture cannot drift from it. STATED LIMIT (PBE-P2-8): because the
    fixture is derived from that map, this proof CANNOT detect a defect in
    the map itself, nor a mismatch between the map and a real guest. That is
    `sonic_provision_supply_proof.py`'s surface and the (VM) legs', not this
    proof's -- LEG 6c counts calls, it does not check port order.
    """
    return list(S._SONIC_PORT_MAPS[_GUEST_HWSKU])


def _guest_port_table():
    """The PORT table the guest reports, as a stub.

    Carries the `index` that `derive_port_order` requires
    (`cassian_nos_sonic.py:141-150` fails loud without it), so the GENERATED
    arm reaches `gen_node_config` and LEG 6c witnesses both counters. Distinct
    from the declared artifact: this is what the DEVICE reports, not what the
    operator supplied -- they agree in key count, which is what LD-45C-R17 R11
    compares, and nothing here asserts they agree in content.
    """
    return {name: {"lanes": "%d,%d,%d,%d" % (i * 4 + 1, i * 4 + 2,
                                             i * 4 + 3, i * 4 + 4),
                   "alias": "fortyGigE0/%d" % i,
                   "index": str(i)}
            for i, name in enumerate(_port_names())}


def _guest_metadata():
    """`DEVICE_METADATA.localhost` as the guest reports it.

    Carries NEITHER `docker_routing_config_mode` NOR
    `frr_mgmt_framework_config` (LD-45C-R22 R1; LD-45C-R23 D-3) -- with either
    present, `assert_routing_mode_clean` refuses the arm that LEGs 6a/6b and 7
    depend on, and the proof would report a HARNESS property as a product one.
    Mirrors the declared artifact's three read-back fields so R11 reconciles.
    """
    return dict(_complete_cfg()["DEVICE_METADATA"]["localhost"])


def main():
    print("=== tests/sonic_preconfigured_proof.py (lab-free) ===")
    tmp = Path(tempfile.mkdtemp(prefix="s45c-precfg-"))
    topo_dir = tmp / "topologies"
    topo_dir.mkdir()
    topo_file = topo_dir / "t1.yaml"
    topo_file.write_text("# fixture path only; content unused\n")

    good = topo_dir / "cfg_good.json"
    good.write_text(json.dumps(_complete_cfg()))

    # -- LEG 1: sonic_mode enum ------------------------------------------
    print("\nLEG 1 -- sonic_mode is an enum, defaulting to generated (R17 R1)")
    r, e = _resolve(_topo(_node()))
    check("(1a) omitted sonic_mode resolves", e is None, str(e))
    if r:
        n = r["nodes"][0]
        check("(1b) default is 'generated', visible in resolved output",
              n.get("sonic_mode") == "generated", repr(n.get("sonic_mode")))
    r, e = _resolve(_topo(_node(sonic_mode="preconfigured",
                                sonic_config_db=str(good))))
    check("(1c) 'preconfigured' with an artifact is accepted", e is None, str(e))
    r, e = _resolve(_topo(_node(sonic_mode="banana")))
    check("(1d) NON-VACUITY: an unknown value is refused", e is not None)
    check("(1e) ... with exit 2, not die()'s default 1",
          e is not None and getattr(e, "code", None) == 2,
          "code=%r" % (getattr(e, "code", None),))

    # -- LEG 2: required iff preconfigured -------------------------------
    print("\nLEG 2 -- sonic_config_db required iff preconfigured (R17 R1)")
    r, e = _resolve(_topo(_node(sonic_mode="preconfigured")))
    check("(2a) preconfigured without the key is refused", e is not None)
    check("(2b) ... exit 2", e is not None and getattr(e, "code", None) == 2)
    r, e = _resolve(_topo(_node(sonic_config_db=str(good))))
    check("(2c) NON-VACUITY: the key on a generated node is REJECTED, not "
          "ignored", e is not None)

    # -- LEG 3: missing artifact, §6.6 #2 element set (REQ-45C-27) -------
    print("\nLEG 3 -- missing artifact: §13-grade, exit 2, four elements")
    missing = topo_dir / "does_not_exist.json"
    r, e = _resolve(_topo(_node(sonic_mode="preconfigured",
                                sonic_config_db=str(missing))),
                    topo_path=topo_file)
    check("(3a) refused", e is not None)
    check("(3b) exit 2", e is not None and getattr(e, "code", None) == 2)
    msg = cm.cassian_common.LAST_ERROR_MSG or ""
    check("(3c) names the node", "s1" in msg, msg[:120])
    check("(3d) names the declared mode", "preconfigured" in msg, msg[:120])
    check("(3e) names the missing path", str(missing) in msg, msg[:160])
    check("(3f) names BOTH corrective options",
          "supply" in msg.lower() and "sonic_mode" in msg, msg[:200])

    # -- LEG 4: completeness precondition (R17 R9) -----------------------
    print("\nLEG 4 -- completeness: parses, carries PORT and DEVICE_METADATA")
    bad_json = topo_dir / "cfg_bad.json"
    bad_json.write_text("{ not json")
    r, e = _resolve(_topo(_node(sonic_mode="preconfigured",
                                sonic_config_db=str(bad_json))),
                    topo_path=topo_file)
    check("(4a) unparseable JSON refused, exit 2",
          e is not None and getattr(e, "code", None) == 2)
    for miss in ("PORT", "DEVICE_METADATA"):
        cfg = _complete_cfg()
        cfg.pop(miss)
        p = topo_dir / ("cfg_no_%s.json" % miss)
        p.write_text(json.dumps(cfg))
        r, e = _resolve(_topo(_node(sonic_mode="preconfigured",
                                    sonic_config_db=str(p))),
                        topo_path=topo_file)
        check("(4b) missing %s refused, exit 2" % miss,
              e is not None and getattr(e, "code", None) == 2)
        check("(4c) ... and the message names %s" % miss,
              miss in (cm.cassian_common.LAST_ERROR_MSG or ""))
    r, e = _resolve(_topo(_node(sonic_mode="preconfigured",
                                sonic_config_db=str(good))),
                    topo_path=topo_file)
    check("(4d) NON-VACUITY: a complete artifact passes the same gate",
          e is None, str(e))

    # -- LEG 5: path resolution (LD-45C-R21 R1/R3) -----------------------
    print("\nLEG 5 -- relative resolves against the TOPOLOGY dir, never CWD")
    elsewhere = tmp / "elsewhere"
    elsewhere.mkdir()
    decoy = elsewhere / "cfg_good.json"
    decoy.write_text(json.dumps({"PORT": {}, "DEVICE_METADATA": {}}))
    cwd0 = os.getcwd()
    try:
        os.chdir(elsewhere)
        r, e = _resolve(_topo(_node(sonic_mode="preconfigured",
                                    sonic_config_db="cfg_good.json")),
                        topo_path=topo_file)
        check("(5a) relative resolved against the topology file's dir",
              e is None, str(e))
        if r:
            got = str(r["nodes"][0].get("sonic_config_db") or "")
            check("(5b) ... to the topology-dir artifact, NOT the CWD decoy",
                  got == str(good), got)
        r, e = _resolve(_topo(_node(sonic_mode="preconfigured",
                                    sonic_config_db="cfg_good.json")),
                        topo_path=None)
        check("(5c) NON-VACUITY: relative with no topo_path is REFUSED, "
              "never silently resolved against CWD", e is not None)
        check("(5d) ... exit 2", e is not None and getattr(e, "code", None) == 2)
        r, e = _resolve(_topo(_node(sonic_mode="preconfigured",
                                    sonic_config_db=str(good))),
                        topo_path=None)
        check("(5e) an ABSOLUTE value needs no topo_path", e is None, str(e))
    finally:
        os.chdir(cwd0)

    # -- LEG 6: zero generation (REQ-45C-26) -----------------------------
    print("\nLEG 6 -- preconfigured invokes NO generation (count, not absence)")
    calls = {"probe_facts": 0, "gen_node_config": 0}
    orig_pf, orig_gnc = S.probe_facts, S.gen_node_config

    def _pf(*a, **k):
        calls["probe_facts"] += 1
        return orig_pf(*a, **k)

    def _gnc(*a, **k):
        calls["gen_node_config"] += 1
        return orig_gnc(*a, **k)

    class _Rt:
        """Records argv and answers THREE shaped queries. No guest is contacted.

        LD-45C-R23 R1/R3: dispatch on the joined argv, following the in-repo
        pattern at `tests/sonic_provision_supply_proof.py:42-51`. This proof
        carries its own copy of the shape and does not import across proof
        files. Three arms, not two: `provision` asks three differently-shaped
        questions, and a single-payload stub cannot answer them -- measured
        `pf=1 gnc=0`, which is the defect LD-45C-R23 was ruled on.
        No leg's assertion changes.
        """
        def __init__(self):
            self.sent = []

        def exec(self, lab, node, argv, **kw):
            self.sent.append(list(argv))
            joined = " ".join(argv)
            if "DEVICE_METADATA.localhost.hwsku" in joined:
                out = _GUEST_HWSKU + "\n"
            elif "--var-json" in joined and "PORT" in joined:
                out = json.dumps(_guest_port_table())
            elif "DEVICE_METADATA['localhost']" in joined:
                out = repr(_guest_metadata())
            else:
                out = ""

            class _CP:
                returncode = 0
                stdout = out
                stderr = ""
            return _CP()

    applied = None
    S.probe_facts, S.gen_node_config = _pf, _gnc
    rt = _Rt()
    try:
        r, _ = _resolve(_topo(_node(sonic_mode="preconfigured",
                                    sonic_config_db=str(good))),
                        topo_path=topo_file)
        nd = r["nodes"][0]
        try:
            applied = S.provision(rt, "lab", "s1", nd, r)
        except SystemExit:
            pass  # a guest-shaped failure is not this leg's subject
        check("(6a) probe_facts call count is 0",
              calls["probe_facts"] == 0, "count=%d" % calls["probe_facts"])
        check("(6b) gen_node_config call count is 0",
              calls["gen_node_config"] == 0,
              "count=%d" % calls["gen_node_config"])
        calls["probe_facts"] = calls["gen_node_config"] = 0
        rt2 = _Rt()
        r2, _ = _resolve(_topo(_node()))
        try:
            S.provision(rt2, "lab", "s1", r2["nodes"][0], r2)
        except SystemExit:
            pass
        check("(6c) NON-VACUITY: the generated path DOES invoke them",
              calls["probe_facts"] > 0 and calls["gen_node_config"] > 0,
              "pf=%d gnc=%d" % (calls["probe_facts"], calls["gen_node_config"]))
    finally:
        S.probe_facts, S.gen_node_config = orig_pf, orig_gnc

    # -- LEG 7: the apply argv (R17 R3/R10) ------------------------------
    print("\nLEG 7 -- apply is `config reload -y -f`, and never `-l`")
    argvs = [" ".join(a) for a in rt.sent]
    reloads = [a for a in argvs if "config" in a and "reload" in a]
    check("(7a) exactly one reload argv was sent",
          len(reloads) == 1, repr(argvs))
    if reloads:
        check("(7b) carries -y and -f", "-y" in reloads[0] and "-f" in reloads[0],
              reloads[0])
        check("(7c) carries NO -l / --load-sysinfo (R10)",
              " -l" not in reloads[0] and "--load-sysinfo" not in reloads[0],
              reloads[0])
        check("(7d) `config load` is NOT used (R3)",
              "config load" not in reloads[0], reloads[0])

    # -- LEG 8: the fork lands AFTER the precondition (LD-45C-R22 R1) -----
    # Added by founder ruling, session 16, after mutation testing measured
    # that legs 1-7 pass unchanged when the fork is moved AHEAD of
    # assert_routing_mode_clean. REQ-45C-44(b) is not among this file's
    # §14.1 :279 Req-IDs; the extension is the founder's act, not authoring.
    print("\nLEG 8 -- the preconfigured fork lands AFTER the precondition")
    first = " ".join(rt.sent[0]) if rt.sent else ""
    check("(8a) a guest read was issued before anything else",
          bool(rt.sent), repr(rt.sent))
    check("(8b) the FIRST guest command is the routing-mode precondition "
          "read, not a staging write",
          "DEVICE_METADATA['localhost']" in first, first[:120])
    check("(8c) NON-VACUITY: the staging write and the reload were both sent "
          "AFTER it, so the ordering is observable",
          len(rt.sent) >= 3, "sent=%d" % len(rt.sent))

    # -- LEG 9: the return contract (LD-45C-R24 R1/R3) --------------------
    # cassian_engine.py:290-296 writes one file per returned key through
    # write_json_canonical. Returning None reaches `if not applied: continue`
    # and the run directory carries nothing for a node that WAS provisioned --
    # absence implying pass, which Doctrine §1.11 :267 forbids.
    print("\nLEG 9 -- provision returns the operator's artifact, never None")
    check("(9a) the preconfigured path returns a mapping, NOT None",
          isinstance(applied, dict), repr(type(applied)))
    if isinstance(applied, dict):
        check("(9b) exactly one key, named for the generated path's artifact",
              list(applied.keys()) == ["config_db.json"],
              repr(list(applied.keys())))
        check("(9c) the value IS the operator's artifact, not a re-derivation",
              applied.get("config_db.json") == _complete_cfg(),
              "declared tables=%r returned tables=%r"
              % (sorted(_complete_cfg()), sorted(applied.get("config_db.json") or {})))
        check("(9d) NON-VACUITY: the mapping is truthy, so "
              "`if not applied: continue` does NOT skip the write",
              bool(applied), repr(applied and list(applied)))

    print("\n%d checks, %d failures" % (CHECKS, len(FAILURES)))
    if FAILURES:
        for f in FAILURES:
            print("  FAILED: %s" % f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
