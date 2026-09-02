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

TWO MODES (LD-45C-R30 R1). With no argv, LEGs 1-9 run and NO guest is
contacted -- that half is lab-free by construction, as it was in packet 1.
With a subcommand, a (VM) leg runs in its bound environment on
`ai-netsim-runner`: `mode4` for §15.2 row 4 (`:451`).

  CORRECTED HERE (LD-45C-R30 R4). Packet 1's header read "LAB-FREE by
  construction. No guest is contacted." LD-45C-R20 R2 creates this file in
  packet 1 and EXTENDS it in packet 2 with the two (VM) legs, which
  falsifies that sentence the moment the extension lands. The correction is
  bounded to this paragraph; no assertion, ordering or text of LEGs 1-9
  moves (LD-45C-R30 R1, LD-45C-R26 R3, LD-45C-R23 R1).

  NOT REPAIRED HERE, and named so a reader has a path to it: packet 1's
  same paragraph glossed `BL-P2-4.5c-35` as recording that "a (VM) row is
  not claimed by a lab-free proof". `-35`'s primary records a superseded
  row citation and an unmet §18(1) BOUND-ENVIRONMENT condition, not that.
  That gloss is `BL-P2-4.5c-121`'s subject and is outside LD-45C-R30 R4;
  it is dropped here rather than carried forward, and `-121` stays open.

  `mode4` DEPLOYS NOTHING. LD-45C-R29 R1: row 4's evidence is
  `topology.resolved.yaml`, written before deploy. R3: the row is (VM) by
  BOUND ENVIRONMENT, not by booting. LD-45C-R14 R6 is why its CI step takes
  no `up`/`down` and is not added to the if:always() teardown sweep.

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
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

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


def _repo_root():
    """The repository root, derived from THIS FILE, never from the CWD.

    The (VM) legs below run `cassian gen` from a temporary workspace, so the
    CWD is deliberately not the repository. Deriving the root from `__file__`
    is what lets that be true.
    """
    return Path(__file__).resolve().parent.parent


def _finish():
    """Summary + exit code for the subcommand arms.

    `main()` carries its own copy of this tail. It is NOT refactored to share
    this one: LD-45C-R30 R1 requires `main()` and LEGs 1-9 byte-identical, and
    a shared helper would edit `main()`. The duplication is the ruling's cost,
    recorded rather than optimised away.
    """
    print("\n%d checks, %d failures" % (CHECKS, len(FAILURES)))
    if FAILURES:
        for f in FAILURES:
            print("  FAILED: %s" % f)
        return 1
    return 0


def _run_gen(topo_path, lab_name, workspace):
    """Run the SHIPPED `cassian gen` as a subprocess, with `workspace` as CWD.

    LD-45C-R15 R4: evaluate the shipped behaviour, never assert it from code
    structure. This invokes the real CLI entry point rather than reaching into
    the engine, so what is measured is what ships.

    WHY A TEMPORARY WORKSPACE, measured not assumed: `cassian_cli.py:386-388`
    binds the labs directory to `Path.cwd()` for every command
    `_command_uses_workspace_labs` admits, and `cassian_engine.py:239-251`
    admits "gen". So the artifact lands under `workspace`, never in the
    repository -- and because `workspace` is NOT the topology's directory,
    the same run exercises LD-45C-R21 R1's cwd-independent `sonic_config_db`
    resolution instead of needing a separate control for it.

    Returns (CompletedProcess, Path-to-topology.resolved.yaml). The lab
    directory is `clab-<topology name>` (`cassian_artifacts.py:15-16`), which
    is the topology's `name` KEY and not its filename -- the control below
    renames one and would silently look in the wrong place otherwise.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_repo_root() / "src")
    proc = subprocess.run(
        [sys.executable, str(_repo_root() / "src" / "cassian.py"),
         "gen", str(topo_path)],
        cwd=str(workspace), env=env, capture_output=True, text=True)
    resolved = (Path(workspace) / "labs" / ("clab-" + lab_name)
                / "topology.resolved.yaml")
    return proc, resolved


def _modes_of(doc):
    """name -> sonic_mode, for whatever `nodes` the document carries."""
    return {n.get("name"): n.get("sonic_mode")
            for n in (doc or {}).get("nodes", []) or []
            if isinstance(n, dict)}


def _leg_mode4():
    """LEG 10 -- §15.2 row 4 (`:451`): mixed-mode resolves PER NODE, visibly.

    Expected column: "Modes visible per-node". The anti-requirement REQ-45C-4
    guards is a mode that is NOT per-node in mixed topologies, so the leg
    asserts the two nodes' modes DIFFER and then shows that assertion is
    capable of failing.

    NO GUEST, NO DEPLOY. LD-45C-R29 R1/R3.
    """
    print("=== tests/sonic_preconfigured_proof.py mode4 (§15.2 row 4) ===")
    root = _repo_root()
    topo = root / "topologies" / "sonic-mode-mixed.yaml"
    check("(10a) the row-4 fixture is present", topo.is_file(), str(topo))
    if not topo.is_file():
        return

    declared = yaml.safe_load(topo.read_text(encoding="utf-8"))
    src_modes = _modes_of(declared)
    check("(10b) s1 declares NO sonic_mode, so a resolved `generated` can "
          "only have been SUPPLIED by resolve", src_modes.get("s1") is None,
          repr(src_modes))
    check("(10c) s2 declares `preconfigured` in the source",
          src_modes.get("s2") == "preconfigured", repr(src_modes))

    ws = Path(tempfile.mkdtemp(prefix="s45c-mode4-"))
    # Decoy: if `sonic_config_db` resolved against the CWD rather than the
    # topology's directory, (10i) would find THIS path and fail. Without it
    # (10i) passes whether resolution is cwd-independent or merely lucky.
    (ws / "sonic-mode-mixed-config-db.json").write_text(
        json.dumps({"DECOY": True}), encoding="utf-8")

    proc, resolved = _run_gen(topo, "sonic-mode-mixed", ws)
    check("(10d) `cassian gen` exits 0 on the mixed fixture",
          proc.returncode == 0,
          "rc=%d stderr=%s" % (proc.returncode, proc.stderr[-400:]))
    check("(10e) the resolved artifact is written, with NO deploy and no "
          "containerlab", resolved.is_file(), str(resolved))
    if not resolved.is_file():
        return

    got = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    modes = _modes_of(got)
    check("(10f) s1 resolves to `generated` -- SUPPLIED by resolve, never "
          "declared", modes.get("s1") == "generated", repr(modes))
    check("(10g) s2 resolves to `preconfigured`",
          modes.get("s2") == "preconfigured", repr(modes))
    check("(10h) the two modes DIFFER -- the per-node property REQ-45C-4's "
          "anti-requirement guards",
          modes.get("s1") != modes.get("s2"), repr(modes))

    cfgdb = {n.get("name"): n.get("sonic_config_db")
             for n in got.get("nodes", []) or [] if isinstance(n, dict)}
    want = str((topo.parent / "sonic-mode-mixed-config-db.json").resolve())
    check("(10i) LD-45C-R21 R1: `sonic_config_db` resolved against the "
          "TOPOLOGY directory from a different cwd carrying a decoy of the "
          "same name", cfgdb.get("s2") == want,
          "cwd=%s got=%r want=%r" % (ws, cfgdb.get("s2"), want))

    _leg_mode4_controls(declared)


def _leg_mode4_controls(declared):
    """NON-VACUITY for (10f), (10g) and (10h), each shown capable of failing.

    Per-guard, and on the negative path as well as the positive one. Two
    controls, because one is not enough: an all-defaulted variant shows the
    DISTINCTNESS assertion can fail, and an all-preconfigured variant shows
    `generated` is not what resolve writes unconditionally. Without the
    second, (10f) would pass against a resolver that hardcoded the first
    node's mode.
    """
    import copy

    def _variant(name, mutate, artifact=False):
        d = copy.deepcopy(declared)
        d["name"] = name
        for n in d.get("nodes", []) or []:
            if isinstance(n, dict):
                mutate(n)
        vdir = Path(tempfile.mkdtemp(prefix="s45c-%s-" % name))
        if artifact:
            (vdir / "cfg.json").write_text(json.dumps(_complete_cfg()),
                                           encoding="utf-8")
        vpath = vdir / (name + ".yaml")
        vpath.write_text(yaml.safe_dump(d, sort_keys=False), encoding="utf-8")
        vws = Path(tempfile.mkdtemp(prefix="s45c-%s-ws-" % name))
        vproc, vres = _run_gen(vpath, name, vws)
        return vproc, vres

    def _defaulted(n):
        n.pop("sonic_mode", None)
        n.pop("sonic_config_db", None)

    def _preconfigured(n):
        n["sonic_mode"] = "preconfigured"
        n["sonic_config_db"] = "cfg.json"

    p1, r1 = _variant("mode4ctl-defaulted", _defaulted)
    check("(10j) control A gen exits 0", p1.returncode == 0,
          "rc=%d stderr=%s" % (p1.returncode, p1.stderr[-400:]))
    m1 = _modes_of(yaml.safe_load(r1.read_text(encoding="utf-8"))) \
        if r1.is_file() else {}
    check("(10k) NON-VACUITY for (10h): with NO node declaring a mode both "
          "resolve to `generated` and are EQUAL, so (10h)'s distinctness "
          "assertion is capable of failing",
          m1.get("s1") == "generated" and m1.get("s2") == "generated"
          and m1.get("s1") == m1.get("s2"), repr(m1))

    p2, r2 = _variant("mode4ctl-preconfigured", _preconfigured, artifact=True)
    check("(10l) control B gen exits 0", p2.returncode == 0,
          "rc=%d stderr=%s" % (p2.returncode, p2.stderr[-400:]))
    m2 = _modes_of(yaml.safe_load(r2.read_text(encoding="utf-8"))) \
        if r2.is_file() else {}
    check("(10m) NON-VACUITY for (10f)/(10g), NEGATIVE PATH: with BOTH nodes "
          "declaring `preconfigured`, s1 resolves to `preconfigured` -- so "
          "`generated` is read from the declaration's absence, not written "
          "unconditionally", m2.get("s1") == "preconfigured"
          and m2.get("s2") == "preconfigured", repr(m2))


def _leg_req26(topo_path, lab):
    """LEG 11 -- §15.2 row 26 (`:452`): the guest boots carrying the OPERATOR'S
    config, and no generation produced it.

    LIVE DEVICE. This leg runs only on `ai-netsim-runner`, after `cassian up`
    has deployed the lab; there is no stub anywhere in it.

    HOW ZERO-GENERATION IS EVIDENCED HERE, and how it differs from LEG 6:
    LEG 6 counts calls to `probe_facts` and `gen_node_config` against a stub
    and proves the branch does not INVOKE generation. That is a lab-free
    property. This leg proves the complementary one at the artifact level --
    what the device ended up holding is byte-for-byte the operator's file, so
    nothing derived it. Neither implies the other and §15.2 row 26 needs the
    device-side half.

    THE `mac` IS THE DISCRIMINATOR, not a nuisance. `LD-45C-R17` §8 records
    that `mac` is per-boot on this image, and the probe reference bears it out
    across two measurements a week apart. The declared artifact carries a
    FIXTURE constant instead. So if `config reload -y -f` had not applied,
    the guest would report a per-boot value and (26f) would red. That is what
    makes the read-back non-vacuous rather than a comparison of a value
    against itself.

    STATED COVERAGE LIMIT (PBE-P2-8): (26i) asserts the ABSENCE of the two
    forbidden mode keys, and an empty mapping has no keys at all -- so (26i)
    passes vacuously whenever the guest read fails. It is meaningful only
    when (26g) is green. Measured with no `docker` present: the leg reports
    9 failures including (26g), and (26i) shows `ok` beside them. The failing
    (26g) is what makes that vacuity visible rather than silent; (26i) is not
    independent evidence and must not be read as such.
    """
    import ast
    import cassian_runtime_vm as _RV

    print("=== tests/sonic_preconfigured_proof.py req26 (§15.2 row 26) ===")
    doc = yaml.safe_load(Path(topo_path).read_text(encoding="utf-8")) or {}
    node = None
    for n in doc.get("nodes", []) or []:
        if isinstance(n, dict) and str(n.get("sonic_mode") or "") == "preconfigured":
            node = n
            break
    check("(26a) the topology declares a preconfigured sonic-vm node",
          node is not None, repr([n.get("name") for n in doc.get("nodes", []) or []]))
    if node is None:
        return
    name = str(node.get("name"))

    art = Path(topo_path).resolve().parent / str(node.get("sonic_config_db"))
    check("(26b) the operator artifact is readable beside the topology",
          art.is_file(), str(art))
    if not art.is_file():
        return
    declared = json.loads(art.read_text(encoding="utf-8"))

    # HALT-2 for the ARTIFACT. LEG 1 of sonic_lifecycle_proof.py sweeps the
    # topology file; nothing sweeps the JSON, and the JSON is what reaches the
    # device. The ranges are restated here rather than imported: importing
    # that module EXECUTES it -- measured, it runs its own argv dispatch and
    # exits -- so a cross-proof import is not available. Restatement is the
    # cost; the two copies are pinned to the same founder ruling of
    # 2026-08-15 and to sonic_lifecycle_proof.py's STOCK_RANGES.
    import ipaddress
    stock = (ipaddress.ip_network("10.0.0.0/26"),
             ipaddress.ip_network("10.1.0.0/24"))
    art_addrs = [k.split("|", 1)[1]
                 for tbl in ("INTERFACE", "LOOPBACK_INTERFACE")
                 for k in (declared.get(tbl) or {}) if "|" in k]
    in_stock = [a for a in art_addrs
                if any(ipaddress.ip_interface(a).ip in nw for nw in stock)]
    check("(26c) the ARTIFACT declares no address inside the stock ranges "
          "(HALT-2; LEG 1 sweeps the topology, not the JSON)",
          art_addrs and not in_stock,
          "declared=%r in-stock=%r" % (art_addrs, in_stock))

    # What the engine actually wrote for this node. `_provision_nos_providers`
    # writes one file per key `provision` returns, through
    # `write_json_canonical` (cassian_engine.py:290-296).
    applied = (Path("labs") / ("clab-" + str(lab)) / "nodes" / name
               / "config_db.json")
    check("(26d) the run wrote a config_db.json for the preconfigured node",
          applied.is_file(), str(applied))
    if applied.is_file():
        check("(26e) ZERO GENERATION: what was applied IS the operator's "
              "artifact, not a re-derivation",
              json.loads(applied.read_text(encoding="utf-8")) == declared,
              "applied tables=%r declared tables=%r"
              % (sorted(json.loads(applied.read_text(encoding='utf-8'))),
                 sorted(declared)))

    # --- Read the device back (LD-45C-R17 R11) ------------------------------
    # A read that cannot be made is a RESULT, not a crash. Measured: with no
    # `docker` on PATH the runtime raises FileNotFoundError and the traceback
    # takes the summary with it, so the checks tally is lost and the step's
    # red says nothing about the device. `_guest_stdout` can also exit via
    # `_fail`. Both are captured and recorded as failures with their detail.
    rt = _RV.build_runtime(doc)

    def _read(argv, purpose):
        try:
            return S._guest_stdout(rt, lab, name, list(argv), purpose), ""
        except SystemExit as exc:
            return "", "guest read refused: %s" % exc
        except Exception as exc:  # noqa: BLE001 - a failed read is a result
            return "", "%s: %s" % (type(exc).__name__, exc)

    meta_raw, meta_err = _read(S._DEVICE_METADATA_ARGV,
                               "REQ-45C-26 (VM) read-back: DEVICE_METADATA")
    check("(26f) the DEVICE_METADATA read reached the guest", not meta_err,
          meta_err or "ok")
    try:
        meta = ast.literal_eval(meta_raw.strip()) if meta_raw.strip() else {}
    except (ValueError, SyntaxError) as exc:
        meta = {}
        print("  note: DEVICE_METADATA did not parse: %s" % exc)
    check("(26g) NON-VACUITY: the guest read returned a non-empty mapping, so "
          "an empty read cannot pass as a match",
          isinstance(meta, dict) and bool(meta), repr(meta_raw[:200]))

    want = declared.get("DEVICE_METADATA", {}).get("localhost", {})
    for field in ("hwsku", "platform", "mac"):
        check("(26h) R11 read-back: DEVICE_METADATA.localhost.%s matches the "
              "declared artifact%s" % (field, "  <-- the per-boot discriminator"
                                       if field == "mac" else ""),
              str(meta.get(field) or "") == str(want.get(field) or ""),
              "guest=%r declared=%r" % (meta.get(field), want.get(field)))

    check("(26i) LD-45C-R22 R1: neither forbidden mode key is present after "
          "the apply",
          not any(k in meta for k in S._FORBIDDEN_MODE_KEYS),
          "present: %r" % [k for k in S._FORBIDDEN_MODE_KEYS if k in meta])

    port_raw, port_err = _read(["sonic-cfggen", "-d", "--var-json", "PORT"],
                               "REQ-45C-26 (VM) read-back: PORT")
    check("(26j) the PORT read reached the guest", not port_err,
          port_err or "ok")
    try:
        guest_port = json.loads(port_raw) if port_raw.strip() else {}
    except ValueError:
        guest_port = {}
    check("(26k) R11 read-back: PORT key count matches the declared artifact",
          len(guest_port) == len(declared.get("PORT") or {}),
          "guest=%d declared=%d" % (len(guest_port),
                                    len(declared.get("PORT") or {})))
    check("(26l) NON-VACUITY: the PORT read is non-empty, so a failed read "
          "cannot satisfy (26k) by matching zero against zero",
          bool(guest_port), repr(port_raw[:160]))


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
    # LD-45C-R30 R1 -- two-mode dispatch, confined to this block. No argv is
    # packet 1's behaviour, byte-for-byte. `req26` is C1c's and is not
    # authored here; an unknown subcommand is a usage error, never a silent
    # no-op that would let a mis-wired CI step pass unseen (F-45C-C3-3).
    _args = sys.argv[1:]
    if not _args:
        sys.exit(main())
    elif _args[0] == "mode4" and len(_args) == 1:
        _leg_mode4()
        sys.exit(_finish())
    elif _args[0] == "req26" and len(_args) == 3:
        _leg_req26(_args[1], _args[2])
        sys.exit(_finish())
    else:
        sys.exit("usage: sonic_preconfigured_proof.py "
                 "[mode4 | req26 <topology> <lab>]"
                 "  (no argv = lab-free LEGs 1-9)")
