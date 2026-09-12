#!/usr/bin/env python3
"""tests/sonic_routing_mode_precondition_proof.py -- §4.5-c WI-1 packet 3a.

Req-ID: REQ-45C-44(b) -- the mode precondition. Ledger row BL-P2-4.5c-50.

Snapshot mapping: `cassian_nos_sonic` -> `src/cassian_nos_sonic.py`. Session
snapshot v54 == branch `feature/4_5c-sonic-base-lifecycle` @ `20db092`.

WHAT THIS COVERS -- §15.2's four REQ-45C-44 rows, and which are NOT here:
  :489  positive        overlay authors no platform-owned data
                        -> already proven by sonic_configgen_determinism_proof
  :492  negative        §4.5-c writes neither mode key anywhere
                        -> LEG 3 below
  :491  negative (VM)   clean guest passes; SEEDED guest fails loud
                        -> LEG 1/2 prove the PREDICATE lab-free; LEG 8, under
                           `req44neg`, proves it on a REAL guest that this leg
                           seeds (LD-45C-R36 R1).
  :490  positive (VM)   post-apply device read vs the image's own
                        persisted declaration, same boot
                        -> LEG 7, under `req44pos` (LD-45C-R35 R1)

THREE MODES. With no argv the six lab-free legs run and both (VM) legs
report BLOCKED; `req44pos <topo> <lab>` additionally runs LEG 7 and
`req44neg <topo> <lab>` LEG 8, each against a real guest. The lab-free
legs replay their guest read through a fake runtime, so they prove the
predicate's behaviour, not the device's.

STATED COVERAGE LIMITS (PBE-P2-8):
  * The replayed payloads are the MEASURED shape from sonic-vm:202405
    (SONiC.202405.1033627-fecd4ec81, read 2026-08-24) -- a Python repr of
    DEVICE_METADATA['localhost']. If a future image returns a different shape,
    these legs still pass while the real read fails. LEG 4 pins the argv so
    the drift is at least locatable.
  * The proof asserts the guard REFUSES a seeded guest. It does not establish
    what SONiC does in those modes -- unmeasured, and the reason the
    disposition is refusal rather than adaptation.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cassian_nos_sonic as S  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


class _CP:
    def __init__(self, rc, out):
        self.returncode = rc
        self.stdout = out
        self.stderr = ""


class _FakeRuntime:
    """Replays one guest read. Records argv so single-sourcing is provable."""

    def __init__(self, out, rc=0):
        self.calls = []
        self._cp = _CP(rc, out)

    def exec(self, lab, node, argv, check=False, capture_output=True,
             interactive=False, timeout_s=None):
        self.calls.append(list(argv))
        return self._cp


# Measured verbatim on sonic-vm:202405, 2026-08-24. Stock guest, un-provisioned.
CLEAN = ("{'bgp_asn': '65100', 'buffer_model': 'traditional', "
         "'default_bgp_status': 'up', 'default_pfcwd_status': 'disable', "
         "'hostname': 's1', 'hwsku': 'Force10-S6000', "
         "'mac': '22:7b:ff:8d:f6:71', 'platform': 'x86_64-kvm_x86_64-r0', "
         "'timezone': 'UTC', 'type': 'LeafRouter'}\n")


def _seeded(key, value):
    return CLEAN.rstrip("\n")[:-1] + ", '%s': '%s'}\n" % (key, value)


# --- LEG 1: a clean guest passes ----------------------------------------------

rt = _FakeRuntime(CLEAN)
ok = True
try:
    S.assert_routing_mode_clean(rt, "lab", "s1")
except SystemExit:
    ok = False
check("REQ-45C-44(b) clean guest passes (measured stock DEVICE_METADATA)", ok)

# --- LEG 2: NON-VACUITY -- each forbidden key, independently, fails loud -------
# Enumerated per key rather than tested once (Rule 14): a guard that fires on
# one key and not the other would pass a single-shape test.

for key, value in (("docker_routing_config_mode", "unified"),
                   ("frr_mgmt_framework_config", "true")):
    rt = _FakeRuntime(_seeded(key, value))
    code = None
    try:
        S.assert_routing_mode_clean(rt, "lab", "s1")
    except SystemExit as exc:
        code = exc.code
    check("REQ-45C-44(b) NON-VACUITY: seeded `%s` fails loud, exit 2" % key,
          code == 2, "exit=%r" % code)

# both set at once
rt = _FakeRuntime(_seeded("docker_routing_config_mode", "split"))
code = None
try:
    S.assert_routing_mode_clean(rt, "lab", "s1")
except SystemExit as exc:
    code = exc.code
check("REQ-45C-44(b) a non-default mode VALUE also fails (value not matched)",
      code == 2, "exit=%r" % code)

# --- LEG 3: §15.2 :492 -- §4.5-c writes neither key anywhere -------------------

root = os.path.join(os.path.dirname(__file__), "..")
hits = []
for key in S._FORBIDDEN_MODE_KEYS:
    cp = subprocess.run(["grep", "-rn", key, "src/"], cwd=root,
                        capture_output=True, text=True)
    for line in (cp.stdout or "").splitlines():
        # The provider's own guard names the keys; that is the guard, not a write.
        if line.startswith("src/cassian_nos_sonic.py:"):
            continue
        hits.append(line)
check("REQ-45C-44(b) §15.2 :492 -- §4.5-c writes neither mode key anywhere",
      not hits, "hits: %s" % (hits or "none"))

# non-vacuity for LEG 3: the grep instrument can find the keys when present
cp = subprocess.run(["grep", "-rn", S._FORBIDDEN_MODE_KEYS[0], "src/"],
                    cwd=root, capture_output=True, text=True)
check("LEG 3 NON-VACUITY: the grep finds the key in the guard itself",
      bool((cp.stdout or "").strip()),
      "guard occurrences: %d" % len((cp.stdout or "").splitlines()))

# --- LEG 4: PBE-P2-6 -- the mode read is single-sourced and NOT _HWSKU_ARGV ----

rt = _FakeRuntime(CLEAN)
try:
    S.assert_routing_mode_clean(rt, "lab", "s1")
except SystemExit:
    pass
check("PBE-P2-6: the guard issues exactly one guest read",
      len(rt.calls) == 1, "calls=%d" % len(rt.calls))
check("PBE-P2-6: the read uses _DEVICE_METADATA_ARGV verbatim",
      rt.calls and tuple(rt.calls[0]) == S._DEVICE_METADATA_ARGV,
      "argv=%s" % (rt.calls[0] if rt.calls else None))
check("PBE-P2-6: _HWSKU_ARGV is NOT widened to carry the mode read",
      S._DEVICE_METADATA_ARGV != S._HWSKU_ARGV
      and "hwsku" not in " ".join(S._DEVICE_METADATA_ARGV))

# --- LEG 5: the guard runs BEFORE any generation or supply --------------------

import inspect  # noqa: E402
src = inspect.getsource(S.provision)
i_guard = src.find("assert_routing_mode_clean(")
i_probe = src.find("probe_facts(")
i_gen = src.find("gen_node_config(")
check("the precondition precedes probe_facts and gen_node_config in provision",
      -1 < i_guard < i_probe and i_guard < i_gen,
      "guard=%d probe=%d gen=%d" % (i_guard, i_probe, i_gen))

# --- LEG 6: leaf-import constraint preserved ----------------------------------
# nos-expansion-structure-design-RATIFIED.md:112 -- providers import only
# cassian_common and the stdlib. `ast` is stdlib; this leg fails if the guard's
# addition reached for the model.

mod_src = open(os.path.join(root, "src", "cassian_nos_sonic.py"),
               encoding="utf-8").read()
check("leaf-import constraint: provider does not import cassian_model",
      "import cassian_model" not in mod_src
      and "from cassian_model" not in mod_src)

# --- LEG 7: the (VM) leg ------------------------------------------------------

_blocked = []


def blocked(name, reason):
    _blocked.append((name, reason))


def _leg_req44_positive(topo_path, lab):
    """REQ-45C-44(a) (VM), §15.2 `:490` -- platform-owned values unaltered.

    The baseline is the guest's OWN persisted declaration at
    `/etc/sonic/config_db.json`, read in the SAME BOOT as the running-database
    read (`LD-45C-R35` R1). `mac` is per-boot (`LD-45C-R17` §8, re-measured
    session 21: two boots returned `22:88:e7:2a:db:59` and
    `22:b2:35:0e:d7:fd`), so a comparison spanning two boots or two labs would
    compare values never meant to match.

    The device is observed through the product's runtime seam and nothing is
    driven (`LD-45C-R1`). Imports are function-local because the module's
    import block sits inside the region `LD-45C-R35` R4 freezes.

    STATED COVERAGE LIMITS (PBE-P2-8): the staging-path control below
    establishes where the overlay IS written, not that nothing else writes
    under `/etc/sonic`. The persisted-vs-running comparison covers the four
    values `:490` names and is not a full-artifact differential. Measured on
    one image, one fixture, one boot.
    """
    import ast
    import json

    import yaml

    import cassian_runtime_vm as _RV

    doc = yaml.safe_load(open(topo_path, encoding="utf-8").read()) or {}
    names = [n.get("name") for n in (doc.get("nodes") or [])
             if isinstance(n, dict)
             and str(n.get("type") or "").strip().lower() == "sonic-vm"]
    check("REQ-45C-44 (VM) NON-VACUITY: fixture carries exactly one sonic-vm "
          "node", len(names) == 1, "sonic-vm nodes: %s" % names)
    if len(names) != 1:
        return
    node = names[0]

    check("REQ-45C-44 (VM) NON-VACUITY: the provider stages its overlay "
          "outside /etc/sonic, so the persisted declaration is not its target "
          "(LD-45C-R35 R2)",
          str(S._OVERLAY_GUEST_PATH).startswith("/tmp/"),
          "_OVERLAY_GUEST_PATH=%r" % (S._OVERLAY_GUEST_PATH,))

    rt = _RV.build_runtime(doc)
    disk = json.loads(S._guest_stdout(
        rt, lab, node, ["cat", "/etc/sonic/config_db.json"],
        "the persisted image declaration").strip() or "{}")
    run_meta = ast.literal_eval(S._guest_stdout(
        rt, lab, node, list(S._DEVICE_METADATA_ARGV),
        "the running device metadata").strip() or "{}")
    run_ports = json.loads(S._guest_stdout(
        rt, lab, node, ["sonic-cfggen", "-d", "--var-json", "PORT"],
        "the running PORT table").strip() or "{}")
    run_if = json.loads(S._guest_stdout(
        rt, lab, node, ["sonic-cfggen", "-d", "--var-json", "INTERFACE"],
        "the running INTERFACE table").strip() or "{}")

    _disk_if = len(disk.get("INTERFACE") or {})
    check("REQ-45C-44 (VM) NON-VACUITY: the persisted declaration and the "
          "running database are DISTINCT -- the overlay is visible in one and "
          "not the other, so the comparison is not one source read twice",
          _disk_if != len(run_if),
          "persisted INTERFACE %d; running INTERFACE %d"
          % (_disk_if, len(run_if)))

    _disk_meta = (disk.get("DEVICE_METADATA") or {}).get("localhost") or {}
    check("REQ-45C-44 (VM) :490 PORT key count unaltered by the apply",
          len(disk.get("PORT") or {}) == len(run_ports),
          "persisted %d; running %d"
          % (len(disk.get("PORT") or {}), len(run_ports)))
    for _f in ("hwsku", "platform", "mac"):
        check("REQ-45C-44 (VM) :490 %s unaltered by the apply" % _f,
              _f in _disk_meta
              and str(_disk_meta.get(_f)) == str(run_meta.get(_f)),
              "persisted %r; running %r"
              % (_disk_meta.get(_f), run_meta.get(_f)))


def _leg_req44_negative(topo_path, lab):
    """REQ-45C-44(b) (VM), §15.2 `:491` -- the guard refuses a seeded guest.

    `LD-45C-R36` R1: the abort message names the offending key AND its value.
    A negative test asserting only that `SystemExit` was raised is not a
    negative test -- session 21 recorded three controls logged as fired that
    had fired as a DIFFERENT guard or not at all. Every assertion below
    therefore reads the message and requires it to name the guard under test.

    ORDER IS FORCED. The clean-guest control runs BEFORE any seed, because
    removing a field once written is unmeasured (`sonic-db-cli HDEL` has never
    been run against this image) and `up --reconfigure` destroys the lab
    unconditionally (`cassian_engine.py:1337`, `:1351`; Doctrine §1.9), so it
    cannot restore a clean guest without wiping the seed. After the first seed
    the guest stays dirty for the rest of the leg; the lab is torn down by the
    CI step that owns it.

    THE SEEDED VALUES ARE SENTINELS, deliberately. The guard's predicate is a
    membership test over `_FORBIDDEN_MODE_KEYS`, so it is value-independent and
    realism buys nothing; a sentinel buys provenance -- a value that appears in
    the abort message can only have been read from the device, which is the
    property `LD-45C-R36` R1 exists to establish.

    Imports are function-local because the module's import block sits inside
    the region `LD-45C-R35` R4 freezes.

    STATED COVERAGE LIMITS (PBE-P2-8): this establishes that the guard refuses
    and names what it found. It does NOT establish what SONiC does in these
    modes -- unmeasured, and the reason the disposition is refusal rather than
    adaptation. The values seeded are sentinels, so nothing here establishes
    behaviour against a production value. One image, one fixture, one boot.
    """
    import contextlib
    import io as _io

    import yaml

    import cassian_runtime_vm as _RV

    doc = yaml.safe_load(open(topo_path, encoding="utf-8").read()) or {}
    names = [n.get("name") for n in (doc.get("nodes") or [])
             if isinstance(n, dict)
             and str(n.get("type") or "").strip().lower() == "sonic-vm"]
    check("REQ-45C-44(b) (VM) NON-VACUITY: fixture carries exactly one "
          "sonic-vm node", len(names) == 1, "sonic-vm nodes: %s" % names)
    if len(names) != 1:
        return
    node = names[0]
    rt = _RV.build_runtime(doc)

    # --- control: the guard PASSES before anything is seeded ------------------
    # Without this the seeded assertions below would also pass against a guard
    # that refuses unconditionally.
    _clean = True
    try:
        S.assert_routing_mode_clean(rt, lab, node)
    except SystemExit:
        _clean = False
    check("REQ-45C-44(b) :491 CONTROL: the provisioned guest is clean and the "
          "guard passes on it", _clean)
    if not _clean:
        return

    _seen = []
    for _key, _value in (("docker_routing_config_mode", "unified-45cR36"),
                         ("frr_mgmt_framework_config", "true-45cR36")):
        _ack = S._guest_stdout(
            rt, lab, node,
            ["sonic-db-cli", "CONFIG_DB", "HSET",
             "DEVICE_METADATA|localhost", _key, _value],
            "the HSET acknowledgement for %s" % _key).strip()
        check("REQ-45C-44(b) :491 seed of `%s` reports the field CREATED "
              "(HSET -> 1), so the guest state actually changed" % _key,
              _ack == "1", "HSET returned %r" % _ack)

        _buf = _io.StringIO()
        _code = None
        with contextlib.redirect_stderr(_buf):
            try:
                S.assert_routing_mode_clean(rt, lab, node)
            except SystemExit as _exc:
                _code = _exc.code
        _msg = _buf.getvalue()

        check("REQ-45C-44(b) :491 seeded `%s`: the guard fails loud, exit 2"
              % _key, _code == 2, "exit=%r" % _code)
        check("REQ-45C-44(b) :491 seeded `%s`: the abort names THE GUARD UNDER "
              "TEST, not some other failure" % _key,
              "unsupported routing configuration mode" in _msg,
              "message=%r" % _msg[:200])
        check("REQ-45C-44(b) :491 seeded `%s`: the abort names the KEY" % _key,
              _key in _msg)
        _pair = "%s=%r" % (_key, _value)
        check("REQ-45C-44(b) :491 seeded `%s`: the abort names the VALUE -- a "
              "sentinel, so it can only have come from the device (R36 R1)"
              % _key, _pair in _msg, "expected %r in the abort" % _pair)
        check("REQ-45C-44(b) :491 seeded `%s`: §13-grade -- the abort also "
              "carries what would be valid" % _key,
              "sets neither" in _msg)

        _seen.append(_pair)
        _absent = [p for p in _seen if p not in _msg]
        check("REQ-45C-44(b) :491 NON-VACUITY: the abort names EVERY key "
              "seeded so far (%d), so the message tracks device state rather "
              "than reporting a constant" % len(_seen),
              not _absent, "missing from the abort: %s" % _absent)


# --- dispatch + report --------------------------------------------------------

_vm_args = sys.argv[1:]
if not _vm_args:
    blocked("REQ-45C-44 (VM) :490 platform-owned values unaltered by the apply",
            "no (VM) argv supplied; run: req44pos <topo> <lab>")
    blocked("REQ-45C-44(b) (VM) :491 seeded guest fails loud naming key/value",
            "no (VM) argv supplied; run: req44neg <topo> <lab>")
elif _vm_args[0] == "req44pos" and len(_vm_args) == 3:
    _leg_req44_positive(_vm_args[1], _vm_args[2])
elif _vm_args[0] == "req44neg" and len(_vm_args) == 3:
    _leg_req44_negative(_vm_args[1], _vm_args[2])
else:
    sys.exit("usage: sonic_routing_mode_precondition_proof.py "
             "[req44pos <topo> <lab> | req44neg <topo> <lab>]  "
             "(no argv = lab-free legs only)")

fails = [c for c in _checks if not c[1]]
for name, ok, detail in _checks:
    print("%s %s%s" % ("PASS" if ok else "FAIL", name,
                       ("  [%s]" % detail) if detail else ""))
for name, reason in _blocked:
    print("BLOCKED %s  [%s]" % (name, reason))
print("=" * 60)
print("RESULT: %s -- %d/%d checks passed%s (REQ-45C-44 mode precondition, "
      "BL-P2-4.5c-50)"
      % ("PASS" if not fails else "FAIL", len(_checks) - len(fails),
         len(_checks),
         ", %d BLOCKED" % len(_blocked) if _blocked else ""))
if _blocked:
    print("NOTE: a BLOCKED leg is not a pass; the closure report carries it as "
          "a condition (PBE-P2-5).")
if fails:
    sys.exit("sonic_routing_mode_precondition_proof FAILED (%d check(s))."
             % len(fails))
