#!/usr/bin/env python3
"""WI-1 packet 2c -- SONiC provision supply path (REQ-45C-1/-42, R-C3-12/-14).

Lab-free. A FakeRuntime replays the guest transcript measured on
sonic-vm:202405 (2026-08-18), so the supply sequence is provable on hosted CI.
COVERAGE LIMIT (PBE-P2-8): this proves the SEQUENCE Cassian issues and the
payload it builds. It does NOT prove the guest merges rather than replaces --
that is settled by the §18(8) VM probe and the REQ-45C-5 provisioning proof.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cassian_nos_sonic as S  # noqa: E402
from cassian_artifacts import write_json_canonical  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


class _CP:
    def __init__(self, rc=0, out=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = "Debian GNU/Linux 12 \\n \\l\n"


_PORT_TABLE = {f"Ethernet{i * 4}": {"index": str(i)} for i in range(32)}


class FakeRuntime:
    def __init__(self, hwsku="Force10-S6000", fail_on=None):
        self.calls = []
        self._hwsku = hwsku
        self._fail_on = fail_on

    def exec(self, lab, node, argv, check=False, capture_output=True,
             interactive=False, timeout_s=None):
        self.calls.append(list(argv))
        joined = " ".join(argv)
        if self._fail_on and self._fail_on in joined:
            return _CP(rc=1, out="")
        if "DEVICE_METADATA.localhost.hwsku" in joined:
            return _CP(out=self._hwsku + "\n")
        if "--var-json" in joined and "PORT" in joined:
            return _CP(out=json.dumps(_PORT_TABLE))
        return _CP(out="")


TOPO = {
    "name": "sonic-supply-proof",
    "nodes": [{"name": "s1", "type": "sonic-vm", "router_id": "192.0.2.11"}],
    "links": [{"endpoints": ["s1:eth1", "r1:eth1"],
               "ipv4": ["192.0.2.0/31", "192.0.2.1/31"]}],
}
NODE = TOPO["nodes"][0]

# --- probe ------------------------------------------------------------------
rt = FakeRuntime()
facts = S.probe_facts(rt, "lab", "s1")
check("R-C3-13 probe returns the guest's hwsku",
      facts["hwsku"] == "Force10-S6000")
check("R-C3-13 probe derives the port order from the guest PORT table",
      facts["port_order"] == S._SONIC_PORT_MAPS["Force10-S6000"],
      "32/32")
check("F-45C-C3-20 NON-VACUITY: the stderr banner never reaches the parse",
      "Debian" not in facts["hwsku"],
      "stdout-only capture; merging stderr would break JSON parsing")

# --- supply sequence --------------------------------------------------------
rt = FakeRuntime()
applied = S.provision(rt, "lab", "s1", NODE, TOPO)
check("R-C3-14 provision returns the mapping it applied",
      isinstance(applied, dict) and list(applied) == ["config_db.json"])

_stage = [c for c in rt.calls if c[:2] == ["sh", "-c"]]
_load = [c for c in rt.calls if "config" in c and "load" in c]
check("R-C3-12 overlay is staged through the exec verb", len(_stage) == 1)
check("R-C3-12 overlay is applied with `config load -y`",
      len(_load) == 1 and _load[0][-1] == "-y" and "sudo" in _load[0])
check("R-C3-12 NON-VACUITY: copy_to_node is never called",
      not any("copy" in " ".join(c) for c in rt.calls),
      "REQ-45a-8/B10 UNSUP stands; §4.5-f owns guest file transfer")
check("R-C3-12 staging precedes apply",
      rt.calls.index(_stage[0]) < rt.calls.index(_load[0]))

# --- payload is canonical ---------------------------------------------------
_overlay = applied["config_db.json"]
_tmp = os.path.join(os.path.dirname(__file__), "_supply_tmp")
os.makedirs(_tmp, exist_ok=True)
try:
    from pathlib import Path
    _p = Path(_tmp) / "canonical.json"
    write_json_canonical(_p, _overlay)
    _canonical = _p.read_text(encoding="utf-8")
    _staged = _stage[0][2]
    check("REQ-45C-42 transport payload is byte-identical to the canonical form",
          _canonical in _staged,
          "%d bytes; provider serialization does not diverge from the serializer"
          % len(_canonical))
finally:
    try:
        os.remove(os.path.join(_tmp, "canonical.json"))
        os.rmdir(_tmp)
    except OSError:
        pass

# --- rejection legs ---------------------------------------------------------
_caught = False
try:
    S.provision(FakeRuntime(fail_on="--var-json"), "lab", "s1", NODE, TOPO)
except SystemExit as _e:
    _caught = (_e.code == 2)
check("REQ-45C-5 a failed PORT probe fails loud, exit 2", _caught)

_caught = False
try:
    S.provision(FakeRuntime(fail_on="printf"), "lab", "s1", NODE, TOPO)
except SystemExit as _e:
    _caught = (_e.code == 2)
check("R-C3-12 a failed staging write fails loud, exit 2", _caught)

_caught = False
try:
    S.provision(FakeRuntime(fail_on="config load"), "lab", "s1", NODE, TOPO)
except SystemExit as _e:
    _caught = (_e.code == 2)
check("R-C3-12 a failed `config load` fails loud, exit 2", _caught,
      "a silent apply failure would leave the node unaddressed")

_caught = False
try:
    S.provision(FakeRuntime(hwsku="Bogus-Platform-9000"), "lab", "s1", NODE, TOPO)
except SystemExit:
    _caught = True
check("R-C3-13 an unlisted HwSKU is SUPPORTED end to end, not refused",
      not _caught, "derivation is authoritative; the table is a drift witness")

# --- report -----------------------------------------------------------------
_failed = [c for c in _checks if not c[1]]
for _n, _ok, _d in _checks:
    print("%-4s %s%s" % ("PASS" if _ok else "FAIL", _n,
                         ("  [%s]" % _d) if _d else ""))
print("=" * 60)
if _failed:
    print("RESULT: FAIL -- %d check(s) (WI-1 SONiC provision supply)"
          % len(_failed))
    sys.exit(1)
print("RESULT: PASS -- %d checks (WI-1 SONiC provision supply)" % len(_checks))
