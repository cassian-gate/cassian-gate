#!/usr/bin/env python3
"""tests/sonic_endpoint_recognition_proof.py -- §4.5-c WI-2 endpoint recognition.

Req-IDs: REQ-45C-6 (host multitool endpoints recognized and provisioned inside
                    SONiC topologies; cell D-012.LIF)
         REQ-45C-7 (linux fallback-kind nodes recognized inside SONiC
                    topologies, lifecycle clean; cell D-013.LIF)

Snapshot mapping (handover §6.7.2 preamble, mapping discipline): the modules
this proof's subject exercises are `cassian_model` -> `src/cassian_model.py`
and `cassian_runtime_container` -> `src/cassian_runtime_container.py`. Session
snapshot is v54 == branch `feature/4_5c-sonic-base-lifecycle` @ `9f1d53a`; the
handover's authoring pin was v45 == `b129510`, which the branch has advanced
past.

RUNTIME PROOF -- this is a (VM) proof per §15.2 and consumes a REAL run. It
takes artifact directories produced by `cassian up`/`test` and asserts against
them. It has NO lab-free mode and reports no BLOCKED legs: §18(1) requires
every §15 proof green in its bound environment, and a (VM) proof that runs
lab-free and reports BLOCKED is the defect `BL-P2-4.5c-35` records. Invoked
after the lifecycle in the same VM-bound workflow step, following the shape
`tests/two_run_real_run_positive_proof.py` uses at `.github/workflows/cassian.yml`.

  python tests/sonic_endpoint_recognition_proof.py <host_artifacts> <linux_artifacts>

Each artifact directory is a copy of `labs/clab-<lab>/` carrying
`topology.resolved.yaml` and `results.json` (the replay contract,
`src/cassian_engine.py:1554-1556`).

WHAT THIS PROOF DOES NOT CLAIM -- the ratified reading, stated so a later
reader does not mistake its scope. Founder interpretive ruling 2026-08-24:
D-012.LIF and D-013.LIF are line-item **L1** cells, "Node type recognized in
topology schema", disposition VERIFY, "verify functional in SONiC-containing
topologies". Reachability THROUGH a SONiC node is D-031.VAL / D-032.VAL at
line-item **V1** and is assigned to §4.5-d by the ratified §4.5 decomposition.
This proof therefore evidences NON-INTERFERENCE: that introducing a
`runtime: vm` SONiC guest into a topology does not break host/linux
recognition, provisioning or lifecycle. It does not evidence host-to-SONiC
adjacency, and must not be read as doing so.

COVERAGE LIMITS (PBE-P2-8), stated rather than implied:
  * The peer-type leg reads DECLARED wiring from the resolved topology. It
    proves the fixture is wired onto a supported peer; it cannot prove the
    runtime applied the address -- that is what the results leg is for.
  * `x1`'s absence from the test set is asserted, not its unreachability. A
    `linux` node takes no core provisioning leg and no readiness gate
    (`src/cassian_runtime_container.py:1275` has no `linux` branch), so a test
    naming it would be untruthful rather than merely redundant.
  * The proof asserts the run PASSED. It does not re-derive the verdict; a
    defect that makes every run pass would defeat it, which is the general
    limit of any artifact-consuming proof.
"""
import json
import os
import sys

import yaml

# Peer types that `configure_hosts_from_topology` will configure a host onto --
# copied from src/cassian_runtime_container.py:1034 / :1046, not recalled.
# `sonic-vm` is deliberately ABSENT there; see BL-P2-4.5c-47.
CORE_SUPPORTED_HOST_PEERS = ("frr", "linux", "nft-fw")

# Stock canned ranges on sonic-vm:202405 (HALT-2 ruling, 2026-08-15, surface
# S-9). Duplicated deliberately from tests/sonic_lifecycle_proof.py: a proof
# that imports its own guard constants from another proof fails silently when
# that proof is renamed.
STOCK_RANGES = ("10.0.0.", "10.1.0.")

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


def _load(artifacts, label):
    p_topo = os.path.join(artifacts, "topology.resolved.yaml")
    p_res = os.path.join(artifacts, "results.json")
    check("%s: topology.resolved.yaml present" % label, os.path.isfile(p_topo),
          p_topo)
    check("%s: results.json present" % label, os.path.isfile(p_res), p_res)
    if not (os.path.isfile(p_topo) and os.path.isfile(p_res)):
        return None, None
    topo = yaml.safe_load(open(p_topo, encoding="utf-8").read()) or {}
    res = json.load(open(p_res, encoding="utf-8"))
    check("%s: resolved topology exposes a nodes list" % label,
          isinstance(topo.get("nodes"), list) and bool(topo.get("nodes")),
          "keys: %s" % sorted(topo.keys()))
    return topo, res


def _types(topo):
    out = {}
    for n in (topo.get("nodes") or []):
        if isinstance(n, dict) and n.get("name"):
            out[str(n["name"])] = str(n.get("type") or "").strip().lower()
    return out


def _verdicts(res):
    out = {}
    for t in (res.get("tests") or []):
        if isinstance(t, dict) and t.get("name"):
            out[str(t["name"])] = str(t.get("verdict") or "").strip().lower()
    return out


def main():
    if len(sys.argv) < 3:
        print("usage: sonic_endpoint_recognition_proof.py "
              "<host_artifacts_dir> <linux_artifacts_dir>")
        print("This is a (VM) proof; it consumes a real run and has no "
              "lab-free mode.")
        sys.exit(2)

    host_dir, linux_dir = sys.argv[1], sys.argv[2]

    # ---------------------------------------------------------------- REQ-45C-6
    topo, res = _load(host_dir, "host-leg")
    if topo is not None:
        types = _types(topo)

        # NON-VACUITY: without a sonic-vm node in the lab this proof would
        # evidence nothing about SONiC-containing topologies.
        check("REQ-45C-6 NON-VACUITY: the lab contains a sonic-vm node",
              "sonic-vm" in types.values(),
              "types: %s" % sorted(set(types.values())))

        hosts = [n for n, t in types.items() if t == "host"]
        check("REQ-45C-6 host node recognized in the resolved topology",
              bool(hosts), "hosts: %s" % (hosts or "none"))

        # Reading-2 guard (BL-P2-4.5c-47). A host wired onto a sonic-vm peer is
        # never configured, silently. Fire here rather than let a future
        # re-wiring produce an unexplained runtime failure.
        bad = []
        for link in (topo.get("links") or []):
            eps = (link or {}).get("endpoints") or []
            if len(eps) != 2:
                continue
            a, b = [str(e).split(":", 1)[0] for e in eps]
            for near, far in ((a, b), (b, a)):
                if types.get(near) == "host" and \
                        types.get(far) not in CORE_SUPPORTED_HOST_PEERS:
                    bad.append("%s->%s(%s)" % (near, far, types.get(far)))
        check("BL-P2-4.5c-47 guard: every host peer is core-supported "
              "%s" % (CORE_SUPPORTED_HOST_PEERS,),
              not bad,
              "unsupported host peers: %s -- a host on a sonic-vm peer is "
              "never configured (runtime_container:1034/:1046)" % (bad or "none"))

        # HALT-2 at run time, on the resolved artifact rather than the fixture.
        stock = []
        for link in (topo.get("links") or []):
            for a in ((link or {}).get("ipv4") or []):
                if any(str(a).startswith(p) for p in STOCK_RANGES):
                    stock.append(str(a))
        check("HALT-2 (S-9): host-leg resolved topology declares no stock-range "
              "address", not stock, "hits: %s" % (stock or "none"))

        check("REQ-45C-6 run result is pass",
              str(res.get("result") or "").strip().lower() == "pass",
              "result=%r" % res.get("result"))

        v = _verdicts(res)
        check("REQ-45C-6 reachability evidence: h1_to_r1_gateway_ping passed "
              "(host provisioned: address + default route applied while a "
              "SONiC guest is up)",
              v.get("h1_to_r1_gateway_ping") == "pass",
              "verdicts: %s" % v)

    # ---------------------------------------------------------------- REQ-45C-7
    topo, res = _load(linux_dir, "linux-leg")
    if topo is not None:
        types = _types(topo)

        check("REQ-45C-7 NON-VACUITY: the lab contains a sonic-vm node",
              "sonic-vm" in types.values(),
              "types: %s" % sorted(set(types.values())))

        linuxes = [n for n, t in types.items() if t == "linux"]
        check("REQ-45C-7 linux fallback-kind node recognized in the resolved "
              "topology", bool(linuxes), "linux nodes: %s" % (linuxes or "none"))

        check("REQ-45C-7 lifecycle completes clean (run result is pass)",
              str(res.get("result") or "").strip().lower() == "pass",
              "result=%r" % res.get("result"))

        # Truthfulness: a `linux` node takes no core provisioning leg, so no
        # test may assert against it. See the coverage-limit block above.
        named = []
        for t in (res.get("tests") or []):
            if not isinstance(t, dict):
                continue
            for field in ("from", "to", "src", "dst"):
                if str(t.get(field) or "") in linuxes:
                    named.append("%s.%s" % (t.get("name"), field))
        check("REQ-45C-7 no test asserts against an unprovisioned linux node",
              not named, "named: %s" % (named or "none"))

    # ------------------------------------------------------------------ report
    fails = [c for c in _checks if not c[1]]
    for name, ok, detail in _checks:
        print("%s %s%s" % ("PASS" if ok else "FAIL", name,
                           ("  [%s]" % detail) if detail else ""))
    print("=" * 60)
    print("RESULT: %s -- %d/%d checks passed (WI-2 endpoint recognition, "
          "REQ-45C-6/-7)"
          % ("PASS" if not fails else "FAIL", len(_checks) - len(fails),
             len(_checks)))
    if fails:
        sys.exit("sonic_endpoint_recognition_proof FAILED (%d check(s))."
                 % len(fails))


if __name__ == "__main__":
    main()
