#!/usr/bin/env python3
"""import_deploy_proof.py -- §4.6 PF-9 (PO-7): the end-to-end deploy proof.

Imports siteA through the shipped `cassian import` command into a scratch
directory, compares the pair to PF-5's golden, then drives the gate's own
lifecycle on the imported topology, unchanged (P-11): validate, up, test,
down. REQ-46-30, in the order the stages run:

  import     the import exits 0
  golden     the pair equals tests/importer/fixtures/golden/siteA/
  set-aside  the route_present check is in the set-aside section of
             tests/starter_invariants.yaml and not in topology.yaml
  validate   `cassian validate` accepts the imported topology
  up         `cassian up` deploys it
  test       `cassian test` exits 0 and results.json records the four
             embedded starter invariants as PASS
  down       `cassian down` exits 0
  no-lab     no container of the lab is left afterwards

The proof owns Doctrine §1.7 (an imported topology is shown to deploy and
pass on running devices) and §1.6 at deploy (the pair deployed is byte for
byte the pair imported). It uses the engine's existing readiness and
precheck waits only, with no timeout or sleep of its own (D-10). A red run
is a failed proof (IR-30), and the output names the stage that failed
(M-11). A stage that did not run is not a pass.

Negative variants (REQ-46-31), run once each in Chat 3 and not in CI:

    python tests/importer/import_deploy_proof.py --case <name>

Each case is a directory under tests/importer/fixtures/deploy-neg/. Its
source/ and golden/ files replace siteA's source and golden files of the
same relative path, in a scratch copy; nothing committed is edited:

  starter-fails   leaf1's remote_asn is 65099, with the golden that import
                  writes: the pair deploys, and a starter invariant cannot
                  pass
  import-fails    leaf1's session has no remote_asn: the import hard-fails
  golden-differs  the golden topology.yaml with one byte changed

Exit 0 on all-pass; loud exit 1 on any failure. Run from the repo root:
    python tests/importer/import_deploy_proof.py
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
CASSIAN = os.path.join(_ROOT, "src", "cassian.py")
FIX = os.path.join(_HERE, "fixtures")
SOURCE = os.path.join(FIX, "siteA")
GOLDEN = os.path.join(FIX, "golden", "siteA")
CASES_DIR = os.path.join(FIX, "deploy-neg")
CASES = ("starter-fails", "import-fails", "golden-differs")
PAIR = ("topology.yaml", os.path.join("tests", "starter_invariants.yaml"))

LAB = "siteA"
STARTERS = (
    "starter_bgp_session_up_leaf1_10_0_0_2",
    "starter_bgp_session_up_spine1_10_0_0_1",
    "starter_interface_state_leaf1_eth1",
    "starter_interface_state_spine1_eth1",
)
SET_ASIDE = ("starter_route_present_leaf1_192_0_2_0_24",)
STAGES = ("import", "golden", "set-aside", "validate", "up", "test", "down", "no-lab")

stages = []


def stage(name, ok, detail=""):
    """Record one stage's outcome and print it; return ok."""
    stages.append((name, ok))
    print("STAGE %-9s %s%s" % (name, "OK" if ok else "FAIL",
                               ("  -- " + detail) if detail and not ok else ""))
    return ok


def cassian(*args):
    """Run the shipped CLI from the repo root; print its exit code and the
    tail of its output, and return both."""
    r = subprocess.run([sys.executable, CASSIAN] + list(args), cwd=_ROOT,
                       env=dict(os.environ, PYTHONPATH="src"),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, errors="replace")
    print("---- cassian %s -> rc=%d" % (" ".join(args), r.returncode))
    for line in r.stdout.rstrip("\n").split("\n")[-25:]:
        print("     | " + line)
    return r.returncode, r.stdout


def overlay(base, case_dir, dest):
    """Copy base to dest, then every file under case_dir over the file of
    the same relative path."""
    shutil.copytree(base, dest)
    for d, _, names in os.walk(case_dir):
        for n in sorted(names):
            src = os.path.join(d, n)
            dst = os.path.join(dest, os.path.relpath(src, case_dir))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)


def read_bytes(root, rel):
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        return f.read()


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def starter_verdicts(path):
    """{name: verdict} for each starter invariant results.json records exactly
    once as kind invariant, expected pass; None when the file is unreadable."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        print("     results.json unreadable: %s" % e)
        return None
    found = {}
    for t in doc.get("tests") or []:
        if t.get("name") in STARTERS:
            found.setdefault(t["name"], []).append(t)
    verdicts = {}
    for name in STARTERS:
        recs = found.get(name) or []
        fields = [{k: r.get(k) for k in ("kind", "expected", "observed", "verdict")}
                  for r in recs]
        if len(recs) == 1 and fields[0] == {"kind": "invariant", "expected": "pass",
                                            "observed": "pass", "verdict": "pass"}:
            verdicts[name] = "pass"
        print("     %s: %s" % (name, json.dumps(fields)))
    return verdicts


def lab_containers():
    """(docker exit code, names of containers of the lab, running or not). With
    no docker executable the check raises nothing: it prints why and returns
    127 and no names, so no-lab is recorded FAIL and named (RP-18; M-11)."""
    prefix = "clab-%s-" % LAB
    try:
        r = subprocess.run(["docker", "ps", "-a", "--filter", "name=^" + prefix,
                            "--format", "{{.Names}}"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, errors="replace")
    except OSError as e:
        print("     docker ps could not run: %s" % e)
        return 127, []
    return r.returncode, sorted(n for n in r.stdout.split() if n.startswith(prefix))


def run(case):
    scratch = tempfile.mkdtemp(prefix="pf9_")
    deployed = False
    try:
        source, golden = SOURCE, GOLDEN
        if case:
            case_dir = os.path.join(CASES_DIR, case)
            if not os.path.isdir(case_dir):
                stage("import", False, "no case directory %s" % case_dir)
                return
            if os.path.isdir(os.path.join(case_dir, "source")):
                source = os.path.join(scratch, "source")
                overlay(SOURCE, os.path.join(case_dir, "source"), source)
            if os.path.isdir(os.path.join(case_dir, "golden")):
                golden = os.path.join(scratch, "golden")
                overlay(GOLDEN, os.path.join(case_dir, "golden"), golden)

        out = os.path.join(scratch, "out")
        rc, _ = cassian("import", source, "--out", out)
        if not stage("import", rc == 0, "rc=%d" % rc):
            return

        differ = [rel for rel in PAIR if read_bytes(out, rel) != read_bytes(golden, rel)]
        if not stage("golden", not differ, "differs from the golden: %s" % ", ".join(differ)):
            return

        topo_path = os.path.join(out, "topology.yaml")
        topo = load_yaml(topo_path)
        starter = load_yaml(os.path.join(out, PAIR[1]))
        embedded = [t.get("name") for t in topo.get("tests") or []]
        aside = [t.get("name") for t in
                 (starter.get("needs_device_configuration") or {}).get("tests") or []]
        route_in_topo = [t.get("name") for t in topo.get("tests") or []
                         if t.get("type") == "route_present"]
        if not stage("set-aside",
                     topo.get("name") == LAB and embedded == list(STARTERS)
                     and aside == list(SET_ASIDE) and not route_in_topo,
                     "lab %r; embedded %s; set aside %s; route_present in topology.yaml %s"
                     % (topo.get("name"), embedded, aside, route_in_topo)):
            return

        rc, _ = cassian("validate", topo_path)
        if not stage("validate", rc == 0, "rc=%d" % rc):
            return

        deployed = True
        rc, _ = cassian("up", topo_path)
        if not stage("up", rc == 0, "rc=%d" % rc):
            return

        results = os.path.join(_ROOT, "labs", "clab-%s" % LAB, "results.json")
        try:
            if os.path.exists(results):
                os.remove(results)  # never read an earlier run's record
        except OSError as e:
            stage("test", False, "cannot remove an earlier results.json: %s" % e)
            return
        rc, _ = cassian("test", LAB)
        verdicts = starter_verdicts(results)
        not_pass = [n for n in STARTERS if (verdicts or {}).get(n) != "pass"]
        stage("test", rc == 0 and verdicts is not None and not not_pass,
              "rc=%d; not PASS in results.json: %s" % (rc, not_pass))
    finally:
        if deployed:
            rc, _ = cassian("down", LAB)
            stage("down", rc == 0, "rc=%d" % rc)
            drc, left = lab_containers()
            stage("no-lab", drc == 0 and not left,
                  "docker ps rc=%d; containers left %s" % (drc, left))
        shutil.rmtree(scratch, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="§4.6 PF-9: the end-to-end deploy proof on siteA")
    ap.add_argument("--case", choices=CASES,
                    help="run one negative variant (REQ-46-31); CI runs the positive only")
    args = ap.parse_args()
    print("PF-9 import_deploy_proof: %s" % ("case " + args.case if args.case else "siteA positive"))
    run(args.case)
    print("=" * 60)
    names = [n for n, _ in stages]
    failed = [n for n, ok in stages if not ok]
    if names == list(STAGES) and not failed:
        print("RESULT: PASS -- PF-9 siteA: %d stages (REQ-46-30)" % len(STAGES))
        sys.exit(0)
    print("FAILED STAGE: %s" % (failed[0] if failed else "none failed, but stages ran: %s" % names))
    print("RESULT: FAIL -- a stage that did not run is not a pass")
    sys.exit(1)


if __name__ == "__main__":
    main()
