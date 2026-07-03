#!/usr/bin/env python3
"""backend_seam_proof.py -- §4.14 WI-3 (PO-5), lab-free.

Proves backend-seam openness (REQ-414-IF-1/-3, open/closed): a second backend,
defined entirely in this test, satisfies the ImporterBackend contract and runs
through the existing run_import orchestrator with NO change to the contract or
to any consumer. Registration is a single registry entry; the orchestrator,
validator reuse, and emission path are unchanged.

Exit 0 on all-pass; loud exit 1 on any failure. Run from the repo root:
    python tests/importer/backend_seam_proof.py
"""
import os
import sys
import tempfile
import shutil

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import yaml  # noqa: E402
import cassian_common as _cc  # noqa: E402
_cc._QUIET_DIE = True

import cassian_import  # noqa: E402
from cassian_import import ImporterBackend, run_import  # noqa: E402
from cassian_model import ensure_valid_topology, resolve_topology  # noqa: E402

checks = []


def record(name, ok, detail=""):
    checks.append((name, ok, detail))


class EchoBackend(ImporterBackend):
    """Independent, test-only backend. Ignores the source and returns a fixed,
    schema-conformant pair — proving the contract is satisfiable by an
    implementation the importer module has never seen."""

    name = "echo"

    def produce(self, source_dir):
        topo = {
            "name": "echo-topo",
            "nodes": [
                {"name": "a", "type": "frr", "asn": 64512, "router_id": "9.9.9.9"},
            ],
            "links": [],
        }
        # Empty starter set: PO-5 proves backend-seam openness, not invariant
        # richness. The pair is gate-conformant with no tests block.
        return topo, []


def main():
    # Open/closed: registering a new backend is one registry entry. No edit to
    # the contract or to run_import / _select_backend / _validate_emitted_pair.
    original = dict(cassian_import.BACKENDS)
    cassian_import.BACKENDS["echo"] = EchoBackend
    scratch = tempfile.mkdtemp(prefix="po5_")
    src = tempfile.mkdtemp(prefix="po5src_")
    try:
        record("PO-5 registry is open for extension (IF-1)",
               "echo" not in original and "echo" in cassian_import.BACKENDS)

        # The unchanged orchestrator drives the new backend end-to-end. The echo
        # backend ignores source contents; an existing dir satisfies the
        # produce_pair precondition without any contract change.
        run_import(src, scratch, backend="echo")
        topo_path = os.path.join(scratch, "topology.yaml")
        record("PO-5 new backend emits via unchanged orchestrator (IF-1)",
               os.path.isfile(topo_path))

        topo = yaml.safe_load(open(topo_path))
        try:
            ensure_valid_topology(topo)
            resolve_topology(topo)
            record("PO-5 second-backend output is gate-conformant (IF-3)", True)
        except SystemExit as e:
            record("PO-5 second-backend output is gate-conformant (IF-3)", False, str(e))
    finally:
        cassian_import.BACKENDS.clear()
        cassian_import.BACKENDS.update(original)
        shutil.rmtree(scratch, ignore_errors=True)
        shutil.rmtree(src, ignore_errors=True)

    failed = [n for n, ok, _ in checks if not ok]
    for n, ok, detail in checks:
        print(("PASS" if ok else "FAIL") + "  " + n + (("  -- " + detail) if detail else ""))
    if failed:
        print("\nBACKEND-SEAM PROOF FAIL: " + str(len(failed)) + " check(s)")
        sys.exit(1)
    print("\nRESULT: PASS -- " + str(len(checks)) + " checks (PO-5)")
    sys.exit(0)


if __name__ == "__main__":
    main()
