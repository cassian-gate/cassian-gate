#!/usr/bin/env python3
"""preservation_proof.py -- §4.14 WI-4 (PO-6), lab-free.

Proves §4.14 preservation (REQ-414-PRES-1/-2/-3): every src/ module OUTSIDE the
scoped set is byte-identical to its pre-§4.14 baseline (the fork point,
`git merge-base HEAD develop/phase1b`), via reproducible per-module SHA-256, plus
a module-set-drift guard. The baseline is read live from git (self-grounding) so
there is no pinned hash to drift.

Scoped (modifiable by §4.14; excluded from byte-identity enforcement):
  src/cassian_cli.py   -- additive `cassian import` registration (WI-2)
Allowed new module (added by §4.14; absent at baseline):
  src/cassian_import.py -- the importer (WI-1)

Everything else in src/ -- including cassian_model.py (reuse-by-import only,
LD-4), the §13(b)(c) render seam + invariant-evaluation path (cassian_tests.py,
cassian_engine.py), the results.json writer (cassian_artifacts.py), and the
advisory adapt/adapters.v1 surface (cassian_engine.py) -- must be byte-identical
to baseline. Those modules are asserted in the enforced set explicitly.

Exit 0 on all-pass; loud exit 1 on any drift, module-set change, or missing
baseline ref. Run from the repo root:
    python tests/importer/preservation_proof.py
"""
import hashlib
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))

SCOPED = {"src/cassian_cli.py"}
NEW_ALLOWED = {"src/cassian_import.py"}

# Non-scoped modules that carry specific preservation obligations; asserted to be
# present in the enforced byte-identical set (defensive, beyond the sweep).
PRES_CRITICAL = {
    "src/cassian_model.py",      # LD-4 reuse-by-import; never edited
    "src/cassian_tests.py",      # §13(b)(c) render seam + invariant evaluation
    "src/cassian_engine.py",     # results.json path + advisory adapt surface
    "src/cassian_artifacts.py",  # results.json canonical writer
}

checks = []


def record(name, ok, detail=""):
    checks.append((name, ok, detail))


def _git(args):
    return subprocess.run(["git"] + args, cwd=_ROOT, capture_output=True,
                          text=True)


def _sha_bytes(b):
    return hashlib.sha256(b).hexdigest()


def _sha_file(path):
    with open(path, "rb") as f:
        return _sha_bytes(f.read())


def _resolve_base():
    for ref in ("origin/develop/phase1b", "develop/phase1b"):
        if _git(["rev-parse", "--verify", "--quiet", ref]).returncode == 0:
            mb = _git(["merge-base", "HEAD", ref])
            if mb.returncode == 0 and mb.stdout.strip():
                return mb.stdout.strip(), ref
    return None, None


def main():
    base, ref = _resolve_base()
    if not base:
        print("FAIL: cannot resolve baseline ref (develop/phase1b not reachable). "
              "Fetch the integration branch and re-run.")
        sys.exit(1)
    print("baseline = " + base[:12] + " (merge-base HEAD " + ref + ")")

    # Baseline src/*.py set from git.
    ls = _git(["ls-tree", "-r", "--name-only", base, "--", "src/"])
    baseline = set(p for p in ls.stdout.splitlines()
                   if p.startswith("src/") and p.endswith(".py"))
    # Current src/*.py set on disk.
    src_dir = os.path.join(_ROOT, "src")
    head = set("src/" + n for n in os.listdir(src_dir) if n.endswith(".py"))

    added, removed = head - baseline, baseline - head
    set_ok = (added == NEW_ALLOWED) and (not removed)
    record("PO-6 module-set drift = {cassian_import.py} added, none removed",
           set_ok, "added=" + str(sorted(added)) + " removed=" + str(sorted(removed)))

    # Per-module byte-identity for every non-scoped baseline module.
    enforced = 0
    drift = []
    for mod in sorted(baseline):
        if mod in SCOPED:
            continue
        blob = _git(["show", base + ":" + mod])
        if blob.returncode != 0:
            drift.append(mod + " (baseline blob unreadable)")
            continue
        baseline_sha = _sha_bytes(blob.stdout.encode("utf-8"))
        # Use git's own object bytes to avoid newline-encoding skew.
        cat = subprocess.run(["git", "cat-file", "blob", base + ":" + mod],
                             cwd=_ROOT, capture_output=True)
        baseline_sha = _sha_bytes(cat.stdout)
        current_sha = _sha_file(os.path.join(_ROOT, mod))
        enforced += 1
        if baseline_sha != current_sha:
            drift.append(mod + " expected " + baseline_sha[:12]
                         + " actual " + current_sha[:12])
    record("PO-6 non-scoped byte-identity vs baseline (" + str(enforced)
           + " enforced, cassian_cli.py scoped)",
           not drift and enforced >= 1, "; ".join(drift))

    # Defensive: the preservation-critical modules are in the enforced set.
    record("PO-6 §13(b)(c) seam + advisory + results-writer + model in enforced set",
           PRES_CRITICAL.issubset(baseline - SCOPED),
           "missing=" + str(sorted(PRES_CRITICAL - (baseline - SCOPED))))

    failed = [n for n, ok, _ in checks if not ok]
    for n, ok, detail in checks:
        print(("PASS" if ok else "FAIL") + "  " + n + (("  -- " + detail) if detail else ""))
    if failed:
        print("\nPRESERVATION FAIL: " + str(len(failed)) + " check(s)")
        sys.exit(1)
    print("\nRESULT: PASS -- " + str(len(checks)) + " checks (PO-6)")
    sys.exit(0)


if __name__ == "__main__":
    main()
