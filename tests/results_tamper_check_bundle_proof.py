#!/usr/bin/env python3
"""results.json tamper-seal proof (§4.5-d, S32-R3; BL-P2-4.5c-230; S30-R33).

Every results.json present under the labs directory is re-verified against its own
tamper seal. Usage, from the repository root:

    python tests/results_tamper_check_bundle_proof.py [<labs_dir>]   # default: labs

Per bundle, each of these must hold:
  B-STATE   tamper_check is an object with state "verified" and a 64-hex digest.
  B-RECIPE  the digest recomputed by THIS FILE's implementation of the recipe in
            docs/audit-grade-evidence.md, "Verifying a bundle", equals the stored one.
  B-ENGINE  the digest recomputed by cassian_engine._audit_compute_tamper_check
            equals the stored one.

Floors and controls (each shown able to fail; a control that is not reached fails
the proof):
  F-FOUND   at least one bundle is found -- an empty labs directory is a FAIL, never
            a pass (absence is not evidence).
  D-DOCS    the recipe this file implements is the recipe the docs page states: the
            excluded names and paths are read from the page and must equal this file's
            constants, so the documented recipe and the checked recipe cannot drift.
  NV-1      a changed verdict (`result` pass<->fail) changes both recomputed digests.
  NV-2      a changed excluded field (`summary.duration_ms`, the `timing` subtree)
            changes neither recomputed digest.
  NV-3      the BL-P2-4.5c-230 defect: a seal computed before the writer's last edits
            (`hard_failure` still null, `overall.expected` absent), then the edits
            made, is detected as a mismatch by both limbs.
  NV-4      the two limbs agree on a synthetic record carrying non-ASCII text, nested
            excluded names, all three excluded paths and a list of objects.
  NV-5      an `unverifiable` stamp is rejected by B-STATE.
NV-1 to NV-3 run on the first bundle found and on a synthetic record, so they are
reached whether or not bundles exist; F-FOUND then fails an empty run.

COVERAGE LIMIT (stated, founder ruling S32-R3 under PBE-P2-11): this proof reaches
every results.json present under the labs directory WHEN IT RUNS. A bundle written
earlier in the same job and overwritten by a later run of the same lab -- `up
--reconfigure` removes the lab directory first -- is not seen; the count printed is
the reach. INDEPENDENCE IS PARTIAL: the recipe limb shares no code with the engine and
is written from the docs page, but one author wrote both.
"""
import copy
import glob
import hashlib
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
import cassian_engine as engine  # noqa: E402

DOCS = os.path.join(ROOT, "docs", "audit-grade-evidence.md")
EXCLUDED_NAMES = {"duration_ms", "started_at", "finished_at",
                  "resolved_topology_mtime", "resolved_topology_path", "tamper_check"}
EXCLUDED_PATHS = {"timing", "blast_radius.path", "authority.supporting_evidence.path"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok)))
    print(("PASS  " if ok else "FAIL  ") + name + (("  -- " + detail) if detail and not ok else ""))
    return bool(ok)


# ---- the recipe, as the docs page states it -------------------------------------

def _drop(value, path):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            here = (path + "." + key) if path else key
            if key in EXCLUDED_NAMES or here in EXCLUDED_PATHS:
                continue
            out[key] = _drop(item, here)
        return out
    if isinstance(value, list):
        return [_drop(item, path) for item in value]   # an array adds no step
    return value


def recipe_digest(record):
    text = json.dumps(_drop(record, ""), indent=2, sort_keys=True, ensure_ascii=False)
    text = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def engine_digest(record):
    return engine._audit_compute_tamper_check(record).get("digest")


def stored(record):
    tc = record.get("tamper_check") if isinstance(record, dict) else None
    if not isinstance(tc, dict) or tc.get("state") != "verified" \
            or not isinstance(tc.get("digest"), str) or not HEX64.match(tc["digest"]):
        return None
    return tc["digest"]


# ---- D-DOCS: the page states this file's recipe -----------------------------------

def docs_recipe():
    text = open(DOCS, encoding="utf-8").read()
    m = re.search(r"(?ms)^### Verifying a bundle\n(.*?)(?=^## )", text)
    if not m:
        return None, None
    body = m.group(1)
    s2 = [l for l in body.split("\n") if l.startswith("2. ")]
    s3 = [l for l in body.split("\n") if l.startswith("3. ")]
    if len(s2) != 1 or len(s3) != 1:
        return None, None
    names = set(re.findall(r"`([^`]+)`", s2[0]))
    lead = s3[0].split(" A path names", 1)[0]
    paths = set(re.findall(r"`([^`]+)`", lead))
    return names, paths


names, paths = docs_recipe()
check("D-DOCS the page's excluded names equal this file's", names == EXCLUDED_NAMES,
      "page %r" % (sorted(names) if names else names))
check("D-DOCS the page's excluded paths equal this file's", paths == EXCLUDED_PATHS,
      "page %r" % (sorted(paths) if paths else paths))
check("D-DOCS control: a page missing one name would differ",
      names is not None and (names - {"tamper_check"}) != EXCLUDED_NAMES)


# ---- synthetic record (reached with or without bundles) ---------------------------

def synthetic():
    rec = {
        "result": "pass", "tool": "cassian-gate", "lab": "lab-ü",
        "tests": [{"name": "t1 — ok", "verdict": "pass", "duration_ms": 12,
                   "meta": {"started_at": 1.0, "note": "naïve"}}],
        "summary": {"passed": 1, "duration_ms": 900, "started_at": 1.0, "finished_at": 2.0,
                    "resolved_topology_path": "/abs/x", "resolved_topology_mtime": 9.9},
        "timing": {"duration_ms": 900, "precheck": {"attempts": 3}},
        "blast_radius": {"path": "/abs/blast", "nodes": ["r1"]},
        "authority": {"verdict_source": "tests",
                      "supporting_evidence": [{"type": "x", "path": "/abs/se"},
                                              {"type": "y", "path": "/abs/se2"}]},
        "hard_failure": {"occurred": False, "phase": "", "error": ""},
        "overall": {"expected": "pass", "observed": "pass", "verdict": "pass"},
    }
    rec["tamper_check"] = engine._audit_compute_tamper_check(rec)
    return rec


SYN = synthetic()
check("NV-4 the two limbs agree on the synthetic record",
      recipe_digest(SYN) == engine_digest(SYN) == stored(SYN),
      "recipe %s engine %s stored %s" % (recipe_digest(SYN)[:12], str(engine_digest(SYN))[:12],
                                         str(stored(SYN))[:12]))


def controls(rec, label):
    want = stored(rec)
    r1 = copy.deepcopy(rec)
    r1["result"] = "fail" if str(r1.get("result")) == "pass" else "pass"
    check("NV-1 %s: a changed verdict changes both digests" % label,
          recipe_digest(r1) != want and engine_digest(r1) != want)
    r2 = copy.deepcopy(rec)
    r2.setdefault("summary", {})["duration_ms"] = 123456789
    r2["timing"] = {"duration_ms": 1, "added": "x"}
    check("NV-2 %s: a changed excluded field changes neither digest" % label,
          recipe_digest(r2) == want and engine_digest(r2) == want)
    # NV-3: the -230 order -- stamp first, then the writer's edits
    r3 = copy.deepcopy(rec)
    r3["hard_failure"] = None
    ov = r3.get("overall") if isinstance(r3.get("overall"), dict) else {}
    ov.pop("expected", None)
    r3["overall"] = ov
    early = engine._audit_compute_tamper_check(r3)
    r3["hard_failure"] = {"occurred": False, "phase": "", "error": ""}
    r3["overall"]["expected"] = "pass"
    r3["tamper_check"] = early
    s3 = stored(r3)
    check("NV-3 %s: a seal taken before the writer's last edits is detected" % label,
          s3 is not None and recipe_digest(r3) != s3 and engine_digest(r3) != s3)


controls(SYN, "synthetic")
bad = copy.deepcopy(SYN)
bad["tamper_check"] = {"algo": "sha256", "digest": None, "domain": "canonical-filtered",
                       "state": "unverifiable"}
check("NV-5 an unverifiable stamp is rejected by B-STATE", stored(bad) is None)


# ---- the bundles ------------------------------------------------------------------

labs = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "labs"))
found = sorted(glob.glob(os.path.join(labs, "**", "results.json"), recursive=True))
print("bundles: %d results.json under %s" % (len(found), labs))
check("F-FOUND at least one bundle is present (an empty run is not a pass)", len(found) > 0)
first = None
for path in found:
    rel = os.path.relpath(path, labs)
    try:
        rec = json.loads(open(path, "rb").read().decode("utf-8"))
    except Exception as exc:
        check("B-PARSE %s" % rel, False, repr(exc))
        continue
    want = stored(rec)
    if not check("B-STATE %s" % rel, want is not None, "tamper_check=%r" % rec.get("tamper_check")):
        continue
    check("B-RECIPE %s" % rel, recipe_digest(rec) == want,
          "recipe %s stored %s" % (recipe_digest(rec)[:12], want[:12]))
    check("B-ENGINE %s" % rel, engine_digest(rec) == want,
          "engine %s stored %s" % (str(engine_digest(rec))[:12], want[:12]))
    if first is None:
        first = (rec, rel)
if first is not None:
    controls(first[0], "bundle %s" % first[1])

fails = [n for n, ok in checks if not ok]
print("=" * 60)
print("bundles verified: %d of %d" % (
    sum(1 for n, ok in checks if ok and n.startswith("B-ENGINE")), len(found)))
print("RESULT: %s -- %d of %d check(s) (S32-R3 tamper seal over every bundle present)"
      % ("PASS" if not fails else "FAIL", len(checks) - len(fails), len(checks)))
sys.exit(1 if fails else 0)
