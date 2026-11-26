#!/usr/bin/env python3
"""wf_additions_only_proof.py -- §4.5-e WI-3, REQ-45E-14 (BL-P2-4.5c-241's instrument; ESC-5 ruling).

Doctrine surface: Design Contract v2.1 §14 item 8, "No silent mutation introduced", for
.github/workflows/cassian.yml. Every change to the workflow is additions-only: each step present at
the merge-base with origin/develop/phase2 is present at HEAD byte-identical, in the same job and in
the same relative order. Added steps are admitted anywhere. No per-section list, so a later section
reuses this file unchanged.

Method (handover B12): resolve `git merge-base HEAD origin/develop/phase2`; read cassian.yml at that
commit and in the working tree; split each job's `steps:` list into step blocks by indentation; every
merge-base step must appear at HEAD, byte for byte, as an ordered subsequence. It never accepts a
removed-line count as the check: a line inserted inside an existing step removes no line (V27a).

Fails closed (ESC-5 ruling): a shallow history, an unresolvable merge-base, an unreadable merge-base
cassian.yml, an unreadable working-tree cassian.yml, or a step split that PyYAML does not confirm is
a FAIL. It never skips and never passes on any of them. CI's Checkout step keeps its default
depth 1, so the CI step that runs this file fetches the base branch's history first (founder answer 5).

Legs:
  A-HEAD  the working tree against the merge-base: every merge-base step present, in order.
  A-FC    fail-closed, each shown red: a depth-1 clone in a temporary directory; an unreadable
          merge-base cassian.yml; an unresolvable merge-base.
  A-NV    on in-memory copies of the working tree's cassian.yml, each shown red: a line inserted
          inside an existing step (V27a), the Checkout step given a fetch-depth, a modified step,
          two steps swapped, a step removed. An added step stays green (additions are admitted).

Coverage limits (PBE-P2-8), stated rather than implied:
  - It compares the jobs' `steps:` lists. Keys outside them (`on:`, `permissions:`, a job's `env:`
    or `runs-on:`) are not compared, and neither is a job added at HEAD.
  - A comment line at or left of a list's item indentation separates steps and belongs to none, so a
    change to such a comment is not seen. Every line inside a step is compared, comments included.
  - It proves the file's steps; it does not prove that a step runs or that its proof passes.

Run:  python3 tests/wf_additions_only_proof.py      (from the repository root or anywhere)
Exit: 0 = every leg passed; 1 = otherwise.
"""
import os
import re
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WF_REL = ".github/workflows/cassian.yml"
BASE_REF = "origin/develop/phase2"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

checks = []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))


def _git(root, *args):
    """Run git in `root`; return (rc, stdout). Never raises."""
    try:
        r = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    except OSError as e:
        return 127, str(e)
    return r.returncode, r.stdout


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def parse_steps(text):
    """Return {job_id: [step_text, ...]} from each job's `steps:` list, split by indentation."""
    lines = text.splitlines(keepends=True)
    jobs, i, n = {}, 0, len(lines)
    while i < n and not re.match(r"^jobs:\s*(#.*)?$", lines[i]):
        i += 1
    i += 1
    job_indent, job = None, None
    while i < n:
        line = lines[i]
        bare = line.strip()
        if not bare or bare.startswith("#"):
            i += 1
            continue
        ind = _indent(line)
        if ind == 0:
            break
        if job_indent is None:
            job_indent = ind
        m = re.match(r"^ {%d}([A-Za-z0-9_-]+):\s*(#.*)?$" % job_indent, line)
        if ind == job_indent and m:
            job = m.group(1)
            jobs.setdefault(job, [])
            i += 1
            continue
        if job is not None and re.match(r"^\s+steps:\s*(#.*)?$", line) and ind > job_indent:
            i, steps = _split_list(lines, i + 1, ind)
            jobs[job] = steps
            continue
        i += 1
    return jobs


def _split_list(lines, i, key_indent):
    """Split the sequence that follows a `steps:` key at key_indent; return (next_index, [step_text])."""
    n, steps, cur, blanks, item = len(lines), [], None, [], None
    while i < n:
        line = lines[i]
        bare = line.strip()
        if not bare:
            blanks.append(line)
            i += 1
            continue
        ind = _indent(line)
        if item is None:
            if bare.startswith("- ") and ind >= key_indent:
                item = ind
            elif bare.startswith("#"):
                blanks = []
                i += 1
                continue
            else:
                break
        if bare.startswith("#") and ind <= item:
            if cur is not None:
                steps.append("".join(cur))
                cur = None
            blanks = []
            i += 1
            continue
        if ind == item and line[ind:].startswith("- "):
            if cur is not None:
                steps.append("".join(cur))
            cur, blanks = [line], []
            i += 1
            continue
        if ind > item and cur is not None:
            cur.extend(blanks)
            cur.append(line)
            blanks = []
            i += 1
            continue
        break
    if cur is not None:
        steps.append("".join(cur))
    return i, steps


def _yaml_counts(text):
    """Step count per job as PyYAML reads it; None if it does not parse as a workflow."""
    try:
        doc = yaml.safe_load(text)
        return {j: len((v or {}).get("steps") or []) for j, v in (doc.get("jobs") or {}).items()}
    except Exception:
        return None


def _missing_in_order(base_steps, head_steps):
    """Merge-base steps not found at HEAD byte-identical after the previous match (ordered subsequence)."""
    missing, j = [], 0
    for b in base_steps:
        k = j
        while k < len(head_steps) and head_steps[k] != b:
            k += 1
        if k == len(head_steps):
            missing.append(b)
        else:
            j = k + 1
    return missing


def _first_line(step):
    return step.splitlines()[0].strip() if step else ""


def evaluate(root, head_text=None, base_ref=BASE_REF, wf_rel=WF_REL):
    """Return (ok, reasons). Every unreadable or unresolvable input is a failure, never a skip."""
    reasons = []
    rc, out = _git(root, "rev-parse", "--is-shallow-repository")
    if rc != 0 or out.strip() not in ("true", "false"):
        return False, ["fail closed: cannot tell whether the history is shallow (rc=%d)" % rc]
    if out.strip() == "true":
        return False, ["fail closed: shallow history; the merge-base cannot be trusted"]
    rc, out = _git(root, "merge-base", "HEAD", base_ref)
    mb = out.strip()
    if rc != 0 or not _SHA_RE.match(mb):
        return False, ["fail closed: merge-base HEAD %s unresolvable (rc=%d)" % (base_ref, rc)]
    rc, base_text = _git(root, "show", "%s:%s" % (mb, wf_rel))
    if rc != 0:
        return False, ["fail closed: %s unreadable at the merge-base %s (rc=%d)" % (wf_rel, mb[:12], rc)]
    if head_text is None:
        try:
            with open(os.path.join(root, wf_rel), encoding="utf-8") as fh:
                head_text = fh.read()
        except OSError as e:
            return False, ["fail closed: %s unreadable in the working tree (%s)" % (wf_rel, e)]
    base, head = parse_steps(base_text), parse_steps(head_text)
    for label, text, parsed in (("merge-base", base_text, base), ("HEAD", head_text, head)):
        counts = _yaml_counts(text)
        mine = {j: len(s) for j, s in parsed.items()}
        if counts is None or not mine or any(v == 0 for v in mine.values()) or counts != mine:
            return False, ["fail closed: the %s step split %s disagrees with PyYAML %s" % (label, mine, counts)]
    for job, steps in base.items():
        if job not in head:
            reasons.append("job %r at the merge-base is absent at HEAD" % job)
            continue
        for s in _missing_in_order(steps, head[job]):
            reasons.append("job %r: merge-base step changed, moved or removed: %s" % (job, _first_line(s)))
    return not reasons, reasons


def _removed_line_count(old, new):
    """The rejected instrument (BL-P2-4.5c-241): lines of `old` that `new` no longer carries."""
    import difflib
    return sum(1 for d in difflib.ndiff(old.splitlines(), new.splitlines()) if d.startswith("- "))


# ---- A-HEAD ----------------------------------------------------------------------------------------
_ok, _why = evaluate(ROOT)
check("A-HEAD every merge-base step of %s is at HEAD byte-identical and in order" % WF_REL, _ok, "; ".join(_why))
_rc, _mb = _git(ROOT, "merge-base", "HEAD", BASE_REF)
with open(os.path.join(ROOT, WF_REL), encoding="utf-8") as _fh:
    HEAD_TEXT = _fh.read()
_rc2, _BASE_TEXT = _git(ROOT, "show", "%s:%s" % (_mb.strip(), WF_REL)) if _rc == 0 else (1, "")
_base_steps = parse_steps(_BASE_TEXT) if _rc2 == 0 else {}
_head_steps = parse_steps(HEAD_TEXT)
print("A-HEAD: merge-base %s; steps per job, merge-base %s, HEAD %s"
      % (_mb.strip()[:12] or "-", {j: len(s) for j, s in _base_steps.items()},
         {j: len(s) for j, s in _head_steps.items()}))
check("A-HEAD the leg was reached: the merge-base has at least one step",
      _rc == 0 and sum(len(s) for s in _base_steps.values()) > 0)

# ---- A-FC: fail closed -------------------------------------------------------------------------------
with tempfile.TemporaryDirectory() as _td:
    _setup = [_git(_td, "init", "-q")[0],
              _git(_td, "fetch", "-q", "--no-tags", "--depth=1", "file://" + ROOT,
                   "+HEAD:refs/heads/nv-head",
                   "+refs/remotes/%s:refs/remotes/%s" % (BASE_REF, BASE_REF))[0],
              _git(_td, "checkout", "-q", "nv-head")[0]]
    _ok, _why = evaluate(_td, head_text=HEAD_TEXT)
    check("A-FC a depth-1 clone in a temporary directory fails, as shallow",
          all(r == 0 for r in _setup) and not _ok and "shallow" in " ".join(_why),
          "setup rc=%s; %s" % (_setup, "; ".join(_why)))
_ok, _why = evaluate(ROOT, head_text=HEAD_TEXT, wf_rel=".github/workflows/__absent_nv__.yml")
check("A-FC an unreadable merge-base cassian.yml fails", not _ok and "unreadable" in " ".join(_why), "; ".join(_why))
_ok, _why = evaluate(ROOT, head_text=HEAD_TEXT, base_ref="refs/remotes/origin/__absent_nv__")
check("A-FC an unresolvable merge-base fails", not _ok and "merge-base" in " ".join(_why), "; ".join(_why))

# ---- A-NV: non-vacuity on in-memory copies ----------------------------------------------------------
_job = next((j for j in _base_steps if j in _head_steps and len(_base_steps[j]) >= 3), None)
check("A-NV vehicle found: a job with at least three merge-base steps", _job is not None)
if _job is not None:
    _bs = [s for s in _base_steps[_job] if HEAD_TEXT.count(s) == 1]
    _run = next((s for s in _bs if "set -euo pipefail\n" in s), None)
    _chk = next((s for s in _bs if "actions/checkout@" in s), None)
    check("A-NV vehicles found: a step with a run script and the Checkout step",
          _run is not None and _chk is not None and len(_bs) >= 3)
    if _run is not None and _chk is not None and len(_bs) >= 3:
        _ind = " " * (_indent(_run.splitlines()[0]) + 2)
        _v27a = HEAD_TEXT.replace(_run, _run.replace("set -euo pipefail\n", "set -euo pipefail\n%s  echo nv\n" % _ind, 1), 1)
        _uses = next(l for l in _chk.splitlines(keepends=True) if "actions/checkout@" in l)
        _depth = HEAD_TEXT.replace(_chk, _chk.replace(_uses, _uses + "%swith:\n%s  fetch-depth: 0\n" % (_ind, _ind), 1), 1)
        _mod = HEAD_TEXT.replace(_bs[1], _bs[1].rstrip("\n") + " # nv\n", 1)
        _a, _b = _bs[1], _bs[2]
        _ia, _ib = HEAD_TEXT.index(_a), HEAD_TEXT.index(_b)
        _gap = HEAD_TEXT[_ia + len(_a):_ib]
        _move = HEAD_TEXT[:_ia] + _b + _gap + _a + HEAD_TEXT[_ib + len(_b):] if _ib > _ia else None
        _del = HEAD_TEXT.replace(_bs[1], "", 1)
        _add = HEAD_TEXT.replace(_bs[2], _bs[2].splitlines(keepends=True)[0].replace(_first_line(_bs[2]), "- name: nv added step", 1)
                                 + "%srun: echo nv\n" % _ind + _bs[2], 1)
        for _label, _text in (("a line inserted inside an existing step (V27a)", _v27a),
                              ("the Checkout step given a fetch-depth", _depth),
                              ("a modified step", _mod),
                              ("two steps swapped", _move),
                              ("a step removed", _del)):
            _ok, _why = evaluate(ROOT, head_text=_text) if _text else (True, ["mutant not built"])
            check("A-NV %s fails" % _label, not _ok, "; ".join(_why[:2]))
        check("A-NV V27a: a removed-line count reads 0 for that mutant, so that instrument would pass it",
              bool(_BASE_TEXT) and _removed_line_count(_BASE_TEXT, _v27a) == 0)
        _ok, _why = evaluate(ROOT, head_text=_add)
        check("A-NV an added step is admitted (the check does not over-fire)", _ok, "; ".join(_why[:2]))

ok = True
for name, passed in checks:
    print("[%s] %s" % ("PASS" if passed else "FAIL", name))
    ok = ok and passed
print("=" * 60)
print("cases:", len(checks))
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
