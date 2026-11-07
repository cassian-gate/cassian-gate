#!/usr/bin/env python3
"""HS-1 -- catalogue drift proof (Stage-1 gap item (d)(2), WI-7 script 2).

Proof obligations: PO-01, PO-02, PO-03 (i) to (viii), PO-04, PO-25 and PO-26 (handover v9-rev3 section 15.1).
Requirements: REQ-S1D2-4, -5, -12, -15, -16 and -29. Acceptance check: C-3.
Founder rulings applied: SLD-3 (the golden, diffed in CI); PBR-8 (PO-25 and PO-26 sit in HS-1); PBR-11 with
SLD-21 (CI step A's interpreter loop); Am-1 (PO-26's coverage limit); Am-3 (the generator's release-version
guard); Am-6 (the human-layout leg, PO-03 (viii)); S1D2-S21-R2 (WI-7's second script; PO-26 red by plan until
WI-9 wires the HS proofs into CI).

What it proves: the catalogue `cassian checks` emits is generated from the code, byte-deterministic, equal to
the committed golden, and wired into CI. The golden is a drift guard: it is regenerated only by
scripts/regenerate_checks_catalogue.py in a reviewed commit, never by this proof (section 6.7.2). This proof
imports the generator and calls its functions; it never runs it as a script.

Legs
  G   PO-01   the generator's catalogue_bytes() equals tests/fixtures/checks_catalogue.json byte for byte.
  M   PO-01   three in-memory mutations each change the bytes, and the comparator reports each: a synthetic
              check; one flipped capability declaration; a synthetic labelled parser leaf.
  H   PO-02   one flipped byte in a temporary copy of the golden is reported by the same comparator.
  D   PO-03   byte-determinism: (i) two in-process builds; (ii) two `cassian checks --json` runs under
              different PYTHONHASHSEED; (iii) LANG=C vs LANG=C.UTF-8; (iv) the `--json` stdout vs the
              generator's catalogue_bytes(); (v) `cassian --verbose checks --json` vs `cassian checks --json`;
              (vi) the `--json` bytes vs write_json_canonical(tmp, catalogue); (vii) the human output under
              COLUMNS=40 vs 200, and through a pipe vs a pseudo-terminal; (viii) the human output rendered from
              the golden-equal catalogue has section 6.1's layout: 12 fixed lines plus one per check, profile
              and command, each line of its template's kind, each check line's two status lists and each
              command line's labels or exception reason equal to the JSON's. Every pair must be byte-equal.
  R   PO-04   on this interpreter, `cassian checks --json` equals the golden (CI step A runs this proof under
              3.10, 3.11 and 3.12).
  K   PO-25   schema_version is "checks.v1"; gate_release is cassian_engine._audit_release_version() in this
              interpreter; provisional is true; the first two human lines are section 6.1's text
              (REQ-S1D2-5); the generator's release_version_guard accepts the matching pair and refuses a
              mismatched one, exit 1, naming both values, writing nothing.
  W   PO-26   CI wiring of the HS proofs in .github/workflows/cassian.yml: every step whose run invokes an HS
              file carries `if: success() || failure()` and names each HS file it runs in its `name:`; HS-1 and
              HS-3 run under each of python3.10, 3.11 and 3.12; some step runs each of HS-2, HS-4, HS-5 and
              HS-6. RED BY PLAN until WI-9 lands (S1D2-S21-R2): before WI-9 no step runs any HS file.
  N   MUTANTS each leg above is shown capable of failing: M's three mutations (G's comparator); a flipped
              golden byte (H); an unsorted set-derived list printed under two hash seeds (D (ii), the same
              comparator); seeded renderers that drop one check line and that swap one status (D (viii));
              a build injected with release_version "0.0.0" (K); and, for W, the workflow with WI-9's two steps
              added in memory (section 14.2 WI-9, verbatim) passes, while copies of it with step A's
              `if:` key removed, an HS file dropped from step B's name, 3.12 dropped from step A's loop, or
              step B removed each fail.

Coverage limits (PBE-P2-8 / PBE-P2-14), stated so a PASS is not read as more than it is:
  1. The golden binds the bytes, not their meaning: a change that a reviewed regeneration also writes into the
     golden passes G. What the bytes must say is HS-2's, HS-3's and HS-4's.
  2. D (ii) and (iii) compare two settings each; D (vii) compares two widths and one pseudo-terminal, which is
     put in raw mode so the terminal's own newline translation does not enter the comparison.
  3. D (viii) checks each line's kind by template and the status and label lists by value; it does not check
     the column widths beyond the template's shape.
  4. W reads one file, .github/workflows/cassian.yml, parsed with PyYAML. A step "runs" an HS file when its
     `run` text names `tests/<file>` after a python invocation; interpreters come from a `for <var> in ...;
     do ... done` loop whose body invokes "python$<var>" (or "python${<var>}") on the file, or from an
     explicit `python3.1x tests/<file>`. Another way of running a file (a wrapper script, a variable holding
     the path) is not seen.
  5. W runs only where HS-1 runs: it cannot detect the removal of CI step A itself, which runs HS-1. That case
     is guarded by tests/wf_12_13_replay_proof.py's lockstep entry, name presence only (Am-1; section 18 C-28).
  6. R runs on this interpreter only; the matrix is CI step A's loop.

usage: PYTHONPATH=src python tests/checks_catalogue_drift_proof.py   (from the repo root; writes nothing in it)
"""
import copy
import dataclasses
import hashlib
import io
import contextlib
import json
import os
import pty
import re
import select
import subprocess
import sys
import tempfile
import tty
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT / "scripts"))

import yaml  # noqa: E402

import cassian_artifacts  # noqa: E402
import cassian_catalogue as C  # noqa: E402
import cassian_cli  # noqa: E402
import cassian_engine  # noqa: E402
import cassian_model  # noqa: E402
import cassian_nos_types as T  # noqa: E402
import regenerate_checks_catalogue as G  # noqa: E402

GOLDEN = ROOT / "tests" / "fixtures" / "checks_catalogue.json"
WORKFLOW = ROOT / ".github" / "workflows" / "cassian.yml"
CASSIAN = SRC / "cassian.py"

HEADER = "Cassian Gate capability catalogue (checks.v1, provisional shape), release %s"
CLOSING = "Parameters, reasons and label reasons: cassian checks --json"
STEP_A_INTERPRETERS = ("3.10", "3.11", "3.12")

# The six HS files of section 14.2 WI-7.
HS = {
    "HS-1": "checks_catalogue_drift_proof.py",
    "HS-2": "checks_catalogue_coherence_proof.py",
    "HS-3": "checks_param_conformance_proof.py",
    "HS-4": "checks_command_surface_proof.py",
    "HS-5": "checks_readonly_ai_free_proof.py",
    "HS-6": "cli_surface_preservation_proof.py",
}
MATRIX_HS = ("HS-1", "HS-3")
SINGLE_HS = ("HS-2", "HS-4", "HS-5", "HS-6")
KEY = "success() || failure()"
ANCHOR_STEP = "Project gate (up -> test -> down)"

# Section 14.2 WI-9, verbatim: the two steps WI-9 inserts immediately before ANCHOR_STEP.
WI9_STEP_A = {
    "name": "Capability catalogue drift and parameter proofs, interpreter matrix "
            "(checks_catalogue_drift_proof.py, checks_param_conformance_proof.py)",
    "if": KEY,
    "shell": "bash",
    "run": "set -euo pipefail\n"
           "for v in 3.10 3.11 3.12; do \"python$v\" tests/checks_catalogue_drift_proof.py; "
           "\"python$v\" tests/checks_param_conformance_proof.py; done\n",
}
WI9_STEP_B = {
    "name": "Capability catalogue coherence, command-surface, read-only and CLI-surface proofs "
            "(checks_catalogue_coherence_proof.py, checks_command_surface_proof.py, "
            "checks_readonly_ai_free_proof.py, cli_surface_preservation_proof.py)",
    "if": KEY,
    "shell": "bash",
    "run": "set -euo pipefail\n"
           "python tests/checks_catalogue_coherence_proof.py\n"
           "python tests/checks_command_surface_proof.py\n"
           "python tests/checks_readonly_ai_free_proof.py\n"
           "python tests/cli_surface_preservation_proof.py\n",
}

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" | {detail}" if detail else ""), flush=True)


def sha12(b):
    return hashlib.sha256(b).hexdigest()[:12]


def compare(a, b):
    """None if the two byte strings are equal; otherwise where they first differ."""
    if a == b:
        return None
    la, lb = a.split(b"\n"), b.split(b"\n")
    for i, (x, y) in enumerate(zip(la, lb)):
        if x != y:
            return f"first difference at line {i + 1}: {x[:60]!r} != {y[:60]!r}"
    return f"one is a prefix of the other ({len(la)} vs {len(lb)} lines)"


# ---------------------------------------------------------------------------------------------------------------
# Builds
# ---------------------------------------------------------------------------------------------------------------

def build(parser=None, release=None):
    return C.build_catalogue(parser or cassian_cli.build_parser(),
                             release_version=release or cassian_engine._audit_release_version())


def env(**extra):
    e = dict(os.environ, PYTHONPATH=str(SRC), PYTHONDONTWRITEBYTECODE="1")
    for k in ("COLUMNS", "LANG", "LC_ALL", "PYTHONHASHSEED"):
        e.pop(k, None)
    e.update(extra)
    return e


def run_cassian(args, **extra):
    """`cassian <args>` from an empty temporary directory: (exit code, stdout bytes, stderr bytes)."""
    with tempfile.TemporaryDirectory() as td:
        r = subprocess.run([sys.executable, "-B", str(CASSIAN), *args], cwd=td, capture_output=True,
                           timeout=300, env=env(**extra))
        left = os.listdir(td)
    return r.returncode, r.stdout, r.stderr + (f"\n(files left: {left})".encode() if left else b"")


def run_on_pty(args, **extra):
    """`cassian <args>` with stdout on a raw-mode pseudo-terminal: (exit code, stdout bytes)."""
    master, slave = pty.openpty()
    tty.setraw(slave)
    with tempfile.TemporaryDirectory() as td:
        p = subprocess.Popen([sys.executable, "-B", str(CASSIAN), *args], cwd=td, stdout=slave,
                             stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, env=env(**extra))
        os.close(slave)
        out = bytearray()
        while True:
            ready, _w, _x = select.select([master], [], [], 60)
            if not ready:
                break
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        rc = p.wait(timeout=300)
    os.close(master)
    return rc, bytes(out)


@contextlib.contextmanager
def patched(obj, name, value):
    old = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, old)


# ---------------------------------------------------------------------------------------------------------------
# PO-01 mutations (in memory)
# ---------------------------------------------------------------------------------------------------------------

def mutated_synthetic_check():
    params = dict(C.CHECK_PARAMETERS)
    params["zz_synthetic"] = copy.deepcopy(C.CHECK_PARAMETERS["route_present"])
    with patched(cassian_model, "_INVARIANT_TYPES", cassian_model._INVARIANT_TYPES + ("zz_synthetic",)), \
            patched(C, "CHECK_PARAMETERS", params):
        return C.render_json(build())


def mutated_disposition():
    """sonic-vm's declaration for the first check it declares IMPL becomes UNSUP with a message."""
    provider = cassian_model.NOS_PROVIDERS["sonic-vm"]
    token = sorted(t for t, d in provider.capabilities.items() if d.state == T.CAP_IMPL)[0]
    caps = dict(provider.capabilities)
    caps[token] = T.unsup("zz flipped by HS-1")
    registry = dict(cassian_model.NOS_PROVIDERS)
    registry["sonic-vm"] = dataclasses.replace(provider, capabilities=caps)
    with patched(cassian_model, "NOS_PROVIDERS", types.MappingProxyType(registry)):
        return C.render_json(build()), token


def mutated_leaf():
    parser = cassian_cli.build_parser()
    for action in parser._actions:
        if action.__class__.__name__ == "_SubParsersAction":
            action.add_parser("zz-synthetic").set_defaults(func=lambda a: None)
    labels = dict(C.COMMAND_LABELS)
    labels["zz-synthetic"] = (("read-only", "writes nothing"),)
    with patched(C, "COMMAND_LABELS", labels):
        return C.render_json(build(parser))


# ---------------------------------------------------------------------------------------------------------------
# PO-03 (viii): the human layout of section 6.1
# ---------------------------------------------------------------------------------------------------------------

def layout_failures(text, cat):
    """Each departure of `text` (the human output) from section 6.1's layout for catalogue `cat`."""
    bad = []
    lines = text.split("\n")
    if lines[-1] != "":
        bad.append("output does not end with one LF")
    lines = lines[:-1]
    checks_, profiles, commands = cat["checks"], cat["profiles"], cat["commands"]
    want = 12 + len(checks_) + len(profiles) + len(commands)
    if len(lines) != want:
        bad.append(f"{len(lines)} lines, expected 12 + {len(checks_)} + {len(profiles)} + {len(commands)} = {want}")
    types_ = [nt["type"] for nt in cat["node_types"]]
    nodes = ", ".join(t if nt["runtime_requirement"] is None else f"{t} (runtime {nt['runtime_requirement']})"
                      for nt, t in zip(cat["node_types"], types_))
    exp = [("header", HEADER % cat["gate_release"]), ("N1", cat["notices"][0]), ("blank", ""),
           ("node types", "Node types: " + nodes), ("blank", ""), ("checks heading", f"Checks ({len(checks_)}):")]
    exp += [("check", c) for c in checks_]
    exp += [("blank", ""), ("profiles heading", f"Profiles ({len(profiles)}):")]
    exp += [("profile", p) for p in profiles]
    exp += [("blank", ""), ("commands heading", f"Commands ({len(commands)}):")]
    exp += [("command", c) for c in commands]
    exp += [("blank", ""), ("closing", CLOSING)]
    check_re = re.compile(r"^  (\S+) +(\S+) +implemented: (.+) \| not implemented: (.+)$")
    for i, (kind, item) in enumerate(exp):
        if i >= len(lines):
            break
        ln = lines[i]
        if kind == "check":
            m = check_re.match(ln)
            done = [t for t in types_ if item["status"][t]["state"] == "implemented"]
            not_done = [t for t in types_ if item["status"][t]["state"] != "implemented"]
            if not m or (m.group(1), m.group(2)) != (item["id"], item["kind"]) \
                    or m.group(3) != (", ".join(done) or "none") or m.group(4) != (", ".join(not_done) or "none"):
                bad.append(f"line {i + 1}: check line for {item['id']} does not match its template and the JSON")
        elif kind == "profile":
            if ln != f"  {item['id']} (unversioned, {len(item['content']['invariants'])} invariants)":
                bad.append(f"line {i + 1}: profile line for {item['id']}")
        elif kind == "command":
            tail = f"exception: {item['exception']}" if item["exception"] is not None \
                else ", ".join(e["label"] for e in item["effects"])
            m = re.match(r"^  (\S+(?: \S+)?) +(.+)$", ln)
            if not m or m.group(1) != item["command"] or m.group(2) != tail:
                bad.append(f"line {i + 1}: command line for {item['command']}")
        elif ln != item:
            bad.append(f"line {i + 1}: {kind} line {ln[:60]!r}")
    return bad


def drop_a_check_line(text):
    lines = text.split("\n")
    i = next(i for i, ln in enumerate(lines) if ln.startswith("Checks ("))
    return "\n".join(lines[:i + 1] + lines[i + 2:])


def swap_a_status(text):
    lines = text.split("\n")
    i = next(i for i, ln in enumerate(lines) if ln.startswith("  ") and "implemented: " in ln
             and " | not implemented: none" not in ln and not ln.split("implemented: ")[1].startswith("none"))
    head, rest = lines[i].split("implemented: ", 1)
    done, not_done = rest.split(" | not implemented: ")
    lines[i] = f"{head}implemented: {not_done} | not implemented: {done}"
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------------------
# PO-26: CI wiring
# ---------------------------------------------------------------------------------------------------------------

def invoked(run, filename):
    """The python invocations of tests/<filename> in a step's run text: set of interpreter tags."""
    tags = set()
    path = re.escape("tests/" + filename)
    for m in re.finditer(r"for\s+(\w+)\s+in\s+([^;\n]+?)\s*;\s*do\b(.*?)\bdone", run, re.S):
        var, values, body = m.group(1), m.group(2).split(), m.group(3)
        if re.search(r'"?python\$\{?' + var + r'\}?"?\s+' + path, body):
            tags.update(values)
    for m in re.finditer(r'(?<![\w$])"?python(3\.\d+|3)?"?\s+' + path, run):
        tags.add(m.group(1) or "default")
    return tags


def wiring_failures(workflow):
    """Each departure of a parsed workflow from PO-26's wiring rule."""
    bad = []
    steps = [s for job in (workflow.get("jobs") or {}).values() for s in (job.get("steps") or [])]
    runs_of = {hs: set() for hs in HS}
    for s in steps:
        run = s.get("run") or ""
        named = [hs for hs, f in HS.items() if invoked(run, f)]
        if not named:
            continue
        label = s.get("name") or "(unnamed step)"
        if s.get("if") != KEY:
            bad.append(f"step '{label[:50]}' runs {', '.join(named)} without `if: {KEY}`")
        for hs in named:
            if HS[hs] not in (s.get("name") or ""):
                bad.append(f"step '{label[:50]}' runs {hs} but its name does not name {HS[hs]}")
            runs_of[hs] |= invoked(run, HS[hs])
    for hs in MATRIX_HS:
        missing = [v for v in STEP_A_INTERPRETERS if v not in runs_of[hs]]
        if missing:
            bad.append(f"{hs} is not run under python{', python'.join(missing)}")
    for hs in SINGLE_HS:
        if not runs_of[hs]:
            bad.append(f"no step runs {hs} ({HS[hs]})")
    return bad


def with_wi9(workflow):
    """A copy of the workflow with section 14.2's WI-9 steps inserted before the project-gate step. A step that
    already carries either name is dropped first, so the copy holds exactly one of each, before WI-9 lands and
    after it."""
    w = copy.deepcopy(workflow)
    for job in w["jobs"].values():
        steps = [s for s in job.get("steps") or [] if s.get("name") not in (WI9_STEP_A["name"], WI9_STEP_B["name"])]
        names = [s.get("name") for s in steps]
        if ANCHOR_STEP in names:
            i = names.index(ANCHOR_STEP)
            steps[i:i] = [copy.deepcopy(WI9_STEP_A), copy.deepcopy(WI9_STEP_B)]
            job["steps"] = steps
            return w
    raise SystemExit(f"no step named {ANCHOR_STEP!r} in {WORKFLOW.relative_to(ROOT)}")


def wi9_step(w, name):
    return next(s for job in w["jobs"].values() for s in job["steps"] if s.get("name") == name)


# ---------------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------------

def main():
    golden = GOLDEN.read_bytes()
    generated = G.catalogue_bytes()
    cat = build()

    # G and M (PO-01)
    diff = compare(generated, golden)
    check("G PO-01 the generator's catalogue_bytes() equals the golden", diff is None,
          diff or f"sha256 {sha12(golden)}, {len(golden)} bytes")
    synth = mutated_synthetic_check()
    flipped, token = mutated_disposition()
    leaf = mutated_leaf()
    for desc, b, needle in (("a synthetic check", synth, b"zz_synthetic"),
                            (f"sonic-vm's '{token}' flipped to UNSUP", flipped, b"zz flipped by HS-1"),
                            ("a synthetic labelled parser leaf", leaf, b"zz-synthetic")):
        d = compare(b, golden)
        check(f"N M PO-01 mutation, {desc}: the bytes change and the comparator reports it",
              d is not None and needle in b and needle not in golden, d or "comparator held")

    # H (PO-02)
    with tempfile.TemporaryDirectory() as td:
        copy_ = Path(td) / "checks_catalogue.json"
        copy_.write_bytes(golden)
        b = bytearray(copy_.read_bytes())
        i = len(b) // 2
        b[i] = ord("x") if b[i] != ord("x") else ord("y")
        copy_.write_bytes(bytes(b))
        d = compare(generated, copy_.read_bytes())
    check("N H PO-02 one flipped byte in a temporary copy of the golden is reported", d is not None,
          d or "comparator held")

    # D (PO-03)
    rc, out_json, err = run_cassian(["checks", "--json"])
    pairs = [
        ("(i) two in-process builds", C.render_json(build()), C.render_json(build())),
    ]
    _rc0, h0, _e0 = run_cassian(["checks", "--json"], PYTHONHASHSEED="0")
    _rc1, h1, _e1 = run_cassian(["checks", "--json"], PYTHONHASHSEED="4242")
    pairs.append(("(ii) PYTHONHASHSEED 0 vs 4242", h0, h1))
    _rc2, l0, _e2 = run_cassian(["checks", "--json"], LANG="C")
    _rc3, l1, _e3 = run_cassian(["checks", "--json"], LANG="C.UTF-8")
    pairs.append(("(iii) LANG=C vs LANG=C.UTF-8", l0, l1))
    pairs.append(("(iv) --json stdout vs the generator's catalogue_bytes()", out_json, generated))
    _rc4, v1, _e4 = run_cassian(["--verbose", "checks", "--json"])
    pairs.append(("(v) cassian --verbose checks --json vs cassian checks --json", v1, out_json))
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "c.json"
        cassian_artifacts.write_json_canonical(p, cat)
        pairs.append(("(vi) --json bytes vs write_json_canonical(tmp, catalogue)", out_json, p.read_bytes()))
    _rc5, t40, _e5 = run_cassian(["checks"], COLUMNS="40")
    _rc6, t200, _e6 = run_cassian(["checks"], COLUMNS="200")
    pairs.append(("(vii) human output, COLUMNS=40 vs 200", t40, t200))
    rc7, tpty = run_on_pty(["checks"], COLUMNS="200")
    pairs.append(("(vii) human output, pipe vs pseudo-terminal", t200, tpty))
    codes = [rc, _rc0, _rc1, _rc2, _rc3, _rc4, _rc5, _rc6, rc7]
    errs = [e for e in (err, _e0, _e1, _e2, _e3, _e4, _e5, _e6) if e]
    check("D PO-03 every run exits 0 with an empty stderr", all(c == 0 for c in codes) and not errs,
          f"exit codes {codes}" + (f"; stderr {errs[0][:80]!r}" if errs else ""))
    for desc, a, b in pairs:
        d = compare(a, b)
        check(f"D PO-03 {desc}: byte-equal", d is None and a, d or f"{sha12(a)}, {len(a)} bytes")
    golden_cat = json.loads(golden)
    human = C.render_text(golden_cat).decode("utf-8")
    bad = layout_failures(human, golden_cat)
    check("D PO-03 (viii) the human output from the golden-equal catalogue has section 6.1's layout",
          not bad and t200.decode("utf-8") == human,
          "; ".join(bad[:3]) if bad else f"{len(human.splitlines())} lines = 12 + {len(golden_cat['checks'])} "
          f"checks + {len(golden_cat['profiles'])} profiles + {len(golden_cat['commands'])} commands")
    for desc, seeded in (("drops one check line", drop_a_check_line(human)),
                         ("swaps one check line's two status lists", swap_a_status(human))):
        bad = layout_failures(seeded, golden_cat)
        check(f"N D PO-03 (viii) a seeded renderer that {desc} is reported", bool(bad) and seeded != human,
              "; ".join(bad[:2]) or "layout held")
    code = "import json; print(json.dumps(list({'zz%d' % i for i in range(64)})))"
    s0 = subprocess.run([sys.executable, "-c", code], capture_output=True, env=env(PYTHONHASHSEED="0")).stdout
    s1 = subprocess.run([sys.executable, "-c", code], capture_output=True, env=env(PYTHONHASHSEED="4242")).stdout
    d = compare(s0, s1)
    check("N D PO-03 (ii) an unsorted set-derived list printed under the same two hash seeds is reported",
          d is not None, "reported: " + d.split(":")[0] if d else "comparator held")

    # R (PO-04)
    d = compare(out_json, golden)
    check("R PO-04 on this interpreter, cassian checks --json equals the golden (CI step A runs it on each)",
          d is None and rc == 0, d or f"sha256 {sha12(out_json)}")

    # K (PO-25, REQ-S1D2-5)
    resolved = cassian_engine._audit_release_version()
    bad = []
    if cat["schema_version"] != "checks.v1":
        bad.append(f"schema_version {cat['schema_version']!r}")
    if cat["gate_release"] != resolved:
        bad.append(f"gate_release {cat['gate_release']!r} != {resolved!r}")
    if cat["provisional"] is not True:
        bad.append(f"provisional {cat['provisional']!r}")
    first_two = t200.decode("utf-8").split("\n")[:2]
    if first_two != [HEADER % resolved, C.NOTICES[0]]:
        bad.append(f"first two human lines {first_two!r}")
    check("K PO-25 markers: schema_version checks.v1, gate_release from _audit_release_version(), provisional "
          "true; the first two human lines are section 6.1's", not bad,
          "; ".join(bad) or f"gate_release {resolved}")
    injected = build(release="0.0.0")
    d = compare(C.render_json(injected), golden)
    check("N K PO-25 a build injected with release_version '0.0.0' differs in gate_release and is reported",
          d is not None and injected["gate_release"] == "0.0.0", d or "comparator held")
    declared = G.declared_release_version()
    before = sorted((p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in GOLDEN.parent.iterdir()
                    if p.is_file())
    err1 = io.StringIO()
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            G.release_version_guard(declared, declared)
            accepted = True
        except SystemExit:
            accepted = False
    with contextlib.redirect_stderr(err1):
        try:
            G.release_version_guard("0.0.0", declared)
            code_ = None
        except SystemExit as e:
            code_ = e.code
    after = sorted((p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in GOLDEN.parent.iterdir()
                   if p.is_file())
    msg = err1.getvalue()
    check("K PO-25 the generator's release_version_guard accepts the matching pair and refuses a mismatched "
          "one: exit 1, both values named, nothing written",
          accepted and code_ == 1 and "'0.0.0'" in msg and repr(declared) in msg and before == after,
          f"accepted={accepted} exit={code_} declared={declared!r} fixtures unchanged={before == after}")

    # W (PO-26)
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    bad = wiring_failures(workflow)
    check("W PO-26 CI wiring of the HS proofs (RED BY PLAN until WI-9, S1D2-S21-R2)", not bad,
          "; ".join(bad) if bad else "every HS file wired as section 14.2 WI-9 rules")
    wi9 = with_wi9(workflow)
    bad = wiring_failures(wi9)
    check("N W PO-26 the workflow with section 14.2's WI-9 steps added in memory passes", not bad,
          "; ".join(bad) or "steps A and B inserted before the project gate")
    name_a, name_b = WI9_STEP_A["name"], WI9_STEP_B["name"]
    m1 = copy.deepcopy(wi9)
    del wi9_step(m1, name_a)["if"]
    m2 = copy.deepcopy(wi9)
    wi9_step(m2, name_b)["name"] = name_b.replace(", checks_readonly_ai_free_proof.py", "")
    m3 = copy.deepcopy(wi9)
    wi9_step(m3, name_a)["run"] = WI9_STEP_A["run"].replace(" 3.12;", ";")
    m4 = copy.deepcopy(wi9)
    for job in m4["jobs"].values():
        job["steps"] = [s for s in job["steps"] if s.get("name") != name_b]
    for desc, w, needle in (("step A's `if:` key removed", m1, "without `if:"),
                            ("checks_readonly_ai_free_proof.py dropped from step B's name", m2,
                             "does not name checks_readonly_ai_free_proof.py"),
                            ("3.12 dropped from step A's loop", m3, "not run under python3.12"),
                            ("step B removed", m4, "no step runs HS-2")):
        bad = wiring_failures(w)
        check(f"N W PO-26 a copy with {desc} is reported", any(needle in b for b in bad),
              "; ".join(bad[:2]) or "wiring held")

    fails = [n for n, ok in checks if not ok]
    print("RESULT: %s (%d checks, %d failed)" % ("PASS" if not fails else "FAIL", len(checks), len(fails)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
