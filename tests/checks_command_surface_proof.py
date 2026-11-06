#!/usr/bin/env python3
"""HS-4 -- command-surface proof (Stage-1 gap item (d)(2), WI-7 script 1).

Proof obligations: PO-05, PO-18, PO-19, PO-20, PO-21 and PO-27 (handover v9-rev3 section 15.1).
Requirements: REQ-S1D2-1, -13, -14, -23 to -26, -30, -32 and -34. Acceptance check: C-6.
Founder rulings applied: SLD-4, SLD-5, SLD-29, SLD-30 and the PBR-1 ruling (the label table of section 7.5;
`ai` carries the exception marker); HALT-1 (a) (no "supported" vocabulary; the no-declaration notice);
HALT-2 (`replay`'s entry); SLD-15 (no `--verbose` on `checks`); LD-S1D2-1 (construction failures exit 1 with
`ERROR: checks: <template>`); S1D2-S21-R1 (WI-10's documents landed before this proof).

What it proves: the `checks` command's surface -- the effect labels it assigns to every command, its
construction failures, its exit codes, its option strings, its vocabulary and the documents that describe it --
is exactly what the handover rules. The live parser is `cassian_cli.build_parser()`; the label table is the
catalogue's; nothing under src/ is changed on disk.

Legs
  A   ASSIGNMENT  the catalogue's `commands` equal section 7.5's table, held below as EXPECTED_COMMANDS
                  (command, labels in Q-B order, each label's reason, or the exception's reason); 21 leaves.
  E   E1-E7       each construction failure, built in memory, makes build_catalogue exit 1 with nothing on
                  stdout and exactly `ERROR: checks: <section 6.6 template>` on stderr: an unlabelled parser leaf
                  (E1); a table entry the parser lacks (E2); an empty set (E3); {read-only, destructive} (E4);
                  the label 'safe' (E5); the exception marker on `exec` (E6); a missing label reason and a
                  missing exception reason (E7). The unmodified build exits 0 (the control).
  S   ASSIST      the case-sensitive string `Cassian Assist` occurs in no file under src/, the golden, the
                  `checks` help, the human output, or the four documents WI-10 edited or created.
  D   DOCS        `docs/cli-reference-v1.md` section 9 names every option string the live `checks` subparser
                  registers; the cheatsheet's Environment block holds the line `cassian checks [--json]`;
                  `mkdocs.yml`'s nav holds `  - Capability Catalogue: capability-catalogue.md`.
  X   EXIT        `cassian checks` and `cassian checks --json` exit 0; `--bogus`, an extra argument and
                  `--verbose` exit 2 (each run from an empty temporary directory).
  V   VOCABULARY  `\\b(un)?supported\\b`, case-insensitive, matches none of: the catalogue bytes, the `checks`
                  help, the human output, the page, section 9, the cheatsheet line. N1 is in the catalogue,
                  the human output and the page; N2 is in the catalogue.
  O   OPTIONS     the live `checks` subparser's option strings are exactly {-h, --help, --json}; it has no
                  positional argument.
  N   MUTANTS     each leg above is shown capable of failing: a seeded `Cassian Assist` in a temporary copy (S);
                  a seeded option on a temporary parser, a temporary mkdocs.yml without the nav line and a
                  temporary cheatsheet without the line (D); a seeded `not supported` in a temporary catalogue
                  reason and a temporary page without N1 (V); a temporary subparser with `--verbose` (O); one
                  expected label changed in a copy of EXPECTED_COMMANDS (A); one expected exit code changed (X).
                  Leg E's own cases are its negative legs; its control is the clean build.

Coverage limits (PBE-P2-8 / PBE-P2-14), stated so a PASS is not read as more than it is:
  1. Leg A holds section 7.5's table in this file. It binds the catalogue to that table; it does not bind the
     table's reasons to the code facts they cite (that is PO-22, HS-2).
  2. Legs A, E, D and O enumerate the live parser through argparse internals (`_actions`, the subparsers
     action's `choices`). A leaf reached another way is not seen (PBE-P2-14).
  3. Leg S matches the exact, case-sensitive string only: a paraphrase, a split across lines, or another
     spelling is not caught (PBE-P2-8). It reads the files under src/ as text, whatever their kind.
  4. Leg V's pattern does not match `techsupport` (a word-boundary pattern) and does not catch a paraphrase
     (PBE-P2-8). Section 9 and the cheatsheet line are scanned alone, because other parts of those files may use
     the word legitimately. N1 is matched as one line of text after the page's `> ` quote marker is removed.
  5. Leg D checks that each option string appears in section 9, not what the section says about it; the strict
     docs build is section 18 C-24's, run locally, because no PR-time CI builds the docs (section 14.3).
  6. Leg X runs `src/cassian.py` with this interpreter from an empty temporary directory, with
     PYTHONDONTWRITEBYTECODE=1; the installed entry point is PO-08's (tests/wheel_import_proof.py).

usage: PYTHONPATH=src python tests/checks_command_surface_proof.py   (from the repo root; writes nothing in it)
"""
import argparse
import contextlib
import copy
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import cassian_catalogue as C  # noqa: E402
import cassian_cli  # noqa: E402
import cassian_common as cc  # noqa: E402

GOLDEN = ROOT / "tests" / "fixtures" / "checks_catalogue.json"
PAGE = ROOT / "docs" / "capability-catalogue.md"
CLI_REF = ROOT / "docs" / "cli-reference-v1.md"
CHEATSHEET = ROOT / "docs" / "cheatsheet.md"
MKDOCS = ROOT / "mkdocs.yml"
WI10_DOCS = (PAGE, CLI_REF, CHEATSHEET, MKDOCS)

ASSIST = "Cassian Assist"
SUPPORTED = re.compile(r"\b(un)?supported\b", re.IGNORECASE)
NAV_LINE = "  - Capability Catalogue: capability-catalogue.md"
CHEAT_LINE = "cassian checks [--json]"
SECTION_9 = "## 9) Capability catalogue"
CHECKS_OPTIONS = {"-h", "--help", "--json"}

# Section 6.6 (N1, N2), verbatim.
N1 = ("Status values report what this release's code implements for each check on each node type. This catalogue "
      "makes no NOS-support declaration and is not a qualification claim.")
N2 = "The shape of this catalogue is provisional: no stability promise is made for it, and later releases may change it."

# Section 7.5's label assignment, verbatim (21 leaves). A tuple of (label, reason) in Q-B order, or, for the
# exception marker, its reason as a string.
EXPECTED_COMMANDS = {
    "adapt ansible": (("advisory", "writes adapter output files (default artifacts/adapters/)"),),
    "adapt terraform": (("advisory", "writes adapter output files (default artifacts/adapters/)"),),
    "ai": "writes no file; with --online, sends the question and an evidence package to an AI endpoint, which no "
          "effect label covers",
    "checks": (("read-only", "prints this catalogue; writes nothing"),),
    "cleanup": (("destructive", "with --yes, destroys Cassian-owned labs found under labs/"),),
    "collect": (("advisory", "writes collected lab evidence under labs/clab-<lab>/artifacts/"),),
    "destroy": (("destructive", "destroys a lab runtime; with --purge-artifacts, deletes its artifacts"),),
    "doctor": (("read-only", "reports environment readiness; writes nothing"),),
    "down": (("destructive", "destroys a deployed lab's runtime"),),
    "exec": (("lab-mutating", "runs a command inside a lab node"),),
    "gen": (("lab-mutating", "rewrites in place the config files a deployed lab of the same name bind-mounts"),),
    "import": "writes an authoritative declaration pair to a path the caller names",
    "preflight": (("advisory", "writes a preflight report (default artifacts/preflight/preflight.json)"),),
    "replay": (("lab-mutating", "deploys a lab from prior artifacts"),
               ("destructive", "replaces an existing lab of the same derived replay name (reconfigure)"),
               ("authoritative", "with --gate, runs test's gate path (cmd_test, _report_authority gate)")),
    "run": (("lab-mutating", "builds, tests and tears down a lab"),
            ("destructive", "with --reconfigure, destroys the existing lab first")),
    "status": (("read-only", "reads lab state with show commands; writes nothing"),),
    "test": (("lab-mutating", "deploys and tears down a clean lab"),
             ("destructive", "replaces an existing lab of the same name (reconfigure)"),
             ("authoritative", "produces the deploy/no-deploy verdict")),
    "up": (("lab-mutating", "deploys a lab"),
           ("destructive", "with --reconfigure, destroys the existing lab first")),
    "validate": (("advisory", "writes a coverage file under labs/"),),
    "validate-contrib": (("read-only", "structural check of contrib content; writes nothing"),),
    "vty": (("lab-mutating", "runs a vty command inside a lab node"),),
}

# Section 6.6's E1-E7 templates, with the values each case below supplies.
LABELS = "read-only, lab-mutating, destructive, authoritative, advisory"
E_TEMPLATES = {
    "E1": "command 'zz-synthetic' has no effect-label entry; add one to the label table in src/cassian_catalogue.py "
          "and regenerate the golden (scripts/regenerate_checks_catalogue.py)",
    "E2": "the label table names 'zz-stale', which the CLI parser does not register; remove the entry and "
          "regenerate the golden",
    "E3": "command 'doctor' has an empty effect-label set; only 'import' and 'ai' carry the exception marker",
    "E4": "command 'doctor' combines 'read-only' with 'destructive'; read-only and advisory never combine with each "
          "other or with lab-mutating, destructive or authoritative",
    "E5": "command 'doctor' carries 'safe', which is not one of: " + LABELS,
    "E6": "command 'exec' carries the exception marker; only 'import' and 'ai' may",
    "E7-label": "command 'doctor' has no reason for 'read-only'",
    "E7-exception": "command 'import' has no reason for 'exception'",
}
EXPECTED_EXITS = (((), 0), (("--json",), 0), (("--bogus",), 2), (("extra",), 2), (("--verbose",), 2))

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" | {detail}" if detail else ""), flush=True)


def checks_subparser(parser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices["checks"]
    raise SystemExit("no subparsers action on the parser")


def build(parser, labels=None):
    """build_catalogue with an optional label table; returns (exit code, stdout, stderr)."""
    saved = C.COMMAND_LABELS
    out, err = io.StringIO(), io.StringIO()
    prev = cc._QUIET_DIE
    cc._QUIET_DIE = False  # as `cassian checks`: die() prints ERROR: on stderr and exits with the code
    try:
        if labels is not None:
            C.COMMAND_LABELS = labels
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            C.build_catalogue(parser, release_version="0+hs4")
        return 0, out.getvalue(), err.getvalue()
    except SystemExit as e:
        return e.code, out.getvalue(), err.getvalue()
    finally:
        C.COMMAND_LABELS = saved
        cc._QUIET_DIE = prev


def as_table(commands):
    out = {}
    for c in commands:
        if c["exception"] is not None:
            out[c["command"]] = c["exception"]
        else:
            out[c["command"]] = tuple((e["label"], e["reason"]) for e in c["effects"])
    return out


# ---------------------------------------------------------------------------------------------------------------
# Legs. Each returns a list of failure descriptions; empty means the leg holds.
# ---------------------------------------------------------------------------------------------------------------

def leg_assignment(catalogue, expected):
    got = as_table(catalogue["commands"])
    bad = [f"{k}: catalogue {got.get(k)!r} != expected {expected.get(k)!r}"
           for k in sorted(set(got) | set(expected)) if got.get(k) != expected.get(k)]
    if len(catalogue["commands"]) != len(expected):
        bad.append(f"{len(catalogue['commands'])} commands, expected {len(expected)}")
    return bad


def e_cases():
    def unlabelled_leaf():
        parser = cassian_cli.build_parser()
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                action.add_parser("zz-synthetic").set_defaults(func=lambda a: None)
        return parser, None

    def with_labels(**changes):
        def make():
            labels = dict(C.COMMAND_LABELS)
            for k, v in changes.items():
                labels[k.replace("_", "-")] = v
            return cassian_cli.build_parser(), labels
        return make

    return (
        ("E1", unlabelled_leaf),
        ("E2", with_labels(zz_stale=(("advisory", "x"),))),
        ("E3", with_labels(doctor=())),
        ("E4", with_labels(doctor=(("read-only", "x"), ("destructive", "x")))),
        ("E5", with_labels(doctor=(("safe", "x"),))),
        ("E6", with_labels(exec="x")),
        ("E7-label", with_labels(doctor=(("read-only", ""),))),
        ("E7-exception", with_labels(**{"import": ""})),
    )


def leg_e():
    bad = []
    rc, out, err = build(cassian_cli.build_parser())
    if rc != 0 or not out == "" or err:
        bad.append(f"control: clean build gave rc={rc} stdout={len(out)}B stderr={err.strip()!r}")
    for name, make in e_cases():
        parser, labels = make()
        rc, out, err = build(parser, labels)
        want = f"ERROR: checks: {E_TEMPLATES[name]}\n"
        if rc != 1 or out != "" or err != want:
            bad.append(f"{name}: rc={rc} stdout={len(out)}B stderr={err!r}")
    return bad


def assist_hits(texts):
    return [name for name, text in texts if ASSIST in text]


def surface_texts(run_results):
    texts = [(str(p.relative_to(ROOT)), p.read_text(encoding="utf-8", errors="replace"))
             for p in sorted(SRC.rglob("*")) if p.is_file() and "__pycache__" not in p.parts]
    texts.append((str(GOLDEN.relative_to(ROOT)), GOLDEN.read_text(encoding="utf-8")))
    texts.append(("`checks --help` stdout", run_results[("--help",)][1]))
    texts.append(("`checks` stdout", run_results[()][1]))
    texts += [(str(p.relative_to(ROOT)), p.read_text(encoding="utf-8")) for p in WI10_DOCS]
    return texts


def section_9(text):
    lines = text.splitlines()
    starts = [i for i, ln in enumerate(lines) if ln.strip() == SECTION_9]
    if len(starts) != 1:
        return None
    end = next((j for j in range(starts[0] + 1, len(lines)) if lines[j].strip() == "---"), len(lines))
    return "\n".join(lines[starts[0]:end])


def environment_block(text):
    lines = text.splitlines()
    starts = [i for i, ln in enumerate(lines) if ln.strip() == "### Environment"]
    if len(starts) != 1:
        return None
    fence = [j for j in range(starts[0] + 1, len(lines)) if lines[j].startswith("```")][:2]
    if len(fence) != 2:
        return None
    return [ln.strip() for ln in lines[fence[0] + 1:fence[1]]]


def option_strings(subparser):
    return {s for a in subparser._actions for s in a.option_strings}


def leg_docs(subparser, cli_ref, cheatsheet, mkdocs):
    bad = []
    sec = section_9(cli_ref)
    if sec is None:
        bad.append(f"cli-reference: '{SECTION_9}' not found exactly once")
    else:
        for opt in sorted(option_strings(subparser)):
            if not re.search(r"(?<![\w-])" + re.escape(opt) + r"(?![\w-])", sec):
                bad.append(f"cli-reference section 9 lacks the option string {opt}")
    block = environment_block(cheatsheet)
    if block is None or CHEAT_LINE not in block:
        bad.append(f"cheatsheet Environment block lacks `{CHEAT_LINE}`")
    if NAV_LINE not in mkdocs.splitlines():
        bad.append(f"mkdocs.yml nav lacks `{NAV_LINE.strip()}`")
    return bad


def run_checks(args, cwd):
    r = subprocess.run([sys.executable, "-B", str(SRC / "cassian.py"), "checks", *args], cwd=cwd,
                       capture_output=True, text=True, timeout=300,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", COLUMNS="200"))
    return r.returncode, r.stdout, r.stderr


def leg_exit(results, expected):
    return [f"`cassian checks {' '.join(args)}` exit {results[args][0]}, expected {rc}"
            for args, rc in expected if results[args][0] != rc]


def page_lines(text):
    return [ln[2:].strip() if ln.startswith("> ") else ln.strip() for ln in text.splitlines()]


def leg_vocabulary(catalogue_bytes, help_text, human_text, page, cli_ref, cheatsheet):
    bad = []
    sec = section_9(cli_ref) or ""
    block = environment_block(cheatsheet) or []
    line = next((ln for ln in block if ln == CHEAT_LINE), "")
    for name, text in (("catalogue bytes", catalogue_bytes), ("checks --help", help_text),
                       ("human output", human_text), ("the page", page), ("cli-reference section 9", sec),
                       ("the cheatsheet line", line)):
        m = SUPPORTED.search(text)
        if m:
            bad.append(f"{name}: matches {m.group(0)!r}")
    try:
        notices = json.loads(catalogue_bytes).get("notices") or []
    except ValueError:
        notices = []
    if N1 not in notices:
        bad.append("N1 absent from the catalogue")
    if N2 not in notices:
        bad.append("N2 absent from the catalogue")
    if N1 not in human_text.splitlines():
        bad.append("N1 absent from the human output")
    if N1 not in page_lines(page):
        bad.append("N1 absent from the page")
    return bad


def leg_options(subparser):
    bad = []
    opts = option_strings(subparser)
    if opts != CHECKS_OPTIONS:
        bad.append(f"option strings {sorted(opts)}, expected {sorted(CHECKS_OPTIONS)}")
    positionals = [a.dest for a in subparser._actions if not a.option_strings]
    if positionals:
        bad.append(f"positional arguments {positionals}")
    return bad


def main():
    parser = cassian_cli.build_parser()
    sub = checks_subparser(parser)
    catalogue = C.build_catalogue(parser, release_version="0+hs4")
    cli_ref = CLI_REF.read_text(encoding="utf-8")
    cheatsheet = CHEATSHEET.read_text(encoding="utf-8")
    mkdocs = MKDOCS.read_text(encoding="utf-8")
    page = PAGE.read_text(encoding="utf-8")

    def report(name, bad, ok_detail):
        check(name, not bad, ("; ".join(bad[:4]) + (f" (+{len(bad) - 4} more)" if len(bad) > 4 else "")) if bad
              else ok_detail)

    report("A assignment: the catalogue's commands equal section 7.5's table (21 leaves)",
           leg_assignment(catalogue, EXPECTED_COMMANDS), "%d commands" % len(catalogue["commands"]))
    report("E construction failures E1-E7: exit 1, empty stdout, the section 6.6 message; the clean build exits 0",
           leg_e(), "%d cases and the control" % len(e_cases()))

    with tempfile.TemporaryDirectory() as td:
        results = {args: run_checks(args, td) for args in [a for a, _rc in EXPECTED_EXITS] + [("--help",)]}
        left = sorted(os.listdir(td))
    report("X exit codes: checks 0, --json 0, --bogus 2, extra 2, --verbose 2",
           leg_exit(results, EXPECTED_EXITS) + ([f"files left in the temporary cwd: {left}"] if left else []),
           ", ".join(f"{' '.join(a) or '(none)'}={results[a][0]}" for a, _rc in EXPECTED_EXITS))

    texts = surface_texts(results)
    hits = assist_hits(texts)
    check("S no `Cassian Assist` in src/, the golden, checks help and human output, the four WI-10 documents",
          not hits, ("found in: " + ", ".join(hits)) if hits else "%d texts scanned" % len(texts))
    report("D docs: cli-reference section 9 names every checks option; cheatsheet line; mkdocs nav line",
           leg_docs(sub, cli_ref, cheatsheet, mkdocs), "options %s" % sorted(option_strings(sub)))
    report("V vocabulary: no (un)supported on any shipped surface; N1 and N2 present",
           leg_vocabulary(results[("--json",)][1], results[("--help",)][1], results[()][1], page, cli_ref,
                          cheatsheet), "6 surfaces scanned; N1 in 3 places, N2 in the catalogue")
    report("O options: checks registers exactly -h, --help, --json and no positional", leg_options(sub),
           "%s" % sorted(option_strings(sub)))

    # Leg N: every leg above can fail.
    seeded = [(name, text.replace("\n", "\nCassian Assist\n", 1) if name.endswith(".md") else text + ASSIST)
              for name, text in texts if name == "docs/capability-catalogue.md"]
    check("N S: a seeded `Cassian Assist` in a temporary copy of the page is found", assist_hits(seeded) == [seeded[0][0]],
          "found in %s" % assist_hits(seeded))

    tparser = cassian_cli.build_parser()
    tsub = checks_subparser(tparser)
    tsub.add_argument("--zz-seeded", action="store_true")
    bad = leg_docs(tsub, cli_ref, cheatsheet, mkdocs)
    check("N D: a seeded option on a temporary parser is reported missing from section 9",
          bad == ["cli-reference section 9 lacks the option string --zz-seeded"], "; ".join(bad) or "leg held")
    bad = leg_docs(sub, cli_ref, cheatsheet, "\n".join(ln for ln in mkdocs.splitlines() if ln != NAV_LINE))
    check("N D: a temporary mkdocs.yml without the nav line is reported", len(bad) == 1 and "mkdocs" in bad[0],
          "; ".join(bad) or "leg held")
    bad = leg_docs(sub, cli_ref, "\n".join(ln for ln in cheatsheet.splitlines() if ln.strip() != CHEAT_LINE), mkdocs)
    check("N D: a temporary cheatsheet without the line is reported", len(bad) == 1 and "cheatsheet" in bad[0],
          "; ".join(bad) or "leg held")

    mcat = json.loads(results[("--json",)][1])
    cell = next(c for c in mcat["checks"] for t in c["status"].values() if t["reason"])
    reason_cell = next(t for t in cell["status"].values() if t["reason"])
    reason_cell["reason"] = reason_cell["reason"] + " (not supported)"
    bad = leg_vocabulary(json.dumps(mcat), results[("--help",)][1], results[()][1], page, cli_ref, cheatsheet)
    check("N V: a seeded `not supported` in a temporary catalogue reason is found",
          len(bad) == 1 and bad[0].startswith("catalogue bytes"), "; ".join(bad) or "leg held")
    bad = leg_vocabulary(results[("--json",)][1], results[("--help",)][1], results[()][1],
                         "\n".join(ln for ln in page.splitlines() if N1 not in ln), cli_ref, cheatsheet)
    check("N V: a temporary page without N1 is reported", bad == ["N1 absent from the page"],
          "; ".join(bad) or "leg held")
    check("N V: the pattern does not match `techsupport` (coverage limit 4)",
          SUPPORTED.search("show techsupport") is None and SUPPORTED.search("is not supported") is not None, "")

    vparser = cassian_cli.build_parser()
    checks_subparser(vparser).add_argument("--verbose", action="store_true")
    bad = leg_options(checks_subparser(vparser))
    check("N O: a temporary checks subparser with --verbose is reported", len(bad) == 1 and "--verbose" in bad[0],
          "; ".join(bad) or "leg held")

    wrong = copy.deepcopy(EXPECTED_COMMANDS)
    wrong["doctor"] = (("advisory", "reports environment readiness; writes nothing"),)
    bad = leg_assignment(catalogue, wrong)
    check("N A: one expected label changed in a copy of the table is reported",
          len(bad) == 1 and bad[0].startswith("doctor:"), "; ".join(bad) or "leg held")
    bad = leg_exit(results, ((("--json",), 2),))
    check("N X: one expected exit code changed is reported", len(bad) == 1, "; ".join(bad) or "leg held")

    fails = [n for n, ok in checks if not ok]
    print("RESULT: %s (%d checks, %d failed)" % ("PASS" if not fails else "FAIL", len(checks), len(fails)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
