#!/usr/bin/env python3
"""HS-5 -- read-only and AI-free proof of `cassian checks` (Stage-1 gap item (d)(2), WI-7 script 3).

Proof obligations: PO-06 and PO-07 (handover v9-rev3 section 15.1). Requirements: REQ-S1D2-2 and -3.
Acceptance check: C-7.
Founder rulings applied: SLD-5 (`checks` is read-only: it prints the catalogue and writes nothing); the scope's
AI-free rule for the catalogue module (Doctrine section 1.12; MS "no hidden mutation"); B19 (`main()` keeps its
signature, so the in-process runs set sys.argv); S1D2-S21-R2 (WI-7's third script).

What it proves: running `cassian checks` and `cassian checks --json` opens no file for writing, creates no
directory, starts no process, opens no connection, changes no file it can see, and neither imports `openai` nor
calls into cassian_ai.py; and the catalogue module does not import the AI module, the engine or a runtime adapter.

Legs
  R  PO-06  in process, with sys.argv set to ["cassian", "checks"] and then ["cassian", "checks", "--json"],
            cassian_cli.main() makes no call to any of: open / io.open in a write mode (w, a, x or +), os.mkdir,
            os.makedirs, Path.write_text, Path.write_bytes, Path.mkdir, subprocess.run, subprocess.Popen,
            socket.socket.connect. Each patched API records the call and stops it.
  S  PO-06  the sha256 snapshot of a temporary cwd, of BASE_DIR (the tree under test, without .git and
            __pycache__) and of BASE_DIR/labs is unchanged around a subprocess run of
            `python3 -B <tree>/src/cassian.py checks --json` from that cwd with PYTHONDONTWRITEBYTECODE=1.
  A  PO-07  (a) a subprocess driver run as `python3 -B -c ...` with PYTHONDONTWRITEBYTECODE=1 puts src/ on
            sys.path, sets sys.argv to ["cassian", "checks", "--json"], imports cassian_cli, calls main() and
            reports on stderr whether "openai" is in sys.modules: it must not be; (b) in process, with
            sys.setprofile installed after cassian_cli is imported and before main() is called, no `call` event
            has a frame whose file is cassian_ai.py; (c) the AST of src/cassian_catalogue.py imports none of
            cassian_ai, openai, cassian_engine, cassian_runtime_container, cassian_runtime_vm.
  N  MUTANTS each leg above is shown capable of failing: for R, a build_catalogue wrapped to make one call of each
            patched API is caught by that API (nine seeds); for S, a run that writes one file into the cwd is
            caught; for A, (a) the same driver with a stand-in `openai` module placed in sys.modules is
            reported, (b) a build_catalogue wrapped to call cassian_ai._ai_sanitize_error is caught by the
            profile, (c) a doctored copy of the catalogue source with `import cassian_ai` is reported.

Coverage limits (PBE-P2-8 / PBE-P2-14), stated so a PASS is not read as more than it is:
  1. R patches these APIs by name in this interpreter: a write through another API (os.open, os.write,
     shutil, a C extension) is not seen. Read-mode opens pass through.
  2. S compares the files it can see: the cwd, the tree under test and its labs/. A write elsewhere (a home
     directory, /tmp outside the cwd) is not seen; the interpreter's bytecode cache is excluded by
     PYTHONDONTWRITEBYTECODE=1 and by skipping __pycache__, so that it is not counted against REQ-S1D2-2.
  3. A (b) sees Python-level calls only (sys.setprofile); A (c) reads `import` and `from ... import` statements,
     not an import made through importlib or __import__.

usage: PYTHONPATH=src python tests/checks_readonly_ai_free_proof.py   (from the repo root; writes nothing in it)
"""
import ast
import builtins
import contextlib
import hashlib
import io
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import cassian_catalogue as C  # noqa: E402
import cassian_cli  # noqa: E402
import cassian_common  # noqa: E402

FORBIDDEN_IMPORTS = ("cassian_ai", "openai", "cassian_engine", "cassian_runtime_container", "cassian_runtime_vm")
ARGVS = (["cassian", "checks"], ["cassian", "checks", "--json"])

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" | {detail}" if detail else ""), flush=True)


class Stopped(BaseException):
    """Raised by a patched API so that a recorded call has no effect; BaseException passes main()'s handler."""


# ---------------------------------------------------------------------------------------------------------------
# R: patched APIs
# ---------------------------------------------------------------------------------------------------------------

def write_mode(mode):
    return isinstance(mode, str) and bool(set(mode) & set("wax+"))


@contextlib.contextmanager
def guarded(calls):
    """Patch each listed API to record its call in `calls` and stop it; read-mode opens pass through."""
    real_open, real_io_open = builtins.open, io.open

    def stop(name):
        def f(*_a, **_k):
            calls.append(name)
            raise Stopped(name)
        return f

    def make_open(real, name):
        def f(file, mode="r", *a, **k):
            if write_mode(mode):
                calls.append(f"{name}(..., {mode!r})")
                raise Stopped(name)
            return real(file, mode, *a, **k)
        return f

    patches = [
        (builtins, "open", make_open(real_open, "open")), (io, "open", make_open(real_io_open, "io.open")),
        (os, "mkdir", stop("os.mkdir")), (os, "makedirs", stop("os.makedirs")),
        (pathlib.Path, "write_text", stop("Path.write_text")), (pathlib.Path, "write_bytes", stop("Path.write_bytes")),
        (pathlib.Path, "mkdir", stop("Path.mkdir")),
        (subprocess, "run", stop("subprocess.run")), (subprocess, "Popen", stop("subprocess.Popen")),
        (socket.socket, "connect", stop("socket.socket.connect")),
    ]
    saved = [(obj, name, getattr(obj, name)) for obj, name, _f in patches]
    try:
        for obj, name, f in patches:
            setattr(obj, name, f)
        yield
    finally:
        for obj, name, old in saved:
            setattr(obj, name, old)


def run_main(argv):
    """cassian_cli.main() in process with sys.argv = argv: (exit code, stdout bytes, stderr text)."""
    out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    err = io.StringIO()
    saved = sys.argv
    sys.argv = list(argv)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                cassian_cli.main()
                rc = 0
            except SystemExit as e:
                rc = e.code
            except Stopped as e:
                rc = f"stopped at {e}"
        out.flush()
        return rc, out.buffer.getvalue(), err.getvalue()
    finally:
        sys.argv = saved


@contextlib.contextmanager
def seeded_build(action):
    """build_catalogue wrapped to perform `action` once before building."""
    real = C.build_catalogue

    def wrapped(*a, **k):
        action()
        return real(*a, **k)

    C.build_catalogue = wrapped
    try:
        yield
    finally:
        C.build_catalogue = real


def seeds(tmp):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return sock, (
        ("open", lambda: open(os.path.join(tmp, "zz"), "w")),
        ("io.open", lambda: io.open(os.path.join(tmp, "zz"), "a")),
        ("os.mkdir", lambda: os.mkdir(os.path.join(tmp, "zz_d"))),
        ("os.makedirs", lambda: os.makedirs(os.path.join(tmp, "zz_e", "f"))),
        ("Path.write_text", lambda: Path(tmp, "zz_t").write_text("x")),
        ("Path.write_bytes", lambda: Path(tmp, "zz_b").write_bytes(b"x")),
        ("Path.mkdir", lambda: Path(tmp, "zz_m").mkdir()),
        ("subprocess.run", lambda: subprocess.run(["true"])),
        ("subprocess.Popen", lambda: subprocess.Popen(["true"])),
        ("socket.socket.connect", lambda: sock.connect(("127.0.0.1", 9))),
    )


# ---------------------------------------------------------------------------------------------------------------
# S: snapshots
# ---------------------------------------------------------------------------------------------------------------

def snapshot(root):
    out = {}
    root = Path(root)
    if not root.exists():
        return out
    for d, dn, fs in os.walk(root):
        dn[:] = sorted(x for x in dn if x not in (".git", "__pycache__"))
        for f in sorted(fs):
            p = Path(d, f)
            try:
                out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                out[str(p.relative_to(root))] = "?"
    return out


def env():
    e = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    e.pop("PYTHONPATH", None)
    return e


def snapshot_run(argv_tail, extra_code=None):
    """Snapshots of the cwd, BASE_DIR and BASE_DIR/labs around one subprocess run: (rc, changed parts)."""
    base = Path(cassian_common.BASE_DIR)
    with tempfile.TemporaryDirectory() as td:
        before = (snapshot(td), snapshot(base), snapshot(base / "labs"))
        if extra_code is None:
            cmd = [sys.executable, "-B", str(SRC / "cassian.py"), *argv_tail]
        else:
            cmd = [sys.executable, "-B", "-c", extra_code]
        r = subprocess.run(cmd, cwd=td, capture_output=True, timeout=300, env=env())
        after = (snapshot(td), snapshot(base), snapshot(base / "labs"))
    changed = [name for name, b, a in zip(("cwd", "BASE_DIR", "BASE_DIR/labs"), before, after) if b != a]
    return r.returncode, changed, len(before[1])


# ---------------------------------------------------------------------------------------------------------------
# A: AI-free
# ---------------------------------------------------------------------------------------------------------------

DRIVER = (
    "import sys\n"
    "sys.path.insert(0, {src!r})\n"
    "sys.argv = ['cassian', 'checks', '--json']\n"
    "import cassian_cli\n"
    "try:\n"
    "    cassian_cli.main()\n"
    "finally:\n"
    "{extra}"
    "    sys.stderr.write('OPENAI_LOADED=%s\\n' % ('openai' in sys.modules))\n"
)


def driver_report(extra=""):
    code = DRIVER.format(src=str(SRC), extra=extra)
    with tempfile.TemporaryDirectory() as td:
        r = subprocess.run([sys.executable, "-B", "-c", code], cwd=td, capture_output=True, text=True,
                           timeout=300, env=env())
    lines = [ln for ln in r.stderr.splitlines() if ln.startswith("OPENAI_LOADED=")]
    return r.returncode, (lines[-1] if lines else None), len(r.stdout)


def profiled(argv):
    """Calls into cassian_ai.py while main() runs with sys.argv = argv, profile installed after the import."""
    hits = []

    def prof(frame, event, _arg):
        if event == "call" and os.path.basename(frame.f_code.co_filename) == "cassian_ai.py":
            hits.append(frame.f_code.co_name)

    sys.setprofile(prof)
    try:
        rc, _out, _err = run_main(argv)
    finally:
        sys.setprofile(None)
    return rc, sorted(set(hits))


def forbidden_imports(source):
    found = []
    for n in ast.walk(ast.parse(source)):
        if isinstance(n, ast.Import):
            found += [a.name.split(".")[0] for a in n.names]
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            found.append(n.module.split(".")[0])
    return sorted(set(found) & set(FORBIDDEN_IMPORTS))


# ---------------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------------

def main():
    # R (PO-06)
    for argv in ARGVS:
        calls = []
        with guarded(calls):
            rc, out, err = run_main(argv)
        check(f"R PO-06 `{' '.join(argv[1:])}` in process: no write, mkdir, process or connect call",
              not calls and rc == 0 and out and not err,
              f"calls={calls}" if calls else f"exit {rc}, {len(out)} bytes on stdout, stderr empty={not err}")
    with tempfile.TemporaryDirectory() as td:
        sock, seeded = seeds(td)
        try:
            for name, action in seeded:
                calls = []
                with seeded_build(action), guarded(calls):
                    rc, _out, _err = run_main(ARGVS[1])
                caught = len(calls) == 1 and calls[0].startswith(name) and str(rc).startswith("stopped at")
                check(f"N R PO-06 a build_catalogue seeded with one {name} call is caught", caught,
                      f"calls={calls}")
        finally:
            sock.close()
        left = sorted(os.listdir(td))
    check("N R PO-06 the stopped seeds wrote nothing", not left, f"left={left}")

    # S (PO-06)
    rc, changed, nfiles = snapshot_run(["checks", "--json"])
    check("S PO-06 `python3 -B src/cassian.py checks --json` from a temp cwd changes no file in the cwd, BASE_DIR "
          "or BASE_DIR/labs", rc == 0 and not changed,
          f"changed={changed}" if changed else f"exit {rc}; {nfiles} files snapshotted under BASE_DIR")
    seed = "open('zz_written_by_hs5', 'w').write('x')\n"
    rc, changed, _n = snapshot_run([], extra_code=seed)
    check("N S PO-06 a run that writes one file into the cwd is caught by the snapshot", changed == ["cwd"],
          f"changed={changed}")

    # A (PO-07)
    rc, line, nout = driver_report()
    check("A PO-07 (a) the subprocess driver reports openai not in sys.modules after main()",
          rc == 0 and line == "OPENAI_LOADED=False" and nout > 0, f"exit {rc}, {line}, {nout} chars on stdout")
    rc, line, _n = driver_report(extra="    import types; sys.modules['openai'] = types.ModuleType('openai')\n")
    check("N A PO-07 (a) the same driver with a stand-in openai module in sys.modules is reported",
          line == "OPENAI_LOADED=True", f"{line}")
    for argv in ARGVS:
        rc, hits = profiled(argv)
        check(f"A PO-07 (b) `{' '.join(argv[1:])}` in process, profiled after the import: no call into "
              f"cassian_ai.py", rc == 0 and not hits, f"calls={hits}" if hits else f"exit {rc}")
    import cassian_ai  # noqa: E402  (imported by cassian_cli already; named here for the seed)
    with seeded_build(lambda: cassian_ai._ai_sanitize_error("x")):
        rc, hits = profiled(ARGVS[1])
    check("N A PO-07 (b) a build_catalogue seeded with a call to cassian_ai._ai_sanitize_error is caught",
          "_ai_sanitize_error" in hits, f"calls={hits}")
    source = (SRC / "cassian_catalogue.py").read_text(encoding="utf-8")
    found = forbidden_imports(source)
    check("A PO-07 (c) src/cassian_catalogue.py imports none of " + ", ".join(FORBIDDEN_IMPORTS), not found,
          f"found={found}" if found else "AST import statements read")
    doctored = source.replace("\nimport cassian_common\n", "\nimport cassian_common\nimport cassian_ai\n", 1)
    found = forbidden_imports(doctored) if doctored != source else ["anchor not found"]
    check("N A PO-07 (c) a doctored copy of the catalogue source importing cassian_ai is reported",
          found == ["cassian_ai"], f"found={found}")

    fails = [n for n, ok in checks if not ok]
    print("RESULT: %s (%d checks, %d failed)" % ("PASS" if not fails else "FAIL", len(checks), len(fails)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
