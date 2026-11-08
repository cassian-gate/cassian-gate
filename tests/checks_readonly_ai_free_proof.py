#!/usr/bin/env python3
"""HS-5 -- read-only and AI-free proof of `cassian checks` (Stage-1 gap item (d)(2), WI-7 script 3).

Proof obligations: PO-06 and PO-07 (handover v9-rev3 section 15.1). Requirements: REQ-S1D2-2 and -3.
Acceptance check: C-7.
Founder rulings applied: SLD-5 (`checks` is read-only: it prints the catalogue and writes nothing); the scope's
AI-free rule for the catalogue module (Doctrine section 1.12; MS "no hidden mutation"); B19 (`main()` keeps its
signature, so the in-process runs set sys.argv); S1D2-S21-R2 (WI-7's third script); LC-1 (closure record
section 1.1, 2026-11-08: S's baseline is taken on a fresh copy made before any in-process run of the code, and
I-7b's repeatable write is a negative leg).

What it proves: running `cassian checks` and `cassian checks --json` opens no file for writing, creates no
directory, starts no process, opens no connection, changes no file it can see, and neither imports `openai` nor
calls into cassian_ai.py; and the catalogue module does not import the AI module, the engine or a runtime adapter.

Legs
  R  PO-06  in process, with sys.argv set to ["cassian", "checks"] and then ["cassian", "checks", "--json"],
            cassian_cli.main() makes no call to any of: open / io.open in a write mode (w, a, x or +), os.mkdir,
            os.makedirs, Path.write_text, Path.write_bytes, Path.mkdir, subprocess.run, subprocess.Popen,
            socket.socket.connect. Each patched API records the call and stops it.
  S  PO-06  before any code of the product runs in this process (before its modules are imported), the
            tracked files of the tree under test (`git ls-files`) are copied, with their working-tree bytes, to a
            pristine copy outside the tree. Each S run is on its own fresh copy of that pristine copy: the sha256
            snapshot of a temporary cwd, of BASE_DIR (that fresh copy, without __pycache__) and of BASE_DIR/labs
            is unchanged around a subprocess run of `python3 -B <copy>/src/cassian.py checks --json` from that
            cwd with PYTHONDONTWRITEBYTECODE=1. The copy's own BASE_DIR is checked to be the copy. So no earlier
            run, in this process or before it, can have written into the baseline.
  A  PO-07  (a) a subprocess driver run as `python3 -B -c ...` with PYTHONDONTWRITEBYTECODE=1 puts src/ on
            sys.path, sets sys.argv to ["cassian", "checks", "--json"], imports cassian_cli, calls main() and
            reports on stderr whether "openai" is in sys.modules: it must not be; (b) in process, with
            sys.setprofile installed after cassian_cli is imported and before main() is called, no `call` event
            has a frame whose file is cassian_ai.py; (c) the AST of src/cassian_catalogue.py imports none of
            cassian_ai, openai, cassian_engine, cassian_runtime_container, cassian_runtime_vm.
  N  MUTANTS each leg above is shown capable of failing: for R, a build_catalogue wrapped to make one call of each
            patched API is caught by that API (nine seeds); for S, a run that writes one file into the cwd is
            caught, and I-7b (LC-1) is caught: a fresh copy has build_catalogue write the same byte into
            src/checks_cache through os.open on every run, an earlier run writes it first, an in-place snapshot
            then sees no change (the condition the closure record's F1 found), and the S procedure on a fresh
            copy reports the file; I-7b is planted only in copies, never in the tree under test; for A, (a) the
            same driver with a stand-in `openai` module placed in sys.modules is reported, (b) a build_catalogue
            wrapped to call cassian_ai._ai_sanitize_error is caught by the profile, (c) a doctored copy of the
            catalogue source with `import cassian_ai` is reported.

Coverage limits (PBE-P2-8 / PBE-P2-14), stated so a PASS is not read as more than it is:
  1. R patches these APIs by name in this interpreter: a write through another API (os.open, os.write,
     shutil, a C extension) is not seen. Read-mode opens pass through.
  2. S compares the files it can see: the cwd, the fresh copy and its labs/. A write elsewhere (a home
     directory, /tmp outside the cwd, the tree under test itself) is not seen; the interpreter's bytecode cache
     is excluded by PYTHONDONTWRITEBYTECODE=1 and by skipping __pycache__, so that it is not counted against
     REQ-S1D2-2. It compares file contents: a write that leaves a file's bytes as they were (a tracked file
     rewritten with its own content) and an empty directory (R covers the mkdir APIs in process) are not
     seen. The copy holds tracked files only: a tracked file the tree has modified is copied as modified, and
     an untracked file is not copied, so a run that needs one fails loudly. Outside a git work tree the file
     list cannot be read, and S fails loudly. The LC-1 negative legs plant I-7b in a copy of the tree under
     test, so on a tree that itself writes they can fail beside S, whose own line names the write.
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
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

# The product's modules are imported by main() after S's pristine copy is taken (LC-1): an import runs their code.
C = None  # cassian_catalogue
cassian_cli = None
PRODUCT_MODULES = ("cassian_catalogue", "cassian_cli", "cassian_common", "cassian_engine")

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


def tracked_files():
    """The tree under test's tracked files, from `git ls-files -z`: (exit code, paths, stderr)."""
    r = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, timeout=120)
    paths = [p for p in r.stdout.decode("utf-8", "surrogateescape").split("\0") if p]
    return r.returncode, paths, r.stderr.decode("utf-8", "replace").strip()


def copy_tracked(src_root, paths, dst_root):
    """Copy each listed path's bytes (and mode) from src_root into dst_root, a new directory: the number copied."""
    copied = 0
    Path(dst_root).mkdir()
    for rel in paths:
        src = Path(src_root, rel)
        if not src.is_file():
            continue
        dst = Path(dst_root, rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, dst)
        copied += 1
    return copied


def snapshot_run(base, argv_tail, extra_code=None):
    """Snapshots of a temporary cwd, BASE_DIR (`base`, a fresh copy) and BASE_DIR/labs around one subprocess run of
    base's src/cassian.py: (exit code, changes as "<part> <+|-|~><path>", files snapshotted under BASE_DIR)."""
    base = Path(base)
    with tempfile.TemporaryDirectory() as td:
        before = (snapshot(td), snapshot(base), snapshot(base / "labs"))
        if extra_code is None:
            cmd = [sys.executable, "-B", str(base / "src" / "cassian.py"), *argv_tail]
        else:
            cmd = [sys.executable, "-B", "-c", extra_code]
        r = subprocess.run(cmd, cwd=td, capture_output=True, timeout=300, env=env())
        after = (snapshot(td), snapshot(base), snapshot(base / "labs"))
    changes = []
    for name, b, a in zip(("cwd", "BASE_DIR", "BASE_DIR/labs"), before, after):
        for path in sorted(set(b) | set(a)):
            if b.get(path) != a.get(path):
                changes.append(f"{name} {'+' if path not in b else '-' if path not in a else '~'}{path}")
    return r.returncode, changes, len(before[1])


def base_dir_of(base):
    """BASE_DIR as the copy's own cassian_common resolves it, read in a subprocess: (exit code, text)."""
    code = ("import sys\n"
            f"sys.path.insert(0, {str(Path(base, 'src'))!r})\n"
            "import cassian_common\n"
            "sys.stdout.write(str(cassian_common.BASE_DIR))\n")
    with tempfile.TemporaryDirectory() as td:
        r = subprocess.run([sys.executable, "-B", "-c", code], cwd=td, capture_output=True, text=True,
                           timeout=120, env=env())
    return r.returncode, r.stdout


# I-7b (closure record section 6; LC-1), verbatim: after build_catalogue's docstring, the same byte is written into
# src/checks_cache through os.open on every run.
I7B_ANCHOR = '    """Build the whole catalogue in memory, or stop with a construction failure."""\n'
I7B_WRITE = ('    import os as _o\n'
             '    _fd = _o.open(_o.path.join(_o.path.dirname(_o.path.abspath(__file__)), "checks_cache"), '
             '_o.O_WRONLY | _o.O_CREAT, 0o644); _o.write(_fd, b"x"); _o.close(_fd)\n')


def plant_i7b(tree):
    """Plant I-7b in `tree`'s copy of the catalogue, only if its anchor occurs once: the anchor's count."""
    p = Path(tree, "src", "cassian_catalogue.py")
    source = p.read_text(encoding="utf-8")
    n = source.count(I7B_ANCHOR)
    if n == 1:
        p.write_text(source.replace(I7B_ANCHOR, I7B_ANCHOR + I7B_WRITE, 1), encoding="utf-8")
    return n


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
    with tempfile.TemporaryDirectory() as work:
        legs(Path(work))
    fails = [n for n, ok in checks if not ok]
    print("RESULT: %s (%d checks, %d failed)" % ("PASS" if not fails else "FAIL", len(checks), len(fails)))
    sys.exit(1 if fails else 0)


def legs(work):
    global C, cassian_cli
    # S's pristine copy (PO-06; LC-1): taken before any product module is imported, so before any of its code runs
    imported = sorted(m for m in PRODUCT_MODULES if m in sys.modules)
    rc, files, err = tracked_files()
    pristine = work / "pristine"
    copied = copy_tracked(ROOT, files, pristine) if rc == 0 else 0
    check("S PO-06 a pristine copy of the tree's tracked files is taken before any product module is imported",
          rc == 0 and files and copied == len(files) and not imported,
          f"git ls-files exit {rc}; {len(files)} tracked, {copied} copied; imported before: {imported}"
          + (f"; {err}" if err else ""))
    if not checks[-1][1]:
        return
    import cassian_catalogue as C  # noqa: E402
    import cassian_cli  # noqa: E402

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

    # S (PO-06), on a fresh copy of the pristine copy
    tree = work / "s-tree"
    copy_tracked(pristine, files, tree)
    rc, changes, nfiles = snapshot_run(tree, ["checks", "--json"])
    check("S PO-06 `python3 -B <copy>/src/cassian.py checks --json` from a temp cwd changes no file in the cwd, "
          "BASE_DIR or BASE_DIR/labs, BASE_DIR a fresh copy of the tree's tracked files", rc == 0 and not changes,
          f"changes={changes}" if changes else f"exit {rc}; {nfiles} files snapshotted under BASE_DIR")
    rc, base_dir = base_dir_of(tree)
    check("S PO-06 the copy's own cassian_common.BASE_DIR is the copy, so the snapshot covers the tree its run uses",
          rc == 0 and base_dir == str(tree.resolve()), f"exit {rc}; BASE_DIR={base_dir!r}")
    seed = "open('zz_written_by_hs5', 'w').write('x')\n"
    rc, changes, _n = snapshot_run(tree, [], extra_code=seed)
    check("N S PO-06 a run that writes one file into the cwd is caught by the snapshot",
          changes == ["cwd +zz_written_by_hs5"], f"changes={changes}")

    # N S (LC-1): I-7b's repeatable write, planted only in copies, never in the tree under test
    planted = work / "planted"
    copy_tracked(pristine, files, planted)
    n = plant_i7b(planted)
    check("N S PO-06 (LC-1) I-7b is planted verbatim in a fresh copy, after build_catalogue's docstring",
          n == 1, f"anchor occurs {n} time(s) in the copy's src/cassian_catalogue.py")
    rc, changes, _n = snapshot_run(planted, ["checks", "--json"])
    cache = planted / "src" / "checks_cache"
    wrote = cache.is_file() and cache.read_bytes() == b"x"
    check("N S PO-06 (LC-1) an earlier run of the planted copy writes its byte into src/checks_cache",
          rc == 0 and wrote and changes == ["BASE_DIR +src/checks_cache"], f"exit {rc}; changes={changes}")
    rc, changes, _n = snapshot_run(planted, ["checks", "--json"])
    check("N S PO-06 (LC-1) after that earlier run, a snapshot taken in place sees no change (the gap F1 found)",
          rc == 0 and not changes, f"exit {rc}; changes={changes}")
    fresh = work / "planted-fresh"
    copy_tracked(planted, files, fresh)
    rc, changes, _n = snapshot_run(fresh, ["checks", "--json"])
    check("N S PO-06 (LC-1) the same repeatable write is caught by S on a fresh copy of the planted tree",
          changes == ["BASE_DIR +src/checks_cache"], f"exit {rc}; changes={changes}")

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


if __name__ == "__main__":
    main()
