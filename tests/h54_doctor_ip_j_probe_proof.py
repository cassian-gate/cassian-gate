#!/usr/bin/env python3
"""PO-H54-probe — BL-H5-4 `cassian doctor` ip -j advisory probe (lab-free behavioral proof).

Proof obligations (handover §15.2):
  REQ-H54-1  parseable JSON  -> present (✔); ip absent / non-parseable / nonzero rc -> ⚠
             (capture + parse, not returncode-only); no false-positive; read-only subcommand.
  REQ-H54-2  probe line rendered exactly once at a fixed, order-stable position
             (after containerlab, before the image-advisory block) with an explicit mark.
  REQ-H54-3  advisory non-escalation: exit is governed by critical checks only; the ip
             result never changes the exit code.

Method (PBE-1b-8): behavioral-model harness over a stubbed which/subprocess. cmd_doctor
resolves `shutil`/`subprocess` via the cassian_engine module namespace, so the probe and the
critical checks are driven deterministically by swapping those names for the duration of a run.
No container, no live `ip`, no deploy.
"""
import argparse
import contextlib
import io
import pathlib
import subprocess as _sp
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import cassian_engine as ce  # noqa: E402

LABEL = "ip -j JSON capability"
CHECKS: list[tuple[bool, str]] = []


def _check(cond: object, msg: str) -> None:
    CHECKS.append((bool(cond), msg))


class _P:
    def __init__(self, returncode: int = 0, stdout: bytes = b"") -> None:
        self.returncode = returncode
        self.stdout = stdout


def _stubs(ip_present=True, ip_rc=0, ip_stdout=b"[]", criticals_ok=True, record=None):
    present = {"docker", "containerlab"}
    if ip_present:
        present.add("ip")

    def fake_which(name):
        return ("/usr/bin/" + name) if name in present else None

    def fake_run(cmd, **kw):
        if record is not None:
            record.append((tuple(cmd), dict(kw)))
        if cmd[:2] == ["ip", "-j"]:
            return _P(returncode=ip_rc, stdout=ip_stdout)
        if cmd == ["docker", "info"]:
            return _P(returncode=0 if criticals_ok else 1)
        if cmd[:3] == ["docker", "image", "inspect"]:
            return _P(returncode=0)
        return _P(returncode=0)

    return fake_which, fake_run


def _run_doctor(fake_which, fake_run):
    orig_shutil, orig_sub = ce.shutil, ce.subprocess
    ce.shutil = types.SimpleNamespace(which=fake_which)
    ce.subprocess = types.SimpleNamespace(run=fake_run, PIPE=_sp.PIPE, DEVNULL=_sp.DEVNULL)
    buf, code = io.StringIO(), None
    try:
        with contextlib.redirect_stdout(buf):
            try:
                ce.cmd_doctor(argparse.Namespace())
            except SystemExit as e:
                code = e.code
    finally:
        ce.shutil, ce.subprocess = orig_shutil, orig_sub
    return buf.getvalue(), code


# REQ-H54-1 positive: parseable JSON array -> present (✔)
out, code = _run_doctor(*_stubs(ip_stdout=b'[{"ifname":"lo"}]'))
_check(f"\u2714 {LABEL}" in out, "REQ-H54-1+: parseable JSON array -> present (✔)")
_check(f"\u26a0 {LABEL}" not in out, "REQ-H54-1+: not marked advisory-absent when present")
_check(code == 0, "REQ-H54-3: present + criticals ok -> exit 0")

# REQ-H54-1 negative: ip absent -> ⚠, exit 0 (advisory non-escalation)
out, code = _run_doctor(*_stubs(ip_present=False))
_check(f"\u26a0 {LABEL}" in out, "REQ-H54-1-: ip absent -> ⚠ advisory")
_check(f"\u2714 {LABEL}" not in out, "REQ-H54-1-: no false-positive when ip absent")
_check(code == 0, "REQ-H54-3: ip absent never escalates exit (criticals ok -> 0)")

# REQ-H54-1 negative: zero-exit but non-parseable stdout -> ⚠ (capture+parse, not zero-exit)
out, code = _run_doctor(*_stubs(ip_stdout=b"not json"))
_check(f"\u26a0 {LABEL}" in out, "REQ-H54-1-: non-parseable stdout -> ⚠ (parse required)")
_check(f"\u2714 {LABEL}" not in out, "REQ-H54-1-: zero-exit + junk stdout != present")
_check(code == 0, "REQ-H54-3: non-parseable never escalates exit")

# REQ-H54-1 negative: nonzero returncode with JSON-looking stdout -> ⚠ (honor returncode)
out, _ = _run_doctor(*_stubs(ip_rc=1, ip_stdout=b"[]"))
_check(f"\u26a0 {LABEL}" in out, "REQ-H54-1-: nonzero rc -> ⚠ even if stdout parses")

# REQ-H54-1 negative: parseable JSON but not a list (e.g. object) -> ⚠ (shape check)
out, _ = _run_doctor(*_stubs(ip_stdout=b'{"not":"a list"}'))
_check(f"\u26a0 {LABEL}" in out, "REQ-H54-1-: JSON non-array -> ⚠ (array shape required)")

# REQ-H54-2: fixed position / order-stable — exactly once, after containerlab, before images
out, _ = _run_doctor(*_stubs())
lines = [ln for ln in out.splitlines() if ln.strip()]
ip_idx = [k for k, ln in enumerate(lines) if LABEL in ln]
clab_idx = [k for k, ln in enumerate(lines) if "containerlab detected" in ln]
img_idx = [k for k, ln in enumerate(lines) if "image present" in ln]
_check(len(ip_idx) == 1, "REQ-H54-2: probe line rendered exactly once")
_check(bool(clab_idx) and ip_idx and ip_idx[0] > clab_idx[0],
       "REQ-H54-2: probe after containerlab (fixed position)")
_check(bool(img_idx) and ip_idx and ip_idx[0] < min(img_idx),
       "REQ-H54-2: probe before image-advisory block (order-stable)")

# REQ-H54-3: exit governed by criticals only — present probe does not rescue a critical fail
out, code = _run_doctor(*_stubs(criticals_ok=False))
_check(code == 1, "REQ-H54-3: critical failure exits 1 (advisory present does not rescue)")
_check(f"\u2714 {LABEL}" in out, "REQ-H54-3: advisory still rendered on the critical-fail path")

# REQ-H54-1: read-only — exactly one `ip -j addr`, captured (PIPE), stderr suppressed (DEVNULL)
rec: list = []
_run_doctor(*_stubs(record=rec))
ip_calls = [(cmd, kw) for cmd, kw in rec if cmd[:2] == ("ip", "-j")]
_check(len(ip_calls) == 1, "REQ-H54-1: probe invokes ip exactly once")
_check(bool(ip_calls) and ip_calls[0][0] == ("ip", "-j", "addr"),
       "REQ-H54-1: read-only subcommand `ip -j addr` (no mutating verb)")
_check(bool(ip_calls) and ip_calls[0][1].get("stdout") is _sp.PIPE,
       "REQ-H54-1: stdout captured (PIPE) for parsing")
_check(bool(ip_calls) and ip_calls[0][1].get("stderr") is _sp.DEVNULL,
       "REQ-H54-1: stderr suppressed (DEVNULL)")

# Source guards (PBE-1b-8): probe present and registered at advisory severity
src = (ROOT / "src" / "cassian_engine.py").read_text(encoding="utf-8")
_check('def _ip_json_capable()' in src, "source: probe helper present in cassian_engine")
_check('checks.append(("ip -j JSON capability", _ip_json_capable(), "advisory"))' in src,
       "source: probe registered at advisory severity (not critical)")

fails = [m for ok, m in CHECKS if not ok]
print(f"PO-H54-probe: {len(CHECKS) - len(fails)}/{len(CHECKS)} checks passed.")
for ok, m in CHECKS:
    print(f"  [{'PASS' if ok else 'FAIL'}] {m}")
if fails:
    sys.exit(f"PO-H54-probe FAILED ({len(fails)} check(s)).")
print("PO-H54-probe OK.")
