#!/usr/bin/env python3
"""PO-11 (REQ-413-4-VAL) — §13(a) intent-input rejection SUFFICIENCY, lab-free, negative.
Symmetric to the §13(b)(c) seam-sufficiency obligation (PO-6). A malformed/unknown-key
intent is hard-failed; the rejection content (1) names the offending field 'intent',
(2) identifies the offending key/value where safe, (3) points to corrective action,
and uses the existing authoritative-input rejection exit code (2). Snapshot-grounded (PBE-1b-8)."""
import sys, os, io, contextlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import cassian_model as m

fails = []
def ck(c, msg):
    print(("PASS  " if c else "FAIL  ") + msg)
    if not c: fails.append(msg)

def topo(intent=None):
    t = {"name": "t", "nodes": [{"name": "r1", "type": "frr"}], "links": []}
    if intent is not None:
        t["intent"] = intent
    return t

def run(t):
    """Return (exit_code_or_None, captured_text)."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
            m.ensure_valid_topology(t)
        return None, buf.getvalue()
    except SystemExit as ex:
        return ex.code, buf.getvalue()

# Positive control: a well-formed string intent is accepted (not silently rejected).
code, _ = run(topo("pre-prod BGP change ticket-4412"))
ck(code is None, "well-formed string intent accepted (not over-rejected)")

# Negative: non-string scalar -> hard-fail with §13(a) sufficiency triad.
code, out = run(topo(123))
ck(code == 2, "int intent hard-fails with existing rejection exit code (2)")
ck("intent" in out, "§13(a)(1) rejection names the offending field 'intent'")
ck("string" in out.lower(), "§13(a)(2) rejection identifies the issue (must be a string)")
ck(("re-run" in out.lower()) or ("correct" in out.lower()) or ("remove" in out.lower()),
   "§13(a)(3) rejection points to corrective action")

# Negative: list intent -> hard-fail.
code, _ = run(topo(["a", "b"]))
ck(code == 2, "list intent hard-fails (code 2)")

# Negative: object intent -> hard-fail naming an unknown key (§19.2 template).
code, out = run(topo({"purpose": "x", "extra": "y"}))
ck(code == 2, "object intent hard-fails (code 2)")
ck("unknown key" in out and ("'purpose'" in out or "'extra'" in out),
   "object intent rejection names an unknown key (identifies offending key safely)")

# Silence != acceptance: malformed intent is NEVER silently accepted.
code, _ = run(topo({"x": 1}))
ck(code == 2, "malformed intent never silently accepted (silence != acceptance)")

print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-11 §13(a) intent-input sufficiency")
sys.exit(1 if fails else 0)
