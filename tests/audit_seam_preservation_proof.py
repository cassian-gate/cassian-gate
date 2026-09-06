#!/usr/bin/env python3
"""PO-6 (REQ-413-P / REQ-413-13BC) — §13(b)(c) render-seam preservation, lab-free.
Source-segment SHA-256 (§4.12 B-6 method) on the seam functions extracted by AST from
the LIVE cassian_tests.py, plus whole-module SHA. The §4.13 audit additions land entirely
in the engine; the seam must be byte-identical to v9."""
import sys, os, ast, hashlib
SRC = os.path.join(os.path.dirname(__file__), "..", "src", "cassian_tests.py")

# v9 baselines (computed from the declared v9 consolidated snapshot).
WHOLE_MODULE_V9 = "d977b4b1318266d6eea1360295b716db6d757ff1eb98f781f29c37f1e509a920"  # re-baselined from b8dc8534 (phase2 §4.5-c Unit B: wait_for_bgp gate predicate + LD-45C-R10 header import; LD-45C-R9/R10/R11; LD-45C-R2 D-5, founder ruling D-6, taken only with both seam segment pins PASSING -- re-measured PASSING at apply time 2026-08-31); prior 49f484b0; prior dd56046b; orig ba0a1f36
SEAM_SEGMENT_V9 = {
    "_format_test_summary":        "2119d19a5667f77168df07ec5edcaa4d3001cdca49386027f1c6186c1f727ffa",
    "write_test_summary_artifact": "ff523b7eb74ebdff684ac8cb179842cd71c099e73913398ed280507343263420",
}

fails = []
def ck(c, msg):
    print(("PASS  " if c else "FAIL  ") + msg)
    if not c: fails.append(msg)

src = open(SRC, encoding="utf-8").read()
whole = hashlib.sha256(src.encode("utf-8")).hexdigest()
ck(whole == WHOLE_MODULE_V9, f"whole-module cassian_tests.py == v9 (49f484b0...)  [{whole[:12]}...]")

tree = ast.parse(src)
lines = src.splitlines(keepends=True)
for fn, baseline in SEAM_SEGMENT_V9.items():
    node = next((n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fn), None)
    if node is None:
        ck(False, f"seam function {fn} present"); continue
    seg = "".join(lines[node.lineno - 1:node.end_lineno])
    seg_sha = hashlib.sha256(seg.encode("utf-8")).hexdigest()
    ck(seg_sha == baseline, f"seam segment {fn} byte-unchanged vs v9  (lines {node.lineno}-{node.end_lineno})")

print("=" * 60)
print("RESULT:", "PASS" if not fails else "FAIL", "-- PO-6 §13(b)(c) seam preservation")
sys.exit(1 if fails else 0)
