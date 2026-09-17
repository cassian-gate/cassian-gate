#!/usr/bin/env python3
"""exec_rule_parity_proof -- REQ-45D-6 extraction bar (hosted).

Property: the exec allow-list's ACCEPT/REJECT SETS **and REASON BYTES** are
identical before and after the per-type rules move out of
`cassian_model._exec_command_allowed`'s if-ladder into each provider's
`exec_command_rule`.

The pre-extraction ladder is carried here as a frozen ORACLE (copied byte-for-byte
from cassian_model.py @ 50201fe :1962-1993). The proof drives a corpus through the
oracle and through the live decision site and requires (allowed, reason) equality
on EVERY case -- one argv changing side, or one reason byte differing, fails.

Non-vacuity is two-directional and controlled: MUTATION-FAIL: too-much (an argv the
oracle rejects must not be accepted) and MUTATION-FAIL: too-little (an argv the
oracle accepts must not be rejected), each exercised against a deliberately broken
rule so the harness is shown capable of failing.
"""
import shlex, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import cassian_model as M

FAILS: list[str] = []
def check(ok: bool, label: str) -> None:
    print(("  ok   " if ok else "  FAIL ") + label)
    if not ok:
        FAILS.append(label)

# ---------------- frozen pre-extraction oracle (verbatim from 50201fe) --------
def ORACLE(command: str, derived_type: str) -> "tuple[bool, str]":
    cmd = str(command or "").strip()
    if not cmd:
        return (False, "command is empty")
    for _ch in (";", "|", "&", "$", "`", "<", ">", "(", ")", "{", "}", "\n", "\\"):
        if _ch in cmd:
            return (False, "raw shell / shell metacharacters are not an accepted exec command form")
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return (False, "command is not a well-formed single command")
    if not argv:
        return (False, "command is empty")
    if derived_type == "frr":
        if argv[0] != "vtysh" or "-c" not in argv:
            return (False, "frr exec commands must be read-only 'vtysh -c \"show \u2026\"'")
        _ci = argv.index("-c")
        if _ci + 1 >= len(argv):
            return (False, "frr exec commands must be read-only 'vtysh -c \"show \u2026\"'")
        _vc = argv[_ci + 1].strip().lower()
        if _vc != "show" and not _vc.startswith("show "):
            return (False, "frr exec commands must be read-only 'vtysh -c \"show \u2026\"'")
        return (True, "")
    if derived_type == "nft-fw":
        if argv[0] != "nft" or len(argv) < 2 or argv[1] != "list":
            return (False, "nft-fw exec commands must be read-only 'nft list \u2026' (mutation subcommands denied)")
        return (True, "")
    return (False, f"no read-only allow-list for node type {derived_type!r}")

# ---------------- corpus ------------------------------------------------------
CMDS = [
    "", "   ", 'vtysh -c "show ip bgp summary"', 'vtysh -c "SHOW ip route"',
    'vtysh -c "show"', 'vtysh -c "showing off"', 'vtysh -c "configure terminal"',
    'vtysh -c', "vtysh", "vtysh -x \"show ip bgp\"", 'vtysh -c "clear ip bgp *"',
    "nft list ruleset", "nft list tables", "nft", "nft flush ruleset",
    "nft add rule inet filter input drop", "nft -v list ruleset",
    "ip -j link show", "ss -tulpn", "show ip bgp summary", "sudo nft list ruleset",
    'vtysh -c "show ip bgp" ; rm -rf /', "nft list ruleset | grep drop",
    'vtysh -c "show $(whoami)"', "echo `id`", 'vtysh -c "show ip route" > /tmp/x',
    "nft list ruleset & ", 'vtysh -c "show {a}"', "unclosed 'quote",
]
TYPES = ["frr", "nft-fw", "sonic-vm", "host", "bogus-type"]

print("== corpus parity: oracle vs live decision site (allowed + reason bytes)")
mismatch = 0
for t in TYPES:
    for c in CMDS:
        exp, got = ORACLE(c, t), M._exec_command_allowed(c, t)
        if exp != got:
            mismatch += 1
            print(f"  FAIL  type={t!r} cmd={c!r}\n        oracle={exp!r}\n        live  ={got!r}")
check(mismatch == 0, f"parity over {len(TYPES)*len(CMDS)} cases, 0 mismatches (got {mismatch})")

print("== single decision site (PBE-1b-9): the model holds no per-type branch")
src = (pathlib.Path(__file__).resolve().parents[1] / "src" / "cassian_model.py").read_text()
body = src[src.index("def _exec_command_allowed("):]
body = body[:body.index("\ndef ", 1)]
check('derived_type == "frr"' not in body and 'derived_type == "nft-fw"' not in body,
      "no hardcoded node-type branch remains in _exec_command_allowed")
check("exec_command_rule(argv)" in body, "dispatch to provider.exec_command_rule(argv) present")

print("== placeholders retired (REQ-45D-6 exit criterion)")
from cassian_nos_types import is_deferred
for t in ("frr", "nft-fw"):
    check(not is_deferred(M.NOS_PROVIDERS[t].exec_command_rule), f"{t} exec_command_rule is wired")

print("== NON-VACUITY (two-directional, with control)")
class _Broken:
    def __init__(self, verdict): self.v = verdict
    def __call__(self, argv): return self.v
_real = M.NOS_PROVIDERS["frr"].exec_command_rule

def _swap(fn):
    import dataclasses
    M.NOS_PROVIDERS = type(M.NOS_PROVIDERS)({
        **{k: (dataclasses.replace(v, exec_command_rule=fn) if k == "frr" else v)
           for k, v in M.NOS_PROVIDERS.items()}})

_swap(_Broken((True, "")))                       # accepts everything -> too-much
tm = any(M._exec_command_allowed(c, "frr") != ORACLE(c, "frr") for c in CMDS)
print("  MUTATION-FAIL: too-much" if tm else "  CONTROL BROKEN: too-much not detected")
check(tm, "harness detects an over-accepting rule")

_swap(_Broken((False, "x")))                     # rejects everything -> too-little
tl = any(M._exec_command_allowed(c, "frr") != ORACLE(c, "frr") for c in CMDS)
print("  MUTATION-FAIL: too-little" if tl else "  CONTROL BROKEN: too-little not detected")
check(tl, "harness detects an over-rejecting rule")

_swap(_real)                                     # control: restored == parity again
check(all(M._exec_command_allowed(c, "frr") == ORACLE(c, "frr") for c in CMDS),
      "control: restored rule reproduces the oracle")

print("PASS" if not FAILS else "FAILED: " + "; ".join(FAILS))
sys.exit(0 if not FAILS else 1)
