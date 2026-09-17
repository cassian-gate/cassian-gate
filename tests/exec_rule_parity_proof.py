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

# ============================ SECOND CORPUS: STATE LEG =========================
# §3 row 112 -- "same harness, second corpus". REQ-45D-7's extraction bar is the
# state-capture argv allow-list: accept/reject AND the operator-facing bytes.
# The pre-extraction ladder is carried as a frozen oracle, copied byte-for-byte
# from cassian_state.py @ faa579b :181-280.

import io, contextlib
import cassian_state as S
from cassian_common import die as _die

_DENY = ["|", ";", "&&", "||", ">", "<", "$(", ")", "`", "\n", "\r"]

def ORACLE_STATE(profile, node, node_type, argv):
    """Returns (outcome, message). outcome: 'ok' | 'die'. Verbatim pre-extraction."""
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x.strip() for x in argv):
        return ("die", f"state-capture: invalid command argv for profile '{profile}' on node '{node}'")
    joined = " ".join(argv)
    for tok in _DENY:
        if tok in joined:
            return ("die", f"state-capture: command denied (token {tok!r}) for profile '{profile}' "
                           f"node '{node}' type '{node_type}': {argv!r}")
    if node_type == "frr":
        if tuple(argv) in {("ip", "-j", "link", "show"), ("ip", "-j", "addr", "show")}:
            return ("ok", "")
        if not (len(argv) == 3 and argv[0] == "vtysh" and argv[1] == "-c"):
            return ("die", f"state-capture: FRR commands must be 'vtysh -c <cmd>' "
                           f"(profile '{profile}' node '{node}'): {argv!r}")
        cmd = argv[2].strip(); cmd_l = cmd.lower()
        if not cmd_l.startswith("show "):
            return ("die", f"state-capture: FRR command must start with 'show ' "
                           f"(profile '{profile}' node '{node}'): {cmd!r}")
        for w in ["configure", "conf t", "write", "clear", "debug", "terminal", "end", "exit", "|"]:
            if w in cmd_l:
                return ("die", f"state-capture: FRR command denied by allowlist rule ({w!r}) "
                               f"(profile '{profile}' node '{node}'): {cmd!r}")
        return ("ok", "")
    elif node_type == "host":
        if tuple(argv) not in {("ip","addr"),("ip","link"),("ip","route"),("ip","neigh"),("ss","-tulpn")}:
            return ("die", f"state-capture: host command not allowlisted "
                           f"(profile '{profile}' node '{node}'): {argv!r}")
        return ("ok", "")
    elif node_type == "nft-fw":
        if tuple(argv) not in {("nft","list","ruleset"),("sysctl","-n","net.ipv4.ip_forward"),
                               ("sysctl","-n","net.ipv4.conf.all.rp_filter"),
                               ("sysctl","-n","net.ipv4.conf.default.rp_filter")}:
            return ("die", f"state-capture: nft-fw command not allowlisted "
                           f"(profile '{profile}' node '{node}'): {argv!r}")
        joined_l = " ".join(argv).lower()
        if "flush" in joined_l or "add" in joined_l or "delete" in joined_l or " -w " in joined_l or "sysctl -w" in joined_l:
            return ("die", f"state-capture: mutation command denied "
                           f"(profile '{profile}' node '{node}'): {argv!r}")
        return ("ok", "")
    else:
        return ("die", f"state-capture: unsupported node type '{node_type}' for profile '{profile}' node '{node}'")

def LIVE_STATE(profile, node, node_type, argv):
    buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(buf):
            S._state_capture_validate_argv_or_die(profile=profile, node=node, node_type=node_type, argv=argv)
        return ("ok", "")
    except SystemExit:
        from cassian_common import LAST_ERROR_MSG
        import cassian_common as C
        return ("die", C.LAST_ERROR_MSG)

ARGVS = [
    ["ip","-j","link","show"], ["ip","-j","addr","show"], ["ip","-j","route","show"],
    ["vtysh","-c","show ip bgp summary"], ["vtysh","-c","show"], ["vtysh","-c","SHOW ip route"],
    ["vtysh","-c","configure terminal"], ["vtysh","-c","show running-config | include foo"],
    ["vtysh","-c","show ip route","extra"], ["vtysh","-x","show ip bgp"], ["vtysh"],
    ["vtysh","-c","show ip route; rm -rf /"], ["vtysh","-c","show debug"], ["vtysh","-c","show terminal"],
    ["nft","list","ruleset"], ["nft","list","tables"], ["nft","flush","ruleset"],
    ["sysctl","-n","net.ipv4.ip_forward"], ["sysctl","-w","net.ipv4.ip_forward=1"],
    ["ip","addr"], ["ip","link"], ["ss","-tulpn"], ["ip","neigh"], ["ip","xfrm"],
    ["echo","`id`"], ["cat",">","/tmp/x"], [], ["  "], ["ok","$(whoami)"],
]
TYPES_S = ["frr", "nft-fw", "host", "sonic-vm", "bogus-type"]

print("== second corpus: state-capture argv parity (outcome + message BYTES)")
bad = 0
for t in TYPES_S:
    for a in ARGVS:
        exp = ORACLE_STATE("p1", "n1", t, a)
        got = LIVE_STATE("p1", "n1", t, a)
        if exp != got:
            bad += 1
            print(f"  FAIL  type={t!r} argv={a!r}\n        oracle={exp!r}\n        live  ={got!r}")
check(bad == 0, f"state parity over {len(TYPES_S)*len(ARGVS)} cases, 0 mismatches (got {bad})")

print("== state placeholders retired (REQ-45D-7 exit criterion)")
for t in ("frr", "nft-fw"):
    check(not is_deferred(M.NOS_PROVIDERS[t].state_argv_allow), f"{t} state_argv_allow is wired")

print("== single decision site: no per-type branch remains for the dispatched types")
ssrc = (pathlib.Path(__file__).resolve().parents[1] / "src" / "cassian_state.py").read_text()
fn = ssrc[ssrc.index("def _state_capture_validate_argv_or_die("):]
fn = fn[:fn.index("\ndef ", 1)]
check('node_type == "frr"' not in fn and 'node_type == "nft-fw"' not in fn,
      "frr/nft-fw branches gone from the state decision site")
check('node_type == "host"' in fn, "host branch retained inline (in-file coverage limit, PBE-P2-8)")
check("state_argv_allow(profile, node, argv)" in fn, "dispatch to provider.state_argv_allow present")

print("== NON-VACUITY (state leg, two-directional, with control)")
import dataclasses
_real_s = M.NOS_PROVIDERS["frr"].state_argv_allow
def _swap_s(fn_):
    M.NOS_PROVIDERS = type(M.NOS_PROVIDERS)({
        **{k: (dataclasses.replace(v, state_argv_allow=fn_) if k == "frr" else v)
           for k, v in M.NOS_PROVIDERS.items()}})
    S.NOS_PROVIDERS = M.NOS_PROVIDERS

_swap_s(lambda p, n, a: (True, ""))
tm_s = any(LIVE_STATE("p1","n1","frr",a) != ORACLE_STATE("p1","n1","frr",a) for a in ARGVS)
print("  MUTATION-FAIL: too-much" if tm_s else "  CONTROL BROKEN: too-much not detected")
check(tm_s, "state harness detects an over-accepting rule")

_swap_s(lambda p, n, a: (False, "nope"))
tl_s = any(LIVE_STATE("p1","n1","frr",a) != ORACLE_STATE("p1","n1","frr",a) for a in ARGVS)
print("  MUTATION-FAIL: too-little" if tl_s else "  CONTROL BROKEN: too-little not detected")
check(tl_s, "state harness detects an over-rejecting rule")

_swap_s(_real_s)
check(all(LIVE_STATE("p1","n1","frr",a) == ORACLE_STATE("p1","n1","frr",a) for a in ARGVS),
      "control: restored state rule reproduces the oracle")

print("PASS" if not FAILS else "FAILED: " + "; ".join(FAILS))
sys.exit(0 if not FAILS else 1)
