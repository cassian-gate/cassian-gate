#!/usr/bin/env python3
"""SONiC read-only exec allow-list proof (REQ-45D-5; LD-45D-5, D2, D4).

`SONIC_PROVIDER.exec_command_rule` replaces its `deferred_leg` placeholder and
becomes a default-deny read-only allow-list accepting exactly two forms:

  * ``show ...``             -- ``argv[0] == "show"``, excluding ``show
                               techsupport`` (founder ruling D4, 2026-09-24).
                               ``show auto-techsupport`` is a distinct
                               subcommand and stays accepted. D4 narrows this
                               form only, by its own words.
  * ``vtysh -c "show ..."``  -- EXACTLY three arguments (founder ruling D2,
                               2026-09-24). The guest's ``/usr/bin/vtysh`` is a
                               wrapper passing every argument to FRR's vtysh,
                               which honours repeated ``-c`` and ``-b`` /
                               ``-f`` / ``-w``.

Every case is driven through the SHIPPED decision site
``cassian_model._exec_command_allowed(command, "sonic-vm")`` rather than by
calling the rule directly, so the proof binds the path validate actually takes
(REQ-45D-6: generic metacharacter / shlex / empty checks stay in the model).

Proof obligations:
  P-SXA-ACCEPT  every declared accepted form is accepted.
  P-SXA-REFUSE  every declared refused shape is refused, including D2's
                repeated ``-c``, ``-b``, ``-f``, ``-w`` and a ``configure``
                payload -- the shapes the D3 chain proved FRR admits.
  P-SXA-D4      ``show techsupport`` is refused at every arity; ``show
                auto-techsupport`` is accepted. The discriminating pair is the
                point of the ruling and is asserted as a pair.
  P-SXA-CLAUSE  a real ``resolve_topology`` rejection renders the
                registry-derived ``Allowed:`` clause carrying the ``sonic-vm``
                segment, and the ``frr`` and ``nft-fw`` segments are
                BYTE-IDENTICAL to their pre-change text.
  P-SXA-REASON  one standard refusal reason for every refusal, as D4 directs.
  P-SXA-NV      non-vacuity: the harness detects an over-accepting rule and an
                over-rejecting rule.

Coverage limits, stated in-file (PBE-P2-8):
  - Lab-free. This proves the VALIDATE-time decision, not guest behaviour. No
    SONiC guest is contacted.
  - The metacharacter and shlex refusals are the MODEL's, not this rule's.
    They are driven here because an operator meets the composite, but a
    passing metacharacter case says nothing about the SONiC rule.
  - ``vtysh -c "show techsupport"`` is ACCEPTED. D4 narrows the ``show ...``
    form only ("this narrows LD-45D-5's ``show ...`` form by one subcommand"),
    and the payload after ``vtysh -c`` reaches FRR's vtysh, which has no
    ``techsupport`` command. Recorded as a deliberate scope edge, not an
    oversight.
  - The accepted-form set is LD-45D-5's as narrowed by D2 and D4. Whether any
    other ``show`` subcommand can hang or mutate is NOT enumerated here --
    carried as the session-2 rulings note's UNCOVERED item.

Exit 0 on all-pass; exit 1 on first failure.
"""
import contextlib
import io
import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, _SRC)

import cassian_common as C  # noqa: E402
import cassian_model as M  # noqa: E402
import cassian_nos_sonic as S  # noqa: E402
from cassian_nos_types import is_deferred  # noqa: E402

checks = []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))


def allowed(cmd):
    return M._exec_command_allowed(cmd, "sonic-vm")


# Pre-change text of the two already-wired segments, measured on the tree
# before this change. P-SXA-CLAUSE pins them: SONiC's arrival must not perturb
# one byte of either.
FRR_SEG = 'frr -> vtysh -c "show \u2026"'
NFT_SEG = "nft-fw -> nft list \u2026"
SONIC_SEG = 'sonic-vm -> show \u2026 or vtysh -c "show \u2026" (not show techsupport)'

ACCEPT = [
    "show",
    "show version",
    "show ip bgp summary",
    "show interfaces status",
    "show auto-techsupport",
    "show auto-techsupport global",
    'vtysh -c "show ip bgp summary"',
    'vtysh -c "show"',
    'vtysh -c "SHOW ip route"',
]

REFUSE = [
    # D4
    "show techsupport",
    "show techsupport --allow-process-stop",
    # D2: every non-three-argument vtysh shape the D3 chain proved FRR admits
    'vtysh -c "show version" -c "configure terminal"',
    'vtysh -b -c "show version"',
    'vtysh -c "show version" -f /tmp/x',
    "vtysh -w",
    "vtysh",
    'vtysh -c "configure terminal"',
    'vtysh -x "show ip bgp"',
    'vtysh -c "show ip route" extra',
    # not a declared form at all
    "config interface ip add Ethernet0 1.1.1.1/32",
    "sudo config load /tmp/x.json -y",
    "reboot",
    "bash",
]

# Refused by the MODEL's generic metacharacter check BEFORE the rule is
# dispatched (REQ-45D-6). Kept separate: a passing case here says nothing
# about the SONiC rule, and folding it into REFUSE would make both the
# reason-uniqueness and the non-vacuity assertions measure two layers at once.
REFUSE_MODEL = [
    "sonic-cfggen -a '{}' --write-to-db",
]

# ---- P-SXA-ACCEPT ----------------------------------------------------------
for _c in ACCEPT:
    _ok, _why = allowed(_c)
    check("P-SXA-ACCEPT %r accepted" % _c, _ok, _why)

# ---- P-SXA-REFUSE ----------------------------------------------------------
for _c in REFUSE:
    _ok, _why = allowed(_c)
    check("P-SXA-REFUSE %r refused" % _c, not _ok)

# ---- P-SXA-D4 --------------------------------------------------------------
check(
    "P-SXA-D4 discriminating pair: techsupport refused AND auto-techsupport accepted",
    (not allowed("show techsupport")[0]) and allowed("show auto-techsupport")[0],
)

for _c in REFUSE_MODEL:
    _ok, _why = allowed(_c)
    check("P-SXA-REFUSE %r refused by the MODEL (metacharacter), not the rule" % _c,
          (not _ok) and "metacharacter" in _why)

# ---- P-SXA-REASON ----------------------------------------------------------
_reasons = {allowed(c)[1] for c in REFUSE}
check(
    "P-SXA-REASON one standard refusal reason across %d refusals" % len(REFUSE),
    len(_reasons) == 1,
    "distinct reasons: %d" % len(_reasons),
)

# ---- P-SXA-CLAUSE ----------------------------------------------------------
check("P-SXA-CLAUSE rule is wired (not deferred)", not is_deferred(S.SONIC_PROVIDER.exec_command_rule))

_topo = {
    "name": "sxa",
    "nodes": [
        {
            "name": "s1",
            "type": "sonic-vm",
            "runtime": "vm",
            "image": "local/sonic-vm:202405",
            "asn": 65001,
            "router_id": "192.0.2.11",
            "networks": ["192.0.2.11/32"],
        }
    ],
    "tests": [
        {
            "kind": "exec",
            "src": "s1",
            "command": "config interface ip add Ethernet0 1.1.1.1/32",
            "assertion": {"contains": "x"},
        }
    ],
}
_buf = io.StringIO()
_msg = None
try:
    with contextlib.redirect_stderr(_buf):
        M.resolve_topology(_topo)
except SystemExit:
    _msg = C.LAST_ERROR_MSG

check("P-SXA-CLAUSE a real resolve_topology rejection was produced", _msg is not None)
_msg = _msg or ""
check("P-SXA-CLAUSE rejection carries the derived Allowed clause", "Allowed: " in _msg)
check("P-SXA-CLAUSE frr segment byte-identical", FRR_SEG in _msg)
check("P-SXA-CLAUSE nft-fw segment byte-identical", NFT_SEG in _msg)
check("P-SXA-CLAUSE sonic-vm segment now rendered", SONIC_SEG in _msg)
check(
    "P-SXA-CLAUSE segment order is nos_known_types() order",
    _msg.find(FRR_SEG) < _msg.find(NFT_SEG) < _msg.find(SONIC_SEG),
)

# ---- P-SXA-NV --------------------------------------------------------------
import dataclasses  # noqa: E402


def _with_rule(fn):
    return dataclasses.replace(S.SONIC_PROVIDER, exec_command_rule=fn)


# NOS_PROVIDERS is a mappingproxy (immutable by construction), so the mutants
# rebind the module attribute to a mutable copy and restore it afterwards.
_orig_map = M.NOS_PROVIDERS
try:
    _m = dict(_orig_map)
    _m["sonic-vm"] = _with_rule(lambda argv: (True, ""))
    M.NOS_PROVIDERS = _m
    _over_accept = all(allowed(c)[0] for c in REFUSE)
    _m["sonic-vm"] = _with_rule(lambda argv: (False, "no"))
    M.NOS_PROVIDERS = _m
    _over_reject = not any(allowed(c)[0] for c in ACCEPT)
finally:
    M.NOS_PROVIDERS = _orig_map

check("P-SXA-NV harness detects an over-accepting rule", _over_accept)
check("P-SXA-NV harness detects an over-rejecting rule", _over_reject)
check("P-SXA-NV provider restored after mutation", allowed("show version")[0] and not allowed("reboot")[0])

ok = True
for name, passed in checks:
    print("[%s] %s" % ("PASS" if passed else "FAIL", name))
    ok = ok and passed
print("=" * 60)
print("cases:", len(checks))
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
