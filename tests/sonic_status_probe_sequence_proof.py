#!/usr/bin/env python3
"""tests/sonic_status_probe_sequence_proof.py -- 4.5-c WI-9 probe sequence.

Req-IDs: REQ-45C-16 (per-mode probe counts 1/2/2/2, fixed by reuse)
         REQ-45C-37 (--bgp-verbose text-mode output byte-identical across fix)
         REQ-45C-38 (SONiC summary leg born with the reuse shape)

Snapshot mapping (handover 6.7.2 mapping discipline): modules consumed are
`cassian_nos_frr` -> `src/cassian_nos_frr.py` and `cassian_nos_sonic` ->
`src/cassian_nos_sonic.py`. Session snapshot v48 == branch
`feature/4_5c-sonic-base-lifecycle`; the handover's authoring pin was v45 ==
`b129510`, which the branch has advanced past.

Lab-free. Probe counts are measured by a recording stub standing in for the
Runtime, so the leg's real code path runs and the calls it issues are counted
rather than asserted from reading.

SCOPE OF THE SONiC HALF (REQ-45C-38), stated rather than left implicit.
Founder ruling 2026-08-18 (reading B, R-C3-16) landed the FRR half first and
discharged REQ-45C-38 as a RATCHET: leg 4 failed loud the moment either SONiC
status leg became callable, obliging whoever wired it to add the per-mode
counts here. §4.5-d wired both legs (REQ-45D-19) and, under founder ruling
S27-R11 of 2026-10-09, leg 4 now COUNTS them on the same recording stub: the
SONiC summary leg is born 1/2/2/2 with the raw text reused, never re-fetched,
and the routes leg issues 1 probe when the JSON parses and 2 on fallback, as
FRR's legs are counted above.

COVERAGE LIMITS (PBE-P2-8):
  * Counts are measured against a stub Runtime. This proves the leg issues N
    probes; it does not prove vtysh behaves as the stub does on a live node.
  * REQ-45C-37 byte-identity is proven for a FIXED fixture. It cannot prove
    two live fetches would have agreed -- that they might NOT agree is the
    argument for reuse, not against it.
  * The ratchet detects a SONiC leg becoming callable. It cannot detect a
    SONiC summary implemented somewhere other than the provider record.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cassian_nos_frr as F  # noqa: E402
from cassian_nos_sonic import SONIC_PROVIDER  # noqa: E402

_checks = []


def check(name, ok, detail=""):
    _checks.append((name, bool(ok), detail))


SUMMARY_TEXT = (
    "BGP router identifier 10.10.10.1, local AS number 65001 vrf-id 0\n"
    "Neighbor        V   AS   MsgRcvd  MsgSent  Up/Down State/PfxRcd\n"
    "10.0.0.2        4 65002      12       12  00:01:02            3\n"
)
SUMMARY_JSON_OK = (
    '{"ipv4Unicast":{"peers":{"10.0.0.2":{"state":"Established",'
    '"remoteAs":65002,"pfxRcd":3}}}}'
)
SUMMARY_JSON_BAD = "% Unknown command\n"


class _CP:
    def __init__(self, out):
        self.stdout = out.encode("utf-8")
        self.stderr = b""
        self.returncode = 0


class RecordingRuntime:
    """Stands in for Runtime; records every exec and replays scripted stdout."""

    def __init__(self, json_out, text_outs):
        self.json_out = json_out
        self.text_outs = list(text_outs)
        self.calls = []

    def exec(self, lab, node, cmd, check=False, capture_output=True):
        self.calls.append(list(cmd))
        joined = " ".join(cmd)
        if joined.endswith("show bgp summary json"):
            return _CP(self.json_out)
        if joined.endswith("show bgp summary"):
            return _CP(self.text_outs.pop(0) if self.text_outs else "")
        if joined.endswith("show ip route json"):
            return _CP(self.json_out)
        if joined.endswith("show ip route"):
            return _CP(self.text_outs.pop(0) if self.text_outs else "")
        return _CP("")


def _run_summary(json_out, text_outs, want_raw):
    rt = RecordingRuntime(json_out, text_outs)
    obs = F._status_bgp_summary(rt, "lab", "r1", want_raw=want_raw)
    return rt, obs


# --- LEG 1 (REQ-45C-16): per-mode probe counts are 1/2/2/2 -------------------
_rt, _o = _run_summary(SUMMARY_JSON_OK, [], False)
check("REQ-45C-16 mode json / no-raw issues 1 probe", len(_rt.calls) == 1,
      "cmds: %s" % [" ".join(c[2:]) for c in _rt.calls])
check("REQ-45C-16 mode json / no-raw parses as json",
      _o.data["parser_mode"] == "json")

_rt, _o = _run_summary(SUMMARY_JSON_BAD, [SUMMARY_TEXT], False)
check("REQ-45C-16 mode text / no-raw issues 2 probes", len(_rt.calls) == 2,
      "cmds: %s" % [" ".join(c[2:]) for c in _rt.calls])
check("REQ-45C-16 mode text / no-raw parses as text",
      _o.data["parser_mode"] == "text")

_rt, _o = _run_summary(SUMMARY_JSON_OK, [SUMMARY_TEXT], True)
check("REQ-45C-16 mode json / raw issues 2 probes", len(_rt.calls) == 2,
      "cmds: %s" % [" ".join(c[2:]) for c in _rt.calls])

_rt4, _o4 = _run_summary(SUMMARY_JSON_BAD, [SUMMARY_TEXT, "SECOND-FETCH"], True)
check("REQ-45C-16 mode text / raw issues 2 probes, not 3 "
      "(the repaired double-fetch)", len(_rt4.calls) == 2,
      "cmds: %s" % [" ".join(c[2:]) for c in _rt4.calls])

# --- LEG 1 non-vacuity: the count discriminates, and reuse is real -----------
# The stub's SECOND `show bgp summary` would return different bytes. Under the
# pre-fix code raw_text would be "SECOND-FETCH"; under reuse it is the fallback
# text. This check FAILS on the old implementation -- it is the discriminator.
check("REQ-45C-16 NON-VACUITY: raw text is REUSED, not re-fetched",
      _o4.data["raw_text"] == SUMMARY_TEXT.strip()
      and _o4.data["raw_text"] != "SECOND-FETCH",
      "a re-fetch would have returned the stub's second scripted value")
check("REQ-45C-16 NON-VACUITY: the recorder observes calls at all",
      len(_rt4.calls) > 0 and _rt4.calls[0][-1].endswith("json"),
      "proves the counter is wired to the real code path")

# --- LEG 2 (REQ-45C-37): --bgp-verbose text-mode byte-identity ---------------
check("REQ-45C-37 text-mode raw output is byte-identical to the fetched text",
      _o4.data["raw_text"] == SUMMARY_TEXT.strip(),
      "%d bytes" % len(_o4.data["raw_text"] or ""))
_rtA, _oA = _run_summary(SUMMARY_JSON_BAD, [SUMMARY_TEXT, "X"], True)
_rtB, _oB = _run_summary(SUMMARY_JSON_BAD, [SUMMARY_TEXT, "Y"], True)
check("REQ-45C-37 two runs over a fixed fixture agree byte-for-byte",
      _oA.data["raw_text"] == _oB.data["raw_text"])

# --- LEG 3: the routes leg is the mirrored model and still never re-fetches --
_rt = RecordingRuntime(SUMMARY_JSON_BAD, [SUMMARY_TEXT])
F._status_routes(_rt, "lab", "r1")
check("REQ-45C-16 routes leg (the mirrored model) issues 2 probes on fallback",
      len(_rt.calls) == 2, "cmds: %s" % [" ".join(c[2:]) for c in _rt.calls])
_rt = RecordingRuntime('{"10.0.0.0/24":[{"protocol":"bgp"}]}', [])
F._status_routes(_rt, "lab", "r1")
check("REQ-45C-16 routes leg issues 1 probe when json parses",
      len(_rt.calls) == 1)

# --- LEG 4 (REQ-45C-38; founder ruling S27-R11): the SONiC legs, counted -----
# Wired at §4.5-d (REQ-45D-19). The ratchet that stood here obliged these
# counts; they run the shipped SONiC legs on the same recording stub.
_s_sum = SONIC_PROVIDER.status_bgp_summary
_s_rts = SONIC_PROVIDER.status_routes
check("REQ-45C-38 SONiC summary and routes legs are wired (callable)",
      callable(_s_sum) and callable(_s_rts))


def _run_sonic_summary(json_out, text_outs, want_raw):
    rt = RecordingRuntime(json_out, text_outs)
    obs = _s_sum(rt, "lab", "s1", want_raw=want_raw)
    return rt, obs


_rt, _o = _run_sonic_summary(SUMMARY_JSON_OK, [], False)
check("REQ-45C-38 SONiC mode json / no-raw issues 1 probe", len(_rt.calls) == 1,
      "cmds: %s" % [" ".join(c[2:]) for c in _rt.calls])
check("REQ-45C-38 SONiC mode json / no-raw parses as json",
      _o.data["parser_mode"] == "json")
_rt, _o = _run_sonic_summary(SUMMARY_JSON_BAD, [SUMMARY_TEXT], False)
check("REQ-45C-38 SONiC mode text / no-raw issues 2 probes", len(_rt.calls) == 2,
      "cmds: %s" % [" ".join(c[2:]) for c in _rt.calls])
check("REQ-45C-38 SONiC mode text / no-raw parses as text",
      _o.data["parser_mode"] == "text")
_rt, _o = _run_sonic_summary(SUMMARY_JSON_OK, [SUMMARY_TEXT], True)
check("REQ-45C-38 SONiC mode json / raw issues 2 probes", len(_rt.calls) == 2,
      "cmds: %s" % [" ".join(c[2:]) for c in _rt.calls])
_srt4, _so4 = _run_sonic_summary(SUMMARY_JSON_BAD, [SUMMARY_TEXT, "SECOND-FETCH"], True)
check("REQ-45C-38 SONiC mode text / raw issues 2 probes, not 3 (born with the "
      "reuse shape)", len(_srt4.calls) == 2,
      "cmds: %s" % [" ".join(c[2:]) for c in _srt4.calls])
check("REQ-45C-38 NON-VACUITY: SONiC raw text is REUSED, not re-fetched",
      _so4.data["raw_text"] == SUMMARY_TEXT.strip()
      and _so4.data["raw_text"] != "SECOND-FETCH",
      "a re-fetch would have returned the stub's second scripted value")
check("REQ-45C-38 NON-VACUITY: the recorder observes the SONiC leg's calls",
      len(_srt4.calls) > 0 and _srt4.calls[0][-1].endswith("json"))
_rt = RecordingRuntime(SUMMARY_JSON_BAD, [SUMMARY_TEXT])
_s_rts(_rt, "lab", "s1")
check("REQ-45C-38 SONiC routes leg issues 2 probes on fallback", len(_rt.calls) == 2,
      "cmds: %s" % [" ".join(c[2:]) for c in _rt.calls])
_rt = RecordingRuntime('{"10.0.0.0/24":[{"protocol":"bgp"}]}', [])
_s_rts(_rt, "lab", "s1")
check("REQ-45C-38 SONiC routes leg issues 1 probe when json parses",
      len(_rt.calls) == 1)

# --- Report ------------------------------------------------------------------
_fails = [c for c in _checks if not c[1]]
for _n, _ok, _d in _checks:
    print("%s %s%s" % ("PASS" if _ok else "FAIL", _n,
                       ("  [%s]" % _d) if _d else ""))
print("=" * 60)
print("RESULT: %s -- %d checks (WI-9 status probe sequence)"
      % ("PASS" if not _fails else "FAIL", len(_checks)))
if _fails:
    sys.exit("sonic_status_probe_sequence_proof FAILED (%d check(s))."
             % len(_fails))
