#!/usr/bin/env python3
"""SONiC observation-kinds proof, H1-b1 script 1 (§4.5-d; handover §6.7.2, §15.2).

Kinds under test (founder ruling A, 2026-09-25; session-9 corrected invariant):
  REQ-45D-1  bgp_neighbor            REQ-45D-9   bgp_localpref_equals
  REQ-45D-8  bgp_session_up          REQ-45D-10  bgp_med_equals
  REQ-45D-15 bgp_community           REQ-45D-16  bgp_as_path
H1-b2 script 1 (founder rulings A, 2026-09-25, and D1 = P1, 2026-09-29):
  REQ-45D-13 route_advertised_to     REQ-45D-14  route_not_advertised_to

Evidence rule (founder statement, 2026-09-26): SONiC's correctness is proven
from SONiC's own evidence. The inputs are captured SONiC guest output,
committed byte-exact under tests/fixtures/sonic-4_5d-h1b1/ (D4: .out only):
  bgp_summary.out           cap-45d-h1b1.tar  (session-8 note §5)
  ip_bgp_10.1.0.1_32.out    cap-45d-h1b1.tar  stock prefix: no locPrf, no community
  ip_bgp_192.0.2.1_32.out   cap-45d-h1b1.tar  absent-prefix control
  h1b1v_prefix_after.out    cap-45d-h1b1v.tar (session-9 note §4)
The expected VALUES cite capture-procedure-4_5d-h1b1-values.md §1 (CONFIGURED
below), never the capture. "keys = FRR's" (handover §15.2 L463) is the shared
result FORMAT only: FRR's key sets are derived here at run time by running
FRR's own handler over the same bytes and reading its KEYS -- no FRR value is
read or compared.

Sections:
  K-DISPATCH  collect() is wired and routes each kind to its handler; an
              undeclared kind is refused loudly (SystemExit 2).
  K-CAP       re-authored in script 2 (ruling D1): the six kinds are declared
              IMPL, exactly the handler table's keys -- handler-to-token
              consistency, both directions (the check nos_deny_by_default's
              leg (i) makes for FRR only) -- and an undeclared kind stays UNSUP.
  K-<kind>    parse on captured output: configured values (per-prefix kinds),
              recorded facts (summary kinds), and the collection-failure shape.
  K-KEYS      data/evidence key sets equal FRR's, per kind.
  K-LASTUPD   paths[*].lastUpdate is never read (session-9 ruling (1)).
  K-NV        two-directional non-vacuity: every value / key / failure-shape
              predicate above is re-run on a mutated capture and must fail.

H1-b2 inputs: tests/fixtures/sonic-4_5d-h1b2/ from cap-45d-h1b2.tar
(session-14 rulings note §3), a peered capture on the committed pair topology;
the values cite capture-procedure-4_5d-h1b2-advertised.md rev 2 §1
(CONFIGURED_ADV), never the capture. In script 1 the two kinds are wired with
no capability token (K-CAP asserts UNSUP); script 2 flips them. Advertised
entries carry no lastUpdate, so K-LASTUPD does not apply to them. H1-b2 limits
(procedure rev 2 §6): IPv4 unicast, one eBGP neighbour, no outbound filter.

Coverage limits (PBE-P2-8): lab-free, no guest contacted; one image
(local/sonic-vm:202405, FRR 8.5.4); the summary capture has no Established
session and no received route, so -1/-8's up path and -16's received-path
semantics are the (VM) legs' (handover §18), not asserted here.
Exit 0 on all-pass; exit 1 on any failure.
"""
import json
import os
import sys
from types import SimpleNamespace

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "src"))

import cassian_nos_frr as FRR  # noqa: E402
import cassian_nos_sonic as S  # noqa: E402
from cassian_nos_types import CAP_IMPL, CAP_UNSUP, ObservationRequest, capability_for  # noqa: E402

FIX = os.path.join(_HERE, "fixtures", "sonic-4_5d-h1b1")

# capture-procedure-4_5d-h1b1-values.md §1 -- the configured values, fixed
# before capture (sha256 f87f87d1…ba35a). Never read from the capture.
CONFIGURED = {
    "prefix": "198.51.100.0/24",
    "locPrf": 250,
    "metric": 4321,
    "community": "64512:4242",
    "aspath": "64999 64998",
}
# Session-8 note §5 (committed record): the stock guest's summary carries
# neighbour 10.0.0.1 and no Established session. 192.0.2.99 is TEST-NET-1 and
# absent from the capture (measured when this proof was authored).
STOCK_NEIGHBOR = "10.0.0.1"
ABSENT_NEIGHBOR = "192.0.2.99"
STOCK_PREFIX = "10.1.0.1/32"
ABSENT_PREFIX = "192.0.2.1/32"

KINDS = ("bgp_neighbor", "bgp_session_up", "bgp_localpref_equals",
         "bgp_med_equals", "bgp_community", "bgp_as_path")
SUMMARY_KINDS = ("bgp_neighbor", "bgp_session_up")
PREFIX_KINDS = ("bgp_localpref_equals", "bgp_med_equals", "bgp_community", "bgp_as_path")

checks = []


def check(name, cond):
    checks.append((name, bool(cond)))


def guarded(name, thunk):
    """A check whose evaluation may raise: an exception is a FAIL, recorded."""
    try:
        check(name, thunk())
    except BaseException as exc:  # SystemExit included: deferred_leg exits 2
        check(f"{name} [raised {type(exc).__name__}]", False)


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


class FakeRt:
    """Answers every exec with one captured stdout; records the argv."""

    def __init__(self, stdout, rc=0):
        self.stdout, self.rc, self.argvs = stdout, rc, []

    def exec(self, lab, node, argv, check=False, **_kw):
        self.argvs.append(list(argv))
        return SimpleNamespace(returncode=self.rc, stdout=self.stdout, stderr="banner")


def req(kind):
    params = {"neighbor": STOCK_NEIGHBOR} if kind in SUMMARY_KINDS else {"prefix": CONFIGURED["prefix"]}
    return ObservationRequest(kind=kind, params=params)


def run(kind, stdout, rc=0, params=None, provider_collect=None):
    r = ObservationRequest(kind=kind, params=params) if params is not None else req(kind)
    fn = provider_collect or S.collect
    rt = FakeRt(stdout, rc)
    return fn(rt, "lab", "s1", r), rt


def frr_keys(kind, stdout, params=None):
    r = ObservationRequest(kind=kind, params=params) if params is not None else req(kind)
    o = FRR._COLLECT_HANDLERS[kind](FakeRt(stdout), "lab", "s1", r)
    return sorted(o.data), sorted(o.evidence)


SUMMARY = load("bgp_summary.out")
AFTER = load("h1b1v_prefix_after.out")
STOCK = load("ip_bgp_10.1.0.1_32.out")
ABSENT = load("ip_bgp_192.0.2.1_32.out")

# -- H1-b2 (script 1): route_advertised_to / route_not_advertised_to --------
# capture-procedure-4_5d-h1b2-advertised.md rev 2 §1 -- the configured values,
# fixed before capture (sha256 2e7ca8bd…2e68f). Never read from the capture,
# which is committed byte-exact under tests/fixtures/sonic-4_5d-h1b2/ (D4):
#   h1b2_adv_after.out       Established neighbour, test prefix advertised
#   h1b2_adv_before.out      Established neighbour, before configuration
#   h1b2_adv_noneighbor.out  the absent-neighbour read (rc 0, warning object)
FIX2 = os.path.join(_HERE, "fixtures", "sonic-4_5d-h1b2")
CONFIGURED_ADV = {
    "peer_ip": "198.51.100.1",      # s2, as s1 sees it on the pair link
    "prefix": "203.0.113.0/24",     # the test prefix s1 originates
    "control": "192.0.2.1/32",      # absent control: never a key
    "absent_peer": "203.0.113.99",  # no such neighbour
}
ADV_KINDS = ("route_advertised_to", "route_not_advertised_to")


def load2(name):
    with open(os.path.join(FIX2, name), encoding="utf-8") as fh:
        return fh.read()


ADV_AFTER = load2("h1b2_adv_after.out")
ADV_BEFORE = load2("h1b2_adv_before.out")
ADV_NONEIGHBOR = load2("h1b2_adv_noneighbor.out")


def adv_params(peer=None):
    return {"peer_ip": peer or CONFIGURED_ADV["peer_ip"], "prefix": CONFIGURED_ADV["prefix"]}


def mutate_json(text, fn):
    doc = json.loads(text)
    fn(doc)
    return json.dumps(doc)


# ---------------------------------------------------------------- predicates
def full_keys(obs, kind, stdout, params=None):
    dk, ek = frr_keys(kind, stdout, params)
    return sorted(obs.data) == dk and sorted(obs.evidence) == ek


def failed_collection(obs, kind, stdout, params=None):
    """A collection failure: parse_error named, every key still present."""
    return bool(obs.evidence.get("parse_error")) and full_keys(obs, kind, stdout, params)


def configured_value(kind, obs):
    d, e = obs.data, obs.evidence
    if e.get("parse_error") or e.get("probe_ok") is not True:
        return False
    if d.get("norm_prefix") != CONFIGURED["prefix"]:
        return False
    if kind == "bgp_localpref_equals":
        return d.get("observed_localpref") == CONFIGURED["locPrf"]
    if kind == "bgp_med_equals":
        return d.get("observed_med") == CONFIGURED["metric"]
    if kind == "bgp_community":
        return d.get("route_present") is True and d.get("observed_communities") == [CONFIGURED["community"]]
    if kind == "bgp_as_path":
        return d.get("route_present") is True and d.get("observed_as_path") == CONFIGURED["aspath"]
    return False


def stock_neighbor_fact(kind, obs):
    d, e = obs.data, obs.evidence
    if e.get("parse_error") or e.get("probe_ok") is not True:
        return False
    state = d.get("state")
    if not (isinstance(state, str) and state and state.lower() != "established"):
        return False
    if kind == "bgp_neighbor":
        return d.get("observed") == "down"
    return d.get("peer_present") is True and d.get("last_error") == ""


try:
    # -------------------------------------------------------------- K-DISPATCH
    check("K-DISPATCH collect is wired (no longer the deferred placeholder)",
          S.SONIC_PROVIDER.collect is S.collect and not hasattr(S.collect, "cassian_deferred_leg"))
    check("K-DISPATCH handler table holds exactly the six H1-b1 kinds and the two H1-b2 kinds",
          sorted(S._SONIC_COLLECT_HANDLERS) == sorted(KINDS + ADV_KINDS))
    for k in KINDS:
        want = list(S._BGP_SUMMARY_ARGV) if k in SUMMARY_KINDS else ["vtysh", "-c", f"show ip bgp {CONFIGURED['prefix']} json"]

        def _dispatch(k=k, want=want):
            o, rt = run(k, SUMMARY if k in SUMMARY_KINDS else AFTER)
            return o.kind == k and rt.argvs == [want]
        guarded(f"K-DISPATCH {k}: Observation.kind == {k!r}, exactly one guest read, argv {want!r}", _dispatch)
    try:
        run("route_present", AFTER, params={"prefix": CONFIGURED["prefix"]})
        refused = False
    except SystemExit as e:
        refused = (e.code == 2)
    check("K-DISPATCH an undeclared kind (route_present) is refused loudly (SystemExit 2)", refused)

    # ------------------------------------------------------------------- K-CAP
    for k in KINDS:
        check(f"K-CAP {k}: declared IMPL (script 2, ruling D1)",
              capability_for(S.SONIC_PROVIDER, k).state == CAP_IMPL)
    # Coverage limit (PBE-P2-8): the two §4.5-c operational legs are named here by
    # hand; any further IMPL token without a handler reds this check for review.
    _impl_toks = {tok for tok, d in S.SONIC_PROVIDER.capabilities.items() if d.state == CAP_IMPL}
    check("K-CAP every H1-b1 handler has an IMPL token and the two H1-b2 handlers have none "
          "(script 1; the flip is script 2); IMPL tokens without a handler are exactly the "
          "§4.5-c legs gen_node_config, provision",
          set(S._SONIC_COLLECT_HANDLERS) - set(ADV_KINDS) <= _impl_toks
          and not (set(ADV_KINDS) & _impl_toks)
          and _impl_toks - set(S._SONIC_COLLECT_HANDLERS) == {"gen_node_config", "provision"})
    check("K-CAP an undeclared kind (route_present) stays UNSUP",
          capability_for(S.SONIC_PROVIDER, "route_present").state == CAP_UNSUP)

    # -------------------------------------------------------- K-<kind> (values)
    for k in SUMMARY_KINDS:
        o, _ = run(k, SUMMARY)
        check(f"K-{k} stock neighbour {STOCK_NEIGHBOR}: present, not Established, no parse error",
              stock_neighbor_fact(k, o))
        o, _ = run(k, SUMMARY, params={"neighbor": ABSENT_NEIGHBOR})
        check(f"K-{k} absent neighbour: collection failure naming absence",
              failed_collection(o, k, SUMMARY, {"neighbor": ABSENT_NEIGHBOR})
              and o.evidence["parse_error"] == "neighbor not present in summary")
    o, _ = run("bgp_session_up", SUMMARY, params={"neighbor": ABSENT_NEIGHBOR})
    check("K-bgp_session_up absent neighbour: peer_present False, state NotConfigured",
          o.data["peer_present"] is False and o.data["state"] == "NotConfigured")

    for k in PREFIX_KINDS:
        o, _ = run(k, AFTER)
        check(f"K-{k} configured value on {CONFIGURED['prefix']} (procedure §1)", configured_value(k, o))
        o, _ = run(k, ABSENT, params={"prefix": ABSENT_PREFIX})
        check(f"K-{k} absent prefix {ABSENT_PREFIX}: collection failure",
              failed_collection(o, k, ABSENT, {"prefix": ABSENT_PREFIX})
              and o.evidence["parse_error"] == "prefix not present in bgp json")
        o, _ = run(k, AFTER, rc=1)
        check(f"K-{k} failed read (rc 1): probe_ok False", o.evidence["probe_ok"] is False)

    o, _ = run("bgp_localpref_equals", STOCK, params={"prefix": STOCK_PREFIX})
    check("K-bgp_localpref_equals stock prefix (no locPrf, session-8 note §5): collection failure",
          o.data["observed_localpref"] is None and o.evidence["parse_error"] == "localpref not present in bgp json")
    o, _ = run("bgp_community", STOCK, params={"prefix": STOCK_PREFIX})
    check("K-bgp_community stock prefix (no community): route present, no communities, no failure",
          o.data["route_present"] is True and o.data["observed_communities"] == [] and not o.evidence["parse_error"])

    # ------------------------------------------------------------------ K-KEYS
    for k in KINDS:
        stdout = SUMMARY if k in SUMMARY_KINDS else AFTER
        o, _ = run(k, stdout)
        check(f"K-KEYS {k}: data and evidence keys equal FRR's (derived at run time)",
              full_keys(o, k, stdout))

    # --------------------------------------------------------------- K-LASTUPD
    def _scramble_lastupdate(doc):
        for p in doc["paths"]:
            p["lastUpdate"] = {"epoch": "not-a-number", "string": None}


    SCRAMBLED = mutate_json(AFTER, _scramble_lastupdate)
    for k in PREFIX_KINDS:
        def _same(k=k):
            a, _ = run(k, AFTER)
            b, _ = run(k, SCRAMBLED)
            return a.data == b.data and a.evidence == b.evidence
        guarded(f"K-LASTUPD {k}: observation identical with lastUpdate scrambled", _same)

    # ---------------------------------------------------------------------- K-NV
    # Direction 1: each value predicate FAILS on a capture whose value moved.
    MOVED = {
        "bgp_localpref_equals": lambda d: d["paths"][0].__setitem__("locPrf", 251),
        "bgp_med_equals": lambda d: d["paths"][0].__setitem__("metric", 4322),
        "bgp_community": lambda d: d["paths"][0].__setitem__("community", {"string": "64512:4243", "list": ["64512:4243"]}),
        "bgp_as_path": lambda d: d["paths"][0]["aspath"].__setitem__("string", "64998 64999"),
    }
    for k, fn in MOVED.items():
        o, _ = run(k, mutate_json(AFTER, fn))
        check(f"K-NV {k}: a moved value is detected (predicate fails)", not configured_value(k, o))

    # Direction 2: each key-drop / malformed capture is a collection failure, and
    # the "present value" predicate fails on it.
    DROPPED = {
        "bgp_localpref_equals": lambda d: d["paths"][0].pop("locPrf"),
        "bgp_med_equals": lambda d: d["paths"][0].pop("metric"),
        "bgp_community": lambda d: d["paths"][0].__setitem__("community", "64512:4242"),
        "bgp_as_path": lambda d: d["paths"][0].pop("aspath"),
    }
    for k, fn in DROPPED.items():
        bad = mutate_json(AFTER, fn)
        o, _ = run(k, bad)
        check(f"K-NV {k}: key-drop is a collection failure, never a partial data",
              failed_collection(o, k, bad) and not configured_value(k, o))
    NOPATHS = mutate_json(AFTER, lambda d: d.pop("paths"))
    for k in PREFIX_KINDS:
        o, _ = run(k, NOPATHS)
        check(f"K-NV {k}: paths removed is a collection failure", failed_collection(o, k, NOPATHS))
        o, _ = run(k, "{ not json")
        check(f"K-NV {k}: malformed output is a collection failure",
              o.evidence["parse_error"] == "vtysh output not parseable as JSON")


    def _drop_state(doc):
        doc["ipv4Unicast"]["peers"][STOCK_NEIGHBOR].pop("state")


    NOSTATE = mutate_json(SUMMARY, _drop_state)
    for k in SUMMARY_KINDS:
        o, _ = run(k, NOSTATE)
        check(f"K-NV {k}: neighbour state dropped is a collection failure, predicate fails",
              failed_collection(o, k, NOSTATE) and not stock_neighbor_fact(k, o))
    EST = mutate_json(SUMMARY, lambda d: d["ipv4Unicast"]["peers"][STOCK_NEIGHBOR].__setitem__("state", "Established"))
    o, _ = run("bgp_neighbor", EST)
    check("K-NV bgp_neighbor: an Established neighbour reads up, so the stock fact fails",
          o.data["observed"] == "up" and not stock_neighbor_fact("bgp_neighbor", o))

    # The key-parity predicate itself can fail: drop one data key.
    o, _ = run("bgp_as_path", AFTER)
    short = SimpleNamespace(kind=o.kind, data={k: v for k, v in o.data.items() if k != "route_present"},
                            evidence=o.evidence)
    check("K-NV K-KEYS detects a dropped data key", not full_keys(short, "bgp_as_path", AFTER))


    # ================================================ H1-b2 script 1 (-13, -14)
    # K-DISPATCH: both kinds route to the one advertised-routes handler, one
    # guest read, the advertised-routes argv for the requested neighbour.
    ADV_ARGV = ["vtysh", "-c", f"show ip bgp neighbor {CONFIGURED_ADV['peer_ip']} advertised-routes json"]
    for k in ADV_KINDS:
        def _adv_dispatch(k=k):
            o, rt = run(k, ADV_AFTER, params=adv_params())
            return o.kind == k and rt.argvs == [ADV_ARGV]
        guarded(f"K-DISPATCH {k}: Observation.kind == {k!r}, exactly one guest read, argv {ADV_ARGV!r}",
                _adv_dispatch)
    check("K-DISPATCH both advertised kinds share one handler (as FRR's do)",
          S._SONIC_COLLECT_HANDLERS["route_advertised_to"] is S._SONIC_COLLECT_HANDLERS["route_not_advertised_to"])

    # K-CAP (script 1): not declared -- the flip is script 2.
    for k in ADV_KINDS:
        check(f"K-CAP {k}: not declared in script 1; stays UNSUP until the script-2 flip",
              capability_for(S.SONIC_PROVIDER, k).state == CAP_UNSUP)

    def adv_ok(o):
        return o.evidence.get("probe_ok") is True and o.evidence.get("parse_error") == ""

    def advertised_configured(o):
        d = o.data
        return (adv_ok(o) and d.get("norm_prefix") == CONFIGURED_ADV["prefix"]
                and CONFIGURED_ADV["prefix"] in d.get("advertised_prefixes", [])
                and d.get("present") is True)

    def control_absent(o):
        return adv_ok(o) and CONFIGURED_ADV["control"] not in o.data.get("advertised_prefixes", [])

    def not_yet_advertised(o):
        d = o.data
        return (adv_ok(o) and d.get("present") is False
                and CONFIGURED_ADV["prefix"] not in d.get("advertised_prefixes", [])
                and len(d.get("advertised_prefixes", [])) > 0)

    def adv_failed(o, stdout, params):
        return (failed_collection(o, o.kind, stdout, params)
                and o.data.get("advertised_prefixes") == [] and o.data.get("present") is False)

    # K-<kind>: parse on captured output. Values cite procedure rev 2 §1; the
    # non-empty BEFORE set is the recorded fact of session-14 note §3.
    _absent = adv_params(CONFIGURED_ADV["absent_peer"])
    for k in ADV_KINDS:
        o, _ = run(k, ADV_AFTER, params=adv_params())
        check(f"K-{k} after configuration: {CONFIGURED_ADV['prefix']} advertised to "
              f"{CONFIGURED_ADV['peer_ip']} (procedure §1)", advertised_configured(o))
        check(f"K-{k} after configuration: control {CONFIGURED_ADV['control']} not advertised (procedure §1)",
              control_absent(o))
        o, _ = run(k, ADV_BEFORE, params=adv_params())
        check(f"K-{k} before configuration: test prefix not advertised, set non-empty (session-14 note §3)",
              not_yet_advertised(o))
        o, _rt = run(k, ADV_NONEIGHBOR, params=_absent)
        check(f"K-{k} absent neighbour {CONFIGURED_ADV['absent_peer']}: collection failure, "
              "never an empty advertised set",
              adv_failed(o, ADV_NONEIGHBOR, _absent)
              and o.evidence["parse_error"].startswith("advertisedRoutes not present in advertised-routes json"))
        check(f"K-DISPATCH {k}: the requested neighbour {CONFIGURED_ADV['absent_peer']} is the one read",
              _rt.argvs == [["vtysh", "-c",
                             f"show ip bgp neighbor {CONFIGURED_ADV['absent_peer']} advertised-routes json"]])
        o, _ = run(k, ADV_AFTER, rc=1, params=adv_params())
        check(f"K-{k} failed read (rc 1): probe_ok False", o.evidence["probe_ok"] is False)
        o, _ = run(k, ADV_AFTER, params=adv_params())
        check(f"K-KEYS {k}: data and evidence keys equal FRR's (derived at run time)",
              full_keys(o, k, ADV_AFTER, adv_params()))

    # K-NV direction 1: each value predicate fails on a capture whose value moved.
    _nv = mutate_json(ADV_AFTER, lambda d: d["advertisedRoutes"].pop(CONFIGURED_ADV["prefix"]))
    o, _ = run("route_advertised_to", _nv, params=adv_params())
    check("K-NV advertised: the test prefix removed from the capture is detected", not advertised_configured(o))
    _nv = mutate_json(ADV_AFTER, lambda d: d["advertisedRoutes"].__setitem__(CONFIGURED_ADV["control"], {}))
    o, _ = run("route_not_advertised_to", _nv, params=adv_params())
    check("K-NV advertised: the control added to the capture is detected", not control_absent(o))
    _nv = mutate_json(ADV_BEFORE, lambda d: d["advertisedRoutes"].__setitem__(CONFIGURED_ADV["prefix"], {}))
    o, _ = run("route_not_advertised_to", _nv, params=adv_params())
    check("K-NV advertised: the test prefix added to the before capture is detected", not not_yet_advertised(o))
    _nv = mutate_json(ADV_BEFORE, lambda d: d["advertisedRoutes"].clear())
    o, _ = run("route_not_advertised_to", _nv, params=adv_params())
    check("K-NV advertised: an empty advertised set fails the non-empty before fact", not not_yet_advertised(o))
    # Direction 2: a key-drop or malformed capture is a collection failure.
    _bad = (
        ("advertisedRoutes removed", mutate_json(ADV_AFTER, lambda d: d.pop("advertisedRoutes"))),
        ("a key that is not a prefix", mutate_json(ADV_AFTER, lambda d: d["advertisedRoutes"].__setitem__("not-a-prefix", {}))),
        ("advertisedRoutes not a mapping", mutate_json(ADV_AFTER, lambda d: d.__setitem__("advertisedRoutes", [CONFIGURED_ADV["prefix"]]))),
        ("malformed output", "{ not json"),
    )
    for name, bad in _bad:
        for k in ADV_KINDS:
            o, _ = run(k, bad, params=adv_params())
            check(f"K-NV {k}: {name} is a collection failure, never a partial set",
                  adv_failed(o, bad, adv_params()) and not advertised_configured(o))
    # The absent-neighbour predicate itself can fail: a good read is not a failure.
    o, _ = run("route_not_advertised_to", ADV_AFTER, params=adv_params())
    check("K-NV the collection-failure predicate fails on a good read", not adv_failed(o, ADV_AFTER, adv_params()))

except BaseException as _exc:  # a section aborted: record it, never exit silently
    check(f"proof aborted in a section [raised {type(_exc).__name__}: {_exc}]", False)

ok = True
for name, passed in checks:
    print("[%s] %s" % ("PASS" if passed else "FAIL", name))
    ok = ok and passed
print("=" * 60)
print("cases:", len(checks))
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
