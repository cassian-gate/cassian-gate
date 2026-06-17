#!/usr/bin/env python3
"""
bgp_community set.community proof (P20 + P21).

§4.10 WI-1 GEN-1/GEN-2 (Amendment A1). Two lab-free obligations against the real
seams in cassian_model.py:

  P20 (REQ-BGPCOM-GEN-1, emission) -- the route-map `set community` emission in
  gen_frr_conf is a deterministic, fixed function of the declared `set.community`
  value: scalar/list, declared order, well-known tokens emitted verbatim, empty
  elements dropped, no-key -> no line, identical declaration -> byte-identical config.

  P21 (REQ-BGPCOM-GEN-2, validation) -- resolve_topology hard-fails a malformed
  route-map `set.community` with a DC v2.1 §13(a)-sufficient message (what / where
  {node + route-map} / what-would-be-valid), reusing the shared community-specifier
  validator; well-formed `set.community` resolves without false-fail; the
  topologies/neg misuse fixture is rejected.

Exit 0 on all-pass; exit 1 on first failure.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import yaml  # noqa: E402
import cassian_common as _cc  # noqa: E402
_cc._QUIET_DIE = True
import cassian_model as cm  # noqa: E402


# ----------------------------------------------------------------- P20 helpers
def _gen_node(set_block):
    return {
        "name": "r2", "type": "frr", "asn": 65002, "router_id": "2.2.2.2",
        "bgp": {"route_maps": [
            {"name": "SET-COMM",
             "entries": [{"seq": 10, "action": "permit", "set": set_block}]}
        ]},
    }


def _render(set_block):
    node = _gen_node(set_block)
    return cm.gen_frr_conf(node, {"name": "t", "nodes": [node], "links": []})


def _community_lines(cfg):
    return [ln for ln in cfg.splitlines() if ln.strip().startswith("set community")]


# ----------------------------------------------------------------- P21 helpers
def _reject_topo(community):
    """Well-formed frr node whose route-map set.community is `community`."""
    n = {"name": "r2", "type": "frr", "asn": 65002, "router_id": "2.2.2.2",
         "bgp": {"route_maps": [
             {"name": "RM-OUT",
              "entries": [{"seq": 10, "action": "permit", "set": {"community": community}}]}
         ]}}
    return {"name": "t", "nodes": [n, {"name": "h1", "type": "host"}], "links": [], "tests": []}


def _resolve(topo):
    try:
        cm.resolve_topology(topo)
        return ("ok", "")
    except SystemExit as e:
        return ("die", str(e))


def main():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # ============================= P20 -- GEN-1 emission =====================
    check("P20a scalar AS:VAL",
          _community_lines(_render({"community": "65000:100"})) == [" set community 65000:100"])
    for tok in ("no-export", "no-advertise", "local-AS", "internet"):
        check(f"P20b well-known {tok} verbatim",
              _community_lines(_render({"community": tok})) == [f" set community {tok}"])
    check("P20c list declared order",
          _community_lines(_render({"community": ["65000:100", "no-export"]}))
          == [" set community 65000:100 no-export"])
    check("P20d all well-known declared order",
          _community_lines(_render({"community": ["no-export", "no-advertise", "local-AS", "internet"]}))
          == [" set community no-export no-advertise local-AS internet"])
    check("P20e reversed declaration -> reversed emission",
          _community_lines(_render({"community": ["internet", "local-AS", "no-advertise", "no-export"]}))
          == [" set community internet local-AS no-advertise no-export"])
    check("P20f whitespace elements dropped",
          _community_lines(_render({"community": ["65000:100", "  ", "", "no-export"]}))
          == [" set community 65000:100 no-export"])
    check("P20g scalar whitespace stripped",
          _community_lines(_render({"community": "  65000:100  "})) == [" set community 65000:100"])
    check("P20h no-community-key -> no line",
          _community_lines(_render({"med": 100})) == [])
    check("P20i empty scalar -> no line", _community_lines(_render({"community": ""})) == [])
    check("P20i empty list -> no line", _community_lines(_render({"community": []})) == [])
    check("P20j non-str/list -> no line", _community_lines(_render({"community": 12345})) == [])
    decl = ["65000:100", "no-export", "local-AS"]
    check("P20k render deterministic (byte-identical)",
          _render({"community": list(decl)}) == _render({"community": list(decl)}))
    cfg = _render({"community": "65000:100"})
    lines = cfg.splitlines()
    try:
        ci = next(i for i, ln in enumerate(lines) if ln.strip() == "set community 65000:100")
        rmi = next(i for i, ln in enumerate(lines) if ln.startswith("route-map SET-COMM permit 10"))
        ordered = rmi < ci
    except StopIteration:
        ordered = False
    check("P20l set community emitted under its route-map clause", ordered)

    # ============================= P21 -- GEN-2 validation ==================
    # positives: well-formed set.community resolves (no false-fail)
    o, _ = _resolve(_reject_topo("65000:100"))
    check("P21-NEG valid scalar resolves", o == "ok")
    o, _ = _resolve(_reject_topo(["65000:100", "no-export", "local-AS", "internet"]))
    check("P21-NEG valid list resolves", o == "ok")

    # malformed scalar
    o, m = _resolve(_reject_topo("bogus"))
    check("P21a malformed scalar rejected",
          o == "die" and "set.community value 'bogus' is malformed" in m)
    # malformed list element
    o, m = _resolve(_reject_topo(["65000:100", "x"]))
    check("P21b malformed list element rejected",
          o == "die" and "set.community value 'x' is malformed" in m)
    # non-str / non-list community
    o, m = _resolve(_reject_topo(12345))
    check("P21c non-str/list rejected",
          o == "die" and "set.community must be a community string or a list" in m)

    # §13(a) sufficiency on a representative rejection
    o, m = _resolve(_reject_topo("bogus"))
    check("P21d-(a) names what (value malformed)", "value 'bogus' is malformed" in m)
    check("P21d-(b) names where (node)", "node 'r2'" in m)
    check("P21d-(b) names where (route-map)", "route-map 'RM-OUT'" in m)
    check("P21d-(c) names valid-form",
          "expected AS:VAL or one of no-export, no-advertise, local-AS, internet" in m)

    # determinism: identical malformed input -> identical message
    _, m1 = _resolve(_reject_topo("bogus"))
    _, m2 = _resolve(_reject_topo("bogus"))
    check("P21e rejection deterministic", m1 == m2)

    # topologies/neg misuse fixture is rejected
    neg = os.path.join(os.path.dirname(_HERE), "topologies", "neg",
                       "bgp_community_set_community_malformed.yaml")
    with open(neg) as fh:
        neg_topo = yaml.safe_load(fh)
    o, m = _resolve(neg_topo)
    check("P21f neg fixture rejected",
          o == "die" and "set.community value 'bogus' is malformed" in m and "node 'r2'" in m)

    # ================================ report ================================
    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    print(f"\n{passed}/{len(checks)} checks passed")
    sys.exit(0 if passed == len(checks) else 1)


if __name__ == "__main__":
    main()
