#!/usr/bin/env python3
"""
BL-H3-8 render-boundary proof — scenarios-summary existing-type rendering (§4.3).

Proves that cassian_tests._render_scenarios_summary renders the type label and
the type-specific endpoint/selector identifiers for the three EXISTING wait_for
types (ping, tcp, route_prefix), sourced from the F6-stabilized scenario step
schema (st.wait_type / st.meta), WITHOUT a deployed lab. On the v477 normal path
the engine emits wait_type + meta and leaves the legacy st.wait_for record key
None; the pre-fix renderer had a legacy block (reads st.wait_for -> empty on the
normal path) and a new-type block gated to the six H3/WI-6 types, so the three
existing types fell through both and rendered a bare line. This harness feeds
synthetic engine-shaped scenario step records through the renderer and asserts
the restored identifiers (REQ-RREG-1), that they are sourced from meta and not
the legacy wait_for path (REQ-RREG-2), that the six new types render unchanged
(REQ-RREG-5), that the DC v2.1 §13(b)(c) failed-invariant rendering seam is
separable and behaviorally intact (REQ-RREG-4), and replay byte-identity (D06).

Proof obligations:
  PO-1   existing-type label + type-specific identifiers render (ping/tcp/route_prefix)
  PO-1b  identifiers render from meta with legacy wait_for=None (normal path)
  PO-3   six new wait_for types render their identifiers unchanged
  PO-4   §13(b)(c) seam (_format_test_summary / _format_observed_state_block)
         separable from _render_scenarios_summary and behaviorally intact
  PO-7   replay byte-identity across two renders of identical input; runtime-
         variant meta excluded from the rendered surface (D06)

Render-boundary proof method per bounded-scope LD-1 / §15.1, modeled on
tests/bl6_observed_state_absence_render_proof.py. Reads against src/cassian_tests.py
as captured in SNAPSHOT_MAPPING.txt (v477).

Exit 0 on all-pass; exit 1 on first failed assertion.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import cassian_tests as ct

# A distinctive runtime-variant value that must never reach the rendered surface
# (D06): the renderer surfaces only the whitelisted stable identifiers.
_RUNTIME_VARIANT = "rtvar_9173_should_not_render"

# §13(b)(c) seam indicator (BL-6 render-boundary proof string).
_SEAM_UNAVAILABLE = "detail: (structured failure detail unavailable for this invariant type)"


def _wait_step(wait_type, meta, *, wait_for=None, verdict="pass"):
    # Engine-shaped wait_for scenario step record (canonical key-set, F6).
    return {
        "type": "wait_for",
        "wait_type": wait_type,
        "wait_for": wait_for,          # None on the normal path (F6)
        "expected": "pass",
        "observed": "pass" if verdict == "pass" else "fail",
        "verdict": verdict,
        "duration_ms": 12,
        "meta": meta,
    }


def _scn(sid, step):
    return {"id": sid, "verdict": "pass", "duration_ms": 12, "steps": [step]}


def _results_existing():
    return {
        "scenarios": [
            _scn("s-ping", _wait_step("ping", {
                "from": "h1", "to": "192.168.2.10", "src_ip": "192.168.1.5",
                "src_if": "eth1", "count": 3,
                "observed_neighbor_count": _RUNTIME_VARIANT,  # D06: must not render
            })),
            _scn("s-tcp", _wait_step("tcp", {
                "from": "h1", "to": "10.0.0.5", "src_ip": "10.0.0.1",
                "src_if": "eth2", "port": 443,
            })),
            _scn("s-route", _wait_step("route_prefix", {
                "from": "r1", "src": "r1", "prefix": "10.0.0.0/24",
            })),
        ],
    }


def _results_new():
    return {
        "scenarios": [
            _scn("n1-bgp", _wait_step("bgp_session_up", {"from": "r1", "dst": "10.0.0.2"})),
            _scn("n2-rp", _wait_step("route_present", {"from": "r1", "prefix": "10.0.0.0/24"})),
            _scn("n3-radv", _wait_step("route_advertised_to",
                 {"from": "leaf1", "peer": "spine1", "prefix": "10.99.99.0/24"})),
            _scn("n4-ebgp", _wait_step("evpn_bgp_session_up", {"from": "leaf2", "peer": "spine1"})),
            _scn("n5-evni", _wait_step("evpn_vni_route_present", {"from": "leaf2", "vni": 10100})),
            _scn("n6-emac", _wait_step("evpn_mac_route_present",
                 {"from": "leaf2", "mac": "de:ad:be:ef:00:01", "vni": 10100})),
        ],
    }


def _results_seam():
    # Single genuine-absence failed invariant (non-dict observed_state), mirroring
    # the BL-6 inv-absent record; used only to confirm the §13(b)(c) seam is intact
    # and separable, not to re-prove BL-6.
    return {
        "lab": "bl-h3-8-seam-smoke",
        "result": "fail",
        "summary": {"total": 1, "passed": 0, "failed": 1},
        "tests": [
            {
                "name": "inv-absent",
                "kind": "invariant",
                "from": "r1",
                "to": "",
                "expected": "pass",
                "observed": "fail",
                "verdict": "fail",
                "error": "FAIL: bgp session not established",
                "meta": {"type": "bgp_session_up", "peer": "10.0.0.2"},
            },
        ],
    }


def main():
    out_existing = ct._render_scenarios_summary(_results_existing())
    out_existing2 = ct._render_scenarios_summary(_results_existing())
    out_new = ct._render_scenarios_summary(_results_new())
    out_seam = ct._format_test_summary(_results_seam())

    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # PO-1 — existing-type label + type-specific identifiers
    check("PO-1 ping type label", "type=ping" in out_existing)
    check("PO-1 ping from", "from=h1" in out_existing)
    check("PO-1 ping to", "to=192.168.2.10" in out_existing)
    check("PO-1 ping src_if", "src_if=eth1" in out_existing)
    check("PO-1 ping count", "count=3" in out_existing)
    check("PO-1 tcp type label", "type=tcp" in out_existing)
    check("PO-1 tcp to", "to=10.0.0.5" in out_existing)
    check("PO-1 tcp src_if", "src_if=eth2" in out_existing)
    check("PO-1 tcp port", "port=443" in out_existing)
    check("PO-1 route_prefix type label", "type=route_prefix" in out_existing)
    check("PO-1 route_prefix from", "from=r1" in out_existing)
    check("PO-1 route_prefix src", "src=r1" in out_existing)
    check("PO-1 route_prefix prefix", "prefix=10.0.0.0/24" in out_existing)

    # PO-1b — identifiers render from meta with legacy wait_for=None (normal path)
    wf_none = all(
        s["steps"][0]["wait_for"] is None for s in _results_existing()["scenarios"]
    )
    check("PO-1b input legacy wait_for is None (normal path)", wf_none)
    check("PO-1b identifiers render despite wait_for=None (ping)",
          "type=ping" in out_existing and "to=192.168.2.10" in out_existing)

    # PO-3 — six new wait_for types render their identifiers unchanged
    check("PO-3 bgp_session_up", "type=bgp_session_up" in out_new and "dst=10.0.0.2" in out_new)
    check("PO-3 route_present", "type=route_present" in out_new and "prefix=10.0.0.0/24" in out_new)
    check("PO-3 route_advertised_to",
          "type=route_advertised_to" in out_new and "peer=spine1" in out_new
          and "prefix=10.99.99.0/24" in out_new)
    check("PO-3 evpn_bgp_session_up",
          "type=evpn_bgp_session_up" in out_new and "peer=spine1" in out_new)
    check("PO-3 evpn_vni_route_present",
          "type=evpn_vni_route_present" in out_new and "vni=10100" in out_new)
    check("PO-3 evpn_mac_route_present",
          "type=evpn_mac_route_present" in out_new and "mac=de:ad:be:ef:00:01" in out_new
          and "vni=10100" in out_new)

    # PO-4 — §13(b)(c) seam separable + behaviorally intact
    check("PO-4 seam functions are distinct objects",
          ct._render_scenarios_summary is not ct._format_test_summary
          and ct._render_scenarios_summary is not ct._format_observed_state_block)
    check("PO-4 scenarios render does not emit the §13 absence indicator",
          _SEAM_UNAVAILABLE not in out_existing)
    check("PO-4 §13(b)(c) seam still renders the absence indicator",
          _SEAM_UNAVAILABLE in out_seam)
    check("PO-4 §13(b)(c) seam still renders (a) invariant type",
          "type: bgp_session_up" in out_seam)
    check("PO-4 §13(b)(c) seam still renders (b) declared expectation",
          "expected: pass" in out_seam)

    # PO-7 — replay byte-identity + D06 runtime-variant exclusion
    check("PO-7 replay byte-identity (existing types)", out_existing == out_existing2)
    check("PO-7 D06 runtime-variant excluded from rendered surface",
          _RUNTIME_VARIANT not in out_existing)
    check("PO-7 header present", "=== Scenarios ===" in out_existing)

    print(out_existing)
    print("=" * 60)
    print(out_new)
    print("=" * 60)
    print(out_seam)
    print("=" * 60)
    ok = True
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=" * 60)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
