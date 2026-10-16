#!/usr/bin/env python3
"""evpn_rr_next_hop_self_proof.py -- §4.5-d, BL-P2-4.5c-219 (founder rulings S25-R5, S26-R5 to S26-R9).

DECLARED CHANGE (DC v2.1 §14 item 8, "No silent mutation introduced"; S26-R8, S26-R9). In the FRR
configuration Cassian Gate generates for an EVPN route-reflector spine, `address-family ipv4 unicast` now
carries `neighbor <client> next-hop-self force` for each route-reflector client, immediately after that
client's `route-reflector-client` line. The `address-family l2vpn evpn` section and every leaf
configuration are unchanged. It changes the spine of every EVPN topology under topologies/ and examples/
that the product resolves: 18 at cassian-gate 99d749a, the 16 top-level ones plus
topologies/neg/h2_invariant_observability_demo.yaml (booted by CI's B-9 step) and
topologies/neg/h2_truncation_proof.yaml.

WHY (S26-R5). The spine reflected each leaf's loopback with that leaf's own link address as next hop.
The other leaf cannot reach that address: the fabric has no IGP and advertises no link subnet. leaf2's
BGP next-hop tracking therefore marked leaf1's VTEP 10.255.0.11 invalid, and FRR installed none of
leaf1's EVPN routes on leaf2.

LAB-FREE LEG (no argument)
  L-CENSUS  The YAML files under topologies/ and examples/ that declare `fabric.evpn.enabled`, resolved
            through the product's resolve_topology(topo, topo_path=...) as `cassian up` resolves them,
            are exactly the 18 RESOLVED and the 9 REJECTED pinned below. Any addition or removal fails.
  L-SHAPE   Each resolved EVPN topology has exactly the FRR nodes spine1 (role spine, evpn_rr), leaf1
            and leaf2, all generated (frr_mode), and the spine has one route-reflector client per leaf.
  L-LEAF    Every leaf renders byte-identical to its pinned pre-change render and names no next-hop-self.
  L-SPINE   On every spine the only next-hop-self lines are `  neighbor <ip> next-hop-self force`, one per
            route-reflector client, each immediately after that client's `route-reflector-client` line
            inside `address-family ipv4 unicast`. Removing them gives the pinned pre-change render.
  L-COUNT   18 configurations change (every spine); 36 are byte-identical (every leaf).
  L-LAB     The committed topology the hosted leg boots still declares every value the hosted leg reads.
  L-NV      Non-vacuity. The spine check rejects a render without the lines, with a line also in the
            l2vpn evpn section, with `next-hop-self` lacking `force`, and with a line in the wrong place.
            The leaf check rejects a leaf carrying the line. The census check rejects an added and a
            removed file. The hosted-leg evaluators return not-holding on FRR 8.4 output from before the
            fix, holding on output from after it, and unknown on an unreadable read.
  Oracle: the pre-change digests below were rendered by the product's gen_frr_conf at cassian-gate
  99d749a (src/cassian_model.py sha256 247bd14e3d82cfb154221705e2e7ea59c1d6efffd7c81206ce35f05a721b8fcb).
  They are static: nothing here recomputes them, and a later change to these renders must update them
  and be declared again.

HOSTED LEG (--hosted evpn-mac-route-absent-expect-fail)
  Run by the cassian.yml step after `cassian up topologies/evpn_mac_route_absent_expect_fail.yaml`.
  Reads through the product's own vty path (cassian_runtime_container.vty), polling every 2 s for at
  most 120 s until every row holds:
    P-0  spine1's running configuration carries `neighbor <client> next-hop-self force` for both
         clients in `address-family ipv4 unicast` (the generated configuration reached the device)
    C-1  control: leaf2's BGP next-hop cache holds 172.16.0.2 valid
    C-2  control: 10.255.0.1/32 (spine1's loopback) is valid on leaf2 via 172.16.0.2, accessible
    C-3  control: every path for host2's MAC under leaf2's RD (10.255.0.12:*) is valid
    H-1  10.255.0.11/32 (leaf1's loopback) is valid on leaf2 via 172.16.0.2, accessible
    H-2  leaf2's BGP next-hop cache holds leaf1's VTEP 10.255.0.11 valid
    H-3  every path for host1's MAC under leaf1's RD (10.255.0.11:*) is valid on leaf2
  A read that fails or cannot be parsed makes its rows "unknown", never "holds" and never "false".

COVERAGE LIMITS (PBE-P2-8). The lab-free leg proves the rendered text, not FRR's behaviour. The hosted
leg proves one booted lab on the runner and reads leaf2's view of leaf1 only: not leaf1's view of leaf2,
not the other EVPN labs, not host-to-host traffic, and not Cassian Gate's own EVPN verdicts, which keep
their shipped meaning in §4.5-d (S26-R4; BL-P2-4.5c-221 is routed to §4.5-e). Green twice in CI
(S25-R5) is read from CI, not from here.

Writes nothing. Exit 0 = GREEN, 1 = RED.
"""

import hashlib
import json
import os
import re
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "src"))

# ---- the hosted lab (lab 3; the lab S26-R7's check ran on) ----------------------------------------
LAB = "evpn-mac-route-absent-expect-fail"
LAB_FILE = "topologies/evpn_mac_route_absent_expect_fail.yaml"
SPINE, OBSERVER, REMOTE = "spine1", "leaf2", "leaf1"
SPINE_RID, OBSERVER_RID, REMOTE_VTEP = "10.255.0.1", "10.255.0.12", "10.255.0.11"
SPINE_LINK_TO_OBSERVER = "172.16.0.2"
CLIENTS = ["172.16.0.1", "172.16.0.3"]
MAC_REMOTE, MAC_LOCAL = "00:11:22:33:44:55", "00:11:22:33:44:66"
BOUND_S, INTERVAL_S = 120.0, 2.0
READS = (
    ("nht", OBSERVER, "show bgp nexthop"),
    ("vtep_route", OBSERVER, "show bgp ipv4 unicast %s/32 json" % REMOTE_VTEP),
    ("spine_route", OBSERVER, "show bgp ipv4 unicast %s/32 json" % SPINE_RID),
    ("evpn", OBSERVER, "show bgp l2vpn evpn route json"),
    ("spine_rc", SPINE, "show running-config"),
)

# ---- census and oracle (generated at cassian-gate 99d749a; static) ---------------------------------
SCAN_ROOTS = ("topologies", "examples")
RESOLVED = (
    "topologies/evpn_bgp_session_up.yaml",
    "topologies/evpn_bgp_session_up_expect_fail.yaml",
    "topologies/evpn_bgp_session_up_misconfigured.yaml",
    "topologies/evpn_mac_route_absent_expect_fail.yaml",
    "topologies/evpn_mac_route_absent_expected_absent_present.yaml",
    "topologies/evpn_mac_route_absent_expected_present.yaml",
    "topologies/evpn_mac_route_present.yaml",
    "topologies/evpn_mac_route_present_expect_fail.yaml",
    "topologies/evpn_runtime_generation.yaml",
    "topologies/evpn_vni_route_absent_expected_present.yaml",
    "topologies/evpn_vni_route_present.yaml",
    "topologies/evpn_vni_route_present_expect_fail.yaml",
    "topologies/ex-evpn-outcome-only.yaml",
    "topologies/neg/h2_invariant_observability_demo.yaml",
    "topologies/neg/h2_truncation_proof.yaml",
    "topologies/pack_local_compatibility_ok.yaml",
    "topologies/pack_resolve_expansion.yaml",
    "topologies/wait-for-evpn-fabric.yaml",
)
REJECTED = (
    "examples/evpn_outcome_only.yaml",
    "topologies/neg/bad_fabric_evpn_unknown_key.yaml",
    "topologies/neg/evpn_invalid_bgp_session_invariant.yaml",
    "topologies/neg/evpn_invalid_mac_invariant.yaml",
    "topologies/neg/evpn_invalid_roles.yaml",
    "topologies/neg/evpn_invalid_vni.yaml",
    "topologies/neg/evpn_invalid_vni_invariant.yaml",
    "topologies/neg/good_fabric_evpn_presence_only.yaml",
    "topologies/neg/pack_incompatible_contents.yaml",
)
# pre-change render digests (gen_frr_conf at 99d749a), one name per distinct render
_LEAF1 = "8839ea710519672099c7d36c2d9c75365e3d784144ef753baf069b5daf28f2c4"
_LEAF1_2 = "5d10e2a59ac6fa3ec2f08c7f5630fc4f9a68fde6b64e6cbbfd7c44f291b200f8"  # topologies/neg/h2_truncation_proof.yaml only
_LEAF2 = "49e92220bdf902de1a9fa192963b8686d1b0eadf5ef947ce0f2091d9ff630277"
_LEAF2_2 = "89c527b892a0be66ba1ab8da3506c29f52994bd39e3f6c7a9ed318d21093bcfb"  # topologies/neg/h2_truncation_proof.yaml only
_SPINE1 = "aa30b3f070dbb265105f9f4f22e4c85f520b71492f24c8c7584dc88a0ca3dd4d"
BEFORE = {
    "topologies/evpn_bgp_session_up.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/evpn_bgp_session_up_expect_fail.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/evpn_bgp_session_up_misconfigured.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/evpn_mac_route_absent_expect_fail.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/evpn_mac_route_absent_expected_absent_present.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/evpn_mac_route_absent_expected_present.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/evpn_mac_route_present.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/evpn_mac_route_present_expect_fail.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/evpn_runtime_generation.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/evpn_vni_route_absent_expected_present.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/evpn_vni_route_present.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/evpn_vni_route_present_expect_fail.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/ex-evpn-outcome-only.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/neg/h2_invariant_observability_demo.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/neg/h2_truncation_proof.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1_2, "leaf2": _LEAF2_2},
    "topologies/pack_local_compatibility_ok.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/pack_resolve_expansion.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
    "topologies/wait-for-evpn-fabric.yaml": {"spine1": _SPINE1, "leaf1": _LEAF1, "leaf2": _LEAF2},
}
EXPECT_CHANGED, EXPECT_UNCHANGED = 18, 36

# ---- FRR 8.4 output, trimmed by program to the keys the evaluators read ---------------------------
# BEFORE: the reads of record of S26-R2's boot (2026-10-08) and S26-R7's check before the change
# (2026-10-09); AFTER: S26-R7's check after the change. Both on ai-netsim, lab 3, cassian-gate 99d749a.
# S26-R7 read p, before the change: show bgp nexthop (leaf2)
FX_NHT_BEFORE = "\n".join([
    "Current BGP nexthop cache:",
    " 10.255.0.11 invalid, #paths 4",
    "  Last update: Fri Oct  9 05:53:38 2026",
    "",
    " 172.16.0.1 invalid, #paths 1",
    "  Last update: Fri Oct  9 05:53:38 2026",
    "",
    " 172.16.0.2 valid [IGP metric 0], #paths 1, peer 172.16.0.2",
    "  if eth1",
    "  Last update: Fri Oct  9 05:53:37 2026",
])

# S26-R7 read a, after the change: show bgp nexthop (leaf2)
FX_NHT_AFTER = "\n".join([
    "Current BGP nexthop cache:",
    " 10.255.0.11 valid [IGP metric 0], #paths 4",
    "  gate 172.16.0.2",
    "  Last update: Fri Oct  9 05:54:15 2026",
    "",
    " 172.16.0.2 valid [IGP metric 0], #paths 2, peer 172.16.0.2",
    "  if eth1",
    "  Last update: Fri Oct  9 05:53:37 2026",
])

# S26-R7 read q, before: show bgp ipv4 unicast 10.255.0.11/32 json (leaf2), trimmed
FX_VTEP_ROUTE_BEFORE = "\n".join([
    "{",
    " \"paths\": [",
    "  {",
    "   \"nexthops\": [",
    "    {",
    "     \"accessible\": false,",
    "     \"ip\": \"172.16.0.1\"",
    "    }",
    "   ],",
    "   \"valid\": false",
    "  }",
    " ],",
    " \"prefix\": \"10.255.0.11/32\"",
    "}",
])

# S26-R7 read c, after: show bgp ipv4 unicast 10.255.0.11/32 json (leaf2), trimmed
FX_VTEP_ROUTE_AFTER = "\n".join([
    "{",
    " \"paths\": [",
    "  {",
    "   \"nexthops\": [",
    "    {",
    "     \"accessible\": true,",
    "     \"ip\": \"172.16.0.2\"",
    "    }",
    "   ],",
    "   \"valid\": true",
    "  }",
    " ],",
    " \"prefix\": \"10.255.0.11/32\"",
    "}",
])

# S26-R2 read d, before: show bgp ipv4 unicast 10.255.0.1/32 json (leaf2), trimmed
FX_SPINE_ROUTE_BEFORE = "\n".join([
    "{",
    " \"paths\": [",
    "  {",
    "   \"nexthops\": [",
    "    {",
    "     \"accessible\": true,",
    "     \"ip\": \"172.16.0.2\"",
    "    }",
    "   ],",
    "   \"valid\": true",
    "  }",
    " ],",
    " \"prefix\": \"10.255.0.1/32\"",
    "}",
])

# S26-R7 read d, after: show bgp ipv4 unicast 10.255.0.1/32 json (leaf2), trimmed
FX_SPINE_ROUTE_AFTER = "\n".join([
    "{",
    " \"paths\": [",
    "  {",
    "   \"nexthops\": [",
    "    {",
    "     \"accessible\": true,",
    "     \"ip\": \"172.16.0.2\"",
    "    }",
    "   ],",
    "   \"valid\": true",
    "  }",
    " ],",
    " \"prefix\": \"10.255.0.1/32\"",
    "}",
])

# S26-R2 read g, before: show bgp l2vpn evpn route json (leaf2), trimmed to mac and valid
FX_EVPN_BEFORE = "\n".join([
    "{",
    " \"10.255.0.11:2\": {",
    "  \"[2]:[0]:[48]:[00:11:22:33:44:55]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"00:11:22:33:44:55\"",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[2]:[0]:[48]:[00:11:22:33:44:55]:[32]:[10.10.10.11]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"00:11:22:33:44:55\"",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[2]:[0]:[48]:[aa:c1:ab:79:71:65]:[128]:[fe80::a8c1:abff:fe79:7165]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"aa:c1:ab:79:71:65\"",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[3]:[0]:[32]:[10.255.0.11]\": {",
    "   \"paths\": [",
    "    [",
    "     {}",
    "    ]",
    "   ]",
    "  },",
    "  \"rd\": \"10.255.0.11:2\"",
    " },",
    " \"10.255.0.12:2\": {",
    "  \"[2]:[0]:[48]:[00:11:22:33:44:66]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"00:11:22:33:44:66\",",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[2]:[0]:[48]:[00:11:22:33:44:66]:[32]:[10.10.10.12]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"00:11:22:33:44:66\",",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[2]:[0]:[48]:[72:0f:8a:a5:01:0a]:[128]:[fe80::700f:8aff:fea5:10a]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"72:0f:8a:a5:01:0a\",",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[3]:[0]:[32]:[10.255.0.12]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"rd\": \"10.255.0.12:2\"",
    " }",
    "}",
])

# S26-R7 read g, after: show bgp l2vpn evpn route json (leaf2), trimmed to mac and valid
FX_EVPN_AFTER = "\n".join([
    "{",
    " \"10.255.0.11:2\": {",
    "  \"[2]:[0]:[48]:[00:11:22:33:44:55]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"00:11:22:33:44:55\",",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[2]:[0]:[48]:[00:11:22:33:44:55]:[32]:[10.10.10.11]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"00:11:22:33:44:55\",",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[2]:[0]:[48]:[aa:c1:ab:a3:41:14]:[128]:[fe80::a8c1:abff:fea3:4114]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"aa:c1:ab:a3:41:14\",",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[3]:[0]:[32]:[10.255.0.11]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"rd\": \"10.255.0.11:2\"",
    " },",
    " \"10.255.0.12:2\": {",
    "  \"[2]:[0]:[48]:[00:11:22:33:44:66]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"00:11:22:33:44:66\",",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[2]:[0]:[48]:[00:11:22:33:44:66]:[32]:[10.10.10.12]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"00:11:22:33:44:66\",",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[2]:[0]:[48]:[3a:75:bb:98:c0:b0]:[128]:[fe80::3875:bbff:fe98:c0b0]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"mac\": \"3a:75:bb:98:c0:b0\",",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"[3]:[0]:[32]:[10.255.0.12]\": {",
    "   \"paths\": [",
    "    [",
    "     {",
    "      \"valid\": true",
    "     }",
    "    ]",
    "   ]",
    "  },",
    "  \"rd\": \"10.255.0.12:2\"",
    " }",
    "}",
])

# S26-R7 read s, after: show running-config (spine1)
FX_SPINE_RC_AFTER = "\n".join([
    "Building configuration...",
    "",
    "Current configuration:",
    "!",
    "frr version 8.4_git",
    "frr defaults traditional",
    "hostname spine1",
    "no ipv6 forwarding",
    "service integrated-vtysh-config",
    "!",
    "interface eth1",
    " ip address 172.16.0.0/31",
    "exit",
    "!",
    "interface eth2",
    " ip address 172.16.0.2/31",
    "exit",
    "!",
    "interface lo",
    " ip address 10.255.0.1/32",
    "exit",
    "!",
    "router bgp 65100",
    " bgp router-id 10.255.0.1",
    " no bgp ebgp-requires-policy",
    " no bgp hard-administrative-reset",
    " no bgp default ipv4-unicast",
    " no bgp graceful-restart notification",
    " neighbor EVPN peer-group",
    " neighbor EVPN remote-as 65100",
    " neighbor 172.16.0.1 peer-group EVPN",
    " neighbor 172.16.0.3 peer-group EVPN",
    " !",
    " address-family ipv4 unicast",
    "  network 10.255.0.1/32",
    "  neighbor 172.16.0.1 activate",
    "  neighbor 172.16.0.1 route-reflector-client",
    "  neighbor 172.16.0.1 next-hop-self force",
    "  neighbor 172.16.0.3 activate",
    "  neighbor 172.16.0.3 route-reflector-client",
    "  neighbor 172.16.0.3 next-hop-self force",
    " exit-address-family",
    " !",
    " address-family l2vpn evpn",
    "  neighbor EVPN activate",
    "  neighbor 172.16.0.1 route-reflector-client",
    "  neighbor 172.16.0.3 route-reflector-client",
    "  advertise-all-vni",
    " exit-address-family",
    "exit",
    "!",
    "end",
])

# derived: read s with its two next-hop-self lines removed (no pre-change running-config read was taken)
FX_SPINE_RC_BEFORE = "\n".join([
    "Building configuration...",
    "",
    "Current configuration:",
    "!",
    "frr version 8.4_git",
    "frr defaults traditional",
    "hostname spine1",
    "no ipv6 forwarding",
    "service integrated-vtysh-config",
    "!",
    "interface eth1",
    " ip address 172.16.0.0/31",
    "exit",
    "!",
    "interface eth2",
    " ip address 172.16.0.2/31",
    "exit",
    "!",
    "interface lo",
    " ip address 10.255.0.1/32",
    "exit",
    "!",
    "router bgp 65100",
    " bgp router-id 10.255.0.1",
    " no bgp ebgp-requires-policy",
    " no bgp hard-administrative-reset",
    " no bgp default ipv4-unicast",
    " no bgp graceful-restart notification",
    " neighbor EVPN peer-group",
    " neighbor EVPN remote-as 65100",
    " neighbor 172.16.0.1 peer-group EVPN",
    " neighbor 172.16.0.3 peer-group EVPN",
    " !",
    " address-family ipv4 unicast",
    "  network 10.255.0.1/32",
    "  neighbor 172.16.0.1 activate",
    "  neighbor 172.16.0.1 route-reflector-client",
    "  neighbor 172.16.0.3 activate",
    "  neighbor 172.16.0.3 route-reflector-client",
    " exit-address-family",
    " !",
    " address-family l2vpn evpn",
    "  neighbor EVPN activate",
    "  neighbor 172.16.0.1 route-reflector-client",
    "  neighbor 172.16.0.3 route-reflector-client",
    "  advertise-all-vni",
    " exit-address-family",
    "exit",
    "!",
    "end",
])

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok), detail))


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ===================================================================================================
# Evaluators (pure; shared by the hosted leg and the non-vacuity checks)
# ===================================================================================================
_IP = r"(?:\d{1,3}\.){3}\d{1,3}"


def nht_state(text, ip):
    """True / False for `ip` in `show bgp nexthop` text (FRR 8.4 has no JSON form); None if absent."""
    states = set()
    for ln in (text or "").splitlines():
        toks = ln.replace(",", " ").split()
        if len(toks) >= 2 and re.fullmatch(_IP, toks[0]) and toks[0] == ip and toks[1] in ("valid", "invalid"):
            states.add(toks[1] == "valid")
    return states.pop() if len(states) == 1 else None


def path_valid_via(text, nh_ip):
    """True if some path is valid with next hop `nh_ip` accessible; False if paths exist and none is;
    None if the read cannot say."""
    try:
        doc = json.loads(text)
    except (TypeError, ValueError):
        return None
    paths = doc.get("paths") if isinstance(doc, dict) else None
    if not isinstance(paths, list) or not paths:
        return None
    for p in paths:
        if not isinstance(p, dict) or p.get("valid") is not True:
            continue
        for nh in p.get("nexthops") or []:
            if isinstance(nh, dict) and nh.get("ip") == nh_ip and nh.get("accessible") is True:
                return True
    return False


def evpn_mac_paths_valid(text, rd_rid, mac):
    """True if the MAC has at least one path under an RD `<rd_rid>:*` and every such path is valid;
    False if some such path is not valid; None if the read holds no such path or cannot be parsed."""
    try:
        doc = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    seen = []
    for rd_key, rd_val in doc.items():
        if not (isinstance(rd_val, dict) and str(rd_key).startswith(rd_rid + ":")):
            continue
        for route in rd_val.values():
            if not isinstance(route, dict):
                continue
            for grp in route.get("paths") or []:
                for e in (grp if isinstance(grp, list) else [grp]):
                    if isinstance(e, dict) and str(e.get("mac") or "").strip().lower() == mac:
                        seen.append(e.get("valid") is True)
    if not seen:
        return None
    return all(seen)


def _af_block(lines, header):
    """Indices [start, end) of the `address-family <x>` block whose header line is `header`."""
    if lines.count(header) != 1:
        return None
    start = lines.index(header)
    for k in range(start + 1, len(lines)):
        if lines[k] == " exit-address-family":
            return start, k
    return None


def running_config_has_nhs(text, clients):
    """True if `address-family ipv4 unicast` holds `neighbor <c> next-hop-self force` for every client;
    False if the section exists without them; None if the read cannot say."""
    lines = (text or "").splitlines()
    blk = _af_block(lines, " address-family ipv4 unicast")
    if blk is None:
        return None
    body = lines[blk[0]:blk[1]]
    return all(("  neighbor %s next-hop-self force" % c) in body for c in clients)


def spine_ok(render, before_sha):
    """L-SPINE on one render; returns (ok, detail)."""
    lines = render.split("\n")
    blk = _af_block(lines, " address-family ipv4 unicast")
    if blk is None:
        return False, "no single ipv4 unicast section"
    rrc = []
    for k in range(blk[0], blk[1]):
        m = re.fullmatch(r"  neighbor (\S+) route-reflector-client", lines[k])
        if m:
            rrc.append((k, m.group(1)))
    nhs = [k for k, ln in enumerate(lines) if "next-hop-self" in ln]
    want = [k + 1 for k, _ip in rrc]
    if not rrc:
        return False, "no route-reflector client in ipv4 unicast"
    if nhs != want:
        return False, "next-hop-self at lines %s, want %s" % (nhs, want)
    for k, ip in rrc:
        if lines[k + 1] != "  neighbor %s next-hop-self force" % ip:
            return False, "line %d is %r" % (k + 1, lines[k + 1])
    stripped = "\n".join(ln for k, ln in enumerate(lines) if k not in set(nhs))
    if _sha(stripped) != before_sha:
        return False, "render without the lines differs from the pre-change render"
    return True, "%d client(s): %s" % (len(rrc), ", ".join(ip for _k, ip in rrc))


def leaf_ok(render, before_sha):
    if "next-hop-self" in render:
        return False, "leaf names next-hop-self"
    if _sha(render) != before_sha:
        return False, "leaf render differs from the pre-change render"
    return True, ""


def census_ok(resolved, rejected):
    return sorted(resolved) == sorted(RESOLVED) and sorted(rejected) == sorted(REJECTED)


def evaluate(reads):
    """reads: key -> (rc, stdout). Returns the ordered rows, each True / False / None (unknown)."""
    def txt(k):
        rc, out = reads.get(k, (None, None))
        return out if rc == 0 else None
    nht, vr, sr, ev, rc_ = (txt("nht"), txt("vtep_route"), txt("spine_route"), txt("evpn"), txt("spine_rc"))
    return [
        ("P-0 spine1 running config carries next-hop-self force for both clients in ipv4 unicast",
         None if rc_ is None else running_config_has_nhs(rc_, CLIENTS)),
        ("C-1 control: leaf2 next-hop cache holds %s valid" % SPINE_LINK_TO_OBSERVER,
         None if nht is None else nht_state(nht, SPINE_LINK_TO_OBSERVER)),
        ("C-2 control: %s/32 valid on leaf2 via %s, accessible" % (SPINE_RID, SPINE_LINK_TO_OBSERVER),
         None if sr is None else path_valid_via(sr, SPINE_LINK_TO_OBSERVER)),
        ("C-3 control: every path for host2's MAC under leaf2's RD is valid",
         None if ev is None else evpn_mac_paths_valid(ev, OBSERVER_RID, MAC_LOCAL)),
        ("H-1 %s/32 valid on leaf2 via %s, accessible" % (REMOTE_VTEP, SPINE_LINK_TO_OBSERVER),
         None if vr is None else path_valid_via(vr, SPINE_LINK_TO_OBSERVER)),
        ("H-2 leaf2 next-hop cache holds leaf1's VTEP %s valid" % REMOTE_VTEP,
         None if nht is None else nht_state(nht, REMOTE_VTEP)),
        ("H-3 every path for host1's MAC under leaf1's RD is valid on leaf2",
         None if ev is None else evpn_mac_paths_valid(ev, REMOTE_VTEP, MAC_REMOTE)),
    ]


def _fmt(v):
    return "holds" if v is True else ("false" if v is False else "unknown")


# ===================================================================================================
# Lab-free leg
# ===================================================================================================
def _evpn_declared(doc):
    fab = doc.get("fabric") if isinstance(doc, dict) else None
    ev = fab.get("evpn") if isinstance(fab, dict) else None
    return isinstance(ev, dict) and bool(ev.get("enabled"))


def lab_free():
    import yaml
    from pathlib import Path
    import cassian_common
    import cassian_model

    cassian_common._QUIET_DIE = True  # a rejected topology raises SystemExit(msg); nothing printed
    resolved, rejected, renders = [], [], {}
    for base in SCAN_ROOTS:
        for root, dirs, files in os.walk(os.path.join(_ROOT, base)):
            dirs.sort()
            for f in sorted(files):
                if not f.endswith((".yaml", ".yml")):
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, _ROOT).replace(os.sep, "/")
                with open(full, encoding="utf-8") as fh:
                    try:
                        doc = yaml.safe_load(fh)
                    except yaml.YAMLError:
                        continue
                if not _evpn_declared(doc):
                    continue
                try:
                    topo = cassian_model.resolve_topology(doc, topo_path=Path(full))
                except SystemExit:
                    rejected.append(rel)
                    continue
                resolved.append(rel)
                renders[rel] = topo

    check("L-CENSUS resolved EVPN topologies are exactly the %d pinned" % len(RESOLVED),
          sorted(resolved) == sorted(RESOLVED),
          "added %s removed %s" % (sorted(set(resolved) - set(RESOLVED)), sorted(set(RESOLVED) - set(resolved))))
    check("L-CENSUS EVPN-declaring files the product rejects are exactly the %d pinned" % len(REJECTED),
          sorted(rejected) == sorted(REJECTED),
          "added %s removed %s" % (sorted(set(rejected) - set(REJECTED)), sorted(set(REJECTED) - set(rejected))))

    changed = unchanged = 0
    last_spine = None
    for rel in sorted(renders):
        topo = renders[rel]
        frr = {n["name"]: n for n in topo.get("nodes", []) if n.get("type") == "frr"}
        leaves = [n for n in topo.get("nodes", []) if n.get("role") == "leaf"]
        shape = (sorted(frr) == ["leaf1", "leaf2", "spine1"]
                 and frr["spine1"].get("role") == "spine" and bool(frr["spine1"].get("evpn_rr"))
                 and all((n.get("frr_mode") or "generated") == "generated" for n in frr.values())
                 and rel in BEFORE)
        check("L-SHAPE %s: FRR nodes spine1 (RR), leaf1, leaf2, generated, pinned" % rel, shape, str(sorted(frr)))
        if not shape:
            continue
        for name in ("leaf1", "leaf2", "spine1"):
            cfg = cassian_model.gen_frr_conf(frr[name], topo)
            if _sha(cfg) == BEFORE[rel][name]:
                unchanged += 1
            else:
                changed += 1
            if name == "spine1":
                ok, detail = spine_ok(cfg, BEFORE[rel][name])
                ok = ok and detail.startswith("%d client(s)" % len(leaves))
                check("L-SPINE %s: next-hop-self force after each client in ipv4 unicast only" % rel, ok, detail)
                if ok:
                    last_spine = (cfg, BEFORE[rel][name])
            else:
                ok, detail = leaf_ok(cfg, BEFORE[rel][name])
                check("L-LEAF %s %s: byte-identical to the pre-change render" % (rel, name), ok, detail)
    check("L-COUNT %d configurations change and %d are byte-identical" % (EXPECT_CHANGED, EXPECT_UNCHANGED),
          changed == EXPECT_CHANGED and unchanged == EXPECT_UNCHANGED, "changed %d unchanged %d" % (changed, unchanged))

    # ---- L-LAB: the hosted leg's values are what the committed topology declares ------------------
    with open(os.path.join(_ROOT, LAB_FILE), encoding="utf-8") as fh:
        lab = yaml.safe_load(fh)
    nodes = {n.get("name"): n for n in lab.get("nodes", [])}
    links = {tuple(l.get("endpoints") or ()): l.get("ipv4") for l in lab.get("links", [])}
    lab_ok = (lab.get("name") == LAB
              and nodes[SPINE].get("router_id") == SPINE_RID and nodes[SPINE].get("evpn_rr") is True
              and nodes[REMOTE].get("router_id") == REMOTE_VTEP and nodes[OBSERVER].get("router_id") == OBSERVER_RID
              and nodes["host1"].get("attach") == REMOTE and nodes["host1"].get("mac") == MAC_REMOTE
              and nodes["host2"].get("attach") == OBSERVER and nodes["host2"].get("mac") == MAC_LOCAL
              and links.get(("spine1:eth1", "leaf1:eth1")) == ["172.16.0.0/31", CLIENTS[0] + "/31"]
              and links.get(("spine1:eth2", "leaf2:eth1")) == [SPINE_LINK_TO_OBSERVER + "/31", CLIENTS[1] + "/31"])
    check("L-LAB %s declares the values the hosted leg reads" % LAB_FILE, lab_ok)

    # ---- L-NV: every check above is shown able to fail ------------------------------------------
    if last_spine is not None:
        cfg, bsha = last_spine
        lines = cfg.split("\n")
        without = "\n".join(ln for ln in lines if "next-hop-self" not in ln)
        check("L-NV spine check rejects the pre-change shape (no next-hop-self)", not spine_ok(without, bsha)[0])
        evpn_hdr = lines.index(" address-family l2vpn evpn")
        extra = lines[:evpn_hdr + 2] + ["  neighbor %s next-hop-self force" % CLIENTS[0]] + lines[evpn_hdr + 2:]
        check("L-NV spine check rejects a next-hop-self line in l2vpn evpn", not spine_ok("\n".join(extra), bsha)[0])
        noforce = cfg.replace("next-hop-self force", "next-hop-self", 1)
        check("L-NV spine check rejects next-hop-self without force", not spine_ok(noforce, bsha)[0])
        k = next(i for i, ln in enumerate(lines) if ln.endswith("next-hop-self force"))
        moved = lines[:k] + lines[k + 1:]
        moved = moved[:k - 2] + [lines[k]] + moved[k - 2:]
        check("L-NV spine check rejects a next-hop-self line out of place", not spine_ok("\n".join(moved), bsha)[0])
    else:
        check("L-NV a spine render passing L-SPINE was available to mutate", False, "none passed")
    leaf_rel = sorted(renders)[0] if renders else None
    if leaf_rel is not None and leaf_rel in BEFORE:
        leaf_node = [n for n in renders[leaf_rel]["nodes"] if n.get("name") == "leaf1"][0]
        lcfg = cassian_model.gen_frr_conf(leaf_node, renders[leaf_rel])
        check("L-NV leaf check rejects a leaf carrying next-hop-self",
              not leaf_ok(lcfg + "  neighbor %s next-hop-self force\n" % SPINE_RID, BEFORE[leaf_rel]["leaf1"])[0])
    check("L-NV census check rejects an added file", not census_ok(list(RESOLVED) + ["topologies/x.yaml"], list(REJECTED)))
    check("L-NV census check rejects a removed file", not census_ok(list(RESOLVED)[1:], list(REJECTED)))

    before_rows = evaluate({"nht": (0, FX_NHT_BEFORE), "vtep_route": (0, FX_VTEP_ROUTE_BEFORE),
                            "spine_route": (0, FX_SPINE_ROUTE_BEFORE), "evpn": (0, FX_EVPN_BEFORE),
                            "spine_rc": (0, FX_SPINE_RC_BEFORE)})
    after_rows = evaluate({"nht": (0, FX_NHT_AFTER), "vtep_route": (0, FX_VTEP_ROUTE_AFTER),
                           "spine_route": (0, FX_SPINE_ROUTE_AFTER), "evpn": (0, FX_EVPN_AFTER),
                           "spine_rc": (0, FX_SPINE_RC_AFTER)})
    failed_rows = evaluate({"nht": (1, ""), "vtep_route": (0, "not json"), "spine_route": (0, "{}"),
                            "evpn": (0, "[]"), "spine_rc": (1, "")})
    check("L-NV evaluators: every row holds on the post-fix reads of record",
          all(v is True for _n, v in after_rows), str([(n[:4], _fmt(v)) for n, v in after_rows]))
    check("L-NV evaluators: P-0 and H-1..H-3 are false and the controls hold on the pre-fix reads of record",
          [v for _n, v in before_rows] == [False, True, True, True, False, False, False],
          str([(n[:4], _fmt(v)) for n, v in before_rows]))
    check("L-NV evaluators: failed or unreadable reads are unknown, never holds or false",
          all(v is None for _n, v in failed_rows), str([(n[:4], _fmt(v)) for n, v in failed_rows]))


# ===================================================================================================
# Hosted leg
# ===================================================================================================
def hosted(lab):
    check("H lab is the pinned hosted lab %s" % LAB, lab == LAB, lab)
    if lab != LAB:
        return
    import cassian_common
    import cassian_runtime_container as crc

    cassian_common.QUIET_RUN = True  # one summary line per attempt instead of one per command
    rt = crc.get_runtime(None)
    for key, node, cmd in READS:
        print("read %-11s docker exec clab-%s-%s vtysh -c '%s'" % (key, lab, node, cmd))
    t0 = time.monotonic()
    attempt, rows, raw = 0, [], {}
    while True:
        attempt += 1
        raw = {}
        for key, node, cmd in READS:
            try:
                cp = crc.vty(rt, lab, node, cmd)
                raw[key] = (cp.returncode, cp.stdout or "")
            except Exception as e:  # a read that cannot run is unknown, not false
                raw[key] = (None, repr(e))
        rows = evaluate(raw)
        elapsed = time.monotonic() - t0
        print("attempt %d at %.1fs: %s" % (attempt, elapsed, " ".join("%s=%s" % (n[:3], _fmt(v)) for n, v in rows)))
        if all(v is True for _n, v in rows) or elapsed >= BOUND_S:
            break
        time.sleep(INTERVAL_S)
    for name, v in rows:
        check("%s (attempt %d, %.1fs, bound %.0fs)" % (name, attempt, time.monotonic() - t0, BOUND_S), v is True, _fmt(v))
    if not all(v is True for _n, v in rows):
        for key, node, cmd in READS:
            rc, out = raw.get(key, (None, ""))
            print("--- last read %s (rc=%s), first lines:" % (key, rc))
            print("\n".join((out or "").splitlines()[:25]))


def main(argv):
    if len(argv) == 1:
        leg = "lab-free"
        lab_free()
    elif len(argv) == 3 and argv[1] == "--hosted":
        leg = "hosted " + argv[2]
        hosted(argv[2])
    else:
        print("usage: evpn_rr_next_hop_self_proof.py [--hosted %s]" % LAB)
        return 2
    fails = [n for n, ok, _d in checks if not ok]
    for n, ok, d in checks:
        print("%s   %s%s" % ("PASS" if ok else "FAIL", n, ("  -- " + d) if (d and not ok) else ""))
    print("RESULT: %s -- %d checks, %d failed (BL-P2-4.5c-219 EVPN route-reflector next-hop-self, %s leg)"
          % ("GREEN" if not fails else "RED", len(checks), len(fails), leg))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
