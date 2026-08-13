#!/usr/bin/env python3
"""
Compatibility shim.

Real implementation lives in `cassian_cli.py`, `cassian_engine.py`, `cassian_ai.py`,
`cassian_candidate.py`, `cassian_state.py`, `cassian_two_run.py`. This file exists
to preserve the `cassian:main` entry point and `from cassian import X` import paths
during the post-split transition. Slated for removal in a future cleanup.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
import shutil
import json
import selectors
import ipaddress
import re
import hashlib
import shlex
import os, time
from typing import Any

from pathlib import Path
from typing import Any

import yaml

import cassian_common
from cassian_common import (
    BASE_DIR, TOPO_DIR, LABS_DIR,
    DEFAULT_IMAGES,
    run, die, fail,
    LAST_ERROR_MSG,
    is_ip_literal, validate_ip_literal, classify_invalid_target,
    nodes_by_type,
    assert_vm_runtime_supported,
)

# ---------------------------------------------------------------------
# Verbose containerlab banner noise filter (v2-verbose-containerlab-upgrade-banner-noise)
# - Line-based, deterministic, allowlist-only suppression
# - Applies ONLY to verbose printing of containerlab output
# ---------------------------------------------------------------------

from cassian_artifacts import (
    lab_dir, node_cfg_dir, write_file, write_json_canonical,
    load_yaml,
    topo_path_for_lab,
)

from cassian_model import (
    _validate_fabric_evpn_presence_only,
    ensure_valid_topology,
    gen_frr_daemons,
    gen_vtysh_conf,
    build_node_links,
    gen_frr_conf,
    topo_to_containerlab,
    resolve_topology,
    adapt_terraform_plan_json,
    adapt_ansible_rendered_dir,
    validate_contrib_path,
)

from cassian_tests import (
    ensure_nc,
    ip_no_mask,
    find_nodes_by_type,
    start_tcp_listener,
    stop_tcp_listeners,
    tcp_connect_test,
    node_first_ipv4,
    run_ping_once_or_die,
    run_tcp_test,
    run_declared_tests,
    connected_prefixes_for_router,
    _coverage_test_ids,
    _coverage_scenario_ids,
    _coverage_touch_nodes_from_test,
    derive_expected_routes_for_frr,
    parse_frr_show_ip_route_prefixes,
    parse_frr_show_ip_route_prefixes_json,
    parse_frr_bgp_summary_neighbors_json,
    derive_expected_bgp_neighbors_from_links,
    parse_frr_bgp_summary_neighbors,
    compare_expected_vs_observed_bgp,
    wait_for_bgp,
    configure_frr_static_routes_from_topology,
    configure_frr_bgp_from_topology,
    _parse_route_entry,
    configure_nftfw_routes_from_topology,
    verify_fw_routed_ready,
    _iter_scenarios,
    validate_scenarios,
    build_test_index,
    resolve_dst_to_ip,
    retry_until,
    wait_for_condition,
    execute_scenario,
    _atomic_test_ids,
    validate_scenario_run_refs_or_die,
    _render_scenarios_summary,
    _format_test_summary,
    write_test_summary_artifact,
    render_gate_result_block,
    _preflight_default_out,
    _preflight_write,
    _preflight_canonical_link_id,
    _preflight_contains_key,
    _preflight_get_touched_nodes,
    _preflight_get_touched_links,
    _preflight_load_adapters,
    _preflight_findings,
    _preflight_report,
    _preflight_format_text,
)

from cassian_runtime_container import (
    gen_nft_fw_rules,
    _coverage_canonical_link_id,
    _coverage_inventory_nodes,
    _coverage_inventory_links,
    _coverage_hash_resolved_topology,
    _coverage_resolve_link_between,
    build_coverage_model,
    write_coverage_artifact,
    write_containerlab_file,
    _normalize_prefix,
    compare_expected_vs_observed_prefixes,
    container_name,
    _node_index_by_name,
    configure_frr_interfaces_from_topology,
    configure_hosts_from_topology,
    host_configure,
    configure_nftfw_from_topology,
    nft_fw_apply,
    verify_host_ready,
    verify_frr_ready,
    verify_lab_ready,
    fw_next_hops_from_links,
    nft_fw_setup_bridge,
    evpn_leaf_setup_vxlan_from_topology,
    lab_file_from_name,
    parse_lab_nodes,
    docker_is_running,
    vty,
    resolved_topology_path,
    load_resolved_topology,
    frr_nodes_from_topology,
    _container_is_running,
    Runtime,
    ContainerRuntime,
    get_runtime,
    list_owned_labs_from_artifacts,
)

from cassian_two_run import _cmd_test_two_run
from cassian_candidate import _candidate_artifacts_dir, _write_candidate_apply_artifact, _candidate_parse_dir_or_die, _candidate_apply_frr_generated_only, _candidate_apply_nft
from cassian_state import _state_capture_expand_plan_or_die, _state_capture_write_plan, _state_capture_run_plan, _capture_config_run_exploration
from cassian_ai import cmd_ai_review
from cassian_engine import _safe_stdio, _sanitize_text, _truncate, _sha256_file, _invocation_reset_written_artifacts, _invocation_record_written_artifact, _command_uses_workspace_labs, _bind_workspace_labs_dir, _print_artifacts_footer_for_lab, load_topology_yaml, _filter_containerlab_line, _run_containerlab, _shell_quote
from cassian_engine import cmd_gen, cmd_validate, cmd_doctor, cmd_preflight, cmd_adapt_terraform, cmd_adapt_ansible
import cassian_engine
from cassian_engine import cmd_up, cmd_replay, cmd_down, cmd_destroy, cmd_cleanup, cmd_exec, cmd_vty, cmd_status, cmd_collect, cmd_run, _finalize_results_schema
from cassian_engine import cmd_test
from cassian_cli import main

# Phase-0 split guardrail marker (historical, inert).
# Corrected §4.5-b (REQ-45b-16b): the grep-based gate this marker served no
# longer exists -- tests/wf_12_13_replay_proof.py asserts both its absence from
# the repo and its non-reintroduction into the CI workflow. The modules it
# named were renamed in the Phase-0 split; ContainerRuntime lives in
# src/cassian_runtime_container.py today. The sentinel below is retained rather
# than removed so no external grep-based consumer breaks; it is inert.
_GUARDRAIL_VERIFY_PHASE1 = """
class ContainerRuntime
"""

# Phase-0 split guardrail marker (Patch 6/7) (historical, inert).
# Corrected §4.5-b (REQ-45b-16b): the grep-based gate this marker served no
# longer exists (see above). The 'validate-contrib' subparser and the
# 'validate_contrib_path' import live in src/cassian_cli.py. The sentinel below
# is retained rather than removed and is inert.
_GUARDRAIL_VERIFY_PHASE1_VALIDATE_CONTRIB = """
add_parser("validate-contrib"
validate_contrib_path
"""
# ------------------------------------------------------------------
# CLI / UX constants
# ------------------------------------------------------------------

# -------------------------
# FRR config generation (simple v1)
# -------------------------


# -------------------------
# Commands
# -------------------------
# -----------------------------
# results.json schema guarantee (v1.5)
# -----------------------------

import re

# --- Assistive AI (v1: advisory-only, artifact-only, post-exec, BYO-key online optional) ---

if __name__ == "__main__":
    main()
