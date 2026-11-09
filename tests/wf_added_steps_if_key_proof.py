#!/usr/bin/env python3
"""Added-step evidence-survival proof for cassian.yml (REQ-45D-27 / REQ-45D-28).

Every CI step §4.5-d adds carries ``if: success() || failure()`` at creation, so
an upstream failure never turns its evidence into a ``skipped`` step (v3.4-CI
§1: a skipped step is absence of evidence, never a pass or a fail). Until now
the key was applied by hand; ``BL-P2-4.5c-167`` records that nothing caught the
one omission among §4.5-c's sixteen. This file is the instrument the scope
recommends as that row's discharge shape. **Consuming the row is the founder's
placement; this file does not consume it.**

!! UNCOVERED CLASS -- PBE-P2-14 (stated here, as scope §9 rule 3 requires) !!
  Leg W-NAME's domain is an ENUMERATED LIST: the fifteen proof files of the
  scope's §9 table, matched to steps BY NAME (LD-45C-R31 R3). PBE-P2-14 holds
  that a guard derived through an enumerated domain is covered by no precedent
  in force. A §4.5-d step whose proof is not on the list, or whose name does not
  carry its file name, is invisible to W-NAME. The property-derived defence
  beside it is leg W-VM below, derived from the property "VM evidence must
  survive an upstream failure", not from the list. Leg W-LABEL is a second,
  narrower defence over the "§4.5-d" naming convention; it shares W-NAME's
  dependence on names.

Legs:
  W-NAME   for each of the fifteen §9 file names (the list below is the table's
           enumeration; its length is computed, never carried as a figure):
             - every step whose ``name`` contains the file name carries
               ``if: success() || failure()`` EXACTLY (REQ-45D-27's form);
             - a §9 file present under tests/ with no step naming it FAILS --
               a proof that no gate runs (the BL-P2-4.5c-109 class);
             - a §9 file not yet written and not yet stepped is PENDING:
               printed and counted, neither pass nor fail. At §4.5-d's closure
               the expected PENDING count is zero; this file does not enforce
               that, Chat 4's closure check does.
  W-VM     every step whose name contains "(VM)" runs after an upstream
           failure: its ``if:`` is ``success() || failure()`` or ``always()``.
           ``always()`` counts because the scope's own census does (handover
           §14.1: "15 (VM)-named, all keyed", fourteen with the key and the
           teardown sweep with ``always()``; read so at §4.5-d session 27 and
           recorded in the second session-27 rulings note, §3.1).
  W-LABEL  every step whose name contains "§4.5-d" carries
           ``if: success() || failure()`` exactly. It reaches the §4.5-d steps
           outside the §9 table (the -32 rc=5 proof, the EVPN precheck poll and
           the route-reflector next-hop-self proof).
  W-NV     non-vacuity: on in-memory copies of the parsed steps, each leg is
           shown to FAIL on a counter-example built from its own property --
           a key removed from a §9-named step, from a (VM)-named step and from
           a §4.5-d-labelled step outside §9; a present §9 proof whose step is
           renamed away; a new (VM)-named step added without a key.

Coverage limits, stated in-file (PBE-P2-8):
  - Reads .github/workflows/cassian.yml as YAML; it proves the KEY, not that a
    step runs, that the runner reaches it, or that its proof passes.
  - Names are the only join between a step and its proof (LD-45C-R31 R3).
  - It does not assert that pre-§4.5-d steps outside the (VM) class carry the
    key; ``BL-P2-4.5c-62`` records three that do not, outside §14.4.

Exit 0 on all-pass; exit 1 otherwise.
"""
import copy
import os
import sys

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "cassian.yml")
KEY = "success() || failure()"
SURVIVES = (KEY, "always()")

# Scope §9's named proof set, rows 1-15, in table order (LOCKED scope rev 9).
# Seven hosted, eight (VM). The count is len(SECTION_9_PROOFS), never a literal.
SECTION_9_PROOFS = (
    "sonic_observation_kinds_proof.py",       # 1 hosted
    "route_prefix_seam_parity_proof.py",      # 2 hosted
    "exec_rule_parity_proof.py",              # 3 hosted
    "sonic_exec_allowlist_proof.py",          # 4 hosted
    "sonic_ospf_unsupported_proof.py",        # 5 hosted
    "sonic_observed_state_render_proof.py",   # 6 hosted
    "wf_added_steps_if_key_proof.py",         # 7 hosted
    "sonic_rib_collection_live_proof.py",     # 8 (VM)
    "sonic_exec_live_proof.py",               # 9 (VM)
    "sonic_ping_through_proof.py",            # 10 (VM)
    "sonic_status_collect_proof.py",          # 11 (VM)
    "sonic_init_cfg_layering_proof.py",       # 12 (VM)
    "sonic_within_boot_reprovision_proof.py", # 13 (VM)
    "sonic_grey_failure_proof.py",            # 14 (VM)
    "sonic_bgp_session_live_proof.py",        # 15 (VM)
)

checks = []


def check(label, ok, detail=""):
    checks.append((label if not detail else "%s (%s)" % (label, detail), bool(ok)))


def load_steps(path=WORKFLOW):
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    out = []
    for job in (doc.get("jobs") or {}).values():
        for step in (job or {}).get("steps") or []:
            if isinstance(step, dict):
                out.append(step)
    return out


def if_of(step):
    v = step.get("if")
    return v.strip() if isinstance(v, str) else v


def w_name(steps, present):
    """Return (failures, pending, keyed) for W-NAME. `present`: file -> exists under tests/."""
    failures, pending, keyed = [], [], 0
    for f in SECTION_9_PROOFS:
        named = [s for s in steps if f in str(s.get("name") or "")]
        if not named:
            (failures if present(f) else pending).append(
                ("%s: proof present but no step names it" % f) if present(f) else f)
            continue
        for s in named:
            if if_of(s) == KEY:
                keyed += 1
            else:
                failures.append("%s: step %r has if=%r" % (f, s.get("name"), if_of(s)))
    return failures, pending, keyed


def w_vm(steps):
    vm = [s for s in steps if "(VM)" in str(s.get("name") or "")]
    bad = ["%r has if=%r" % (s.get("name"), if_of(s)) for s in vm if if_of(s) not in SURVIVES]
    return bad, len(vm)


def w_label(steps):
    lab = [s for s in steps if "§4.5-d" in str(s.get("name") or "")]
    bad = ["%r has if=%r" % (s.get("name"), if_of(s)) for s in lab if if_of(s) != KEY]
    return bad, len(lab)


def present_on_disk(f):
    return os.path.isfile(os.path.join(ROOT, "tests", f))


STEPS = load_steps()

# ---- shape of the enumerated domain ----------------------------------------
check("domain: the §9 list has no duplicate", len(set(SECTION_9_PROOFS)) == len(SECTION_9_PROOFS))
check("domain: every §9 entry is a *_proof.py file name",
      all(f.endswith("_proof.py") and "/" not in f for f in SECTION_9_PROOFS))
check("domain: this file is on the list it checks", os.path.basename(__file__) in SECTION_9_PROOFS)
check("workflow parsed: steps found", len(STEPS) > 0, "steps=%d" % len(STEPS))

# ---- W-NAME ----------------------------------------------------------------
_f, _p, _k = w_name(STEPS, present_on_disk)
check("W-NAME every step naming a §9 proof carries if: %s, and no present §9 proof is unstepped" % KEY,
      not _f, "; ".join(_f))
check("W-NAME at least one §9 step examined (the leg was reached)", _k > 0, "keyed=%d" % _k)
_stepped = sum(1 for f in SECTION_9_PROOFS if any(f in str(s.get("name") or "") for s in STEPS))
print("W-NAME: %d of %d §9 proofs named by a step; %d keyed step(s); PENDING (not yet written, not stepped): %d%s"
      % (_stepped, len(SECTION_9_PROOFS), _k, len(_p), (" -- " + ", ".join(_p)) if _p else ""))

# ---- W-VM ------------------------------------------------------------------
_b, _n = w_vm(STEPS)
check("W-VM every (VM)-named step runs after an upstream failure (if: %s or always())" % KEY,
      not _b, "; ".join(_b))
check("W-VM at least one (VM)-named step examined (the leg was reached)", _n > 0, "vm_steps=%d" % _n)
print("W-VM: %d (VM)-named steps examined" % _n)

# ---- W-LABEL ---------------------------------------------------------------
_b, _n = w_label(STEPS)
check("W-LABEL every §4.5-d-labelled step carries if: %s" % KEY, not _b, "; ".join(_b))
check("W-LABEL at least one §4.5-d step examined (the leg was reached)", _n > 0, "labelled=%d" % _n)
print("W-LABEL: %d §4.5-d-labelled steps examined" % _n)

# ---- W-NV ------------------------------------------------------------------
def _first(steps, pred):
    for i, s in enumerate(steps):
        if pred(s):
            return i
    return None


def _unkey(steps, i):
    m = copy.deepcopy(steps)
    m[i].pop("if", None)
    return m


_i9 = _first(STEPS, lambda s: any(f in str(s.get("name") or "") for f in SECTION_9_PROOFS))
_ivm = _first(STEPS, lambda s: "(VM)" in str(s.get("name") or ""))
_ilab = _first(STEPS, lambda s: "§4.5-d" in str(s.get("name") or "")
               and not any(f in str(s.get("name") or "") for f in SECTION_9_PROOFS))
check("W-NV vehicles found: a §9 step, a (VM) step, a §4.5-d step outside §9",
      None not in (_i9, _ivm, _ilab), "i9=%s ivm=%s ilab=%s" % (_i9, _ivm, _ilab))
if None not in (_i9, _ivm, _ilab):
    check("W-NV W-NAME fails when a §9 step loses its key",
          bool(w_name(_unkey(STEPS, _i9), present_on_disk)[0]))
    check("W-NV W-VM fails when a (VM) step loses its key", bool(w_vm(_unkey(STEPS, _ivm))[0]))
    check("W-NV W-LABEL fails when a §4.5-d step outside §9 loses its key",
          bool(w_label(_unkey(STEPS, _ilab))[0]))
    _ren = copy.deepcopy(STEPS)
    _ren[_i9]["name"] = "renamed step"
    check("W-NV W-NAME fails when a present §9 proof's step no longer names it",
          bool(w_name(_ren, present_on_disk)[0]))
    _add = copy.deepcopy(STEPS) + [{"name": "SONiC new leg (VM) — x_proof.py (§4.5-d)", "run": "true"}]
    check("W-NV W-VM fails when a (VM) step is added without a key", bool(w_vm(_add)[0]))
    check("W-NV W-LABEL fails when a §4.5-d step is added without a key", bool(w_label(_add)[0]))
    _pend = w_name(STEPS, lambda f: True)[0]
    check("W-NV a not-yet-stepped §9 proof becomes a FAIL once its file exists",
          (not _p) or bool(_pend))

ok = True
for name, passed in checks:
    print("[%s] %s" % ("PASS" if passed else "FAIL", name))
    ok = ok and passed
print("=" * 60)
print("cases:", len(checks))
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
