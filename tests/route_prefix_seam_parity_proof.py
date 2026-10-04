#!/usr/bin/env python3
"""route_prefix_seam_parity_proof.py -- §4.5-d H1-b3 script 1b (REQ-45D-2, LD-45D-1).

The FRR before/after differential that REQ-45D-2 (handover §3 row 3, §15.2) and
founder ruling D-1 (2026-09-30) bind: `route_prefix` moves onto the NOS seam at
BOTH engine sites -- the test path `run_route_prefix_test` and the scenario
`wait_for route_prefix` branch -- and no FRR verdict may move on any committed
fixture. Any delta there is a HALT, never a fix-in-place.

Method. Lab-free. Both engine sites are executed from their source text inside
cassian_engine's namespace (the idiom of bgp_as_path_authority_parity_proof.py),
against a fake runtime that answers the kernel-FIB read for each node:
  BEFORE  the pre-seam texts, frozen below from cassian-gate@a2fcae5 by AST line
          span and pinned by sha256 (the oracle never changes with the tree);
  AFTER   the same two sites extracted from the live src/cassian_engine.py.
The scenario oracle is the live wait_for_predicate with only its route_prefix
branch replaced by the frozen one, so the two runs differ in that branch alone.

Widened by H1-b3 script 2a (founder rulings Q20-3 (i) of 2026-10-02, and F-S21-1
(A) and R2 of 2026-10-03). This proof's property is no longer route_prefix alone:
section P-RP also holds the route_present / route_absent consumer of
run_invariant_test (test path) and the wait_for route_present branch of
wait_for_predicate (scenario) to FRR rc-0 parity and to never-a-pass on a read the
provider cannot vouch for, for both NOSes. The file name is kept because it is
CI-wired and named in wf_12_13_replay_proof.py's §4.5-d loop.

Sections:
  P-ORACLE  the frozen texts are the a2fcae5 extraction (sha256 pinned).
  P-SITES   no route command is issued from core at either site; each calls
            _nos_collect(kind="route_prefix") once (handover §18 L558, read
            with D-1: the check reaches both core sites).
  P-PARITY  every committed fixture's route_prefix test and route_prefix wait
            (enumerated by walking topologies/ and examples/), each in the
            present and the absent state: identical verdict, observed, record
            (test path, duration excluded) and evidence / last_rc (scenario).
  P-DECL    the deltas DECLARED under DC v2.1 §14 item 8, each shown to differ
            in its declared direction and nowhere else:
              D-1   IPv6 prefix on the scenario path (the retired read was -4 only);
              D-1   /32 host route on the scenario path (the retired substring
                    rule missed it; read of record, session-18 note §5);
              Q-A   host vantage: test path refusal -> registry die (exit 2);
                    scenario working read -> registry die (exit 2);
              Q-A   nft-fw vantage: refusal text changes and expect: fail stops
                    passing (explicit UNSUP-fail); scenario wait raises the UNSUP;
              Q20-2 scenario last_rc reports the read's own rc (retired form
                    forced 0 with `|| true`); verdict unchanged.
            Observed, not changed (ZERO-TOUCH meta block, D-1): an expect: pass
            wait that times out raises TypeError at time_to_success_ms
            (int(None)) in both forms, for every wait_for type (F-S20-2).
  P-NEVER   ruling (I): a read the provider cannot vouch for (probe_ok False)
            is verdict fail regardless of expect on the test path, and raises on
            the scenario path. SONiC route_prefix stays UNSUP until script 2.
  P-RP      (script 2a) ORACLE: each consumer is the live function with exactly
            the 2a guard text removed, sha256-pinned to the f015801 extraction.
            PARITY: FRR rc 0, every committed route_present / route_absent test
            and route_present wait plus a synthetic matrix -- identical before and
            after. DECL (DC v2.1 §14 item 8): FRR non-zero rc on the test path
            (verdict fail) and on the scenario path (raises); a provider without
            the kind on the scenario path (raises with the UNSUP reason). UNSUP:
            the test path's recorded misuse and exit 2, unchanged. NEVER: a read
            the provider cannot vouch for is verdict fail for both kinds and both
            expects, asserting the record's verdict as well as its observed, and
            raises on the scenario path.
  P-NV      mutation controls on the consumed surfaces (the executed engine
            text and FRR's handler): each must turn a check above red. A
            detected mutant prints MUTATION-FAIL; an undetected one prints
            CONTROL BROKEN.

Exit 0 on all-pass; exit 1 on any failure.
"""
import ast
import copy
import glob
import hashlib
import ipaddress
import os
import re
import sys
import textwrap
from types import SimpleNamespace

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)

import cassian_engine as E  # noqa: E402
import cassian_nos_frr as FRR  # noqa: E402
from cassian_nos_types import Observation  # noqa: E402

import contextlib  # noqa: E402
import io  # noqa: E402

import cassian_common as C  # noqa: E402

# die() is left in its production form (print, then SystemExit(code)): Q-A's
# registry UNSUP is asserted as exit code 2, its text read from LAST_ERROR_MSG.

checks = []


def check(name, cond):
    checks.append((name, bool(cond)))


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ------------------------------------------------------------ frozen oracle
# Extracted from cassian-gate@a2fcae5 src/cassian_engine.py by AST line span,
# textwrap.dedent'ed (session-20 B0). Copied, never edited.
OLD_RPT_SHA256 = "90ef4a4f37c07cdd0e954844a6601ffc4345166fe0266ae98c6851aefd16138c"
OLD_RPT = r'''def run_route_prefix_test(*, test_name: str, src: str, t: dict, record_fn=record_test) -> str:
    """
    v1.5: per-prefix assertion (execution-backed), minimal deterministic parsing.
    - src: vantage node name (runs check here)
    - prefix: CIDR string
    - expect: pass|fail (negative semantics preserved)
    Current v1.5 support: frr nodes only (vtysh).
    """
    prefix = str(t.get("prefix") or "").strip()

    expected = str(t.get("expect") or "pass").strip().lower()
    if expected not in ("pass", "fail"):
        expected = "pass"

    # Resolve node type deterministically from resolved topology
    node_type = ""
    for n in (topo.get("nodes") or []):
        if isinstance(n, dict) and n.get("name") == src:
            node_type = str(n.get("type") or "").strip().lower()
            break

    start = time.time()

    if node_type != "frr":
        dur_ms = int((time.time() - start) * 1000)
        observed = "fail"
        verdict = "fail" if expected == "pass" else "pass"
        record_fn(
            name=test_name,
            kind="route_prefix",
            src=src,
            dst="",
            expected=expected,
            observed=observed,
            verdict=verdict,
            duration_ms=dur_ms,
            error=f"route_prefix unsupported on node type '{node_type}' (supported: frr only)",
            evidence={"reason": "unsupported_node_type"},
            meta={"prefix": prefix, "node_type": node_type},
        )
        return verdict

    # Deterministic route presence check (kernel FIB)
    # Rationale: connected routes + installed routes are observable here even if FRR daemons/vtysh view differs.
    try:
        nw = ipaddress.ip_network(prefix, strict=False)
        ipver = nw.version
    except Exception:
        # Should have been caught in resolve-time validation; keep deterministic failure here.
        ipver = 4

    ip_cmd = ["ip", f"-{ipver}", "route", "show", prefix]
    cp = rt.exec(lab, src, ip_cmd, check=False, capture_output=True)

    # rt.exec() may return a CompletedProcess-like object OR a raw string.
    if isinstance(cp, str):
        out = cp
        rc = None
    else:
        out = ""
        if hasattr(cp, "stdout") and cp.stdout is not None:
            out = cp.stdout
        elif hasattr(cp, "output") and cp.output is not None:
            out = cp.output

        # Normalize bytes -> str (defensive)
        if isinstance(out, (bytes, bytearray)):
            try:
                out = out.decode("utf-8", errors="replace")
            except Exception:
                out = str(out)

        rc = getattr(cp, "returncode", None)

    out = str(out or "")
    # Deterministic presence rule for `ip route show <prefix>`:
    # - present => prints one or more lines
    # - absent  => prints nothing
    present = bool(out.strip())

    observed = "pass" if present else "fail"
    verdict = "pass" if observed == expected else "fail"

    dur_ms = int((time.time() - start) * 1000)
    record_fn(
        name=test_name,
        kind="route_prefix",
        src=src,
        dst="",
        expected=expected,
        observed=observed,
        verdict=verdict,
        duration_ms=dur_ms,
        error="" if verdict == "pass" else f"route_prefix mismatch (expected {expected}, observed {observed})",
        evidence={"cmd": " ".join(ip_cmd), "rc": rc},
        meta={"prefix": prefix, "present": bool(present)},
    )
    return verdict
'''

OLD_BRANCH_SHA256 = "691a73935b0db1cb2eee6eb4128025be7849aa2c577957f2a73486985bb9f57c"
OLD_BRANCH = r'''        if wtype == "route_prefix":
            # Vantage node is wait_for.src (normalized from on->src in resolve)
            vantage = wait_for.get("src") or wait_for.get("on")
            if not isinstance(vantage, str) or not vantage.strip():
                raise ValueError("wait_for route_prefix: requires src/on as a node name")

            prefix = wait_for.get("prefix")
            if not isinstance(prefix, str) or not prefix.strip():
                raise ValueError("wait_for route_prefix: requires prefix as CIDR")

            # Deterministic: ip route lookup should be fast; per_attempt_timeout_s is recorded.
            cmd = ["sh", "-lc", f"ip -4 route show {prefix.strip()} 2>/dev/null || true"]
            cp = rt.exec(lab, str(vantage).strip(), cmd, check=False)
            last_cp = cp

            out = getattr(cp, "stdout", "") or ""
            if isinstance(out, (bytes, bytearray)):
                try:
                    out = out.decode("utf-8", errors="replace")
                except Exception:
                    out = str(out)

            present = (prefix.strip() in str(out))

            # Underlying success for route_prefix is: present == True (uniform success definition)
            last_obs = "pass" if present else "fail"
            last_evidence = {
                "cmd": f"ip -4 route show {prefix.strip()}",
                "prefix": prefix.strip(),
                "present": bool(present),
                "last_rc": getattr(cp, "returncode", None),
            }

            attempt_success = (last_obs == "pass")
            return attempt_success, (cp, last_obs)
'''

# The /32 read of record (session-18 note §5): `ip -4 route show 198.18.32.1/32`
# on an FRR node, 31 bytes, identical in the test-path and scenario forms.
HOST32 = "198.18.32.1/32"
HOST32_READ = "198.18.32.1 dev lo scope link \n"
HOST32_READ_SHA256 = "a8cbfc1c2b89edfcee9f237e6eb6c4ebe0b50db05d5e5825c51223b2f8b887ec"

HEAD = '        if wtype == "route_prefix":\n'
SEP = "\n        # -------------------------\n        # type: bgp_session_up"

try:
    with open(os.path.join(_SRC, "cassian_engine.py"), encoding="utf-8") as fh:
        ENG_SRC = fh.read()
    LINES = ENG_SRC.splitlines(keepends=True)
    FN = {n.name: n for n in ast.walk(ast.parse(ENG_SRC)) if isinstance(n, ast.FunctionDef)}

    def seg(name):
        n = FN[name]
        return textwrap.dedent("".join(LINES[n.lineno - 1:n.end_lineno]))

    NEW_RPT = seg("run_route_prefix_test")
    NEW_WFP = seg("wait_for_predicate")

    def split_branch(wfp):
        assert wfp.count(HEAD) == 1 and wfp.count(SEP) == 1, "branch markers not unique"
        i = wfp.index(HEAD)
        j = wfp.index(SEP, i)
        return wfp[:i], wfp[i:j], wfp[j:]

    _pre, NEW_BRANCH, _post = split_branch(NEW_WFP)
    OLD_WFP = _pre + OLD_BRANCH + _post

    # --------------------------------------------------------------- P-ORACLE
    check("P-ORACLE frozen run_route_prefix_test is the a2fcae5 extraction (sha256 pinned)",
          sha(OLD_RPT) == OLD_RPT_SHA256)
    check("P-ORACLE frozen scenario route_prefix branch is the a2fcae5 extraction (sha256 pinned)",
          sha(OLD_BRANCH) == OLD_BRANCH_SHA256)
    check("P-ORACLE the /32 read of record is byte-exact (31 bytes, sha256 pinned)",
          len(HOST32_READ.encode()) == 31 and sha(HOST32_READ) == HOST32_READ_SHA256)

    # ---------------------------------------------------------------- P-SITES
    for _name, _text in (("run_route_prefix_test", NEW_RPT), ("scenario route_prefix branch", NEW_BRANCH)):
        check(f"P-SITES {_name}: no route command issued from core ('ip route show' / 'ip -' / rt.exec absent)",
              not re.search(r"ip route show|ip -", _text) and "rt.exec" not in _text)
        check(f"P-SITES {_name}: exactly one _nos_collect call, kind route_prefix",
              _text.count("_nos_collect(") == 1 and 'ObservationRequest(kind="route_prefix"' in _text)
    check("P-SITES the frozen oracle does issue the core reads (the check above can fail)",
          "rt.exec" in OLD_RPT and "rt.exec" in OLD_BRANCH and re.search(r"ip -", OLD_BRANCH))

    # ----------------------------------------------------------- harness
    class FakeRt:
        """Answers the kernel-FIB read per node. `fib` maps node -> list of
        (network, printed line). The retired scenario form runs under
        `sh -lc '… 2>/dev/null || true'`, so its rc is 0 whatever ip returns."""

        def __init__(self, fib, rc=0, present_after=None):
            self.fib, self.rc, self.present_after, self.calls = fib, rc, present_after, []

        def _show(self, node, fam, pfx):
            if self.present_after is not None and len(self.calls) <= self.present_after:
                return ""
            try:
                want = ipaddress.ip_network(pfx, strict=False)
            except ValueError:
                return ""
            if want.version != fam:
                return ""
            return "".join(line for net, line in self.fib.get(node, []) if net == want)

        def exec(self, lab, node, argv, check=False, **_kw):
            self.calls.append(list(argv))
            if argv[:2] == ["sh", "-lc"]:
                m = re.fullmatch(r"ip -(4|6) route show (\S+) 2>/dev/null \|\| true", argv[2])
                assert m, f"unexpected shell form {argv!r}"
                out = "" if self.rc else self._show(node, int(m.group(1)), m.group(2))
                return SimpleNamespace(returncode=0, stdout=out, stderr="")
            if argv[:1] == ["ip"] and argv[2:4] == ["route", "show"] and len(argv) == 5:
                fam = int(argv[1][1:])
                if self.rc:
                    return SimpleNamespace(returncode=self.rc, stdout="", stderr="Error")
                return SimpleNamespace(returncode=0, stdout=self._show(node, fam, argv[4]), stderr="")
            raise AssertionError(f"unexpected argv {argv!r}")

    def line_for(prefix):
        net = ipaddress.ip_network(prefix, strict=False)
        if prefix == HOST32:
            return (net, HOST32_READ)
        if net.version == 6:
            return (net, f"{prefix} dev eth1 proto kernel metric 256 pref medium\n")
        return (net, f"{prefix} via 10.0.0.2 dev eth1 proto bgp metric 20 \n")

    def ns_for(text, topo, rt):
        ns = dict(E.__dict__)
        ns.update(topo=topo, rt=rt, lab="lab", record_test=lambda **_kw: None)
        exec(compile(text, "<route_prefix_seam_parity_proof>", "exec"), ns)
        return ns

    def run_test(text, topo, rt, t, src):
        cap = {}
        ns = ns_for(text, topo, rt)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                verdict = ns["run_route_prefix_test"](test_name="t", src=src, t=t,
                                                      record_fn=lambda **kw: cap.update(kw))
        except SystemExit as exc:
            return ("exit", exc.code), None
        rec = {k: v for k, v in cap.items() if k != "duration_ms"}
        return ("verdict", verdict), rec

    def run_wait(text, topo, rt, wf):
        ns = ns_for(text, topo, rt)
        w = dict(wf, timeout=1, interval_s=0.05)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                wtype, expected, observed, _dur, meta, verdict = ns["wait_for_predicate"](w)
        except SystemExit as exc:
            return ("exit", exc.code), None
        except Exception as exc:  # the scenario runner records a raised wait as a failed step
            return ("raise", type(exc).__name__, str(exc)), None
        stable = {k: meta[k] for k in ("type", "from", "succeeded", "last_rc", "evidence") if k in meta}
        return ("verdict", verdict, observed), stable

    def topo_of(doc, vantage_type=None, vantage=None):
        nodes = copy.deepcopy(doc.get("nodes") or [])
        if vantage_type is not None:
            for n in nodes:
                if isinstance(n, dict) and n.get("name") == vantage:
                    n["type"] = vantage_type
        return {"nodes": nodes}

    # ---------------------------------------------------------------- P-PARITY
    fixtures_tests, fixtures_waits = [], []
    for path in sorted(glob.glob(os.path.join(_ROOT, "topologies", "*.yaml"))
                       + glob.glob(os.path.join(_ROOT, "examples", "*.yaml"))):
        with open(path, encoding="utf-8") as fh:
            try:
                doc = yaml.safe_load(fh)
            except yaml.YAMLError:
                continue
        if not isinstance(doc, dict):
            continue
        rel = os.path.relpath(path, _ROOT)
        for t in doc.get("tests") or []:
            if isinstance(t, dict) and t.get("kind") == "route_prefix":
                fixtures_tests.append((rel, doc, t))
        for s in doc.get("scenarios") or []:
            for st in (s.get("steps") or []) if isinstance(s, dict) else []:
                wf = st.get("wait_for") if isinstance(st, dict) else None
                if isinstance(wf, dict) and wf.get("type") == "route_prefix":
                    fixtures_waits.append((rel, doc, wf))

    check("P-PARITY enumeration found route_prefix tests and waits in the committed fixtures",
          len(fixtures_tests) > 0 and len(fixtures_waits) > 0)
    print(f"P-PARITY enumerated {len(fixtures_tests)} route_prefix test(s), "
          f"{len(fixtures_waits)} route_prefix wait(s)")

    def parity_deltas(rpt_text, wfp_old, wfp_new):
        deltas = []
        for rel, doc, t in fixtures_tests:
            src = str(t.get("src") or "")
            topo = topo_of(doc)
            for present in (True, False):
                fib = {src: [line_for(str(t.get("prefix")))]} if present else {}
                a = run_test(OLD_RPT, topo, FakeRt(fib), dict(t), src)
                b = run_test(rpt_text, topo, FakeRt(fib), dict(t), src)
                if a != b:
                    deltas.append((rel, t.get("name"), present, a, b))
        for rel, doc, wf in fixtures_waits:
            vantage = str(wf.get("src") or wf.get("on") or "")
            topo = topo_of(doc)
            states = [("present", {vantage: [line_for(str(wf.get("prefix")))]}, None),
                      ("absent", {}, None),
                      ("becomes-present", {vantage: [line_for(str(wf.get("prefix")))]}, 1)]
            for label, fib, after in states:
                a = run_wait(wfp_old, topo, FakeRt(fib, present_after=after), dict(wf))
                b = run_wait(wfp_new, topo, FakeRt(fib, present_after=after), dict(wf))
                if a != b:
                    deltas.append((rel, wf.get("prefix"), label, a, b))
        return deltas

    _deltas = parity_deltas(NEW_RPT, OLD_WFP, NEW_WFP)
    for _d in _deltas:
        print("DELTA:", _d)
    check("P-PARITY zero FRR verdict / record / evidence deltas on every committed fixture, "
          "present, absent and becomes-present (REQ-45D-2; D-1: any delta is a HALT)",
          not _deltas)

    # ------------------------------------------------------------------ P-DECL
    R1 = {"nodes": [{"name": "r1", "type": "frr"}]}

    def wf_for(prefix, expect, vantage="r1"):
        return {"type": "route_prefix", "from": vantage, "src": vantage, "prefix": prefix, "expect": expect}

    def t_for(prefix, expect, src="r1"):
        return {"name": "t", "kind": "route_prefix", "src": src, "prefix": prefix, "expect": expect}

    # D-1, IPv6 on the scenario path.
    V6 = "2001:db8:1::/64"
    fib6 = {"r1": [line_for(V6)]}
    a = run_wait(OLD_WFP, R1, FakeRt(fib6), wf_for(V6, "fail"))
    b = run_wait(NEW_WFP, R1, FakeRt(fib6), wf_for(V6, "fail"))
    check("P-DECL D-1 IPv6 (scenario, expect fail): retired -4 read saw nothing (verdict pass); "
          "seam read sees the route (verdict fail)",
          a[0] == ("verdict", "pass", "fail") and b[0] == ("verdict", "fail", "pass"))
    a = run_wait(OLD_WFP, R1, FakeRt(fib6), wf_for(V6, "pass"))
    b = run_wait(NEW_WFP, R1, FakeRt(fib6), wf_for(V6, "pass"))
    check("P-DECL D-1 IPv6 (scenario, expect pass): retired read timed out (raised in the meta block, "
          "F-S20-2); seam read passes",
          a[0][:2] == ("raise", "TypeError") and b[0] == ("verdict", "pass", "pass"))
    check("P-DECL D-1 IPv6 (test path): no delta -- both forms read -6",
          run_test(OLD_RPT, R1, FakeRt(fib6), t_for(V6, "pass"), "r1")
          == run_test(NEW_RPT, R1, FakeRt(fib6), t_for(V6, "pass"), "r1"))

    # D-1, /32 on the scenario path (read of record).
    fib32 = {"r1": [line_for(HOST32)]}
    a = run_wait(OLD_WFP, R1, FakeRt(fib32), wf_for(HOST32, "fail"))
    b = run_wait(NEW_WFP, R1, FakeRt(fib32), wf_for(HOST32, "fail"))
    check("P-DECL D-1 /32 (scenario, expect fail): retired substring rule read it absent (verdict pass); "
          "seam rule reads it present (verdict fail)",
          a[0] == ("verdict", "pass", "fail") and b[0] == ("verdict", "fail", "pass"))
    a = run_wait(OLD_WFP, R1, FakeRt(fib32), wf_for(HOST32, "pass"))
    b = run_wait(NEW_WFP, R1, FakeRt(fib32), wf_for(HOST32, "pass"))
    check("P-DECL D-1 /32 (scenario, expect pass): retired rule timed out (raised in the meta block, "
          "F-S20-2); seam rule passes",
          a[0][:2] == ("raise", "TypeError") and b[0] == ("verdict", "pass", "pass"))
    check("P-DECL D-1 /32 (test path): no delta -- both apply present <=> non-empty",
          run_test(OLD_RPT, R1, FakeRt(fib32), t_for(HOST32, "pass"), "r1")
          == run_test(NEW_RPT, R1, FakeRt(fib32), t_for(HOST32, "pass"), "r1"))

    # Q-A, host vantage.
    H1 = {"nodes": [{"name": "h1", "type": "host"}]}
    fibh = {"h1": [line_for("192.0.2.0/24")]}
    a = run_test(OLD_RPT, H1, FakeRt(fibh), t_for("192.0.2.0/24", "pass", "h1"), "h1")
    b = run_test(NEW_RPT, H1, FakeRt(fibh), t_for("192.0.2.0/24", "pass", "h1"), "h1")
    check("P-DECL Q-A host (test path): recorded refusal -> registry UNSUP die, exit 2",
          a[0] == ("verdict", "fail") and "supported: frr only" in (a[1] or {}).get("error", "")
          and b == (("exit", 2), None)
          and "unsupported node type 'host'" in C.LAST_ERROR_MSG
          and "no NOS provider is registered" in C.LAST_ERROR_MSG)
    a = run_wait(OLD_WFP, H1, FakeRt(fibh), wf_for("192.0.2.0/24", "pass", "h1"))
    b = run_wait(NEW_WFP, H1, FakeRt(fibh), wf_for("192.0.2.0/24", "pass", "h1"))
    check("P-DECL Q-A host (scenario): working core read (pass) -> registry UNSUP die, exit 2",
          a[0] == ("verdict", "pass", "pass") and b == (("exit", 2), None)
          and "unsupported node type 'host'" in C.LAST_ERROR_MSG)

    # Q-A, nft-fw vantage.
    F1 = {"nodes": [{"name": "fw", "type": "nft-fw"}]}
    fibf = {"fw": [line_for("192.0.2.0/24")]}
    a = run_test(OLD_RPT, F1, FakeRt(fibf), t_for("192.0.2.0/24", "fail", "fw"), "fw")
    b = run_test(NEW_RPT, F1, FakeRt(fibf), t_for("192.0.2.0/24", "fail", "fw"), "fw")
    check("P-DECL Q-A nft-fw (test path): expect: fail passed on a refusal -> explicit UNSUP-fail, verdict fail",
          a[0] == ("verdict", "pass") and b[0] == ("verdict", "fail")
          and b[1]["observed"] == "fail" and b[1]["evidence"].get("reason") == "unsupported_provider_capability"
          and "route_prefix unsupported on node type 'nft-fw'" in b[1]["error"])
    b2 = run_test(NEW_RPT, F1, FakeRt(fibf), t_for("192.0.2.0/24", "pass", "fw"), "fw")
    check("P-DECL Q-A nft-fw (test path): expect: pass is also verdict fail (regardless of expect)",
          b2[0] == ("verdict", "fail"))
    a = run_wait(OLD_WFP, F1, FakeRt(fibf), wf_for("192.0.2.0/24", "pass", "fw"))
    b = run_wait(NEW_WFP, F1, FakeRt(fibf), wf_for("192.0.2.0/24", "pass", "fw"))
    check("P-DECL Q-A nft-fw (scenario): working core read -> the wait raises the provider UNSUP",
          a[0] == ("verdict", "pass", "pass") and b[0][0] == "raise"
          and b[0][1] == "NosCapabilityUnsupported" and "route_prefix" in b[0][2] and "nft-fw" in b[0][2])

    # Q20-2, last_rc on a failed ip read.
    fib4 = {"r1": [line_for("192.0.2.0/24")]}
    a = run_wait(OLD_WFP, R1, FakeRt(fib4, rc=2), wf_for("192.0.2.0/24", "fail"))
    b = run_wait(NEW_WFP, R1, FakeRt(fib4, rc=2), wf_for("192.0.2.0/24", "fail"))
    check("P-DECL Q20-2 (scenario): last_rc 0 (forced by || true) -> 2, the read's own rc; verdict unchanged",
          a[0] == b[0] and a[1]["last_rc"] == 0 and b[1]["last_rc"] == 2
          and a[1]["evidence"]["last_rc"] == 0 and b[1]["evidence"]["last_rc"] == 2)
    check("P-DECL Q20-2 (test path): no delta -- both forms recorded the read's own rc",
          run_test(OLD_RPT, R1, FakeRt(fib4, rc=2), t_for("192.0.2.0/24", "pass"), "r1")
          == run_test(NEW_RPT, R1, FakeRt(fib4, rc=2), t_for("192.0.2.0/24", "pass"), "r1"))

    # ----------------------------------------------------------------- P-NEVER
    def stub_collect(rt, lab, node, ntype, request, seam):
        p = request.params["prefix"]
        return Observation(kind=request.kind, data={"prefix": p, "routes": [p]},
                           evidence={"cmd": "stub", "rc": 1, "parse_error": "read not vouched for", "probe_ok": False})

    def run_test_stub(text, expect):
        cap = {}
        ns = ns_for(text, R1, FakeRt({}))
        ns["_nos_collect"] = stub_collect
        v = ns["run_route_prefix_test"](test_name="t", src="r1", t=t_for("192.0.2.0/24", expect),
                                        record_fn=lambda **kw: cap.update(kw))
        return v, cap

    def run_wait_stub(text, expect):
        ns = ns_for(text, R1, FakeRt({}))
        ns["_nos_collect"] = stub_collect
        try:
            ns["wait_for_predicate"](dict(wf_for("192.0.2.0/24", expect), timeout=1, interval_s=0.05))
        except RuntimeError as exc:
            return "raise", str(exc)
        return "returned", ""

    def never_pass_test(text):
        vp, cp = run_test_stub(text, "pass")
        vf, cf = run_test_stub(text, "fail")
        return (vp == "fail" and vf == "fail" and cf.get("observed") == "fail"
                and cf.get("evidence", {}).get("parse_error") == "read not vouched for")

    def never_pass_wait(text):
        return all(run_wait_stub(text, e)[0] == "raise" and "collection failed" in run_wait_stub(text, e)[1]
                   for e in ("pass", "fail"))

    check("P-NEVER test path: probe_ok False is verdict fail for expect pass AND expect fail, reason recorded (ruling (I))",
          never_pass_test(NEW_RPT))
    check("P-NEVER scenario: probe_ok False raises (the wait fails regardless of expect; ruling (I))",
          never_pass_wait(NEW_WFP))
    S1 = {"nodes": [{"name": "s1", "type": "sonic-vm"}]}
    v = run_test(NEW_RPT, S1, FakeRt({}), t_for("192.0.2.0/24", "fail", "s1"), "s1")
    check("P-NEVER sonic-vm route_prefix stays UNSUP until script 2: explicit UNSUP-fail, verdict fail",
          v[0] == ("verdict", "fail") and v[1]["evidence"].get("reason") == "unsupported_provider_capability")

    # ------------------------------------------------------------------- P-RP
    # H1-b3 script 2a (rulings Q20-3 (i), F-S21-1 (A), R2). Oracles are the live
    # functions with exactly the guard text below removed; that removal must
    # reproduce the f015801 extraction byte for byte.
    import json as _json

    RIT_ORACLE_SHA256 = "2a2fa73c2fb47283e1dbdbb6486dced205999473972b511af4eaab0a640e5d2a"
    WFP_ORACLE_SHA256 = "f90862ca977f6193ba3607ae8fe01f024cc988345036a32485e9b11b41499529"
    GUARD_RIT = '''\
        # Q20-3 (founder ruling (i) of 2026-10-02, an SP #1 bounded-scope amendment;
        # finding F-S20-1): a read the provider cannot vouch for (probe_ok False)
        # is an explicit collection failure for both NOSes -- verdict fail
        # regardless of expect, never an absent answer (Doctrine 1.11). The shape
        # of run_route_prefix_test's collection-failure record.
        if not _vtysh_ok:
            _parse_error = str(last_evidence.get("parse_error") or "")
            _cf_evidence = {
                "cmd": last_evidence.get("cmd") or "vtysh -c 'show ip route json'",
                "rc": rc,
            }
            if _parse_error:
                _cf_evidence["parse_error"] = _parse_error
            record_fn(
                name=test_name,
                kind="invariant",
                src=src,
                dst="",
                expected=expected,
                observed="fail",
                verdict="fail",
                duration_ms=int((time.time() - start) * 1000),
                error=f"{inv_type} collection failed on '{src}': {_parse_error or 'probe not ok'}",
                evidence=_cf_evidence,
                meta={
                    "type": inv_type,
                    "prefix": norm_prefix,
                },
            )
            return "fail"

'''
    GUARD_WFP = '''\
            if not vtysh_ok:
                # F-S21-1 (founder ruling (A) of 2026-10-03, an SP #1 bounded-scope
                # amendment): a read the provider cannot vouch for, or a provider
                # that does not declare the kind, fails the wait step regardless
                # of expect -- the scenario behaviour script 1b gave route_prefix.
                _parse_error = str((evidence or {}).get("parse_error") or "")
                raise RuntimeError(
                    f"wait_for route_present: collection failed on '{str(src).strip()}': "
                    f"{_parse_error or 'probe not ok'}"
                )
'''
    NEW_RIT = seg("run_invariant_test")
    NEW_EIA = seg("_evaluate_invariant_attempt")
    OLD_RIT = NEW_RIT.replace(GUARD_RIT, "")
    OLD_WFP_RP = NEW_WFP.replace(GUARD_WFP, "")
    check("P-RP-ORACLE run_invariant_test carries the Q20-3 guard exactly once and is otherwise "
          "the f015801 extraction (sha256 pinned)",
          NEW_RIT.count(GUARD_RIT) == 1 and sha(OLD_RIT) == RIT_ORACLE_SHA256)
    check("P-RP-ORACLE wait_for_predicate carries the F-S21-1 guard exactly once and is otherwise "
          "the f015801 extraction (sha256 pinned)",
          NEW_WFP.count(GUARD_WFP) == 1 and sha(OLD_WFP_RP) == WFP_ORACLE_SHA256)

    class FakeRib:
        """Answers FRR's `vtysh -c 'show ip route json'` per node. `rib` maps
        node -> prefixes; a non-zero rc returns empty output, as a failed read."""

        def __init__(self, rib, rc=0, present_after=None):
            self.rib, self.rc, self.present_after, self.calls = rib, rc, present_after, []

        def exec(self, lab, node, argv, check=False, **_kw):
            self.calls.append(list(argv))
            assert list(argv) == ["vtysh", "-c", "show ip route json"], f"unexpected argv {argv!r}"
            if self.rc:
                return SimpleNamespace(returncode=self.rc, stdout="", stderr="% error")
            pfxs = [] if (self.present_after is not None and len(self.calls) <= self.present_after) \
                else sorted(self.rib.get(node, ()))
            body = _json.dumps({p: [{"prefix": p, "protocol": "bgp"}] for p in pfxs})
            return SimpleNamespace(returncode=0, stdout=body, stderr="")

    def ns_rp(texts, topo, rt, collect=None):
        ns = dict(E.__dict__)
        ns.update(topo=topo, rt=rt, lab="lab", record_test=lambda **_kw: None)
        for _text in texts:
            exec(compile(_text, "<route_prefix_seam_parity_proof:P-RP>", "exec"), ns)
        if collect is not None:
            ns["_nos_collect"] = collect
        return ns

    def run_inv(rit, topo, rt, t, src, collect=None):
        cap = {}
        ns = ns_rp((NEW_EIA, rit), topo, rt, collect)
        try:
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                out = ("verdict", ns["run_invariant_test"](test_name="t", src=src, t=t,
                                                          record_fn=lambda **kw: cap.update(kw)))
        except SystemExit as exc:
            out = ("exit", exc.code)
        return out, {k: val for k, val in cap.items() if k != "duration_ms"}

    def run_wfp(wfp, topo, rt, wf, collect=None):
        ns = ns_rp((NEW_EIA, wfp), topo, rt, collect)
        w = dict(wf, timeout=1, interval_s=0.05)
        try:
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                _wt, _ex, observed, _dur, meta, verdict = ns["wait_for_predicate"](w)
        except SystemExit as exc:
            return ("exit", exc.code), None
        except Exception as exc:  # the scenario runner records a raised wait as a failed step
            return ("raise", type(exc).__name__, str(exc)), None
        return ("verdict", verdict, observed), {k: meta[k] for k in ("type", "from", "succeeded", "last_rc", "evidence")
                                                if k in meta}

    def inv_t(kind, prefix, expect, node="r1"):
        return {"name": "t", "kind": "invariant", "type": kind, "node": node, "prefix": prefix, "expect": expect}

    def rp_wf(prefix, expect, vantage="r1"):
        return {"type": "route_present", "from": vantage, "prefix": prefix, "expect": expect}

    rp_tests, rp_waits = [], []
    for path in sorted(glob.glob(os.path.join(_ROOT, "topologies", "*.yaml"))
                       + glob.glob(os.path.join(_ROOT, "examples", "*.yaml"))):
        with open(path, encoding="utf-8") as fh:
            try:
                doc = yaml.safe_load(fh)
            except yaml.YAMLError:
                continue
        if not isinstance(doc, dict):
            continue
        rel = os.path.relpath(path, _ROOT)
        for t in doc.get("tests") or []:
            if isinstance(t, dict) and t.get("kind") == "invariant" and t.get("type") in ("route_present", "route_absent"):
                rp_tests.append((rel, doc, t))
        for s in doc.get("scenarios") or []:
            for st in (s.get("steps") or []) if isinstance(s, dict) else []:
                wf = st.get("wait_for") if isinstance(st, dict) else None
                if isinstance(wf, dict) and wf.get("type") == "route_present":
                    rp_waits.append((rel, doc, wf))
    check("P-RP enumeration found route_present / route_absent tests and route_present waits in the committed fixtures",
          len(rp_tests) > 0 and len(rp_waits) > 0)
    print(f"P-RP enumerated {len(rp_tests)} route_present/route_absent test(s), {len(rp_waits)} route_present wait(s)")

    def rp_parity_deltas(rit_new, wfp_new):
        deltas = []
        cases_t = [(rel, topo_of(doc), dict(t), str(t.get("node") or "")) for rel, doc, t in rp_tests]
        cases_t += [("synthetic", R1, inv_t(k, "192.0.2.0/24", e), "r1")
                    for k in ("route_present", "route_absent") for e in ("pass", "fail")]
        for rel, topo, t, node in cases_t:
            for present in (True, False):
                rib = {node: {str(t.get("prefix"))}} if present else {}
                a = run_inv(OLD_RIT, topo, FakeRib(rib), dict(t), node)
                b = run_inv(rit_new, topo, FakeRib(rib), dict(t), node)
                if a != b:
                    deltas.append(("test", rel, t.get("type"), t.get("expect"), present, a, b))
        cases_w = [(rel, topo_of(doc), dict(wf)) for rel, doc, wf in rp_waits]
        cases_w += [("synthetic", R1, rp_wf("192.0.2.0/24", "fail"))]
        for rel, topo, wf in cases_w:
            v, pfx = str(wf.get("from") or ""), str(wf.get("prefix"))
            for label, rib, after in (("present", {v: {pfx}}, None), ("absent", {}, None),
                                      ("becomes-present", {v: {pfx}}, 1)):
                a = run_wfp(OLD_WFP_RP, topo, FakeRib(rib, present_after=after), wf)
                b = run_wfp(wfp_new, topo, FakeRib(rib, present_after=after), wf)
                if a != b:
                    deltas.append(("wait", rel, wf.get("expect"), label, a, b))
        return deltas

    _rp_deltas = rp_parity_deltas(NEW_RIT, NEW_WFP)
    for _d in _rp_deltas:
        print("DELTA:", _d)
    check("P-RP-PARITY FRR rc 0: zero verdict / record / evidence deltas, test path and scenario, every committed "
          "fixture plus the synthetic matrix, present, absent and becomes-present",
          not _rp_deltas)

    # Declared deltas, DC v2.1 §14 item 8.
    a = run_inv(OLD_RIT, R1, FakeRib({}, rc=1), inv_t("route_absent", "192.0.2.0/24", "pass"), "r1")
    b = run_inv(NEW_RIT, R1, FakeRib({}, rc=1), inv_t("route_absent", "192.0.2.0/24", "pass"), "r1")
    check("P-RP-DECL Q20-3 FRR non-zero rc (test path, route_absent, expect pass): the retired consumer passed on "
          "the failed read; now an explicit collection failure, verdict fail",
          a[0] == ("verdict", "pass") and b[0] == ("verdict", "fail")
          and b[1].get("observed") == "fail" and b[1].get("verdict") == "fail"
          and b[1].get("error") == "route_absent collection failed on 'r1': probe not ok"
          and b[1].get("evidence") == {"cmd": "vtysh -c 'show ip route json'", "rc": 1})
    a = run_inv(OLD_RIT, R1, FakeRib({}, rc=1), inv_t("route_present", "192.0.2.0/24", "fail"), "r1")
    b = run_inv(NEW_RIT, R1, FakeRib({}, rc=1), inv_t("route_present", "192.0.2.0/24", "fail"), "r1")
    check("P-RP-DECL Q20-3 FRR non-zero rc (test path, route_present, expect fail): the retired consumer passed; "
          "now verdict fail",
          a[0] == ("verdict", "pass") and b[0] == ("verdict", "fail") and b[1].get("verdict") == "fail")
    a = run_wfp(OLD_WFP_RP, R1, FakeRib({}, rc=1), rp_wf("192.0.2.0/24", "fail"))
    b = run_wfp(NEW_WFP, R1, FakeRib({}, rc=1), rp_wf("192.0.2.0/24", "fail"))
    check("P-RP-DECL F-S21-1 FRR non-zero rc (scenario, expect fail): the retired wait passed on the failed read; "
          "now it raises and the step fails",
          a[0] == ("verdict", "pass", "fail")
          and b[0] == ("raise", "RuntimeError", "wait_for route_present: collection failed on 'r1': probe not ok"))
    a = run_wfp(OLD_WFP_RP, F1, FakeRib({}), rp_wf("192.0.2.0/24", "fail", "fw"))
    b = run_wfp(NEW_WFP, F1, FakeRib({}), rp_wf("192.0.2.0/24", "fail", "fw"))
    check("P-RP-DECL F-S21-1 provider without the kind (scenario, nft-fw, expect fail): the retired wait passed on "
          "the refusal; now it raises with the UNSUP reason",
          a[0] == ("verdict", "pass", "fail") and b[0][:2] == ("raise", "RuntimeError")
          and "collection failed on 'fw'" in b[0][2] and "nft-fw" in b[0][2] and "route_present" in b[0][2])

    _same = True
    for _k in ("route_present", "route_absent"):
        for _e in ("pass", "fail"):
            a = run_inv(OLD_RIT, F1, FakeRib({}), inv_t(_k, "192.0.2.0/24", _e, "fw"), "fw")
            b = run_inv(NEW_RIT, F1, FakeRib({}), inv_t(_k, "192.0.2.0/24", _e, "fw"), "fw")
            _same = _same and a == b and a[0] == ("exit", 2) and a[1].get("verdict") == "fail"
    check("P-RP-UNSUP test path unchanged: a provider without the kind keeps its recorded misuse and exit 2, "
          "identical before and after, both kinds and both expects", _same)

    def stub_collect_rp(rt, lab, node, ntype, request, seam):
        p = request.params["prefix"]
        return Observation(kind=request.kind, data={"norm_prefix": p, "present": False, "observed_prefixes": []},
                           evidence={"cmd": "stub", "rc": 1, "parse_error": "read not vouched for", "probe_ok": False})

    def never_pass_rit(rit):
        ok = True
        for k in ("route_present", "route_absent"):
            for e in ("pass", "fail"):
                out, rec = run_inv(rit, R1, FakeRib({}), inv_t(k, "192.0.2.0/24", e), "r1", collect=stub_collect_rp)
                ok = (ok and out == ("verdict", "fail") and rec.get("verdict") == "fail"
                      and rec.get("observed") == "fail"
                      and rec.get("evidence", {}).get("parse_error") == "read not vouched for"
                      and rec.get("error") == f"{k} collection failed on 'r1': read not vouched for")
        return ok

    def never_pass_wfp(wfp):
        res = [run_wfp(wfp, R1, FakeRib({}), rp_wf("192.0.2.0/24", e), collect=stub_collect_rp)
               for e in ("pass", "fail")]
        return all(r[0] == ("raise", "RuntimeError",
                            "wait_for route_present: collection failed on 'r1': read not vouched for") for r in res)

    check("P-RP-NEVER test path: probe_ok False is verdict fail for route_present AND route_absent, expect pass AND "
          "fail -- the returned verdict, the record's verdict and its observed -- reason recorded (Q20-3)",
          never_pass_rit(NEW_RIT))
    check("P-RP-NEVER scenario: probe_ok False raises for expect pass AND expect fail (F-S21-1)",
          never_pass_wfp(NEW_WFP))

    # -------------------------------------------------------------------- P-NV
    def mutate(text, old, new):
        assert text.count(old) == 1, f"mutation anchor count {text.count(old)}"
        return text.replace(old, new)

    def report(name, detected):
        print(("MUTATION-FAIL: %s" % name) if detected else ("CONTROL BROKEN: %s not detected" % name))
        check(f"P-NV {name}: detected", detected)

    _PRES = 'present = bool(_obs.data.get("routes"))'
    m1 = mutate(NEW_RPT, _PRES, 'present = not bool(_obs.data.get("routes"))')
    report("test-path presence rule inverted -> parity delta", bool(parity_deltas(m1, OLD_WFP, NEW_WFP)))

    _orig = FRR._COLLECT_HANDLERS["route_prefix"]

    def _blind(rt, lab, node, req):
        o = _orig(rt, lab, node, req)
        return Observation(kind=o.kind, data=dict(o.data, routes=[]), evidence=o.evidence)
    FRR._COLLECT_HANDLERS["route_prefix"] = _blind
    try:
        report("FRR handler blind to routes -> parity delta", bool(parity_deltas(NEW_RPT, OLD_WFP, NEW_WFP)))
    finally:
        FRR._COLLECT_HANDLERS["route_prefix"] = _orig

    m3 = mutate(NEW_RPT, 'if not _ev.get("probe_ok"):', "if False:")
    report("test-path probe gate removed -> never-a-pass fails", not never_pass_test(m3))

    m4 = _pre + mutate(NEW_BRANCH, _PRES, 'present = (_prefix in " ".join(_obs.data.get("routes") or []))') + _post
    b = run_wait(m4, R1, FakeRt(fib32), wf_for(HOST32, "pass"))
    report("scenario substring rule reinstated -> /32 declared class fails", b[0] != ("verdict", "pass", "pass"))

    m5 = _pre + mutate(NEW_BRANCH, 'if not _ev.get("probe_ok"):', "if False:") + _post
    report("scenario probe raise removed -> never-a-pass fails", not never_pass_wait(m5))

    m6 = mutate(NEW_RIT, "if not _vtysh_ok:", "if False:")
    report("Q20-3 guard removed -> test-path never-a-pass fails", not never_pass_rit(m6))

    m7 = mutate(NEW_RIT, 'verdict="fail",\n                duration_ms=int((time.time() - start) * 1000),\n                error=f"{inv_type} collection failed', 'verdict="pass",\n                duration_ms=int((time.time() - start) * 1000),\n                error=f"{inv_type} collection failed')
    report("Q20-3 failure record written with verdict pass -> test-path never-a-pass fails on the record's verdict",
           not never_pass_rit(m7))

    m8 = mutate(NEW_WFP, "if not vtysh_ok:", "if False:")
    report("F-S21-1 guard removed -> scenario never-a-pass fails", not never_pass_wfp(m8))

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
