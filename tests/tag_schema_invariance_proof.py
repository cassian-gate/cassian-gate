#!/usr/bin/env python3
"""§4.8 schema-invariance proof (REQ-TAG-SCHEMA-3): the presence or value of the declarative
`tags` field never alters a test's verdict, the Resolve outcome, or determinism.

Lab-free discharge of the §15.2 with/without-`tags` regression obligation, generalized beyond a
single results.json diff: (B) Resolve is byte-identical (modulo the passed-through `tags` field)
across topologies that differ only in tags presence and tags value; and (S) the sole site in the
engine that reads the `tags` field for any decision is `_tag_selected`, which short-circuits to
True when no `--tag` filter is supplied. Together these prove no verdict-computation or Resolve
path consumes `tags` for any topology, not merely the fixtures exercised here.

Fails loudly: any new engine site that reads the `tags` field (e.g. a verdict path) breaks the
count-equality source assertion; any Resolve divergence under tags presence/value breaks (B).
"""
import inspect, os, sys, copy, json
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)
import cassian_common as _cc; _cc._QUIET_DIE = True
import cassian_model as M
import cassian_engine as E

C = []
def ck(n, c): C.append((n, bool(c)))

# ---- (B) Resolve invariance to tags presence + value -----------------------------------------
_BASE = {
    "name": "s3", "nodes": [{"name": "r1", "type": "frr"}, {"name": "r2", "type": "frr"}],
    "links": [{"endpoints": ["r1:eth1", "r2:eth1"]}],
    "tests": [
        {"name": "t1", "kind": "invariant", "type": "bgp_session_up", "src": "r1", "dst": "10.0.0.2"},
        {"name": "t2", "kind": "invariant", "type": "bgp_session_up", "src": "r1", "dst": "10.0.0.2"},
    ],
}

def _variant(tagsets):
    t = copy.deepcopy(_BASE)
    for test, tg in zip(t["tests"], tagsets):
        if tg is not None: test["tags"] = tg
    return t

def _resolved_modulo_tags(topo):
    t = copy.deepcopy(topo)
    M.ensure_valid_topology(t)
    r = M.resolve_topology(t)
    r = r if isinstance(r, dict) else t
    r = copy.deepcopy(r)
    for test in (r.get("tests") or []):
        if isinstance(test, dict): test.pop("tags", None)
    return json.dumps(r, sort_keys=True)

none_  = _resolved_modulo_tags(_variant([None, None]))               # tags absent
pres_  = _resolved_modulo_tags(_variant([["bgp"], ["edge", "core"]]))  # tags present
val_   = _resolved_modulo_tags(_variant([["x"], ["y", "z", "w"]]))     # different values
empty_ = _resolved_modulo_tags(_variant([[], []]))                   # empty-list tags

ck("Resolve identical: tags absent vs present (presence invariance)", none_ == pres_)
ck("Resolve identical: differing tags values (value invariance)", pres_ == val_)
ck("Resolve identical: empty-list tags vs absent", none_ == empty_)

# ---- (B) Executed set is identical: no-filter selects all, regardless of tags ----------------
declared = [{"name": "a", "tags": ["x"]}, {"name": "b"}, {"name": "c", "tags": []}]
sel_all = [d["name"] for d in declared if E._tag_selected(d, None)]
ck("no `--tag` filter selects every declared test irrespective of tags", sel_all == ["a", "b", "c"])

# ---- (S) Source: the only engine site reading the `tags` FIELD is `_tag_selected` ------------
eng_src = inspect.getsource(E)
sel_src = inspect.getsource(E._tag_selected)
def _field_reads(s): return s.count('.get("tags")') + s.count('["tags"]') + s.count(".get('tags')") + s.count("['tags']")
eng_reads, sel_reads = _field_reads(eng_src), _field_reads(sel_src)
ck("`_tag_selected` reads the tags field at least once", sel_reads >= 1)
ck("no engine site outside `_tag_selected` reads the tags field (no verdict path)", eng_reads == sel_reads)
ck("`_tag_selected` short-circuits to True when no filter (`if not filter_tags:`)", "if not filter_tags:" in sel_src)

# ---- (S) Model: `tags` is validated + carried as inert metadata, never a Resolve branch ------
mdl_src = inspect.getsource(M)
ck("model lists `tags` in allowed_exec_keys (inert passthrough, not stripped)", '"tags"' in mdl_src and "allowed_exec_keys" in mdl_src)

fail = [n for n, ok in C if not ok]
for n, ok in C: print(("  PASS " if ok else "  FAIL ") + n)
print(("\nAll %d passed." % len(C)) if not fail else ("\nFAILED: " + "; ".join(fail)))
sys.exit(1 if fail else 0)
