from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

def _ai_resolve_lab_and_dir(arg: str) -> tuple[str, str]:
    """
    If 'arg' looks like a topology file (*.yaml|*.yml), load it and use its 'name' as the lab.
    Otherwise treat it as a lab name directly.
    Returns (lab, lab_dir).
    """
    from pathlib import Path
    import yaml

    p = Path(arg)
    if p.suffix in (".yaml", ".yml") and p.exists():
        with p.open("r", encoding="utf-8") as f:
            topo = yaml.safe_load(f) or {}
        lab = str((topo.get("name") or "").strip())
        if not lab:
            print("ERROR: topology must define 'name' to resolve lab.", file=sys.stderr)
            sys.exit(2)
    else:
        lab = arg.strip()
        if not lab:
            print("ERROR: lab name is empty.", file=sys.stderr)            
            sys.exit(2)

    return lab, os.path.join("labs", f"clab-{lab}")


def _ai_read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _ai_file_exists(path: str) -> bool:
    try:
        st = os.stat(path)
        return st.st_size >= 0
    except Exception:
        return False


def _ai_advisory_headers() -> dict[str, Any]:
    return {
        "authority": "advisory",
        "non_authoritative": True,
        "disclaimer": "Assistive AI is advisory-only. Tests & scenarios are authoritative.",
    }


def _ai_print_json(payload: dict[str, Any], ensure_ascii: bool = False) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=ensure_ascii))


def _ai_env(name: str) -> str:
    return (os.getenv(name) or "").strip()


def _ai_default_bundle_out_path(bundle: dict[str, Any]) -> str | None:
    """
    Default bundle location:
      - explain: labs/<labdir>/ai/ai_bundle.json (uses bundle["lab"]["labdir"])
      - review: no default (no labdir) -> only writes if --bundle-out is provided
      - coach: no default (no labdir) -> only writes if --bundle-out is provided
    """
    lab = bundle.get("lab")
    if isinstance(lab, dict):
        labdir = lab.get("labdir")
        if isinstance(labdir, str) and labdir.strip():
            return os.path.join(labdir.strip(), "ai", "ai_bundle.json")
    return None


def _ai_write_bundle(path: str, bundle: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, sort_keys=True, ensure_ascii=False)


def _ai_online_config(args) -> dict[str, Any]:
    """
    BYO key contract:
      - provider: AI_NETSIM_AI_PROVIDER (currently only 'openai' supported)
      - api_key: AI_NETSIM_AI_API_KEY or OPENAI_API_KEY
      - model:   --model or AI_NETSIM_AI_MODEL (fallback safe default inside _ai_try_online)
      - base_url: optional AI_NETSIM_AI_BASE_URL (for proxies/self-hosting)
    """
    provider = _ai_env("AI_NETSIM_AI_PROVIDER").lower()
    api_key = _ai_env("AI_NETSIM_AI_API_KEY") or _ai_env("OPENAI_API_KEY")
    model = (getattr(args, "model", None) or _ai_env("AI_NETSIM_AI_MODEL") or "").strip()
    base_url = _ai_env("AI_NETSIM_AI_BASE_URL") or ""
    if base_url == "":
        base_url = None
    return {
        "provider": provider,
        "api_key": api_key,
        "model": model,
        "base_url": base_url,
    }

def _ai_sanitize_error(msg: str) -> str:
    """
    Sanitize provider error messages so they are safe to emit:
      - remove API keys
      - trim excessive length
    """
    if not msg:
        return ""

    # Never leak anything that looks like an API key
    msg = re.sub(r"sk-[A-Za-z0-9]{10,}", "sk-REDACTED", msg)

    # Bound size (CI / logs safety)
    MAX = 500
    if len(msg) > MAX:
        msg = msg[:MAX] + "...(truncated)"

    return msg

def _ai_validate_output_schema(out: Any) -> tuple[bool, str]:
    """
    Validate the v1 AI output schema.

    Required:
      - summary: string

    Optional (but if present must match shape):
      - findings: list of {title,evidence,suggestion} strings
      - suggested_next_tests: list of {id,title,why,yaml} strings

    Returns: (ok, error_string)
    """
    if not isinstance(out, dict):
        return (False, "AI output must be a JSON object")

    summary = out.get("summary")
    if not isinstance(summary, str):
        return (False, "ERROR: AI output 'summary' must be a string")

    findings = out.get("findings", [])
    if findings is None:
        findings = []
    if not isinstance(findings, list):
        return (False, "ERROR: AI output 'findings' must be a list")

    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            return (False, f"ERROR: AI output findings[{i}] must be an object")
        for k in ("title", "evidence", "suggestion"):
            if k not in f or not isinstance(f.get(k), str):
                return (False, f"ERROR: AI output findings[{i}].{k} must be a string")

    nxt = out.get("suggested_next_tests")
    if nxt is not None:
        if not isinstance(nxt, list):
            return (False, "ERROR: AI output 'suggested_next_tests' must be a list")
        for i, item in enumerate(nxt):
            if not isinstance(item, dict):
                return (False, f"ERROR: AI output suggested_next_tests[{i}] must be an object")
            for k in ("id", "title", "why", "yaml"):
                if k not in item or not isinstance(item.get(k), str):
                    return (False, f"ERROR: AI output suggested_next_tests[{i}].{k} must be a string")

    return (True, "")

def _ai_parse_and_validate_model_json(text: str) -> tuple[dict[str, Any], str]:
    """
    JSON-only contract:
      - Must be valid JSON
      - Must be a dict matching the required schema
    Returns: (parsed_dict_or_empty, error_string_or_empty)
    """
    text = (text or "").strip()
    if not text:
        return ({}, "empty model response")

    try:
        out = json.loads(text)
    except Exception as e:
        return ({}, f"non-JSON model response: {e!s}")

    ok, err = _ai_validate_output_schema(out)
    if not ok:
        return ({}, err)

    # Safe: schema-validated dict. Keep as-is (do not rewrite content).
    return (out, "")

def _ai_sanitize_output_for_fixture(ai_output: Any) -> dict[str, Any]:
    """
    Convert schema-valid ai_output into a stable, content-free structure for fixtures.

    This is a structural contract sanitizer:
      - does NOT validate correctness of content
      - does NOT pin wording
      - only preserves schema shape + required keys
    """
    # If it's not schema-valid, return empty dict (caller should already validate schema).
    if not isinstance(ai_output, dict):
        return {}

    # Enforce only the allowed schema keys in the sanitized fixture
    allowed_top = {"summary", "findings", "suggested_next_tests"}
    out: dict[str, Any] = {}

    # summary
    if "summary" in ai_output and isinstance(ai_output.get("summary"), str):
        out["summary"] = "<string>"
    else:
        out["summary"] = "<missing>"

    # findings
    findings = ai_output.get("findings")
    san_findings: list[dict[str, str]] = []
    if isinstance(findings, list):
        for f in findings:
            if isinstance(f, dict):
                san_findings.append({
                    "title": "<string>" if isinstance(f.get("title"), str) else "<missing>",
                    "evidence": "<string>" if isinstance(f.get("evidence"), str) else "<missing>",
                    "suggestion": "<string>" if isinstance(f.get("suggestion"), str) else "<missing>",
                })
            else:
                san_findings.append({
                    "title": "<invalid>",
                    "evidence": "<invalid>",
                    "suggestion": "<invalid>",
                })
    out["findings"] = san_findings

    # suggested_next_tests
    nxt = ai_output.get("suggested_next_tests")
    san_nxt: list[dict[str, str]] = []
    if isinstance(nxt, list):
        for item in nxt:
            if isinstance(item, dict):
                san_nxt.append(
                    {
                        "id": "<string>" if isinstance(item.get("id"), str) else "<missing>",
                        "title": "<string>" if isinstance(item.get("title"), str) else "<missing>",
                        "why": "<string>" if isinstance(item.get("why"), str) else "<missing>",
                        "yaml": "<string>" if isinstance(item.get("yaml"), str) else "<missing>",
                    }
                )
            else:
                san_nxt.append({"id": "<invalid>", "title": "<invalid>", "why": "<invalid>", "yaml": "<invalid>"})
    out["suggested_next_tests"] = san_nxt

    # If additional keys exist, record them explicitly (so fixtures can guard expansion).
    extras = sorted([k for k in ai_output.keys() if k not in allowed_top])
    out["_extra_keys"] = extras  # must be [] in fixtures

    return out

def _ai_provider_openai(
    bundle: dict[str, Any],
    model: str,
    api_key: str,
    base_url: str | None
) -> tuple[str, dict[str, Any], str]:
    """
    Returns (ai_status, ai_output, ai_error)

    ai_output:
      - parsed JSON dict if the model returns JSON
      - else {"raw_text": "..."} if non-JSON
    """
    try:
        from openai import OpenAI  # type: ignore
    except Exception as e:
        return (
            "unavailable",
            {},
            _ai_sanitize_error(f"openai sdk not importable: {e!s}")
        )

    try:
        client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)

        # Deterministic prompt object: bundle-only input.
        prompt_obj = {
            "task": "Cassian Gate advisory analysis",
            "rules": {
                "authority": "advisory",
                "non_authoritative": True,
                "do_not_change_verdicts_or_exit_codes": True,
                "artifact_only": True,
                "no_runtime_calls": True,
            },
            "bundle": bundle,
            "output_contract": {
                "json_only": True,
                "no_markdown": True,
                "no_prose_outside_json": True,
                "rules": [
                    "Return JSON only. No YAML, no markdown, no prose outside the JSON object.",
                    "Never claim correctness or safety. Do NOT use words like: validated, correct, safe, approved, guaranteed.",
                    "Anchor claims to observed evidence (tests/scenarios/results pointers) where possible. Config text is context only.",
                    "Candidate changes are context-only and are never executed/simulated/validated by Cassian Gate.",
                    "Suggested tests MUST be actionable: include a copy-paste YAML snippet that fits Cassian Gate v1 schema.",
                ],
                "schema": {
                    "summary": "string",
                    "findings": [{"title": "string", "evidence": "string", "suggestion": "string"}],
                    "suggested_next_tests": [
                        {"id": "string", "title": "string", "why": "string", "yaml": "string"},
                    ],
                },
            },
        }

        resp = client.responses.create(
            model=model,
            input=[
                {
                    "role": "user",
                    "content": json.dumps(prompt_obj, sort_keys=True),
                }
            ],
        )

        # Defensive extraction (Responses API)
        text = ""
        try:
            # Preferred: SDK convenience field
            text = getattr(resp, "output_text", "") or ""
        except Exception:
            text = ""

        # Fallback: scan structured output for message content
        if not text:
            try:
                for item in getattr(resp, "output", []) or []:
                    if getattr(item, "type", "") == "message":
                        for part in getattr(item, "content", []) or []:
                            if getattr(part, "type", "") == "output_text":
                                text += getattr(part, "text", "") or ""
                            elif getattr(part, "type", "") == "text":
                                # Some SDKs use "text" parts
                                text += getattr(part, "text", "") or ""
            except Exception:
                text = ""

        if not text:
            # Last resort: string form (usually not useful, but keep deterministic behavior)
            try:
                text = str(resp)
            except Exception:
                text = ""

        text = (text or "").strip()
        if not text:
            return ("unavailable", {}, "empty model response")

        out, perr = _ai_parse_and_validate_model_json(text)
        if perr:
            return ("unavailable", {}, _ai_sanitize_error(perr))
        return ("ok", out, "")

    except Exception as e:
        return (
            "unavailable",
            {},
            _ai_sanitize_error(str(e))
        )

def _ai_try_online(bundle: dict[str, Any], args) -> dict[str, Any]:
    """
    Never raises. Never gates.
    Returns:
      {ai_status, ai_error, model_used, ai_output}
    """
    if not bool(getattr(args, "online", False)):
        return {"ai_status": "unavailable", "ai_error": "online not requested", "model_used": None, "ai_output": {}}

    cfg = _ai_online_config(args)

    if not cfg["provider"]:
        return {"ai_status": "unavailable", "ai_error": "AI_NETSIM_AI_PROVIDER not set", "model_used": None, "ai_output": {}}

    if cfg["provider"] != "openai":
        return {"ai_status": "unavailable", "ai_error": f"unsupported provider '{cfg['provider']}'", "model_used": None, "ai_output": {}}

    if not cfg["api_key"]:
        return {
            "ai_status": "unavailable",
            "ai_error": "AI_NETSIM_AI_API_KEY/OPENAI_API_KEY not set",
            "model_used": None,
            "ai_output": {},
        }

    # Safe default (can change later). Keep deterministic behavior regardless.
    model = cfg["model"] or "gpt-4.1-mini"

    st, out, err = _ai_provider_openai(bundle=bundle, model=model, api_key=cfg["api_key"], base_url=cfg["base_url"])
    return {"ai_status": st, "ai_error": err, "model_used": model, "ai_output": out}


def _ai_finalize_and_emit(command_name: str, bundle: dict[str, Any], args) -> None:
    """
    Single enforcement point for v1 AI CLI contract.

    Rules:
      - Bundle is deterministic and always exists.
      - --bundle: print bundle JSON (no online), exit 0
      - --bundle-out: write bundle to path (no online), exit 0
      - default: write bundle to default path if available (explain only)
      - --online: attempt provider call; failures never gate; exit 0
      - output controlled by --format json|text (default json per argparse)
    """

    def _cc_summary_text(bundle_in: dict[str, Any]) -> str | None:
        # Support legacy keys + current key.
        cc = bundle_in.get("change_context") or bundle_in.get("change_review") or bundle_in.get("change_explain")
        if not isinstance(cc, dict):
            return None

        present = bool(cc.get("present", False))
        if not present:
            return None

        counts = cc.get("counts") if isinstance(cc.get("counts"), dict) else {}
        items = int(counts.get("items", 0) or 0)
        included = int(counts.get("included", 0) or 0)
        missing = int(counts.get("missing", 0) or 0)
        blocked = int(counts.get("blocked", 0) or 0)
        too_large = int(counts.get("too_large", 0) or 0)

        # One-line banner: explicit non-execution + non-authority (v1 contract).
        return (
            f"change_context: present (items={items} included={included} missing={missing} "
            f"blocked={blocked} too_large={too_large}) — context-only, NOT executed, does not affect verdicts"
        )


    def _ai_contains_forbidden_correctness_language(obj: Any) -> bool:
        # Non-blocking lint: warn in text mode (never gate).
        # Expand list to cover common implied authority / safety claims.
        forbidden = (
            "validated",
            "correct",
            "safe",
            "approved",
            "guaranteed",
            "compliant",
            "secure",
            "certified",
            "verified",
        )
        try:
            s = json.dumps(obj, ensure_ascii=True).lower()
            return any(w in s for w in forbidden)
        except Exception:
            return False


    def _render_ai_output_text(ai_out: Any) -> None:
        """
        Human-friendly rendering for engineers.

        Expected ai_out schema:
          {
            "summary": str,
            "findings": [{title,evidence,suggestion}],
            "suggested_next_tests": [{id,title,why,yaml}]
          }
        Backward compatible: if suggested_next_tests is list[str], print as generic.
        """
        if not ai_out:
            return

        if not isinstance(ai_out, dict):
            print(str(ai_out))
            return

        summary = ai_out.get("summary")
        if isinstance(summary, str) and summary.strip():
            print("summary:")
            print(f"  {summary.strip()}")
            print("  (Informational only. Only tests & scenarios prove behavior.)")
            print()

        findings = ai_out.get("findings")
        if isinstance(findings, list) and findings:
            print("findings:")
            n = 0
            for f in findings:
                if not isinstance(f, dict):
                    continue
                title = str(f.get("title") or "").strip()
                suggestion = str(f.get("suggestion") or "").strip()
                evidence = str(f.get("evidence") or "").strip()
                if not (title or suggestion or evidence):
                    continue
                n += 1
                head = title if title else f"finding {n}"
                print(f"  {n}. {head}")
                if suggestion:
                    print(f"     suggestion: {suggestion}")
                if evidence:
                    print(f"     evidence: {evidence}")
            print()

        nxt = ai_out.get("suggested_next_tests")
        if isinstance(nxt, list) and nxt:
            print("suggested_next_tests (copy/paste):")
            for item in nxt:
                if isinstance(item, str):
                    # Backward-compat: older models may still return strings.
                    print(f"  - {item} (generic; no YAML provided)")
                    continue
                if not isinstance(item, dict):
                    continue

                tid = str(item.get("id") or "").strip()
                title = str(item.get("title") or "").strip()
                why = str(item.get("why") or "").strip()
                yaml_snip = str(item.get("yaml") or "").rstrip()

                head = ""
                if tid and title:
                    head = f"{tid}: {title}"
                elif title:
                    head = title
                elif tid:
                    head = tid
                else:
                    head = "test"

                print(f"  - {head}")
                if why:
                    print(f"    why: {why}")
                if yaml_snip:
                    print("    add to topology:")
                    for line in yaml_snip.splitlines():
                        print(f"      {line}")
            print()

    # Ensure mandatory deterministic headers exist (do NOT overwrite if already set)
    bundle.setdefault("schema_version", "1")
    for k, v in _ai_advisory_headers().items():
        bundle.setdefault(k, v)

    # Determine requested output mode flags
    want_bundle = bool(getattr(args, "bundle", False))
    bundle_out = getattr(args, "bundle_out", None)

    fmt = (getattr(args, "format", None) or "json").strip().lower()
    if fmt not in ("json", "text"):
        fmt = "json"

    # 1) --bundle-out: write bundle and exit (no online)
    if bundle_out:
        _ai_write_bundle(str(bundle_out), bundle)
        bundle_with_ptr = dict(bundle)
        bundle_with_ptr["bundle_path"] = str(bundle_out)

        if fmt == "json":
            _ai_print_json(bundle_with_ptr)
        else:
            print(f"[advisory] ai {command_name}")
            print(bundle_with_ptr.get("disclaimer"))
            cc_line = _cc_summary_text(bundle)
            if cc_line:
                print(cc_line)
            print(f"bundle_path: {bundle_with_ptr['bundle_path']}")
        return

    # 2) --bundle: print bundle and exit (no online)
    if want_bundle:
        if fmt == "json":
            _ai_print_json(bundle)
        else:
            print(f"[advisory] ai {command_name}")
            print(bundle.get("disclaimer"))
            cc_line = _cc_summary_text(bundle)
            if cc_line:
                print(cc_line)
            print(json.dumps(bundle, indent=2, sort_keys=True))
        return

    # 3) Default bundle write (best practice): only if we can infer a default path (explain has labdir)
    default_path = _ai_default_bundle_out_path(bundle)
    if default_path:
        try:
            _ai_write_bundle(default_path, bundle)
        except Exception:
            default_path = None

    # 4) Optional online call
    online_res = {
        "ai_status": "unavailable",
        "ai_error": "online not requested",
        "model_used": None,
        "ai_output": {},
    }
    if bool(getattr(args, "online", False)):
        try:
            online_res = _ai_try_online(bundle=bundle, args=args)
        except Exception as e:
            online_res = {"ai_status": "unavailable", "ai_error": str(e), "model_used": None, "ai_output": {}}

    # 5) Final advisory output (stable, CI-safe)
    out: dict[str, Any] = {
        "schema_version": "1",
        **_ai_advisory_headers(),
        "command": command_name,
        "inputs": {"bundle_path": default_path},
        "ai_status": online_res.get("ai_status"),
        "ai_error": online_res.get("ai_error") or "",
        "model_used": online_res.get("model_used"),
        "ai_output": online_res.get("ai_output") or {},
        # always include the deterministic bundle for audit/debug
        "bundle": bundle,
    }

    if fmt == "json":
        _ai_print_json(out)
        return

    # text mode (human-friendly)
    print(f"[advisory] ai {command_name}")
    print(out.get("disclaimer"))

    cc_line = _cc_summary_text(bundle)
    if cc_line:
        print(cc_line)

    if out["inputs"].get("bundle_path"):
        print(f"bundle_path: {out['inputs']['bundle_path']}")

    print(f"ai_status: {out.get('ai_status')}")

    if out.get("ai_error"):
        print(f"ERROR: {out.get('ai_error')}")

    if out.get("model_used"):
        print(f"model_used: {out.get('model_used')}")

    if out.get("ai_output"):
        if _ai_contains_forbidden_correctness_language(out["ai_output"]):
            print("WARN: AI output contained correctness/safety language. Treat as advisory and prove via tests.")
        _render_ai_output_text(out["ai_output"])

def _ai_explain_change_sections(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Step 4 (v1): Change-aware explain scaffold.

    Rules:
      - deterministic
      - vendor-agnostic (no parsing)
      - advisory-only
      - no remediation instructions
      - links failures to "affected areas" based on declared candidate_changes metadata only
    """
    cc = bundle.get("change_context") or {}
    items = list(cc.get("items") or [])

    # deterministic ordering
    def _k_item(it: dict) -> tuple:
        return (str(it.get("id") or ""), str(it.get("node") or ""), str(it.get("description") or ""))

    items = sorted([it for it in items if isinstance(it, dict)], key=_k_item)

    # Build a light-weight index: node -> change ids
    node_to_changes: dict[str, list[str]] = {}
    change_ids: list[str] = []
    for it in items:
        cid = str(it.get("id") or "").strip()
        if cid:
            change_ids.append(cid)
        node = it.get("node")
        if isinstance(node, str) and node.strip() and cid:
            node_to_changes.setdefault(node.strip(), []).append(cid)

    for k in list(node_to_changes.keys()):
        node_to_changes[k] = sorted(set(node_to_changes[k]))

    change_ids = sorted(set(change_ids))

    verdict = bundle.get("verdict") or {}
    failed_tests = list(verdict.get("failed_tests") or [])
    failed_steps = list(verdict.get("failed_scenarios") or [])
    wait_failures = list(verdict.get("wait_failures") or [])

    # Helper: try to extract node-ish strings from a failure record without guessing too hard
    def _extract_nodes_from_failure(rec: dict) -> set[str]:
        out: set[str] = set()
        if not isinstance(rec, dict):
            return out

        # Common spots
        for key in ("name", "reason", "error"):
            v = rec.get(key)
            if isinstance(v, str):
                # light heuristic: if a node name appears exactly as a token in the string, match it
                # (still deterministic, but best-effort)
                for n in node_to_changes.keys():
                    if n and (f" {n} " in f" {v} " or v.strip() == n):
                        out.add(n)

        meta = rec.get("meta")
        if isinstance(meta, dict):
            for key in ("node", "src", "dst", "from", "to"):
                v = meta.get(key)
                if isinstance(v, str) and v.strip() in node_to_changes:
                    out.add(v.strip())

        return out

    affected_nodes: set[str] = set()
    for rec in failed_tests:
        affected_nodes |= _extract_nodes_from_failure(rec)
    for rec in failed_steps:
        affected_nodes |= _extract_nodes_from_failure(rec)
    for rec in wait_failures:
        affected_nodes |= _extract_nodes_from_failure(rec)

    affected_nodes = set(sorted(affected_nodes))

    affected_changes: list[str] = []
    for n in affected_nodes:
        affected_changes.extend(node_to_changes.get(n) or [])
    affected_changes = sorted(set(affected_changes))

    # Calm, on-call friendly notes (no remediation)
    notes: list[str] = []
    present = bool(cc.get("present"))
    if not present:
        notes.append("No candidate change context was provided, so this explanation is based on test/scenario evidence only.")
    else:
        if cc.get("counts", {}).get("missing"):
            notes.append("Some change_context files were missing at bundle time; affected-area mapping may be incomplete.")
        if cc.get("counts", {}).get("blocked"):
            notes.append("Some change_context items were blocked for safety (path rules); mapping may be incomplete.")
        if cc.get("counts", {}).get("too_large"):
            notes.append("Some change_context items were too large and were not included; mapping may be incomplete.")

    mapping = {
        "affected_nodes": sorted(list(affected_nodes)),
        "affected_change_ids": affected_changes,
        "node_to_change_ids": {k: node_to_changes[k] for k in sorted(node_to_changes)},
    }

    # Minimal structured output required by Step 4
    out = {
        "present": bool(cc.get("present")),
        "summary": {
            "change_ids": change_ids,
            "affected_nodes": mapping["affected_nodes"],
            "affected_change_ids": mapping["affected_change_ids"],
        },
        "mapping": mapping,
        "notes": notes,
        "reminders": [
            "This is advisory context only. Tests & scenarios are authoritative.",
            "No vendor parsing was performed; mapping uses declared metadata only.",
            "No remediation instructions are provided.",
        ],
    }

    return out

def cmd_ai_explain(args) -> None:
    """
    Explain a prior run using artifacts only.

    v1 contract:
      - always builds a deterministic bundle
      - --bundle prints bundle JSON and exits 0
      - --bundle-out writes bundle and exits 0
      - --online attempts optional model layer; failures never gate (exit 0)

    Exit codes:
      0 = success (including AI unavailable)
      2 = CLI usage / missing required artifacts when --strict-inputs
    """
    lab, labdir = _ai_resolve_lab_and_dir(args.target)
    res_path = os.path.join(labdir, "results.json")
    topo_resolved_path = os.path.join(labdir, "topology.resolved.yaml")
    summary_path = os.path.join(labdir, "results.summary.txt")

    strict = bool(getattr(args, "strict_inputs", False))

    # Required artifacts for v1 explain
    missing: list[str] = []
    if not _ai_file_exists(res_path):
        missing.append("results.json")
    if not _ai_file_exists(topo_resolved_path):
        missing.append("topology.resolved.yaml")

    if missing and strict:
        print(
            f"ERROR: missing required artifacts in {labdir}: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(2)

    adapter_paths = list(getattr(args, "adapter", None) or [])
    adapters = _ai_load_adapters(adapter_paths, command_name="explain") if adapter_paths else {
        "authority": "advisory",
        "count": 0,
        "inputs": [],
    }

    bundle = {
        "schema_version": "1",
        **_ai_advisory_headers(),
        "command": "explain",
        "adapters": adapters,
        "lab": {"name": lab, "labdir": labdir},
        "artifacts": {
            "results_json": os.path.join(labdir, "results.json"),
            "resolved_topology": os.path.join(labdir, "topology.resolved.yaml"),
            "summary_txt": os.path.join(labdir, "results.summary.txt"),
            "present": {
                "results_json": _ai_file_exists(res_path),
                "resolved_topology": _ai_file_exists(topo_resolved_path),
                "summary_txt": _ai_file_exists(summary_path),
            },
        },
        "verdict": {
            "overall": None,
            "failed_tests": [],
            "failed_scenarios": [],
            "wait_failures": [],
        },
        "notes": [],
    }

    # Change Context (bundle-time only): pull from resolved topology if present
    # Use labdir as the deterministic base_dir so explain works from artifacts alone.
    cc_base_dir = Path(labdir)

    if _ai_file_exists(topo_resolved_path):
        try:
            topo_resolved = _ai_read_yaml(topo_resolved_path)
            bundle["change_context"] = _ai_cc_build_change_context(topo_resolved, base_dir=cc_base_dir)
        except Exception as e:
            bundle["change_context"] = {
                "present": False,
                "counts": {"items": 0, "included": 0, "blocked": 0, "missing": 0, "errors": 1, "too_large": 0},
                "limits": {
                    "item_max_bytes": _AI_CC_ITEM_MAX_BYTES,
                    "total_max_bytes": _AI_CC_TOTAL_MAX_BYTES,
                    "preview_max_chars": _AI_CC_PREVIEW_MAX_CHARS,
                    "max_items": _AI_CC_MAX_ITEMS,
                },
                "items": [],
                "notes": [f"Failed to parse topology.resolved.yaml for change_context: {e!s}"],
            }
    else:
        bundle["change_context"] = _ai_cc_build_change_context({}, base_dir=cc_base_dir)

    # Deterministic scaffold: extract stable evidence pointers
    if _ai_file_exists(res_path):
        try:
            r = _ai_read_json(res_path)
            bundle["verdict"]["overall"] = r.get("result")
            results_ptr = f"{labdir}/results.json"

            tests = list(r.get("tests") or [])
            for i, t in enumerate(tests):
                if not isinstance(t, dict):
                    continue
                if (t.get("verdict") or "").lower() == "fail":
                    bundle["verdict"]["failed_tests"].append(
                        {
                            "name": t.get("name"),
                            "type": t.get("type"),
                            "reason": t.get("reason"),
                            "evidence": {"artifact": results_ptr, "path": f"tests[{i}]"},
                        }
                    )

            scenarios = list(r.get("scenarios") or [])
            for si, s in enumerate(scenarios):
                if not isinstance(s, dict):
                    continue
                sid = s.get("id")
                steps = list(s.get("steps") or [])
                for st_i, st in enumerate(steps):
                    if not isinstance(st, dict):
                        continue

                    if (st.get("verdict") or "").lower() == "fail":
                        bundle["verdict"]["failed_scenarios"].append(
                            {
                                "scenario_id": sid,
                                "step": st.get("step"),
                                "type": st.get("type"),
                                "error": st.get("error"),
                                "meta": st.get("meta"),
                                "evidence": {
                                    "artifact": results_ptr,
                                    "path": f"scenarios[{si}].steps[{st_i}]",
                                },
                            }
                        )

                    st_type = st.get("type")
                    st_verdict = (st.get("verdict") or "").lower()
                    if st_type in ("wait_for", "wait_for_bgp") and st_verdict != "pass":
                        bundle["verdict"]["wait_failures"].append(
                            {
                                "scenario_id": sid,
                                "step": st.get("step"),
                                "type": st_type,
                                "expected": st.get("expected"),
                                "observed": st.get("observed"),
                                "error": st.get("error"),
                                "evidence": {
                                    "artifact": results_ptr,
                                    "path": f"scenarios[{si}].steps[{st_i}]",
                                },
                            }
                        )

            # Deterministic sorting
            def _k_test(x: dict) -> tuple:
                ev = x.get("evidence", {}) or {}
                return (
                    str(x.get("name") or ""),
                    str(x.get("type") or ""),
                    str(ev.get("path") or ""),
                )

            def _k_step(x: dict) -> tuple:
                step_v = x.get("step")
                step_i = step_v if isinstance(step_v, int) else 10**9
                return (str(x.get("scenario_id") or ""), step_i, str(x.get("type") or ""))

            bundle["verdict"]["failed_tests"] = sorted(bundle["verdict"]["failed_tests"], key=_k_test)
            bundle["verdict"]["failed_scenarios"] = sorted(bundle["verdict"]["failed_scenarios"], key=_k_step)
            bundle["verdict"]["wait_failures"] = sorted(bundle["verdict"]["wait_failures"], key=_k_step)

        except Exception as e:
            bundle["notes"].append(f"Failed to parse results.json: {e!s}")

    # IMPORTANT: all output logic lives in the shared finalizer
    bundle["change_explain"] = _ai_explain_change_sections(bundle)
    _ai_finalize_and_emit("explain", bundle, args)

# ----------------------------
# v1: Change Context (Step 2) — AI bundle-only packaging helpers
#   - best-effort, deterministic
#   - size-limited, redacted
#   - NEVER affects runtime / verdicts / exit codes
# ----------------------------

_AI_CC_ITEM_MAX_BYTES = 64 * 1024        # 64 KiB per item read cap
_AI_CC_TOTAL_MAX_BYTES = 256 * 1024      # 256 KiB total cap across items
_AI_CC_PREVIEW_MAX_CHARS = 4096          # preview chars per item (after redaction)
_AI_CC_MAX_ITEMS = 50                    # hard cap for safety


def _ai_cc_redact(text: str) -> str:
    """
    Deterministic, conservative redaction for common secret-like patterns.
    Not a security guarantee; just hygiene to reduce accidental leakage.
    """
    if not text:
        return text

    out_lines: list[str] = []
    keys = ("password", "passwd", "secret", "token", "api_key", "apikey", "private_key")

    for line in text.splitlines(True):  # keep newlines
        low = line.lower()
        if any(k in low for k in keys):
            # redact value after common separators
            for sep in (":", "=", " "):
                if sep in line:
                    left, right = line.split(sep, 1)
                    # keep left + sep, replace remainder
                    line = f"{left}{sep} <redacted>\n" if line.endswith("\n") else f"{left}{sep} <redacted>"
                    break
        out_lines.append(line)

    return "".join(out_lines)


def _ai_cc_safe_read_text_file(base_dir: Path, rel_path: str, max_bytes: int) -> tuple[str, dict]:
    """
    Best-effort safe read:
      - only allows paths within base_dir (no traversal)
      - blocks absolute paths
      - reads at most max_bytes
    Returns: (text, meta)
    """
    meta: dict[str, Any] = {
        "source_kind": "file",
        "path": rel_path,
        "status": "unavailable",
        "bytes": 0,
        "truncated": False,
        "reason": "",
    }

    try:
        if not isinstance(rel_path, str) or not rel_path.strip():
            meta["status"] = "invalid"
            meta["reason"] = "empty path"
            return "", meta

        rp = rel_path.strip()
        p = Path(rp)

        if p.is_absolute():
            meta["status"] = "blocked"
            meta["reason"] = "absolute paths are blocked"
            return "", meta

        # Resolve under base_dir and prevent traversal
        base = base_dir.resolve()
        full = (base / p).resolve()
        if str(full) == str(base) or (not str(full).startswith(str(base) + os.sep)):
            meta["status"] = "blocked"
            meta["reason"] = "path traversal / outside base_dir blocked"
            return "", meta

        if not full.exists() or not full.is_file():
            meta["status"] = "missing"
            meta["reason"] = "file not found"
            return "", meta

        # bounded read
        with full.open("rb") as f:
            raw = f.read(max_bytes + 1)

        if len(raw) > max_bytes:
            raw = raw[:max_bytes]
            meta["truncated"] = True

        # decode best-effort as utf-8; replace errors deterministically
        txt = raw.decode("utf-8", errors="replace")
        meta["status"] = "ok"
        meta["bytes"] = len(raw)
        return txt, meta

    except Exception as e:
        meta["status"] = "error"
        meta["reason"] = str(e)
        return "", meta


def _ai_cc_build_change_context(topo_obj: dict, base_dir: Path) -> dict[str, Any]:
    """
    Build deterministic change_context bundle payload from topo candidate_changes.
    Reads candidate content ONLY here (bundle-time), size-limited.
    """
    cc = topo_obj.get("candidate_changes")
    out: dict[str, Any] = {
        "present": bool(cc),
        "counts": {"items": 0, "included": 0, "blocked": 0, "missing": 0, "errors": 0, "too_large": 0},
        "limits": {
            "item_max_bytes": _AI_CC_ITEM_MAX_BYTES,
            "total_max_bytes": _AI_CC_TOTAL_MAX_BYTES,
            "preview_max_chars": _AI_CC_PREVIEW_MAX_CHARS,
            "max_items": _AI_CC_MAX_ITEMS,
        },
        "items": [],
        "notes": [],
    }

    if not isinstance(cc, list) or not cc:
        return out

    total_budget = _AI_CC_TOTAL_MAX_BYTES
    included = 0

    # Preserve declared ordering (author intent), but cap number of items deterministically
    for idx, item in enumerate(cc[:_AI_CC_MAX_ITEMS], start=1):
        if not isinstance(item, dict):
            continue

        cid = item.get("id")
        cid = cid.strip() if isinstance(cid, str) else f"candidate_changes[{idx}]"

        entry: dict[str, Any] = {
            "id": cid,
            "description": (item.get("description").strip() if isinstance(item.get("description"), str) else ""),
            "format": (item.get("format").strip() if isinstance(item.get("format"), str) else ""),
            "scope": (item.get("scope") if isinstance(item.get("scope"), list) else []),
            "source": {},
            "preview": {"text": "", "redacted": True},
        }

        # inline wins only if present (Step 1 enforces exactly one)
        if item.get("inline") is not None:
            s = item.get("inline")
            if not isinstance(s, str):
                s = str(s)
            raw = s
            # enforce per-item cap via bytes
            b = raw.encode("utf-8", errors="replace")
            meta = {
                "source_kind": "inline",
                "status": "ok",
                "bytes": min(len(b), _AI_CC_ITEM_MAX_BYTES),
                "truncated": len(b) > _AI_CC_ITEM_MAX_BYTES,
                "reason": "",
            }
            if len(b) > _AI_CC_ITEM_MAX_BYTES:
                raw = b[:_AI_CC_ITEM_MAX_BYTES].decode("utf-8", errors="replace")
            # total budget enforcement
            if meta["bytes"] > total_budget:
                meta["status"] = "too_large"
                meta["reason"] = "exceeds remaining total budget"
                out["counts"]["too_large"] += 1
                entry["source"] = meta
                out["items"].append(entry)
                continue

            total_budget -= meta["bytes"]
            red = _ai_cc_redact(raw)
            entry["source"] = meta
            entry["preview"]["text"] = red[:_AI_CC_PREVIEW_MAX_CHARS]
            included += 1
            out["items"].append(entry)
            continue

        # file path
        rel_path = item.get("file")
        rel_path = rel_path.strip() if isinstance(rel_path, str) else str(rel_path)

        # if no budget left, record deterministically
        if total_budget <= 0:
            entry["source"] = {
                "source_kind": "file",
                "path": rel_path,
                "status": "too_large",
                "bytes": 0,
                "truncated": False,
                "reason": "no remaining total budget",
            }
            out["counts"]["too_large"] += 1
            out["items"].append(entry)
            continue

        max_bytes = min(_AI_CC_ITEM_MAX_BYTES, total_budget)
        txt, meta = _ai_cc_safe_read_text_file(base_dir, rel_path, max_bytes=max_bytes)

        # update counters
        st = meta.get("status")
        if st == "ok":
            included += 1
        elif st == "blocked":
            out["counts"]["blocked"] += 1
        elif st == "missing":
            out["counts"]["missing"] += 1
        elif st == "error":
            out["counts"]["errors"] += 1
        elif st == "too_large":
            out["counts"]["too_large"] += 1

        # budget accounting only if we actually read bytes
        if st == "ok":
            total_budget -= int(meta.get("bytes") or 0)

        entry["source"] = meta
        if st == "ok":
            red = _ai_cc_redact(txt)
            entry["preview"]["text"] = red[:_AI_CC_PREVIEW_MAX_CHARS]
        out["items"].append(entry)

    out["counts"]["items"] = min(len(cc), _AI_CC_MAX_ITEMS)
    out["counts"]["included"] = included
    if len(cc) > _AI_CC_MAX_ITEMS:
        out["notes"].append(f"candidate_changes truncated to first {_AI_CC_MAX_ITEMS} items (safety cap)")

    return out

def _ai_read_yaml(path: str) -> Any:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
    
def _ai_load_adapters(paths: list[str], command_name: str) -> dict[str, Any]:
    """
    Load adapters.v1 JSON files for AI context only.
    Missing/unreadable path is an AI usage error (exit 2) because the user explicitly requested it.
    Adapter parse_errors inside the JSON are preserved as advisory and do not fail the AI command.
    """
    from pathlib import Path

    norm_paths: list[str] = []
    for p in (paths or []):
        if isinstance(p, str) and p.strip():
            norm_paths.append(p.strip())

    # Deterministic order
    norm_paths = sorted(set(norm_paths))

    out_inputs: list[dict[str, Any]] = []
    for p in norm_paths:
        pp = Path(p)
        if not pp.exists():
            print(f"ERROR: adapter not found: {pp}", file=sys.stderr)
            sys.exit(2)
        if not pp.is_file():
            print(f"ERROR: adapter is not a file: {pp}", file=sys.stderr)
            sys.exit(2)

        try:
            with pp.open("r", encoding="utf-8") as f:
                obj = json.load(f)
        except Exception as e:
            print(f"ERROR: failed to read adapter JSON {pp}: {e!s}", file=sys.stderr)
            sys.exit(2)

        # Minimal schema sanity (advisory-only)
        schema_version = str(obj.get("schema_version") or "")
        authority = str(obj.get("authority") or "")
        source_type = str(obj.get("source_type") or "")
        summary = obj.get("summary") if isinstance(obj.get("summary"), dict) else {}

        parse_errors = obj.get("parse_errors") if isinstance(obj.get("parse_errors"), list) else []
        parse_warnings = obj.get("parse_warnings") if isinstance(obj.get("parse_warnings"), list) else []

        out_inputs.append(
            {
                "path": str(pp),
                "schema_version": schema_version,
                "authority": authority,
                "source_type": source_type,
                "summary": {
                    "items_total": int(summary.get("items_total") or 0),
                    "items_changed": int(summary.get("items_changed") or 0),
                    "items_added": int(summary.get("items_added") or 0),
                    "items_removed": int(summary.get("items_removed") or 0),
                },
                "parse": {
                    "warnings": int(len(parse_warnings)),
                    "errors": int(len(parse_errors)),
                },
                "notes": [
                    "Advisory-only adapter context. Does not affect verdicts/exit codes.",
                    f"Loaded by ai {command_name}.",
                ],
            }
        )

    return {
        "authority": "advisory",
        "count": int(len(out_inputs)),
        "inputs": out_inputs,
    }

def _ai_review_change_sections(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Deterministic, vendor-agnostic offline review sections for Change Context.
    No remediation. No vendor parsing. Advisory only.
    """
    cc = (bundle.get("change_context") or {}) if isinstance(bundle, dict) else {}
    items = cc.get("items") if isinstance(cc.get("items"), list) else []
    counts = cc.get("counts") if isinstance(cc.get("counts"), dict) else {}
    present = bool(cc.get("present"))

    # ---- 1) What Changed? ----
    what_changed: list[dict[str, Any]] = []
    if not present:
        what_changed.append(
            {"type": "no_change_context", "summary": "No candidate_changes declared in topology."}
        )
    else:
        for it in items:
            if not isinstance(it, dict):
                continue
            src = it.get("source") or {}
            what_changed.append(
                {
                    "id": it.get("id"),
                    "format": it.get("format") or "",
                    "scope": it.get("scope") or [],
                    "source_status": src.get("status"),
                    "source_kind": src.get("source_kind"),
                    "summary": it.get("description") or "",
                }
            )

    # ---- 2) Am I Missing Something? ----
    missing: list[dict[str, Any]] = []

    if present and int(counts.get("included") or 0) == 0:
        missing.append(
            {
                "type": "change_context_not_included",
                "hint": "Candidate changes were declared but none could be included in the bundle (missing/blocked/too_large).",
            }
        )

    # scope hygiene: if any item has empty scope, nudge to add it (still optional)
    if present:
        any_empty_scope = False
        any_has_scope = False
        for it in items:
            if not isinstance(it, dict):
                continue
            sc = it.get("scope")
            if isinstance(sc, list) and sc:
                any_has_scope = True
            else:
                any_empty_scope = True
        if any_empty_scope:
            missing.append(
                {
                    "type": "scope_not_specified",
                    "hint": "Some candidate changes have no scope. Consider adding scope: [node1, node2] to clarify what should be proven.",
                }
            )
        if not any_has_scope:
            missing.append(
                {
                    "type": "no_scopes_present",
                    "hint": "No candidate changes specify scope. Proof suggestions will be generic (still safe).",
                }
            )

    # deterministic checklist reminders (generic, not vendor-specific)
    missing.extend(
        [
            {"type": "pre_change_baseline", "hint": "Do you have steady-state tests that pass before the change? (baseline proof)"},
            {"type": "negative_tests", "hint": "If a firewall/policy exists, do you have at least one expected-fail (blocked) test?"},
            {"type": "failover_scenarios", "hint": "If the change could affect failover, do you have a scenario with fault + wait_for + post-fault revalidation?"},
        ]
    )

    # ---- 3) Minimal Proof Set (template-level) ----
    proof: list[dict[str, Any]] = []

    # Always include a tiny deterministic proof set template (does not claim correctness)
    proof.append(
        {
            "name": "baseline_reachability",
            "purpose": "Prove the network still forwards the intended steady-state traffic.",
            "templates": [
                {"kind": "ping", "from": "<src_node>", "to_ip": "<dst_ip_or_service_vip>"},
                {"kind": "tcp", "from": "<src_node>", "to_ip": "<dst_ip_or_service_vip>", "port": 443},
            ],
        }
    )
    proof.append(
        {
            "name": "control_plane_convergence",
            "purpose": "Prove routing converges to the expected state after events (if applicable).",
            "templates": [
                {"scenario_step": "wait_for_bgp", "node": "<frr_node>", "timeout": 60},
                {"scenario_step": "wait_for", "type": "ping", "from": "<src_node>", "to": "<dst_node_or_ip>", "expect": "pass", "timeout": 30},
            ],
        }
    )
    proof.append(
        {
            "name": "policy_negative",
            "purpose": "Prove must-not traffic is still blocked (if policy/firewall is in path).",
            "templates": [
                {"kind": "tcp", "from": "<src_node>", "to_ip": "<dst_ip>", "port": 22, "expected": "fail"},
            ],
        }
    )

    return {
        "what_changed": what_changed,
        "missing_something": missing,
        "minimal_proof_set": proof,
        "notes": [
            "Change context is advisory-only; tests and scenarios remain authoritative.",
            "This section is vendor-agnostic and does not interpret configs.",
        ],
    }

def cmd_ai_review(args) -> None:
    """
    Unified conversational ai handler (advisory-only, artifact-only).

    Exit codes:
      0 = successful advisory response
      1 = internal ai interface failure after valid invocation context
      2 = misuse / blocked / missing-artifact / ambiguous-context error
    """
    from pathlib import Path
    import json
    import yaml

    def _blocked_message() -> str:
        return (
            "AI request blocked (advisory scope exceeded)\n\n"
            "The assistant cannot create or modify topology or tests."
        )

    def _question_text() -> str:
        parts = list(getattr(args, "question", []) or [])
        return " ".join([str(x) for x in parts]).strip()

    def _route_question(question: str) -> str | None:
        q = (question or "").strip().lower()
        if not q:
            return None
        advisory_words = (
            "why",
            "what",
            "how",
            "explain",
            "teach",
            "review",
            "improve",
            "better",
            "example",
            "missing",
            "next",
            "likely",
            "suggest",
            "prove",
            "test",
        )
        if "blast radius" in q:
            return "blast_radius_explain"
        if (
            "invariant" in q
            and (
                "add" in q
                or "missing" in q
                or "help" in q
                or "draft" in q
                or "first" in q
                or "would you" in q
                or "should i" in q
            )
        ):
            return "coverage_review"
        if "invariant" in q:
            return "invariant_explain"
        if (
            "scenario" in q
            or "failover" in q
            or "fault should i inject" in q
            or "failure scenario" in q
        ) and (
            any(word in q for word in advisory_words)
            or "validate" in q
            or "add" in q
            or "missing" in q
            or "draft" in q
            or "inject" in q
        ):
            return "coverage_review"
        if (
            "proof gap" in q
            or "proof am i missing" in q
            or "prove first" in q
            or "what should i prove first" in q
        ):
            return "failure_explain"
        if "coverage" in q or (
            ("test" in q or "tests" in q) and any(word in q for word in advisory_words)
        ):
            return "coverage_review"
        if (
            ("topology" in q or "design" in q)
            and any(word in q for word in advisory_words)
        ) or (
            "topology" in q
            and (
                "improved" in q
                or "improve this" in q
                or "how would you improve" in q
                or "make this better" in q
            )
        ):
            return "topology_review"
        if (
            "fail" in q
            or "wrong" in q
            or "cause" in q
            or "change first" in q
            or "what should i change first" in q
            or "path to a passing result" in q
            or "failure mechanism" in q
            or "inspect first" in q
            or "concrete fix" in q
        ):
            return "failure_explain"
        if (
            "validation plan" in q
            or "validate this better" in q
            or "what tests should i add next" in q
        ):
            return "coverage_review"
        return None

    def _is_out_of_scope(question: str) -> bool:
        q = (question or "").strip().lower()
        if not q:
            return False
        advisory_words = (
            "why",
            "what",
            "how",
            "explain",
            "teach",
            "review",
            "improve",
            "better",
            "example",
            "missing",
            "next",
            "likely",
            "suggest",
        )
        mutate_words = ("modify", "change", "create", "add", "rewrite", "generate", "update", "fix")
        scope_words = ("topology", "scenario", "scenarios", "config", "configs", "configuration")
        execute_words = ("run ", "execute ", "deploy", "provision", "destroy", "replay")
        if any(w in q for w in execute_words):
            return True
        if "apply the best fix now" in q:
            return True
        if any(w in q for w in mutate_words) and any(w in q for w in scope_words):
            return not any(w in q for w in advisory_words)
        return False

    def _latest_artifacts_dir() -> tuple[Path | None, str]:
        labs_dir = Path("labs")
        if not labs_dir.exists() or not labs_dir.is_dir():
            return None, "most_recent_run"
        candidates: list[tuple[float, str, Path]] = []
        for child in sorted(labs_dir.iterdir(), key=lambda p: p.name):
            if not child.is_dir() or not child.name.startswith("clab-"):
                continue
            rp = child / "results.json"
            tp = child / "topology.resolved.yaml"
            if not rp.exists() or not tp.exists():
                continue
            try:
                score = max(rp.stat().st_mtime, tp.stat().st_mtime)
            except Exception:
                score = 0.0
            candidates.append((score, child.name, child))
        if not candidates:
            return None, "most_recent_run"
        candidates = sorted(candidates, key=lambda x: (x[0], x[1]))
        return candidates[-1][2], "most_recent_run"

    def _resolve_context_dir() -> tuple[Path | None, str]:
        artifacts = getattr(args, "artifacts", None)
        lab = getattr(args, "lab", None)
        latest_dir, latest_source = _latest_artifacts_dir()
        if artifacts:
            return Path(str(artifacts)), "explicit_artifacts"
        if lab:
            lab_dir = Path("labs") / f"clab-{str(lab).strip()}"
            rp = lab_dir / "results.json"
            tp = lab_dir / "topology.resolved.yaml"
            if rp.exists() and tp.exists():
                return lab_dir, "explicit_lab"
            return lab_dir, "explicit_lab"
        if latest_dir is not None:
            return latest_dir, latest_source
        return None, "most_recent_run"

    def _selected_rendering_mode() -> str:
        return "online-enriched advisory rendering" if getattr(args, "online", False) else "local advisory rendering"

    def _build_banner(context_dir: Path, context_source: str, module_name: str, loaded: list[str]) -> list[str]:
        return [
            "AI Assistant (Advisory Mode)",
            "Authority: Advisory Only",
            "Execution Impact: None",
            f"Context Source: {context_source}",
            f"Artifacts Dir: {context_dir}",
            f"Artifacts Loaded: {', '.join(loaded)}",
            f"Module: {module_name}",
            f"Rendering Mode: {_selected_rendering_mode()}",
        ]

    def _build_evidence_package(
        module_name: str,
        question: str,
        output: dict[str, Any],
        context_dir: Path,
        context_source: str,
        loaded: list[str],
    ) -> dict[str, Any]:
        return {
            "authority": "advisory",
            "execution_impact": "none",
            "context_source": context_source,
            "artifacts_dir": str(context_dir),
            "artifacts_loaded": list(loaded),
            "module": module_name,
            "question": question,
            "response": output,
        }

    def _load_required_artifacts(context_dir: Path) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
        resolved_path = context_dir / "topology.resolved.yaml"
        results_path = context_dir / "results.json"
        missing: list[str] = []
        if not resolved_path.exists():
            missing.append("topology.resolved.yaml")
        if not results_path.exists():
            missing.append("results.json")
        if missing:
            print(
                "ERROR: AI Assistant cannot operate without artifacts.\n\n"
                "Required artifacts:\n"
                "  topology.resolved.yaml\n"
                "  results.json\n\n"
                "Run:\n"
                "cassian test <topology>",
                file=sys.stderr,
            )
            sys.exit(2)
        with resolved_path.open("r", encoding="utf-8") as f:
            topo = yaml.safe_load(f) or {}
        with results_path.open("r", encoding="utf-8") as f:
            results = json.load(f) or {}
        return topo, results, ["topology.resolved.yaml", "results.json"]

    def _inventory(topo: dict[str, Any]) -> dict[str, Any]:
        nodes = topo.get("nodes") or []
        tests = topo.get("tests") or []
        scenarios = topo.get("scenarios") or []
        node_names: list[str] = []
        node_types: dict[str, str] = {}
        for n in nodes:
            if isinstance(n, dict):
                nm = str(n.get("name") or "").strip()
                tp = str(n.get("type") or "").strip()
                if nm:
                    node_names.append(nm)
                    if tp:
                        node_types[nm] = tp
        node_names = sorted(set(node_names))
        return {
            "node_names": node_names,
            "node_types": {k: node_types[k] for k in sorted(node_types)},
            "tests_count": len(tests),
            "scenarios_count": len(scenarios),
            "hosts": sorted([n for n in node_names if node_types.get(n) == "host"]),
            "routers": sorted([n for n in node_names if node_types.get(n) in ("frr", "linux", "sonic-vm")]),
        }

    def _failed_tests(results: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for t in list(results.get("tests") or []):
            if isinstance(t, dict) and str(t.get("verdict") or "").lower() == "fail":
                out.append(
                    {
                        "name": str(t.get("name") or ""),
                        "kind": str(t.get("kind") or t.get("type") or ""),
                        "reason": str(t.get("reason") or ""),
                    }
                )
        return sorted(out, key=lambda x: (x["name"], x["kind"], x["reason"]))

    def _failed_scenario_steps(results: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for s in list(results.get("scenarios") or []):
            if not isinstance(s, dict):
                continue
            sid = str(s.get("id") or "")
            for st in list(s.get("steps") or []):
                if isinstance(st, dict) and str(st.get("verdict") or "").lower() == "fail":
                    step_v = st.get("step")
                    step_i = step_v if isinstance(step_v, int) else 10**9
                    out.append(
                        {
                            "scenario_id": sid,
                            "step": step_i,
                            "type": str(st.get("type") or ""),
                            "error": str(st.get("error") or ""),
                        }
                    )
        return sorted(out, key=lambda x: (x["scenario_id"], x["step"], x["type"], x["error"]))

    def _module_output(module_name: str, question: str, topo: dict[str, Any], results: dict[str, Any], context_dir: Path) -> dict[str, Any]:
        inv = _inventory(topo)
        failed_tests = _failed_tests(results)
        failed_steps = _failed_scenario_steps(results)
        tests = list(topo.get("tests") or [])
        scenarios = sorted(
            [
                str(s.get("id") or "")
                for s in list(topo.get("scenarios") or [])
                if isinstance(s, dict) and str(s.get("id") or "").strip()
            ]
        )
        overall = results.get("result")
        blast_radius_path = context_dir / "artifacts" / "blast-radius" / "blast_radius.json"

        if module_name == "failure_explain":
            all_expect_fail = bool(tests) and all(str(t.get("expect", "")).strip().lower() == "fail" for t in tests)
            likely_causes = [
                "Validation failures are derived from existing authoritative artifacts only.",
                "Review the named failed tests or scenario steps first; AI does not redefine verdicts.",
            ]
            next_actions = [
                "Inspect the failed test or scenario entries in results.json.",
                "Use deterministic replay or gate rerun to reproduce if needed.",
            ]
            example_drafts = []
            coaching_notes = []

            failed_test_names = {
                str(t.get("name") or "").strip()
                for t in failed_tests
                if str(t.get("name") or "").strip()
            }
            declared_failed_tests = [
                t for t in tests
                if isinstance(t, dict) and str(t.get("name") or "").strip() in failed_test_names
            ]
            declared_failed_tcp_tests = [
                t for t in declared_failed_tests
                if str(t.get("kind", "")).strip().lower() == "tcp"
            ]

            requested_tcp_ports: list[int] = []
            for t in declared_failed_tcp_tests:
                try:
                    requested_tcp_ports.append(int(t.get("port")))
                except Exception:
                    pass
            requested_tcp_ports = sorted(set(requested_tcp_ports))

            allowed_tcp_ports: list[int] = []
            for node in list(topo.get("nodes") or []):
                if not isinstance(node, dict):
                    continue
                ports = node.get("allow_tcp")
                if isinstance(ports, list):
                    for port in ports:
                        try:
                            allowed_tcp_ports.append(int(port))
                        except Exception:
                            pass
            allowed_tcp_ports = sorted(set(allowed_tcp_ports))

            failed_invariants = [
                t for t in failed_tests
                if str(t.get("kind", "")).strip().lower() == "invariant"
            ]
            declared_failed_invariants = [
                t for t in declared_failed_tests
                if str(t.get("kind", "")).strip().lower() == "invariant"
            ]
            failed_route_invariants = [
                t for t in declared_failed_invariants
                if str(t.get("type", "")).strip().lower() in {"route_advertised_to", "route_present", "route_not_advertised_to"}
            ]

            if declared_failed_tcp_tests and requested_tcp_ports and allowed_tcp_ports and requested_tcp_ports != allowed_tcp_ports:
                requested_desc = ", ".join(str(p) for p in requested_tcp_ports)
                allowed_desc = ", ".join(str(p) for p in allowed_tcp_ports)
                likely_causes = [
                    f"The failed tcp proof expects port {requested_desc}, but the declared firewall policy allows TCP on {allowed_desc}.",
                    "The most likely issue is a port/policy mismatch between the test intent and the allowed service ports.",
                ]
                next_actions = [
                    f"First, decide whether the intended service should use port {requested_desc} or {allowed_desc}.",
                    f"Second, if {requested_desc} is correct, update the firewall allow list; if {allowed_desc} is correct, update the tcp proof port.",
                    "Not yet: do not add more scenarios or topology complexity until the intended service port is aligned.",
                ]
                example_drafts = [
                    f"Example only: firewall-side fix\nnodes:\n  - name: fw1\n    type: nft-fw\n    allow_tcp: [{allowed_desc}, {requested_desc}]",
                    f"Example only: test-side fix\ntests:\n  - name: h1_tcp_{allowed_desc.replace(', ', '_or_')}_to_h2_should_pass\n    kind: tcp\n    src: h1\n    dst: h2\n    port: {allowed_tcp_ports[0]}\n    listener: true\n    expect: pass",
                ]
                coaching_notes = [
                    "This is an advisory diagnosis only; the AI is pointing to the most likely mismatch from bounded artifacts and is not applying a change."
                ]
            elif failed_route_invariants:
                inv0 = failed_route_invariants[0]
                prefix = str(inv0.get("prefix") or "").strip()
                node_name = str(inv0.get("node") or "").strip()
                peer_name = str(inv0.get("peer") or "").strip()
                inv_type = str(inv0.get("type") or "").strip()
                likely_causes = [
                    f"The failed {inv_type} proof is scoped to prefix {prefix} between {node_name} and {peer_name}.",
                    "The most likely issue is either the wrong peer/prefix is being asserted, or the intended control-plane truth is not yet encoded in the topology under test.",
                ]
                next_actions = [
                    f"First, verify that {prefix} is the exact route you intend {node_name} to advertise toward {peer_name}.",
                    "Second, prove one route-focused truth before adding broader end-to-end or failover expectations.",
                    "Not yet: do not add more invariants until the first peer/prefix control-plane assertion is confirmed correct.",
                ]
                example_drafts = [
                    f"tests:\n  - name: {node_name}_advertises_{prefix.replace('/', '_')}_to_{peer_name}\n    kind: invariant\n    type: route_advertised_to\n    node: {node_name}\n    peer: {peer_name}\n    prefix: {prefix}\n    expect: pass"
                ]
                coaching_notes = [
                    "A failed route-focused invariant often means the proof target itself should be checked before broadening the test surface."
                ]
            elif all_expect_fail:
                likely_causes = [
                    "All declared tests currently expect failure, so a full PASS does not yet prove an intended success path.",
                    "The biggest proof gap is usually missing positive intent: what should pass in steady state is not yet encoded as a passing proof.",
                ]
                next_actions = [
                    "First, decide the first steady-state behavior that should succeed and encode it as an explicit passing test.",
                    "Second, keep failure-expected tests for negative intent, but separate them from the first success-path proof.",
                    "Not yet: do not expand topology or add resiliency scenarios before one intended passing path is proven.",
                ]
                example_drafts = [
                    "Example only: tests:\n  - name: h1_to_h2_ping_should_pass\n    kind: ping\n    src: h1\n    dst: h2\n    expect: pass\n    count: 2"
                ]
                coaching_notes = [
                    "A full PASS across failure-expected tests can still mean the topology lacks any proof of intended success."
                ]

            return {
                "summary": f"Overall result is {overall}. Failed tests: {len(failed_tests)}. Failed scenario steps: {len(failed_steps)}.",
                "primary_failures": failed_tests[:10],
                "evidence_refs": [
                    {"artifact": str(context_dir / "results.json"), "section": "tests"},
                    {"artifact": str(context_dir / "topology.resolved.yaml"), "section": "nodes"},
                ],
                "likely_causes": likely_causes,
                "next_actions": next_actions,
                "example_drafts": example_drafts,
                "coaching_notes": coaching_notes,
                "authority": "advisory",
            }


        if module_name == "coverage_review":
            question_l = (question or "").strip().lower()
            all_expect_fail = bool(tests) and all(str(t.get("expect", "")).strip().lower() == "fail" for t in tests)
            has_positive_tests = any(str(t.get("expect", "")).strip().lower() == "pass" for t in tests)
            has_scenarios = bool(inv["scenarios_count"])
            host_pair = "host endpoints" if len(inv["hosts"]) >= 2 else "declared endpoints"

            link_pair_counts: dict[tuple[str, str], int] = {}
            pair_link_details: dict[tuple[str, str], list[tuple[str, str]]] = {}
            for link in list(topo.get("links") or []):
                if not isinstance(link, dict):
                    continue
                endpoints = list(link.get("endpoints") or [])
                if len(endpoints) != 2:
                    continue
                try:
                    left_node, left_if = str(endpoints[0]).split(":", 1)
                    right_node, right_if = str(endpoints[1]).split(":", 1)
                except ValueError:
                    continue
                pair = tuple(sorted([left_node, right_node]))
                link_pair_counts[pair] = link_pair_counts.get(pair, 0) + 1
                pair_link_details.setdefault(pair, []).append((left_if, right_if))
            parallel_pairs = sorted([pair for pair, count in link_pair_counts.items() if count > 1])

            host_networks: list[str] = []
            for node in list(topo.get("nodes") or []):
                if not isinstance(node, dict):
                    continue
                if str(node.get("type") or "").strip() != "host":
                    continue
                ip_v = str(node.get("ip") or "").strip()
                if not ip_v:
                    continue
                try:
                    host_networks.append(str(ipaddress.ip_interface(ip_v).network))
                except Exception:
                    pass
            host_networks = sorted(set(host_networks))

            scenario_ids = sorted(
                str(s.get("id") or "").strip()
                for s in list(topo.get("scenarios") or [])
                if isinstance(s, dict) and str(s.get("id") or "").strip()
            )
            tests_by_kind: dict[str, list[dict[str, Any]]] = {}
            for t in tests:
                if not isinstance(t, dict):
                    continue
                kind = str(t.get("kind") or "").strip().lower()
                tests_by_kind.setdefault(kind, []).append(t)

            route_like_invariants = []
            for t in tests_by_kind.get("invariant", []):
                inv_type = str(t.get("type") or "").strip().lower()
                if inv_type in {"route_advertised_to", "route_present", "route_not_advertised_to"}:
                    route_like_invariants.append(t)

            insights: list[str] = []
            if inv["tests_count"] == 0:
                insights.append("No tests are declared, so the topology currently has no executable proof of intended behavior.")
            if not has_scenarios:
                insights.append("No scenarios are declared, so failure choreography and recovery behavior are not being proven.")
            if all_expect_fail:
                insights.append("All current declared tests expect failure, so the topology does not yet prove any intended success path.")
            elif not has_positive_tests and inv["tests_count"] > 0:
                insights.append("There are declared tests, but none currently prove a clear positive steady-state success path.")
            if len(inv["hosts"]) >= 2 and inv["tests_count"] > 0:
                insights.append(f"The highest-value next proof is usually one explicit steady-state test across the {host_pair}.")
            if parallel_pairs:
                pair_desc = " and ".join(f"{a}<->{b}" for a, b in parallel_pairs)
                insights.append(f"Parallel links exist between {pair_desc}, so the topology already encodes a failover or ambiguity surface that should be proven explicitly.")
            if host_networks and ("invariant" in question_l or "scenario" in question_l):
                insights.append(f"Declared host subnets {', '.join(host_networks)} provide a bounded control-plane or path-intent surface for more targeted proofs.")
            if "invariant" in question_l and not route_like_invariants and host_networks:
                insights.append("No route-focused invariant is currently declared, so control-plane truth for the host subnets is still unproven.")
            if "scenario" in question_l and parallel_pairs and not any("break_primary_path" == sid for sid in scenario_ids):
                insights.append("The topology exposes a parallel-link fault surface, but there is no clearly named scenario that proves the primary-path failure behavior.")
            if "invariant" in question_l and parallel_pairs and route_like_invariants:
                insights.append("Control-plane checks should stay scoped to one peer/prefix truth first, rather than broadening into multiple parallel-link assertions at once.")

            ranked_actions: list[str] = []
            example_drafts: list[str] = []
            coaching_notes: list[str] = []

            if "validation plan" in question_l or "validate this better" in question_l:
                ranked_actions = [
                    "First, add one explicit steady-state passing proof for the intended successful path.",
                    "Second, add one negative-path proof for traffic or policy that must fail.",
                    "Third, add one scenario that injects the most important failure and re-runs the key proof.",
                    "Not yet, do not broaden topology complexity until these three proof layers exist.",
                ]
                example_drafts = [
                    "Example only: tests:\n  - name: h1_to_h2_ping_should_pass\n    kind: ping\n    src: h1\n    dst: h2\n    expect: pass\n    count: 2",
                    "Example only: tests:\n  - name: h1_to_h2_tcp_22_should_fail\n    kind: tcp\n    src: h1\n    dst: h2\n    port: 22\n    expect: fail",
                ]
                if parallel_pairs:
                    pair = parallel_pairs[0]
                    details = pair_link_details.get(pair) or []
                    left_if, right_if = details[0] if details else ("ethX", "ethY")
                    example_drafts.append(
                        f"Example only: scenarios:\n  - id: break_primary_path\n    steps:\n      - run: h1_to_h2_ping_should_pass\n      - fault:\n          link_down:\n            a: {pair[0]}\n            a_if: {left_if}\n            b: {pair[1]}\n            b_if: {right_if}\n      - run: h1_to_h2_ping_should_pass"
                    )
                else:
                    example_drafts.append(
                        "Example only: scenarios:\n  - id: break_primary_path\n    steps:\n      - run: h1_to_h2_ping_should_pass\n      - fault:\n          interface_down:\n            node: r1\n            if: eth1\n      - run: h1_to_h2_ping_should_pass"
                    )
                coaching_notes = [
                    "A validation plan is advisory only until each step is encoded as deterministic tests or scenarios."
                ]
            elif "scenario" in question_l and ("missing" in question_l or "add" in question_l or "draft" in question_l):
                ranked_actions = [
                    "First, add one scenario that breaks the most important dependency in the path.",
                    "Second, re-run the key end-to-end proof before and after the fault step.",
                    "Not yet, do not add extra scenarios until the primary failure scenario proves a meaningful behavior change.",
                ]
                if parallel_pairs:
                    pair = parallel_pairs[0]
                    details = pair_link_details.get(pair) or []
                    left_if, right_if = details[0] if details else ("ethX", "ethY")
                    example_drafts = [
                        f"Example only: scenarios:\n  - id: break_primary_path\n    steps:\n      - run: h1_to_h2_ping_should_pass\n      - fault:\n          link_down:\n            a: {pair[0]}\n            a_if: {left_if}\n            b: {pair[1]}\n            b_if: {right_if}\n      - run: h1_to_h2_ping_should_pass"
                    ]
                else:
                    example_drafts = [
                        "Example only: scenarios:\n  - id: break_primary_path\n    steps:\n      - run: h1_to_h2_ping_should_pass\n      - fault:\n          interface_down:\n            node: r1\n            if: eth1\n      - run: h1_to_h2_ping_should_pass"
                    ]
                coaching_notes = [
                    "Missing-scenario advice is advisory only until the scenario is declared and proven by deterministic execution."
                ]
            elif "invariant" in question_l and ("help" in question_l or "add" in question_l or "missing" in question_l or "draft" in question_l):
                ranked_actions = [
                    "First, add one invariant that proves the intended control-plane or policy truth directly.",
                    "Second, keep the invariant narrowly scoped to the specific route, peer, or attribute that matters.",
                    "Not yet, do not add multiple broad invariants before proving one high-value truth cleanly.",
                ]
                if host_networks and parallel_pairs:
                    pair = parallel_pairs[0]
                    example_drafts = [
                        f"Example only: tests:\n  - name: {pair[0]}_advertises_{host_networks[-1].replace('/', '_')}_to_{pair[1]}\n    kind: invariant\n    type: route_advertised_to\n    node: {pair[0]}\n    peer: {pair[1]}\n    prefix: {host_networks[-1]}\n    expect: pass"
                    ]
                elif host_networks:
                    example_drafts = [
                        f"Example only: tests:\n  - name: route_for_{host_networks[0].replace('/', '_')}_present\n    kind: invariant\n    type: route_advertised_to\n    node: r1\n    peer: r2\n    prefix: {host_networks[0]}\n    expect: pass"
                    ]
                else:
                    example_drafts = [
                        "Example only: tests:\n  - name: r2_advertises_expected_prefix\n    kind: invariant\n    type: route_advertised_to\n    node: r2\n    peer: fw1\n    prefix: 192.168.2.0/24\n    expect: pass"
                    ]
                coaching_notes = [
                    "Invariant suggestions are advisory only until the invariant is declared and proven by deterministic execution."
                ]
            else:
                if all_expect_fail:
                    ranked_actions = [
                        "First, choose the first end-to-end behavior that should succeed in steady state and express it as a passing test.",
                        "Second, keep the existing failure-expected tests as negative proofs, but do not treat them as proof of intended success.",
                        "Not yet, do not add more coverage breadth before one positive proof exists.",
                    ]
                    example_drafts = [
                        "Example only: tests:\n  - name: h1_to_h2_ping_should_pass\n    kind: ping\n    src: h1\n    dst: h2\n    expect: pass\n    count: 2",
                        "Example only: tests:\n  - name: h1_to_h2_tcp_443_should_pass\n    kind: tcp\n    src: h1\n    dst: h2\n    port: 443\n    expect: pass"
                    ]
                    coaching_notes = [
                        "When all declared tests expect failure, a full PASS mostly proves negative intent, not the design you want to succeed."
                    ]
                else:
                    ranked_actions = [
                        "First, add or strengthen the most important steady-state proof if coverage is sparse.",
                        "Second, add explicit failure choreography where resiliency matters.",
                        "Not yet, do not widen the proof surface until the highest-value steady-state and failure proofs are solid.",
                    ]
                    example_drafts = [
                        "Example only: add one steady-state path test and one failure scenario before treating coverage as strong."
                    ]
                    coaching_notes = [
                        "Suggested tests and scenarios are advisory ideas only until they are added and proven by deterministic execution."
                    ]

            return {
                "summary": f"Topology has {inv['tests_count']} tests and {inv['scenarios_count']} scenarios.",
                "primary_failures": [],
                "evidence_refs": [
                    {"artifact": str(context_dir / "topology.resolved.yaml"), "section": "tests"},
                    {"artifact": str(context_dir / "topology.resolved.yaml"), "section": "scenarios"},
                ],
                "likely_causes": insights,
                "next_actions": ranked_actions,
                "example_drafts": example_drafts,
                "coaching_notes": coaching_notes,
                "authority": "advisory",
            }


        if module_name == "topology_review":
            question_l = (question or "").strip().lower()
            all_expect_fail = bool(tests) and all(str(t.get("expect", "")).strip().lower() == "fail" for t in tests)
            notes: list[str] = []
            if len(inv["hosts"]) < 2:
                notes.append("Topology has fewer than two host nodes; endpoint coverage may be limited.")
            if inv["scenarios_count"] == 0:
                notes.append("No scenarios are declared.")
            if all_expect_fail:
                notes.append("All declared tests currently expect failure, so the main gap is proving the intended success state, not just changing node shape.")

            link_pair_counts: dict[tuple[str, str], int] = {}
            for link in list(topo.get("links") or []):
                if not isinstance(link, dict):
                    continue
                endpoints = list(link.get("endpoints") or [])
                if len(endpoints) != 2:
                    continue
                try:
                    left_node, _left_if = str(endpoints[0]).split(":", 1)
                    right_node, _right_if = str(endpoints[1]).split(":", 1)
                except ValueError:
                    continue
                pair = tuple(sorted([left_node, right_node]))
                link_pair_counts[pair] = link_pair_counts.get(pair, 0) + 1
            parallel_pairs = sorted([pair for pair, count in link_pair_counts.items() if count > 1])

            ranked_actions = [
                "Use explicit tests and scenarios to validate intended behavior.",
                "Keep suggestions advisory and prove them through deterministic tests.",
            ]
            example_drafts = [
                "Example only: strengthen the topology review by adding explicit validation intent rather than treating topology shape alone as proof."
            ]
            coaching_notes = [
                "Topology suggestions are non-authoritative examples for human review and must be validated through tests or scenarios."
            ]

            core_path = None
            if {"r1", "r2", "fw1", "r3"}.issubset(set(inv["node_names"])):
                core_path = "r1 -> r2 -> fw1 -> r3"

            if parallel_pairs:
                pair_desc = " and ".join(f"{a}<->{b}" for a, b in parallel_pairs)
                notes.append(f"Parallel links exist between {pair_desc}, so the topology already contains an explicit failover or ambiguity surface.")

            if all_expect_fail:
                ranked_actions = [
                    "First, keep the current shape if it already represents the intended path, and add one explicit passing proof for the success behavior you actually want.",
                    "Second, simplify only if extra links are not needed for failure-choreography or ambiguity testing.",
                    "Not yet, do not expand topology complexity before the current shape proves one intended success path.",
                ]
                example_drafts = [
                    "Example only: keep the current node/link shape, but add a passing steady-state test such as h1_to_h2_ping_should_pass before expanding the topology.",
                    "Example only: tests:\n  - name: h1_to_h2_ping_should_pass\n    kind: ping\n    src: h1\n    dst: h2\n    expect: pass\n    count: 2"
                ]
                coaching_notes = [
                    "When all tests expect failure, improving proof quality is usually more valuable than adding more topology complexity."
                ]

            if "improved topology" in question_l or "better topology" in question_l:
                if core_path:
                    draft_lines = [
                        "Example only: topology guidance",
                        f"- keep {core_path} as the core path",
                    ]
                    if parallel_pairs:
                        draft_lines.append(f"- keep the parallel {parallel_pairs[0][0]}<->{parallel_pairs[0][1]} link only if you want failover or ambiguity testing")
                        draft_lines.append("- otherwise remove the extra link to simplify proof intent")
                    example_drafts = [
                        "\n".join(draft_lines),
                        "Example only: tests:\n  - name: h1_to_h2_ping_should_pass\n    kind: ping\n    src: h1\n    dst: h2\n    expect: pass\n    count: 2",
                        "Example only: scenarios:\n  - id: break_primary_path\n    steps:\n      - run: h1_to_h2_ping_should_pass\n      - fault:\n          link_down:\n            a: r2\n            a_if: eth2\n            b: fw1\n            b_if: eth1\n      - run: h1_to_h2_ping_should_pass"
                    ]
                else:
                    example_drafts = [
                        "Example only: keep the existing path shape if it matches intent, remove only links or nodes that are not buying proof value, and add one passing steady-state proof plus one failure scenario before expanding topology complexity."
                    ]

            return {
                "summary": f"Resolved topology contains {len(inv['node_names'])} nodes.",
                "primary_failures": [],
                "evidence_refs": [{"artifact": str(context_dir / "topology.resolved.yaml"), "section": "nodes"}],
                "likely_causes": notes,
                "next_actions": ranked_actions,
                "example_drafts": example_drafts,
                "coaching_notes": coaching_notes,
                "authority": "advisory",
            }

        if module_name == "blast_radius_explain":
            if blast_radius_path.exists():
                with blast_radius_path.open("r", encoding="utf-8") as f:
                    br = json.load(f) or {}
                return {
                    "summary": "Blast radius artifact is present.",
                    "primary_failures": [],
                    "evidence_refs": [{"artifact": str(blast_radius_path), "section": "counts"}],
                    "likely_causes": [f"Directly covered: {json.dumps(br.get('directly_covered') or {}, sort_keys=True)}"],
                    "next_actions": ["Use blast radius as supporting evidence only."],
                    "authority": "advisory",
                }
            return {
                "summary": "Blast radius artifact is not present for this context.",
                "primary_failures": [],
                "evidence_refs": [{"artifact": str(context_dir / 'results.json'), "section": "blast_radius"}],
                "likely_causes": ["No blast_radius.json artifact was found in the selected context."],
                "next_actions": ["Run a topology or scenario path that produces blast radius artifacts if needed."],
                "authority": "advisory",
            }

        if module_name == "scenario_interpret":
            return {
                "summary": f"Resolved topology declares {len(scenarios)} scenarios.",
                "primary_failures": failed_steps[:10],
                "evidence_refs": [{"artifact": str(context_dir / "topology.resolved.yaml"), "section": "scenarios"}],
                "likely_causes": ["Scenario interpretation is based only on declared scenarios and recorded scenario results."],
                "next_actions": ["Review failed scenario steps in results.json for exact step ordering and errors."],
                "example_drafts": [
                    "Example only: add one scenario that injects the key failure and re-runs the primary proof before and after the fault."
                ],
                "authority": "advisory",
            }

        if module_name == "invariant_explain":
            invariant_failures = [t for t in failed_tests if t.get("kind") == "invariant"]
            return {
                "summary": f"Found {len(invariant_failures)} failed invariant tests.",
                "primary_failures": invariant_failures[:10],
                "evidence_refs": [{"artifact": str(context_dir / "results.json"), "section": "tests"}],
                "likely_causes": ["Invariant explanations are derived from existing failed invariant entries only."],
                "next_actions": ["Inspect the failed invariant entries in results.json and replay deterministically if needed."],
                "example_drafts": [
                    "Example only: add one narrowly scoped invariant that proves the intended route, peer, or attribute truth directly."
                ],
                "authority": "advisory",
            }

        print("ERROR: unsupported ai routing target", file=sys.stderr)
        sys.exit(2)

    def _emit_text(question: str, banner_lines: list[str], module_name: str, output: dict[str, Any]) -> None:
        def _looks_structured_block(text: str) -> bool:
            if "\n" not in text:
                return False
            stripped = text.strip()
            if not stripped:
                return False
            structured_markers = (
                "tests:\n",
                "scenarios:\n",
                "nodes:\n",
                "links:\n",
                "vlans:\n",
                "fabric:\n",
                "packs:\n",
            )
            return stripped.startswith(structured_markers) or "\n  - " in stripped or "\n    " in stripped

        def _print_draft_block(text: str) -> None:
            print("-----")
            print(text.rstrip())
            print("-----")

        def _draft_label(idx: int, text: str) -> str:
            stripped = text.lstrip()
            lowered = stripped.lower()
            if lowered.startswith("tests:\n"):
                return f"Draft {idx} — test block"
            if lowered.startswith("scenarios:\n"):
                return f"Draft {idx} — scenario block"
            if lowered.startswith("nodes:\n"):
                return f"Draft {idx} — node block"
            if lowered.startswith("links:\n"):
                return f"Draft {idx} — link block"
            if lowered.startswith("topology guidance"):
                return f"Draft {idx} — topology guidance"
            if lowered.startswith("firewall-side fix"):
                return f"Draft {idx} — firewall-side fix"
            if lowered.startswith("test-side fix"):
                return f"Draft {idx} — test-side fix"
            return f"Draft {idx}"

        def _normalize_draft_text(text: str) -> str:
            stripped = text.lstrip()
            if stripped.startswith("Example only: "):
                stripped = stripped[len("Example only: "):]
            return stripped.rstrip()

        for line in banner_lines:
            print(line)
        print("")
        print(f"Question: {question}")
        print(f"Summary: {output.get('summary')}")

        evidence_refs = list(output.get("evidence_refs") or [])
        likely_causes = list(output.get("likely_causes") or [])
        next_actions = list(output.get("next_actions") or [])
        example_drafts = list(output.get("example_drafts") or [])
        coaching_notes = list(output.get("coaching_notes") or [])

        if evidence_refs:
            print("")
            print("Deterministic Facts / Grounded Evidence:")
            for item in evidence_refs:
                if isinstance(item, dict):
                    artifact = str(item.get("artifact") or "")
                    section = str(item.get("section") or "")
                    if artifact and section:
                        print(f"- {artifact} [{section}]")
                    elif artifact:
                        print(f"- {artifact}")

        if likely_causes:
            print("")
            print("Advisory Interpretation / Likely Cause:")
            for item in likely_causes:
                print(f"- {item}")

        if next_actions:
            print("")
            print("Recommended Next Steps:")
            for item in next_actions:
                print(f"- {item}")

        if example_drafts:
            print("")
            print("Example Drafts (Non-Authoritative / Human Review Only):")
            for idx, item in enumerate(example_drafts, start=1):
                original_text = str(item)
                text = _normalize_draft_text(original_text)
                print(_draft_label(idx, text))
                if _looks_structured_block(text):
                    _print_draft_block(text)
                else:
                    print(text)

        if coaching_notes:
            print("")
            print("Teaching / Coaching (Advisory Only):")
            for item in coaching_notes:
                print(f"- {item}")

    def _emit_json(question: str, context_dir: Path, context_source: str, loaded: list[str], module_name: str, output: dict[str, Any]) -> None:
        payload = {
            "authority": "advisory",
            "execution_impact": "none",
            "context_source": context_source,
            "artifacts_dir": str(context_dir),
            "artifacts_loaded": loaded,
            "module": module_name,
            "question": question,
            "response": output,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))

    try:
        question = _question_text()
        if question and _is_out_of_scope(question):
            print(_blocked_message(), file=sys.stderr)
            sys.exit(2)

        context_dir, context_source = _resolve_context_dir()
        if context_dir is None:
            print(
                "ERROR: AI Assistant cannot operate without artifacts.\n\n"
                "Required artifacts:\n"
                "  topology.resolved.yaml\n"
                "  results.json\n\n"
                "Run:\n"
                "cassian test <topology>",
                file=sys.stderr,
            )
            sys.exit(2)

        topo, results, loaded = _load_required_artifacts(context_dir)

        def _handle_one(question: str) -> None:
            if _is_out_of_scope(question):
                print(_blocked_message(), file=sys.stderr)
                sys.exit(2)
            module_name = _route_question(question)
            if module_name is None:
                print("ERROR: unsupported/out-of-scope advisory request", file=sys.stderr)
                sys.exit(2)
            output = _module_output(module_name, question, topo, results, context_dir)
            banner_lines = _build_banner(context_dir, context_source, module_name, loaded)
            fmt = str(getattr(args, "format", "text") or "text")
            if fmt == "json":
                _emit_json(question, context_dir, context_source, loaded, module_name, output)
            else:
                _emit_text(question, banner_lines, module_name, output)

        if getattr(args, "online", False):
            if not question:
                print("ERROR: online-enriched advisory rendering requires a question", file=sys.stderr)
                sys.exit(2)
            module_name = _route_question(question)
            if module_name is None:
                print("ERROR: unsupported/out-of-scope advisory request", file=sys.stderr)
                sys.exit(2)
            output = _module_output(module_name, question, topo, results, context_dir)
            evidence_package = _build_evidence_package(
                module_name,
                question,
                output,
                context_dir,
                context_source,
                loaded,
            )
            cfg = _ai_online_config(args)
            if not cfg["provider"]:
                print("ERROR: online-enriched advisory rendering requested but unavailable: AI_NETSIM_AI_PROVIDER not set", file=sys.stderr)
                sys.exit(2)
            if cfg["provider"] != "openai":
                print(f"ERROR: online-enriched advisory rendering requested but unavailable: unsupported provider '{cfg['provider']}'", file=sys.stderr)
                sys.exit(2)
            if not cfg["api_key"]:
                print("ERROR: online-enriched advisory rendering requested but unavailable: AI_NETSIM_AI_API_KEY/OPENAI_API_KEY not set", file=sys.stderr)
                sys.exit(2)
            model = cfg["model"] or "gpt-4.1-mini"
            ai_status, ai_output, ai_error = _ai_provider_openai(
                bundle=evidence_package,
                model=model,
                api_key=cfg["api_key"],
                base_url=cfg["base_url"],
            )
            if ai_status != "ok":
                err = ai_error or "online AI unavailable"
                print(f"ERROR: online-enriched advisory rendering requested but unavailable: {err}", file=sys.stderr)
                sys.exit(2)
            banner_lines = _build_banner(context_dir, context_source, module_name, loaded)
            fmt = str(getattr(args, "format", "text") or "text")
            if fmt == "json":
                payload = {
                    "authority": "advisory",
                    "execution_impact": "none",
                    "context_source": context_source,
                    "artifacts_dir": str(context_dir),
                    "artifacts_loaded": loaded,
                    "module": module_name,
                    "rendering_mode": _selected_rendering_mode(),
                    "question": question,
                    "model_used": model,
                    "response": ai_output,
                }
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                for line in banner_lines:
                    print(line)
                print("")
                print(f"Question: {question}")
                print(f"Summary: {str(ai_output.get('summary') or '').strip()}")

                findings = list(ai_output.get("findings") or [])
                suggested_next_tests = list(ai_output.get("suggested_next_tests") or [])

                if findings:
                    print("")
                    print("Advisory Interpretation / Likely Cause:")
                    for item in findings:
                        if isinstance(item, dict):
                            title = str(item.get("title") or "").strip()
                            evidence = str(item.get("evidence") or "").strip()
                            suggestion = str(item.get("suggestion") or "").strip()
                            if title:
                                print(f"- {title}")
                            if evidence:
                                print(f"  Evidence: {evidence}")
                            if suggestion:
                                print(f"  Advisory suggestion: {suggestion}")

                if suggested_next_tests:
                    print("")
                    print("Recommended Next Steps:")
                    for item in suggested_next_tests:
                        if isinstance(item, dict):
                            title = str(item.get("title") or "").strip()
                            why = str(item.get("why") or "").strip()
                            if title:
                                print(f"- Suggested next test: {title}")
                            if why:
                                print(f"  Why: {why}")
            return

        if question:
            _handle_one(question)
            return

        # Optional interactive mode: artifact context is locked for the session.
        banner_lines = _build_banner(context_dir, context_source, "session", loaded)
        for line in banner_lines:
            print(line)
        while True:
            try:
                q = input("> ").strip()
            except EOFError:
                break
            if not q:
                continue
            if q.lower() in ("exit", "quit"):
                break
            _handle_one(q)

    except SystemExit:
        raise
    except Exception as e:
        print(f"ERROR: Cassian Gate AI interface failure: {e!s}", file=sys.stderr)
        sys.exit(1)

def cmd_ai_coach(args) -> None:
    """
    Coach/onboarding: deterministic, static guidance (no YAML emission).
    Exit codes: 0 success, 2 usage error (none expected here).
    """
    bundle = {
        "schema_version": "1",
        **_ai_advisory_headers(),
        "command": "coach",
        "model": "v1 onboarding",
        "topics": [
            "run vs test (explore vs gate)",
            "atomic tests vs scenarios",
            "artifacts: results.json, topology.resolved.yaml, results.summary.txt",
            "negative tests and fail-fast philosophy",
        ],
        "what_to_validate_next": [
            "Steady-state reachability (ping/tcp)",
            "Control-plane convergence (wait_for_bgp)",
            "Failure choreography (interface/link down/up + revalidation)",
        ],
    }

    _ai_finalize_and_emit("coach", bundle, args)
