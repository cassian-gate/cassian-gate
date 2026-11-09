#!/usr/bin/env python3
"""Regenerate the capability catalogue golden, tests/fixtures/checks_catalogue.json.

When to run it: after changing a check, capability declaration, pack or command, run this script;
it refuses to write unless the release version it resolves equals `pyproject.toml`'s, and commit the
golden in the same change.

    python3 scripts/regenerate_checks_catalogue.py

The golden is written only by this script, through the same byte function as `cassian checks --json`
(`cassian_catalogue.render_json`); it is never edited by hand. Importing this module writes nothing:
only running it as a script writes the golden. Product code never imports it, `cassian checks` never
invokes it, and CI never runs it as a script.

Stage-1 gap item (d)(2), WI-6: handover v9-rev3 section 8 rule B13, section 14.2; REQ-S1D2-15, -16.
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
PYPROJECT = ROOT / "pyproject.toml"
GOLDEN_REL = "tests/fixtures/checks_catalogue.json"
GOLDEN = ROOT / GOLDEN_REL

# The pattern cassian_engine._audit_release_version() applies to pyproject.toml. It is used here
# instead of tomllib, which python3.10 lacks: the drift proof imports this module under python3.10.
VERSION_RE = r'(?m)^\s*version\s*=\s*"([^"]+)"'


def _src_on_path() -> None:
    src = str(SRC)
    if src not in sys.path:
        sys.path.insert(0, src)


def catalogue_bytes() -> bytes:
    """Return the `cassian checks --json` bytes, built as `cmd_checks` builds them (rule B01)."""
    _src_on_path()
    import cassian_catalogue
    import cassian_cli
    import cassian_engine

    catalogue = cassian_catalogue.build_catalogue(
        cassian_cli.build_parser(), release_version=cassian_engine._audit_release_version()
    )
    return cassian_catalogue.render_json(catalogue)


def declared_release_version() -> str | None:
    """Return the `version` pyproject.toml declares, read with VERSION_RE, or None if it declares none."""
    m = re.search(VERSION_RE, PYPROJECT.read_text(encoding="utf-8"))
    return m.group(1) if m else None


def release_version_guard(resolved: str | None, declared: str | None) -> None:
    """Refuse unless the release version the build resolves equals pyproject.toml's.

    On a mismatch, print both values to stderr and exit 1; the caller has written nothing.
    """
    if resolved != declared:
        print(
            f"regenerate_checks_catalogue: refused, nothing written: the release version resolved by "
            f"cassian_engine._audit_release_version() is {resolved!r}, and pyproject.toml declares "
            f"{declared!r}",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    _src_on_path()
    import cassian_engine

    release_version_guard(cassian_engine._audit_release_version(), declared_release_version())
    data = catalogue_bytes()
    with open(GOLDEN, "wb") as f:
        f.write(data)
    print(f"{hashlib.sha256(data).hexdigest()}  {GOLDEN_REL}")


if __name__ == "__main__":
    main()
