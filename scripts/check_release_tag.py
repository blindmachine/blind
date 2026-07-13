#!/usr/bin/env python3
"""Require a release tag to match the reviewed package version exactly."""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    tag = os.environ.get("GITHUB_REF_NAME", "")
    ref_type = os.environ.get("GITHUB_REF_TYPE", "")
    expected = f"v{project['version']}"
    if ref_type != "tag" or tag != expected:
        raise SystemExit(f"release ref must be the exact tag {expected}; received {ref_type}:{tag}")
    print(f"release tag verified: {tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
