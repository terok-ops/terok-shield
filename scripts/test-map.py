#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Generate a Markdown test map from pytest collection.

Runs ``pytest --collect-only -q`` on ``tests/integration/`` and groups
the collected test IDs by directory, producing a Markdown table.

Can be used standalone (``python scripts/test-map.py``) or as a mkdocs
gen-files script (imported by ``docs/gen_test_map.py``).
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INTEGRATION_DIR = ROOT / "tests" / "integration"
_VENV_BIN = Path(sys.executable).parent


def collect_tests() -> list[str]:
    """Run pytest --collect-only and return the list of test node IDs."""
    result = subprocess.run(
        [str(_VENV_BIN / "pytest"), "--collect-only", "-qq", "-p", "no:tach", str(INTEGRATION_DIR)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=60,
    )
    lines = result.stdout.strip().splitlines()
    # Filter to actual test IDs (contain ::)
    return [line.strip() for line in lines if "::" in line]


def _extract_markers(test_file: Path) -> dict[str, list[str]]:
    """Extract pytest markers from a test file, keyed by class or module.

    Returns a mapping of ``ClassName`` (or ``_module``) to a list of
    marker names found on that scope.
    """
    markers: dict[str, list[str]] = defaultdict(list)
    current_class = "_module"
    if not test_file.is_file():
        return markers
    for line in test_file.read_text().splitlines():
        class_match = re.match(r"^class (\w+)", line)
        if class_match:
            current_class = class_match.group(1)
        marker_match = re.match(r"^@pytest\.mark\.(\w+)", line.strip())
        if marker_match:
            markers[current_class].append(marker_match.group(1))
    return markers


def generate_test_map(test_ids: list[str] | None = None) -> str:
    """Generate a Markdown test map grouped by directory.

    Args:
        test_ids: Optional pre-collected test IDs. If ``None``, runs
            ``pytest --collect-only`` to collect them.

    Returns:
        Markdown string with the test map.
    """
    if test_ids is None:
        test_ids = collect_tests()

    # Group by subdirectory
    groups: dict[str, list[str]] = defaultdict(list)
    for tid in test_ids:
        # tid looks like: tests/integration/blocking/test_default_deny.py::TestClass::test_method
        parts = tid.split("::")
        file_path = parts[0]
        # Extract subdirectory relative to tests/integration/
        rel = file_path.replace("tests/integration/", "")
        subdir = rel.split("/")[0] if "/" in rel else "(root)"
        groups[subdir].append(tid)

    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Integration Test Map\n\n",
        f"*Generated: {now}*\n\n",
    ]

    # Summary
    total = len(test_ids)
    lines.append(f"**{total} tests** across **{len(groups)} directories**\n\n")

    # Table per directory
    dir_order = [
        "setup",
        "launch",
        "blocking",
        "allow_deny",
        "dns",
        "observability",
        "safety",
        "cli",
    ]
    sorted_dirs = [d for d in dir_order if d in groups]
    sorted_dirs += sorted(d for d in groups if d not in dir_order)

    for subdir in sorted_dirs:
        tids = groups[subdir]

        # Read the README for this directory if it exists
        readme = INTEGRATION_DIR / subdir / "README.md"
        desc = ""
        if readme.is_file():
            readme_lines = readme.read_text().strip().splitlines()
            # Skip the heading line, take the description
            desc_lines = [ln.strip() for ln in readme_lines[1:] if ln.strip()]
            desc = " ".join(desc_lines)

        lines.append(f"## `{subdir}/`\n\n")
        if desc:
            lines.append(f"{desc}\n\n")

        lines.append("| Test | Class | Markers |\n")
        lines.append("|---|---|---|\n")

        # Collect markers per file
        marker_cache: dict[str, dict[str, list[str]]] = {}

        for tid in sorted(tids):
            parts = tid.split("::")
            file_path = parts[0]
            class_name = parts[1] if len(parts) > 2 else ""
            test_name = parts[-1]

            if file_path not in marker_cache:
                marker_cache[file_path] = _extract_markers(ROOT / file_path)
            file_markers = marker_cache[file_path]

            # Merge class + module markers
            all_markers = set(file_markers.get("_module", []))
            if class_name:
                all_markers.update(file_markers.get(class_name, []))
            # Filter to meaningful markers
            env_markers = sorted(m for m in all_markers if m.startswith("needs_"))
            marker_str = ", ".join(f"`{m}`" for m in env_markers) if env_markers else ""

            lines.append(f"| `{test_name}` | `{class_name}` | {marker_str} |\n")

        lines.append("\n")

    return "".join(lines)


if __name__ == "__main__":
    output = generate_test_map()
    # Write to docs/ if it exists, otherwise print to stdout
    docs_dir = ROOT / "docs"
    if docs_dir.is_dir():
        out_path = docs_dir / "test-map.md"
        out_path.write_text(output)
        print(f"Wrote {out_path}")
    else:
        print(output)
