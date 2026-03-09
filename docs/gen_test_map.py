# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Generate the integration test map page for MkDocs.

Runs during ``mkdocs build`` via the mkdocs-gen-files plugin.
Delegates to ``scripts/test-map.py`` for the actual collection and
Markdown generation.
"""

import importlib
import sys
from pathlib import Path

import mkdocs_gen_files

# Make scripts/ importable
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

test_map_mod = importlib.import_module("test-map")

report = test_map_mod.generate_test_map()
with mkdocs_gen_files.open("test-map.md", "w") as f:
    f.write(report)
