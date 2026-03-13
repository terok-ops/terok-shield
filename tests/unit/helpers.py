# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared helper utilities for unit tests."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


def write_lines(path: Path, lines: Sequence[str]) -> Path:
    """Write non-empty *lines* to *path* with a trailing newline when needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines)
    path.write_text(f"{content}\n" if content else "")
    return path


def write_jsonl(path: Path, entries: Sequence[Mapping[str, Any] | str]) -> Path:
    """Write JSONL *entries* to *path* and return the written path."""
    rendered = [json.dumps(entry) if isinstance(entry, Mapping) else entry for entry in entries]
    return write_lines(path, rendered)
