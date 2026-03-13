# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HookExecutor class."""

import json
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import state
from terok_shield.oci_hook import HookExecutor
from terok_shield.run import ExecError

from ..testnet import RFC1918_HOST, TEST_IP1, TEST_IP2
from .helpers import write_lines


@pytest.fixture
def make_executor(
    tmp_path: Path,
) -> Callable[..., tuple[HookExecutor, mock.MagicMock, mock.MagicMock, mock.MagicMock]]:
    """Create a HookExecutor plus its default mock collaborators."""

    def _make_executor(
        *,
        runner: mock.MagicMock | None = None,
        audit: mock.MagicMock | None = None,
        ruleset: mock.MagicMock | None = None,
        state_dir: Path | None = None,
    ) -> tuple[HookExecutor, mock.MagicMock, mock.MagicMock, mock.MagicMock]:
        runner = runner or mock.MagicMock()
        audit = audit or mock.MagicMock()
        ruleset = ruleset or mock.MagicMock()
        executor = HookExecutor(
            runner=runner,
            audit=audit,
            ruleset=ruleset,
            state_dir=state_dir or tmp_path,
        )
        return executor, runner, audit, ruleset

    return _make_executor


def test_hook_executor_stores_collaborators(
    tmp_path: Path,
    make_executor: Callable[
        ..., tuple[HookExecutor, mock.MagicMock, mock.MagicMock, mock.MagicMock]
    ],
) -> None:
    """Construction keeps the injected collaborators and state dir."""
    runner = mock.MagicMock()
    audit = mock.MagicMock()
    ruleset = mock.MagicMock()
    executor, _, _, _ = make_executor(
        runner=runner,
        audit=audit,
        ruleset=ruleset,
        state_dir=tmp_path,
    )
    assert executor._runner is runner
    assert executor._audit is audit
    assert executor._ruleset is ruleset
    assert executor._state_dir == tmp_path


@pytest.mark.parametrize(
    ("allowed_ips", "nft_side_effect", "add_elements", "expected_calls"),
    [
        pytest.param([], ["", "valid list output"], "", 2, id="no-pre-resolved-ips"),
        pytest.param(
            [TEST_IP1, TEST_IP2],
            ["", "", "valid list output"],
            f"add element allow_v4 {{ {TEST_IP1} }}",
            3,
            id="with-pre-resolved-ips",
        ),
    ],
)
def test_apply_successfully_applies_ruleset_and_verifies(
    tmp_path: Path,
    make_executor: Callable[
        ..., tuple[HookExecutor, mock.MagicMock, mock.MagicMock, mock.MagicMock]
    ],
    allowed_ips: list[str],
    nft_side_effect: list[str],
    add_elements: str,
    expected_calls: int,
) -> None:
    """apply() installs the hook ruleset, optional allow-set elements, and verifies."""
    if allowed_ips:
        write_lines(state.profile_allowed_path(tmp_path), allowed_ips)

    executor, runner, audit, ruleset = make_executor(state_dir=tmp_path)
    runner.nft_via_nsenter.side_effect = nft_side_effect
    ruleset.build_hook.return_value = "hook ruleset"
    ruleset.verify_hook.return_value = []
    ruleset.add_elements_dual.return_value = add_elements

    executor.apply("test-ctr", "42")

    assert runner.nft_via_nsenter.call_count == expected_calls
    details = [call.kwargs.get("detail", "") for call in audit.log_event.call_args_list]
    assert "ruleset applied" in details
    assert "verification passed" in details
    assert f"applied with {len(allowed_ips)} allowed IPs" in details


def test_apply_fails_closed_on_ruleset_apply_error(
    make_executor: Callable[
        ..., tuple[HookExecutor, mock.MagicMock, mock.MagicMock, mock.MagicMock]
    ],
) -> None:
    """apply() short-circuits when nft rejects the hook ruleset."""
    executor, runner, _, ruleset = make_executor()
    runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "permission denied")
    ruleset.build_hook.return_value = "hook"

    with pytest.raises(RuntimeError):
        executor.apply("test-ctr", "42")

    runner.nft_via_nsenter.assert_called_once()
    ruleset.verify_hook.assert_not_called()


def test_apply_fails_closed_on_verification_error(
    make_executor: Callable[
        ..., tuple[HookExecutor, mock.MagicMock, mock.MagicMock, mock.MagicMock]
    ],
) -> None:
    """apply() raises RuntimeError when verification finds ruleset errors."""
    executor, runner, _, ruleset = make_executor()
    runner.nft_via_nsenter.side_effect = ["", "bad output"]
    ruleset.build_hook.return_value = "hook"
    ruleset.verify_hook.return_value = ["policy is not drop"]

    with pytest.raises(RuntimeError, match="verification failed"):
        executor.apply("test-ctr", "42")


@pytest.mark.parametrize(
    ("profile_lines", "live_lines", "deny_lines", "expected"),
    [
        pytest.param([TEST_IP1, TEST_IP2], [], [], [TEST_IP1, TEST_IP2], id="profile-only"),
        pytest.param([TEST_IP1], [TEST_IP2], [], [TEST_IP1, TEST_IP2], id="profile-and-live"),
        pytest.param([TEST_IP1], [TEST_IP1, TEST_IP2], [], [TEST_IP1, TEST_IP2], id="deduplicates"),
        pytest.param([], [], [], [], id="missing-files"),
        pytest.param(["", TEST_IP1, ""], [], [], [TEST_IP1], id="skips-blank-lines"),
        pytest.param([TEST_IP1, TEST_IP2], [], [TEST_IP1], [TEST_IP2], id="subtracts-denied"),
    ],
)
def test_read_allowed_ips_merges_allowlists(
    tmp_path: Path,
    make_executor: Callable[
        ..., tuple[HookExecutor, mock.MagicMock, mock.MagicMock, mock.MagicMock]
    ],
    profile_lines: list[str],
    live_lines: list[str],
    deny_lines: list[str],
    expected: list[str],
) -> None:
    """_read_allowed_ips() returns the effective allowlist from state files."""
    if profile_lines:
        write_lines(state.profile_allowed_path(tmp_path), profile_lines)
    if live_lines:
        write_lines(state.live_allowed_path(tmp_path), live_lines)
    if deny_lines:
        write_lines(state.deny_path(tmp_path), deny_lines)

    executor, _, _, _ = make_executor(state_dir=tmp_path)
    assert executor._read_allowed_ips() == expected


def test_nft_exec_returns_runner_output(
    make_executor: Callable[
        ..., tuple[HookExecutor, mock.MagicMock, mock.MagicMock, mock.MagicMock]
    ],
) -> None:
    """_nft_exec() returns the runner output on success."""
    executor, runner, _, _ = make_executor()
    runner.nft_via_nsenter.return_value = "output"
    assert executor._nft_exec("test-ctr", "42", "list", "ruleset") == "output"


@pytest.mark.parametrize(
    ("action", "expected_message"),
    [
        pytest.param("", "list failed", id="default-action-label"),
        pytest.param("add-elements", "add-elements failed", id="custom-action-label"),
    ],
)
def test_nft_exec_converts_exec_error_to_runtime_error(
    make_executor: Callable[
        ..., tuple[HookExecutor, mock.MagicMock, mock.MagicMock, mock.MagicMock]
    ],
    action: str,
    expected_message: str,
) -> None:
    """_nft_exec() logs and re-raises runner failures as RuntimeError."""
    audit = mock.MagicMock()
    executor, runner, _, _ = make_executor(audit=audit)
    runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "fail")

    kwargs = {"stdin": "rules", "action": action} if action else {}
    args = () if action else ("list", "ruleset")
    with pytest.raises(RuntimeError, match=expected_message):
        executor._nft_exec("test-ctr", "42", *args, **kwargs)
    audit.log_event.assert_called()


def test_parse_oci_state_returns_container_and_pid() -> None:
    """parse_oci_state() exposes the static parser for valid OCI JSON."""
    cid, pid, annotations = HookExecutor.parse_oci_state(json.dumps({"id": "abc123", "pid": 42}))
    assert (cid, pid, annotations) == ("abc123", "42", {})


def test_parse_oci_state_rejects_invalid_json() -> None:
    """parse_oci_state() raises ValueError for malformed JSON."""
    with pytest.raises(ValueError):
        HookExecutor.parse_oci_state("not json")


def test_apply_logs_private_ranges_as_notes(
    tmp_path: Path,
    make_executor: Callable[
        ..., tuple[HookExecutor, mock.MagicMock, mock.MagicMock, mock.MagicMock]
    ],
) -> None:
    """Private-range IPs are logged as notes during apply()."""
    write_lines(state.profile_allowed_path(tmp_path), [RFC1918_HOST])

    executor, runner, audit, ruleset = make_executor(state_dir=tmp_path)
    runner.nft_via_nsenter.side_effect = ["", "", "valid"]
    ruleset.build_hook.return_value = "hook"
    ruleset.verify_hook.return_value = []
    ruleset.add_elements_dual.return_value = "add element"

    executor.apply("test-ctr", "42")

    note_calls = [call for call in audit.log_event.call_args_list if call.args[1] == "note"]
    assert any("private range" in call.kwargs.get("detail", "") for call in note_calls)


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(OSError("disk fail"), id="oserror"),
        pytest.param(UnicodeError("bad encoding"), id="unicodeerror"),
    ],
)
def test_apply_fails_closed_when_reading_cached_ips_fails(
    make_executor: Callable[
        ..., tuple[HookExecutor, mock.MagicMock, mock.MagicMock, mock.MagicMock]
    ],
    error: Exception,
) -> None:
    """Cache read failures are converted into RuntimeError before nft verification."""
    executor, runner, _, ruleset = make_executor()
    runner.nft_via_nsenter.return_value = ""
    ruleset.build_hook.return_value = "hook"

    with mock.patch.object(executor, "_read_allowed_ips", side_effect=error):
        with pytest.raises(RuntimeError):
            executor.apply("test-ctr", "42")
