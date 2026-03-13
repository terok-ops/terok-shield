# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HookMode class."""

import json
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import state
from terok_shield.config import (
    ANNOTATION_AUDIT_ENABLED_KEY,
    ANNOTATION_STATE_DIR_KEY,
    ShieldConfig,
    ShieldState,
)
from terok_shield.mode_hook import HookMode, install_hooks
from terok_shield.nft import bypass_ruleset, hook_ruleset
from terok_shield.run import ExecError

from ..testfs import BIN_DIR_NAME, HOOK_ENTRYPOINT_NAME, HOOKS_DIR_NAME
from ..testnet import IPV6_CLOUDFLARE, TEST_DOMAIN, TEST_IP1, TEST_IP2
from .helpers import write_lines


@pytest.fixture
def make_hook_mode(
    make_config: Callable[..., ShieldConfig],
) -> Callable[..., HookMode]:
    """Create a ``HookMode`` with mock collaborators."""

    def _make_hook_mode(
        config: ShieldConfig | None = None,
        *,
        runner: mock.MagicMock | None = None,
        audit: mock.MagicMock | None = None,
        dns: mock.MagicMock | None = None,
        profiles: mock.MagicMock | None = None,
        ruleset: mock.MagicMock | None = None,
    ) -> HookMode:
        return HookMode(
            config=config or make_config(),
            runner=runner or mock.MagicMock(),
            audit=audit or mock.MagicMock(),
            dns=dns or mock.MagicMock(),
            profiles=profiles or mock.MagicMock(),
            ruleset=ruleset or mock.MagicMock(),
        )

    return _make_hook_mode


def _annotation_value(args: list[str], key: str) -> str:
    """Extract an annotation value from the podman args returned by pre_start()."""
    prefix = f"{key}="
    for index, arg in enumerate(args[:-1]):
        if arg == "--annotation" and args[index + 1].startswith(prefix):
            return args[index + 1][len(prefix) :]
    raise AssertionError(f"annotation not found: {key}")


def test_hook_mode_stores_collaborators(
    make_hook_mode: Callable[..., HookMode],
    make_config: Callable[..., ShieldConfig],
) -> None:
    """Construction keeps the injected collaborators and config."""
    config = make_config()
    runner = mock.MagicMock()
    audit = mock.MagicMock()
    dns = mock.MagicMock()
    profiles = mock.MagicMock()
    ruleset = mock.MagicMock()

    mode = make_hook_mode(
        config=config,
        runner=runner,
        audit=audit,
        dns=dns,
        profiles=profiles,
        ruleset=ruleset,
    )

    assert mode._config is config
    assert mode._runner is runner
    assert mode._audit is audit
    assert mode._dns is dns
    assert mode._profiles is profiles
    assert mode._ruleset is ruleset


@mock.patch("os.geteuid", return_value=1000)
def test_pre_start_uses_pasta_for_rootless_mode(
    _geteuid: mock.Mock,
    make_hook_mode: Callable[..., HookMode],
    make_config: Callable[..., ShieldConfig],
) -> None:
    """pre_start() uses pasta and loopback flags in rootless mode."""
    runner = mock.MagicMock()
    runner.run.return_value = json.dumps({"host": {"rootlessNetworkCmd": "pasta"}})
    profiles = mock.MagicMock()
    profiles.compose_profiles.return_value = [TEST_DOMAIN]

    args = make_hook_mode(
        config=make_config(loopback_ports=(8080,)),
        runner=runner,
        profiles=profiles,
        dns=mock.MagicMock(),
    ).pre_start("test", ["dev-standard"])

    network_arg = args[args.index("--network") + 1]
    assert network_arg.startswith("pasta:")
    assert "-T,8080" in network_arg


def test_pre_start_installs_hooks_and_creates_state_dirs(
    make_hook_mode: Callable[..., HookMode],
    make_config: Callable[..., ShieldConfig],
) -> None:
    """pre_start() installs OCI hook files and state directories."""
    config = make_config()
    profiles = mock.MagicMock()
    profiles.compose_profiles.return_value = []

    with mock.patch("os.geteuid", return_value=0):
        make_hook_mode(config=config, profiles=profiles, dns=mock.MagicMock()).pre_start(
            "test",
            ["dev-standard"],
        )

    assert state.hooks_dir(config.state_dir).is_dir()
    assert state.hook_entrypoint(config.state_dir).is_file()


@pytest.mark.parametrize(
    ("config_kwargs", "annotation_key", "expected_value"),
    [
        pytest.param(
            {}, ANNOTATION_STATE_DIR_KEY, lambda cfg: str(cfg.state_dir.resolve()), id="state-dir"
        ),
        pytest.param(
            {"audit_enabled": False},
            ANNOTATION_AUDIT_ENABLED_KEY,
            lambda _cfg: "false",
            id="audit-enabled",
        ),
    ],
)
def test_pre_start_includes_expected_annotations(
    make_hook_mode: Callable[..., HookMode],
    make_config: Callable[..., ShieldConfig],
    config_kwargs: dict[str, object],
    annotation_key: str,
    expected_value: Callable[[ShieldConfig], str],
) -> None:
    """pre_start() includes the expected state and audit annotations."""
    config = make_config(**config_kwargs)
    profiles = mock.MagicMock()
    profiles.compose_profiles.return_value = []

    with mock.patch("os.geteuid", return_value=0):
        args = make_hook_mode(config=config, profiles=profiles, dns=mock.MagicMock()).pre_start(
            "test",
            ["dev-standard"],
        )

    assert _annotation_value(args, annotation_key) == expected_value(config)


@pytest.mark.parametrize(
    ("method", "ip", "expected_action", "expected_set"),
    [
        pytest.param("allow_ip", TEST_IP1, "add", "allow_v4", id="allow-ipv4"),
        pytest.param("allow_ip", IPV6_CLOUDFLARE, "add", "allow_v6", id="allow-ipv6"),
        pytest.param("deny_ip", TEST_IP1, "delete", "allow_v4", id="deny-ipv4"),
    ],
)
def test_allow_and_deny_use_expected_nft_set(
    make_hook_mode: Callable[..., HookMode],
    method: str,
    ip: str,
    expected_action: str,
    expected_set: str,
) -> None:
    """allow_ip()/deny_ip() target the correct nft set for each address family."""
    runner = mock.MagicMock()
    ruleset = mock.MagicMock()
    ruleset.safe_ip.return_value = ip
    mode = make_hook_mode(runner=runner, ruleset=ruleset)

    getattr(mode, method)("test-ctr", ip)

    nft_args = runner.nft_via_nsenter.call_args.args
    assert expected_action in nft_args
    assert expected_set in nft_args


def test_allow_persists_and_deduplicates_live_allowed(
    make_hook_mode: Callable[..., HookMode],
    make_config: Callable[..., ShieldConfig],
) -> None:
    """allow_ip() persists to live.allowed without duplicate lines."""
    config = make_config()
    runner = mock.MagicMock()
    ruleset = mock.MagicMock()
    ruleset.safe_ip.return_value = TEST_IP1
    mode = make_hook_mode(config=config, runner=runner, ruleset=ruleset)

    mode.allow_ip("test-ctr", TEST_IP1)
    mode.allow_ip("test-ctr", TEST_IP1)

    lines = state.live_allowed_path(config.state_dir).read_text().splitlines()
    assert lines.count(TEST_IP1) == 1


@pytest.mark.parametrize(
    ("profile_lines", "live_lines", "expect_deny_file", "nft_side_effect"),
    [
        pytest.param([TEST_IP1], [], True, None, id="profile-ip-persists-to-deny-list"),
        pytest.param([], [TEST_IP1], False, None, id="live-only-no-deny-list"),
        pytest.param(
            [TEST_IP1],
            [TEST_IP1],
            True,
            ExecError(["nft"], 1, "not in set"),
            id="nft-error-still-persists",
        ),
    ],
)
def test_deny_updates_state_files(
    make_hook_mode: Callable[..., HookMode],
    make_config: Callable[..., ShieldConfig],
    profile_lines: list[str],
    live_lines: list[str],
    expect_deny_file: bool,
    nft_side_effect: ExecError | None,
) -> None:
    """deny_ip() removes live entries and optionally persists a deny.list record."""
    config = make_config()
    if profile_lines:
        write_lines(state.profile_allowed_path(config.state_dir), profile_lines)
    if live_lines:
        write_lines(state.live_allowed_path(config.state_dir), live_lines)

    runner = mock.MagicMock()
    runner.nft_via_nsenter.side_effect = nft_side_effect
    ruleset = mock.MagicMock()
    ruleset.safe_ip.return_value = TEST_IP1
    mode = make_hook_mode(config=config, runner=runner, ruleset=ruleset)

    mode.deny_ip("test-ctr", TEST_IP1)

    live_path = state.live_allowed_path(config.state_dir)
    live_content = live_path.read_text().splitlines() if live_path.exists() else []
    assert TEST_IP1 not in live_content

    deny_file = state.deny_path(config.state_dir)
    assert deny_file.is_file() is expect_deny_file
    if expect_deny_file:
        assert TEST_IP1 in deny_file.read_text()


def test_allow_after_deny_clears_deny_list(
    make_hook_mode: Callable[..., HookMode],
    make_config: Callable[..., ShieldConfig],
) -> None:
    """allow_ip() removes the IP from deny.list when re-allowing it."""
    config = make_config()
    write_lines(state.deny_path(config.state_dir), [TEST_IP1, TEST_IP2])

    ruleset = mock.MagicMock()
    ruleset.safe_ip.return_value = TEST_IP1
    mode = make_hook_mode(config=config, runner=mock.MagicMock(), ruleset=ruleset)

    mode.allow_ip("test-ctr", TEST_IP1)
    denied = state.read_denied_ips(config.state_dir)
    assert TEST_IP1 not in denied
    assert TEST_IP2 in denied


def test_list_rules_returns_runner_output(make_hook_mode: Callable[..., HookMode]) -> None:
    """list_rules() returns the nft ruleset text on success."""
    runner = mock.MagicMock()
    runner.nft_via_nsenter.return_value = "table inet terok_shield {}"
    assert "terok_shield" in make_hook_mode(runner=runner).list_rules("test-ctr")


def test_list_rules_returns_empty_on_exec_error(
    make_hook_mode: Callable[..., HookMode],
) -> None:
    """list_rules() tolerates ExecError and returns an empty string."""
    runner = mock.MagicMock()
    runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "error")
    assert make_hook_mode(runner=runner).list_rules("test-ctr") == ""


@pytest.mark.parametrize(
    ("allow_all", "verify_errors", "expected_message"),
    [
        pytest.param(False, [], None, id="success"),
        pytest.param(
            False, ["error: missing policy"], "verification failed", id="verification-failure"
        ),
    ],
)
def test_shield_down_builds_bypass_ruleset(
    make_hook_mode: Callable[..., HookMode],
    allow_all: bool,
    verify_errors: list[str],
    expected_message: str | None,
) -> None:
    """shield_down() applies bypass mode and verifies the resulting ruleset."""
    runner = mock.MagicMock()
    runner.nft_via_nsenter.side_effect = ["", "bad output" if verify_errors else "valid output"]
    ruleset = mock.MagicMock()
    ruleset.build_bypass.return_value = "bypass ruleset"
    ruleset.verify_bypass.return_value = verify_errors
    mode = make_hook_mode(runner=runner, ruleset=ruleset)

    if expected_message is None:
        mode.shield_down("test-ctr", allow_all=allow_all)
        assert runner.nft_via_nsenter.call_count == 2
        ruleset.build_bypass.assert_called_once_with(allow_all=allow_all)
    else:
        with pytest.raises(RuntimeError, match=expected_message):
            mode.shield_down("test-ctr", allow_all=allow_all)


@pytest.mark.parametrize(
    ("allowed_ips", "verify_errors", "expected_calls"),
    [
        pytest.param([], [], 2, id="no-cached-ips"),
        pytest.param([TEST_IP1], [], 3, id="readds-cached-ips"),
        pytest.param([], ["error"], 2, id="verification-failure"),
    ],
)
def test_shield_up_reapplies_hook_ruleset(
    make_hook_mode: Callable[..., HookMode],
    make_config: Callable[..., ShieldConfig],
    allowed_ips: list[str],
    verify_errors: list[str],
    expected_calls: int,
) -> None:
    """shield_up() restores hook mode, optionally re-adding effective IPs."""
    config = make_config()
    if allowed_ips:
        write_lines(state.profile_allowed_path(config.state_dir), allowed_ips)

    runner = mock.MagicMock()
    runner.nft_via_nsenter.side_effect = [""] * (expected_calls - 1) + [
        "valid output" if not verify_errors else "bad output"
    ]
    ruleset = mock.MagicMock()
    ruleset.build_hook.return_value = "hook ruleset"
    ruleset.verify_hook.return_value = verify_errors
    ruleset.add_elements_dual.return_value = f"add element {TEST_IP1}" if allowed_ips else ""
    mode = make_hook_mode(config=config, runner=runner, ruleset=ruleset)

    if verify_errors:
        with pytest.raises(RuntimeError):
            mode.shield_up("test-ctr")
    else:
        mode.shield_up("test-ctr")
    assert runner.nft_via_nsenter.call_count == expected_calls


@pytest.mark.parametrize(
    ("nft_output", "verify_bypass", "verify_hook", "expected"),
    [
        pytest.param("", None, None, ShieldState.INACTIVE, id="inactive"),
        pytest.param(hook_ruleset(), ["not bypass"], [], ShieldState.UP, id="up"),
        pytest.param(bypass_ruleset(), [], None, ShieldState.DOWN, id="down"),
        pytest.param(
            "random nft stuff", ["not bypass"], ["not hook"], ShieldState.ERROR, id="error"
        ),
    ],
)
def test_shield_state_classifies_rulesets(
    make_hook_mode: Callable[..., HookMode],
    nft_output: str,
    verify_bypass: list[str] | None,
    verify_hook: list[str] | None,
    expected: ShieldState,
) -> None:
    """shield_state() distinguishes inactive, hook, bypass, and invalid rulesets."""
    runner = mock.MagicMock()
    runner.nft_via_nsenter.return_value = nft_output
    ruleset = mock.MagicMock()
    if verify_bypass is not None:
        ruleset.verify_bypass.return_value = verify_bypass
    if verify_hook is not None:
        ruleset.verify_hook.return_value = verify_hook
    assert make_hook_mode(runner=runner, ruleset=ruleset).shield_state("test") == expected


@pytest.mark.parametrize(
    ("kwargs", "expected", "method_name"),
    [
        pytest.param({}, "hook ruleset", "build_hook", id="default-hook-preview"),
        pytest.param(
            {"down": True, "allow_all": True}, "bypass ruleset", "build_bypass", id="bypass-preview"
        ),
    ],
)
def test_preview_delegates_to_ruleset_builder(
    make_hook_mode: Callable[..., HookMode],
    kwargs: dict[str, bool],
    expected: str,
    method_name: str,
) -> None:
    """preview() delegates to the right ruleset builder entry point."""
    ruleset = mock.MagicMock()
    getattr(ruleset, method_name).return_value = expected
    mode = make_hook_mode(ruleset=ruleset)
    assert mode.preview(**kwargs) == expected


@pytest.mark.parametrize(
    ("runner_output", "expected"),
    [
        pytest.param(json.dumps({"host": {"rootlessNetworkCmd": "pasta"}}), "pasta", id="pasta"),
        pytest.param(
            json.dumps({"host": {"rootlessNetworkCmd": "slirp4netns"}}),
            "slirp4netns",
            id="slirp4netns",
        ),
        pytest.param("", "pasta", id="empty-output-fallback"),
        pytest.param("not json", "pasta", id="invalid-json-fallback"),
    ],
)
def test_detect_rootless_network_mode(
    make_hook_mode: Callable[..., HookMode],
    runner_output: str,
    expected: str,
) -> None:
    """_detect_rootless_network_mode() prefers podman info but fails safe to pasta."""
    runner = mock.MagicMock()
    runner.run.return_value = runner_output
    assert make_hook_mode(runner=runner)._detect_rootless_network_mode() == expected


def test_install_hooks_creates_entrypoint_and_hook_jsons(tmp_path: Path) -> None:
    """install_hooks() writes the executable entrypoint plus both hook descriptors."""
    hook_entrypoint = tmp_path / BIN_DIR_NAME / HOOK_ENTRYPOINT_NAME
    hooks_dir = tmp_path / HOOKS_DIR_NAME

    install_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)

    assert hook_entrypoint.exists()
    assert hook_entrypoint.stat().st_mode & 0o100
    assert hook_entrypoint.read_text().startswith("#!/bin/sh\n")
    assert "terok_shield.oci_hook" in hook_entrypoint.read_text()

    for stage_name in ("createRuntime", "poststop"):
        hook_file = hooks_dir / f"terok-shield-{stage_name}.json"
        assert hook_file.exists()
        data = json.loads(hook_file.read_text())
        assert data["version"] == "1.0.0"
        assert data["hook"]["path"] == str(hook_entrypoint)
        assert stage_name in data["stages"]
