# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Shield facade class (__init__.py)."""

from collections.abc import Callable, Iterator
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import Shield, ShieldConfig, ShieldState

from ..testnet import TEST_DOMAIN, TEST_IP1, TEST_IP2


@pytest.fixture
def make_shield(make_config: Callable[..., ShieldConfig]) -> Callable[..., Shield]:
    """Create a ``Shield`` with injected mocks while bypassing ``_create_mode``."""

    def _make_shield(
        config: ShieldConfig | None = None,
        *,
        mode: mock.MagicMock | None = None,
        audit: mock.MagicMock | None = None,
        dns: mock.MagicMock | None = None,
        profiles: mock.MagicMock | None = None,
        ruleset: mock.MagicMock | None = None,
    ) -> Shield:
        shield = Shield.__new__(Shield)
        shield.config = config or make_config()
        shield.runner = mock.MagicMock()
        shield.audit = audit or mock.MagicMock()
        shield.dns = dns or mock.MagicMock()
        shield.profiles = profiles or mock.MagicMock()
        shield.ruleset = ruleset or mock.MagicMock()
        shield._mode = mode or mock.MagicMock()
        return shield

    return _make_shield


def test_shield_default_collaborators(tmp_path: Path) -> None:
    """Shield creates default collaborators when none are injected."""
    shield = Shield(ShieldConfig(state_dir=tmp_path))
    assert shield.runner is not None
    assert shield.audit is not None
    assert shield.dns is not None
    assert shield.profiles is not None
    assert shield.ruleset is not None


def test_shield_uses_injected_collaborators(tmp_path: Path) -> None:
    """Shield keeps explicitly injected collaborators."""
    runner = mock.MagicMock()
    audit = mock.MagicMock()
    dns = mock.MagicMock()
    profiles = mock.MagicMock()
    ruleset = mock.MagicMock()

    shield = Shield(
        ShieldConfig(state_dir=tmp_path),
        runner=runner,
        audit=audit,
        dns=dns,
        profiles=profiles,
        ruleset=ruleset,
    )

    assert shield.runner is runner
    assert shield.audit is audit
    assert shield.dns is dns
    assert shield.profiles is profiles
    assert shield.ruleset is ruleset


def test_create_mode_rejects_unsupported_value(tmp_path: Path) -> None:
    """_create_mode raises ValueError for unsupported modes."""
    shield = Shield.__new__(Shield)
    shield.config = ShieldConfig(state_dir=tmp_path)
    shield.runner = mock.MagicMock()
    shield.audit = mock.MagicMock()
    shield.dns = mock.MagicMock()
    shield.profiles = mock.MagicMock()
    shield.ruleset = mock.MagicMock()

    fake_mode = mock.MagicMock()
    fake_mode.__eq__ = lambda self, other: False
    with pytest.raises(ValueError):
        shield._create_mode(fake_mode)


def test_status_returns_mode_profiles_and_audit(make_shield: Callable[..., Shield]) -> None:
    """status() reports the facade configuration and available profiles."""
    profiles = mock.MagicMock()
    profiles.list_profiles.return_value = ["base", "dev-standard"]
    result = make_shield(profiles=profiles, audit=mock.MagicMock()).status()
    assert result == {
        "mode": "hook",
        "profiles": ["base", "dev-standard"],
        "audit_enabled": True,
    }


def test_pre_start_dispatches_and_logs(make_shield: Callable[..., Shield]) -> None:
    """pre_start() delegates to the backend and logs the chosen profiles."""
    mode = mock.MagicMock()
    mode.pre_start.return_value = ["--network", "pasta:"]
    audit = mock.MagicMock()

    result = make_shield(mode=mode, audit=audit).pre_start("test-ctr", ["dev-standard"])

    mode.pre_start.assert_called_once_with("test-ctr", ["dev-standard"])
    assert result == ["--network", "pasta:"]
    audit.log_event.assert_called_once_with("test-ctr", "setup", detail="profiles=dev-standard")


def test_pre_start_uses_default_profiles(
    make_shield: Callable[..., Shield],
    make_config: Callable[..., ShieldConfig],
) -> None:
    """pre_start() falls back to config.default_profiles when profiles is None."""
    mode = mock.MagicMock()
    mode.pre_start.return_value = []
    shield = make_shield(
        config=make_config(default_profiles=("base",)), mode=mode, audit=mock.MagicMock()
    )

    shield.pre_start("test-ctr")
    mode.pre_start.assert_called_once_with("test-ctr", ["base"])


@pytest.mark.parametrize(
    ("method", "target", "resolver_method", "backend_method", "expected"),
    [
        pytest.param("allow", TEST_IP1, None, "allow_ip", [TEST_IP1], id="allow-ip"),
        pytest.param("deny", TEST_IP1, None, "deny_ip", [TEST_IP1], id="deny-ip"),
        pytest.param(
            "allow",
            TEST_DOMAIN,
            "resolve_domains",
            "allow_ip",
            [TEST_IP1, TEST_IP2],
            id="allow-domain",
        ),
        pytest.param(
            "deny",
            TEST_DOMAIN,
            "resolve_domains",
            "deny_ip",
            [TEST_IP1, TEST_IP2],
            id="deny-domain",
        ),
    ],
)
def test_allow_and_deny_resolve_targets_and_delegate(
    make_shield: Callable[..., Shield],
    method: str,
    target: str,
    resolver_method: str | None,
    backend_method: str,
    expected: list[str],
) -> None:
    """allow()/deny() either use the target directly or resolve domains first."""
    mode = mock.MagicMock()
    dns = mock.MagicMock()
    dns.resolve_domains.return_value = [TEST_IP1, TEST_IP2]
    audit = mock.MagicMock()

    shield = make_shield(mode=mode, dns=dns, audit=audit)
    result = getattr(shield, method)("test-ctr", target)

    if resolver_method is None:
        dns.resolve_domains.assert_not_called()
    else:
        getattr(dns, resolver_method).assert_called_once_with([target])
    assert getattr(mode, backend_method).call_args_list == [
        mock.call("test-ctr", ip) for ip in expected
    ]
    assert result == expected
    assert audit.log_event.call_count == len(expected)


@pytest.mark.parametrize(
    ("method", "backend_method", "target"),
    [
        pytest.param("allow", "allow_ip", TEST_IP1, id="allow"),
        pytest.param("deny", "deny_ip", TEST_IP1, id="deny"),
    ],
)
def test_allow_and_deny_swallow_backend_exceptions(
    make_shield: Callable[..., Shield],
    method: str,
    backend_method: str,
    target: str,
) -> None:
    """allow()/deny() are best-effort when backend IP operations fail."""
    mode = mock.MagicMock()
    getattr(mode, backend_method).side_effect = RuntimeError("nft failed")
    result = getattr(make_shield(mode=mode, audit=mock.MagicMock()), method)("test-ctr", target)
    assert result == []


def test_rules_delegates_to_mode(make_shield: Callable[..., Shield]) -> None:
    """rules() returns the backend ruleset text."""
    mode = mock.MagicMock()
    mode.list_rules.return_value = "table inet terok_shield {}"
    assert "terok_shield" in make_shield(mode=mode).rules("test-ctr")
    mode.list_rules.assert_called_once_with("test-ctr")


@pytest.mark.parametrize(
    ("allow_all", "expected_detail"),
    [
        pytest.param(False, None, id="default"),
        pytest.param(True, "allow_all=True", id="allow-all"),
    ],
)
def test_down_delegates_and_logs(
    make_shield: Callable[..., Shield],
    allow_all: bool,
    expected_detail: str | None,
) -> None:
    """down() delegates to the backend and records the right audit detail."""
    mode = mock.MagicMock()
    audit = mock.MagicMock()
    make_shield(mode=mode, audit=audit).down("test-ctr", allow_all=allow_all)
    mode.shield_down.assert_called_once_with("test-ctr", allow_all=allow_all)
    audit.log_event.assert_called_once_with("test-ctr", "shield_down", detail=expected_detail)


def test_up_delegates_and_logs(make_shield: Callable[..., Shield]) -> None:
    """up() delegates to the backend and logs the transition."""
    mode = mock.MagicMock()
    audit = mock.MagicMock()
    make_shield(mode=mode, audit=audit).up("test-ctr")
    mode.shield_up.assert_called_once_with("test-ctr")
    audit.log_event.assert_called_once_with("test-ctr", "shield_up")


def test_state_delegates_to_mode(make_shield: Callable[..., Shield]) -> None:
    """state() returns the backend shield state."""
    mode = mock.MagicMock()
    mode.shield_state.return_value = ShieldState.UP
    assert make_shield(mode=mode).state("test-ctr") == ShieldState.UP


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        pytest.param({}, "table inet terok_shield { policy drop }", id="default"),
        pytest.param({"down": True, "allow_all": True}, "bypass", id="down-bypass"),
    ],
)
def test_preview_delegates_to_mode(
    make_shield: Callable[..., Shield],
    kwargs: dict[str, bool],
    expected: str,
) -> None:
    """preview() passes through the requested preview mode."""
    mode = mock.MagicMock()
    mode.preview.return_value = expected
    shield = make_shield(mode=mode)
    assert shield.preview(**kwargs) == expected
    mode.preview.assert_called_once_with(
        down=kwargs.get("down", False), allow_all=kwargs.get("allow_all", False)
    )


def test_resolve_composes_profiles_and_caches_dns(make_shield: Callable[..., Shield]) -> None:
    """resolve() composes profile entries and passes them to the DNS cache."""
    profiles = mock.MagicMock()
    profiles.compose_profiles.return_value = [TEST_DOMAIN]
    dns = mock.MagicMock()
    dns.resolve_and_cache.return_value = [TEST_IP1]

    result = make_shield(profiles=profiles, dns=dns).resolve(["dev-standard"])

    profiles.compose_profiles.assert_called_once_with(["dev-standard"])
    dns.resolve_and_cache.assert_called_once()
    assert result == [TEST_IP1]


def test_resolve_returns_empty_for_empty_profiles(make_shield: Callable[..., Shield]) -> None:
    """resolve() short-circuits when composed profiles contain no entries."""
    profiles = mock.MagicMock()
    profiles.compose_profiles.return_value = []
    assert make_shield(profiles=profiles).resolve(["empty"]) == []


@pytest.mark.parametrize(
    ("force", "expected_max_age"),
    [
        pytest.param(False, 3600, id="default-cache"),
        pytest.param(True, 0, id="force-refresh"),
    ],
)
def test_resolve_passes_cache_age(
    make_shield: Callable[..., Shield],
    force: bool,
    expected_max_age: int,
) -> None:
    """resolve() adjusts cache freshness based on the force flag."""
    profiles = mock.MagicMock()
    profiles.compose_profiles.return_value = [TEST_DOMAIN]
    dns = mock.MagicMock()
    dns.resolve_and_cache.return_value = [TEST_IP1]

    make_shield(profiles=profiles, dns=dns).resolve(["dev-standard"], force=force)
    assert dns.resolve_and_cache.call_args.kwargs["max_age"] == expected_max_age


def test_resolve_uses_default_profiles(
    make_shield: Callable[..., Shield],
    make_config: Callable[..., ShieldConfig],
) -> None:
    """resolve() falls back to config.default_profiles when profiles is None."""
    profiles = mock.MagicMock()
    profiles.compose_profiles.return_value = []
    shield = make_shield(config=make_config(default_profiles=("base",)), profiles=profiles)
    shield.resolve()
    profiles.compose_profiles.assert_called_once_with(["base"])


@pytest.mark.parametrize(
    ("method", "attr", "return_value", "args"),
    [
        pytest.param("profiles_list", "profiles", ["base", "dev"], (), id="profiles-list"),
        pytest.param(
            "compose_profiles",
            "profiles",
            [TEST_DOMAIN],
            (["dev-standard"],),
            id="compose-profiles",
        ),
    ],
)
def test_simple_profile_delegations(
    make_shield: Callable[..., Shield],
    method: str,
    attr: str,
    return_value: list[str],
    args: tuple[list[str], ...],
) -> None:
    """Small profile-related helpers delegate directly to the collaborator."""
    profiles = mock.MagicMock()
    if method == "profiles_list":
        profiles.list_profiles.return_value = return_value
    else:
        profiles.compose_profiles.return_value = return_value
    shield = make_shield(profiles=profiles)
    assert getattr(shield, method)(*args) == return_value


def test_tail_log_delegates_to_audit(make_shield: Callable[..., Shield]) -> None:
    """tail_log() delegates to audit.tail_log()."""
    audit = mock.MagicMock()
    audit.tail_log.return_value = iter([{"action": "setup"}])
    shield = make_shield(audit=audit)
    result = shield.tail_log(10)
    audit.tail_log.assert_called_once_with(10)
    assert isinstance(result, Iterator)
