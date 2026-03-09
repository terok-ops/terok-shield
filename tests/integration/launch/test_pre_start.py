# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: shield_pre_start and firewall application."""

from pathlib import Path

import pytest

from terok_shield import ShieldConfig, shield_pre_start, shield_setup

from ..conftest import nft_missing, podman_missing
from ..helpers import assert_ruleset_applied

# ── shield_pre_start ─────────────────────────────────────


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestShieldPreStart:
    """Verify ``shield_pre_start()`` returns correct podman args."""

    def test_pre_start_returns_podman_args(self, shield_env: Path) -> None:
        """Returned args contain ``--hooks-dir``, ``--annotation``, ``--cap-drop``."""
        cfg = ShieldConfig()
        shield_setup(config=cfg)
        args = shield_pre_start("test-container", config=cfg)

        assert "--hooks-dir" in args
        assert "--annotation" in args
        assert "--cap-drop" in args
        assert "--security-opt" in args

    def test_pre_start_without_setup_raises(self, shield_env: Path) -> None:
        """Calling ``shield_pre_start()`` before setup raises ``RuntimeError``."""
        cfg = ShieldConfig()
        with pytest.raises(RuntimeError, match="hook not installed"):
            shield_pre_start("test-container", config=cfg)

    @pytest.mark.needs_internet
    def test_pre_start_resolves_dns(self, shield_env: Path) -> None:
        """The resolved cache file is created after ``shield_pre_start()``."""
        cfg = ShieldConfig()
        shield_setup(config=cfg)
        shield_pre_start("dns-test-ctr", config=cfg)

        resolved_dir = shield_env / "resolved"
        assert resolved_dir.is_dir()
        cache_files = list(resolved_dir.iterdir())
        assert len(cache_files) > 0, "At least one resolved cache file should be created"


# ── Firewall applied via public API lifecycle ────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestFirewallApplied:
    """Verify firewall rules are applied after the public API lifecycle."""

    def test_firewall_applied_via_hook(self, shielded_container: str) -> None:
        """A container started via the public API has firewall rules applied."""
        assert_ruleset_applied(shielded_container)
