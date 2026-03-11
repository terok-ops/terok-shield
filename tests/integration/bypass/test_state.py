# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: shield state detection with real containers.

Verifies ``shield_state()`` correctly classifies live nft rulesets
as UP, DOWN, DOWN_ALL, or INACTIVE by querying actual container
network namespaces.
"""

import uuid

import pytest

from terok_shield import ShieldState, shield_down, shield_state, shield_up

from ..conftest import nft_missing, podman_missing


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestShieldState:
    """Verify shield_state() returns correct states for live containers."""

    def test_state_up_after_setup(self, shielded_container: str) -> None:
        """A freshly shielded container reports state UP."""
        state = shield_state(shielded_container)
        assert state == ShieldState.UP

    def test_state_down_after_shield_down(self, shielded_container: str) -> None:
        """State is DOWN after shield_down() (RFC1918 protection kept)."""
        shield_down(shielded_container)
        state = shield_state(shielded_container)
        assert state == ShieldState.DOWN

    def test_state_down_all_after_shield_down_all(self, shielded_container: str) -> None:
        """State is DOWN_ALL after shield_down(allow_all=True)."""
        shield_down(shielded_container, allow_all=True)
        state = shield_state(shielded_container)
        assert state == ShieldState.DOWN_ALL

    def test_state_up_after_shield_up(self, shielded_container: str) -> None:
        """State returns to UP after shield_down() then shield_up()."""
        shield_down(shielded_container)
        assert shield_state(shielded_container) == ShieldState.DOWN

        shield_up(shielded_container)
        assert shield_state(shielded_container) == ShieldState.UP


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestShieldStateInactive:
    """Verify INACTIVE state for containers without rulesets."""

    def test_state_inactive_for_stopped_container(self) -> None:
        """A nonexistent/stopped container reports INACTIVE."""
        bogus = f"nonexistent-{uuid.uuid4().hex[:12]}"
        state = shield_state(bogus)
        assert state == ShieldState.INACTIVE

    def test_state_inactive_for_bare_container(self, container: str) -> None:
        """A running container with no shield ruleset reports INACTIVE."""
        state = shield_state(container)
        assert state == ShieldState.INACTIVE
