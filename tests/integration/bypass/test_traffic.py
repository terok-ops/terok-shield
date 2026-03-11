# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: network behavior during bypass mode.

Verifies actual traffic flows correctly when the shield is down:
all outbound traffic accepted (with logging), RFC1918 still rejected
by default, and IPv6 unconditionally dropped.
"""

import pytest

from terok_shield import shield_down, shield_rules, shield_up
from terok_shield.nft_constants import BYPASS_LOG_PREFIX, RFC1918
from tests.testnet import (
    ALLOWED_TARGET_HTTP,
    BLOCKED_TARGET_HTTP,
    IPV6_CLOUDFLARE,
)

from ..conftest import nft_missing, podman_missing
from ..helpers import assert_blocked, assert_reachable, exec_in_container as _exec


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestBypassTraffic:
    """Verify traffic behavior when shield is down."""

    def test_all_traffic_allowed_in_bypass(self, shielded_container: str) -> None:
        """Both normally-allowed and normally-blocked destinations are reachable."""
        # Verify blocked before bypass
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)

        shield_down(shielded_container)
        assert_reachable(shielded_container, ALLOWED_TARGET_HTTP)
        assert_reachable(shielded_container, BLOCKED_TARGET_HTTP)

    def test_traffic_blocked_again_after_up(self, shielded_container: str) -> None:
        """Traffic is blocked again after restoring the shield."""
        shield_down(shielded_container)
        assert_reachable(shielded_container, BLOCKED_TARGET_HTTP)

        shield_up(shielded_container)
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)

    def test_bypass_ruleset_has_log_prefix(self, shielded_container: str) -> None:
        """The bypass ruleset contains the TEROK_SHIELD_BYPASS log prefix."""
        shield_down(shielded_container)
        rules = shield_rules(shielded_container)
        assert BYPASS_LOG_PREFIX in rules

    def test_bypass_ruleset_has_accept_policy(self, shielded_container: str) -> None:
        """The bypass ruleset output chain has policy accept."""
        shield_down(shielded_container)
        rules = shield_rules(shielded_container)
        assert "policy accept" in rules


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestBypassRFC1918:
    """Verify RFC1918 protection during bypass mode."""

    def test_rfc1918_rules_present_in_default_bypass(self, shielded_container: str) -> None:
        """Default bypass (no --all) keeps RFC1918 reject rules."""
        shield_down(shielded_container)
        rules = shield_rules(shielded_container)
        for net in RFC1918:
            assert net in rules, f"RFC1918 reject rule for {net} missing in bypass"

    def test_rfc1918_rules_absent_in_allow_all_bypass(self, shielded_container: str) -> None:
        """Bypass with allow_all=True removes RFC1918 reject rules."""
        shield_down(shielded_container, allow_all=True)
        rules = shield_rules(shielded_container)
        for net in RFC1918:
            assert (
                f"ip daddr {net}" not in rules or "reject" not in rules.split(net)[1].split("\n")[0]
            ), f"RFC1918 reject rule for {net} should not be in allow_all bypass"

    def test_rfc1918_reject_is_fast_in_bypass(self, shielded_container: str) -> None:
        """RFC1918 reject in bypass mode is immediate, not a silent drop.

        Since we can't route to real RFC1918 addresses from a rootless
        container, we verify structurally that reject rules are present
        (which guarantees ICMP admin-prohibited responses).
        """
        shield_down(shielded_container)
        rules = shield_rules(shielded_container)
        assert "admin-prohibited" in rules


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestBypassIPv6:
    """Verify IPv6 is still dropped in bypass mode."""

    def test_ipv6_dropped_in_bypass(self, shielded_container: str) -> None:
        """IPv6 traffic is unconditionally dropped even in bypass mode."""
        shield_down(shielded_container)

        # Structural check
        rules = shield_rules(shielded_container)
        assert "nfproto ipv6 drop" in rules

        # Functional check (skip if IPv6 not available pre-firewall)
        pre = _exec(shielded_container, "ping", "-6", "-c1", "-W2", IPV6_CLOUDFLARE, timeout=5)
        if pre.returncode != 0:
            pytest.skip("IPv6 not available — functional check would be false positive")
        # Re-apply bypass after the pre-check (state may have changed)
        shield_down(shielded_container)
        post = _exec(shielded_container, "ping", "-6", "-c1", "-W2", IPV6_CLOUDFLARE, timeout=5)
        assert post.returncode != 0, "IPv6 should be dropped in bypass mode"
