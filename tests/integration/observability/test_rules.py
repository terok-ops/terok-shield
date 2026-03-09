# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: rules and logs inspection (API + CLI)."""

import pytest

from terok_shield import shield_rules
from terok_shield.cli import main

from ..conftest import nft_missing, podman_missing

# ── Public API rules ─────────────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestRulesAPI:
    """Verify ``shield_rules()`` returns the applied ruleset."""

    def test_shield_rules_returns_ruleset(self, shielded_container: str) -> None:
        """``shield_rules()`` returns text containing ``terok_shield``."""
        rules = shield_rules(shielded_container)
        assert "terok_shield" in rules
        assert "allow_v4" in rules


# ── CLI rules ────────────────────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestRulesCLI:
    """Verify ``terok-shield rules`` via CLI."""

    def test_cli_rules(self, shielded_container: str, capsys: pytest.CaptureFixture) -> None:
        """``main(["rules", container])`` prints the ruleset."""
        main(["rules", shielded_container])
        captured = capsys.readouterr()
        assert "terok_shield" in captured.out


# ── CLI logs ─────────────────────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestLogsCLI:
    """Verify ``terok-shield logs`` via CLI."""

    def test_cli_logs(self, shielded_container: str, capsys: pytest.CaptureFixture) -> None:
        """``main(["logs", "--container", container])`` shows log entries."""
        # The shielded_container fixture logs a "setup" event via shield_pre_start
        main(["logs", "--container", shielded_container])
        captured = capsys.readouterr()
        # Audit log must have the setup entry from shield_pre_start
        assert "setup" in captured.out
