# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for shared utility functions."""

import unittest

from terok_shield.util import is_ipv4

from ..testnet import TEST_IP1, TEST_NET1


class TestIsIpv4(unittest.TestCase):
    """Tests for is_ipv4."""

    def test_ipv4_address(self) -> None:
        """Detect plain IPv4 address."""
        self.assertTrue(is_ipv4(TEST_IP1))

    def test_cidr(self) -> None:
        """Detect CIDR notation."""
        self.assertTrue(is_ipv4(TEST_NET1))

    def test_domain(self) -> None:
        """Reject domain names."""
        self.assertFalse(is_ipv4("example.com"))

    def test_empty(self) -> None:
        """Reject empty string."""
        self.assertFalse(is_ipv4(""))

    def test_ipv6_rejected(self) -> None:
        """Reject IPv6 addresses."""
        self.assertFalse(is_ipv4("::1"))
