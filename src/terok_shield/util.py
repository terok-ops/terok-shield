# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared utility functions."""

import ipaddress


def is_ipv4(value: str) -> bool:
    """Return True if *value* is an IPv4 address or CIDR notation.

    Uses ``ipaddress.IPv4Address`` for plain addresses and
    ``ipaddress.IPv4Network(..., strict=False)`` for CIDRs.
    """
    try:
        if "/" in value:
            ipaddress.IPv4Network(value, strict=False)
        else:
            ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False
