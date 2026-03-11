# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""nftables ruleset generation.

+=====================================================+
|  SECURITY BOUNDARY -- read this file first.         |
|                                                     |
|  Every nftables ruleset is generated here.          |
|  All inputs are validated before interpolation.     |
|  Only stdlib + nft_constants.py imports allowed.    |
+=====================================================+
"""

import ipaddress
import re
import textwrap

from .nft_constants import (
    BYPASS_LOG_PREFIX,
    IPV6_PRIVATE,
    NFT_TABLE,
    PASTA_DNS,
    RFC1918,
)

# ── Validation ───────────────────────────────────────────


def _safe_port(port: int) -> int:
    """Validate a port number.  Raises ValueError for out-of-range or non-int."""
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError(f"Port must be an integer, got {type(port).__name__}")
    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")
    return port


def safe_ip(value: str) -> str:
    """Validate an IPv4 or IPv6 address or CIDR notation.

    Prevents nft command injection by ensuring the value is a valid
    IP address or network.  Raises ValueError on invalid input.
    """
    v = value.strip()
    try:
        if "/" in v:
            ipaddress.ip_network(v, strict=False)
        else:
            ipaddress.ip_address(v)
    except ValueError as e:
        raise ValueError(f"Invalid IP/CIDR: {v!r}") from e
    return v


def _is_v4(value: str) -> bool:
    """Return True if a validated IP string is IPv4."""
    try:
        if "/" in value:
            return isinstance(ipaddress.ip_network(value, strict=False), ipaddress.IPv4Network)
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


# ── Rulesets ─────────────────────────────────────────────


def _rfc1918_rules(prefix: str = "TEROK_SHIELD_RFC1918") -> str:
    """Generate RFC1918 reject rules.  Used by both modes."""
    return "\n".join(
        f'        ip daddr {net} log prefix "{prefix}: " reject with icmp type admin-prohibited'
        for net in RFC1918
    )


def _ipv6_private_rules(prefix: str = "TEROK_SHIELD_PRIVATE_V6") -> str:
    """Generate IPv6 private-range reject rules (ULA + link-local)."""
    return "\n".join(
        f'        ip6 daddr {net} log prefix "{prefix}: " reject with icmpv6 type admin-prohibited'
        for net in IPV6_PRIVATE
    )


def _audit_deny_rule() -> str:
    """Generate the deny-all rule with audit logging.

    Uses ``icmpx`` for cross-family reject in ``inet`` tables —
    auto-selects ICMP (IPv4) or ICMPv6 (IPv6).
    """
    return (
        '        log prefix "TEROK_SHIELD_DENIED: " counter\n'
        "        reject with icmpx admin-prohibited"
    )


def _audit_allow_rules() -> str:
    """Generate audit rules for allowed traffic (IPv4 + IPv6).

    No rate limit — only new connections reach these rules because
    ``ct state established,related accept`` is earlier in the chain.
    """
    return (
        '        ip daddr @allow_v4 log prefix "TEROK_SHIELD_ALLOWED: " counter accept\n'
        '        ip6 daddr @allow_v6 log prefix "TEROK_SHIELD_ALLOWED: " counter accept'
    )


def _loopback_port_rules(ports: tuple[int, ...]) -> str:
    """Generate nft accept rules for loopback ports."""
    return "\n".join(f'            tcp dport {p} oifname "lo" accept' for p in ports)


def hook_ruleset(dns: str = PASTA_DNS, loopback_ports: tuple[int, ...] = ()) -> str:
    """Generate a per-container nftables ruleset for hook mode.

    Applied by the OCI hook into the container's own netns.
    Dual-stack: both IPv4 and IPv6 use deny-all + allowlist.

    Chain order (output):
        loopback -> established -> DNS -> loopback ports -> allow sets -> RFC1918/v6-private reject -> deny

    Args:
        dns: DNS server address (pasta default forwarder).
        loopback_ports: TCP ports to allow on the loopback interface.
    """
    safe_ip(dns)
    for p in loopback_ports:
        _safe_port(p)
    port_rules = _loopback_port_rules(loopback_ports)
    port_block = f"\n{port_rules}\n" if port_rules else "\n"
    return textwrap.dedent(f"""\
        table {NFT_TABLE} {{
            set allow_v4 {{ type ipv4_addr; flags interval; }}
            set allow_v6 {{ type ipv6_addr; flags interval; }}

            chain output {{
                type filter hook output priority filter; policy drop;
                oifname "lo" accept
                ct state established,related accept
                udp dport 53 ip daddr {dns} accept
                tcp dport 53 ip daddr {dns} accept{port_block}\
        {_audit_allow_rules()}
                ip daddr @allow_v4 accept
                ip6 daddr @allow_v6 accept
        {_rfc1918_rules()}
        {_ipv6_private_rules()}
        {_audit_deny_rule()}
            }}

            chain input {{
                type filter hook input priority filter; policy drop;
                iifname "lo" accept
                ct state established,related accept
                udp sport 53 accept
                tcp sport 53 accept
                drop
            }}
        }}
    """)


def bypass_ruleset(
    dns: str = PASTA_DNS,
    loopback_ports: tuple[int, ...] = (),
    *,
    allow_all: bool = False,
) -> str:
    """Generate a bypass (accept-all + log) nftables ruleset.

    Same structure as ``hook_ruleset()`` but output chain policy is accept
    and new connections are logged with the bypass prefix.  Private-range
    reject rules (RFC1918 + IPv6 ULA/link-local) are kept unless
    *allow_all* is True.

    Args:
        dns: DNS server address (pasta default forwarder).
        loopback_ports: TCP ports to allow on the loopback interface.
        allow_all: If True, remove private-range reject rules.
    """
    safe_ip(dns)
    for p in loopback_ports:
        _safe_port(p)
    port_rules = _loopback_port_rules(loopback_ports)
    port_block = f"\n{port_rules}\n" if port_rules else "\n"
    private_block = "" if allow_all else f"\n{_rfc1918_rules()}\n{_ipv6_private_rules()}"
    bypass_log = f'        ct state new log prefix "{BYPASS_LOG_PREFIX}: " counter'
    return textwrap.dedent(f"""\
        table {NFT_TABLE} {{
            set allow_v4 {{ type ipv4_addr; flags interval; }}
            set allow_v6 {{ type ipv6_addr; flags interval; }}

            chain output {{
                type filter hook output priority filter; policy accept;
                oifname "lo" accept
                ct state established,related accept
                udp dport 53 ip daddr {dns} accept
                tcp dport 53 ip daddr {dns} accept{port_block}\
        {bypass_log}{private_block}
            }}

            chain input {{
                type filter hook input priority filter; policy drop;
                iifname "lo" accept
                ct state established,related accept
                udp sport 53 accept
                tcp sport 53 accept
                drop
            }}
        }}
    """)


# ── Set operations ───────────────────────────────────────


def add_elements(set_name: str, ips: list[str], table: str = NFT_TABLE) -> str:
    """Generate nft command to add validated IPs to a set.

    Returns empty string if no valid IPs.
    """
    valid = [safe_ip(ip) for ip in ips if _try_validate(ip)]
    if not valid:
        return ""
    return f"add element {table} {set_name} {{ {', '.join(valid)} }}\n"


def add_elements_dual(ips: list[str], table: str = NFT_TABLE) -> str:
    """Classify IPs by family and generate add-element commands for both sets.

    IPv4 addresses go to ``allow_v4``, IPv6 to ``allow_v6``.
    Returns empty string if no valid IPs.
    """
    v4 = [ip for ip in ips if _try_validate(ip) and _is_v4(ip)]
    v6 = [ip for ip in ips if _try_validate(ip) and not _is_v4(ip)]
    parts: list[str] = []
    cmd = add_elements("allow_v4", v4, table)
    if cmd:
        parts.append(cmd)
    cmd = add_elements("allow_v6", v6, table)
    if cmd:
        parts.append(cmd)
    return "".join(parts)


# ── Verification ─────────────────────────────────────────


def _verify_rfc1918_blocks(nft_output: str) -> list[str]:
    """Check RFC1918 reject rules are present in the ruleset.

    Uses a regex to match reject rule context (``ip daddr <net> ... reject``)
    rather than bare CIDR presence, so set elements don't produce false passes.
    """
    errors: list[str] = []
    for net in RFC1918:
        pattern = rf"ip daddr {re.escape(net)}.*reject"
        if not re.search(pattern, nft_output):
            errors.append(f"RFC1918 reject rule for {net} missing")
    return errors


def _verify_ipv6_private_blocks(nft_output: str) -> list[str]:
    """Check IPv6 private-range reject rules are present."""
    errors: list[str] = []
    for net in IPV6_PRIVATE:
        pattern = rf"ip6 daddr {re.escape(net)}.*reject"
        if not re.search(pattern, nft_output):
            errors.append(f"IPv6 private reject rule for {net} missing")
    return errors


def verify_ruleset(nft_output: str) -> list[str]:
    """Check applied ruleset invariants.  Returns errors (empty = OK).

    Verifies:
    - Default policy is drop
    - Both output and input chains exist
    - Reject type is present
    - Deny log prefix is present
    - All RFC1918 ranges are present (reject rules for non-whitelisted LAN traffic)
    - All IPv6 private ranges are present
    - Dual-stack allow sets are declared
    """
    errors: list[str] = []
    if "policy drop" not in nft_output:
        errors.append("policy is not drop")
    for chain in ("output", "input"):
        if f"chain {chain}" not in nft_output:
            errors.append(f"{chain} chain missing")
    if "admin-prohibited" not in nft_output:
        errors.append("reject type missing")
    if "TEROK_SHIELD_DENIED" not in nft_output:
        errors.append("deny log prefix missing")
    if "allow_v6" not in nft_output:
        errors.append("allow_v6 set missing")
    errors.extend(_verify_rfc1918_blocks(nft_output))
    errors.extend(_verify_ipv6_private_blocks(nft_output))
    return errors


def verify_bypass_ruleset(nft_output: str) -> list[str]:
    """Check applied bypass ruleset invariants.  Returns errors (empty = OK).

    Verifies:
    - Output chain has policy accept
    - Input chain has policy drop
    - Bypass log prefix is present
    - Dual-stack allow sets are declared
    """
    errors: list[str] = []
    if "policy accept" not in nft_output:
        errors.append("output policy is not accept")
    if "policy drop" not in nft_output:
        errors.append("input policy is not drop")
    for chain in ("output", "input"):
        if f"chain {chain}" not in nft_output:
            errors.append(f"{chain} chain missing")
    if BYPASS_LOG_PREFIX not in nft_output:
        errors.append("bypass log prefix missing")
    if "allow_v6" not in nft_output:
        errors.append("allow_v6 set missing")
    return errors


def _try_validate(ip: str) -> bool:
    """Return True if ip is a valid IPv4 address/CIDR, False otherwise."""
    try:
        safe_ip(ip)
        return True
    except ValueError:
        return False
