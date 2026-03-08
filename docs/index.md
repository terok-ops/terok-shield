# terok-shield

nftables-based egress firewalling for rootless Podman containers.

## What it does

terok-shield enforces **default-deny outbound** network filtering on Podman containers using nftables. Containers can only reach explicitly allowed destinations — everything else is rejected with an ICMP error.

### Key properties

- **Default-deny egress** — containers start with no outbound access
- **DNS-based allowlisting** — allowed destinations specified as domain names, resolved and cached automatically
- **RFC1918 blocking** — private networks and link-local addresses rejected by default (with opt-in whitelisting for local infrastructure)
- **IPv6 dropped** — all IPv6 traffic unconditionally dropped (IPv4-only allow sets)
- **Fail-closed** — if the firewall hook fails, the container is torn down
- **Audit logging** — JSON-lines lifecycle logs + kernel-level per-packet nftables logs
- **Live allow/deny** — add or remove IPs at runtime without restarting the container

### Two operating modes

| Mode | Network | Firewall scope | Requirements |
|------|---------|----------------|--------------|
| **Standard** | pasta/slirp (rootless default) | Per-container netns via OCI hook | `nft` binary |
| **Hardened** | Named bridge (`ctr-egress`) | rootless-netns (shared) | `nft` + `dnsmasq` + bridge network |

## Quick start

```bash
pip install terok-shield

terok-shield setup        # install OCI hook (standard) or verify bridge (hardened)
terok-shield status       # verify mode, profiles, audit config
terok-shield resolve      # resolve DNS allowlists and cache IPs
```

### CLI commands

| Command | Description |
|---------|-------------|
| `setup` | Install OCI hook or verify bridge network |
| `status` | Show mode, active profiles, log file locations |
| `resolve` | Resolve DNS profiles and cache results |
| `allow <container> <target>` | Live-allow a domain or IP for a running container |
| `deny <container> <target>` | Live-deny a domain or IP (best-effort) |
| `rules <container>` | Show current nft ruleset for a container |
| `logs [container]` | Tail audit logs (all or per-container) |

## Library API

terok-shield exposes a Python API for integration with [terok](https://github.com/terok-ai/terok):

```python
from terok_shield import (
    ShieldConfig, ShieldMode, ExecError,
    shield_setup, shield_status,
    shield_pre_start, shield_post_start, shield_pre_stop,
    shield_allow, shield_deny, shield_rules,
    shield_resolve, list_profiles,
    log_event, tail_log, list_log_files,
    load_shield_config,
)
```

See [API Reference](reference/) for full documentation.

## Documentation

- [Security & Design](SECURITY.md) — threat model, security boundary, chain evaluation order
- [Architecture](DESIGN.md) — modes, allowlisting, audit logging, public API
- [Contributing](DEVELOPER.md) — development setup, testing, conventions
- [Code Quality](quality-report.md) — auto-generated quality metrics
- [API Reference](reference/) — auto-generated from docstrings
