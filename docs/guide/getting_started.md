# Getting Started

This guide walks through installing terok-shield and running your first
shielded container.

## Prerequisites

- **Linux** with nftables (`nft` binary available)
- **Podman** (rootless mode)
- **Python 3.12+**
- **`dig`** (from `dnsutils` or `bind-utils`) for DNS resolution

## Install

```bash
pip install terok-shield
```

Verify the installation:

```bash
terok-shield --version
```

## Resolve DNS allowlists

Before starting a container, pre-resolve the domains from your allowlist
profiles into cached IPs:

```bash
terok-shield resolve my-container
```

```text
Resolved 28 IPs for my-container
  140.82.121.3
  140.82.121.4
  ...
```

The IPs are cached per-container and automatically refreshed when stale
(default: 1 hour). Force a refresh with `--force`.

## Run a shielded container

The simplest way is to let `pre_start()` handle everything via the Python API
(this is how [terok](https://github.com/terok-ai/terok) uses it). For
standalone CLI usage, you need to pass the right podman flags:

```bash
podman run --rm -it \
  --name my-container \
  --annotation terok.shield.profiles=dev-standard \
  --annotation terok.shield.state_dir=$HOME/.local/state/terok-shield/containers/my-container \
  --annotation terok.shield.version=1 \
  --hooks-dir ~/.local/state/terok-shield/containers/my-container/hooks \
  --cap-drop NET_ADMIN --cap-drop NET_RAW \
  --security-opt no-new-privileges \
  alpine:latest sh
```

Breaking this down:

| Flag | Purpose |
|------|---------|
| `--name my-container` | Names the container (used by `allow`, `deny`, `rules`, etc.) |
| `--annotation terok.shield.profiles=dev-standard` | Tells the OCI hook which allowlist profiles to apply |
| `--annotation terok.shield.state_dir=...` | Where the hook finds its state bundle |
| `--annotation terok.shield.version=1` | Bundle version (must match installed version) |
| `--hooks-dir ...` | Points podman to the container's hook directory |
| `--cap-drop NET_ADMIN` | Prevents the workload from modifying the firewall |
| `--cap-drop NET_RAW` | Prevents raw socket access |
| `--security-opt no-new-privileges` | Prevents privilege escalation |

!!! tip "Multiple profiles"
    Combine profiles with commas:
    `--annotation terok.shield.profiles=dev-standard,dev-python,nvidia-hpc`

!!! tip "Easier with the Python API"
    `Shield.pre_start()` generates all annotations and podman args automatically.
    The CLI flags above are what it produces under the hood.

### What happens at startup

1. Podman sees the `terok.shield.profiles` annotation and fires the OCI hook
2. The hook reads `state_dir` from annotations, enters the container's network
   namespace via the PID
3. nftables rules are applied: default-deny policy with the allowlisted IPs
4. The hook verifies the rules are correctly applied
5. If any step fails, the container is torn down (fail-closed)

From inside the container, only the allowed destinations are reachable.
All other outbound traffic is dropped. Allowlisting private-range addresses
(RFC 1918, RFC 4193) or large CIDRs generates a notice in the audit log.

## Allow or deny destinations at runtime

While the container is running, you can modify its allow set:

```bash
# Allow a domain (resolves to IPs automatically)
terok-shield allow my-container example.com
# Allowed example.com -> <resolved-ip> for my-container

# Allow a raw IP
terok-shield allow my-container 203.0.113.10

# Revoke access
terok-shield deny my-container example.com
```

Changes take effect immediately — no container restart needed. Allowed IPs are
persisted to `live.allowed`, and denying a preset IP persists it to `deny.list`,
so both survive `down`/`up` bypass cycles and container restarts.

## Inspect the firewall

```bash
# Show active nftables rules for a container
terok-shield rules my-container

# Show recent audit log entries
terok-shield logs --container my-container -n 10
```

## Bypass mode

Temporarily disable the firewall for debugging or traffic discovery:

```bash
terok-shield down my-container          # bypass (private ranges still blocked)
terok-shield down my-container --all    # bypass everything

terok-shield up my-container            # restore deny-all
```

## Next steps

- [Allowlist Profiles](profiles.md) — customize what your containers can reach
- [Firewall Modes](modes.md) — understand hook mode
- [CLI Reference](cli.md) — full command reference
