# terok-shield

nftables-based egress firewalling for rootless Podman containers.

## What it does

terok-shield enforces **default-deny outbound** network filtering on Podman
containers using nftables. Containers can only reach explicitly allowed
destinations — everything else is rejected with an ICMP error.

### Key properties

- **Default-deny egress** — containers start with no outbound access
- **DNS-based allowlisting** — allowed destinations specified as domain names, resolved and cached automatically
- **RFC1918 awareness** — allowlisting private network or link-local addresses generates a notice in the audit log
- **Dual-stack** — full IPv4 and IPv6 support with separate allow sets
- **Fail-closed** — if the firewall hook fails, the container is torn down
- **Audit logging** — JSON-lines lifecycle logs + kernel-level per-packet nftables logs
- **Live allow/deny** — add or remove IPs at runtime without restarting the container
- **Per-container isolation** — each container gets its own state bundle, hooks, and audit log

### Hook mode

Uses an OCI hook to apply per-container nftables rules inside each container's
network namespace. Works with pasta/slirp (rootless default). Only requires the
`nft` binary.

See [Firewall Modes](guide/modes.md) for details.

## Quick start

### 1. Install

```bash
pip install terok-shield
```

No changes to your Dockerfiles or container images are needed — the firewall
is applied externally at container creation time.

### 2. Start a shielded container

```bash
terok-shield resolve my-container    # pre-resolve DNS → cached IPs

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

The container starts with a default-deny firewall — only destinations in the
`dev-standard` [allowlist profile](guide/profiles.md) are reachable.

!!! tip "Python API"
    `Shield.pre_start()` generates all annotations and podman args automatically.
    This is how [terok](https://github.com/terok-ai/terok) uses terok-shield.

### 3. Allow a domain at runtime

While the container is running, you can add or remove destinations:

```bash
terok-shield allow my-container example.com
# Allowed example.com -> <resolved-ip> for my-container

terok-shield deny my-container example.com   # revoke later
```

### 4. Inspect

```bash
terok-shield rules my-container     # show active nft rules
terok-shield logs --container my-container -n 10   # recent audit log
```

## Next steps

- [Getting Started](guide/getting_started.md) — full setup walkthrough
- [Allowlist Profiles](guide/profiles.md) — bundled profiles and custom allowlists
- [CLI Reference](guide/cli.md) — all commands and options
- [Firewall Modes](guide/modes.md) — hook mode details
- [Configuration](guide/configuration.md) — config file, paths, caching
- [Audit Logging](guide/logging.md) — log format and inspection
