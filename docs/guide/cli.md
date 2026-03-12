# CLI Reference

All commands are invoked as `terok-shield <command> [options]`.

Global options:

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--state-dir <path>` | Override state root directory |

## status

Show current shield status: active mode, available profiles, audit state.

```bash
terok-shield status
```

```text
Mode:     hook
Audit:    enabled
Profiles: base, dev-node, dev-python, dev-standard, nvidia-hpc
```

## resolve

Resolve DNS domains from the configured profiles and cache the resulting IPs.

```bash
terok-shield resolve <container> [--force]
```

| Argument | Description |
|----------|-------------|
| `container` | Container name (used as the cache key) |
| `--force` | Bypass cache freshness and re-resolve all domains |

```bash
terok-shield resolve my-container
# Resolved 28 IPs for my-container

terok-shield resolve my-container --force
# Resolved 28 IPs for my-container (forced)
```

Cached IPs are stored in the container's `profile.allowed` file and
automatically refreshed when stale (default: 1 hour).

## allow

Add a domain or IP to a running container's allow set.

```bash
terok-shield allow <container> <target>
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `target` | Domain name or IP address to allow |

```bash
terok-shield allow my-container example.com
# Allowed example.com -> <resolved-ip> for my-container

terok-shield allow my-container 203.0.113.10
# Allowed 203.0.113.10 -> 203.0.113.10 for my-container
```

If `target` is a domain name, it is resolved to IPs automatically.
Changes take effect immediately. Allowed IPs are persisted to `live.allowed`
and survive `down`/`up` bypass cycles. If the IP was previously denied
(present in `deny.list`), the deny is cleared automatically.

## deny

Remove a domain or IP from a running container's allow set.

```bash
terok-shield deny <container> <target>
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `target` | Domain name or IP address to deny |

```bash
terok-shield deny my-container example.com
# Denied example.com (<resolved-ip>) for my-container
```

The IP is removed from the nft allow set (best-effort) and from `live.allowed`.
If the IP originated from a loaded preset (`profile.allowed`), it is also
written to `deny.list` so the deny persists across `up`/`down` cycles and
container restarts.

## down

Switch a container to bypass mode. Public traffic is accepted with logging;
private ranges (RFC 1918/RFC 4193) remain blocked unless `--all` is used.

```bash
terok-shield down <container> [--all]
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `--all` | Also allow private-range traffic (RFC 1918/RFC 4193) |

By default, private ranges (RFC 1918 and RFC 4193) are still rejected in
bypass mode. Use `--all` to allow everything.

## up

Restore normal deny-all mode for a container.

```bash
terok-shield up <container>
```

Re-applies the deny-all ruleset and restores effective IPs:
`(profile.allowed ∪ live.allowed) − deny.list`.

## preview

Show the nftables ruleset that would be applied.

```bash
terok-shield preview [--down] [--all]
```

| Option | Description |
|--------|-------------|
| `--down` | Show bypass ruleset instead of default deny-all |
| `--all` | Omit private-range reject rules (requires `--down`) |

## rules

Display the active nftables rules for a container.

```bash
terok-shield rules <container>
```

Shows the container's shield state and the full nftables ruleset in its
network namespace.

## logs

Show audit log entries.

```bash
terok-shield logs [--container <name>] [-n <count>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--container` | all | Filter by container name |
| `-n` | 50 | Number of recent entries to show |

```bash
terok-shield logs --container my-container -n 10
terok-shield logs -n 5   # last 5 entries across all containers
```

Each entry is a JSON object printed on one line. See [Audit Logging](logging.md)
for the log format.
