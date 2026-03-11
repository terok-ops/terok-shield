# bypass/ — Shield Down/Up Bypass Tests

Tests for the manual bypass toggle that temporarily switches a container
from deny-all to accept-all+log mode for traffic discovery.

## Stories

| File | What it tests |
|------|---------------|
| `test_state.py` | `shield_state()` detection: UP, DOWN, DOWN_ALL, INACTIVE |
| `test_traffic.py` | Network behavior in bypass: traffic flows, RFC1918 protection, IPv6 drop |
| `test_cli.py` | CLI `down`, `up`, `rules --state`, `preview --down` commands |
| `test_lifecycle.py` | Full E2E lifecycle: state transitions, idempotency, IP restoration, audit trail |
