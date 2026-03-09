# Integration Test Map

*Generated: 2026-03-09 00:21 UTC*

**79 tests** across **8 directories**

## `setup/`

Tests for hook installation, config path resolution, profile loading, and auto-detection. Covers the initial setup workflow before any container is started.

| Test | Class | Markers |
|---|---|---|
| `test_at_least_standard_with_nft` | `TestAutoDetect` | `needs_podman` |
| `test_returns_valid_mode` | `TestAutoDetect` | `needs_podman` |
| `test_config_root_with_xdg` | `TestPathResolution` | `needs_host_features` |
| `test_ensure_dirs_creates_tree` | `TestPathResolution` | `needs_host_features` |
| `test_explicit_overrides_xdg` | `TestPathResolution` | `needs_host_features` |
| `test_state_root_with_xdg` | `TestPathResolution` | `needs_host_features` |
| `test_cli_setup` | `TestCLISetup` | `needs_podman` |
| `test_cli_setup_idempotent` | `TestCLISetup` | `needs_podman` |
| `test_setup_creates_hook_files` | `TestShieldSetup` | `needs_podman` |
| `test_setup_idempotent` | `TestShieldSetup` | `needs_podman` |
| `test_all_bundled_profiles_load` | `TestProfilesLive` | `needs_host_features` |
| `test_base_profile_entries` | `TestProfilesLive` | `needs_host_features` |
| `test_compose_deduplicates` | `TestProfilesLive` | `needs_host_features` |

## `launch/`

Tests for the container launch workflow: `shield_pre_start`, nft ruleset application via `nsenter`, `apply_hook`, and `hook_main` end-to-end.

| Test | Class | Markers |
|---|---|---|
| `test_apply_hook_allows_pre_resolved` | `TestApplyHookE2E` | `needs_internet`, `needs_podman` |
| `test_apply_hook_blocks_traffic` | `TestApplyHookE2E` | `needs_internet`, `needs_podman` |
| `test_apply_hook_creates_firewall` | `TestApplyHookE2E` | `needs_internet`, `needs_podman` |
| `test_apply_hook_fail_closed_bad_pid` | `TestApplyHookE2E` | `needs_internet`, `needs_podman` |
| `test_apply_hook_with_pre_resolved_ips` | `TestApplyHookE2E` | `needs_internet`, `needs_podman` |
| `test_reapply_after_flush` | `TestApplyHookE2E` | `needs_internet`, `needs_podman` |
| `test_hook_main_bad_pid` | `TestHookMainE2E` | `needs_internet`, `needs_podman` |
| `test_hook_main_invalid_json` | `TestHookMainE2E` | `needs_internet`, `needs_podman` |
| `test_hook_main_success` | `TestHookMainE2E` | `needs_internet`, `needs_podman` |
| `test_hook_main_with_pre_resolved_blocks_and_allows` | `TestHookMainE2E` | `needs_internet`, `needs_podman` |
| `test_apply_and_list` | `TestStandardApply` | `needs_podman` |
| `test_flush_and_reapply` | `TestStandardApply` | `needs_podman` |
| `test_policy_drop_enforced` | `TestStandardApply` | `needs_podman` |
| `test_rfc1918_blocked` | `TestStandardApply` | `needs_podman` |
| `test_verify_applied_ruleset` | `TestStandardApply` | `needs_podman` |
| `test_firewall_applied_via_hook` | `TestFirewallApplied` | `needs_podman` |
| `test_pre_start_resolves_dns` | `TestShieldPreStart` | `needs_internet`, `needs_podman` |
| `test_pre_start_returns_podman_args` | `TestShieldPreStart` | `needs_internet`, `needs_podman` |
| `test_pre_start_without_setup_raises` | `TestShieldPreStart` | `needs_internet`, `needs_podman` |

## `blocking/`

Tests for default-deny behavior: HTTP/HTTPS blocking, IPv6 drop, RFC1918 reject rules, reject-vs-drop timing, and ICMP probe detection.

| Test | Class | Markers |
|---|---|---|
| `test_traffic_blocked_by_default` | `TestDefaultDenyAPI` | `needs_internet`, `needs_podman` |
| `test_http_blocked_after_ruleset` | `TestFirewallBlocking` | `needs_internet`, `needs_podman` |
| `test_https_blocked_after_ruleset` | `TestFirewallBlocking` | `needs_internet`, `needs_podman` |
| `test_ipv6_blocked_after_ruleset` | `TestFirewallBlocking` | `needs_internet`, `needs_podman` |
| `test_reject_is_fast_not_timeout` | `TestFirewallBlocking` | `needs_internet`, `needs_podman` |
| `test_rfc1918_still_blocked_when_not_whitelisted` | `TestFirewallBlocking` | `needs_internet`, `needs_podman` |
| `test_open_port_on_localhost` | `TestProbeRealSocket` | `needs_host_features`, `needs_internet`, `needs_podman` |
| `test_port_unreachable_on_localhost` | `TestProbeRealSocket` | `needs_host_features`, `needs_internet`, `needs_podman` |
| `test_admin_prohibited_detected` | `TestShieldProbe` | `needs_host_features` |
| `test_allowed_ip_is_open` | `TestShieldProbe` | `needs_host_features` |

## `allow_deny/`

Tests for the allow/deny workflow: adding IPs to the allow set, verifying traffic passes, RFC1918 whitelisting, and the full allow → deny cycle via API and CLI.

| Test | Class | Markers |
|---|---|---|
| `test_cli_allow` | `TestAllowDenyCLI` | `needs_internet`, `needs_podman` |
| `test_cli_deny` | `TestAllowDenyCLI` | `needs_internet`, `needs_podman` |
| `test_elements_appear_in_set` | `TestAddElementsLive` | `needs_internet`, `needs_podman` |
| `test_multiple_elements` | `TestAddElementsLive` | `needs_internet`, `needs_podman` |
| `test_shield_allow_deny_cycle` | `TestAllowDenyAPI` | `needs_internet`, `needs_podman` |
| `test_shield_allow_ip` | `TestAllowDenyAPI` | `needs_internet`, `needs_podman` |
| `test_allow_then_block_different_targets` | `TestFirewallAllowing` | `needs_internet`, `needs_podman` |
| `test_allowed_ip_reachable_http` | `TestFirewallAllowing` | `needs_internet`, `needs_podman` |
| `test_allowed_ip_reachable_https` | `TestFirewallAllowing` | `needs_internet`, `needs_podman` |
| `test_non_allowed_ip_still_blocked` | `TestFirewallAllowing` | `needs_internet`, `needs_podman` |
| `test_rfc1918_allowed_when_whitelisted` | `TestRFC1918Allow` | `needs_internet`, `needs_podman` |

## `dns/`

Tests for DNS resolution: live `dig` resolution, resolve-and-cache pipeline, `shield_resolve()` API, CLI resolve, and the full profile → DNS → cache pipeline.

| Test | Class | Markers |
|---|---|---|
| `test_cli_resolve` | `TestCLIResolve` | `needs_internet` |
| `test_resolve_creates_cache` | `TestShieldResolve` | `needs_internet`, `needs_podman` |
| `test_resolve_force_bypasses_cache` | `TestShieldResolve` | `needs_internet`, `needs_podman` |
| `test_resolve_returns_ips` | `TestShieldResolve` | `needs_internet`, `needs_podman` |
| `test_base_profile_resolves` | `TestProfileResolvePipeline` | `needs_internet` |
| `test_dev_standard_resolves_github` | `TestProfileResolvePipeline` | `needs_internet` |
| `test_user_profile_override` | `TestProfileResolvePipeline` | `needs_internet` |
| `test_cache_roundtrip` | `TestResolveAndCacheLive` | `needs_internet` |
| `test_mixed_entries` | `TestResolveAndCacheLive` | `needs_internet` |
| `test_multiple_domains` | `TestResolveLive` | `needs_internet` |
| `test_resolves_known_domain` | `TestResolveLive` | `needs_internet` |
| `test_unresolvable_domain_returns_empty` | `TestResolveLive` | `needs_internet` |

## `observability/`

Tests for status, rules inspection, audit logging, and log viewing via both the public API and CLI.

| Test | Class | Markers |
|---|---|---|
| `test_apply_hook_audit_on_failure` | `TestApplyHookAudit` | `needs_host_features` |
| `test_apply_hook_audit_with_pre_resolved_ips` | `TestApplyHookAudit` | `needs_host_features` |
| `test_apply_hook_produces_audit_trail` | `TestApplyHookAudit` | `needs_host_features` |
| `test_jsonl_format` | `TestAuditLive` | `needs_host_features`, `needs_internet`, `needs_podman` |
| `test_list_log_files` | `TestAuditLive` | `needs_host_features`, `needs_internet`, `needs_podman` |
| `test_log_and_tail` | `TestAuditLive` | `needs_host_features`, `needs_internet`, `needs_podman` |
| `test_tail_empty_container` | `TestAuditLive` | `needs_host_features`, `needs_internet`, `needs_podman` |
| `test_cli_logs` | `TestLogsCLI` | `needs_internet`, `needs_podman` |
| `test_shield_rules_returns_ruleset` | `TestRulesAPI` | `needs_internet`, `needs_podman` |
| `test_cli_rules` | `TestRulesCLI` | `needs_internet`, `needs_podman` |
| `test_cli_status` | `TestCLIStatus` | `needs_host_features` |
| `test_status_returns_dict` | `TestShieldStatus` | `needs_host_features`, `needs_podman` |

## `safety/`

Tests for fail-closed error paths: CLI error handling when containers are missing or unreachable.

| Test | Class | Markers |
|---|---|---|
| `test_cli_allow_bad_container` | `TestCLIErrors` | `needs_podman` |

## `cli/`

Tests for CLI parsing and help output that don't require containers or network access.

| Test | Class | Markers |
|---|---|---|
| `test_cli_no_args_exits_zero` | `TestCLIHelp` | `needs_host_features` |

