# Forklift Client integration plan

## Inspection before Milestone 1

The Axum manager authorizes human administrators through LDAP membership, session cookies, Origin/CSRF checks and recovery guards. SQLite schema 5 stores hosts as JSON under stable random IDs; manual host CRUD and per-host LDAP bundle generation already work. DNS intent, per-value ownership and retry journals live separately. None of these are machine enrollment or telemetry credentials. There is no client enrollment, host heartbeat or notification service yet. Keep client credentials separate from LDAP bind identities and preserve manual host behavior.

## Milestone 1

1. Add an additive SQLite machine-enrollment registry and `/api/client/v1/` contract. Use the device authorization model for approval in Hosts, with 10-minute one-use pairing codes, idempotent initialization, pending cancellation and explicit manual-host linking.
2. Bind enrollment and each machine credential to a P-256 key generated locally. Verify standard ES256 DPoP proofs, server nonces, target/method/token binding and durable replay protection. HTTPS remains mandatory; reverse proxies do not supply authentication headers. No administrator password reaches the client.
3. Implement a separate native Rust CLI and hardened root systemd service. Preserve pending enrollment across interruptions and credentials across restarts; limit writes to root-owned client state. Provide CA-file/system trust, bounded communication, local status and initial client-only diagnostics. Authentication-service diagnostics, network monitoring and automatic DNS updates follow in later milestones.
4. Discover `_forklift._tcp.local.` services with untrusted TXT metadata, then independently verify HTTPS. Since the normal manager is bridged, provide an optional server-side publisher on the LAN; do not claim bridge-local multicast reaches physical clients. Manual HTTPS URLs always work. The client has no container deployment.
5. Add matching Hosts pairing/review/link/revoke dialogs, enrollment indicators and actual last-contact observations. Hide supporting guidance behind information buttons. Manual inventory has no offline status.
6. Exercise native client binaries against actual TLS, LDAP-backed administrator authorization and persistent server storage. Test wrong keys, nonce/proof replay, expiry, cancellation, code guessing limits, interrupted approval, linking, revocation, offline local status and isolated root state. Never modify test-host authentication/network configuration.

## Later milestones

Milestones 1–4 are implemented, including read-only system diagnostics and authoritative issue/notification history. Milestone 4 adds Debian packaging, credential rotation and wider supported-Ubuntu recovery/security drills. No fake diagnostic results, automatic system repair, remote commands or automatic identity merging are permitted.

## Milestone 2 architecture

Reuse enrollment keys, DPoP verification, stable host IDs and the existing DNS ownership journals. Add a separate monitoring table without rewriting schema-5 host rows or enrollment identity. Keep observed hostname/FQDN separate from administrator-configured inventory and DNS names.

1. Accept bounded version-1 inventory reports with a durable monotonic sequence. Save server receipt time before DNS work; identical retries return the original receipt and cannot extend freshness.
2. Reconcile the native inventory every configured heartbeat interval, with debounced route-netlink events for relevant address/interface changes. Cache the latest snapshot and sequence atomically before network access. Preserve read-only system inspection and root-only storage.
3. Derive online/offline independently from heartbeat receipt, with a server watcher for transition history. Ordinary session checks do not count as heartbeats; manual inventory has no offline state.
4. Require per-host DNS opt-in and explicit IPv4/optional IPv6 selectors. Refuse ambiguous/missing addresses and externally changed ownership; retain administrator-controlled names. Reuse native API reconciliation, per-value markers and durable retry plans. Bound DNS work separately and return independent inventory/DNS outcomes.
5. Show actual inventory, freshness, DNS outcome, policy and bounded history in Hosts. Use contextual information buttons and existing styled dialogs. Verify native HTTPS, isolated netlink changes, real PowerDNS answers, persistence, stale reports, outages and revocation.

Milestones 3 and 4 implement diagnostics, issue/notification lifecycle, packaging and rotation.

## Milestone 3 architecture

Add typed diagnostic expectations to the existing monitoring policy. The authenticated client retrieves only bounded names, endpoints, public LDAP trust and test/context identifiers; no commands, scripts or user credentials. Native checks use fixed read-only tools, verified LDAP TLS, normal NSS/resolver lookups and DNS protocol queries with bounded execution/output. Cache the latest checks for offline CLI use and report them under a separate monotonic sequence/profile revision.

Keep authoritative issues separate from observations and notifications. Require consecutive distinct failing reports (configurable), deduplicate active issues, resolve only on a positive check, and preserve unknown/stale results without false recovery. Server-clock offline/DNS failures join the same lifecycle. Retire superseded profiles/credentials explicitly. Bound retained history and notifications.

Extend Hosts with DNS, Authentication, SSH and Issues views and add a shared notification control. Reuse contextual help and styled components; manual inventory remains unmonitored. Verify actual native checks, real TLS/LDAP/DNS services, issue/recovery/acknowledgment semantics, stale/replayed/cross-host reports and existing monitoring regressions without modifying development-host authentication or resolver files.

## Milestone 4 architecture

1. Add staged key/credential rotation to the existing DPoP protocol. Persist a provisional local key before preparation and the provisional token before confirmation. Activate only with the new key; resume interrupted/lost-response confirmations idempotently. Expiring unconfirmed rotations retain the original credential. Revocation/restore fence both identities. Preserve host IDs, report counters, policies and issue history.
2. Rotate automatically after 30 days and support administrator requests from the existing client-details dialog. Show actual generation/pending/completion state without exposing credentials. Keep incompatible older clients usable and identify their rotation capability honestly.
3. Build native Debian packages through maintained packaging tooling with pinned versions, derived runtime dependencies and reproducible archive timestamps. Preserve root-only state on upgrade/remove/purge and avoid any authentication/resolver modifications. Test actual install/upgrade/removal and deterministic package output.
4. Harden process/tool cleanup, root-state validation and service lifecycle; exercise offline/revoked/expired/interrupted rotation, permissions and cache bounds. Attempt isolated full-systemd validation where tooling permits and document exact tested Ubuntu/architecture limits. The product gains no container deployment, remote commands, automatic authentication repair or changes to trusted management identity.
