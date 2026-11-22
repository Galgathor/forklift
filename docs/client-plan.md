# Forklift Client integration plan

## Existing components

The Axum manager authorizes human administrators through LDAP membership, session cookies, Origin/CSRF checks and recovery guards. SQLite schema 5 stores hosts as JSON under stable random IDs; manual host CRUD and per-host LDAP bundle generation already work. DNS intent, per-value ownership and retry journals live separately. None of these are machine enrollment or telemetry credentials. There is no client enrollment, host heartbeat or notification service yet. Keep client credentials separate from LDAP bind identities and preserve manual host behavior.

## Milestone 1

1. Add an additive SQLite machine-enrollment registry and `/api/client/v1/` contract. Use the device authorization model for approval in Hosts, with 10-minute one-use pairing codes, idempotent initialization, pending cancellation and explicit manual-host linking.
2. Bind enrollment and each machine credential to a P-256 key generated locally. Verify standard ES256 DPoP proofs, server nonces, target/method/token binding and durable replay protection. HTTPS remains mandatory; reverse proxies do not supply authentication headers. No administrator password reaches the client.
3. Implement a separate native Rust CLI and hardened root systemd service. Preserve pending enrollment across interruptions and credentials across restarts; limit writes to root-owned client state. Provide CA-file/system trust, bounded communication, local status and initial client-only diagnostics. Authentication-service diagnostics, network monitoring and automatic DNS updates follow in later milestones.
4. Discover `_forklift._tcp.local.` services with untrusted TXT metadata, then independently verify HTTPS. Since the normal manager is bridged, provide an optional server-side publisher on the LAN; do not claim bridge-local multicast reaches physical clients. Manual HTTPS URLs always work. The client has no container deployment.
5. Add matching Hosts pairing/review/link/revoke dialogs, enrollment indicators and actual last-contact observations. Hide supporting guidance behind information buttons. Manual inventory has no offline status.
6. Exercise native client binaries against actual TLS, LDAP-backed administrator authorization and persistent server storage. Test wrong keys, nonce/proof replay, expiry, cancellation, code guessing limits, interrupted approval, linking, revocation, offline local status and isolated root state. Never modify test-host authentication/network configuration.

## Later milestones

Milestone 2 adds netlink plus periodic inventory, independent freshness/offline detection and explicitly authorized DNS reconciliation. Milestone 3 adds read-only system diagnostics and authoritative issue/notification history. Milestone 4 completes Debian packaging, credential rotation and wider supported-Ubuntu recovery/security drills. No fake diagnostic results, automatic system repair, remote commands or automatic identity merging are permitted.
