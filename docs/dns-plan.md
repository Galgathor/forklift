# Integrated DNS implementation plan

DNS is a standard Forklift component. PowerDNS failures must not block manager startup, LDAP readiness or Linux authentication. Preserve existing schema-5 metadata and LDAP volumes; DNS has separate data, secret and Unix-control volumes.

1. **Single-node DNS (implemented and tested):** pin PowerDNS Authoritative 5.1.5; initialize its shipped Generic SQLite3 schema safely; supervise it as UID10001; bind its REST API to container loopback and relay authenticated requests over a protected Unix socket. Publish configurable TCP/UDP DNS ports. Add Rust validation, authorization, audit events, zone ownership, optimistic record-set edits, reverse zones, optional PTR reconciliation, service diagnostics and a matching WebUI. Verify actual DNS responses and recreation/outage behavior.
2. **Host integration (implemented):** track host-owned forward/reverse values, offer lifecycle reconciliation/deletion choices, and report independent LDAP/DNS outcomes.
3. **Replication (implemented):** reuse enrollment/trust patterns for independent PowerDNS secondaries, TSIG-authenticated transfers, actual SOA/query monitoring and outage tests. No automatic promotion.
4. **Hardening (implemented):** encrypted primary DNS snapshots/restoration/rollback, reviewed JSON import, retryable secondary key/TLS rotation, upgrade drills and failure testing. See [hardening scope](dns-hardening-plan.md) and [recovery procedures](dns-recovery.md).

Phases 1–4 expose DNS, host lifecycle management and native primary/secondary replication; results are in [verification](verification.md). Native zones do not imply replication; API connectivity is separate from authoritative DNS response checks. Configuration is fixed, unsigned transfers and dynamic updates are disabled, and native API/TSIG keys never reach the browser.
