# Phase 3: DNS replication

Keep LDAP and DNS provisioning independent. Extend the existing pinned PowerDNS image, additive SQLite metadata, protected local API and copyable enrollment workflow.

1. Add a DNS Servers panel with a reachable private primary DNS endpoint, secondary zone assignments and a one-use, expiring HTTPS join configuration. Reuse the directory certificate validator and installation secret with separate DNS key derivation contexts.
2. Deploy a dedicated secondary Compose stack with independent SQLite/secrets storage. Keep the native API on loopback; expose only authoritative DNS and a pinned-TLS, authenticated fixed-operation management listener on its private interface. Do not proxy arbitrary PowerDNS configuration or commands.
3. Configure native Primary/Secondary zones and per-node HMAC-SHA256 TSIG transfer permissions through the documented API. Deny unsigned AXFR, secondary retransfers and DNS UPDATE. Preserve unassigned/manual zones and existing LDAP configuration.
4. Persist desired assignments and reconciliation errors. Retry partial provisioning idempotently, remove obsolete managed assignments explicitly and revoke primary transfer authorization before removing a node. Reconcile new/deleted zones with enrolled nodes without claiming an atomic cross-node commit.
5. Compare actual authoritative SOA responses with the current primary serial, retaining last confirmed synchronization separately from current reachability. Verify real transfers, updates, recovery, persistence, unauthorized requests and secondary UDP/TCP answers while the primary and manager are offline.

TSIG authenticates transfers; it does not encrypt zone data. Use trusted private networks or a VPN. No primary promotion, custom database synchronization or shared SQLite files. Integrated encrypted DNS recovery is documented in [Phase 4](dns-recovery.md).
