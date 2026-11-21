# Phase 2: host-owned DNS

Extend the current host forms and additive schema-5 metadata. Hosts can opt into forward/reverse DNS without implicitly granting SSH access. Use generic domains and LAN examples throughout documentation and tests.

1. Add desired zone/FQDN/IPv4/optional IPv6/PTR configuration and a separate DNS status to each host, preserving older host records and clients.
2. Track individual host-owned values with PowerDNS comments plus Forklift metadata. Never adopt pre-existing values; merge additions and remove only explicitly owned, unchanged values. Manual record editing relinquishes host ownership.
3. Reuse durable DNS change plans with record/comment revision checks. Save the host independently; DNS failures produce visible retryable state. Superseded intents cancel older plans while retaining ownership candidates for safe cleanup.
4. Offer apply/defer when editing and retain/delete when removing a host. Preserve a cleanup tombstone if the host is removed while DNS is unavailable; expose it in DNS management.
5. Verify actual A/AAAA/PTR answers, rename/address changes, shared/manual values, outages, retries, stale edits, deletion choices, persistence and existing LDAP behavior. Update the browser checks and operational instructions. DNS replication and integrated DNS recovery remain later phases.
