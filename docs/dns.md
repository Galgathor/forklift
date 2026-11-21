# DNS management (Phase 1)

PowerDNS Authoritative is a standard part of Forklift. It uses its own persistent SQLite database and continues answering configured zones when the manager or LDAP is stopped. DNS outages do not block LDAP startup, readiness or authentication. There is no recursive resolver, Kerberos, Windows domain join or automatic primary promotion.

## Deployment and existing installations

Update/rebuild the existing Compose deployment normally. Keep all existing volumes: no LDAP reinitialization or metadata schema reset is needed. Three additional volumes hold DNS data/configuration (`dns_data`), generated credentials (`dns_secrets`) and protected Unix control (`dns_control`). The manager does not depend on DNS container health.

PowerDNS Authoritative **5.1.5** is pinned by image digest. It initializes the upstream Generic SQLite3 schema once, validates existing storage and refuses an unreviewed schema change rather than recreating a database. Back up before upgrading. See the [upstream release notes](https://doc.powerdns.com/authoritative/changelog/5.1.html) and [SQLite backend documentation](https://doc.powerdns.com/authoritative/backends/generic-sqlite3.html).

Configure these deployment settings before starting/recreating containers:

```dotenv
FORKLIFT_DNS_BIND=127.0.0.1
FORKLIFT_DNS_PORT=53
```

For LAN DNS use the Docker host's specific private address. If another service owns port 53, choose a different address/port, for example `10.0.20.2:1053`. TCP **and** UDP are published. Forklift does not change your resolver, AdGuard or host DNS settings.

Docker publishes host ports, not an additional LAN IP for a container. A service bound to `0.0.0.0:53` may conflict even if PowerDNS uses a specific host IP. Use a nonstandard port plus conditional forwarding, a separate host/IP, or reconfigure the existing service through its own management interface. Ordinary clients generally expect port 53 and cannot use a custom port supplied through standard DHCP DNS settings. Docker-published ports may bypass some host firewall rules; restrict intended client networks using appropriate Docker-aware rules. IPv4 is the current publishing default; AAAA data can still be served over IPv4 DNS transport.

The PowerDNS REST API binds **only to container loopback**. Forklift accesses it over an authenticated protected Unix socket; there is no API TCP port published or exposed through NPM. Internal supervisor operations are fixed health/rotation actions, not arbitrary commands or configuration directives. Runtime UID is 10001 with no capabilities and a read-only root filesystem. API credentials are generated locally, stored in restricted volume files and never sent to the browser. Settings in the DNS page can rotate the API credential, briefly restarting DNS.

## Zones and record sets

Open **DNS → Create zone**. Choose:

- Forward: an internal domain such as `ad.ilpe.me`.
- Private IPv4 reverse: an aligned RFC1918 `/8`, `/16` or `/24`, such as `10.0.20.0/24` → `20.0.10.in-addr.arpa.`. Classless RFC2317 delegation is not implemented.
- ULA IPv6 reverse: a nibble-form zone within `c.f.ip6.arpa.` or `d.f.ip6.arpa.`, for example `d.f.ip6.arpa.` for `fd00::/8`.

Specify the primary nameserver and, when it belongs to the new zone, its IPv4/IPv6 address. Forklift creates SOA, NS and any in-zone nameserver address. Additional NS values can be edited afterward. Zone settings expose SOA mailbox/name/timers; SOA serials increase through PowerDNS's `INCREASE` API policy. Zone kinds are **Native / standalone**, not replicated primaries or secondaries.

Select a zone to manage A, AAAA, CNAME, PTR, TXT, MX, SRV and NS record sets. Enter one value per line; editing replaces that selected set, not other types at the same owner. Relative names belong to the selected zone; `@` means its apex. Absolute names must stay inside that zone, and owners covered by a more specific configured zone must be edited there. CNAMEs cannot coexist with other records or occupy the apex. Duplicate values are rejected. TXT values use quoted DNS presentation strings; MX uses `priority target`, SRV uses `priority weight port target`. Hostname targets are treated as full names, not silently appended to the zone.

Read-only revisions reject stale edits. Only Forklift-owned Native zones (`account=forklift`) are editable. Avoid concurrent external API/database writers: PowerDNS does not provide transactional compare-and-swap across independent clients. Zone deletion requires typing its exact name and checking its current revision. It removes that zone’s records; PTR records in other zones are retained for separate review. The final apex NS and SOA cannot be removed through ordinary record forms.

## Automatic PTR and partial changes

For A/AAAA record sets, **Manage matching PTR records** looks for the longest matching managed reverse zone. Missing reverse coverage is rejected before changing the forward record. `10.0.20.10` becomes `10.20.0.10.in-addr.arpa.`; with a `/24` reverse zone its relative owner is `10`. IPv6 addresses use the full reversed 32-nibble owner.

Automatic PTR changes preserve existing values. Forklift tracks values it added; explicit manual PTR edits relinquish that automatic ownership. A PTR set changed outside its recorded revision is preserved for review rather than overwritten or deleted. Removing/changing forward addresses cleans up only unchanged, tracked PTR values. This is record-set management, **not yet automatic Host registration**.

Forward and reverse zones cannot be changed atomically. Durable pending-change plans record exact before/after sets. Interrupted or failed operations appear in **Pending DNS changes**. Retry checks actual state, skips already applied steps and refuses conflicting changes. New record operations wait for pending work to be resolved. **Review complete; keep applied steps** closes an operation without rolling back or deleting already-applied records; inspect both forward and reverse results first. LDAP and DNS data are independent.

## AdGuard Home conditional forwarding

In AdGuard Home's **Settings → DNS settings → Upstream DNS servers**, add the internal forward zone while retaining your existing general upstreams:

```text
[/ad.ilpe.me/]10.0.20.2:1053
```

In the separate **Private reverse DNS servers** field, add the private reverse zone:

```text
[/20.0.10.in-addr.arpa/]10.0.20.2:1053
```

Enable **Use private reverse DNS resolvers**. Private-range reverse upstreams belong in that separate field; putting them only in the main upstream list does not route private PTR queries. Add corresponding IPv6 reverse zones there if needed. Test an internal forward name and PTR through AdGuard before changing client DNS settings. Forklift does not modify AdGuard automatically. See [AdGuard's domain and private-reverse forwarding documentation](https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration#specifying-upstreams-for-reverse-dns).

NPM proxies only Forklift HTTP/HTTPS. DNS uses ordinary UDP/TCP networking, never an NPM HTTP Proxy Host.

## Backup, restoration and migration boundaries

The DNS page exports individual zones as BIND-format text through the documented PowerDNS API. These exports are useful for inspection and recovery planning, but are not a complete snapshot of configuration, credentials or Forklift's PTR/pending-change metadata. Bulk import is planned; do not assume an exported file can currently be uploaded back into Forklift.

**Existing Forklift encrypted backups cover LDAP, Forklift metadata and LDAP secrets, not the separate DNS database/secrets volumes.** Until integrated DNS backup/restore is implemented, take a consistent infrastructure backup through your Docker/volume backup system: stop the DNS container cleanly, back up `dns_data` and `dns_secrets` together, preserve the matching application metadata snapshot, then restart it. Do not copy only a live SQLite main file while omitting its WAL. SQLite's supported online backup API is another consistent option for an infrastructure backup tool; manual database writes for zone changes are unsupported.

Restore matching DNS data/secrets into empty target volumes with UID/GID10001 ownership, retain the schema marker/configuration and use the matching image revision. Keep the DNS port fenced until API, SOA serials and representative UDP/TCP answers are verified. Never overwrite the LDAP volumes to restore DNS. Do not restore old pending plans blindly beside a newer DNS database: revisions may conflict; review and reconcile them. Missing secrets, integrity errors and schema mismatches fail closed with startup diagnostics. Integrated encrypted DNS restore and tested cross-version schema migrations remain Phase 4 work.

For AD DNS migration, retain AD until independently verified. Export zone records through the existing Windows DNS administration tools (for example `Export-DnsServerZone` or `Get-DnsServerResourceRecord`), identify ordinary supported records, and recreate those through Forklift's validated forms. Validate SOA/NS, forward/reverse answers, MX/SRV/TXT and TTLs against both services before changing conditional forwarding. Automatic AD export ingestion and bulk BIND import are not implemented. AD-integrated update permissions, Kerberos and Windows discovery/service records do not become equivalent services merely by copying DNS records.

## Status and remaining phases

API connectivity, local authoritative UDP probe, SOA serials and record counts use actual backend state. A healthy process/API does not establish replication health. Phase 1 explicitly reports **replication not configured**. The local probe does not prove clients can cross your firewall or published port; integration tests query both published UDP and TCP sockets.

This release supports at most 128 zones, 100 values per edited set, bounded DNS API responses and 256 KiB record-change requests. Large-directory/load and multi-host DNS replication tests are not yet covered.

Host-owned DNS lifecycle integration, secondary enrollment/TSIG transfers/failover, bulk import and integrated encrypted DNS recovery remain unimplemented. No simulated synchronization or secondary health is shown.
