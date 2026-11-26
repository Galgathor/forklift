# DNS management

PowerDNS Authoritative is a standard part of Forklift. It uses its own persistent SQLite database and continues answering configured zones when the manager or LDAP is stopped. DNS outages do not block LDAP startup, readiness or authentication. The primary can forward queries for other zones to an existing DNS resolver. There is no Kerberos, Windows domain join or automatic primary promotion.

## Deployment and existing installations

Update/rebuild the existing Compose deployment normally. Keep all existing volumes: no LDAP reinitialization or metadata schema reset is needed. Three additional volumes hold DNS data/configuration (`dns_data`), generated credentials (`dns_secrets`) and protected Unix control (`dns_control`). The manager does not depend on DNS container health.

PowerDNS Authoritative **5.1.5** is pinned by image digest. It initializes the upstream Generic SQLite3 schema once, validates existing storage and refuses an unreviewed schema change rather than recreating a database. Back up before upgrading. See the [upstream release notes](https://doc.powerdns.com/authoritative/changelog/5.1.html) and [SQLite backend documentation](https://doc.powerdns.com/authoritative/backends/generic-sqlite3.html).

Configure these deployment settings before starting/recreating containers:

```dotenv
FORKLIFT_DNS_BIND=0.0.0.0
FORKLIFT_DNS_PORT=53
```

New installations accept DNS on host interfaces. Restrict access to your private network with Docker-aware firewall rules. Forklift automatically uses the private server address selected during setup for replication; you do not need to enter it again. You can limit the Docker listener to the same private address selected in Forklift setup. Existing localhost-only settings are preserved. If another service owns port 53, choose a different address/port, for example `192.168.1.2:1053`. TCP **and** UDP are published. Forklift does not change your resolver or host DNS settings.

Docker publishes host ports, not an additional LAN IP for a container. A service bound to `0.0.0.0:53` may conflict even if PowerDNS uses a specific host IP. Use a nonstandard port plus conditional forwarding, a separate host/IP, or reconfigure the existing service through its own management interface. Ordinary clients generally expect port 53 and cannot use a custom port supplied through standard DHCP DNS settings. Docker-published ports may bypass some host firewall rules; restrict intended client networks using appropriate Docker-aware rules. IPv4 is the current publishing default; AAAA data can still be served over IPv4 DNS transport.

The primary PowerDNS REST API binds **only to container loopback**. Forklift accesses it over an authenticated protected Unix socket; there is no API TCP port published or exposed through NPM. Internal supervisor operations are fixed health/rotation actions, not arbitrary commands or configuration directives. Runtime UID is 10001 with no capabilities and a read-only root filesystem. API credentials are generated locally, stored in restricted volume files and never sent to the browser. Settings in the DNS page can rotate the API credential, briefly restarting DNS.

## Zones and record sets

Open **DNS → Create zone**. Choose:

- Forward: an internal domain such as `example.test`.
- Private IPv4 reverse: an aligned RFC1918 `/8`, `/16` or `/24`, such as `192.168.1.0/24` → `1.168.192.in-addr.arpa.`. Classless RFC2317 delegation is not implemented.
- ULA IPv6 reverse: a nibble-form zone within `c.f.ip6.arpa.` or `d.f.ip6.arpa.`, for example `d.f.ip6.arpa.` for `fd00::/8`.

Specify the primary nameserver and, when it belongs to the new zone, its IPv4/IPv6 address. Forklift creates SOA, NS and any in-zone nameserver address. Additional NS values can be edited afterward. Zone settings expose SOA mailbox/name/timers; SOA serials increase through PowerDNS's `INCREASE` API policy. Joined nodes receive managed zones automatically. [Pair a Forklift node](peer-controllers.md)

Select a zone to manage A, AAAA, CNAME, PTR, TXT, MX, SRV and NS record sets. Enter one value per line; editing replaces that selected set, not other types at the same owner. Relative names belong to the selected zone; `@` means its apex. Absolute names must stay inside that zone, and owners covered by a more specific configured zone must be edited there. CNAMEs cannot coexist with other records or occupy the apex. Duplicate values are rejected. TXT values use quoted DNS presentation strings; MX uses `priority target`, SRV uses `priority weight port target`. Hostname targets are treated as full names, not silently appended to the zone.

Read-only revisions reject stale edits. Only Forklift-owned Native/Primary zones (`account=forklift`) are editable. Avoid concurrent external API/database writers: PowerDNS does not provide transactional compare-and-swap across independent clients. Zone deletion requires typing its exact name and checking its current revision. It removes that zone’s records; PTR records in other zones are retained for separate review. The final apex NS and SOA cannot be removed through ordinary record forms.

## Automatic PTR and partial changes

For A/AAAA record sets, **Manage matching PTR records** looks for the longest matching managed reverse zone. Missing reverse coverage is rejected before changing the forward record. `192.168.1.50` becomes `50.1.168.192.in-addr.arpa.`; with a `/24` reverse zone its relative owner is `50`. IPv6 addresses use the full reversed 32-nibble owner.

Automatic PTR changes preserve existing values. Forklift tracks values it added; explicit manual PTR edits relinquish that automatic ownership. A PTR set changed outside its recorded revision is preserved for review rather than overwritten or deleted. Removing/changing forward addresses cleans up only unchanged, tracked PTR values. For automatic host registration, use the Hosts workflow below.

Forward and reverse zones cannot be changed atomically. Durable pending-change plans record exact before/after sets. Interrupted or failed operations appear in **Pending DNS changes**. Retry checks actual state, skips already applied steps and refuses conflicting changes. New record operations wait for pending work to be resolved. **Review complete; keep applied steps** closes an operation without rolling back or deleting already-applied records; inspect both forward and reverse results first. LDAP and DNS data are independent.

## Host DNS registration

In **Hosts → Register host** (or **Edit host**), enable **Manage this host’s DNS records**. Select an existing managed forward zone, enter its relative name or FQDN, an IPv4 address and optional IPv6 address. For example, `server` in `example.test.` with `192.168.1.50` creates `server.example.test. A 192.168.1.50`. The inventory hostname and DNS name are separate fields; review both when renaming a machine.

**Create matching reverse DNS** requires managed reverse zones covering every supplied address. Create `192.168.1.0/24` first for the example above; its PTR owner is `50.1.168.192.in-addr.arpa.`. IPv6 registration requires a covering ULA nibble reverse zone. Missing coverage or CNAME/zone conflicts leave a saved host with an actionable DNS error, without partially applying that new plan.

Directory machines, including the primary, can manage DNS through the same form. Login groups may be empty for DNS-only inventory; DNS registration never grants SSH or sudo permissions. Configuring Linux login still requires permitted groups and deployment of the client configuration. Removing a directory server retains its DNS-managed host inventory so its records can be reviewed and explicitly retained/deleted through Hosts.

Saving a host and changing DNS are independent operations. Host saves survive DNS outages. Leave **Apply DNS changes after saving** checked, or uncheck it to review later. **Reconcile DNS** applies pending settings, retries failed work and checks ownership against current native record sets. Status is the last confirmed application result, not continuous host/service monitoring. Inventory edits from older API clients that omit DNS preserve the existing desired name and defer reconciliation. Host revisions protect concurrent edits; DNS settings changes also advance the configuration revision.

Forklift tracks individual values in its metadata and [PowerDNS record-set comments](https://doc.powerdns.com/authoritative/http-api/zone.html#comment). It merges host values into existing record sets, preserving unrelated values, disabled flags, comments and TTLs. Preexisting identical values are preserved without taking ownership. Editing a record set through DNS releases host ownership of the edited values and flags the host for review. Removing ownership comments or disabling a value externally also prevents automatic deletion of that value. Do not edit DNS SQLite files directly or run concurrent external API writers; record revision checks cannot provide atomic compare-and-swap with independent administrators.

Changing addresses or DNS names removes only still-owned old values and creates the new values/PTRs. A desired value already disabled in PowerDNS produces a visible registration error and is preserved. Disabling DNS management or deleting a host requires an explicit choice: **Keep records and release ownership** or **Delete only this host’s managed values**. Host deletion revokes its LDAP credential independently. If DNS cleanup fails after host deletion, **DNS → Host DNS tasks** retains a durable cleanup task. Retry there, or explicitly keep already-applied records to close the task. Superseding an unfinished host plan cancels its old retry and checks ownership of every possibly applied value before cleanup. Pending DNS plans block other record mutations until resolved.

Existing installations need no storage reset. Desired settings and ownership metadata are additive; older host rows remain unmanaged until configured. Preserve matching Forklift metadata with DNS data during infrastructure backups, because ownership and pending cleanup plans live in the manager’s SQLite database.

## Forwarding through Forklift

Open **DNS → DNS forwarding**. Enable **Forward queries for other zones**, enter your upstream server’s IP address and port (usually `53`), and list the private networks allowed to use it. For example, use router `192.168.1.1` and client network `192.168.1.0/24`. Save the form. No Compose edits or extra published ports are needed after updating the manager, DNS and maintenance images.

You can enter up to four upstreams. The first healthy server is preferred; another is selected when health checks mark it unavailable. A query already in flight may fail during that transition. If all upstreams are unavailable, external queries return `SERVFAIL`; local zones continue answering. Allowed networks apply to forwarded queries only. Queries outside those networks are refused instead of creating an open public resolver. Localhost queries passing through Docker NAT may appear to come from the private Docker bridge address; allow that private network too if local forwarding is needed.

Managed forward and reverse zones always go to OpenLDAP-independent PowerDNS storage. Missing names and missing record types within those zones remain authoritative negative answers, even if an upstream has a different answer. Creating or deleting a zone immediately updates routing. Zone transfers still require the existing TSIG permissions. Forwarding is disabled initially; disabling it restores authoritative-only behavior.

This uses the pinned Debian `dnsdist` package (`1.9.16-0+deb13u1`) inside the existing DNS image. Its public listener remains container port `5353`; PowerDNS Authoritative and its API listen only on container loopback. The supervisor generates a fixed configuration from validated fields. Administrators cannot submit Lua, configuration directives or commands. No DNS protocol is implemented in Forklift. Routing follows [dnsdist’s documented rules](https://www.dnsdist.org/reference/rules-management.html) and [primary transfer handling](https://www.dnsdist.org/advanced/axfr.html).

Upstreams must already provide the DNS answers you need. This is query forwarding, not a new full recursive resolver: Forklift does not walk internet delegations, validate DNSSEC independently or chase external CNAME targets for an authoritative answer. A local alias pointing outside its managed zone may need a follow-up query from the client. Use your existing recursive resolver if that behavior is required. Upstream DNS uses ordinary UDP/TCP; DNS-over-TLS/HTTPS is not implemented. Do not use Forklift itself as an upstream, or configure an upstream to send the same queries back to Forklift.

The manager automatically sends saved forwarding settings to updated, enrolled DNS peers over their authenticated management connections. A peer keeps its last applied settings on disk and can forward queries while the manager and original DNS server are offline. Only assigned zones are served on each peer. Queries inside other known Forklift zones stay local and are refused when the peer has no copy. For failover, assign the same zones to both servers and give clients both DNS addresses ahead of time. Choose upstreams reachable from both DNS servers. DNS server checks report forwarding settings separately from zone synchronization.

Update both the main stack and existing DNS peers to use this feature. A saved change applies to the main DNS server first. Peers normally receive it on the next sync pass, about ten seconds later, and disconnected peers catch up automatically. Backups include the main server's forwarding settings. Older backups without forwarding settings restore with forwarding disabled. Applying a changed policy briefly restarts the DNS listener.

## Conditional forwarding with an existing resolver

Keep your existing recursive DNS service for client resolution, filtering and general upstream queries. Configure its conditional-forwarding, stub-zone or equivalent rules for the zones hosted by Forklift:

| Zone | Authoritative endpoint |
| --- | --- |
| `example.test` | `192.168.1.2:1053` |
| `1.168.192.in-addr.arpa` | `192.168.1.2:1053` |

Use your actual domain, reverse zone, address and published port. Resolver products differ in their syntax, support for nonstandard ports, and handling of private reverse queries; consult your tool’s documentation. Retain existing general upstreams for other names. Verify forward and PTR lookups through your resolver before changing client settings. Forklift does not change the existing resolver automatically.

NPM proxies only Forklift HTTP/HTTPS. DNS uses ordinary UDP/TCP networking, never an NPM HTTP Proxy Host.

## Backup, restoration and migration boundaries

The DNS page exports BIND text for inspection and **JSON** for supported record migration. **Import records** accepts Forklift JSON exports or PowerDNS zone JSON, shows a before/after preview and requires the exact zone name plus confirmation. Merge preserves existing values/TTLs/disabled flags; Replace replaces only listed sets. Unlisted sets and the current SOA/serial policy remain. Imports use the native API and the same durable pending-change/retry machinery as record forms. BIND text and arbitrary configuration directives are not imported. See [formats and limits](dns-recovery.md#reviewed-zone-import).

Settings creates encrypted installation backups containing primary DNS SQLite, its schema marker and credentials, alongside LDAP, Forklift metadata and installation secrets. SQLite's online backup API captures DNS while it continues answering; do not copy only a live main file while omitting its WAL. Full restoration validates the pinned schema, fences native services and strips archived transfer authorization before publishing DNS. Archived secondary enrollments are quarantined for explicit replacement. See [backup, restoration and upgrades](dns-recovery.md).
For AD DNS migration, retain AD until independently verified. Export zone records through the existing Windows DNS administration tools (for example `Export-DnsServerZone` or `Get-DnsServerResourceRecord`), identify ordinary supported records, and recreate those through Forklift's validated forms or convert ordinary supported records into the reviewed JSON import format. Validate SOA/NS, forward/reverse answers, MX/SRV/TXT and TTLs against both services before changing conditional forwarding. Automatic AD export ingestion and bulk BIND import are not implemented. AD-integrated update permissions, Kerberos and Windows discovery/service records do not become equivalent services merely by copying DNS records.

## Status and remaining phases

API connectivity, local authoritative UDP probe, SOA serials and record counts use actual backend state. A healthy process/API does not establish replication health. Unassigned single-node deployments report **replication not configured**; assigned primaries report replication configured, while legacy secondaries have separate transfer checks. Joined-node DNS copy status is shown under **Directory Servers**. The local probe does not prove clients can cross your firewall or published port; integration tests query both published UDP and TCP sockets.

This release supports at most 128 zones, 100 values per edited set, bounded DNS API responses and 256 KiB record-change requests. Large-directory/load and separate physical-host network/firewall tests are not yet covered.

For existing native secondaries, see the [legacy DNS replication guide](dns-replication.md). Reviewed JSON import, in-place secondary credential/certificate rotation and integrated encrypted primary DNS recovery are implemented; their limits and recovery procedures are in [DNS recovery](dns-recovery.md). No simulated synchronization or secondary health is shown.

To edit managed zones from a second Forklift manager running the standard Compose stack, see [Node pairing](peer-controllers.md#dns-writes-from-every-paired-webui).
