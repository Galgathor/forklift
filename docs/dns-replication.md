# Legacy DNS secondaries

Current Forklift deployments use [node pairing](peer-controllers.md) to add DNS capacity. This guide documents native secondaries and the controls in releases that offered a separate **DNS servers** panel.

Forklift manages one writable PowerDNS primary and up to eight independent secondaries. Each secondary has its own SQLite database and serves previously transferred zones without Forklift or LDAP. There is no shared database, second management WebUI or automatic primary promotion. LDAP replicas and DNS secondaries are separate deployments and can run on the same second Docker host.

## Check this host’s DNS endpoint

The main stack includes DNS. The WebUI shows its endpoint using the private address from Forklift setup and the published DNS port. If port 53 is already occupied, you can still adjust the Docker listener in your deployment settings. Existing deployments with a saved endpoint override keep that endpoint for compatibility.

## Assignments, updates and diagnostics

**Assign zones** saves the desired selection; **Reconcile DNS server** applies it and requests a native refresh. Existing zone transfers then continue through native NOTIFY/SOA refresh without Forklift. New zones require an explicit assignment. Removing an assignment deletes only that enrollment's secondary copy. Confirmed primary zone deletion also removes its assignments; unavailable secondaries retain a visible retry error until reconciliation. Primary zone data is never deleted by deassigning a secondary.

Assigned Forklift-owned zones become native Primary zones; unassigned zones remain Native. Both stay editable in Forklift, including host-owned forward/PTR registration. Existing serial-increase policy is retained. Native transfers carry ordinary DNS zone data; PowerDNS comments and Forklift ownership metadata stay in the primary management installation.

The manager sets native transfer keys and zone metadata through the documented [PowerDNS API](https://doc.powerdns.com/authoritative/http-api/zone.html). Each secondary gets a separate HMAC-SHA256 TSIG key and only assigned zones authorize it. IP-only transfer exceptions, secondary retransfers and unauthenticated DNS UPDATE are disabled. Notifications are restricted to the registered primary IP and are unsigned: [PowerDNS signs each zone’s NOTIFY with only its first key](https://doc.powerdns.com/authoritative/settings.html#send-signed-notify), which conflicts with independent per-node transfer keys. A notification only prompts a refresh from the already-configured primary; the actual transfer still requires that secondary’s TSIG key. Native [AXFR transfers](https://doc.powerdns.com/authoritative/modes-of-operation.html) are used; the secondary may request IXFR, but PowerDNS Authoritative 5.1 serves a complete AXFR fallback rather than incremental IXFR data. There is no custom replication of SQLite files.

**Check synchronization** obtains fresh pinned-HTTPS diagnostics and actual authoritative SOA responses. A connected API, healthy container or responding server does not by itself mean synchronization succeeded. The dashboard shows per-zone expected and observed serials, primary reachability from the secondary, last check and last confirmed synchronization. These timestamps are observations, not continuous monitoring. If the primary is unavailable, current synchronization cannot be confirmed; the last confirmed time is retained. An unreachable management port reports management availability as unknown without claiming that DNS stopped.

Publish appropriate secondary NS/glue records through DNS when the zones are delegated, or configure your existing resolver's conditional forwarding to use **both** authoritative endpoints. Forklift does not change another resolver automatically. Validate representative forward/reverse queries through that resolver before changing clients. A pair of responding servers alone does not give clients failover unless their resolver configuration uses both.

## Outages, removal and recovery boundaries

A secondary continues answering previously synchronized zones after a primary/manager outage, including container recreation, until the SOA expiration interval is reached. It cannot receive new changes while the primary is offline. On recovery, native SOA checks resume transfers; reconciliation can request an immediate refresh. Primary failure does not promote the secondary or enable administrative writes there.

Removing a DNS node first revokes its transfer authorization at the primary, then removes its managed secondary zones. If either step fails, the record remains with an actionable removal error. Retry in the WebUI. After transfer revocation is confirmed, **Keep data; forget node** explicitly retains its remote copy and removes inventory. Stop/remove the old Docker stack separately through your hosting tool: a retained server can answer stale cached zones until expiration. No other DNS server or unrelated zone is deleted.

[TSIG](https://doc.powerdns.com/authoritative/tsig.html) authenticates transfers and detects tampering; it **does not encrypt** zone contents. Use trusted private networks or a VPN, and keep peer clocks synchronized because TSIG signatures have a bounded time window. HTTPS management uses a locally generated pinned RSA leaf certificate valid for one year. Rotate it through the WebUI before expiration; an already expired identity requires replacement enrollment.

## Rotate credentials and certificates

Use **Rotate DNS credentials** on an enrolled server. Forklift journals a new credential epoch, temporarily authorizes both transfer keys, updates the peer and proves a real signed transfer with the new key for every assigned zone. It retires the old transfer key after verification; the peer stops accepting its old management token when applying the new configuration. If interrupted, use **Resume DNS credential rotation**. An unavailable primary leaves overlap visible until a retry can verify and retire it. Do not edit assignments or start another identity transition during rotation.

Use **Stage DNS certificate**, then **Finish DNS certificate rotation**. The private key stays on the secondary; Forklift records the new public pin before activation. Activation verifies a fresh HTTPS connection trusting only the new certificate and then retires old files/trust. Interrupted publication recovers from a peer-local journal; retry the pending operation in DNS servers. Native DNS keeps serving throughout certificate changes. Button labels may indicate a pending operation; completion is based on actual peer verification.

Upgrade older secondary containers from the current repository, retaining their volumes, before rotating identities. Older helpers continue transfers and ordinary reconciliation but are explicitly refused by the new rotation operations. See [upgrade and recovery procedures](dns-recovery.md).

Encrypted installation backups include the **primary** DNS snapshot, installation secrets and matching management metadata. They do not capture remote secondary private keys/databases. After full restore, old peers must stay fenced: transfer authorization is cleared and archived enrollments require explicit removal/re-enrollment. Keep a consistent local secondary-volume backup if needed for disaster planning; resynchronizing a fresh secondary from the recovered primary is the supported management workflow. Do not reset existing LDAP or primary DNS volumes to add or upgrade a secondary.

Set forwarding once under **DNS → DNS forwarding**. Updated, enrolled DNS peers copy and store the settings automatically. For DNS failover, assign the same zones to both machines, make sure both can reach the upstream servers, and give clients both DNS addresses in advance. Use **Check synchronization** to verify zone copies and the last applied forwarding settings separately.
