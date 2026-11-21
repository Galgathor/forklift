# DNS recovery and upgrades

Routine DNS administration, backups, imports and identity rotation are available in Forklift. Your Docker hosting tool remains responsible for image deployment, persistent-volume protection and network/firewall configuration.

## Installation backups

In **Settings**, generate and store a private recovery key, create an encrypted backup, and download its separate trusted checksum receipt. Verify the archive through Settings before relying on it. New archive format **3** includes:

- LDAP data/configuration, signing authority and service credentials.
- Forklift metadata, including allocation history, host DNS ownership and pending operations.
- The primary PowerDNS SQLite snapshot, pinned schema marker and primary API/control credentials.

DNS stays authoritative while SQLite's supported online backup API captures a consistent snapshot. The manager drains administrative writes, closes its metadata connection and briefly pauses LDAP for its own snapshot. DNS changes made outside Forklift are not coordinated; use a single management writer. Plaintext staging is restricted to the custodian and removed after completion/acknowledgment. Encrypted archives contain authentication secrets; protect the archive, checksum and private recovery identity separately.

Remote LDAP/DNS servers and their local private keys/databases are **not** included. Resynchronizing fresh replicas from the restored primary is the supported recovery workflow. BIND or JSON zone exports alone are not installation backups: they omit credentials, ownership and enrollment metadata.

Older 0.5 **format-2 LDAP-only archives** remain verifiable. Their result explicitly says DNS is absent. Full installation restoration rejects them before changing live data; use the matching older release in an isolated recovery environment or obtain a format-3 backup first. No storage reset is needed to upgrade a working schema-5 installation.

## Restore and interruption

1. Fence the original LDAP and DNS primaries **and every old replica** through your hosting/network controls. Never publish two writable primaries or restored stale replicas.
2. Use **Settings → Restore** or the first-run **Restore from backup** flow. Provide the trusted checksum, recovery key, target LDAP listener and future Unix ID floor. Confirm replacement of LDAP/DNS data.
3. Forklift validates archive integrity, exact supported DNS schema and native LDAP data before replacement. It snapshots current target storage for rollback and fences both native services with durable markers outside their replaced volumes.
4. DNS starts privately on container loopback, removes archived transfer keys/ACLs/notifications and returns restored zones to standalone Native mode before exposing DNS. LDAP renews the target listener certificate. Sessions and old enrollment tokens are invalidated.
5. Sign in with an archived administrator. Complete the recovery review, confirm the intended primary DNS endpoint, inspect forward/reverse UDP/TCP answers and reconcile host DNS ownership. Archived pending record plans are closed for review rather than blindly replayed.
6. Remove quarantined DNS inventory and enroll fresh secondary stacks. Keep old peer storage fenced: clearing primary transfer permissions cannot remotely erase old answers or private keys. Directory replicas require their own reseeding review.

Interrupted replacement keeps native services offline even if containers are recreated. DNS recovery control remains available while fenced even when partially replaced native storage cannot be opened. The progress dialog offers **Resume** and eligible **Roll back** operations. Rollback restores the pre-operation LDAP/DNS snapshot and credentials and revokes sessions. Do not delete offline markers, journals or staging manually. Recovery authorization is limited to the initiating session/bootstrap identity and recorded operation; see [operations](operations.md) for administrator lockout recovery.

Restoration is a full installation operation, not an independent DNS point-in-time rollback. DNS serials and cached answers can move backward relative to outside clients; plan resolver cache review and fresh replica enrollment. Do not reconnect stale secondaries to restored zones.

## Reviewed zone import

Select an existing zone, then **Export JSON** or **Import records**. Supported input is Forklift format-1 JSON or PowerDNS zone JSON (`name` instead of `zone`):

```json
{
  "format": 1,
  "zone": "example.test.",
  "rrsets": [{
    "name": "server.example.test.",
    "type": "A",
    "ttl": 300,
    "records": [{"content": "192.168.1.50", "disabled": false}]
  }]
}
```

Create the destination forward/reverse zone first. Import previews validate A, AAAA, CNAME, PTR, TXT, MX, SRV and NS values, ownership, child-zone boundaries and conflicts. SOA input is skipped with a warning: the existing SOA/serial policy is preserved. Names may be relative or absolute; hostname targets are full names. Server settings, credentials, native comments and configuration directives are never applied from the file. BIND text import is not supported.

**Merge** appends missing values while preserving existing TTLs and disabled flags. **Replace listed record sets** replaces only the sets present in the file. Both retain unlisted sets; neither deletes the zone or generates PTRs automatically. A changed set releases automatic PTR/host ownership and can require review in Hosts. Export includes SOA for reference and ordinary records, not ownership or secrets.

The WebUI accepts files up to 240 KiB; the API request limit is 256 KiB. Each import is bounded to 512 sets, 5000 total values and 100 values per set. Large exports may need splitting into reviewed batches. Type the exact zone name and confirm the preview before applying. If the zone, content or ownership changed, generate a new preview. Partial native changes remain in **Pending DNS changes**, with conflict-checked retry or explicit retention of applied steps.

## Upgrade and identity maintenance

Before upgrading, create/download/verify a current backup. Rebuild/redeploy the primary stack through your hosting tool while retaining **all** volumes. Then upgrade each secondary from the same repository revision, rebuilding its image and recreating its container with its existing volume. Already enrolled peers do not need a new join token. Ordinary Phase 3 transfers/reconciliation remain compatible; new rotation operations refuse older helper versions before recording an identity transition.

Use **Rotate DNS credentials**, **Stage DNS certificate** and **Finish DNS certificate rotation** in DNS servers. Retry interrupted operations there. New signed transfers and a fresh connection trusting only the staged certificate must succeed before old permissions/trust retire. Keep clocks synchronized and rotate certificates before expiry; an expired/unrecoverable pinned identity requires a fresh enrollment. Primary API credentials rotate separately through DNS settings, with a brief native DNS restart.

PowerDNS remains pinned to 5.1.5 and its shipped SQLite schema. Startup/restore refuse mismatches instead of initializing over existing data. Schema-changing engine upgrades need a reviewed migration; none is claimed here. Restore supports Forklift-owned Native/Primary zones and supported record types, not custom DNSSEC, Lua, custom SQLite objects or arbitrary native metadata. Preserve an older matching release and backup when running unsupported customizations.

## Operational limits

There is no scheduled backup, recursive resolver, automatic primary promotion, distributed transaction or continuous replication monitor. DNS health and last-confirmed synchronization are separate observations. TSIG authenticates transfers without encrypting their contents; use trusted private networking/VPN. Validate backup space, routing, client resolution and recovery on your own hosts. Single-host container drills do not certify separate-machine firewall/NAT behavior or long-lived partitions.
