# Operations and recovery — 0.5

All routine directory operations are in **Settings**. The old Python administrator CLI and certificate-renewal/primary-preparation scripts have been removed. Start the Docker deployment once; Forklift manages its own directory configuration thereafter. Infrastructure upgrades, resolver forwarding, firewall rules and Linux client deployment remain the responsibility of your hosting environment.

## Back up and verify

1. Open Settings and generate a recovery key. Your browser downloads the **private age recovery identity once**. Store it in a password manager or protected offline location. Forklift retains only the public encryption recipient.
2. Create an encrypted backup. Forklift drains administrative API requests, checkpoints/closes SQLite, pauses the LDAP primary, records its snapshot and restarts the directory. Primary DNS is captured through SQLite's online backup API and keeps serving. The progress dialog remains available. Healthy replicas continue serving authentication.
3. Download the archive and its creation receipt. Keep the receipt/checksum in a trusted location separately from the ciphertext. Downloaded keys and backups do not belong in Git or bug reports.
4. Test verification: upload the archive, enter the trusted creation-time SHA-256 checksum and select its private recovery key. Verification checks authenticated age decryption, strict archive paths/types/count/size/hash limits, schema-5 SQLite integrity, native OpenLDAP configuration/data readability and the supported DNS schema/data scope. It does not replace live data.

Recovery keys are transmitted only over HTTPS or localhost and held in temporary memory/tmpfs during decryption. They are excluded from persistent job records. New archives contain LDAP and primary DNS data, metadata, service secrets and the signing authority; protect them accordingly. Backup encryption is native age, not a custom protocol. There is no backup scheduler yet.

Uploads are limited to 8 GiB ciphertext and extracted snapshots default to 8 GiB (bounded configurable limit). Ensure adequate space for the archive, staging, current directory and rollback snapshot. Set your reverse proxy's upload limit appropriately. Losing the private recovery identity makes the archive unrecoverable.

## Restore

Use the first-launch wizard's **Restore from backup** option on a fresh deployment, or Settings on an existing installation. Initial restoration uses the local one-time installation key; no temporary dummy directory or admin account is necessary.

Before confirming:

- Stop/fence the original LDAP and DNS primaries and all old directory/DNS replicas. Prevent old hosts from presenting stale identities; restored metadata alone cannot stop remote machines. Never create two writable primaries.
- Choose the target's private listener in the form. Its certificate is renewed for that address automatically; the target's current browser origin is preserved.
- Supply a future Unix ID floor greater than every allocation ever made, including allocations after the snapshot. The archive cannot know that later history.
- Confirm replacement of the target's data, upload the archive, and supply its separately trusted checksum and private age identity.

Forklift validates before replacing anything, pauses LDAP and DNS, saves a coherent rollback snapshot, publishes validated state, renews the target LDAP certificate and verifies native startup. DNS restarts with archived transfer rights removed. It keeps staging/rollback until the manager reopens and integrity-checks metadata. Restored passwords and existing numeric IDs survive; sessions and pending enrollments are revoked, old replica records are quarantined, and normal writes require the WebUI recovery review. Sign in with an administrator from the snapshot, review Settings, fence/reseed old replicas, regenerate affected host bundles, then explicitly enable writes.

A live restore revokes your old session. Initial restore similarly transitions from the bootstrap key to the archived administrator identity. The private key is never stored for later use.

## Interrupted operations

The progress dialog records the actual durable phase and offers **Resume** or, for eligible restores, **Roll back**. Reloading/restarting the manager or worker preserves the recorded operation. A verified restore can resume without re-entering its private key. Interruption before verification requires selecting the archive/key again.

Protected offline markers outside replaced LDAP/DNS storage prevent native startup during incomplete replacement, including container recreation. The manager blocks unrelated APIs while maintenance is active. Recovery authorization is limited to the initiating session (or installation key), its expiry, recorded job and CSRF nonce. It permits status/resume/rollback only; it cannot start arbitrary new privileged work while LDAP authorization is unavailable. Completed jobs cannot be replayed. If that session expires and you cannot sign in, use the local emergency recovery exception below.

Do not manually delete job journals, markers, staging or rollback storage. Preserve all volumes if recovery fails. Repeatedly recreating data volumes is not a recovery procedure.

## Credentials, certificates and addresses

Settings can rotate the manager's LDAP service credential with a durable journal, verify the new bind, and revoke administrative sessions. Sign in again afterward. The credential is stored in protected mounted secret files because LDAP binds require it; it is never stored in SQLite or logs.

Primary certificate renewal keeps the installation CA and existing DNS/IP SANs so clients keep trusting the same CA. Changing the private listener checks that the address belongs to this host and the port is available, signs the selected identity and restarts the supervised directory. Existing host endpoints are revised; regenerate/deploy affected host bundles. Directory Servers shows replicas needing **Reconnect primary** after an address change.

Replica credential/certificate operations use the node's pinned-TLS fixed-operation control service. Staging a replica certificate adds both pins and marks affected SSH host bundles for export. Deploy combined trust before activating, then deploy the final bundle after retirement. See [replication](replication.md).

## Persistent storage and upgrades

Named volumes separate directory data, manager metadata, manager credentials, runtime directory credentials, signing authority, encrypted backups, uploads, work journals and protected control/LDAPI sockets. The CA private key is mounted only into the non-root, network-isolated custodian. Manager and directory containers cannot read it.

Version 0.5 uses metadata schema **5**. New encrypted backups use archive format **3**, including primary DNS. Earlier 0.5 format-2 LDAP-only archives can be verified, but full restoration requires a DNS-inclusive archive or their matching earlier release. Pre-0.5 storage/archives are deliberately refused. Preserve old data and use its matching release; deploy fresh volumes for 0.5. Do not mount old directory data beside new empty metadata, which would lose Unix allocation history.

For future updates, create/download/verify a matching backup first and test restoration on an isolated, fenced installation. Deploy the new images through your Docker hosting UI. Do not roll back only one database or use an older binary against newer metadata. Container recreation preserves volumes; volume deletion does not.

The LDAP control health check reports supervisor reachability so the management plane can stay up before setup/during recovery. `/health` is manager liveness; `/ready` performs a real directory read and metadata check when normal operation is available. Directory Servers reports actual LDAPS reachability and synchronization evidence. Failed readiness during offline maintenance is expected.

## Emergency console exception

Only when no administrator can sign in:

```sh
./scripts/emergency-recovery.sh
```

The console tool prompts without password echo, can finish or roll back an existing interrupted job, resets an **existing** account, enables it and restores explicit administrator membership. It revokes sessions and audits recovery. If needed, enter the corrected WebUI origin. The wrapper restarts the manager to reload that origin. No public API exposes this action; it requires local Docker access and protected Unix control credentials. It cannot create a new directory or reset UID allocation.

## Diagnostics

The WebUI displays actionable LDAP/TLS, listener and replication errors. Your Docker hosting UI provides container health/logs; credentials and request bodies are not logged. An unavailable primary makes writes unavailable; verified enrolled replicas can still serve read management and Linux authentication. No automatic promotion occurs. For SSSD caching/revocation limits, see [Linux clients](linux-clients.md).

## DNS recovery scope

New encrypted backups include the primary DNS database/schema and credentials, together with matching Forklift metadata. Remote secondaries remain separate; full restoration quarantines their enrollment records and clears archived transfer authorization before DNS resumes. Legacy LDAP-only archives are never presented as full DNS recovery. See [DNS recovery and upgrades](dns-recovery.md) for exact scope, restrictions, rollback, JSON import and rotation procedures.
