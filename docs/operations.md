# Operations and recovery

## Encrypted, consistent backups

Milestone 4 includes a local operator CLI, `scripts/forklift-admin.py`, and an isolated maintenance image. It never runs in the WebUI or receives Docker access through the manager. Requirements: Python 3.11+, local Docker access and this checkout. Build the toolbox before use:

```sh
docker build -t forklift-maintenance -f docker/maintenance/Dockerfile .
python3 scripts/forklift-admin.py keygen --output /safe/off-host-copy/forklift-recovery.txt
```

Use a real private destination outside this checkout; the example path must exist or be writable. Key generation creates a new mode-0600 age X25519 identity and prints **only its public recipient** and file location. Copy the identity to independent protected storage. Losing both this identity and its safe copies makes backups unrecoverable. The backup host only needs the public recipient; keep the private identity off-host between recovery drills.

```sh
python3 scripts/forklift-admin.py backup \
  --recipient age1YOUR_PUBLIC_RECIPIENT \
  --output /private/backups/forklift-2026-11-20.tar.gz.age
```

The CLI discovers the actual primary/manager containers and named volumes, takes a local lock, remembers which containers were running, stops the manager then primary cleanly, checkpoints metadata and snapshots the directory, metadata, `.env` and **all installation secrets including the CA key**. It streams directly into age encryption; it creates no plaintext archive on the host. It records image IDs, checkout revision, architecture, schema and individual file hashes in an encrypted manifest. The new ciphertext file is mode 0600 and cannot overwrite an existing backup. The CLI restarts only the containers that were previously running, LDAP first, and waits for health. Expect a brief primary/management outage; configured synchronized replicas continue authentication independently. This is an offline backup, without a scheduler or online snapshot promise.

Save the printed JSON receipt, especially its SHA-256, in independent trusted storage. Settings shows recorded maintenance results, but an attacker with host/metadata access can change them. **age recipient encryption authenticates ciphertext integrity, not the identity of its creator.** Verification therefore requires the trusted creation-time checksum; do not replace it with a checksum supplied beside an untrusted archive. Copy receipts and ciphertext off-host. A backup on the same disk is insufficient recovery protection.

For non-default deployments, global options precede the subcommand:

```sh
python3 scripts/forklift-admin.py --root /srv/forklift --project forklift \
  --file /srv/forklift/compose.yaml --file /srv/forklift/deploy/primary/clients.compose.yaml \
  backup --recipient age1YOUR_PUBLIC_RECIPIENT --output /private/backups/forklift.tar.gz.age
```

Use your actual overrides; `clients.compose.yaml` is the repository's optional private LDAPS publication override. Named directory/metadata volumes and the standard installation-secret mounts are required. Custom secret sources or customized slapd configurations need a separately reviewed recovery strategy. Do not copy live MDB files or SQLite journals independently. The default uncompressed snapshot limit is 8 GiB, configurable with `--max-gib` (1–64); the helper uses bounded memory and file-count limits. Backups cover the primary installation, not replica volumes or Linux client machines.

## Verify and rehearse restoration

```sh
python3 scripts/forklift-admin.py verify \
  --archive /private/backups/forklift.tar.gz.age \
  --identity /private/recovery/forklift-recovery.txt \
  --sha256 YOUR_TRUSTED_CREATION_TIME_SHA256
```

Verification decrypts into a temporary Docker volume, checks the complete age authentication stream, strict regular-file paths, duplicate/size/hash constraints, SQLite integrity and schema, the fixed generated LDAP configuration and native `slaptest`/`slapcat` readability. It rejects unsupported architectures/configurations. Plan free Docker storage for decrypted staging plus restored volumes. Plaintext staging is protected and removed afterward; deletion is not secure erasure, and the Docker host/storage are trusted. SIGKILL or a host crash can leave a staging volume labeled `io.forklift.maintenance=restore-stage`; inspect and remove only confirmed abandoned staging volumes. Retain appropriate encrypted backups before upgrades and rehearse this procedure regularly on an isolated Docker host.

To restore, use a **fresh checkout at the matching release**, build the manager, LDAP and maintenance images, and use a fresh Compose project with no existing containers, named volumes, `.env` or `.secrets`. Do not run the installer there. Never merge archives into a live installation.

Before starting a restored primary, fence the original primary **and every old replica** at the network/host level. Reconnecting an old replica after rollback can leave obsolete identities and revocations; clients must not authenticate against unfenced old nodes. If rehearsing while production remains available, isolate the entire drill from production networks and clients.

```sh
docker compose build
docker build -t forklift-maintenance -f docker/maintenance/Dockerfile .
python3 scripts/forklift-admin.py --project forklift-recovered restore \
  --archive /private/backups/forklift.tar.gz.age \
  --identity /private/recovery/forklift-recovery.txt \
  --sha256 YOUR_TRUSTED_CREATION_TIME_SHA256 \
  --uid-floor 1000000 --original-fenced
# Review restored .env, port/interface publication, DNS, firewall and certificates.
docker compose -p forklift-recovered up -d --no-build
```

`--original-fenced` is an explicit operator acknowledgment, not remote proof. **Choose a UID/GID floor above every ID ever allocated**, including IDs created and deleted after the snapshot. The tool verifies it exceeds archived LDAP IDs and the allocator, but cannot reconstruct lost history. The numeric example is suitable only if you know no historical allocation reached it. New allocations start at that floor; restored identities retain their original IDs. Do not lower it afterward.

Restore clears all manager sessions and pending enrollment credentials, quarantines recorded replicas as `restore_required`, increments host configuration revisions and records recovery review as required. Services remain stopped until you explicitly start them. Log in using an administrator credential from the snapshot, verify users/groups/IDs and direct LDAP authentication, then complete the review in Settings to enable administrative writes. Review passwords and access revoked after the snapshot: rollback restores their older state. Remove quarantined replica records only after fencing their old nodes; enroll replacement nodes into **empty independent volumes** and confirm synchronization. Redeploy host configuration/trust bundles before returning clients to service. Removing a record never erases its remote disk or terminates existing connections.

A database copy and environment publication use durable incomplete markers. A partially restored volume cannot silently start. `resume` can finish a fully prepared restore after interrupted environment publication. If preparation failed before reaching that stage, preserve the failed target for diagnosis and restore into another fresh target; there is no automatic destructive cleanup. Keep the same explicit project/options on every command. The published environment must retain the target's volume names; review `docker compose config` before starting.

## Interrupted maintenance and service credential rotation

Upgrade to Milestone 4 manager/primary images first. The CLI requires their startup-barrier support. Keep a matching encrypted backup and a local recovery login.

```sh
python3 scripts/forklift-admin.py rotate-service
# After an interrupted operation, using identical root/project/file options:
python3 scripts/forklift-admin.py resume
```

Service rotation stops both services, journals a new random secret in protected installation storage and updates the manager LDAP identity plus the derived monitor identity, when present, using native offline `slapmodify`. It preserves mounted file inodes/ownership, clears manager sessions, restarts the original running containers and verifies an actual TLS-protected service bind. The journal remains until this acknowledgment; startup barriers prevent a mixed LDAP/file state from serving. Resume rolls the same credential forward rather than generating another. An orphaned helper from an interrupted CLI is labeled with its operation ID; resume and service startup refuse to overlap an active helper. Wait for it to finish and retry; investigate a stuck native writer before stopping anything. Never delete journals or incomplete markers to bypass failed maintenance. Do not run overlapping manual maintenance or multiple managers against the same volumes.

User passwords remain unchanged. The monitor password reaches replicas through Syncrepl; wait for confirmed synchronization afterward. Existing LDAP binds/SSH sessions are not forcibly disconnected by password changes. Host read credentials rotate on host-bundle export. Replica replication credentials rotate separately as below. The CLI does not rotate the CA or recover a lost administrator password; retain independently protected administrator access and recovery material.

## Primary TLS renewal

Settings displays configured certificate expiry/fingerprints and stored replica pins, with renewal warnings below 30 days. Configured expiry is not proof that a remote server presents that certificate. For primary leaf renewal, keep the installation CA and every required DNS SAN:

```sh
./scripts/renew-ldap-certificate.sh ldap1.homelab.internal
docker compose restart ldap
curl --fail http://localhost:8080/ready
```

The script retains existing DNS SANs plus `ldap` and adds the provided hostname. It validates the new pair and preserves restricted ownership, replacing both bind-mounted file contents. Run in a maintenance window; a durable local journal rolls interrupted pair replacement forward when you rerun with the same requested hostname, before starting LDAP. The CA key remains local and is never mounted into long-running services. Verify actual client binds and manager readiness after restart. Clients trusting the unchanged CA need no new CA bundle for primary leaf renewal. NPM HTTPS certificates are independent. CA root rotation is a planned manual migration, not an automated feature; renew before expiry and never disable TLS verification.

## Replica certificate and replication credential lifecycle

Upgrade the standalone replica runtime before using lifecycle commands: copy `backend/assets/replica.py` to its private deployment directory as `replica.py`, then `docker compose build replica` and recreate it. New bundles already contain the current runtime. Keep private enrollment/update files excluded from source control and image contexts. Run commands on the **replica Docker host**; no manager-to-host SSH or Docker API is needed.

1. Generate a candidate locally: `docker compose run --rm --no-deps replica stage-certificate > replica-next.crt`. Only the public certificate is printed; its private key stays in the replica volume.
2. In Directory Servers, upload that public file under **Credentials & certificate rotation**. Forklift validates its hostname, lifetime and leaf constraints, trusts current and candidate pins, and increments affected host revisions.
3. Export and redeploy each affected host bundle; these include both certificates. Bundle export rotates that host's read password, so deploy the entire bundle. Check all clients before activation.
4. Stop the replica: `docker compose stop replica`. Activate using `docker compose run --rm --no-deps replica activate-certificate`, then start with `docker compose up -d --no-build`. A local journal resumes a torn pair replacement on startup.
5. Confirm synchronization, then choose **Verify & finalize certificate**. The manager verifies the actual peer presents the staged certificate before retiring its old pin. This marks hosts for a second export/redeployment containing only final trust. Existing deployed host bundles retain old trust until redeployed.
6. Once final trust is deployed and verified, run `docker compose run --rm --no-deps replica retire-certificate` to remove the previous private pair. This command does not prove deployment to clients.

Do not activate before client trust deployment. If activation fails, preserve the journal/candidate and rerun activation or normal startup to roll forward; do not invent a new unpinned certificate. A compromised replica key requires fencing that node, reviewing directory secrets and reseeding from a trusted primary; ordinary overlap is not a compromise-recovery protocol.

**Rotate replication credential** immediately replaces the provider bind password and returns a private update archive. Transfer it privately to the replica host and follow its README: update/build the included runtime, stop the replica, pipe `credential-update.json` into `docker compose run --rm -T --no-deps replica apply-credential`, then start/recreate the replica. Updates are scoped to node/base/provider and monotonically increasing epochs; stale/replayed updates are refused. Check that a newly created directory change synchronizes, proving reconnection with the new credential. Delete transported plaintext update files after protected storage/deployment review. Losing a download can be recovered by issuing a newer update. Existing bound connections can remain alive until disconnected. The dashboard reports **issuance**, never a fabricated remote-deployment receipt.

## Audit, sessions, upgrades and diagnostics

Settings provides literal actor/action/target search, cursor-paginated audit history and NDJSON export. `GET /api/audit` defaults to 50 events (maximum 200); `before` is an exclusive event-ID cursor. `GET /api/audit/export` exports at most 5,000 matching events, with `X-Next-Cursor` for older pages. Both require an LDAP-authorized administrative session. Revoke all administrative sessions from Settings after suspected exposure; this includes your current session. The audit database is local and can be tampered with by host/DB administrators. Arrange external retention for stronger assurance; automatic audit deletion/rotation and tamper-resistant shipping are not implemented.

Before upgrades, create and verify a matching backup and record image IDs/revision. Test the new release on an isolated restored installation. Recreate with `docker compose up -d --build`. Schema 4 upgrades preserve existing identities, hosts, sessions and ID allocation; older code refuses a newer metadata schema. Rollback requires restoring an entire matching snapshot with the recovery precautions above, never only an older image or metadata file.

`docker compose logs --tail=100 manager ldap` shows operational failures. Default primary/manager/generated replica logs rotate at 10 MiB × 3 files per container. API errors omit raw LDAP diagnostics and passwords. `/health` proves process liveness; `/ready` verifies metadata and authenticated verified-TLS directory access, including available replicas. Failed LDAP connectivity/authorization fails closed. Check DNS SANs, expiry, CA files, mounted permissions and clocks for TLS errors. Never disable verification.

Origin errors require matching the exact scheme/hostname/port in `FORKLIFT_PUBLIC_URL`. HTTPS enables Secure cookies; use the proxy hostname. Persistent login throttles apply globally (20 attempts/5 minutes) and per exact username (10/5 minutes); restarts do not clear them. A hostile caller can exhaust this budget, so restrict management network access.

Partial initial setup never resets a directory automatically. If LDAP completed but metadata did not, retry with the same bootstrap token, base and original administrator credentials. For a failed native initialization, preserve the entire volume and inspect logs before any deliberate replacement. Lost metadata requires a matching backup; repeating setup cannot reconstruct historical UID allocation or auditing. Keep local Linux recovery accounts: the management process is unnecessary for normal LDAP authentication, but disconnected replicas and client caches cannot receive new revocations. See [Linux clients](linux-clients.md) and [replication](replication.md).
