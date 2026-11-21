# Operations and recovery

## Consistent offline backup

Stop both services before copying their volumes; copying a running MDB file or SQLite WAL independently is not a consistent backup. Use the same Compose project name as your installation (normally `forklift`). First discover the actual volume names:

```sh
docker volume ls --filter label=com.docker.compose.project=forklift
docker compose stop
mkdir -m 700 backup
```

For a default project, archive each volume with a temporary container. Adjust volume names if you changed the project name. The examples create files owned by root, readable only by root.

```sh
docker run --rm -v forklift_directory:/source:ro -v "$PWD/backup:/backup" alpine:3.22.2 sh -c 'umask 077; tar -C /source -czf /backup/directory.tar.gz .'
docker run --rm -v forklift_metadata:/source:ro -v "$PWD/backup:/backup" alpine:3.22.2 sh -c 'umask 077; tar -C /source -czf /backup/metadata.tar.gz .'
sudo tar -czf backup/installation.tar.gz .secrets .env
sudo chmod 600 backup/installation.tar.gz
docker compose start
```

Store these three archives as one dated set with the Git commit and image digests. Encrypt before moving them off-host. The installation archive contains plaintext bind secrets, private TLS keys and the CA signing key; the directory archive contains password hashes. Never attach these archives to bug reports.

## Restore on a separate clean host

Restore into a fresh checkout at the original release and clean volumes. Do not merge restored data into nonempty live volumes. Keep production stopped while verifying a restore. Extract the installation archive at the repository root; retain permissions and UID 10001 ownership on mounted private files. Create containers/volumes without starting:

```sh
docker compose build
docker compose create
docker run --rm -v forklift_directory:/target -v "$PWD/backup:/backup:ro" alpine:3.22.2 tar -C /target -xzf /backup/directory.tar.gz
docker run --rm -v forklift_metadata:/target -v "$PWD/backup:/backup:ro" alpine:3.22.2 tar -C /target -xzf /backup/metadata.tar.gz
docker compose up -d
```

Use the actual project-specific volume names. Verify `/ready`, login, user/group counts, Unix IDs and a test account bind before returning to service. Restored sessions may be usable until expiry; invalidate them offline if the backup crossed a trust boundary. A supported manager-session/service-credential rotation command is planned; host read credentials can be rotated by exporting a new host bundle. Offline file backup instructions are a recovery procedure, not a claim of a tested automatic restore product.

## Partial setup

- A configured SQLite database always prevents the wizard from initializing again.
- The helper refuses to overwrite `/directory/slapd.conf`, even if initialization failed. Inspect the directory volume and logs; never delete it to make a health check green.
- If LDAP initialization completed but the manager crashed before saving metadata, retry the same setup with the bootstrap token, base DN and original administrator credentials. The manager authenticates to the existing directory before recording completion.
- If slapadd failed before the completion marker, first take a copy of the entire volume. Only for an installation confirmed to contain no valuable identities should an operator deliberately replace the failed directory volume with a clean one. There is no automatic destructive reset endpoint.
- If metadata was lost on an established installation, restore the matching metadata backup. Re-running setup cannot recover the historical ID allocator/audit log and is not a supported replacement for backup restoration.

## Diagnostics

`docker compose logs --tail=100 manager ldap` shows operational failures. API errors intentionally omit raw LDAP diagnostics and user input. Check service health with `/ready`; `/health` alone does not prove LDAP is reachable. Authentication fails closed if LDAP cannot be reached or administrator membership cannot be verified.

If LDAP reports certificate verification failure, check expiry, certificate SAN `ldap`, CA trust, mounted permissions and the clock. The directory certificate lasts 365 days; the CA lasts ten years. Do not disable verification. For a directory hostname change or renewal, use `scripts/renew-ldap-certificate.sh your-directory-dns-name` with the existing CA, then restart LDAP. See [Linux clients](linux-clients.md) for private publication and deployment. The installer preserves certificates and does not renew them. A signed certificate and its private key must be replaced together; keep file ownership UID/GID 10001 and mode 0600 for the key. Changing the public UI certificate in NPM has no effect on LDAPS trust.

If login returns Origin rejected, ensure the browser scheme, hostname and port match `FORKLIFT_PUBLIC_URL` exactly, then recreate the manager. HTTPS configuration sets Secure cookies, so use the HTTPS proxy URL rather than the direct HTTP port for browser login. A global login throttle can block new sessions for five minutes; existing sessions continue to work. Restarting the manager does not clear throttling.

If the manager is unavailable, directory authentication should still work while slapd remains healthy. With an enrolled, synchronized replica and redeployed client endpoint/trust configuration, native SSSD failover can continue uncached LDAP authentication during a primary/Docker-host outage. Without a configured reachable replica, uncached authentication is interrupted. Client offline-cache behavior is controlled on each host, not by Forklift.

## Replica persistence and recovery

Back up each replica volume separately if preserving its certificate identity and local Syncrepl configuration is required. It contains a private server key and a reusable replication bind credential as well as directory password hashes. Protect these backups exactly like primary secrets. Never mount or copy a live primary MDB database as a shared replica database. A stopped, complete replica volume can be restored as the same read-only node with its existing certificate pin and enrollment identity; it resumes synchronization from its stored context when the primary returns. Replaying an enrollment token is neither necessary nor permitted.

A new/replacement node should enroll into its own independent volume and synchronize from the primary. Preserve any failed/old volume for inspection before deliberately retiring it. For certificate renewal before the 365-day leaf expires, plan a replacement enrollment and update client trust; automatic certificate rotation remains unimplemented. An alternate DNS name/port can permit old and replacement nodes to overlap during migration. Do not overwrite a pinned certificate and expect TLS clients to accept the new key automatically.

Decommission by stopping the replica, removing it from Forklift and redeploying client endpoint/trust settings. This revokes new replication binds but does not remotely terminate existing bound connections, erase storage or remove software. See [replication operations](replication.md) for token recovery, monitoring and stale-revocation limits.
