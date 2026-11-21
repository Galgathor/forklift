# Primary/replica replication

Forklift manages one writable OpenLDAP primary and up to eight read/authentication replicas from one WebUI. Each server owns its own persistent MDB database. Native OpenLDAP Syncrepl (`refreshAndPersist`) synchronizes identities, POSIX attributes, groups, account/password state and directory operational attributes over verified LDAPS.

There is no automatic primary promotion, shared database volume, Docker socket, manager-to-host SSH connection, or second management interface. Replicas remain read-only even when the primary fails. Writes wait for the primary to recover.

## Upgrade an existing installation

Make a consistent backup of metadata, directory storage and installation secrets first. Build and recreate the primary stack from the same checkout:

```sh
docker compose up -d --build
```

If you use the optional client/LDAPS Compose override, retain its `COMPOSE_FILE` setting. SQLite schema 2 migrates to schema 3. Before starting slapd, the directory helper recognizes the previous generated configuration, saves `slapd.conf.pre-replication`, adds the syncprov module/overlay and replication indexes, extends the password-hash read ACL only to dedicated replication identities, validates the configuration and reindexes the existing database offline. The MDB directory and existing identities are retained. This creates a brief authentication interruption on the primary; an already configured replica continues serving authentication.

The helper refuses customized/unrecognized configurations rather than guessing. If an upgrade is interrupted during indexing, it retries the idempotent offline index operation on the next start. It does not discard a configured directory or run first-time setup. Rollback requires a matching complete backup and release, because old managers refuse newer metadata schemas.

## Networking and certificates

Before enrollment, ensure:

- The manager has its correct HTTPS public URL configured, normally through Nginx Proxy Manager. Publicly trusted certificates work with system roots. For a private manager CA, place that public CA in `enrollment/manager-ca.crt` in the deployment bundle **before** running `prepare.sh`.
- The primary exposes a private LDAPS endpoint reachable from the replica, with a DNS SAN matching its hostname and a certificate signed by the installation CA. Follow [Linux clients](linux-clients.md) for certificate renewal and private port publication. The internal Docker hostname `ldap` is normally not resolvable from another physical host.
- The replica's DNS name points to its private address, and the registered LDAPS port is reachable from Forklift and Linux clients. Restrict ports to trusted networks with Docker-aware firewall rules. Do not publish the primary provisioner's port 8090.
- Clocks are synchronized for certificate validity and token expiry. Enrollment tokens last 15 minutes from issuance.

LDAP and Syncrepl do not go through an NPM HTTP Proxy Host. NPM carries the WebUI and HTTPS enrollment API; LDAPS is a separate TCP endpoint.

Each replica generates a new RSA private key locally and a self-signed **non-CA leaf** certificate for exactly its registered DNS hostname. The authenticated enrollment registers that certificate as the node's pinned trust anchor. Certificates with CA signing permission, wrong DNS names, invalid validity windows, weak/non-RSA keys or excessive lifetimes are refused. Monitoring still performs ordinary TLS certificate and hostname validation; it does not enable insecure TLS options.

No installation CA signing key is mounted into the manager, primary or replica. The replica private key never travels to the manager. Pinning permits independent replica enrollment without copying a CA signing key or adding an unrestricted certificate-signing service. The generated leaf certificate lasts 365 days; Milestone 4 supports locally staged renewal, dual manager/client trust and verified finalization; follow [certificate lifecycle](operations.md#replica-certificate-and-replication-credential-lifecycle). Plan maintenance before expiry. Replacing the certificate without updating enrollment/trust makes monitoring and client TLS fail, as intended.

## Add a replica

1. Open **Directory Servers → Add server**. Enter a name, the replica's private LDAPS DNS endpoint (for example `ldaps://ldap2.homelab.internal:636`) and the primary LDAPS endpoint reachable from that replica (for example `ldaps://ldap1.homelab.internal:636`). These addresses must refer to different servers.
2. Select **Generate deployment**. Download the private archive and transfer it securely to the second Docker host. The token is scoped to this registered node, expires in 15 minutes and can be redeemed once. Only its digest is stored in metadata. Do not commit, email, log or publicly share the archive: successful enrollment grants access to the directory's password hashes for replication.
3. Extract into a private directory. The archive includes a pinned-version Dockerfile, the replica runtime, Compose, provider CA, one-time enrollment settings, `prepare.sh` and instructions. For private HTTPS PKI, add `enrollment/manager-ca.crt` now. Run:

   ```sh
   ./prepare.sh
   ```

4. Set `.env` to the second host's private interface and registered LDAP port:

   ```dotenv
   FORKLIFT_REPLICA_BIND=192.168.1.11
   FORKLIFT_REPLICA_PORT=636
   ```

5. Start the replica:

   ```sh
   docker compose up -d --build
   docker compose logs --tail=100 replica
   ```

6. Watch Directory Servers until **Synchronization confirmed** appears. Initial enrollment, a running container or a successful TCP handshake does not imply the directory data has synchronized.
7. Edit each affected Linux host's ordered endpoints to include both the primary and replica. Generate and deploy a **new host bundle**, which includes the replica's pinned public certificate as well as the installation CA. Wait for synchronization after generating host credentials, because the new host read identity/password must reach the replica before failover can work.

`prepare.sh` gives the runtime's fixed UID 10001 access to restricted enrollment files. It does not configure a remote Docker host from the manager. The replica container has a read-only root filesystem, dropped capabilities, no privilege escalation, and one independent writable data volume. The archive builds locally from pinned OpenLDAP/base versions; no private container registry is required.

## Credentials and privilege boundaries

The manager provisions a unique `cn=replica-<id>,<base DN>` identity using its normal LDAP service account. This replication identity can read the replicated password hashes but cannot modify directory entries or OpenLDAP configuration. Its random credential is returned once over the verified enrollment HTTPS connection, then stored only in the replica's restricted persistent configuration, where native Syncrepl requires it. It is never retained in SQLite or audit records.

A separate `cn=monitor,<base DN>` identity serves verified monitoring and replica-backed management authorization reads. Its password is derived from the existing service secret using standard HMAC-SHA256 with a versioned domain-separation label; the read credential cannot reveal the write secret. The manager never sends its write-service password to a replica for monitoring. Monitor/host identities cannot read password hashes or modify the directory.

The replica has an internal root DN for Syncrepl's local update mechanism, with no root password and no corresponding bindable directory entry. Client-facing writes are rejected by `readonly on`. The primary's management identity can authenticate to a replica because its password hash is replicated, but cannot write there. There is no promotion endpoint.

Treat every enrolled replica host as trusted authentication infrastructure: it holds directory data, password hashes and keys and accepts users' passwords. A compromised replica is a serious authentication incident even though it cannot perform normal LDAP writes to the primary.

## What the dashboard proves

Directory Servers and Dashboard refresh real measurements on demand and every 30 seconds while those pages are open. Monitoring verifies TLS, performs an authenticated LDAP bind/read, and queries the suffix's `contextCSN` set. It records the last actual check, comparison and error state.

- **Synchronization confirmed:** both endpoints returned the same nonempty sorted contextCSN set in this check. `last_sync_at` advances only on that evidence.
- **Catching up:** the contexts differ or are absent. This can be a normal transient after a write; persistent differences require inspecting replica logs for Syncrepl, TLS, credential or connectivity errors.
- **Unreachable / TLS error:** the manager could not establish a verified LDAP bind. DNS, certificates, firewalls, initial synchronization and bind credentials can cause this state. Container liveness alone is insufficient.
- **Primary unavailable · sync unconfirmed:** the replica can still be read, but there is no current primary context to compare. The last confirmed synchronization time is retained and is not advanced just because the replica is reachable.
- Enrollment states distinguish pending, expired, in-progress and failed attempts from connected/synchronized nodes.

Matching contexts are point-in-time evidence, not a promise about future synchronization, byte-for-byte backup integrity, zero lag, or quorum. No simulated healthy status, fixed synchronization timestamp or automatic promotion is used. Individual replica container logs provide native Syncrepl diagnostics; the WebUI does not invent a specific root cause from a failed generic LDAP/TLS operation.

## Primary failure and recovery

Ubuntu SSSD uses the ordered LDAPS URI list and validates either the primary CA or enrolled replica certificate. With a synchronized replica, a fresh user can resolve identity and authenticate using the normal LDAP password while the primary is stopped; no previously cached password is required. The manager is not part of the host login path.

During a primary outage, Forklift can authenticate administrators and serve read-only data through a verified enrolled replica. The interface displays this mode explicitly. Group-based administrative authorization is still checked server-side against that replica. All privileged directory/host/server/enrollment writes continue to require the primary; the consumer is never made writable. Logout invalidates the caller's local session independently of LDAP availability.

Asynchronous replicas may hold stale passwords, disabled states and administrator memberships. A revocation cannot reach a disconnected replica. Do not treat replica-backed login/authorization as linearizable or use the last-confirmed timestamp as a revocation guarantee. Review cache/offline limitations in [Linux clients](linux-clients.md). Existing SSH/LDAP connections are not forcibly closed by a user or replication-identity deletion.

Once the primary returns, Syncrepl reconnects automatically (five-second initial retries, then 30-second retries), catches up and resumes persistent updates. Verify context equality before relying on the node after an extended outage. Persistent volumes survive container recreation; restarting a configured replica uses its stored configuration and does not redeem the consumed token again.

## Enrollment failures and removal

An invalid/expired token or invalid certificate does not grant replication credentials. Once redemption is accepted, the token is consumed before provisioning and cannot be replayed. A failure that reaches the manager is marked failed; an unused failed/pending enrollment can receive a new token. A process crash or lost response can leave the server in-progress/enrolled while the replica lacks a complete saved response. Stop the incomplete stack, inspect/preserve its volume, then remove and re-register that node to establish a new scoped enrollment. Do not reset an existing working directory or delete volumes as a generic retry step.

The replica saves the returned configuration before starting local provisioning, so normal local restart/recreation can finish without replaying the token. Partial/unparseable state fails closed for operator inspection. Enrollment files may retain the used token, which has no further authority; keep the directory private because it also contains trust material and deployment details.

To decommission, stop the replica first, remove it in Forklift (revoking new provider binds and enrollment authority), and update/redeploy client endpoint/trust bundles. Existing persistent replication connections are not remotely terminated by identity deletion. Forklift does not erase remote disks, uninstall remote containers or remove client configurations. Keep necessary backups before intentionally retiring that node's data volume.

References: [OpenLDAP 2.6 replication](https://www.openldap.org/doc/admin26/replication.html), [Ubuntu replication guidance](https://ubuntu.com/server/docs/how-to/openldap/replication/), [ldap3 TLS settings](https://docs.rs/ldap3/0.12.1/ldap3/struct.LdapConnSettings.html).
