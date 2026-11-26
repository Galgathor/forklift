# Add a directory server

For a writable server with its own WebUI, use [Forklift node pairing](peer-controllers.md). This guide covers existing read-only LDAP replicas.

Your initial Forklift deployment **already contains the primary OpenLDAP server**. Setup creates its private LDAPS endpoint and certificate. A new replica needs a Linux machine with Docker and private connectivity; do not install OpenLDAP or prepare an LDAPS endpoint yourself.

## First-launch primary configuration

The setup wizard selects the primary Docker host's actual private interface, an IP or optional DNS name, and directory port (default **1636**). Using the IP requires no DNS changes. If using DNS, point it to that private interface. Forklift validates the address and creates the listener/certificate. Change it later under Settings; there is no Existing Server configuration section in replica enrollment.

Expose the WebUI over HTTPS through NPM. Replicas need to reach that HTTPS hostname for one-time enrollment. LDAP itself uses the separate private port and never NPM's HTTP Proxy Host.

## Deploy using an enrolled client

For a target running client 0.5 and Docker/Compose, use **Hosts → Client enrolled → LDAP replica service**. Select its stable private address and LDAP/control ports, then approve. The client uses versioned components shipped with its package, builds/starts a dedicated Compose project and completes existing secure replica enrollment. No repository checkout or manual join configuration is needed. The existing Host record and login/DNS policies are retained. Read [client-driven deployment](client-replica-deployment.md) for prerequisites, ownership protection, retry, cancellation and initial-release limits.

## Add server

1. Open **Directory Servers → Add server**.
2. Enter a friendly name and the new Docker host's private IP. Optionally supply its DNS name. Advanced settings choose its LDAPS port (1636) and management control port (9443). Keep both reachable only on the intended private networks, including the manager’s Docker network. Host firewalls can block bridge-to-host traffic; allow the manager to reach these ports. The inherited primary connection is displayed for clarity.
3. Select **Generate join configuration**, then **Copy join configuration**. It includes the connection settings, primary public CA and a one-use enrollment credential expiring after 15 minutes. Generating another configuration invalidates the previous one. If your WebUI uses a private HTTPS CA, paste its **public CA certificate** into the optional field before generation; leave it blank for publicly trusted HTTPS.
4. Clone the same Forklift release/revision on the new machine. In `deploy/replica`, paste the complete copied line into `.env`. Alternatively deploy this repository's `deploy/replica/compose.yaml` in a Git-based Docker hosting UI and set its `FORKLIFT_REPLICA_JOIN` environment value (the part after the first `=`). Start that standalone stack. There is no archive to transfer or extract, no separate repository, and no manual certificate exchange.
5. Wait for **Synchronized** in Forklift. Checks bind over verified LDAPS, compare nonempty `contextCSN` sets against the primary and record the last confirmed match. A generated join configuration or healthy container is not proof of synchronization.

For Docker Compose, after cloning the matching repository checkout:

```sh
cd deploy/replica
# Save the copied FORKLIFT_REPLICA_JOIN line in .env using your editor.
docker compose up -d --build
```

The join configuration is base64-encoded for reliable copying, **not encrypted**. Treat it as a password until consumed/expired, protect `.env`, and never commit it. Both Git and the Docker build context exclude `.env`. The replica generates its own private key and redeems the token only over verified HTTPS. Public certificates establish trust; they do not replace authorization. No CA signing key or primary private key is transferred.

Once synchronized, remove the temporary join setting from your deployment if desired. Restarts read the replica's protected persistent state and do not require a join token, primary or manager. Do not delete its data volume. An invalid/expired join setting on an unconfigured node requires a fresh configuration from Forklift; no LDAP commands are needed.

The older archive API remains available for existing automation; the WebUI uses the copyable flow. Previously deployed replicas do not need reenrollment.

Every directory server appears in **Hosts** automatically, including pending replicas and the primary. These are inventory records with no SSH authorization. To enable conventional Linux authentication on that machine, edit its allowed groups and deploy its generated host configuration separately.

Replicas have their own database volume and native read-only Syncrepl configuration. Their locally generated TLS private key never leaves the machine. The manager pins the validated public leaf certificate and checks the registered DNS/IP SAN. Enrollment token digests and credential epochs live in metadata; no reusable node password is stored in SQLite. Existing configured replicas restart without contacting the primary or manager.

## Ongoing administration

Use each server's WebUI controls:

- **Rotate credentials:** update its replication and control credentials together. A recorded pending epoch makes retries safe if communication is interrupted.
- **Restart:** restart the supervised LDAP process without restarting Docker or exposing a command endpoint.
- **Reconnect primary:** apply the current setup/Settings primary address after it changes. The UI reports stale provider addresses.
- **Renew certificate:** generate a new private key/certificate on the replica and stage its public pin in Forklift. Generate/deploy affected Linux host bundles with both pins. Activate through Forklift; it reloads LDAP/control TLS, verifies the actual LDAP certificate, then retires the old pin/key. Generate/deploy final host bundles afterward. Retry interrupted transitions through the same controls.

The control service runs as the unprivileged directory user and accepts fixed authenticated operations over pinned TLS; no arbitrary commands, SSH or Docker socket are available. Do not publish it to the internet. If a replica is permanently lost, fence it, remove its record and deploy a fresh replica. Directory deletion removes an inventory-only Host; a Host with configured SSH policies remains as an ordinary Linux host. Removing metadata cannot stop a remote machine or revoke existing sessions there.

## Linux client failover

In Hosts, list the primary and synchronized replicas as ordered LDAPS endpoints. Generate/deploy a new bundle so SSSD receives all matching CA/leaf trust and the replicated host read identity. SSSD performs failover and ordinary PAM password authentication; Forklift is outside that login path. See [Linux clients](linux-clients.md).

Authentication can continue on a synchronized secondary when the primary is unavailable, including users not previously cached by that client. Writes wait for primary recovery. There is no automatic primary promotion or multi-provider mode. A disconnected replica cannot receive password resets, disabled accounts or group revocations; monitor and fence stale nodes. Existing SSH sessions and caches have their own lifetime.

Restored backups quarantine old replica records. Fence and reseed those machines before using them again; restoring stale copies into a live topology risks diverging identity history. Do not share database volumes across hosts.
