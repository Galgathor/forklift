# Forklift reference

Self-hosted OpenLDAP management for homelabs. Rust/Axum, React/TypeScript, SQLite, OpenLDAP 2.6 and PowerDNS Authoritative, deployed with Docker Compose.

**Development release 0.5 — breaking deployment change.** Initial setup, users/groups, POSIX identities, host configuration, primary/replica Syncrepl and directory maintenance are managed through the WebUI. Backups, restoration, service credentials, primary networking and certificates no longer require an administration script. SSH-key schema support and scheduled backups remain planned. This security-critical software has not received an external security audit.

## Install

Requirements: **Linux**, Docker Engine and Compose v2, private network connectivity and about 2 GB free memory for a source build. Directory containers use Linux host networking so Forklift can configure their private listeners without Docker socket access. Docker Desktop is not supported by this deployment.

```sh
git clone git@gitea-git:Galgathor/forklift.git
cd forklift
cp .env.example .env
# Set your Gitea image location in .env; images default to latest (see ci.md).
# Choose deployment settings in .env, then:
docker compose pull
docker compose up -d
```

You can also deploy the Compose project through your Docker hosting UI. Starting containers and managing the host's DNS/firewall remain infrastructure tasks. Ongoing directory administration takes place in Forklift.

| Deployment setting         | Default                 | Purpose                                                             |
| -------------------------- | ----------------------- | ------------------------------------------------------------------- |
| `FORKLIFT_BIND`            | `127.0.0.1`             | Specific host interface publishing the management port              |
| `FORKLIFT_PORT`            | `8080`                  | Published management HTTP port                                      |
| `FORKLIFT_PUBLIC_URL`      | `http://localhost:8080` | Initial browser origin; setup saves the actual browser origin       |
| `FORKLIFT_BOOTSTRAP_TOKEN` | generated               | Optional random one-time installation key of at least 32 characters |

Choose the installation key with a password manager. If omitted, the initializer writes a generated key to its **local container log**, available through your Docker hosting UI. Protect that log and deployment settings. Real `.env` files, keys and persistent data must never be committed.

Open the management URL (default `http://localhost:8080` on the Docker host). For remote use, configure NPM or bind the management port to a specific private LAN interface before deployment. Use HTTPS outside localhost.

The first-launch wizard:

1. Checks your installation key, directory supervisor and storage.
2. Selects this Docker host's private interface and an IP or optional DNS name. Forklift creates the LDAPS listener and certificate automatically. **You do not need an existing LDAP endpoint.** The default directory port is **1636**.
3. Creates a directory name, base DN such as `dc=homelab,dc=internal`, and administrator password (14+ characters), or restores a supported encrypted backup.
4. Initializes schemas, access rules, service identities and the administrator group. Sign in to open the dashboard.

Choose the base DN carefully: suffix changes are unsupported. Setup refuses to overwrite a configured directory. Container recreation preserves state; deleting persistent volumes destroys it. A partial setup can be retried with its original base DN and administrator identity. Missing metadata beside an initialized directory requires recovery of a matching backup.

**0.4 storage and backups are incompatible with 0.5.** Use fresh volumes for this development release. Preserve old volumes and use their matching release if you need to recover them. There is no automatic conversion or reset. The development/test suites use isolated projects and never delete default installation volumes.

## Optional native client

Forklift Client pairs Linux machines through **Hosts → Join existing machine**. It adds a revocable, key-bound identity, live inventory, heartbeat connectivity, read-only diagnostics and host issues/notifications. Administrators can explicitly enable updates to that host’s managed DNS addresses. The native client never changes Linux authentication or resolver configuration. Manual hosts remain supported. See [native client enrollment](client-enrollment.md) for installation, trusted HTTPS, LAN discovery, linking, revocation and milestone limits. See [diagnostics and host issues](client-diagnostics.md) for enabling checks, and [network port verification](network-checks.md) for client/server reachability checks. Native Debian packages, resumable machine-credential rotation and client-driven LDAP replica deployment are implemented. With Docker/Compose installed on an enrolled client 0.5 host, approve deployment under its client details; no Git checkout or manual join configuration is needed. Upgrade the server first. See [client-driven replication](client-replica-deployment.md).

## Integrated DNS

PowerDNS is a standard part of the management stack. Open **DNS** to create forward/private reverse zones, manage record sets and matching PTR records, edit SOA/NS, inspect real service health, export zones and rotate the DNS API credential. Its own SQLite data persists independently of LDAP. Existing schema-5 installations can upgrade without resetting any directory/metadata volumes.

Set `FORKLIFT_DNS_BIND` and `FORKLIFT_DNS_PORT` in deployment settings before starting. New installations publish **both TCP and UDP** on port 53 across host interfaces. Restrict DNS to your private network with Docker-aware firewall rules. Forklift derives the primary endpoint from your setup address and published port; existing localhost-only settings are preserved. If another DNS service already owns port 53, use a suitable private address/nonstandard port such as `192.168.1.2:1053`; do not replace your current resolver. Configure resolver conditional forwarding for managed forward/reverse zones. No host resolver settings are changed automatically.

The primary PowerDNS HTTP API binds to container loopback and is reached only through protected Unix transport. It is never published through Docker or NPM. DNS keeps answering when Forklift/LDAP is down; DNS failures do not block LDAP readiness or authentication.

Hosts can manage A/AAAA and matching PTR values, update names/addresses, defer or retry changes, and explicitly retain/delete owned records. DNS servers provides copyable HTTPS enrollment, zone assignments, TSIG-authenticated transfers, synchronization checks and retryable credential/certificate rotation. Deploy `deploy/dns-secondary/compose.yaml` independently on the second host; the LDAP replica stack remains separate.

Encrypted installation backups now include a consistent online primary DNS snapshot and its credentials. Settings provides verification, restoration and interrupted-operation rollback. Older LDAP-only archives can be verified but cannot perform a full installation restore in this release. DNS also supports reviewed JSON record imports and JSON/BIND exports. See [DNS recovery and upgrades](dns-recovery.md) for archive scope, peer re-enrollment and supported import limits.

Networking/resolver examples, supported records and reverse boundaries, PTR reconciliation, backups, AD migration and limitations: [DNS operations](dns.md). Secondary deployment, firewall requirements and outage behavior: [DNS replication](dns-replication.md).

## Nginx Proxy Manager

1. Publish the manager to an address reachable by NPM. A container's loopback is its own; use a shared Docker network forwarding to `manager:8080`, or publish on a specific private host address. Restrict that management port to NPM at the firewall.
2. In NPM, add a Proxy Host for your public hostname, scheme **http**, selected private forwarding address and port **8080** (or the published `FORKLIFT_PORT`). Enable Block Common Exploits.
3. Select/request an SSL certificate and enable Force SSL. WebSockets are unnecessary. Finish initial Forklift setup using that HTTPS hostname.
4. For large backup uploads, set an appropriate `client_max_body_size` in the Proxy Host's Advanced configuration, up to Forklift's 8 GiB encrypted upload limit. Allow enough proxy read timeout for downloads; long maintenance work itself uses short progress polls.

To change the public hostname later, prepare the new Proxy Host, then use **Settings → WebUI address**. Forklift saves the new origin, revokes sessions and redirects for sign-in. Do not change only the deployment environment after initial setup; the saved setting is authoritative.

Security decisions use the exact saved browser origin and Secure/HttpOnly/SameSite cookies with CSRF protection. Forwarded headers are not consumed or trusted. LDAP traffic **does not pass through NPM's HTTP Proxy Host**. Linux clients and replicas connect directly to the separate private LDAPS address selected in setup. Restrict the selected directory port and replica control port to their intended private networks. Permit the manager’s Docker network to reach replica LDAPS/control ports; host firewalls may block bridge-to-host traffic even when the LAN can reach it.

## Daily management

- **Users / Groups:** create, edit, disable, delete, reset passwords and manage POSIX group membership. UIDs/GIDs are allocated monotonically and never automatically reused. Disabling removes the password hash and expires the account. Re-enabling requires a new password. Account renames, manual UID overrides and SSH-key attributes remain unsupported.
- **Hosts:** every primary and replica appears automatically. Its initial state is **Inventory only**; registration grants no SSH access. Select allowed login groups and generate a protected SSSD/PAM/NSS bundle when configuring Linux authentication. Ansible/manual deployment is supported; Forklift does not claim to remotely deploy those files. SSH eligibility and sudo authorization are separate.
- **Directory Servers:** add a new machine by friendly name and private address, generate a copyable join configuration, and paste it into the standalone `deploy/replica` stack from this repository. Start it through Docker Compose or your hosting UI; no archive transfer or manual certificate exchange is required. The primary connection is inherited from setup. After enrollment, rotate credentials, restart the directory, reconnect the primary or renew certificates in Forklift.
- **Settings:** generate/download a recovery key, create/download/delete encrypted backups, verify/restore archives, rotate the service credential, renew the primary certificate, change its private listener, review recovery, inspect/export audit events and revoke sessions.

Backup operations briefly pause the primary for a consistent snapshot; healthy replicas continue independently. The WebUI remains available with durable progress and recovery controls. Restoration requires fencing old writers/replicas, a trusted creation-time checksum and a future Unix ID floor above **all** historical allocations. Keep the private recovery key and checksum separately from the encrypted archive.

Linux hosts authenticate using ordinary SSSD/PAM password prompts. Generated configurations validate certificates and disable offline password caching by default. The manager is outside the authentication path. Asynchronous replicas cannot apply revocations while disconnected; cached identities and existing sessions can outlive changes. Keep an independent local Linux recovery account.

Detailed instructions: [Linux clients](linux-clients.md), [replication](replication.md), [backups and recovery](operations.md), [security](security.md), [architecture](architecture.md).

## Locked out?

The only local administration tool is [emergency account recovery](scripts/emergency-recovery.sh), for when no administrator can sign in. It finishes a recorded interrupted operation if necessary, resets an existing account, restores administrator membership and revokes sessions. It can also correct an unreachable saved WebUI origin. Routine operations belong in the WebUI.

## Development and checks

```sh
npm ci --prefix frontend
npm run build --prefix frontend
cd backend
cargo fmt --check
cargo test --locked
cargo clippy --locked -- -D warnings
cd ..
docker compose -f compose.yaml -f compose.dev.yaml build
python3 tests/integration.py
python3 tests/hardening.py
python3 tests/replication.py
python3 tests/dns.py
```

These scripts require built manager, directory and maintenance images. Each creates a random Compose project, private fixtures and fresh volumes, and cleans up only its own resources. No installer-generated secrets are required. See [verification](verification.md) for exercised checks and browser/Ubuntu options.

Vite proxies `/api` to localhost:8080. For a development frontend, use its actual browser origin during setup (normally `http://localhost:5173`). The manager serves the production bundle without CDNs, external fonts, mock data or WebSockets.

License: [MIT](LICENSE).

## Automated builds

Gitea Actions uses `ubuntu-latest` to check builds and publish container images/native client packages to the repository owner’s Packages. Configure the `PACKAGES_TOKEN` Actions secret in both repositories before the first run. See [CI setup, runner requirements and package usage](ci.md).
