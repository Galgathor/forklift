# Forklift

Self-hosted OpenLDAP management for homelabs. A Rust/Axum API, React/TypeScript interface, SQLite metadata store, and a real OpenLDAP 2.6 directory deployed with Docker Compose.

**Development release: Milestone 2.** Setup, administrator login, user/POSIX group management, host registration, SSSD/PAM/NSS configuration exports and an Ubuntu Ansible role are implemented. SSH-key schema support, replica provisioning, automated backup/restore and service-credential rotation are not implemented. Host configuration export is not remote deployment or liveness monitoring. Do not rely on this release as your only path into critical infrastructure. Keep an independently managed local recovery account on Linux hosts.

## Quick start

Requirements: Linux with Docker Engine and Compose v2, Git, OpenSSL, and about 2 GB of free memory for a source build. Docker access is needed only by the installer and deployment operator, never by the manager container.

```sh
git clone git@gitea-git:Galgathor/forklift.git
cd forklift
./scripts/install.sh
# Edit .env if using a different hostname, port, or Nginx Proxy Manager.
docker compose up -d --build
```

The installer creates `.env`, restricted installation secrets, a local certificate authority and a directory certificate. It displays a one-time bootstrap token; save it locally for the setup form. Nothing secret belongs in Git. Running the installer again preserves existing credentials and certificates. Builds use lockfiles and pinned base image digests; operating system security packages still follow the Debian repositories. On a slow machine the first source build can exceed ten minutes.

Open `http://localhost:8080` on the Docker host. From a remote workstation, an SSH tunnel is suitable for initial local setup:

```sh
ssh -L 8080:127.0.0.1:8080 your-docker-host
```

The setup form asks for the bootstrap token, directory name, a base DN such as `dc=homelab,dc=internal`, and the initial administrator username/password. Names use lowercase Unix-compatible characters. Passwords require at least 14 characters. Base DNs currently support two or more lowercase `dc=` components; choose carefully because changing the suffix is not supported.

Setup provisions schemas, directory containers, a service account, the initial POSIX administrator and the `administrators` group. Connections verify the directory certificate. After setup, sign in with the administrator account. The bootstrap endpoint refuses further setup. The token does not grant access to an initialized manager.

The manager and LDAP containers run as UID/GID 10001, with all capabilities dropped and no Docker socket. Docker volumes retain both databases across `up --force-recreate` and `down`. **Do not use `docker compose down -v` on an installation you want to preserve.**

## Configuration

Copy `.env.example` via the installer. Settings:

| Setting               | Default                 | Purpose                                                               |
| --------------------- | ----------------------- | --------------------------------------------------------------------- |
| `FORKLIFT_PUBLIC_URL` | `http://localhost:8080` | Exact browser origin; HTTPS activates Secure cookies. No path prefix. |
| `FORKLIFT_BIND`       | `127.0.0.1`             | Host address for the published management port.                       |
| `FORKLIFT_PORT`       | `8080`                  | Published management port.                                            |

The Rust process defaults to `0.0.0.0:8080` inside its container. Advanced deployments can set `FORKLIFT_LISTEN` in a Compose override and adjust the container target port and health check together. It is not necessary to change this when changing the published host port.

`GET /health` is process liveness. `GET /ready` checks metadata access and, after setup, an authenticated directory read over verified TLS. The directory container health check verifies its helper and that its slapd child has not exited; the manager readiness endpoint verifies actual LDAP operations. Check with:

```sh
docker compose ps
curl --fail http://localhost:8080/ready
docker compose logs --tail=100 manager ldap
```

## Nginx Proxy Manager

1. Set `FORKLIFT_PUBLIC_URL=https://forklift.example.com` and recreate the manager with `docker compose up -d`.
2. If NPM is on the Docker host itself, forward its Proxy Host to `http://127.0.0.1:8080`. If NPM runs in a container, its loopback refers to that container; use a shared Docker network or a reachable private host address instead.
3. For a separate NPM machine/container using the LAN, set `FORKLIFT_BIND` to the Docker host's specific private address. Allow the port only from NPM at the host firewall. Forward to that private address and the selected published port.
4. Add a Proxy Host for `forklift.example.com`, scheme **http**, forwarding target as above, port **8080** (or `FORKLIFT_PORT`). Enable Block Common Exploits. Request/select a TLS certificate on the SSL tab and enable Force SSL. WebSocket support is unnecessary.
5. Browse through the configured HTTPS hostname. Origin validation requires that exact origin, including any non-default public port.

Forklift derives security decisions from the configured public URL and **does not trust any forwarded headers**. `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` cannot change the request origin, cookie policy or rate-limit identity. No trusted-proxy configuration is needed in this release because no such headers are consumed. Login throttling is global, persisted in SQLite (20 attempts per five minutes), not client-IP based; this avoids proxy spoofing but permits temporary denial of login by a hostile caller. Restrict access to your management network.

Never send LDAP authentication traffic through NPM's HTTP Proxy Host. LDAPS is a separate protocol and certificate. The default stack publishes no directory ports. The optional client Compose override publishes LDAPS on an explicitly configured private address; see [Linux clients](docs/linux-clients.md).

## Users and groups

The Users page creates, edits, disables and deletes LDAP accounts, changes/reset passwords, displays timestamps, and searches current account attributes. Supported attributes include display name, email, description, primary GID, home directory and a restricted shell selection. UIDs are allocated automatically. Username changes are intentionally unsupported. UID/GID overrides and SSH public keys are not supported yet.

Groups are `posixGroup` entries with `memberUid` usernames. Create or rename a group, edit its member usernames, and delete unused groups. Primary-group references prevent deletion. Supplemental membership is managed on the group form. The `administrators` group authorizes the WebUI independently of the user's primary GID. Administrators cannot delete/disable themselves or remove their own current administrator membership.

A shared monotonic allocator starts after UID/GID 10000. Deleted IDs are not reused. Do not create entries outside Forklift, run multiple managers against one directory, or restore metadata from an older point than directory data; those workflows currently lack reconciliation and could create duplicate numeric identities.

Disabling an account removes its password hash and sets `shadowExpire=1`, blocking subsequent LDAP binds. Re-enabling requires a new password. Password reset and disabling revoke that account's Forklift sessions. Administrator membership is checked against LDAP on every privileged request, so removed administrators immediately lose API access. Previously issued host/offline credentials remain subject to the destination system's policies.

Password modifications use the LDAP Password Modify extended operation; OpenLDAP's Argon2 module hashes the result. Plaintext user passwords are used only during request processing and are never written to the metadata store or application logs. The manager's reusable service credential is a restricted mounted secret file, necessary to bind to LDAP; protect host storage and backups. LDAP and SQLite operations cannot form a shared transaction. A failed multi-step edit can be partial; refresh and inspect the account before retrying. A newly created account without a completed password operation cannot authenticate.

## Linux authentication and SSH

Register Linux hosts with friendly names, DNS hostnames, permitted login groups and ordered LDAPS endpoints. Generate a protected configuration archive containing a dedicated read-only host bind credential, certificate authority, SSSD identity/password settings and SSH/PAM group access rules. Deploy with the Ubuntu Ansible role or manual instructions. Every export rotates the host credential; edits require redeployment. Referenced groups are protected against rename/deletion.

Users authenticate through conventional SSH password prompts using their LDAP password. Destination PAM enforces login groups and SSSD checks account expiration. Local recovery accounts retain their existing policy, and sudo remains separate. Offline password caching is disabled in generated configurations; group/identity data has a 60-second cache interval.

Complete private LDAPS publication, DNS/certificate setup, Ansible deployment, manual setup, authorization and outage guidance: [Linux clients](docs/linux-clients.md).

## Replication

Planned for Milestone 3: one writable primary plus read/authentication replicas using native Syncrepl, short-lived enrollment credentials, per-host persistent storage, synchronization monitoring and SSSD endpoint failover. No replica Compose stack is provided because enrollment and trust provisioning are not implemented. Administrative writes will remain unavailable during a primary outage. Automatic primary promotion and multi-provider writes are out of scope for the first release.

The management application is not in the LDAP authentication path. Stopping it leaves slapd running. Independent replica authentication during primary failure will require Milestone 3 and is not claimed in this release.

## Backups, recovery and upgrades

See [operations](docs/operations.md) for offline backup/restore, partial initialization and TLS recovery. This release has no online backup scheduler, restore UI or automatic certificate/service-credential rotation. Back up directory data/configuration, metadata **and** installation secrets together. Keep archives encrypted and offline. The CA private key is retained on the installation host but is never mounted into either service.

Before upgrading: stop services, make a matching backup, build the new revision and run the integration suite on a separate test project. Recreate services with `docker compose up -d --build`. Milestone 2 automatically migrates metadata schema 1 to 2 while preserving identities, sessions and the ID allocator. Metadata schema is versioned; a newer schema is refused by older code. Rollback requires restoring a matching complete backup, not just an older image.

## Development and verification

```sh
cd frontend
npm ci
npm run build
cd ../backend
cargo fmt --check
cargo test --locked
cargo clippy --locked -- -D warnings
cd ..
docker compose build
python3 tests/integration.py
# Optional, comprehensive Ubuntu client checks:
docker build -t forklift-ubuntu-client -f tests/ubuntu/Dockerfile .
FORKLIFT_TEST_UBUNTU=1 python3 tests/integration.py
python3 tests/certificates.py
```

The integration suite requires the installer-created secret files and built `forklift-manager:latest` / `forklift-ldap:latest` images. It creates a randomly named Compose project with fresh volumes and a temporary loopback port, then removes **only its test volumes**. It does not initialize or delete your default installation. Test credentials are random and never printed. Ubuntu mode also runs the Ansible role twice and actual NSS/PAM/SSH password and access-policy checks. Checks include bootstrap replay/origin rejection, authenticated and unauthenticated authorization, CSRF, LDAP bind/password/disable behavior, group CRUD, administrator revocation, non-reused IDs, container recreation, independent LDAP operation, directory outages, certificate rejection and login throttling.

Vite development mode proxies `/api` to localhost:8080; configure `FORKLIFT_PUBLIC_URL` to the actual development browser origin (usually `http://localhost:5173`). The production UI is embedded in the manager image. No external fonts, CDNs, runtime mock records or WebSockets are required.

Architecture and phased implementation: [docs/architecture.md](docs/architecture.md). Security boundaries and remaining limitations: [docs/security.md](docs/security.md). License: [MIT](LICENSE).
