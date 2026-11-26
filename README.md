# Forklift

Forklift is a self-hosted application for managing Linux accounts and internal DNS from a web interface. It uses OpenLDAP for directory accounts and PowerDNS for DNS records.

Use it to manage users and groups, choose which groups can sign in to your Linux machines, maintain DNS records, and add backup directory servers. You do not need to edit LDAP files or run LDAP administration commands.

Forklift Client is an optional companion for Linux machines. It reports health and address changes. Linux sign-in still uses standard SSSD, PAM and SSH.

## Basic setup

You need a Linux host with Docker Engine and Docker Compose v2. Docker Desktop is not supported. The published images currently support amd64 Linux.

1. Clone this repository, open its folder, and start Forklift.

   ```sh
   docker compose up -d
   ```

2. Open `http://localhost:8080` on the Docker host. For remote access, configure an HTTPS reverse proxy and set `FORKLIFT_PUBLIC_URL` in `.env` before setup. See the [network setup guide](docs/reference-guide.md).
3. Enter the installation key from the initialize container’s logs.

   ```sh
   docker compose logs initialize
   ```

4. Choose **Create new installation** for your first node. To add a node, run the same Compose command on the other host and choose **Join existing installation**. The existing manager needs a reachable HTTPS address. [Pair a Forklift node](docs/peer-controllers.md#join-an-installation)

Forklift sets up the directory and checks PowerDNS before finishing setup. If setup reports a DNS problem, run `docker compose logs dns` and retry after fixing it.

Keep `.env`, installation keys and backups private. Container recreation keeps your data; deleting storage volumes removes it.

## What to do next

- Create users and groups in the WebUI.
- Enable **DNS → DNS forwarding** if Forklift should send queries for other zones to your router or another DNS server.
- [Set up Linux sign-in](docs/linux-clients.md).
- [Enroll a machine with Forklift Client](docs/client-enrollment.md).
- [Add a writable Forklift node](docs/peer-controllers.md), or [operate an existing read-only replica](docs/replication.md).
- [Back up and restore your installation](docs/operations.md).
- [Check network connections and ports](docs/network-checks.md).

LDAP and DNS continue working when the management interface is offline. Replicas provide backup access only after they have synchronized. Adding a host entry alone does not set up Linux sign-in.

## Builds and development

Ready-built images are published to GitHub Container Registry (GHCR). See [build publishing and image downloads](docs/ci.md#github-container-registry-mirror) for configuration and deployment details.

For development commands, see [Repository Guidelines](AGENTS.md). Detailed setup, reverse-proxy configuration and troubleshooting are in the [reference guide](docs/reference-guide.md). This project is under active development; [verification notes](docs/verification.md) describe what has been tested and current limits.
