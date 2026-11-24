# Forklift

Forklift is a self-hosted application for managing Linux accounts and internal DNS from a web interface. It uses OpenLDAP for directory accounts and PowerDNS for DNS records.

Use it to manage users and groups, choose which groups can sign in to your Linux machines, maintain DNS records, and add backup directory servers. You do not need to edit LDAP files or run LDAP administration commands.

Forklift Client is an optional companion for Linux machines. It reports health and address changes, and can deploy an LDAP replica after you approve it in Forklift. Linux sign-in still uses standard SSSD, PAM and SSH.

## Basic setup

You need a Linux host with Docker Engine and Docker Compose v2. Docker Desktop is not supported. The published images currently support amd64 Linux.

1. Clone this repository and open its folder.
2. Copy the example settings and review `.env`:

   ```sh
   cp .env.example .env
   ```

3. Set `FORKLIFT_IMAGE_PREFIX` to your Gitea registry/account. Images use `latest` automatically; no tag setting is needed. Find the image location in Gitea Packages; see [image setup](docs/ci.md#deploy-published-images). For private packages, sign in with `docker login YOUR_REGISTRY` using a read-only package token.
4. For remote access, set `FORKLIFT_PUBLIC_URL` to your HTTPS address and configure your reverse proxy. The default management port is 8080 and is reachable only from the Docker host. See the [network setup guide](docs/reference-guide.md).
5. Download and start Forklift:

   ```sh
   docker compose pull
   docker compose up -d
   ```

6. Open your configured address, or `http://localhost:8080` on the Docker host. Enter the installation key from your settings. If you did not choose one, find the generated key in the initialize container’s logs:

   ```sh
   docker compose logs initialize
   ```

7. Follow the setup wizard to choose your directory name, private server address and administrator account. Forklift creates the LDAP service and certificates for you. **You do not need an existing LDAP server.**

Keep `.env`, installation keys and backups private. Container recreation keeps your data; deleting storage volumes removes it.

## What to do next

- Create users and groups in the WebUI.
- [Set up Linux sign-in](docs/linux-clients.md).
- [Enroll a machine with Forklift Client](docs/client-enrollment.md).
- [Deploy a replica through an enrolled client](docs/client-replica-deployment.md), or [add a replica manually](docs/replication.md).
- [Back up and restore your installation](docs/operations.md).
- [Check network connections and ports](docs/network-checks.md).

LDAP and DNS continue working when the management interface is offline. Replicas provide backup access only after they have synchronized. Adding a host entry alone does not set up Linux sign-in.

## Builds and development

Gitea Actions publishes ready-built images to Gitea Packages and GitHub Container Registry (GHCR). See [CI setup and image downloads](docs/ci.md) to configure the publishing token and deploy those images.

For development commands, see [Repository Guidelines](AGENTS.md). Detailed setup, reverse-proxy configuration and troubleshooting are in the [reference guide](docs/reference-guide.md). This project is under active development; [verification notes](docs/verification.md) describe what has been tested and current limits.
