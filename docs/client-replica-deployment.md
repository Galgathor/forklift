# Deploy an LDAP replica through Forklift Client

Install Docker Engine with a Compose plugin supporting `up --wait` on the target Linux machine, install client 0.5, and enroll it. Docker is a prerequisite; the client does not install or reconfigure the shared Docker daemon. Choose a stable private IPv4 address for the replica and permit the selected private LDAP/control ports from their intended sources. The host also needs management HTTPS and primary LDAPS connectivity. Forklift never changes firewall rules, SSSD, PAM/NSS, SSH or host resolver configuration.

## WebUI workflow

1. Upgrade Forklift and the client to matching replica component versions. Wait for the host's fresh inventory report.
2. Open **Hosts → Client enrolled → LDAP replica service**.
3. Select the host's private address and distinct LDAP/control TCP ports (defaults 1636/9443; client-driven deployment requires ports >=1024).
4. Select **Deploy LDAP replica** and confirm the target service.
5. Follow queued, preparing, starting and client-reported service state. **Directory synchronization** comes from the manager's existing verified LDAP/contextCSN checks, independently of client progress.

Use a separate machine for host-failure protection. A second container on one machine cannot protect against that machine failing. Every replica has an independent persistent volume. No Git checkout, manual archive transfer, certificate exchange, LDIF editing or join-configuration copying is required for this workflow. Manual replica enrollment remains available.

## Deployment mechanism

The native executable contains the approved Dockerfile and replica supervisor from the matching Forklift release. The server job identifies their SHA-256 component digest; the client refuses a different component. It never accepts scripts, Dockerfiles, Compose YAML, images, mount paths or shell fragments from server responses.

The client invokes fixed local Docker/Compose commands directly, using the local Unix socket transiently through the CLI. The manager receives no Docker access, and no container mounts the Docker socket. The first deployment builds the pinned-base/pinned-OpenLDAP image from the packaged build context, requiring registry/package-repository access. Build contexts exclude enrollment files and other workspace contents. A future release can use approved prebuilt images pinned by digest without changing the WebUI workflow; no image registry publishing is currently claimed.

Each job owns one `forklift-replica-<job-id>` Compose project and named data volume. The client refuses unknown existing storage/containers and verifies Compose ownership labels before reuse. Protected workspaces and a separate atomic deployment journal live under `/var/lib/forklift-client/`. Credentials and host report counters remain in their existing independent state. The replica runs as UID 10001 with a read-only root filesystem, bounded logs and all Linux capabilities dropped. One fixed read-only host public-CA bundle mount lets its HTTPS enrollment honor Ubuntu's system trust; an explicit enrollment CA is also preserved. No host credential/configuration directories are mounted.

The client builds before requesting a 15-minute enrollment credential over its existing authenticated HTTPS/DPoP channel. It starts the service, then clears the consumed credential from the protected environment file and container configuration. Replica private keys are generated inside its volume. The existing replica enrollment provisions native Syncrepl, trust and read-only replication permissions. The selected Host ID, name, hostname, access groups and DNS policy remain intact; there is no hostname/IP-based enrollment merge.

## Failure, retry and scope

The atomic journal survives client/process interruption. Retry from the WebUI resumes only the same approved project/storage; existing LDAP data is never reset or deleted. A port conflict, missing Docker/Compose, unavailable address, component mismatch or failed container health produces a separate deployment error. Client heartbeat/diagnostics continue during deployment; ordinary credential rotation waits for the active worker. The systemd memory ceiling is 256 MiB to accommodate the Docker CLI; image builds run in Docker's own daemon.

**Cancel deployment** cancels further deployment authorization and invalidates an unused pending join credential. It does not remove data or stop already-created containers. Client revocation similarly prevents subsequent machine-authorized operations; a provisioned directory retains its separate identity. Fence and retire a compromised replica through the directory-server recovery/administration procedures as well.

Running replicas restart through Docker and continue authenticating independently of the manager/client. Completed deployments are not replayed automatically after package upgrades. This first release supports LDAP deployment/retry, not client-driven DNS secondaries, Docker installation, arbitrary service management, automatic replica image upgrades, automatic teardown/reseeding or primary promotion. Select stable addresses/ports before approval; pending deployment records are retained for review rather than silently overwritten.
