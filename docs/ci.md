# Gitea Actions and packages

Both repositories use the existing `ubuntu-latest` runner label. Enable Actions in each repository's settings. Trusted pushes to `main`, `v*` tags and manual runs on those refs perform checks/builds and publish to the repository owner's Gitea Packages. Other refs are rejected. Pull-request workflows are deliberately absent: these jobs execute trusted repository code with access to Docker. Use an isolated build runner, separate from production directory/data workloads.

## Secrets to configure

Set **PACKAGES_TOKEN** in **Settings → Actions → Secrets** in **both** `forklift` and `forklift-client`, or as a shared owner-level Actions secret if supported by your instance. Use a personal access token belonging to the publishing account with **write:package** (package read/write) permission. It must be authorized for the target user/organization's packages. No administrator, repository-write, SSH private key, Docker Hub credential or runner registration token is needed. Checkout uses Gitea's built-in job token.

For private PKI, the optional **CI_CA_CERT** secret in the client repository contains the **public PEM CA certificate/bundle only**. It installs trust into the fresh Ubuntu build environment before checkout; never provide a private key. Configure the runner's own OS/Node trust and Docker daemon's registry trust separately before either workflow runs. Verification is never disabled. Publicly trusted Gitea HTTPS needs no extra certificate secret.

No secrets are committed. Publishing secrets are exposed only to configuration validation and publishing steps, not compiler/test/image-build steps. Docker login uses stdin and a temporary private config that is removed after the step. Package HTTP clients refuse redirects rather than forwarding authorization elsewhere.

## Optional Actions variables

| Variable | Default / purpose |
| --- | --- |
| `PACKAGES_USERNAME` | Repository owner; override when the token belongs to a different publishing user. |
| `PACKAGE_OWNER` | Repository owner; change only when publishing to another authorized user/organization. |
| `CONTAINER_REGISTRY` | Host and port from the Gitea server URL; optional separate OCI registry host. No scheme/path. |
| `DEB_MAINTAINER` | Client only: `Name <email>`; defaults to the last commit's author. Public Debian package metadata. |

The API address comes from `gitea.server_url`. OCI image namespaces use the lowercase package owner. An unusual reverse-proxy subpath may require a separately exposed registry host serving `/v2/`; configure the override accordingly.

## Runner requirements

Use an **amd64 Linux** runner. The server job needs Git, Python 3.9+, Node 20+ for checkout, Docker CLI/Buildx and access to a working local Docker daemon. Rust/Node checks run in pinned disposable containers using Docker copies, so Docker-hosted job workspaces do not need matching host bind paths. The runner still needs the tools/socket available inside its job environment; the label alone does not install them.

The client job explicitly uses a pinned Ubuntu 24.04 build container, installs build dependencies and checksum-verified Node 24.11.1 **before** the JavaScript checkout action, verifies the pinned rustup 1.28.2 bootstrap checksum, uses `rust-toolchain.toml` and locked Cargo dependencies, and installs cargo-deb 3.8.0 with `--locked`. This container is a compiler environment only: the outputs are a native Linux executable and `.deb`; there is no client container deployment. The runner must support job containers. Checkout actions use a pinned upstream commit. Network access to Gitea, GitHub Actions sources, Rust/crates, Docker base registries and package mirrors is required. Build output requires several GB of temporary disk space. Workflows time out after 60 minutes.

## Published outputs

Server builds all five images successfully before logging in/pushing:

- `<registry>/<owner>/forklift-manager`
- `<registry>/<owner>/forklift-ldap`
- `<registry>/<owner>/forklift-replica`
- `<registry>/<owner>/forklift-dns` (primary and secondary)
- `<registry>/<owner>/forklift-maintenance` (initialization and maintenance)

Main publishes `sha-<full-commit>` tags. A tag exactly matching `v<Cargo.toml version>` also publishes the version without `v`. There is no moving `latest`/`main` tag. Output is linux/amd64 only. A Generic package named `forklift-images` contains five JSON digest manifests for each build (`<version>-dev.<full-commit>` on main, exact version for release tags). Pull by the recorded digest when immutable deployment is required. OCI version tags are conventional registry tags; protect release tags and restrict package-write credentials, since registry administrators can otherwise retag them.

The client publishes an executable, Ubuntu 24.04 amd64 `.deb`, `build.json` and `SHA256SUMS` into the owner's **forklift-client** Generic package. Main versions use `<version>-dev.<full-commit>`; Debian revisions use `0.dev.<full-commit>` so they sort below stable revision `1`. Release tags must match the manifest version. Image publishing checks existing single-platform image configurations and refuses to replace a different image at the same tag. Registry lookups must succeed or confirm absence before a new push; protect release tags/package access to cover concurrent external publishers. Existing Generic files are accepted on rerun only if byte-identical; differing output fails without deleting/overwriting the package. Packages are downloaded from Gitea's Packages UI/API; this is not an APT repository or a signature/release-asset service. Package visibility/access follows the owner's Gitea configuration.

## Deploy published images

After the first successful publication, add these nonsecret values to your normal deployment environment (use your actual registry, lowercase namespace and build tag):

```dotenv
FORKLIFT_IMAGE_PREFIX=git.example.test/your-account
FORKLIFT_IMAGE_TAG=sha-FULL_COMMIT_SHA
```

Authenticate with a **read-only** package token if pulling private images. Do not distribute the CI write token to hosts. Keep the existing volumes and runtime configuration:

```sh
docker compose -f compose.yaml -f compose.images.yaml pull
docker compose -f compose.yaml -f compose.images.yaml up -d --no-build
```

The `!reset` overlays require Compose 2.24.4 or newer and remove source-build directives. Matching overlays are provided in `deploy/replica/` and `deploy/dns-secondary/` for their existing manual enrollment flows. Container recreation preserves the existing named-volume configuration; take a normal backup before upgrades. Client-driven replica deployment still uses its locally compiled allowlist/build context; publishing images does not silently change that trust policy.

Until secrets are filled in and a real runner job completes, package publication is unverified. Re-run the workflow after configuring secrets; create `v<version>` tags explicitly when ready for a stable release. No workflow deploys containers to production or changes host authentication/firewall settings.

References: [Gitea container packages](https://docs.gitea.com/usage/packages/container/), [Generic package API](https://docs.gitea.com/usage/packages/generic/), [Actions variables](https://docs.gitea.com/usage/actions/actions-variables/).
