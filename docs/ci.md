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

Main publishes `sha-<full-commit>` tags. A tag exactly matching `v<Cargo.toml version>` also publishes the version without `v`. After all five images and their digest manifests are published, successful main builds also update `latest` for all five images. Release-tag builds do not change `latest`. Output is linux/amd64 only. A Generic package named `forklift-images` contains five JSON digest manifests for each build (`<version>-dev.<full-commit>` on main, exact version for release tags). Pull by the recorded digest when immutable deployment is required. OCI version tags are conventional registry tags; protect release tags and restrict package-write credentials, since registry administrators can otherwise retag them.

The client publishes an executable, Ubuntu 24.04 amd64 `.deb`, `build.json` and `SHA256SUMS` into the owner's **forklift-client** Generic package. Main versions use `<version>-dev.<full-commit>`; Debian revisions use `0.dev.<full-commit>` so they sort below stable revision `1`. Release tags must match the manifest version. Image publishing checks existing single-platform image configurations and refuses to replace a different image at the same tag. Registry lookups must succeed or confirm absence before a new push; protect release tags/package access to cover concurrent external publishers. Existing Generic files are accepted on rerun only if byte-identical; differing output fails without deleting/overwriting the package. Packages are downloaded from Gitea's Packages UI/API; this is not an APT repository or a signature/release-asset service. Package visibility/access follows the owner's Gitea configuration.

## Deploy published images

Compose pulls the published `ghcr.io/galgathor/forklift-*` images directly. No package-location setting is required in `.env`.

Compose uses `latest` automatically. To keep a particular build, optionally set `FORKLIFT_IMAGE_TAG=sha-FULL_COMMIT_SHA` instead.

Run `docker compose pull` when you want to download updates, then recreate the stack. Running containers do not update automatically. Wait for the complete publishing workflow to succeed before pulling; registries update image tags individually, so a failed or interrupted publish can leave mixed `latest` tags. Use a common commit tag for a fixed build.

Authenticate with a **read-only** package token if pulling private images. Do not distribute the CI write token to hosts. Keep the existing volumes and runtime configuration:

```sh
docker compose pull
docker compose up -d
```

The main Compose file uses published images directly; no overlay is needed. For local source builds, add `-f compose.yaml -f compose.dev.yaml` to build and startup commands. The older `compose.images.yaml` remains compatible but is unnecessary for the main stack. Image overlays using `!reset` require Compose 2.24.4 or newer and are provided in `deploy/replica/` and `deploy/dns-secondary/` for their existing manual enrollment flows. Container recreation preserves the existing named-volume configuration; take a normal backup before upgrades. Client-driven replica deployment still uses its locally compiled allowlist/build context; publishing images does not silently change that trust policy.

Until secrets are filled in and a real runner job completes, package publication is unverified. Re-run the workflow after configuring secrets; create `v<version>` tags explicitly when ready for a stable release. No workflow deploys containers to production or changes host authentication/firewall settings.

References: [Gitea container packages](https://docs.gitea.com/usage/packages/container/), [Generic package API](https://docs.gitea.com/usage/packages/generic/), [Actions variables](https://docs.gitea.com/usage/actions/actions-variables/).

## GitHub Container Registry mirror

The server workflow also publishes the same five images to GHCR after Gitea publication succeeds. Forklift Client remains a native download in Gitea Packages; this does not add a client container or change its publishing workflow.

Set these **Actions secrets** in the Forklift server repository (or make them available as shared secrets):

- `GHCR_USERNAME`: your GitHub username.
- `GHCR_TOKEN`: a GitHub personal access token (classic) with `write:packages`, authorized for the destination account or organization. If your organization requires SSO, authorize the token for it.

The destination defaults to `ghcr.io/<lowercase-GHCR_USERNAME>/forklift-manager` and the corresponding `forklift-ldap`, `forklift-replica`, `forklift-dns` and `forklift-maintenance` packages. To publish under an organization, set the optional Actions **variable** `GHCR_OWNER` to its name. Keep `GHCR_USERNAME` as the token owner's username.

Commit tags and release tags match Gitea. Successful main builds also update `latest`, after all five GHCR revision images have been published. Images are retagged from the existing local build, not rebuilt for GHCR. Existing revision tags are checked before writing and a different image is refused. Login uses standard input and a temporary Docker configuration; GHCR secrets are available only to the GHCR publishing step. The workflow writes local `dist/images/ghcr-*.json` digest records; Gitea's published digest records still refer to Gitea images.

The supplied Compose files already use `ghcr.io/galgathor`. No registry or account setting is needed. Forks publishing elsewhere can replace the image names in their own Compose override.

Then run `docker compose pull` and `docker compose up -d`. No tag setting is needed. For private packages, sign in to `ghcr.io` with a read-only package token first. Newly created GHCR packages are private by default; change each package's visibility in GitHub if you want anonymous downloads. The workflow does not change visibility. A successful local check cannot verify your registry permissions; the first Actions run confirms actual publication.

See GitHub's [container registry guide](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry) for token permissions, SSO and package visibility.
