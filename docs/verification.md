# Milestone 4 verification

Validated on 2026-11-20–21 using a Linux x86_64 Docker host, native OpenLDAP 2.6.10 containers and Ubuntu 24.04 client containers. Each integration project uses independent named volumes and random credentials. Replication and recovery tests generate disposable installation secrets; they do not rotate the checkout's credentials. Failure tests intentionally interrupt only their own fixtures.

| Check | Result |
| --- | --- |
| Rust formatting, locked compilation/unit tests (including monotonic schema guards) and Clippy with warnings denied | Passed; 8 unit tests |
| TypeScript/Vite production build and frontend Prettier checks | Passed |
| Python compilation, renewal shell syntax and Docker image builds | Passed |
| Core real-LDAP integration with Ubuntu client mode | Passed; 103 HTTP checks plus native NSS/PAM/SSH and Ansible idempotence |
| Real HTTPS replica enrollment and Syncrepl suite | Passed; 86 HTTPS checks after guided-enrollment improvements, independent volumes, interruption/catch-up, primary/manager outage and fresh Ubuntu SSH |
| Replica lifecycle extension | Passed; staged dual trust, actual presented-certificate verification, final trust redeployment, stale/scoped credential updates and native service/monitor rotation |
| Encrypted backup and fresh-target restoration | Passed; 34 HTTP checks plus native LDAP and SQLite validation, age wrong-key/corruption checks, strict archive validation, ID floor, old-session rejection, replica quarantine and recovery write guard |
| Interrupted service rotation | Passed; fail-closed startup, refusal to overlap an active orphan helper, and resume from a deliberate LDAP/secret-file mismatch |
| Primary leaf renewal | Passed; unchanged CA, existing/new DNS SANs, private-key ownership, injected SAN rejection and interrupted-pair resume |
| Populated Milestone 2 and 3 installation upgrades | Passed; schemas 2/3 → 4 with identity, ID, host and session preservation, 96 HTTP checks per upgrade |
| Real Chromium UI | Passed; login, Settings API data, audit search/export link, directory navigation, dark/light modes and 390-pixel mobile layout without horizontal overflow |

Run the checks from the README. Optional browser verification uses a pinned Playwright container and matching host-side test package outside the repository:

```sh
npm install --prefix /tmp/forklift-browser --no-save --ignore-scripts playwright@1.65.0
FORKLIFT_TEST_BROWSER_DEPS=/tmp/forklift-browser/node_modules \
FORKLIFT_TEST_BROWSER_OUTPUT=/tmp/forklift-browser-output \
  python3 tests/hardening.py
```

Browser credentials travel through stdin; no trace/video or login screenshots are retained. Screenshots capture only authenticated Settings in the disposable directory. Test resources are removed after execution; the requested screenshot output directory remains for inspection.

These tests exercise independent Docker projects and real protocol/process behavior on one host. They are not a physical multi-host disaster simulation, external security audit, dependency vulnerability certification or exhaustive browser/platform matrix. No production installation was upgraded or restored as part of these checks. Test recovery with your own DNS, private networks, storage, reverse proxy and Linux clients before relying on it. Offline password caching remains disabled by default, and no automatic primary promotion or CA-root rollover is provided.

## Guided enrollment follow-up (2026-11-21)

The replica flow was verified through real primary preparation, credential-free primary TLS verification, browser setup and private archive download. Checks cover rejected unauthenticated/CSRF requests, a failed check before certificate preparation, a successful check afterward, actual TLS on the privately published host port, persistent Compose publication, preconfigured replica bind/port values and executable start scripts. The replica starts using the generated `start.sh`; downloaded enrollment files retain operator ownership while a one-shot helper prepares a private runtime volume. A deliberately unreachable provider fails before consuming the token, and the original token subsequently enrolls successfully. The full Syncrepl/Ubuntu failover/lifecycle suite passes with this flow.

Chromium also checks the first-replica instructions on HTTP setup, where enrollment is disabled pending WebUI HTTPS, and the complete three-step setup and download behind the disposable HTTPS proxy. The latter is enabled with:

```sh
FORKLIFT_TEST_BROWSER_DEPS=/tmp/forklift-browser/node_modules python3 tests/replication.py
```

These additions passed Rust tests/Clippy, production frontend/Docker builds, formatting, Python compilation, shell syntax and the encrypted recovery regression suite (34 HTTP checks plus actual LDAP restoration/rotation).
