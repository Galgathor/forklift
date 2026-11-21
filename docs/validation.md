# Validation

## Milestone 2 — Linux integration

Verified locally on 2026-11-20, Linux/amd64, Docker Engine 29.1.3, Forklift 0.2.0 and OpenLDAP 2.6.10.

| Check                                                                             | Result                                                                                                                         |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Rust formatting, locked unit tests and Clippy with warnings denied                | Passed; four tests, including endpoint/configuration injection rejection and schema migration                                  |
| Strict TypeScript checking and Vite production build                              | Passed                                                                                                                         |
| Final manager image and Ubuntu client image builds                                | Passed                                                                                                                         |
| Frontend/documentation/Ansible Prettier formatting                                | Passed                                                                                                                         |
| Python compilation, shell syntax and optional LDAPS Compose configuration         | Passed                                                                                                                         |
| Full integration suite with `FORKLIFT_TEST_UBUNTU=1`                              | Passed; 102 HTTP checks plus real Ubuntu NSS/PAM/SSH and Ansible operations                                                    |
| Subsequent core integration run with additional password-rotation/metadata checks | Passed; 92 HTTP checks plus LDAP bind verification and SQLite/WAL inspection                                                   |
| `python3 tests/certificates.py`                                                   | Passed using a disposable CA; internal/external SANs, CA preservation, restricted key permissions and injected-input rejection |

Host tests cover authenticated/unauthenticated access, CSRF, invalid/empty policies, unknown groups, duplicate hostnames, stale edit/export revisions, archive permissions, policy-group dependencies, host persistence across recreation and read-identity deletion. Additional rotation tests reject the old host credential, accept its replacement and verify the reusable secret is absent from API metadata, SQLite and its journal. The Ubuntu test additionally verifies the read identity cannot modify users or read password hashes.

The Ubuntu 24.04 container ran the actual Ansible role twice (second run `changed=0`), actual SSSD and OpenSSH, and ordinary SSH password authentication through Ubuntu PAM. It verified LDAP UID/GID and supplemental groups through NSS, automatic home creation, permitted and denied users, wrong passwords, live group changes after cache expiration, disabled/expired accounts (including account-only PAM checks), wrong-CA rejection, private endpoint fallback when the first port was unreachable, local recovery accounts, login with the manager stopped, no offline LDAP password login during a directory outage, and recovery afterward. These are not mocked authentication checks.

A test initially expected host read-identity deletion to stop all subsequent SSH authentication. Ubuntu showed that SSSD can authenticate a known user with that user's own LDAP credentials. The assertion was corrected to test the actual boundary (deleted read credentials cannot bind), and this operational limit is explicit in the UI/guide/security documentation. Host deletion is not a remote access kill switch.

The Ubuntu fixture runs SSSD and sshd directly and uses `forklift_manage_services=false`; a full systemd boot, service handlers in a VM, Ubuntu 22.04, browser rendering/interactions, multi-architecture builds, SSH key workflows, performance/load, actual Syncrepl replication, backup/restore drills and production security certification remain unverified. Group changes were checked after explicitly expiring identity caches rather than waiting out their configured 60-second TTL. Fallback was tested against an unreachable port followed by a live primary, not against a real replica.

Tests create and clean up isolated Compose projects, a disposable Ubuntu container and temporary secret archives. No default installation or real CA/private key was modified by the certificate test. Historical Milestone 1 results follow for context; Milestone 2 supersedes their statement that Linux integration is unimplemented.

---

# Milestone 1 validation (historical)

Verified locally on 2026-11-20 using Docker Engine 29.1.3 on Linux/amd64.

| Check                                                | Result                                                                   |
| ---------------------------------------------------- | ------------------------------------------------------------------------ |
| Rust formatting, `cargo test --locked`               | Passed; two validator unit tests                                         |
| `cargo clippy --locked -- -D warnings`               | Passed                                                                   |
| TypeScript strict checking and Vite production build | Passed, including the final manager image build                          |
| Prettier frontend/documentation formatting           | Passed                                                                   |
| Installer shell syntax and Compose configuration     | Passed                                                                   |
| Python module compilation                            | Passed                                                                   |
| Both production Docker image builds                  | Passed                                                                   |
| `python3 tests/integration.py`                       | Passed; 70 HTTP checks plus direct LDAP operations and failure scenarios |

The integration suite used fresh randomly named Compose projects and removed its own volumes. It did not initialize a default installation. Both containers ran without capabilities and with read-only root filesystems. Tests used real OpenLDAP 2.6.10 with the native Argon2 module and actual certificate verification.

Verified behavior includes unauthorized reads, wrong bootstrap token, hostile Origin, bootstrap replay, wrong password, administrator login, cookie attributes, CSRF rejection, actual user/group CRUD, Unix ID allocation without reuse, primary-group and administrator protections, direct LDAP password authentication, disabled binds, password reset, mandatory password on re-enable, immediate administrative membership revocation, absence of password hashes in API JSON, session/directory persistence across container recreation, LDAP authentication with the manager stopped, fail-closed management when LDAP stops, recovery after restart, logout invalidation, and persistent global login throttling.

The TLS failure test recreated the Rust manager with an unrelated CA trust store and confirmed that `/ready` and the authenticated API returned 503. Restoring its real trust store restored directory access. An independent directory-side TLS client also rejected an untrusted certificate. The initial test exposed missing CA key-usage extensions; certificate generation was corrected before the final clean test run.

Not verified: browser rendering/interactions, Ubuntu SSSD/PAM/SSH authorization, multi-architecture builds, performance/load, replica enrollment/failover, full backup/restore drills, certificate renewal or credential rotation. Browser automation was unavailable. Host integration and replication are unimplemented future milestones; offline backup/restore is documented but not certified by this test suite. This validation does not constitute a security audit or production certification.
