# Milestone 1 validation

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
