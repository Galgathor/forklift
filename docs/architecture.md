# Architecture and implementation plan

Milestone 1: one non-root Axum process serves a React application and a same-origin JSON API. OpenLDAP owns users, POSIX groups, salted passwords and account state. SQLite owns setup state, expiring sessions, monotonic Unix ID allocation, login throttling and administrative audit records. All administrative requests recheck LDAP administrator-group membership. Mutations require an exact configured Origin and a per-session CSRF token.

A separate, unexposed one-shot provisioning HTTP helper in the directory container creates a constrained slapd configuration and initial directory. It runs as the directory OS user, cannot accept commands or arbitrary LDIF, and refuses reinitialization. The manager never receives cn=config or root LDAP credentials. TLS uses an installation-local CA; the manager verifies its directory certificate. Installation secrets are files with restricted permissions outside Git. LDAP and management have independent lifetimes after provisioning.

Implementation sequence: provision TLS and deployment files; implement setup and LDAP authentication; implement user/group API and persistent metadata; implement responsive setup/login/dashboard and CRUD; run formatting, builds and integration tests against the real Compose stack; document recovery limits. Commit each working stage.

Milestone 2 adds host/SSSD/Ansible workflows as described below. Milestones 3–4 remain planned: replication/enrollment, supported backup/restore and credential rotation. No synthetic host or replication data will be presented as working features. Milestone 1 is a development release until security and failure checks pass. Setup uses a single instance; active/active managers are unsupported.

## Milestone 2 implementation plan

Add version-2 metadata for registered hosts, permitted LDAP group names, ordered LDAPS endpoints and configuration/export revisions. Host state describes configuration generation only; there is no resident agent or invented reachability data. Each export creates/rotates a dedicated read-only LDAP bind identity. Reusable host credentials are returned only in a protected archive, never persisted in SQLite. Existing installation ACLs already permit authenticated reads and forbid password reads and non-manager writes, so no privileged directory migration is needed.

Generate RFC2307 SSSD identity/password configuration with certificate verification and shadow account-expiry checks. PAM enforces allowed POSIX groups for SSH, preserving local recovery accounts; SSH access never grants sudo. Provide an Ubuntu Ansible role and equivalent manual instructions. Export revisions and group references prevent stale or silently broken policies. Deployable LDAPS endpoints need real DNS certificate SANs and explicit private-interface publication, independently of NPM.

Verify API authorization/CSRF, group dependencies, credential isolation/revocation, upgrades and persistence. Add an Ubuntu 24.04 client running actual SSSD, PAM and OpenSSH; test permitted/denied users, LDAP group updates, disabled accounts, passwords, TLS, endpoint fallback and Ansible idempotence. Multi-server replication remains Milestone 3.
