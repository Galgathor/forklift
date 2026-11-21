# Architecture and implementation plan

Milestone 1: one non-root Axum process serves a React application and a same-origin JSON API. OpenLDAP owns users, POSIX groups, salted passwords and account state. SQLite owns setup state, expiring sessions, monotonic Unix ID allocation, login throttling and administrative audit records. All administrative requests recheck LDAP administrator-group membership. Mutations require an exact configured Origin and a per-session CSRF token.

A separate, unexposed one-shot provisioning HTTP helper in the directory container creates a constrained slapd configuration and initial directory. It runs as the directory OS user, cannot accept commands or arbitrary LDIF, and refuses reinitialization. The manager never receives cn=config or root LDAP credentials. TLS uses an installation-local CA; the manager verifies its directory certificate. Installation secrets are files with restricted permissions outside Git. LDAP and management have independent lifetimes after provisioning.

Implementation sequence: provision TLS and deployment files; implement setup and LDAP authentication; implement user/group API and persistent metadata; implement responsive setup/login/dashboard and CRUD; run formatting, builds and integration tests against the real Compose stack; document recovery limits. Commit each working stage.

Milestones 2–4 are planned: host/SSSD/Ansible workflows, replication/enrollment, supported backup/restore and credential rotation. No synthetic host or replication data will be presented as working features. Milestone 1 is a development release until security and failure checks pass. Setup uses a single instance; active/active managers are unsupported.
