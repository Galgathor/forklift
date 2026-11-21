# Security model

This is an early security-critical implementation, not a completed security audit or a production-hardening claim.

- The browser authenticates via an LDAP bind over verified LDAPS. A designated POSIX group's explicit memberUid membership authorizes management access. Every privileged API request rechecks membership and disabled state.
- Sessions are random 256-bit tokens; SQLite stores SHA-256 digests. Cookies are HttpOnly, SameSite=Strict, scoped to `/`, expire after eight hours and use Secure for configured HTTPS origins. Mutations require exact Origin plus a random per-session CSRF token. Login and bootstrap require exact Origin. No cross-origin API/CORS support.
- Credentials are not included in audit records or JSON responses. LDAP queries request an explicit attribute allowlist without userPassword. Password changes use LDAP Password Modify and the native OpenLDAP Argon2 module. API errors return generic operational messages.
- Username/group/base-DN validation excludes filter and DN metacharacters. Numeric fields are typed. LDAP values are transmitted through the ldap3 encoder, not interpolated LDIF. Only the constrained initial helper builds LDIF after validating all interpolated identifiers.
- The manager holds a write-capable service credential for directory data. It has no cn=config connection, rootDN credentials, OS root, shell/command endpoint or Docker socket. Protect `.secrets`, metadata, volumes and host root access; reusable service credentials currently use restricted files rather than an external secret manager.
- The one-shot helper runs as the LDAP OS user and accepts only a fixed initialization payload authenticated by a random installation token over verified TLS. It can create initial configuration; it cannot accept commands or arbitrary LDIF and refuses a second initialization. Neither helper nor LDAP is published on host ports. Processes on the private Docker network are inside this trust boundary.
- The CA signing key remains only on the installation host. It is never mounted into the manager or directory. Both containers use read-only root filesystems, drop Linux capabilities and disallow acquiring privileges; only persistent data volumes and temporary memory storage are writable.
- Forwarded headers are ignored. Public URL configuration controls origin validation and cookie transport policy. No request-derived host/scheme or forwarded client-IP is trusted. Twenty login attempts per five minutes are allowed globally, persisted across restarts.
- Deleting or disabling your own current administrator, removing yourself from administrators or renaming/deleting that group is refused. Password resets and disables remove target sessions. Disabled users have no LDAP password and an expired shadow account; offline client caches are outside this mechanism.

## Known limits

The UI cannot rename users or customize UID/GID allocation. The shared numeric allocator assumes exclusive Forklift administration and matching metadata/directory backups. All results currently fit the homelab-oriented directory search size limit; server-side paging is planned. No administrative MFA, credential-rotation UI, SSH-key schema, host enrollment, replication, supported online backup/restore, per-IP throttling, distributed transactions or multi-manager coordination. The API is intended for a restricted management network behind HTTPS. HTTP is available for loopback setup/development only.

LDAP writes and audit writes are separate operations; interrupted multi-step changes can be partial. Mutation attempts are recorded before changes, with a separate completion event after successful operations. An attempt without a completion requires operator inspection. Audit log rotation and tamper-resistant external audit export are planned. Login failure logging is deliberately minimal. Existing LDAP sessions, client caches and SSH connections are not terminated by account disable. Group renames may affect future external access policies; this version has no policy engine.

Before production deployment, complete restore drills, dependency/security review, credential/certificate lifecycle management, client authorization tests and the remaining hardening milestone. Never disable certificate verification as a workaround.

## References

[OpenLDAP 2.6 administration](https://www.openldap.org/doc/admin26/guide.html), [OpenLDAP access control](https://www.openldap.org/doc/admin26/access-control.html), and [ldap3 API documentation](https://docs.rs/ldap3/0.12.1/ldap3/) describe the directory operations and ACL behavior used here.
