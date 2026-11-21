# Security model

This is an early security-critical implementation, not a completed security audit or a production-hardening claim.

- The browser authenticates via an LDAP bind over verified LDAPS. A designated POSIX group's explicit memberUid membership authorizes management access. Every privileged API request rechecks membership and disabled state.
- Sessions are random 256-bit tokens; SQLite stores SHA-256 digests. Cookies are HttpOnly, SameSite=Strict, scoped to `/`, expire after eight hours and use Secure for configured HTTPS origins. Mutations require exact Origin plus a random per-session CSRF token. Login and bootstrap require exact Origin. No cross-origin API/CORS support.
- Credentials are not included in audit records or JSON responses. LDAP queries request an explicit attribute allowlist without userPassword. Password changes use LDAP Password Modify and the native OpenLDAP Argon2 module. API errors return generic operational messages.
- Username/group/base-DN validation excludes filter and DN metacharacters. Numeric fields are typed. LDAP values are transmitted through the ldap3 encoder, not interpolated LDIF. Only the constrained initial helper builds LDIF after validating all interpolated identifiers.
- The manager holds a write-capable service credential for directory data. It has no cn=config connection, rootDN credentials, OS root, shell/command endpoint or Docker socket. Protect `.secrets`, metadata, volumes and host root access; reusable service credentials currently use restricted files rather than an external secret manager.
- The one-shot helper runs as the LDAP OS user and accepts only a fixed initialization payload authenticated by a random installation token over verified TLS. It can create initial configuration; it cannot accept commands or arbitrary LDIF and refuses a second initialization. The default stack publishes neither helper nor LDAP. An optional Compose override publishes only LDAPS on an explicitly configured private interface; the provisioner stays unexposed. Processes on the private Docker network are inside this trust boundary.
- The CA signing key remains only on the installation host. It is never mounted into the manager or directory. Both containers use read-only root filesystems, drop Linux capabilities and disallow acquiring privileges; only persistent data volumes and temporary memory storage are writable.
- Forwarded headers are ignored. Public URL configuration controls origin validation and cookie transport policy. No request-derived host/scheme or forwarded client-IP is trusted. Twenty login attempts per five minutes are allowed globally, persisted across restarts.
- Deleting or disabling your own current administrator, removing yourself from administrators or renaming/deleting that group is refused. Password resets and disables remove target sessions. Disabled users have no LDAP password and an expired shadow account; offline client caches are outside this mechanism.

## Known limits

The UI cannot rename users or customize UID/GID allocation. The shared numeric allocator assumes exclusive Forklift administration and matching metadata/directory backups. All results currently fit the homelab-oriented directory search size limit; server-side paging is planned. No administrative MFA, manager-service-credential rotation UI, SSH-key schema, supported online backup/restore, per-IP throttling, distributed transactions or multi-manager coordination. The API is intended for a restricted management network behind HTTPS. HTTP is available for loopback setup/development only.

LDAP writes and audit writes are separate operations; interrupted multi-step changes can be partial. Mutation attempts are recorded before changes, with a separate completion event after successful operations. An attempt without a completion requires operator inspection. Audit log rotation and tamper-resistant external audit export are planned. Login failure logging is deliberately minimal. Existing LDAP sessions, client caches and SSH connections are not terminated by account disable. Host group dependencies prevent renaming/deleting referenced groups. Permitted-group changes require deploying a new host configuration; group membership updates follow NSS/SSSD cache policy.

## Replication boundary

Enrollment requires configured manager HTTPS, an authenticated administrator to issue a scoped bundle and a 256-bit one-use token expiring after 15 minutes. Only the token digest is stored. Enrollment certificates must be valid self-signed non-CA RSA leaves for exactly the registered DNS name. Private keys remain on replicas; no signing CA key enters a long-running service container. Native TLS hostname/chain checks remain enabled. A routine monitor uses a separate read-only credential; it never sends the manager write-service password to a secondary.

The dedicated Syncrepl identity must read password hashes, so every replica is trusted authentication infrastructure. The manager returns its credential once; the native consumer stores it in restricted local persistent configuration. Consumers have no bindable root credential and reject network writes. Each replica has independent storage. No automatic promotion, Docker control or remote shell endpoint exists.

Replica-backed administrative reads recheck authorization against a verified replica during primary failure. Asynchronous data can be stale, including passwords and administrator groups. Writes always require the primary. ContextCSN equality is sampled evidence; the last-confirmed timestamp is never advanced while the primary is unavailable. Deleting a replication identity does not forcibly terminate existing bound connections; stop replicas before decommissioning. Full details and recovery: [replication](replication.md).

Before production deployment, complete restore drills, dependency/security review, credential/certificate lifecycle management, broader client/platform testing and the remaining hardening milestone. Never disable certificate verification as a workaround.

## Linux host boundary

Registered hosts receive independent read-only LDAP bind identities. Export is an authenticated, CSRF-protected POST with explicit rotation acknowledgment and a current configuration revision. The protected archive contains the plaintext read credential required by SSSD; it is never written to metadata or audit records. A second export rotates it. API/filename/configuration inputs are validated, paths and URI credentials are rejected, and archives contain fixed relative filenames. The UI does not infer successful remote deployment from an export.

SSSD uses RFC2307 identity lookup, verified LDAPS, native endpoint fallback and shadow account-expiry checks. Destination SSH PAM enforces permitted POSIX groups, bypassing only the added group rule for local recovery accounts. Both primary and supplemental groups count. No sudo provider/rules are generated. Default offline password caching is disabled, but identity/group caches and existing sessions are separate concerns.

Read-credential deletion/rotation is not an LDAP user authentication ban. In Ubuntu tests, a known user could still authenticate using their own password after the host read identity was deleted. Decommission by changing/removing the host configuration or controlling network access; disabling an account remains a directory-wide user decision. Existing SSH sessions are not forcibly terminated.

The local certificate-renewal script runs a temporary Docker process with only the installation secrets mounted; this is an operator command, never a WebUI endpoint. The CA key remains outside both long-running service containers. Protect generated bundles and root-only SSSD configuration/backups, and use HTTPS for the management UI.

## References

[OpenLDAP 2.6 administration](https://www.openldap.org/doc/admin26/guide.html), [OpenLDAP access control](https://www.openldap.org/doc/admin26/access-control.html), and [ldap3 API documentation](https://docs.rs/ldap3/0.12.1/ldap3/) describe the directory operations and ACL behavior used here.
