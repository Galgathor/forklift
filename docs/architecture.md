# Architecture and implementation plan

## Version 0.5 architecture

One Rust/Axum process serves the React application and same-origin API. OpenLDAP owns users, groups, POSIX attributes and salted passwords; SQLite owns configuration, expiring sessions, monotonic ID allocation, host policy/revisions, node enrollment epochs and audit events. Administrative requests recheck directory authorization, and writes require exact Origin plus CSRF.

Docker Compose starts a one-shot initializer, primary OpenLDAP container, network-isolated custodian and manager. All runtimes use UID10001 and read-only root filesystems. Only directory runtimes retain NET_BIND_SERVICE. There is no Docker socket, SSH-from-manager or command endpoint.

Named volumes separate manager metadata, manager/runtime secrets, directory data, signing authority, encrypted backups, transfers, maintenance journals and Unix IPC. The CA key is available only to the custodian. The primary supervisor accepts fixed authenticated Unix requests; manager LDAP access uses a protected LDAPI socket. Remote authentication/replication use verified LDAPS. Linux host networking lets setup configure a private native listener without Docker authority.

Initial setup verifies a local installation key, readiness and private interface, creates the primary listener/certificate, then initializes directory/admin metadata or restores a supported backup. Every directory server maintains a corresponding Hosts inventory record with no implicit SSH access. New replica enrollment inherits the primary endpoint; there is no Existing Server setup during add-replica.

Replicas run native read-only Syncrepl with independent storage. One-use HTTPS enrollment validates/pins a locally generated leaf; private keys remain local. The WebUI emits a copyable join setting with public trust for the standalone `deploy/replica` Compose stack in the same repository. The existing archive API remains compatible. A narrow pinned-TLS control service applies epoch-ordered credentials, provider changes, restarts and staged certificate renewal. No primary promotion occurs. Monitoring uses actual verified binds/nonempty contextCSN comparisons.

Maintenance jobs drain ordinary requests, close SQLite, pause native LDAP and call fixed Unix-only custodian operations. Durable phase/ticket records outside restored storage keep the WebUI recoverable. Restore verifies authenticated encryption, externally trusted checksum, archive paths/hashes, metadata and native LDAP before publication; coherent rollback storage remains until manager acknowledgment. Private recovery identities never enter durable records. Restored sessions/enrollment are invalidated, replicas quarantined and writes held for recovery review.

## Implementation sequence

1. Replace legacy deployment/scripts with primary supervision, split-secret initialization and constrained maintenance control.
2. Add Rust maintenance coordination and authentication fencing, initial network/restore setup, automatic directory host inventory and replica remote controls.
3. Add browser setup, maintenance/progress/recovery, and replica lifecycle forms.
4. Exercise real fresh setup, auth/CRUD, encrypted restore, interruptions, native replication, Ubuntu authentication and browser behavior. Update instructions and remove routine CLI tools.

Version 0.5 deliberately requires fresh storage (schema5/archive2); earlier releases remain necessary for old volumes/backups. The only console administration exception is administrator lockout recovery. SSH-key schema, automatic client deployment and backup scheduling remain future work.
