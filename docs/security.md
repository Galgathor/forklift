# Security model — 0.5

Forklift is security-critical development software without an independent security audit. Run it on restricted management/private networks and keep local Linux recovery accounts.

## Authentication and authorization

Administrative passwords use native LDAP authentication. Internal primary management binds over a protected LDAPI socket with `localSSF 256`; remote reads, Linux authentication and replication use verified LDAPS. Explicit membership of `administrators` authorizes management independently of primary GID. Every normal privileged request rechecks live LDAP membership and disabled state. Writes require the primary and are blocked pending post-restore review.

Sessions use random 256-bit tokens, stored only as SHA-256 digests, with HttpOnly, SameSite=Strict cookies, eight-hour expiry and Secure for the saved HTTPS origin. Mutations require exact Origin and a per-session CSRF nonce. There is no CORS support. Login throttling persists in SQLite: 20 global and 10 exact-username attempts per five minutes. Forwarded headers are ignored; they cannot set cookie security, origin or client identity. Restrict management access because global throttling can itself temporarily deny login.

Initial setup requires a random local installation key; its write request must carry a valid browser Origin matching the supplied public URL. That key cannot authorize normal operations after setup. A partial setup records the original base/administrator before provisioning and cannot adopt an unrelated initialized directory beside empty metadata.

User/group/base DN validators exclude filter and DN metacharacters. Values use ldap3 encoding; the fixed initialization/emergency helpers validate identifiers before generating constrained LDIF. Password Modify uses native OpenLDAP Argon2 salted hashing. APIs use an explicit attribute allowlist without password hashes. Request bodies, passwords and recovery identities are excluded from logs/audits. Protected SSSD bundles necessarily contain their dedicated reusable read credential; store them securely.

## Process and storage boundaries

The Rust manager runs as UID10001, has no OS root, Docker socket, command endpoint, cn=config/rootDN credentials or CA signing key. It has a restricted write-capable LDAP service identity and metadata/secrets needed for its role. Reusable bind credentials live in protected mounted files because they must be supplied to LDAP; they are never stored plaintext in SQLite.

The primary supervisor is available only over a protected authenticated Unix socket. It supports fixed initialize/pause/start/network operations and never accepts a shell command or arbitrary LDIF. Native LDAP and supervisor run as UID10001. Linux host networking permits selecting the private listener in setup/Settings without Docker control. Only NET_BIND_SERVICE is retained; the manager and maintenance worker drop all capabilities. Read-only root filesystems, tmpfs and no-new-privileges constrain runtimes.

The non-root **custodian** has `network_mode:none`, no capabilities or Docker socket, bounded memory/processes and authenticated Unix-only fixed operations. It alone mounts the signing authority key and required data volumes. Manager and LDAP receive separate secret volumes. Protect Docker/host root access: it can read those volumes and is inside the trust boundary. The one-shot initializer creates split persistent credentials and refuses to regenerate missing required secrets beside initialized storage.

## Maintenance authorization and consistency

The manager drains ordinary API requests under a read/write lease, checkpoints/closes SQLite and pauses the primary for offline operations. The WebUI keeps reporting progress. A durable ticket outside replaced metadata retains only the initiating session/key digest, CSRF nonce, expiry, actor, origin and job ID. While live LDAP authorization is unavailable, this capability permits **only** status and resuming/rolling back that recorded operation. It cannot launch new work or bypass normal administrator checks. Expired tickets require account recovery if the directory cannot start.

Backups stream into native age encryption. Restore additionally requires a separately trusted creation-time ciphertext SHA-256; anyone with a public recipient can create ciphertext, so encryption alone does not establish provenance. Archive parsing rejects traversal, links, unsupported roots, unexpected types, excess files/sizes and mismatched hashes. Known configuration profiles are checked before native tools parse them. SQLite integrity/schema and native LDAP readability are validated before replacement.

Durable phase journals, a separate offline marker and coherent rollback storage protect replacement across process restarts. The manager validates/reopens SQLite before acknowledging and cleaning recovery snapshots. Private age identities exist only in request memory and temporary tmpfs, never durable job parameters. Restore revokes sessions/pending enrollment, quarantines replicas, preserves target control authorization and requires fencing plus a future Unix ID floor. Restored credentials can revive access revoked after the snapshot; review topology and clients before enabling writes.

## Replica boundary

Enrollment requires manager HTTPS and an administrator-issued, one-use 15-minute token; only its digest is stored. The WebUI packages the token, public CA and connection details into a copyable join setting for the standalone replica stack. Base64 is transport encoding, not encryption; protect this setting and exclude `.env` from Git/build contexts. Regeneration invalidates the previous token. Certificates establish trust but do not authorize enrollment by themselves. A replica generates its private key locally. The manager validates/pins a self-signed non-CA RSA leaf restricted to the registered DNS/IP SAN. Native TLS chain/hostname validation remains enabled. The routine monitor uses a separate read identity and never sends the write-service password to a secondary.

Replication/control secrets are purpose-separated per-node HMAC values derived from a protected installation key and credential epoch. Only epochs are in SQLite. The consumer necessarily stores its replication secret in restricted native configuration. Replicas can read password hashes and are trusted authentication infrastructure. They have independent read-only databases and no bindable root credential; no automatic promotion or multi-provider mode exists.

Pinned HTTPS replica control accepts fixed authenticated credential/provider/restart/certificate operations as the directory OS user. It exposes no shell or Docker functionality. Credential updates are epoch ordered/idempotent; pending state permits safe retries. Certificate renewal temporarily trusts two approved pins, verifies the actual presented LDAP certificate and then retires the old key/pin. Client trust must be deployed at both stages. Restrict the private control port to the manager network.

Replica-backed reads during primary failure can see stale passwords/groups. Nonempty contextCSN equality is sampled synchronization evidence; an unreachable primary cannot advance last-confirmed sync. Deleting identities cannot forcibly terminate existing binds or stop remote machines. Fence decommissioned/restored replicas independently.

## Linux host boundary

Directory servers automatically appear in Hosts as inventory only, with no SSH groups or claim of deployment. Configuring Linux authentication requires explicit allowed groups and deploying its protected SSSD/PAM/NSS bundle. Export requires authentication, CSRF, current revision and rotation acknowledgment. Each host gets an independent read-only LDAP identity; exporting again rotates it and requires redeployment.

Destination SSSD/PAM/OpenSSH enforce group access and shadow expiry. Local accounts retain their existing policy, and no sudo rule is granted. Default password caching is disabled; identity/group caches and existing sessions still outlive some changes. A known user can authenticate with its own password even after the host read identity is removed. Host deletion is not a remote access kill switch.

## Remaining limits

No MFA, automatic CA root rotation, remote secret erasure, automatic Linux client deployment, scheduled backups, distributed LDAP/SQLite transactions, multi-manager coordination, large-directory paging or independent audit certification. Interrupted multi-step directory edits may be partial; audit attempts and completions help inspect them. Local database/host administrators can alter audit history. Test supported recovery on your actual infrastructure before relying on it.

The sole local tool is emergency account recovery for an administrator who cannot sign in. It requires Docker/Unix-secret access, restores an existing account and audits/revokes sessions. There is no public HTTP endpoint for this action. See [operations](operations.md).

## Authoritative DNS boundary

PowerDNS is a standard, independently supervised non-root container with separate SQLite data/configuration, secrets and Unix-control volumes. The native REST API binds only to its container loopback; authenticated requests travel through protected Unix transport. No API TCP port is published, and API credentials never reach the browser. Only DNS UDP/TCP ports are configurable. Transfers, DNS UPDATE, primary/secondary automation and Lua records are disabled in this single-node release.

DNS mutations recheck the existing LDAP administrator role, require Origin/CSRF and respect recovery review. DNS traffic never depends on that authentication path. Only Forklift-owned Native zones are editable; validated record types/names/values and stale-revision checks prevent accidental set loss. Management assumes one Forklift writer; external simultaneous API/database writers cannot receive transactional compare-and-swap guarantees from PowerDNS. Durable before/after plans guard partial forward/PTR operations and refuse conflicts. Explicit manual PTR edits relinquish tracked ownership.

Host DNS changes use the same administrator, CSRF and recovery guards as other privileged writes. Desired settings are saved separately from native DNS changes. Per-value ownership requires both Forklift metadata and a matching native ownership comment; preexisting values are never adopted. Cleanup preserves unrelated and disabled values. Native record/comment revisions protect retries, superseded plans cannot be replayed, and deleted hosts retain unfinished cleanup metadata until an administrator retries or explicitly retains their records. Manual record editing releases ownership. These markers are management metadata, not protection against an administrator with direct native API or storage access.

The existing LDAP backup does not contain DNS data/secrets. See [DNS recovery scope](dns.md) before relying on a full infrastructure recovery. TSIG-authenticated replication, bulk import and integrated encrypted DNS recovery remain unimplemented phases.
