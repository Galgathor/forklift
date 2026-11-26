# Peer controllers

Every joined controller should serve the same managed DNS zones, forward other DNS queries using the same policy, authenticate users, and accept WebUI changes. A controller must keep operating from durable local state when another controller is off. Clients need two controller addresses configured ahead of time (DNS through DHCP or static settings, LDAP through SSSD). A client pointing only at one physical IP still loses that endpoint if its host goes down.

## Deliver DNS failover first

Keep the existing authenticated zone transfers as the upgrade path. Add the same forwarding listener to enrolled DNS peers and replicate upstream addresses and allowed client networks through the existing authenticated configuration channel. Persist the policy on each peer. Route managed zones locally, including negative answers, and apply the client network restrictions before forwarding other queries. Preserve signed zone transfers and notification source checks. Report loaded policy version separately from transferred zone serials. Test both DNS paths from a separate client after stopping the original controller. This stage gives query parity while edits still use the existing controller.

## Replicate changes between controllers

Give every controller a stable identity and local durable storage. Authenticate peer traffic and exchange changes promptly, retry after disconnects, and track which changes each peer has applied. Keep separate health for DNS, LDAP and configuration replication. Seed new peers from a consistent snapshot with a replay position. Never announce synchronization merely because a peer responded.

Use a durable change record with a stable operation ID, a logical timestamp informed by the controller clock, and a controller ID for deterministic ties. Record deletes as changes so delayed updates cannot restore deleted state. For conflicting edits to the same field or record set, take the newest version. Merge independent changes, including a profile edit and a password reset for the same account. Use complete DNS record sets as the conflict unit. Apply changes idempotently, retain an audit record of both competing edits, and surface replication lag without requiring conflict resolution by an administrator.

Use local PowerDNS storage and apply replicated zone and record changes through its API. Do not share SQLite files or expect zone transfers to merge independent edits. Evaluate native OpenLDAP multi-provider replication for directory entries, with explicit tests for concurrent changes, deletes and clock skew. Do not assume it replicates Forklift metadata or implements the product's entire conflict policy.

## Accept writes during a network split

Each controller accepts local changes, including password resets, account disables, and administrator grants, while its peers are unreachable. A successful save means the local controller durably recorded the change. It sends changes to connected peers promptly and automatically exchanges missed changes when they reconnect. A third voter is unnecessary. The WebUI should show whether a change is saved locally or synchronized to peers.

During a split, an isolated controller can still accept an old password or honor access that another controller revoked. That window closes when it applies the change. Each controller must track its local ordering state across restarts and report clock skew. A timestamp and controller ID produce the same winner on every peer even when clock skew makes the real order of independent edits unknowable.

Resolve conflicts at the smallest unit with a clear meaning. A profile edit cannot overwrite credentials, account status, or group membership. A password reset conflicts with another password reset, and a membership add conflicts with removal of that same membership. Apply timestamp ordering within each unit. Keep account deletion as a durable marker for that identity. Recreating a deleted account creates a new identity, so stale edits cannot revive the deleted account.

Assign each controller a nonoverlapping Unix ID allocation range during enrollment so disconnected peers can create accounts without reusing numeric IDs. If two peers independently claim the same username, select one owner by the same ordering rule. Disable sign-in for the losing identity and retain it for audit. Never merge two accounts or move their credentials, group grants, or file ownership to the winner.

Before switching the default deployment, test migration without wiping existing stores, offline DNS forwarding and uncached LDAP authentication, writes on a survivor, concurrent edits and deletes, recovery after a partition, duplicate identity handling, and restore into a cluster. Keep the existing deployment available until these checks pass.
