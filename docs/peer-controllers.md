# Peer controllers

Every joined controller should serve the same managed DNS zones, forward other DNS queries using the same policy, authenticate users, and accept WebUI changes. A controller must keep operating from durable local state when another controller is off. Clients need two controller addresses configured ahead of time (DNS through DHCP or static settings, LDAP through SSSD). A client pointing only at one physical IP still loses that endpoint if its host goes down.

## Deliver DNS failover first

Keep the existing authenticated zone transfers as the upgrade path. Add the same forwarding listener to enrolled DNS peers and replicate upstream addresses and allowed client networks through the existing authenticated configuration channel. Persist the policy on each peer. Route managed zones locally, including negative answers, and apply the client network restrictions before forwarding other queries. Preserve signed zone transfers and notification source checks. Report loaded policy version separately from transferred zone serials. Test both DNS paths from a separate client after stopping the original controller. This stage gives query parity while edits still use the existing controller.

## Replicate changes between controllers

Give every controller a stable identity and local durable storage. Authenticate peer traffic and exchange changes promptly, retry after disconnects, and track which changes each peer has applied. Keep separate health for DNS, LDAP and configuration replication. Seed new peers from a consistent snapshot with a replay position. Never announce synchronization merely because a peer responded.

Use a durable change record with a stable operation ID, a logical timestamp informed by the controller clock, and a controller ID for deterministic ties. Record deletes as changes so delayed updates cannot restore deleted state. For conflicting ordinary edits to the same object, take the newest version. Merge changes to different objects independently. Use complete DNS record sets as the conflict unit. Apply changes idempotently, retain an audit record of both competing edits, and surface replication lag without requiring conflict resolution by an administrator.

Use local PowerDNS storage and apply replicated zone and record changes through its API. Do not share SQLite files or expect zone transfers to merge independent edits. Evaluate native OpenLDAP multi-provider replication for directory entries, with explicit tests for concurrent changes, deletes and clock skew. Do not assume it replicates Forklift metadata or implements the product's entire conflict policy.

## Decide the partition policy before enabling distributed writes

With two controllers, loss of contact cannot distinguish a crashed controller from a network split. If both must keep accepting writes, changes can only converge after contact returns. Timestamp ordering is deterministic with a tie-breaker, but clocks cannot prove the real order of independent edits during a partition. In particular, an old controller can still authenticate a recently revoked user until it receives the revocation.

Choose which operations need coordination before enabling peer writes. Options include a third voter for security and uniqueness changes, or independently writable peers with documented revocation delays, collision-free ID allocation and explicit conservative rules for concurrent security changes. Cluster membership, administrator grants, credential revocations and account deletion need their own rules. Never let an ordinary profile edit undo a security change.

Before switching the default deployment, test migration without wiping existing stores, offline DNS forwarding and uncached LDAP authentication, writes on a survivor, concurrent edits and deletes, recovery after a partition, duplicate identity handling, and restore into a cluster. Keep the existing deployment available until these checks pass.
