# Forklift nodes

Every node uses the main Compose stack and runs a manager, a persistent OpenLDAP directory and a persistent PowerDNS server. Any joined node can manage accounts and groups and answer DNS queries. DNS edits from any paired WebUI go through the installation's DNS coordinator.

## Join an installation

1. Run `docker compose up -d` from the repository on the new host and open its WebUI. Copy the installation key from `docker compose logs initialize`.
2. Open the existing manager using its HTTPS address. In **Directory Servers → Node pairing**, choose **Approve node pairing**. Keep the pairing key private and use it within ten minutes.
3. On the new node, enter its installation key and choose a private address and port for its directory. Choose **Join existing installation** and enter the existing manager's HTTPS address and pairing key.
4. Wait for setup to confirm the directory and DNS copy. Sign in using the existing administrator account. Check **Directory Servers** for live comparisons between the nodes and the status of the local DNS copy.
5. Configure clients with both directory and DNS addresses before relying on failover.

The new manager must trust the coordinator's HTTPS certificate. Use a certificate from a CA already trusted by the manager when possible. The node keeps its own LDAP private key. Forklift exchanges the directory trust certificates and creates replication credentials during pairing. Let joined nodes reach each other's private LDAP listeners by TCP. Let intended DNS clients reach both DNS listeners by TCP and UDP.

Join protects initialized local storage and can resume with the same pairing key and local address if the connection drops. Existing installations keep their volumes and can act as the first node. Existing read-only replicas and DNS secondaries can continue serving while you move clients to joined nodes.

## Directory changes and outages

Forklift configures OpenLDAP Syncrepl for reads and writes on each node. Each node has a distinct server ID, its own credentials and a separate range for Unix user and group IDs. OpenLDAP tracks and resolves changes using its native replication state. An available node can authenticate users and accept directory edits when another node is offline. Nodes catch up over verified private LDAP connections after reconnecting. [OpenLDAP replication guide](https://www.openldap.org/doc/admin25/replication.html)

An isolated node may still accept an old password or grant access based on old group membership until it receives the change. Avoid editing the same account or group concurrently during an outage. Host inventory, host access policies and management sessions are stored on each manager. LDAP credentials, accounts and groups are shared through the directory.

## DNS writes from every paired WebUI

The first node is the DNS write coordinator. Each joined manager forwards DNS zone and record changes to it over verified HTTPS. The setup wizard assigns this connection automatically.

The coordinator validates DNS edits and rejects stale record-set revisions. A retried WebUI record submission can return the original result or resume an interrupted change without writing it twice. Each peer fetches a complete snapshot of shared zones, updates its PowerDNS using the supported API, and records the revision after comparing the resulting records and SOA serials. Zones and records absent from a newer snapshot are removed from the peer's copy. [PowerDNS zone API](https://doc.powerdns.com/authoritative/http-api/zone.html)

When the coordinator is offline, peers continue serving the last applied copy. DNS edits can resume when the coordinator returns. DNS forwarding settings are local to each node.

## Remove or recover a node

Revoke the pairing on the coordinator and remove that node's endpoints from client configuration. A revoked node keeps serving its local LDAP and DNS data. Shut down or isolate a revoked node before relying on changed passwords, access restrictions or DNS records.

Keep encrypted backups. Restore fences archived peer credentials. Recover a coordinator with older directory data only after isolating the old cluster, then pair fresh nodes. Select a Unix ID floor above IDs issued by any old node. [Backup and recovery](operations.md)
