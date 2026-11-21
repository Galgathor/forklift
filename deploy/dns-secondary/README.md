# Deploy a DNS secondary

The primary DNS server is already part of the main Forklift stack. You do not need an existing DNS service or manually configured TLS certificate on the second machine.

1. In Forklift, open **DNS → DNS servers**. Configure the primary's reachable private DNS endpoint, then choose **Add DNS secondary**.
2. Select this second machine's private IPv4 address, available DNS/management ports and zones. Generate a one-time join configuration. Supply a public HTTPS CA certificate only if Forklift uses private HTTPS PKI.
3. In your Docker Compose hosting tool, deploy this `compose.yaml` from a checkout of the Forklift repository. Its build context requires the repository files; pasting the Compose text alone cannot build the image.
4. Paste the generated `FORKLIFT_DNS_JOIN=…` setting into the stack's deployment environment and start it within 15 minutes.
5. In Forklift, choose **Check synchronization** and verify the assigned zones before configuring your resolver to use both DNS endpoints.

Keep the independent `dns_secondary` volume. Configured containers restart without a new join setting, including during primary/manager outages. Protect the private management port; transfers use TSIG over trusted private networking or a VPN. LDAP replication is configured separately.

See [DNS replication operations](../../docs/dns-replication.md) for networking, assignments, revocation, SOA expiration and recovery limitations.
