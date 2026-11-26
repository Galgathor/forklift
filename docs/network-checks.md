# Network and port checks

Open **Settings → Network port checks → Check ports** for manager-origin checks and received client observations. An enrolled host's **Network** diagnostic tab shows its periodic outbound checks and an optional manager-to-host SSH TCP test. Upgrade the server first, then install client 0.4.1; the client's first inventory enables its network expectations.

| Path | Transport | Port selection |
| --- | --- | --- |
| Client → Forklift | Verified HTTPS | Saved public URL, usually TCP 443 |
| Client / manager → directory | TCP | Configured LDAPS endpoint, default published port 1636 |
| Client / manager → authoritative DNS | TCP **and** UDP | Configured DNS listener, usually 53 |
| Manager → LDAP replica control | TCP | Registered private control port, default 9443 |
| Manager → DNS secondary control | TCP | Registered private control port |
| Manager → selected host SSH address | TCP | Administrator's SSH diagnostic address/port |

The native monitoring client requires no inbound management listener. Nginx Proxy Manager forwards WebUI HTTP only; LDAP and DNS use their own listeners. Keep management/control ports restricted to their intended sources. Docker publishes TCP and UDP separately, and host publishing, bridge routing, host firewalls and network firewalls can each affect a path. Do not expose PowerDNS's API to make these checks pass.

Each manager result identifies its destination, transport, check time and source namespace. Client observations identify the enrolled host, server receipt time and freshness. Stale, revoked, missing or obsolete-profile observations cannot certify current reachability. Manager self-path success does not prove LAN ingress; client success proves only that client's path at that time. The manager rejects loopback/unspecified/multicast addresses for remote-host SSH probes.

TCP acceptance proves a listener accepted a connection; LDAP certificate/protocol checks remain separate. DNS checks require an actual matching reply on each transport. Even a negative/refused DNS reply proves transport reachability, while zone contents, transfers and synchronization need their separate checks. UDP sends without replies never pass.

Refusal suggests a missing listener or rejection; timeouts can reflect routing, filtering or a service outage. Results do not name an unproven firewall cause. Check the configured bind address, published port/protocol, service, routing and applicable rules. No check edits firewall rules, SSSD, PAM/NSS, SSH or the host resolver. Manager checks are administrator-triggered and limited to six requests/minute; client checks run with the existing periodic diagnostics and issue/notification lifecycle. Manager checks cover the configured primary services, up to 12 LDAP replicas and eight DNS secondaries. Client profiles retain their existing four-endpoint/four-DNS-listener bounds.

Network diagnostics do not deploy services or automatically repair connectivity.
