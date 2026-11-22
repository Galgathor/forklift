# Native Forklift Client enrollment

Forklift Client is an optional Linux companion in the separate `forklift-client` repository. Manual host creation, LDAP authentication and DNS management remain independent. The client never configures SSSD, PAM, NSS, SSH or the system resolver.

## Pair a machine

Install the native executable and systemd unit using the client repository's instructions. On that machine, run `sudo forklift-client join --server https://identity.example.test`. A publicly/OS-trusted HTTPS certificate needs no additional option. For private PKI, supply an independently trusted public CA with `--ca-file /path/to/manager-ca.crt`; do not download and trust an unverified certificate. The LDAP CA and the WebUI HTTPS CA are different trust domains.

Open **Hosts → Join existing machine**, enter the displayed code, and choose **Find machine**. Compare the hostname, enrollment addresses and machine-key fingerprint with the client console before approving. Choose **Create a new host** or explicitly select an existing inventory record to link. Forklift rejects silent hostname merges and replacement of an active client. Revoke an old identity before enrolling a replacement. Approval creates inventory only; choose login groups and deploy the existing client configuration separately when you want LDAP login.

Pairing codes expire in ten minutes and are consumed by approval. Interrupted joins retain their key and pending request; run `join` again to resume. A completed join atomically saves the machine credential, confirms it to Forklift, and starts its own installed monitoring service. The daemon sends live inventory separately from the original enrollment observations. Last contact means a credential-authenticated session, not a successful SSH/PAM login. Last heartbeat measures the monitoring daemon independently. Reported hostname changes do not rename administrator-configured inventory or DNS names.

## LAN discovery

The client discovers `_forklift._tcp.local.` services and presents a numbered selection. TXT records carry `name`, `url`, `api=1` and a nonsecret `instance` identifier. Discovery is untrusted; the selected HTTPS endpoint is verified independently before enrollment information is sent.

The manager normally uses Docker bridge networking, which does not advertise to physical LAN clients. Enable the **server stack's** `discovery` Compose profile in your deployment settings to run a separate, non-root LAN publisher with host networking. Set deployment `FORKLIFT_PUBLIC_URL` to the same saved HTTPS origin used by Forklift. The publisher has no metadata, credentials or privileged sockets mounted. It validates the public HTTPS information endpoint, advertises its resolved endpoint addresses, and withdraws the advertisement when it cannot verify the manager.

The default publisher CA bundle is `/etc/ssl/certs/ca-certificates.crt` from the Docker host; `FORKLIFT_DISCOVERY_CA_BUNDLE` can point to a trusted public-CA bundle. Keep it free of private keys. Permit local multicast UDP 5353 on the intended network. mDNS generally stays within one broadcast domain; VLANs, Wi-Fi isolation and firewalls can prevent discovery. IPv4/IPv6 DNS-SD support depends on those interfaces. If the WebUI address changes, update the publisher deployment's origin/trust too. Manual `--server` works without the publisher or mDNS. Unicast DNS-SD is deferred.

## Revocation and removal

Choose a client's entry in Hosts to inspect its enrollment and last contact. **Revoke client identity** uses a styled confirmation dialog and revokes only that machine credential. Inventory, managed DNS values and Linux login configuration remain. This is not an SSH session kill switch.

`sudo forklift-client leave` confirms remote revocation/cancellation before removing local credentials. If the manager is unreachable, it retains the local identity; `leave --local-only` requires explicit confirmation and reports that remote unenrollment was not verified. Revoke the old identity through Forklift later. Deleting host inventory revokes its client identities before removing metadata. A full installation restore quarantines archived clients; fence old infrastructure and re-enroll after recovery review.

## Inventory and automatic DNS

Open the enrolled client's details in **Hosts** to see reported OS/kernel/version, interfaces, addresses and the server-observed last heartbeat. The list refreshes every 30 seconds while Hosts is open. A client is offline after three missed heartbeat intervals (normally 15 minutes), or a longer administrator-selected threshold. Older clients that only check sessions are **not reporting**. Manual inventory is never offline merely for lacking a client.

Configure and apply the host's managed DNS records first. In its client details, enable **Automatically update managed DNS addresses**, choose its IPv4 interface and optionally IPv6 interface, then save. The next heartbeat applies the selection. **Follow sole interface address** follows future address changes only when exactly one eligible address is reported for that family; pin a specific address on multihomed interfaces. A missing or ambiguous selection pauses DNS updates. Without an IPv6 selector, the configured IPv6 value remains unchanged. The current host-DNS model requires IPv4; IPv6-only automatic registration is not implemented.

Forklift checks that this host owns its current A/AAAA/PTR values before automatic changes, preserves unrelated records, and uses existing DNS reconciliation/retry journals. Manual record edits that relinquish ownership require administrator review. Inventory can succeed while DNS shows **needs retry**. A newer heartbeat retries current DNS intent; the existing Hosts/DNS reconciliation controls also remain available. Do not interpret online inventory as successful DNS synchronization or Linux authentication. Replacement enrollments require fresh DNS opt-in.

The daemon uses read-only Linux route-netlink events plus periodic reconciliation (default five minutes). Known container/virtual interfaces, loopback, link-local and temporary/deprecated/tentative IPv6 addresses are excluded. Explicit local `join --include-interface NAME` can include a normally ignored interface; it never makes loopback/link-local/temporary addresses eligible. Events are debounced with a 30-second send floor; periodic reconciliation remains available if netlink is unavailable. Hostname changes are detected during reconciliation. The latest local snapshot, observation time, sequence and result remain bounded and root-only across outages.

History retains the latest 100 server-timestamped monitoring events. Reload monitoring to refresh history/settings; doing so discards unsaved policy edits. Diagnostic issue and notification behavior is documented in [client diagnostics](client-diagnostics.md).

## Implemented scope

Milestones 1–3 provide the native CLI, LAN discovery, verified HTTPS, key-bound pairing, manual linking, root-only persistent state, root systemd service, live inventory, network events, independent heartbeat/offline history, authorized DNS address updates and WebUI revocation. Read-only DNS, LDAPS, SSSD, NSS, PAM and SSH diagnostics and issue/notification lifecycle are implemented. Milestone 4 adds native Debian packages and resumable machine credential rotation. Unsupported/unverifiable checks are explicit. No synthetic health is shown.

Build/install the 0.4 client from its separate repository after updating the server. The source build and native integration currently target Ubuntu 24.04 amd64; other Ubuntu LTS/architectures need separate validation. See the canonical [v1 API contract](client-api-v1.md) and [integration plan](client-plan.md).


## Credential rotation and packages

Upgrade Forklift first, then install client 0.4 using its native Debian package. Package upgrade/removal preserves root-only machine state; removing the binary does not revoke the server identity. Use **Revoke client** when a machine is retired or compromised.

Client details show actual credential generation, pending state and last confirmed rotation. **Request credential rotation** queues a replacement for a rotation-capable daemon; confirmation is required in the styled dialog. Automatic rotation also becomes due after 30 days, using server time. The client persists provisional keys before contacting Forklift and resumes interrupted confirmations, including lost acknowledgments. The original identity is invalidated only when the server commits the replacement. Expired unconfirmed attempts retain the original identity. Offline/revoked clients show errors rather than false completion. Rotation retains the stable host, report counters, monitoring policy and history. Compromised hosts require revocation/investigation and fresh enrollment.

## Network ports

Client 0.4.1 adds periodic management HTTPS, LDAP TCP and independent DNS TCP/UDP reachability checks. View results in the host's **Network** tab or aggregate client observations in **Settings → Network port checks**. The manager can also probe configured primary/replica/control ports and the selected host's SSH port. Results identify their source/path and freshness; they never claim a listener proves all firewall paths are open. No firewall or authentication/resolver configuration is changed. See [port verification](network-checks.md).
