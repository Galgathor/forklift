# Native Forklift Client enrollment

Forklift Client is an optional Linux companion in the separate `forklift-client` repository. Manual host creation, LDAP authentication and DNS management remain independent. The client never configures SSSD, PAM, NSS, SSH or the system resolver.

## Pair a machine

Install the native executable and systemd unit using the client repository's instructions. On that machine, run `sudo forklift-client join --server https://identity.example.test`. A publicly/OS-trusted HTTPS certificate needs no additional option. For private PKI, supply an independently trusted public CA with `--ca-file /path/to/manager-ca.crt`; do not download and trust an unverified certificate. The LDAP CA and the WebUI HTTPS CA are different trust domains.

Open **Hosts → Join existing machine**, enter the displayed code, and choose **Find machine**. Compare the hostname, enrollment addresses and machine-key fingerprint with the client console before approving. Choose **Create a new host** or explicitly select an existing inventory record to link. Forklift rejects silent hostname merges and replacement of an active client. Revoke an old identity before enrolling a replacement. Approval creates inventory only; choose login groups and deploy the existing client configuration separately when you want LDAP login.

Pairing codes expire in ten minutes and are consumed by approval. Interrupted joins retain their key and pending request; run `join` again to resume. A completed join atomically saves the machine credential, confirms it to Forklift, and starts its own installed monitoring service. Initial system identity/addresses are enrollment observations, not continuously updated inventory. Last contact means a credential-authenticated session, not a successful SSH/PAM login or a live diagnostic result.

## LAN discovery

The client discovers `_forklift._tcp.local.` services and presents a numbered selection. TXT records carry `name`, `url`, `api=1` and a nonsecret `instance` identifier. Discovery is untrusted; the selected HTTPS endpoint is verified independently before enrollment information is sent.

The manager normally uses Docker bridge networking, which does not advertise to physical LAN clients. Enable the **server stack's** `discovery` Compose profile in your deployment settings to run a separate, non-root LAN publisher with host networking. Set deployment `FORKLIFT_PUBLIC_URL` to the same saved HTTPS origin used by Forklift. The publisher has no metadata, credentials or privileged sockets mounted. It validates the public HTTPS information endpoint, advertises its resolved endpoint addresses, and withdraws the advertisement when it cannot verify the manager.

The default publisher CA bundle is `/etc/ssl/certs/ca-certificates.crt` from the Docker host; `FORKLIFT_DISCOVERY_CA_BUNDLE` can point to a trusted public-CA bundle. Keep it free of private keys. Permit local multicast UDP 5353 on the intended network. mDNS generally stays within one broadcast domain; VLANs, Wi-Fi isolation and firewalls can prevent discovery. IPv4/IPv6 DNS-SD support depends on those interfaces. If the WebUI address changes, update the publisher deployment's origin/trust too. Manual `--server` works without the publisher or mDNS. Unicast DNS-SD is deferred.

## Revocation and removal

Choose a client's entry in Hosts to inspect its enrollment and last contact. **Revoke client identity** uses a styled confirmation dialog and revokes only that machine credential. Inventory, managed DNS values and Linux login configuration remain. This is not an SSH session kill switch.

`sudo forklift-client leave` confirms remote revocation/cancellation before removing local credentials. If the manager is unreachable, it retains the local identity; `leave --local-only` requires explicit confirmation and reports that remote unenrollment was not verified. Revoke the old identity through Forklift later. Deleting host inventory revokes its client identities before removing metadata. A full installation restore quarantines archived clients; fence old infrastructure and re-enroll after recovery review.

## Implemented scope

Milestone 1 provides the CLI, actual local discovery, verified HTTPS, key-bound device pairing, manual linking, persistent native state, root systemd service, session/contact checks, local status, initial enrollment diagnostics and WebUI revocation. It does not implement live network inventory, netlink, automatic DNS updates, heartbeat-based offline detection, system diagnostics, issue/notification lifecycle, credential rotation or Debian packaging. These are subsequent milestones. Manual hosts have no implied offline status. No synthetic health is shown.

The daemon currently checks its enrolled session at the locally configured interval (default five minutes), retaining identity and a bounded last result across outages. Initial diagnostics explicitly mark system checks unsupported. Test your firewall, HTTPS trust and service hardening on the deployment host. The source build and native integration tests currently target Linux amd64 on Ubuntu 24.04; other Ubuntu LTS/architectures and packaged upgrades need later validation. See the canonical [v1 API contract](client-api-v1.md) and [integration plan](client-plan.md).
