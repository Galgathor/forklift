# Client diagnostics and host issues

Update Forklift before installing Forklift Client 0.3. Existing enrollment identities and manual hosts remain compatible. The client continues to inspect and report only; it never installs packages, changes authentication/resolver files, repairs configuration, starts authentication services or attempts password logins.

## Enable checks

Open **Hosts → Client enrolled → Monitoring → Diagnostic expectations**. Enable authentication and/or SSH checks only for machines intended to use those services. Select the SSSD domain and a test user/group. These are lookup names, not credentials; no test password is accepted or stored.

For SSH, select the expected source address, optional source hostname, local listening address and port. The test user and this connection context are passed to OpenSSH's supported configuration-test mode to evaluate `Match` rules. Without a complete context, authentication configuration remains unknown. No authentication attempt is sent. A listener check reads only the SSH greeting.

DNS expectations come from the host's managed DNS registration. Public serving endpoints come from DNS server configuration; management API credentials are never supplied. The client compares registered addresses and reverse names using normal NSS/resolver lookups and checks zone SOA responses separately. A direct authoritative answer cannot make an incorrect normal lookup pass. Hosts-file mappings can affect NSS, and custom split-DNS configurations without a resolv.conf forwarding stub need manual verification.

## Read results

Host details contain **DNS**, **Authentication**, **SSH**, and **Issues** views. Information buttons contain technical details, timestamps and remediation guidance. The Hosts list separates heartbeat connectivity, overall diagnostic health and active-issue count. A recent heartbeat alone never proves authentication works.

Checks report pass, warning, failure, unknown or unsupported. Missing tools, unavailable service-management APIs, missing connection context and execution timeouts are distinguished from confirmed configuration failures. `getent` can return cached identities; live LDAPS TLS verification and SSSD's online state are separate checks. Static PAM/access/SSH inspection never proves a successful password login or evaluates every possible SSH connection.

A default two consecutive distinct bad reports opens one stable issue. Change the threshold from one to five in monitoring settings. Retrying an identical report cannot increase the count or refresh receipt time. Repeated failures update the same issue. A positive check resolves it; unknown, unsupported, omitted and stale checks do not. Changed check targets and revoked/replaced enrollment identities retire obsolete issues separately from recovery. Threshold-only changes preserve existing issues. A full restore retires archived issues and quarantines client identities. Historical episodes remain available within bounded retention.

The notification button shows issue creation, severity changes and recovery. Marking an event seen or dismissing it leaves the underlying issue unchanged. Issue acknowledgment also leaves an active problem unresolved. These administrative actions are audited and shared between administrators. The newest 500 notification events and up to 232 issue episodes per host are retained; the notification panel shows the latest 200 events.

## Offline behavior and limits

The server independently detects missed heartbeats and records an offline issue/recovery. Server-managed DNS errors have their own issue state; disabling automatic updates retires that check rather than claiming DNS recovery. Diagnostic freshness uses server receipt time, the current expectation profile and at least three diagnostic intervals. Incomplete reports cannot certify healthy status.

The daemon caches its latest diagnostic snapshot and trusted expectation profile in root-only state, continues local checks during management outages and retries communication with bounded backoff. `sudo forklift-client diagnostics` runs current checks using cached expectations and shows the cached result separately. It works without the management server. No cache is interpreted as live server authorization. Root state is bounded to 256 KiB and retains at most one latest diagnostic snapshot; system configuration and raw command output are never uploaded.

External checks use fixed executable paths/arguments, no shell, closed stdin, a three-second execution limit and an 8 KiB output limit. Only curated results are reported. LDAP probes validate certificates using operating-system roots plus the public directory trust bundle supplied through the already-verified management connection; they confirm an anonymous LDAP protocol reply without binding with a user's password. Management-server trust is never changed by a response.

Ubuntu 24.04 amd64 is the initial validation target. Disposable Linux fixtures exercise real SSSD, PAM, NSS, OpenSSH, LDAPS and DNS without changing the development host. Full installed-systemd boots, other Ubuntu releases/architectures, arbitrary custom PAM/access-policy equivalence and genuine end-to-end password login are not certified by these diagnostics. Debian packaging and credential rotation remain Milestone 4.
