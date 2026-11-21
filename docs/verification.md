# Version 0.5 verification

Validated on Linux/amd64 with Docker Engine, native OpenLDAP 2.6.10 and isolated Compose projects. Each test uses random credentials, private temporary fixtures and independent volumes; it cleans up only its own resources. No default installation or user volume is reset.

| Check                                                                     | Result                                                                                                                                        |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Locked Rust unit tests, formatting and Clippy with warnings denied        | Passed; 14 unit tests                                                                                                                         |
| Strict TypeScript/Vite production build                                   | Passed                                                                                                                                        |
| Python compilation, emergency shell syntax, Compose validation            | Passed                                                                                                                                        |
| Manager, primary and network-isolated maintenance images                  | Built successfully                                                                                                                            |
| Core actual-LDAP API/authentication/CRUD/failure suite                    | Passed; 90 HTTP checks plus native LDAP                                                                                                       |
| WebUI backup, streaming transfer, archive verification/checksum rejection | Passed                                                                                                                                        |
| First-launch restoration with bootstrap key                               | Passed; original passwords/IDs, future allocation floor, recovery review and recreation                                                       |
| Service credential rotation and primary certificate renewal               | Passed; session revocation, actual reauthentication                                                                                           |
| Interrupted worker/manager recovery                                       | Passed; durable offline fence, original scoped session, CSRF and completed-job replay rejection                                               |
| HTTPS replica enrollment/native Syncrepl                                  | Passed; generated Compose deployment, automatic Hosts inventory, independent volumes                                                          |
| WebUI replica lifecycle                                                   | Passed; credential rotation, restart, staged certificate activation/actual peer verification/retirement, provider reconnect                   |
| Replica outage behavior                                                   | Passed; restarted secondary authenticates with primary and manager stopped                                                                    |
| Chromium                                                                  | Passed; first-launch setup, LDAP login, Hosts, key/receipt/archive downloads, verification, replica wizard/download, themes and mobile layout |

The extended recovery suite also passed wrong-key and trusted-checksum rejection, crafted archive-path rejection, unauthorized/CSRF maintenance rejection, readiness/new-operation rejection while metadata is closed, verified-stage interruption, changed-stage detection, coherent rollback, and local-only emergency account recovery. Recovery identities were checked absent from persistent job records and metadata. Initial staging interruption and refusal of schema4 startup are exercised by the core suite. The Ubuntu 24.04 client run passed 101 HTTP checks plus actual SSH/PAM/NSS and Ansible idempotence; the latest core-only run separately includes the breaking schema guard.

## Copyable replica enrollment

The standalone `deploy/replica/compose.yaml` stack was built and exercised without transferring an archive. Tests passed for authenticated/CSRF-protected join generation, private-key input rejection, local and server-side expiration, superseded/consumed-token rejection, private HTTPS CA validation before redemption, and absence of plaintext enrollment tokens from SQLite. Native Syncrepl, credential/certificate lifecycle and provider changes passed. The replica was recreated with an empty join setting while both primary and manager were stopped and still authenticated a directory user. Chromium verified generation, public-trust packaging, clipboard copy and mobile layout.

## Integrated DNS Phase 1

DNS is a standard deployment component. Real PowerDNS Authoritative 5.1.5 tests passed for initialization; forward, private IPv4 and ULA IPv6 reverse zones; published UDP/TCP queries; A/AAAA/CNAME/PTR/TXT/MX/SRV/NS sets; SOA settings and serial increases; relative owners; duplicate/CNAME/ownership validation; stale revisions; confirmed zone deletion; automatic PTR cleanup and manual-value preservation; BIND zone export; API authentication/rotation; and refusal of AXFR and unauthenticated DNS UPDATE. The API port is not published.

Failure tests passed for unavailable DNS while LDAP remained usable, interrupted forward/reverse plan retries through the real API, unexpected native-process exit/restart, container recreation/persistence, and DNS answers with both manager and LDAP stopped. Chromium passed zone creation, in-dialog validation, A/PTR forms, zone selection and mobile layout, alongside the existing account/backup/replica enrollment flow. Core LDAP regression passed 90 HTTP checks plus native binds.

`tests/dns_upgrade.py` built the actual pre-DNS manager from commit `804bb40`, populated LDAP/schema-5 metadata, then upgraded the deployment. Passwords, Unix IDs, groups, host policy and the administrator session were preserved while DNS initialized without resetting LDAP or changing the schema version.

Run `python3 tests/dns.py` and `python3 tests/dns_upgrade.py` after building images. The upgrade fixture needs Git history. DNS tests use random loopback TCP/UDP ports, isolated volumes and the native `dig`/`nsupdate` clients. No existing DNS/resolver service or default installation is modified.

Phase 4 adds integrated recovery, reviewed import and secondary identity rotation as documented below. Separate physical-host routing/firewall tests, schema-changing PowerDNS upgrades, large/load tests and an external security audit remain unverified. See [DNS operations](dns.md) for deployment and forwarding boundaries.

## Host DNS integration (Phase 2)

Run `python3 tests/dns_hosts.py` against the built manager/DNS images. The suite passed real published DNS checks for host A/AAAA and IPv4/IPv6 PTR values, relative names, record-set merging and TTL preservation, preexisting/manual/disabled value protection, shared PTR ownership, rename/address changes, apply/defer, stale revisions, authenticated/CSRF-protected writes and explicit retention/deletion. It exercises DNS outages independently of LDAP, persisted retry state across manager recreation, deleted-host cleanup, interruption after an actual native write, conflicting external edits, superseded-plan rejection, primary inventory registration and volume persistence.

The Chromium suite also passed registration without SSH groups, editing addresses, deferred application, reconciliation, explicit DNS retention during deletion, actual retained values in the DNS page and responsive host forms. This phase does not include host liveness monitoring, DNS replication, continuous DNS drift polling, bulk import or integrated DNS recovery. Native comment ownership is a safety check with recorded metadata, not a lock against concurrent external PowerDNS administrators. One expanded run failed directory readiness after full-stack recreation with a missing LDAPI socket; the isolated rerun, including full recreation, passed. The cause of that transient existing-directory restart failure was not established; no LDAP configuration was changed for this feature.

## DNS replication (Phase 3)

Run `python3 tests/dns_replication.py` after building manager/DNS images. It deploys real PowerDNS primary and independent secondary SQLite containers, using isolated private networking and a disposable verified HTTPS proxy. The production secondary Compose stack uses host networking; the fixture overrides only networking to model separate machines without changing the host firewall. The suite passed private-CA trust, expiring/superseded/one-use enrollment, certificate constraints, session/CSRF authorization, native TSIG transfers, unsigned AXFR rejection, actual authoritative UDP/TCP responses, serial comparisons, live forward/reverse changes, host DNS on replicated zones, API-key rotation, zone assignments/deletion, management outages and transfer revocation. Two independently enrolled peers verify per-zone key isolation and actual signed-AXFR rejection after one peer is removed, while the other still receives updates. An already-configured secondary is recreated with no join credential while primary and manager are stopped, and answers real DNS queries from its own persistent data.

Chromium covers the primary endpoint form, secondary registration, zone selection, private HTTPS CA field, expiring join generation, clipboard copy and mobile layout alongside the existing DNS/host/LDAP/backup/replica flows. `tests/dns.py`, `tests/dns_hosts.py` and the core LDAP suite remain regression checks. Initial real-service testing exposed the native API’s legacy Master/Slave role strings; the adapter now normalizes them to Primary/Secondary. The two-peer test also exposed first-key-only native NOTIFY signing; explicit source-restricted unsigned notifications preserve per-node transfer-key isolation while allowing both peers to refresh. An earlier same-host fixture had blocked bridge-to-host notifications; peers now use isolated routable container interfaces rather than changing firewall rules or weakening peer checks.

This is primary/secondary DNS with native AXFR (IXFR requests can fall back to AXFR), not writable automatic failover. TSIG does not encrypt zone contents; use trusted private networking/VPN. Synchronization is checked on demand, with separate last-confirmed timestamps. No separate physical-host deployment, NAT/firewall matrix, expired-zone time-travel test, in-place secondary certificate/key rotation or integrated DNS recovery is claimed by this phase. See [deployment and operational limits](dns-replication.md).

## DNS hardening (Phase 4)

`tests/dns_import.py` exercises reviewed JSON preview/apply through the actual PowerDNS API and queries real DNS answers. Checks cover supported record types, merge/replace/TTL behavior, validation/CNAME/duplicate/ownership rejection, stale previews/hash confirmation, Forklift/native JSON roundtrips, host ownership release and a partially applied import with conflict-checked retry. LDAP remains functional while DNS is unavailable.

`tests/dns_recovery.py` verifies DNS answers during encrypted online backup, archive format-3 scope, no omitted-WAL copying, rejection of custom SQLite objects, legacy format-2 verification/full-restore refusal, and real LDAP plus A/PTR restoration into a fresh target. It checks transfer revocation, peer/token quarantine, recovery guards, host ownership reconciliation and persistence. The interruption drill recreates a fenced DNS container, injects failure midway through storage replacement, recreates recovery control beside an unreadable native database and rolls back to previous actual answers and LDAP credentials.

The extended `tests/dns_replication.py` verifies actual signed transfers under new credential epochs, old transfer/control rejection, lost-ack recovery and interrupted TLS key/certificate publication. It verifies the new certificate independently, rejects the old pin and confirms retirement of old private/staged files. A populated helper built from Phase 3 commit `e9a4b24` is upgraded with the same volume to check compatibility and refusal of new identity operations on old software. `tests/dns_upgrade.py` also builds the actual Phase 3 manager, DNS and maintenance images, populates real LDAP plus host-owned A/PTR records, then upgrades without resetting volumes; credentials, sessions, DNS SQLite and ownership reconciliation are preserved. These are isolated containers with real native services; they do not modify host firewalls.

Chromium additionally exercises JSON export/download, file upload, import preview/confirmation, actual displayed results, responsive import forms and DNS-inclusive backup receipts/verification. The ordinary DNS, host-DNS, core LDAP, encrypted recovery and pre-DNS upgrade suites remain regression checks. See [DNS recovery](dns-recovery.md) for operational limits and unsupported custom native configurations.

## Run the suites

Build all images with `docker compose build`, then run `python3 tests/integration.py`, `python3 tests/hardening.py`, and `python3 tests/replication.py`. No local installer or installation-secret files are required.

Optional real Ubuntu checks use `docker build -t forklift-ubuntu-client -f tests/ubuntu/Dockerfile .` followed by `FORKLIFT_TEST_UBUNTU=1 python3 tests/integration.py`. This exercises the actual Ansible role, NSS, PAM, SSSD and SSH processes; it does not boot a full systemd VM.

Optional browser checks use a matching host-side Playwright package outside the repository:

```sh
npm install --prefix /tmp/forklift-browser --no-save --ignore-scripts playwright@1.65.0
FORKLIFT_TEST_BROWSER_DEPS=/tmp/forklift-browser/node_modules python3 tests/browser.py
```

The harness uses a pinned matching Chromium container and a disposable HTTPS proxy/private CA. Chromium's test-only certificate-error switch permits downloads through that disposable proxy; this does not change application LDAP/enrollment/control TLS verification. Native TLS trust tests remain separate. Private downloads are deleted with the fixture.

This host's firewall blocks Docker-bridge-to-host listeners. HTTPS/replica/client fixtures therefore use isolated host-network listeners on random ports; ordinary HTTP/core fixtures exercise the normal bridge manager deployment and protected LDAPI. Production bridge managers need permitted routing/firewall access to replica LDAP/control ports. No host firewall rules are changed by tests.

## Limits

Single Docker host tests simulate independent machines with separate storage and processes. Physically separate hosts/VMs, Ubuntu 22.04, full systemd boots, multiple simultaneous replicas, multi-architecture builds, large/load testing, long partitions, CA-root rotation and independent security auditing remain unverified. Metadata schema5 remains a deliberate break from 0.4 storage. New backups use archive3; archive2 is verification-only in the current full-installation restore flow. No production certification or automatic primary promotion is implied.

## Contextual WebUI help

Supporting explanations and deployment instructions use shared information popovers beside headings and fields. Field labels, operational data, errors, import warnings and destructive confirmations remain visible. The TypeScript/Vite build and Chromium suite verify click/keyboard opening, Escape and focus return, outside dismissal, one-open-at-a-time behavior, mobile viewport bounds, dark/light themes and existing setup/DNS/host/backup flows. The popovers use the browser's native Popover API and require a current browser.
