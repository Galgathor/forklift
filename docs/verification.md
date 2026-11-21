# Version 0.5 verification

Validated on Linux/amd64 with Docker Engine, native OpenLDAP 2.6.10 and isolated Compose projects. Each test uses random credentials, private temporary fixtures and independent volumes; it cleans up only its own resources. No default installation or user volume is reset.

| Check                                                                     | Result                                                                                                                                        |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Locked Rust unit tests, formatting and Clippy with warnings denied        | Passed; 12 unit tests                                                                                                                         |
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

Unimplemented DNS phases: secondary enrollment/TSIG transfers/failover, bulk zone import and integrated encrypted DNS backup/restore. The existing encrypted LDAP snapshot excludes separate DNS data/secrets volumes. Multi-host DNS, schema-changing PowerDNS upgrades, infrastructure DNS restoration, large/load tests and an external security audit remain unverified. See [DNS operations](dns.md) for deployment, resolver forwarding and recovery boundaries.

## Host DNS integration (Phase 2)

Run `python3 tests/dns_hosts.py` against the built manager/DNS images. The suite passed real published DNS checks for host A/AAAA and IPv4/IPv6 PTR values, relative names, record-set merging and TTL preservation, preexisting/manual/disabled value protection, shared PTR ownership, rename/address changes, apply/defer, stale revisions, authenticated/CSRF-protected writes and explicit retention/deletion. It exercises DNS outages independently of LDAP, persisted retry state across manager recreation, deleted-host cleanup, interruption after an actual native write, conflicting external edits, superseded-plan rejection, primary inventory registration and volume persistence.

The Chromium suite also passed registration without SSH groups, editing addresses, deferred application, reconciliation, explicit DNS retention during deletion, actual retained values in the DNS page and responsive host forms. This phase does not include host liveness monitoring, DNS replication, continuous DNS drift polling, bulk import or integrated DNS recovery. Native comment ownership is a safety check with recorded metadata, not a lock against concurrent external PowerDNS administrators. One expanded run failed directory readiness after full-stack recreation with a missing LDAPI socket; the isolated rerun, including full recreation, passed. The cause of that transient existing-directory restart failure was not established; no LDAP configuration was changed for this feature.

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

Single Docker host tests simulate independent machines with separate storage and processes. Physically separate hosts/VMs, Ubuntu 22.04, full systemd boots, multiple simultaneous replicas, multi-architecture builds, large/load testing, long partitions, CA-root rotation and independent security auditing remain unverified. Schema5/archive2 is a deliberate break, not an upgrade claim for 0.4 storage. No production certification or automatic primary promotion is implied.
