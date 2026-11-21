# Version 0.5 verification

Validated on Linux/amd64 with Docker Engine, native OpenLDAP 2.6.10 and isolated Compose projects. Each test uses random credentials, private temporary fixtures and independent volumes; it cleans up only its own resources. No default installation or user volume is reset.

| Check                                                                     | Result                                                                                                                                        |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Locked Rust unit tests, formatting and Clippy with warnings denied        | Passed; 8 unit tests                                                                                                                          |
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
