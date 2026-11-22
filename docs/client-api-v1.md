# Forklift Client API v1

**Canonical contract:** this file in the Forklift server repository. The companion repository mirrors it under `docs/`. Protocol version is independent of either product release. No client credential grants LDAP, administrative API, direct DNS API or command-execution access. Administrators may explicitly authorize backend-managed address updates for that client’s host.

## Transport and identity

Require HTTPS at the saved public origin. Ignore forwarded authentication headers. The manager works behind its existing HTTPS reverse proxy; client authentication is application-level, not proxy-asserted client certificates. Clients validate the operating-system CA store or an administrator-supplied public CA file. Redirects and HTTP URLs are rejected. Discovery never supplies trusted certificates.

Machine proofs follow [RFC 9449 DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) using ES256/P-256. The JWT header contains only `typ=dpop+jwt`, `alg=ES256`, and a public JWK with `crv`, `kty`, `x`, `y`. Claims are `jti` (at least 128 bits of randomness), `htm=POST`, exact canonical `htu` without query/fragment, `iat` within 60 seconds, and the latest server `nonce`. Authenticated requests additionally include `ath=base64url(SHA256(access_token))` and `Authorization: DPoP <access_token>`. Private JWK members, alternative algorithms, wrong targets/methods/keys/tokens and reused proofs are rejected. Thumbprints use [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html) canonical required members. Keep clocks synchronized.

All machine responses carry `DPoP-Nonce`. Obtain the first nonce from `GET /api/client/v1/info`. A 401 `use_dpop_nonce` permits one retry with a new proof/JTI and the supplied nonce. Nonces cover the current/previous server minute, and replay entries persist for two minutes. New proof IDs are required for every retry. HTTPS protects request bodies; DPoP itself is not a body-signing protocol.

## Pairing profile

This is a bounded JSON device-pairing profile modeled on [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html), not a general-purpose OAuth authorization server. JSON bodies reject unknown fields and are limited to 16 KiB. No machine endpoint uses an administrator's cookie or LDAP password.

| Endpoint | Request / behavior |
| --- | --- |
| `GET /api/client/v1/info` | Public `{api_version:1, instance_id, name, url, pairing_lifetime:600, capabilities:["enrollment-v1","session-v1"]}`. Setup and HTTPS are required. |
| `POST /api/client/v1/enrollments` | DPoP proof; `{api_version:1, request_id:<64 random hex>, identity}`. Save the key and request ID **before** this request. Returns `{api_version, enrollment_id, device_code, user_code, verification_uri, expires_at, expires_in, interval:5, key_fingerprint}`. Retrying the same request ID/key returns the same pending grant. |
| `POST /api/client/v1/enrollments/{id}/token` | DPoP proof plus `{device_code}`. Poll no faster than five seconds. Returns `{state:"authorization_pending"}` or `{state:"approved",api_version:1,host_id,credential_id,access_token,token_type:"DPoP"}`. A grant expires after ten minutes. |
| `POST /api/client/v1/enrollments/{id}/cancel` | DPoP proof and `{device_code}` cancel pending/unconfirmed approval. Completed enrollment uses authenticated leave. |
| `POST /api/client/v1/hosts/{host_id}/session` | Bound machine token/proof, empty JSON body. Returns `{api_version:1,host_id,server_time,enrollment:"active"}`. Confirms first receipt and records contact using server time. |
| `POST /api/client/v1/hosts/{host_id}/leave` | Bound machine token/proof. Revokes the identity and retains inventory and all Linux/DNS configuration. Returns `{revoked:true,host_retained:true}`. |

`identity` contains `hostname`, optional `fqdn`, `os`, `os_version`, `kernel`, `architecture`, `client_version`, `addresses:[{interface,address}]`, and `capabilities`. It is self-reported, bounded identifying information at enrollment, not verified hardware identity or current monitoring. Hostnames must be lowercase DNS names; up to 32 useful IPv4/IPv6 addresses and eight bounded capability strings are accepted. No MAC address, machine-id, user password or unrelated configuration is collected.

Codes have eight cryptographically derived base-32 characters, displayed `XXXX-XXXX` (40 bits), ten-minute expiry and one approval. Device codes and access tokens are independent 256-bit installation-key derivations; the registry stores only device/code digests, public keys and approval state. The client alone stores its private key and access credential. The installation key is outside SQLite in existing restricted secret storage. Token retrieval can be retried under the same key until the grant expires, handling a lost response or interrupted atomic local save. Active credentials remain revocable and key-bound; automated credential rotation is deferred to Milestone 4. Revoke/re-enroll to replace an identity now.

## Administrator endpoints

All require the existing LDAP administrator session. Write operations additionally require the exact Origin, CSRF token and completed recovery review.

- `GET /api/clients`: at most 128 newest pending/retained enrollment records; never returns device codes or access credentials.
- `POST /api/clients/lookup` with `{code}`: returns the pending record, hostname, addresses, public-key thumbprint and expiry for review. A consumed, expired or invalid code is not reviewable.
- `POST /api/clients/{id}/approve` with `{name,host_id:null|existing_id,host_revision:null|current_revision,acknowledge:true}`: atomically approves and creates inventory or explicitly links the selected existing host. Rejects hostname conflicts and an existing active client. Does not grant login groups or configure DNS/authentication.
- `POST /api/clients/{id}/revoke` with `{acknowledge:true}`: revokes pending/approved/active identity while retaining the host. Provides administrator-side cancellation too.

A host's existing response gains optional `client` metadata; old manual host endpoints remain compatible. Manual inventory has no implicit health/offline state. Client records contain `id,identity,key_fingerprint,state,host_id,created_at,expires_at,enrolled_at,last_contact`. The contact timestamp is a server observation, not a health diagnosis. States include pending, approved, active, cancelled, revoked and restore_required. Deleting a host revokes its client identities. Full installation restore quarantines every archived client identity; administrator review and fresh enrollment are required.

## Limits and errors

Initialization is globally limited to 30 requests/minute, three new requests/key/minute and 64 simultaneously pending machines. Lookup is limited to 20/minute. Polling is globally bounded to 1200/minute and five seconds/request; session checks allow 30/minute/identity; machine-authentication attempts are capped at 1200/minute and cancellation at 60/minute. Unknown device codes/tokens/keys cannot populate the replay cache. These are persistent installation-wide limits because forwarded source IPs are not trusted. Expired unlinked requests and replay/rate entries are pruned. An attacker able to reach the enrollment endpoint can temporarily exhaust pending capacity; existing enrolled sessions remain independent.

Use 400/422 for validation/compatibility failures (413 for an oversized body and 415 for an unsupported content type), 401 for invalid proof/credential or nonce challenge, 403 for denied/cancelled grants, 404 for unavailable pairing review, 409 for stale/conflicting/consumed approval, 410 for expired grants, 429 for throttling and 503 for unavailable storage/maintenance/setup. 429 carries Retry-After. Unexpected errors must not expose keys or request bodies.

## Inventory and monitoring (Milestone 2)

`GET /api/client/v1/info` advertises `inventory-v1` when supported. Upgrade the server before starting a 0.2 client daemon. Existing pairing/session endpoints and manual host APIs stay compatible. A 0.1 client can still check its session; it has no heartbeat and is shown as not reporting.

`POST /api/client/v1/hosts/{host_id}/heartbeat` requires the same DPoP authorization, nonce and exact method/target binding as session. Body:

```json
{"api_version":1,"sequence":1,"interval":300,"identity":{"hostname":"application.example.test","fqdn":"application.example.test","os":"ubuntu","os_version":"24.04","kernel":"example","architecture":"x86_64","client_version":"0.2.0","addresses":[{"interface":"eth0","address":"192.168.1.40"}],"capabilities":["inventory-v1"]},"interfaces":["eth0"]}
```

The entire request is limited to 16 KiB. Identity uses enrollment bounds; interfaces are bounded to 32 names of 1–32 safe ASCII characters. Reject duplicate addresses, loopback, unspecified, multicast, link-local, broadcast and IPv4-mapped IPv6 addresses. Interval is 30–3600 seconds; sequence is positive and below signed 64-bit maximum. No client timestamps determine freshness. Unknown fields (including commands) are rejected.

The native daemon atomically persists the latest snapshot and an incremented sequence **before** transmission. The sequence is scoped to the enrollment credential; never restore client state to an older sequence. Re-enroll after losing its state/counter. A higher sequence replaces the current observation. An identical same-sequence retry returns the original receipt/outcome without refreshing freshness or rerunning DNS; changed/stale sequences return 409. A new report retries pending DNS intent. Reports are limited to six/minute per identity, in addition to existing proof/authentication limits.

Success returns `api_version,host_id,sequence,received_at,inventory:"accepted",dns:{state,...}`. Inventory receipt is durable before independent DNS work, bounded to eight seconds per heartbeat. DNS may be disabled, pending, applied or needs_retry; inventory acceptance never implies DNS success. Responses after interrupted processing can retain pending state until a newer report retries. No DNS dependency is introduced into LDAP authentication or ordinary session checks.

`GET /api/hosts/{id}/monitoring` requires administrator authorization and returns `{policy,revision,history}`. `PUT` requires administrator authorization, Origin/CSRF/recovery checks and `{revision,policy}`. Policy contains `offline_after` (90–10800 seconds, default 900), `dns_updates` (default false), and `ipv4`/`ipv6` selectors, each null or `{interface,address:null|literal_ip}`. IPv4 selection is required for automatic updates because the existing host-DNS model requires IPv4. Without an IPv6 selector the existing configured AAAA remains. Follow an interface only if it has exactly one eligible family address; pin a literal when ambiguous. Missing selected addresses never delete records. Deliberately deferred administrator DNS edits require review and are not applied or overwritten by heartbeats.

Hosts gain `client.monitoring` with `connectivity`, `received_at`, `interval`, `offline_after`, `interfaces`, `inventory`, and a separate `dns` outcome. Values are observations, not proof of authentication health. Offline occurs after the greater of the configured threshold and three heartbeat intervals. Summary reads derive freshness immediately; a 30-second server watcher records transitions independently. Session requests cannot refresh heartbeat freshness. History retains the latest 100 server-timestamped enrollment-monitoring, inventory-change, policy, DNS-outcome, offline and recovery events; repeated unchanged reports do not duplicate them. Manual hosts remain unmonitored.

Automatic DNS uses only administrator-configured host names/zones and existing host-owned values. It validates actual PowerDNS ownership markers, rejects externally relinquished ownership, and preserves unrelated record-set members. The existing host-DNS journal handles partial writes/retry; its current state is authoritative for DNS reconciliation. Host DNS changes advance the host revision to prevent stale administrative edits. Hostname/FQDN changes in reports are observations only. A replacement enrollment resets DNS opt-in. Full installation restore still quarantines credentials; archived clients cannot report or modify DNS.

## Scope

Milestones 1–2 implement enrollment/linkage/revocation, native inventory/netlink, heartbeat freshness/offline history and explicitly authorized DNS address updates. DNS/LDAP/SSSD/PAM/NSS/SSH diagnostics, issue lifecycle/notifications, credential rotation and Debian packaging remain subsequent milestones. There are no remote commands or configuration repairs. A manual host never needs this client.
