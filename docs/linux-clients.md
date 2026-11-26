# Ubuntu/Linux integration

Forklift uses standard RFC2307 LDAP identities, SSSD, NSS, PAM and OpenSSH. Users enter their centrally managed password at `ssh username@server`. There is no resident Forklift authentication agent and the manager is not in the login path.

## Use the directory address from setup

First-launch setup creates the primary's private LDAPS listener and matching certificate. No certificate script or Compose override is required. Use the address shown in Directory Servers, normally `ldaps://<private-IP>:1636`, or the optional DNS name selected in setup. NPM carries WebUI HTTPS only; LDAP connects directly to its private port. Restrict that port to intended client networks using the host firewall.

Change the address or renew the certificate under Settings. Regenerate/deploy affected host bundles afterward. The certificate must match the configured DNS/IP address; never disable TLS verification.

Additional endpoint URIs are accepted for SSSD failover in listed order. Every endpoint must hold the same directory data and host read identity and present a matching DNS certificate. Regenerated bundles trust the primary CA plus the pinned leaf certificates of enrolled replicas in the endpoint list. Add new directory servers through [node pairing](peer-controllers.md) and monitor them in Directory Servers.

## Register and generate a host bundle

Primary and replica machines appear automatically as **Inventory only** with no SSH grant. Edit one to assign allowed groups before generating a client bundle. For other machines, register a Linux host.

Create at least one practical login group, such as `server-admins`, and assign users to it. In **Hosts**, register a friendly name, DNS hostname, ordered LDAPS endpoints, and permitted login groups. At least one group is required; an empty policy is refused.

The host bundle endpoint is available to existing automation. This creates or rotates a dedicated `cn=host-<id>,<base DN>` read identity. The manager write credential is never distributed to clients. Host bind secrets are random, hashed by OpenLDAP using Argon2, returned in the archive only and not retained in SQLite. Password hashes cannot be read by the host identity and directory modifications are denied.

**Each export rotates that host's bind password.** Redeploy the new configuration promptly; previous bundles cannot make new binds. If delivery fails, export again. Already authenticated LDAP connections and cached identity data may outlive rotation. Deleting a host revokes its bind identity and removes metadata; it does not uninstall client files, kill SSH sessions or ban that machine from authenticating LDAP users. SSSD can authenticate known users with their own passwords even after the read identity is revoked. Decommission by removing its SSH/PAM configuration or blocking network access as well; do not use host deletion as an access-control kill switch.

The `.tar.gz` contains:

| File            | Purpose                                                                                              |
| --------------- | ---------------------------------------------------------------------------------------------------- |
| `sssd.conf`     | Sensitive host bind credential, RFC2307 mappings, verified TLS, account expiry and ordered endpoints |
| `ca.crt`        | Public installation CA                                                                               |
| `access.conf`   | Allowed LDAP SSH groups followed by deny-all                                                         |
| `sshd-pam.conf` | PAM account rules preserving local recovery accounts                                                 |
| `sshd.conf`     | PAM-enabled SSH password authentication; no sudo rules                                               |
| `manifest.json` | Host ID, configuration revision, endpoints, groups and export timestamps                             |
| `README.txt`    | Installation summary and security notes                                                              |

Extract under a private directory (`umask 077`, directory mode 0700). The archive sets `sssd.conf` mode 0600. Do not commit or attach bundles to bug reports. Use encrypted storage and transport; SSSD must be able to read its bind password, so it is stored root-only on the destination host.

Host state is factual: **Not exported**, **Configuration exported**, or **Needs new export**. Forklift does not claim the host is online or that deployment succeeded. Editing endpoints or permitted groups increments the revision and requires generating and deploying new files. Concurrent edits/exports with an old revision are rejected. Referenced groups cannot be renamed or deleted without updating the host policies first.

## Ansible deployment

The role targets Ubuntu 22.04 and 24.04; validation results identify which release was actually exercised. Use a local recovery account or existing SSH key for Ansible bootstrap, with privilege escalation. Keep a recovery shell open until a second login succeeds. No Forklift write credential or Docker access is needed on the client.

Inventory on your Ansible controller:

```ini
[forklift_clients]
backup.homelab.internal ansible_user=localadmin forklift_bundle_dir=/secure/forklift/backup
```

`forklift_bundle_dir` is an absolute path on the controller containing the extracted bundle for that specific host. Deploy from the repository:

```sh
ansible-playbook -i inventory.ini ansible/playbook.yml --ask-become-pass
```

The role installs client packages, copies SSSD secrets without logging their contents, adds NSS lookups, enables the standard SSSD/mkhomedir PAM profiles and adds an SSH account policy. It validates SSSD and the complete SSH configuration before restarting SSSD or reloading SSH. It preserves backup copies of changed files. Credential-containing backups on the client remain sensitive and require the same protection as the original file. Do not disable `no_log` or run configuration diffs on the secret task.

The role manages one Forklift SSSD domain and `/etc/sssd/sssd.conf`; do not apply it over an existing multi-domain setup without reviewing the combined configuration. Local `/etc/passwd` users retain their existing SSH/PAM policy. The role does not grant sudo, disable pre-existing sudo rules, or replace your independent local recovery account. If SSSD already appears in `/etc/nsswitch.conf`, it is not duplicated.

## Manual installation

On the Ubuntu client, with the extracted bundle in the current directory:

```sh
sudo apt-get update
sudo apt-get install sssd-ldap sssd-tools libnss-sss libpam-sss openssh-server
sudo install -d -o root -g root -m 0711 /etc/sssd
sudo install -o root -g root -m 0600 sssd.conf /etc/sssd/sssd.conf
sudo install -o root -g root -m 0644 ca.crt /etc/sssd/forklift-ca.crt
sudo install -o root -g root -m 0644 access.conf /etc/security/forklift-access.conf
sudo install -o root -g root -m 0644 sshd.conf /etc/ssh/sshd_config.d/00-forklift.conf
sudo pam-auth-update --enable sss --enable mkhomedir
```

Ensure `sss` appears once on each `passwd:`, `group:` and `shadow:` line in `/etc/nsswitch.conf`, retaining existing sources such as `files` and `systemd`. In `/etc/pam.d/sshd`, insert the **two lines from `sshd-pam.conf` together**, immediately before `@include common-account`:

```text
account [success=1 default=ignore] pam_localuser.so
account required pam_access.so accessfile=/etc/security/forklift-access.conf nodefgroup
```

These lines let local accounts skip only the Forklift group rule. The existing Ubuntu PAM stack still validates local and LDAP accounts. `pam_access` resolves permitted primary/supplemental POSIX groups via NSS; SSSD independently checks the LDAP shadow expiration during account management. Applying only `sssd.conf` without the PAM rule does **not** enforce permitted SSH groups.

Validate before restarting services:

```sh
sudo sssctl config-check
sudo sshd -t
sudo systemctl enable --now sssd ssh
sudo systemctl restart sssd
sudo systemctl reload ssh
getent passwd youruser
id youruser
ssh youruser@yourhost
```

Confirm both an allowed user's login and a disallowed user's rejection before closing the recovery session. Verify `sudo sshd -T` reports `usepam yes` and `passwordauthentication yes`; existing earlier SSH directives, cloud-image snippets or administrator Match blocks can override generated settings. Review those conflicts rather than weakening PAM policy.

## Authorization, cache behavior and outages

- Login permission is enforced by destination PAM, SSSD and SSH, not by the WebUI. Allowed primary or supplemental group membership grants SSH eligibility. The WebUI administrator group uses explicit membership and is separate from this host permission.
- A correct LDAP password without a permitted group must fail SSH account management. A disabled account has its password removed and shadow expiry set; SSSD's LDAP access provider rejects it during account management, including an account-only PAM check.
- The generated policy applies to SSH. Other PAM services retain their existing Ubuntu configuration; apply equivalent account rules separately if you also want to restrict console or other services. It does not control applications that bypass PAM.
- SSSD identity/group caching is set to 60 seconds. Membership changes can take that long to take effect; existing SSH sessions are not terminated. For a diagnostic refresh, `sudo sss_cache -E` expires identity caches.
- Offline password caching is disabled by default (`cache_credentials=false`). Uncached authentication fails closed when all LDAP endpoints are unavailable. Existing installations that previously enabled credential caching should explicitly review/clear old caches and set their own offline policy. No management operation can instantly revoke an offline credential or existing session.
- The manager can be stopped without interrupting LDAP authentication. Endpoint fallback is native SSSD behavior; one reachable correctly provisioned directory is sufficient. Actual primary/replica data synchronization and first-login failover are covered by the replication integration test.
- Each user has one centrally managed password. Password resets happen in Forklift; the generated client disables self-service password changes because the server currently reserves password writes for its management identity.
- No sudo provider/rule is generated. Configure privilege escalation independently and review any existing local sudo groups.

## Troubleshooting and removal

Use `getent passwd`, `id`, `sssctl config-check`, `sssctl user-checks username -s sshd`, `journalctl -u sssd -u ssh` and `/var/log/sssd/`. Do not paste `sssd.conf` or the archive into logs or bug reports. Common failures are wrong DNS SANs, inaccessible private ports, a stale host bind password after export, missing PAM rules, name/UID collisions with local users, and stale identity/group caches.

For rollback, use the independent local administrator. Restore the pre-deployment SSSD, NSS, PAM and SSH files, remove `/etc/ssh/sshd_config.d/00-forklift.conf` if appropriate, validate SSH, then restart/reload services. Revoke the host identity through Forklift when removing the client permanently. Host deletion alone does not remove those client files. Do not delete shared SSSD databases or disable authentication modules blindly on a remotely accessed server.

References: [Ubuntu SSSD/LDAP integration](https://ubuntu.com/server/docs/how-to/sssd/with-ldap/), [SSSD LDAP options](https://manpages.ubuntu.com/manpages/noble/man5/sssd-ldap.5.html), [PAM access rules](https://manpages.ubuntu.com/manpages/noble/man5/access.conf.5.html).
