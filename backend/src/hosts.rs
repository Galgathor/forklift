use super::*;
use crate::dns::host_records as dns_hosts;
use serde::Serialize;

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct HostDraft {
    pub name: String,
    pub hostname: String,
    pub endpoints: Vec<String>,
    pub allowed_groups: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Host {
    pub id: String,
    #[serde(default)]
    pub directory_id: Option<String>,
    #[serde(default)]
    pub directory_role: Option<String>,
    #[serde(flatten)]
    pub draft: HostDraft,
    #[serde(default)]
    pub dns: Option<dns_hosts::Config>,
    #[serde(default)]
    pub dns_status: Option<dns_hosts::Status>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<Value>,
    pub revision: i64,
    pub exported_revision: Option<i64>,
    pub exported_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}
pub(super) fn hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}
#[cfg(test)]
fn validate(p: &HostDraft) -> Result<()> {
    validate_inventory(p, false)
}
fn validate_inventory(p: &HostDraft, inventory: bool) -> Result<()> {
    if p.name.trim().is_empty()
        || p.name.len() > 100
        || p.name.chars().any(char::is_control)
        || !hostname(&p.hostname)
        || p.endpoints.is_empty()
        || p.endpoints.len() > 8
        || (!inventory && p.allowed_groups.is_empty())
        || p.allowed_groups.len() > 32
        || p.allowed_groups.iter().any(|s| !valid(s))
        || p.allowed_groups.iter().collect::<HashSet<_>>().len() != p.allowed_groups.len()
    {
        return Err(bad(
            "Provide a name, lowercase DNS hostname and 1–8 LDAPS endpoints. Select up to 32 distinct existing login groups; at least one is required unless this is DNS-only or directory inventory",
        ));
    }
    for endpoint in &p.endpoints {
        endpoint_hostname(endpoint)?;
    }

    Ok(())
}
pub(super) fn endpoint_hostname(endpoint: &str) -> Result<String> {
    let uri = reqwest::Url::parse(endpoint).map_err(|_| bad("Invalid LDAPS endpoint"))?;
    if uri.scheme() != "ldaps"
        || !uri.username().is_empty()
        || uri.password().is_some()
        || !uri.host_str().is_some_and(hostname)
        || uri.query().is_some()
        || uri.fragment().is_some()
        || uri.path() != ""
        || uri.port() == Some(0)
        || endpoint.len() > 300
        || endpoint.bytes().any(|c| c.is_ascii_whitespace())
    {
        return Err(bad(
            "Use ldaps://dns-name[:port] endpoints without paths, credentials or query parameters",
        ));
    }
    Ok(uri.host_str().unwrap().to_string())
}
fn valid_id(s: &str) -> Result<()> {
    if s.len() != 32 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(bad("Invalid host ID"));
    }
    Ok(())
}
pub(super) fn migrate(db: &Connection) -> anyhow::Result<()> {
    let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    db.execute_batch("BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS hosts(id TEXT PRIMARY KEY,hostname TEXT NOT NULL,data TEXT NOT NULL);")?;
    db.pragma_update(None, "user_version", version.max(2))?;
    db.execute_batch("COMMIT;")?;
    Ok(())
}
pub(super) fn list(a: &App) -> Result<Vec<Host>> {
    let db = a.db.lock().unwrap();
    let mut q = db
        .prepare("SELECT data FROM hosts ORDER BY hostname")
        .map_err(anyhow::Error::from)?;
    let data = q
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(anyhow::Error::from)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?;
    drop(q);
    drop(db);
    data.into_iter()
        .map(|s| {
            let mut h: Host = serde_json::from_str(&s).map_err(anyhow::Error::from)?;
            h.client = crate::clients::summary(a, &h.id)?;
            h.dns_status = dns_hosts::status(a, &h.id, h.dns.as_ref(), h.revision)?;
            Ok(h)
        })
        .collect()
}
pub(crate) fn load(a: &App, id: &str) -> Result<Host> {
    valid_id(id)?;
    list(a)?
        .into_iter()
        .find(|h| h.id == id)
        .ok_or(Error(StatusCode::NOT_FOUND, "Host not found".into()))
}
pub(super) fn group_in_use(a: &App, name: &str) -> Result<bool> {
    Ok(list(a)?
        .iter()
        .any(|h| h.draft.allowed_groups.iter().any(|g| g == name)))
}
async fn check_groups(a: &App, p: &HostDraft) -> Result<()> {
    let mut l = service(a).await?;
    for name in &p.allowed_groups {
        if search(
            &mut l,
            &format!("ou=groups,{}", base(a)?),
            &format!("(&(objectClass=posixGroup)(cn={name}))"),
        )
        .await?
        .is_empty()
        {
            return Err(bad("A permitted login group does not exist"));
        }
    }
    Ok(())
}
pub(super) fn store(a: &App, h: &Host) -> Result<()> {
    if list(a)?
        .iter()
        .any(|e| h.directory_id.is_none() && e.draft.hostname == h.draft.hostname && e.id != h.id)
    {
        return Err(bad("A host with that hostname already exists"));
    }
    write_host(a, h)
}

fn write_host(a: &App, h: &Host) -> Result<()> {
    let mut stored = h.clone();
    stored.dns_status = None;
    stored.client = None;
    a.db.lock().unwrap().execute("INSERT INTO hosts(id,hostname,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET hostname=excluded.hostname,data=excluded.data", params![h.id,h.draft.hostname,serde_json::to_string(&stored).map_err(anyhow::Error::from)?]).map_err(anyhow::Error::from)?;
    Ok(())
}
pub(super) async fn index(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    Ok(Json(json!(list(&a)?)))
}
fn yes() -> bool {
    true
}
#[derive(Deserialize)]
pub(super) struct Create {
    #[serde(flatten)]
    draft: HostDraft,
    dns: Option<dns_hosts::Config>,
    #[serde(default = "yes")]
    dns_apply: bool,
}
pub(super) async fn create(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Create>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    let dns = p.dns.map(dns_hosts::Config::normalize).transpose()?;
    validate_inventory(&p.draft, dns.is_some())?;
    let _guard = a.gate.lock().await;
    dns_hosts::validate_unique(&a, "", dns.as_ref())?;
    check_groups(&a, &p.draft).await?;
    let host = Host {
        directory_id: None,
        directory_role: None,
        id: token()[..32].into(),
        draft: p.draft,
        dns,
        dns_status: None,
        client: None,
        revision: 1,
        exported_revision: None,
        exported_at: None,
        created_at: now(),
        updated_at: now(),
    };
    audit(&a, &who, "attempt register host", &host.id)?;
    store(&a, &host)?;
    audit(&a, &who, "register host", &host.id)?;
    finish_dns(&a, &who, &host, p.dns_apply).await;
    Ok(Json(json!(load(&a, &host.id)?)))
}
async fn finish_dns(a: &App, who: &str, host: &Host, apply: bool) {
    if host.dns.is_some() || host.dns_status.is_some() {
        if let Err(error) = dns_hosts::intent(a, host) {
            eprintln!("Host DNS intent failed: {}", error.1);
            return;
        }
        if apply && let Err(error) = dns_hosts::reconcile_locked(a, who, &host.id).await {
            eprintln!("Host DNS reconciliation failed: {}", error.1);
        }
    }
}
#[derive(Default)]
enum DnsEdit {
    #[default]
    Unchanged,
    Set(Option<dns_hosts::Config>),
}
impl<'de> Deserialize<'de> for DnsEdit {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(Self::Set(Option::deserialize(d)?))
    }
}
#[derive(Deserialize)]
pub(super) struct Update {
    #[serde(flatten)]
    draft: HostDraft,
    revision: i64,
    #[serde(default)]
    dns: DnsEdit,
    #[serde(default = "yes")]
    dns_apply: bool,
    dns_cleanup: Option<String>,
}
pub(super) async fn update(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Update>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    let mut host = load(&a, &id)?;
    if host.directory_id.is_some() && host.draft.hostname != p.draft.hostname {
        return Err(bad(
            "Directory hostnames are managed through Directory Servers",
        ));
    }
    if host.revision != p.revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Host changed; refresh before editing".into(),
        ));
    }
    let explicit = matches!(p.dns, DnsEdit::Set(_));
    let disabling =
        matches!(p.dns, DnsEdit::Set(None)) && (host.dns.is_some() || host.dns_status.is_some());
    if disabling && !matches!(p.dns_cleanup.as_deref(), Some("keep" | "delete")) {
        return Err(bad("Choose whether to keep or delete managed DNS records"));
    }
    if let DnsEdit::Set(config) = p.dns {
        host.dns = config.map(dns_hosts::Config::normalize).transpose()?;
    }
    validate_inventory(
        &p.draft,
        host.dns.is_some() || host.directory_id.is_some() || host.draft.allowed_groups.is_empty(),
    )?;
    dns_hosts::validate_unique(&a, &id, host.dns.as_ref())?;
    check_groups(&a, &p.draft).await?;
    host.draft = p.draft;
    host.revision += 1;
    host.updated_at = now();
    audit(&a, &who, "attempt update host", &id)?;
    store(&a, &host)?;
    audit(&a, &who, "update host", &id)?;
    if disabling && p.dns_cleanup.as_deref() == Some("keep") {
        dns_hosts::detach(&a, &host)?;
    } else {
        finish_dns(&a, &who, &host, explicit && p.dns_apply).await;
    }
    Ok(Json(json!(load(&a, &id)?)))
}
#[derive(Deserialize)]
pub(super) struct Delete {
    dns: Option<String>,
    revision: Option<i64>,
}
pub(super) async fn delete(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(p): axum::extract::Query<Delete>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    let host = load(&a, &id)?;
    if host.directory_id.is_some() {
        return Err(bad("Remove directory servers through Directory Servers"));
    }
    let has_dns = host.dns.is_some() || host.dns_status.is_some();
    if has_dns
        && (p.revision != Some(host.revision)
            || !matches!(p.dns.as_deref(), Some("keep" | "delete")))
    {
        return Err(bad(
            "Refresh this host and explicitly choose to keep or delete its managed DNS records",
        ));
    }
    audit(&a, &who, "attempt delete host", &id)?;
    let mut l = service(&a).await?;
    let b = base(&a)?;
    if !search(&mut l, &b, &format!("(cn=host-{})", host.id))
        .await?
        .is_empty()
    {
        l.delete(&format!("cn=host-{id},{b}")).await?.success()?;
    }
    crate::clients::revoke_host(&a, &id)?;
    dns_hosts::retire(&a, &host, has_dns && p.dns.as_deref() == Some("delete"))?;
    audit(&a, &who, "delete host", &id)?;
    let status = if has_dns && p.dns.as_deref() == Some("delete") {
        Some(
            dns_hosts::reconcile_locked(&a, &who, &id)
                .await
                .unwrap_or_else(|e| dns_hosts::Status::failed(&e.1)),
        )
    } else {
        None
    };
    Ok(Json(json!({"ok":true,"dns_status":status})))
}
pub(super) fn sssd(h: &Host, b: &str, credential: &str) -> String {
    format!(
        "# Forklift host {} · revision {}\n# Sensitive: root:root, mode 0600. Never commit this file.\n[sssd]\nconfig_file_version = 2\nservices = nss, pam\ndomains = forklift\n\n[nss]\nfilter_users = root\nfilter_groups = root\n\n[pam]\noffline_credentials_expiration = 1\n\n[domain/forklift]\nid_provider = ldap\nauth_provider = ldap\nchpass_provider = none\naccess_provider = ldap\nldap_access_order = expire\nldap_account_expire_policy = shadow\nldap_schema = rfc2307\nldap_uri = {}\nldap_search_base = {b}\nldap_user_search_base = ou=people,{b}\nldap_group_search_base = ou=groups,{b}\nldap_default_bind_dn = cn=host-{},{}\nldap_default_authtok_type = password\nldap_default_authtok = {credential}\nldap_tls_reqcert = demand\nldap_tls_cacert = /etc/sssd/forklift-ca.crt\nldap_referrals = false\nldap_network_timeout = 3\nldap_opt_timeout = 5\ncache_credentials = false\nuse_fully_qualified_names = false\nenumerate = false\nmin_id = 10000\nentry_cache_timeout = 60\n",
        h.id,
        h.revision,
        h.draft.endpoints.join(", "),
        h.id,
        b
    )
}
pub(super) fn access(h: &Host) -> String {
    format!(
        "# Forklift SSH group policy; local recovery accounts bypass this file via pam_localuser.\n+ : {} : ALL\n- : ALL : ALL\n",
        h.draft
            .allowed_groups
            .iter()
            .map(|g| format!("({g})"))
            .collect::<Vec<_>>()
            .join(" ")
    )
}
const PAM: &str = "account [success=1 default=ignore] pam_localuser.so\naccount required pam_access.so accessfile=/etc/security/forklift-access.conf nodefgroup\n";
const SSHD: &str = "# Forklift: LDAP password authentication uses normal PAM. No sudo grants.\nUsePAM yes\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\n";
#[derive(Deserialize)]
pub(super) struct Export {
    revision: i64,
    rotate: bool,
}
pub(super) async fn bundle(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Export>,
) -> Result<Response> {
    let who = admin(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    let mut host = load(&a, &id)?;
    if host.draft.allowed_groups.is_empty() {
        return Err(bad(
            "Choose SSH login groups before configuring this Linux host",
        ));
    }
    if p.revision != host.revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Host changed; refresh before exporting".into(),
        ));
    }
    if !p.rotate {
        return Err(bad(
            "Explicitly acknowledge host credential rotation to generate a bundle",
        ));
    }
    check_groups(&a, &host.draft).await?;
    let ca = replicas::client_trust(&a, &host.draft.endpoints)?;
    let credential = token();
    let b = base(&a)?;
    let dn = format!("cn=host-{id},{b}");
    let mut l = service(&a).await?;
    audit(&a, &who, "attempt rotate host credential", &id)?;
    if search(&mut l, &b, &format!("(cn=host-{id})"))
        .await?
        .is_empty()
    {
        // No password until Password Modify succeeds; a partial creation cannot bind.
        l.add(
            &dn,
            vec![
                (
                    "objectClass".to_string(),
                    HashSet::from([
                        "organizationalRole".to_string(),
                        "simpleSecurityObject".to_string(),
                    ]),
                ),
                ("cn".to_string(), HashSet::from([format!("host-{id}")])),
                (
                    "userPassword".to_string(),
                    HashSet::from(["{CRYPT}!".to_string()]),
                ),
            ],
        )
        .await?
        .success()?;
    }
    password(&mut l, &dn, &credential).await?;
    host.exported_revision = Some(host.revision);
    host.exported_at = Some(now());
    store(&a, &host)?;
    let conf = sssd(&host, &b, &credential);
    let policy = access(&host);
    let manifest = serde_json::to_string_pretty(&host).map_err(anyhow::Error::from)?;
    let readme = format!(
        "Forklift client bundle for {} ({}), revision {}\n\nSENSITIVE: sssd.conf contains a read-only LDAP bind credential. Keep this archive private.\nThis export rotated the host credential; previous exports stop working for new LDAP binds.\n\nUse the repository's ansible/playbook.yml with forklift_bundle_dir set to this extracted directory.\nSee docs/linux-clients.md for full manual instructions and recovery guidance.\nRequired packages: sssd-ldap sssd-tools libnss-sss libpam-sss openssh-server.\n\nInstall sssd.conf as /etc/sssd/sssd.conf root:root 0600.\nInstall ca.crt as /etc/sssd/forklift-ca.crt root:root 0644.\nInstall access.conf as /etc/security/forklift-access.conf root:root 0644.\nInsert the account rules from sshd-pam.conf in /etc/pam.d/sshd before @include common-account.\nInstall sshd.conf as /etc/ssh/sshd_config.d/00-forklift.conf root:root 0644.\nAdd sss to passwd/group/shadow in /etc/nsswitch.conf; run pam-auth-update --enable sss --enable mkhomedir.\nRun sssctl config-check and sshd -t before restarting SSSD and reloading SSH.\nKeep a local recovery account and an open session during deployment.\n\nAll endpoints must be reachable and certificate DNS names/CA must match.\nNo credentials are cached for offline login. Group lookups may be cached for 60 seconds.\nThe PAM rules restrict LDAP SSH accounts, preserving local /etc/passwd accounts.\nThese files grant no sudo permissions. Host liveness/deployment is not reported to Forklift.\n",
        host.draft.name, host.draft.hostname, host.revision
    );
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (name, bytes, mode) in [
        ("sssd.conf", conf.as_bytes(), 0o600),
        ("ca.crt", ca.as_slice(), 0o644),
        ("access.conf", policy.as_bytes(), 0o644),
        ("sshd-pam.conf", PAM.as_bytes(), 0o644),
        ("sshd.conf", SSHD.as_bytes(), 0o644),
        ("manifest.json", manifest.as_bytes(), 0o600),
        ("README.txt", readme.as_bytes(), 0o600),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_mtime(now() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, name, bytes)
            .map_err(anyhow::Error::from)?;
    }
    let bytes = archive
        .into_inner()
        .map_err(anyhow::Error::from)?
        .finish()
        .map_err(anyhow::Error::from)?;
    audit(&a, &who, "export host configuration", &id)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/gzip".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"forklift-{}.tar.gz\"",
                    host.draft.hostname
                ),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        bytes,
    )
        .into_response())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_configuration_injection() {
        let mut h = HostDraft {
            name: "Server".into(),
            hostname: "server.example.test".into(),
            endpoints: vec!["ldaps://ldap.example.test:636".into()],
            allowed_groups: vec!["server-admins".into()],
        };
        assert!(validate(&h).is_ok());
        for uri in [
            "ldap://ldap",
            "ldaps://user:secret@ldap",
            "ldaps://ldap/path",
            "ldaps://ldap\ncache_credentials=true",
            "ldaps://ldap?query",
            "ldaps://ldap:0",
        ] {
            h.endpoints = vec![uri.into()];
            assert!(validate(&h).is_err(), "{uri}");
        }
        h.endpoints = vec!["ldaps://ldap".into()];
        h.allowed_groups = vec![];
        assert!(validate(&h).is_err());
    }
    #[test]
    fn omitted_dns_preserves_settings_but_null_requests_detachment() {
        let body = json!({"name":"Server", "hostname":"server.example.test", "endpoints":["ldaps://ldap.example.test"], "allowed_groups":["administrators"], "revision":1});
        let omitted: Update = serde_json::from_value(body.clone()).unwrap();
        assert!(matches!(omitted.dns, DnsEdit::Unchanged));
        let mut body = body;
        body["dns"] = Value::Null;
        let detached: Update = serde_json::from_value(body).unwrap();
        assert!(matches!(detached.dns, DnsEdit::Set(None)));
    }
    #[test]
    fn migration_preserves_existing_metadata() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE settings(value TEXT); INSERT INTO settings VALUES('preserve'); PRAGMA user_version=1;").unwrap();
        migrate(&db).unwrap();
        migrate(&db).unwrap();
        assert_eq!(
            db.query_row("SELECT value FROM settings", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "preserve"
        );
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
}

/// Inventory registration does not install SSSD or grant SSH access.
pub(super) fn sync_directory(
    a: &App,
    directory_id: &str,
    name: &str,
    hostname: &str,
    role: &str,
) -> Result<()> {
    sync_directory_for(a, directory_id, name, hostname, role, None)
}
pub(super) fn sync_directory_for(
    a: &App,
    directory_id: &str,
    name: &str,
    hostname: &str,
    role: &str,
    target: Option<&str>,
) -> Result<()> {
    sync_directory_entry(a, directory_id, name, hostname, role, target, None)
}

pub(super) fn sync_provider(
    a: &App,
    directory_id: &str,
    hostname: &str,
    endpoint: &str,
) -> Result<()> {
    sync_directory_entry(
        a,
        directory_id,
        "Directory Server",
        hostname,
        "provider",
        None,
        Some(endpoint),
    )
}

fn sync_directory_entry(
    a: &App,
    directory_id: &str,
    name: &str,
    hostname: &str,
    role: &str,
    target: Option<&str>,
    endpoint: Option<&str>,
) -> Result<()> {
    let records = list(a)?;
    let existing = if let Some(id) = target {
        records.into_iter().find(|h| h.id == id)
    } else {
        records
            .iter()
            .find(|h| h.directory_id.as_deref() == Some(directory_id))
            .cloned()
            .or_else(|| {
                records
                    .into_iter()
                    .find(|h| h.directory_id.is_none() && h.draft.hostname == hostname)
            })
    };
    if target.is_some() && existing.is_none() {
        return Err(bad("Host no longer exists"));
    }
    let endpoint = endpoint
        .map(str::to_owned)
        .or_else(|| config(a).and_then(|c| c["network"]["endpoint"].as_str().map(str::to_owned)))
        .ok_or(bad("Complete directory setup first"))?;
    if let Some(host) = &existing
        && host.directory_id.as_deref() == Some(directory_id)
        && host.directory_role.as_deref() == Some(role)
        && (target.is_some() || host.client.is_some() || host.draft.hostname == hostname)
        && !(directory_id == "primary"
            && matches!(
                host.draft.name.as_str(),
                "Primary directory" | "Local directory"
            ))
    {
        return Ok(());
    }
    let mut host = existing.unwrap_or(Host {
        id: if directory_id == "primary" {
            "00000000000000000000000000000001".into()
        } else if role == "provider" {
            provider_host_id(directory_id)
        } else {
            directory_id.into()
        },
        directory_id: Some(directory_id.into()),
        directory_role: Some(role.into()),
        draft: HostDraft {
            name: name.into(),
            hostname: hostname.into(),
            endpoints: vec![endpoint],
            allowed_groups: vec![],
        },
        dns: None,
        dns_status: None,
        client: None,
        revision: 1,
        exported_revision: None,
        exported_at: None,
        created_at: now(),
        updated_at: now(),
    });
    host.directory_id = Some(directory_id.into());
    host.directory_role = Some(role.into());
    if target.is_none() && host.client.is_none() {
        host.draft.hostname = hostname.into();
    }
    if directory_id == "primary"
        && matches!(
            host.draft.name.as_str(),
            "Primary directory" | "Local directory"
        )
    {
        host.draft.name = name.into();
    }
    host.updated_at = now();
    store(a, &host)
}
fn provider_host_id(directory_id: &str) -> String {
    digest(&format!("forklift:directory-host:{directory_id}"))[..32].into()
}

pub(super) fn unlink_directory(a: &App, directory_id: &str) -> Result<()> {
    for mut host in list(a)?
        .into_iter()
        .filter(|h| h.directory_id.as_deref() == Some(directory_id))
    {
        let generated = host.directory_role.as_deref() != Some("provider")
            || host.id == provider_host_id(directory_id);
        if generated
            && host.client.is_none()
            && host.draft.allowed_groups.is_empty()
            && host.dns.is_none()
            && host.dns_status.is_none()
        {
            a.db.lock()
                .unwrap()
                .execute("DELETE FROM hosts WHERE id=?", [host.id])
                .map_err(anyhow::Error::from)?;
        } else {
            host.directory_id = None;
            host.directory_role = None;
            write_host(a, &host)?;
        }
    }
    Ok(())
}
