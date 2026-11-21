use super::*;
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(super) struct Server {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub provider: String,
    pub state: String,
    pub certificate: Option<String>,
    pub expires_at: i64,
    pub last_checked_at: Option<i64>,
    pub last_sync_at: Option<i64>,
    pub last_error: Option<String>,
}
pub(super) fn migrate(db: &Connection) -> anyhow::Result<()> {
    db.execute_batch("BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS directory_servers(id TEXT PRIMARY KEY,name TEXT NOT NULL,endpoint TEXT NOT NULL UNIQUE,provider TEXT NOT NULL,state TEXT NOT NULL,certificate TEXT,enrollment_hash TEXT,enrollment_expires INTEGER NOT NULL,last_checked_at INTEGER,last_sync_at INTEGER,last_error TEXT); PRAGMA user_version=3; COMMIT;")?;
    Ok(())
}
pub(super) fn records(a: &App) -> Result<Vec<Server>> {
    let db = a.db.lock().unwrap();
    let mut q=db.prepare("SELECT id,name,endpoint,provider,state,certificate,enrollment_expires,last_checked_at,last_sync_at,last_error FROM directory_servers ORDER BY name").map_err(anyhow::Error::from)?;
    Ok(q.query_map([], |r| {
        Ok(Server {
            id: r.get(0)?,
            name: r.get(1)?,
            endpoint: r.get(2)?,
            provider: r.get(3)?,
            state: r.get(4)?,
            certificate: r.get(5)?,
            expires_at: r.get(6)?,
            last_checked_at: r.get(7)?,
            last_sync_at: r.get(8)?,
            last_error: r.get(9)?,
        })
    })
    .map_err(anyhow::Error::from)?
    .collect::<std::result::Result<Vec<_>, _>>()
    .map_err(anyhow::Error::from)?)
}
fn load(a: &App, id: &str) -> Result<Server> {
    records(a)?.into_iter().find(|s| s.id == id).ok_or(Error(
        StatusCode::NOT_FOUND,
        "Directory server not found".into(),
    ))
}
fn https_required(a: &App) -> Result<()> {
    if !a.url.starts_with("https://") {
        return Err(bad(
            "Configure FORKLIFT_PUBLIC_URL with HTTPS before replica enrollment",
        ));
    }
    Ok(())
}
#[derive(Deserialize)]
pub(super) struct Draft {
    name: String,
    endpoint: String,
    provider: String,
}
pub(super) async fn create(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Draft>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    https_required(&a)?;
    if p.name.trim().is_empty() || p.name.len() > 100 || p.name.chars().any(char::is_control) {
        return Err(bad("Provide a directory server name"));
    }
    hosts::endpoint_hostname(&p.endpoint)?;
    hosts::endpoint_hostname(&p.provider)?;
    if same_endpoint(&p.endpoint, &p.provider) {
        return Err(bad("Primary and replica endpoints must be different"));
    }
    let _guard = a.gate.lock().await;
    if records(&a)?.len() >= 8 {
        return Err(bad("This release supports up to eight enrolled replicas"));
    }
    if records(&a)?
        .iter()
        .any(|r| same_endpoint(&r.endpoint, &p.endpoint))
    {
        return Err(bad("Directory endpoint already registered"));
    }
    let id = token()[..32].to_string();
    audit(&a, &who, "register replica", &id)?;
    a.db.lock().unwrap().execute("INSERT INTO directory_servers(id,name,endpoint,provider,state,enrollment_expires) VALUES(?,?,?,?,'pending',0)",params![id,p.name,p.endpoint,p.provider]).map_err(anyhow::Error::from)?;
    Ok(Json(json!(load(&a, &id)?)))
}
fn archive(files: Vec<(&str, Vec<u8>, u32)>) -> Result<Vec<u8>> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    for (name, bytes, mode) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(mode);
        h.set_mtime(now() as u64);
        h.set_cksum();
        tar.append_data(&mut h, name, bytes.as_slice())
            .map_err(anyhow::Error::from)?;
    }
    Ok(tar
        .into_inner()
        .map_err(anyhow::Error::from)?
        .finish()
        .map_err(anyhow::Error::from)?)
}
const COMPOSE: &str = include_str!("../assets/replica.compose.yaml");
const DOCKERFILE: &str = include_str!("../assets/replica.Dockerfile");
#[derive(Deserialize)]
pub(super) struct Bundle {
    acknowledge: bool,
}
pub(super) async fn bundle(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Bundle>,
) -> Result<Response> {
    let who = admin(&a, &h, true).await?;
    https_required(&a)?;
    if !p.acknowledge {
        return Err(bad(
            "Acknowledge that the bundle contains a short-lived enrollment secret",
        ));
    }
    let _guard = a.gate.lock().await;
    let server = load(&a, &id)?;
    if server.state == "enrolled" || server.state == "redeeming" {
        return Err(bad(
            "An enrolled or in-progress server cannot receive another enrollment token",
        ));
    }
    let raw = token();
    let expiry = now() + 900;
    let enrollment = json!({"id":id,"token":raw,"hostname":hosts::endpoint_hostname(&server.endpoint)?,"provider":server.provider,"manager_url":a.url,"expires_at":expiry});
    let ca = std::fs::read("/run/secrets/ca.crt").map_err(anyhow::Error::from)?;
    let readme = format!(
        "Forklift replica: {}\n\nPrivate enrollment bundle. Token expires at Unix time {} (15 minutes), is scoped to this server and can be redeemed once.\nExtract on the second Docker host. Keep this directory private. Run ./prepare.sh, set FORKLIFT_REPLICA_BIND to a private interface in .env, then docker compose up -d --build.\nThe DNS name {} must resolve to this host and its published LDAPS port must match {}. The provider {} must be reachable from the replica.\nManager HTTPS uses system trust; for private PKI place its public CA in enrollment/manager-ca.crt before startup.\nThe replica generates its own private TLS key. Its non-CA certificate is pinned during enrollment; the installation CA signing key is never distributed.\nWait for confirmed synchronization in Forklift before putting the replica in client endpoint lists. Regenerate host bundles so SSSD trusts the new server certificate.\nUse independent storage. Never share primary MDB files or promote this read-only server automatically.\nA consumed token cannot be replayed, even after an interrupted response. Stop the failed stack and reissue an unused enrollment, or remove/re-add a consumed server. Never erase a working directory to hide an error.\n",
        server.name,
        expiry,
        hosts::endpoint_hostname(&server.endpoint)?,
        server.endpoint,
        server.provider
    );
    let prepare = include_bytes!("../assets/replica.prepare.sh");
    let bytes = archive(vec![
        ("compose.yaml", COMPOSE.as_bytes().to_vec(), 0o600),
        ("Dockerfile", DOCKERFILE.as_bytes().to_vec(), 0o600),
        (
            "replica.py",
            include_bytes!("../assets/replica.py").to_vec(),
            0o600,
        ),
        ("prepare.sh", prepare.to_vec(), 0o700),
        (
            "enrollment/enrollment.json",
            serde_json::to_vec_pretty(&enrollment).map_err(anyhow::Error::from)?,
            0o600,
        ),
        ("enrollment/provider-ca.crt", ca, 0o644),
        ("README.txt", readme.into_bytes(), 0o600),
    ])?;
    a.db.lock().unwrap().execute("UPDATE directory_servers SET enrollment_hash=?,enrollment_expires=?,state='pending',last_error=NULL WHERE id=?",params![digest(&raw),expiry,id]).map_err(anyhow::Error::from)?;
    audit(&a, &who, "issue replica enrollment", &id)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/gzip".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"forklift-replica-{id}.tar.gz\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        bytes,
    )
        .into_response())
}
fn validate_certificate(pem: &str, hostname: &str) -> Result<()> {
    if pem.len() > 16384 {
        return Err(bad("Replica certificate is too large"));
    }
    let cert = openssl::x509::X509::from_pem(pem.as_bytes())
        .map_err(|_| bad("Invalid replica certificate"))?;
    let der = cert.to_der().map_err(anyhow::Error::from)?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der)
        .map_err(|_| bad("Invalid replica certificate"))?;
    let constraints = parsed
        .basic_constraints()
        .map_err(|_| bad("Invalid certificate constraints"))?
        .ok_or(bad("Certificate must explicitly be a non-CA leaf"))?;
    let usage = parsed
        .key_usage()
        .map_err(|_| bad("Invalid certificate key usage"))?
        .ok_or(bad("Certificate needs key usage constraints"))?;
    let names = parsed
        .subject_alternative_name()
        .map_err(|_| bad("Invalid certificate DNS names"))?
        .ok_or(bad("Certificate needs a DNS SAN"))?;
    let expected = x509_parser::extensions::GeneralName::DNSName(hostname);
    let key = cert.public_key().map_err(anyhow::Error::from)?;
    if constraints.value.ca
        || usage.value.key_cert_sign()
        || !usage.value.digital_signature()
        || names.value.general_names != vec![expected]
        || !parsed.validity().is_valid()
        || parsed.validity().not_after.timestamp() - parsed.validity().not_before.timestamp()
            > 397 * 86400
        || key.id() != openssl::pkey::Id::RSA
        || key.bits() < 2048
        || !cert.verify(&key).map_err(anyhow::Error::from)?
    {
        return Err(bad(
            "Use a valid self-signed non-CA RSA certificate (2048+ bits), at most 397 days, with exactly the registered DNS SAN",
        ));
    }
    Ok(())
}
#[derive(Deserialize)]
pub(super) struct Enrollment {
    token: String,
    certificate: String,
}
pub(super) async fn enroll(
    State(a): State<App>,
    Path(id): Path<String>,
    Json(p): Json<Enrollment>,
) -> Result<Json<Value>> {
    https_required(&a)?;
    if p.token.len() != 64 || !p.token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Invalid or expired enrollment".into(),
        ));
    }
    let _guard = a.gate.lock().await;
    let server = load(&a, &id)?;
    // The token authenticates this one endpoint, not a global administrator.
    let expected=a.db.lock().unwrap().query_row("SELECT enrollment_hash FROM directory_servers WHERE id=? AND state='pending' AND enrollment_expires>?",params![id,now()],|r|r.get::<_,Option<String>>(0)).ok().flatten();
    if expected.as_deref() != Some(digest(&p.token).as_str()) {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Invalid or expired enrollment".into(),
        ));
    }
    validate_certificate(&p.certificate, &hosts::endpoint_hostname(&server.endpoint)?)?;
    a.db.lock()
        .unwrap()
        .execute(
            "UPDATE directory_servers SET state='redeeming',enrollment_hash=NULL WHERE id=?",
            [&id],
        )
        .map_err(anyhow::Error::from)?;
    let result = provision_reader(&a, &id).await;
    match result {
        Ok(credential) => {
            a.db.lock().unwrap().execute("UPDATE directory_servers SET state='enrolled',certificate=?,last_error=NULL WHERE id=?",params![p.certificate,id]).map_err(anyhow::Error::from)?;
            audit(&a, "enrollment", "enroll replica", &id)?;
            Ok(Json(
                json!({"base":base(&a)?,"provider":server.provider,"credential":credential}),
            ))
        }
        Err(e) => {
            a.db.lock().unwrap().execute("UPDATE directory_servers SET state='failed',last_error='Primary provisioning failed; issue a new enrollment' WHERE id=?",[&id]).map_err(anyhow::Error::from)?;
            Err(e)
        }
    }
}
fn monitor_credential() -> String {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(secret("service").as_bytes()).expect("HMAC key");
    mac.update(b"forklift/directory-monitor/v1");
    hex::encode(mac.finalize().into_bytes())
}
async fn provision_reader(a: &App, id: &str) -> Result<String> {
    let mut l = service(a).await?;
    let b = base(a)?;
    let dn = format!("cn=replica-{id},{b}");
    if search(&mut l, &b, &format!("(cn=replica-{id})"))
        .await?
        .is_empty()
    {
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
                ("cn".to_string(), HashSet::from([format!("replica-{id}")])),
                (
                    "userPassword".to_string(),
                    HashSet::from(["{CRYPT}!".to_string()]),
                ),
            ],
        )
        .await?
        .success()?;
    }
    let monitor_dn = format!("cn=monitor,{b}");
    if search(&mut l, &b, "(cn=monitor)").await?.is_empty() {
        l.add(
            &monitor_dn,
            vec![
                (
                    "objectClass".to_string(),
                    HashSet::from([
                        "organizationalRole".to_string(),
                        "simpleSecurityObject".to_string(),
                    ]),
                ),
                ("cn".to_string(), HashSet::from(["monitor".to_string()])),
                (
                    "userPassword".to_string(),
                    HashSet::from(["{CRYPT}!".to_string()]),
                ),
            ],
        )
        .await?
        .success()?;
    }
    password(&mut l, &monitor_dn, &monitor_credential()).await?;
    let raw = token();
    password(&mut l, &dn, &raw).await?;
    Ok(raw)
}
pub(super) async fn connection(a: &App, s: &Server) -> anyhow::Result<Ldap> {
    let cert = s
        .certificate
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Replica has no enrolled certificate"))?;
    let mut tls = native_tls::TlsConnector::builder();
    tls.disable_built_in_roots(true);
    tls.add_root_certificate(native_tls::Certificate::from_pem(cert.as_bytes())?);
    let settings = ldap3::LdapConnSettings::new()
        .set_conn_timeout(std::time::Duration::from_secs(3))
        .set_connector(tls.build()?);
    let (conn, mut l) = LdapConnAsync::with_settings(settings, &s.endpoint).await?;
    ldap3::drive!(conn);
    l.with_timeout(std::time::Duration::from_secs(5));
    l.simple_bind(
        &format!(
            "cn=monitor,{}",
            base(a).map_err(|_| anyhow::anyhow!("Setup required"))?
        ),
        &monitor_credential(),
    )
    .await?
    .success()?;
    Ok(l)
}
pub(super) async fn fallback(a: &App) -> anyhow::Result<Ldap> {
    let mut attempts = tokio::task::JoinSet::new();
    for server in records(a)
        .map_err(|_| anyhow::anyhow!("Directory metadata unavailable"))?
        .into_iter()
        .filter(|s| s.state == "enrolled")
    {
        let app = a.clone();
        attempts.spawn(async move { connection(&app, &server).await });
    }
    while let Some(result) = attempts.join_next().await {
        if let Ok(Ok(l)) = result {
            attempts.abort_all();
            return Ok(l);
        }
    }
    anyhow::bail!("Primary and enrolled replicas unavailable")
}
async fn context(l: &mut Ldap, b: &str) -> anyhow::Result<Vec<String>> {
    l.with_timeout(std::time::Duration::from_secs(5));
    let (rs, _) = l
        .search(b, Scope::Base, "(objectClass=*)", vec!["contextCSN"])
        .await?
        .success()?;
    let mut csn = rs
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .and_then(|e| e.attrs.get("contextCSN").cloned())
        .unwrap_or_default();
    csn.sort();
    Ok(csn)
}
pub(super) async fn health(a: &App) -> Result<Value> {
    let b = base(a)?;
    let primary = match service(a).await {
        Ok(mut l) => context(&mut l, &b).await,
        Err(e) => Err(e),
    };
    let primary_csn = primary.as_ref().ok().cloned();
    let mut nodes = vec![
        json!({"id":"primary","name":"Primary directory","endpoint":"ldaps://ldap:636","role":"primary","reachable":primary.is_ok(),"state":if primary.is_ok(){"ready"}else{"unreachable"},"context_csn":primary_csn,"checked_at":now(),"error":primary.as_ref().err().map(|_|"Primary LDAP/TLS connection failed; administrative writes unavailable")}),
    ];
    let mut probes = tokio::task::JoinSet::new();
    for server in records(a)? {
        probes.spawn(probe(a.clone(), server, primary_csn.clone()));
    }
    let mut replicas = Vec::new();
    while let Some(result) = probes.join_next().await {
        replicas.push(result.map_err(anyhow::Error::from)??);
    }
    replicas.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    nodes.extend(replicas);
    Ok(json!({"servers":nodes,"primary_available":primary.is_ok(),"checked_at":now()}))
}
async fn probe(a: App, s: Server, primary_csn: Option<Vec<String>>) -> Result<Value> {
    let b = base(&a)?;
    let mut state = s.state.clone();
    let mut reachable = false;
    let mut observed = None;
    let mut error = None;
    let mut sync = s.last_sync_at;
    if s.state == "enrolled" {
        match connection(&a, &s).await {
            Ok(mut l) => match context(&mut l, &b).await {
                Ok(csn) => {
                    reachable = true;
                    let equal = primary_csn
                        .as_ref()
                        .is_some_and(|p| !p.is_empty() && *p == csn);
                    state = if equal {
                        "synchronized"
                    } else if primary_csn.is_none() {
                        "primary_unavailable"
                    } else {
                        "catching_up"
                    }
                    .into();
                    if equal {
                        sync = Some(now());
                    } else if primary_csn.is_some() {
                        error=Some("ContextCSNs differ or are absent; inspect replica Syncrepl/TLS logs if this persists".to_string());
                    }
                    observed = Some(csn);
                }
                Err(_) => {
                    state = "unavailable".into();
                    error = Some(
                        "LDAP bind succeeded but synchronization context could not be read".into(),
                    );
                }
            },
            Err(_) => {
                state = "unreachable".into();
                error=Some("Replica LDAP/TLS bind failed; check DNS, reachability, pinned certificate and initial synchronization".into());
            }
        }
        a.db.lock().unwrap().execute("UPDATE directory_servers SET last_checked_at=?,last_sync_at=CASE WHEN ? IS NULL THEN last_sync_at ELSE MAX(COALESCE(last_sync_at,0),?) END,last_error=? WHERE id=?",params![now(),sync,sync,error,s.id]).map_err(anyhow::Error::from)?;
    } else if s.state == "pending" && s.expires_at > 0 && s.expires_at <= now() {
        state = "expired".into();
    }
    if s.state != "enrolled" {
        error = error.or(s.last_error);
    }
    Ok(
        json!({"id":s.id,"name":s.name,"endpoint":s.endpoint,"provider":s.provider,"role":"replica","state":state,"enrollment_state":s.state,"reachable":reachable,"checked_at":if s.state=="enrolled"{Some(now())}else{None},"last_sync_at":sync,"context_csn":observed,"expires_at":s.expires_at,"error":error}),
    )
}
pub(super) async fn index(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    Ok(Json(health(&a).await?))
}
pub(super) async fn delete(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    load(&a, &id)?;
    let mut l = service(&a).await?;
    let b = base(&a)?;
    audit(&a, &who, "attempt remove replica", &id)?;
    if !search(&mut l, &b, &format!("(cn=replica-{id})"))
        .await?
        .is_empty()
    {
        l.delete(&format!("cn=replica-{id},{b}")).await?.success()?;
    }
    a.db.lock()
        .unwrap()
        .execute("DELETE FROM directory_servers WHERE id=?", [&id])
        .map_err(anyhow::Error::from)?;
    audit(&a, &who, "remove replica", &id)?;
    Ok(Json(json!({"ok":true})))
}
fn same_endpoint(left: &str, right: &str) -> bool {
    match (reqwest::Url::parse(left), reqwest::Url::parse(right)) {
        (Ok(a), Ok(b)) => {
            a.host_str() == b.host_str() && a.port().unwrap_or(636) == b.port().unwrap_or(636)
        }
        _ => false,
    }
}
pub(super) fn client_trust(a: &App, endpoints: &[String]) -> Result<Vec<u8>> {
    let mut ca = std::fs::read("/run/secrets/ca.crt").map_err(anyhow::Error::from)?;
    for s in records(a)?.into_iter().filter(|s| {
        s.state == "enrolled" && endpoints.iter().any(|e| same_endpoint(e, &s.endpoint))
    }) {
        if let Some(cert) = s.certificate {
            ca.push(b'\n');
            ca.extend_from_slice(cert.as_bytes());
        }
    }
    Ok(ca)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn certificate_requires_explicit_leaf_and_matching_name() {
        assert!(validate_certificate("not a certificate", "replica.test").is_err());
        assert!(validate_certificate(&"a".repeat(17000), "replica.test").is_err());
    }
    #[test]
    fn migration_preserves_hosts() {
        let db = Connection::open_in_memory().unwrap();
        hosts::migrate(&db).unwrap();
        db.execute("INSERT INTO hosts VALUES('id','hostname','preserved')", [])
            .unwrap();
        migrate(&db).unwrap();
        migrate(&db).unwrap();
        assert_eq!(
            db.query_row("SELECT data FROM hosts", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "preserved"
        );
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            3
        );
    }
}
