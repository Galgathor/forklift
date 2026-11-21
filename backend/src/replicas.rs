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
    pub next_certificate: Option<String>,
    pub certificate_staged_at: Option<i64>,
    pub credential_rotated_at: Option<i64>,
    pub credential_epoch: i64,
    pub address: String,
    pub control_port: u16,
    pub pending_epoch: Option<i64>,
}
pub(super) fn migrate(db: &Connection) -> anyhow::Result<()> {
    let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    db.execute_batch("BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS directory_servers(id TEXT PRIMARY KEY,name TEXT NOT NULL,endpoint TEXT NOT NULL UNIQUE,provider TEXT NOT NULL,state TEXT NOT NULL,certificate TEXT,enrollment_hash TEXT,enrollment_expires INTEGER NOT NULL,last_checked_at INTEGER,last_sync_at INTEGER,last_error TEXT);")?;
    db.pragma_update(None, "user_version", version.max(3))?;
    db.execute_batch("COMMIT;")?;
    Ok(())
}
pub(super) fn records(a: &App) -> Result<Vec<Server>> {
    let db = a.db.lock().unwrap();
    let mut q=db.prepare("SELECT id,name,endpoint,provider,state,certificate,enrollment_expires,last_checked_at,last_sync_at,last_error,next_certificate,certificate_staged_at,credential_rotated_at,credential_epoch,address,control_port,pending_epoch FROM directory_servers ORDER BY name").map_err(anyhow::Error::from)?;
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
            next_certificate: r.get(10)?,
            certificate_staged_at: r.get(11)?,
            credential_rotated_at: r.get(12)?,
            credential_epoch: r.get(13)?,
            address: r.get(14)?,
            control_port: r.get(15)?,
            pending_epoch: r.get(16)?,
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
    if !public_url(a).starts_with("https://") {
        return Err(bad(
            "Configure the HTTPS WebUI address in Settings before replica enrollment",
        ));
    }
    Ok(())
}
#[derive(Deserialize)]
pub(super) struct Draft {
    name: String,
    address: String,
    hostname: Option<String>,
    #[serde(default = "directory_port")]
    port: u16,
    #[serde(default = "control_port")]
    control_port: u16,
}
fn directory_port() -> u16 {
    1636
}
fn control_port() -> u16 {
    9443
}
pub(super) async fn create(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Draft>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    https_required(&a)?;
    if p.name.trim().is_empty()
        || p.name.len() > 100
        || p.name.chars().any(char::is_control)
        || p.port == 0
        || p.control_port == 0
        || p.port == p.control_port
    {
        return Err(bad("Choose a name and distinct directory/control ports"));
    }
    replica_setup::private_ipv4(&p.address)?;
    let hostname = p
        .hostname
        .filter(|s| !s.is_empty())
        .unwrap_or(p.address.clone());
    let endpoint = format!("ldaps://{hostname}:{}", p.port);
    hosts::endpoint_hostname(&endpoint)?;
    let provider = config(&a)
        .and_then(|v| v["network"]["endpoint"].as_str().map(str::to_owned))
        .ok_or(bad(
            "Complete the primary server configuration in initial setup",
        ))?;
    if same_endpoint(&endpoint, &provider) {
        return Err(bad("Use a different machine or port for this replica"));
    }
    let _guard = a.gate.lock().await;
    if records(&a)?.len() >= 8
        || records(&a)?
            .iter()
            .any(|r| same_endpoint(&r.endpoint, &endpoint))
    {
        return Err(bad(
            "This replica already exists or the eight-server limit was reached",
        ));
    }
    let id = token()[..32].to_owned();
    audit(&a, &who, "register replica", &id)?;
    a.db.lock().unwrap().execute("INSERT INTO directory_servers(id,name,endpoint,provider,state,enrollment_expires,address,control_port) VALUES(?,?,?,?,'pending',0,?,?)",params![id,p.name,endpoint,provider,p.address,p.control_port]).map_err(anyhow::Error::from)?;
    hosts::sync_directory(&a, &id, &p.name, &hostname, "replica")?;
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
    let (server, enrollment, ca, expiry) = issue_enrollment(&a, &id, &who)?;
    let readme = format!(
        "Forklift replica: {}\n\nExtract this private archive on the new Docker host and start the included Compose stack using Docker Compose or your Docker hosting UI. Compose prepares enrollment permissions automatically; no administrator scripts or .env edits are required.\nOne-use enrollment expires at Unix time {}. Keep the deployment private. The directory binds {} on its configured port and its pinned-TLS control service uses port {}. Restrict both to the intended private networks.\nThe primary address is inherited from Forklift setup: {}. WebUI HTTPS must be reachable; for private HTTPS PKI place its public CA in enrollment/manager-ca.crt before starting.\nAfter enrollment, use Forklift for credentials, certificates and configuration. This node appears in Hosts automatically; that inventory record does not grant SSH access. Wait for confirmed synchronization before configuring Linux clients for failover.\n",
        server.name, expiry, server.address, server.control_port, server.provider
    );
    let files = vec![
        (
            ".gitignore",
            b".env\nenrollment/\ncredential-update.json\n".to_vec(),
            0o600,
        ),
        (
            ".dockerignore",
            b".env\nenrollment/\ncredential-update.json\n".to_vec(),
            0o600,
        ),
        ("compose.yaml", COMPOSE.as_bytes().to_vec(), 0o600),
        ("Dockerfile", DOCKERFILE.as_bytes().to_vec(), 0o600),
        (
            "replica.py",
            include_bytes!("../assets/replica.py").to_vec(),
            0o600,
        ),
        (
            "enrollment/enrollment.json",
            serde_json::to_vec_pretty(&enrollment).map_err(anyhow::Error::from)?,
            0o600,
        ),
        ("enrollment/provider-ca.crt", ca, 0o644),
        ("README.txt", readme.into_bytes(), 0o600),
    ];
    let bytes = archive(files)?;
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
fn issue_enrollment(a: &App, id: &str, who: &str) -> Result<(Server, Value, Vec<u8>, i64)> {
    let server = load(a, id)?;
    if server.state == "enrolled" || server.state == "redeeming" {
        return Err(bad(
            "An enrolled or in-progress server cannot receive another enrollment token",
        ));
    }
    let raw = token();
    let expiry = now() + 900;
    let enrollment = json!({"id":id,"token":raw,"hostname":hosts::endpoint_hostname(&server.endpoint)?,"provider":server.provider,"manager_url":public_url(a),"expires_at":expiry,"address":server.address,"port":reqwest::Url::parse(&server.endpoint).map_err(|_|bad("Invalid endpoint"))?.port().unwrap_or(636),"control_port":server.control_port});
    let ca = std::fs::read("/run/secrets/ca.crt").map_err(anyhow::Error::from)?;
    a.db.lock().unwrap().execute("UPDATE directory_servers SET enrollment_hash=?,enrollment_expires=?,state='pending',last_error=NULL WHERE id=?",params![digest(&raw),expiry,id]).map_err(anyhow::Error::from)?;
    audit(a, who, "issue replica enrollment", id)?;
    Ok((server, enrollment, ca, expiry))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JoinRequest {
    acknowledge: bool,
    manager_ca: Option<String>,
}
pub(super) async fn deployment(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<JoinRequest>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    https_required(&a)?;
    if !p.acknowledge {
        return Err(bad(
            "Acknowledge that the join configuration contains a short-lived enrollment secret",
        ));
    }
    if let Some(ca) = &p.manager_ca {
        if ca.len() > 65536
            || ca.contains("PRIVATE KEY")
            || ca
                .replace("-----BEGIN CERTIFICATE-----", "")
                .contains("-----BEGIN")
        {
            return Err(bad(
                "Supply only public HTTPS CA certificates, without private keys",
            ));
        }
        let certs = openssl::x509::X509::stack_from_pem(ca.as_bytes())
            .map_err(|_| bad("Invalid HTTPS CA certificate"))?;
        if certs.is_empty() {
            return Err(bad(
                "Supply a public HTTPS CA certificate or leave it blank",
            ));
        }
    }
    let _guard = a.gate.lock().await;
    let (_, enrollment, ca, expiry) = issue_enrollment(&a, &id, &who)?;
    let provider_ca = String::from_utf8(ca).map_err(anyhow::Error::from)?;
    let envelope = json!({"version":1,"enrollment":enrollment,"provider_ca":provider_ca,"manager_ca":p.manager_ca});
    let encoded =
        openssl::base64::encode_block(&serde_json::to_vec(&envelope).map_err(anyhow::Error::from)?);
    Ok(Json(
        json!({"join_config":format!("FORKLIFT_REPLICA_JOIN={encoded}"),"expires_at":expiry,"directory_id":id}),
    ))
}

fn validate_certificate(pem: &str, hostname: &str) -> Result<()> {
    let trimmed = pem.trim();
    if !trimmed.starts_with("-----BEGIN CERTIFICATE-----")
        || !trimmed.ends_with("-----END CERTIFICATE-----")
        || trimmed.matches("-----BEGIN").count() != 1
    {
        return Err(bad(
            "Provide one public certificate, without private keys or additional PEM blocks",
        ));
    }
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
    let ip = hostname.parse::<std::net::IpAddr>().ok();
    let octets = match ip {
        Some(std::net::IpAddr::V4(v)) => v.octets().to_vec(),
        Some(std::net::IpAddr::V6(v)) => v.octets().to_vec(),
        None => Vec::new(),
    };
    let expected = if octets.is_empty() {
        x509_parser::extensions::GeneralName::DNSName(hostname)
    } else {
        x509_parser::extensions::GeneralName::IPAddress(&octets)
    };
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
            "Use a valid self-signed non-CA RSA certificate (2048+ bits), at most 397 days, with exactly the registered DNS/IP SAN",
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
    let consumed=a.db.lock().unwrap().execute("UPDATE directory_servers SET state='redeeming',enrollment_hash=NULL WHERE id=? AND state='pending' AND enrollment_hash=? AND enrollment_expires>?",params![id,digest(&p.token),now()]).map_err(anyhow::Error::from)?;
    if consumed != 1 {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Invalid or expired enrollment".into(),
        ));
    }
    let result = provision_reader(&a, &id).await;
    match result {
        Ok(credential) => {
            a.db.lock().unwrap().execute("UPDATE directory_servers SET state='enrolled',certificate=?,credential_epoch=1,last_error=NULL WHERE id=?",params![p.certificate,id]).map_err(anyhow::Error::from)?;
            audit(&a, "enrollment", "enroll replica", &id)?;
            Ok(Json(
                json!({"base":base(&a)?,"provider":server.provider,"credential":credential,"credential_epoch":1,"control_token":node_secret(&id,1,"control")}),
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
    let raw = node_secret(id, 1, "replication");
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
    if let Some(next) = &s.next_certificate {
        tls.add_root_certificate(native_tls::Certificate::from_pem(next.as_bytes())?);
    }
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
        json!({"id":"primary","name":"Primary directory","endpoint":config(a).map(|v|v["network"]["endpoint"].clone()),"role":"primary","reachable":primary.is_ok(),"state":if primary.is_ok(){"ready"}else{"unreachable"},"context_csn":primary_csn,"checked_at":now(),"error":primary.as_ref().err().map(|_|"Primary LDAP/TLS connection failed; administrative writes unavailable")}),
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
        json!({"id":s.id,"name":s.name,"endpoint":s.endpoint,"provider":s.provider,"role":"replica","state":state,"enrollment_state":s.state,"reachable":reachable,"checked_at":if s.state=="enrolled"{Some(now())}else{None},"last_sync_at":sync,"context_csn":observed,"expires_at":s.expires_at,"certificate_rotation_pending":s.next_certificate.is_some(),"certificate_staged_at":s.certificate_staged_at,"credential_rotated_at":s.credential_rotated_at,"credential_epoch":s.credential_epoch,"address":s.address,"control_port":s.control_port,"pending_epoch":s.pending_epoch,"provider_needs_update":config(&a).is_some_and(|v|v["network"]["endpoint"]!=s.provider),"error":error}),
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
    hosts::unlink_directory(&a, &id)?;
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
        if let Some(cert) = s.next_certificate {
            ca.push(b'\n');
            ca.extend_from_slice(cert.as_bytes());
        }
    }
    Ok(ca)
}

#[derive(Deserialize)]
pub(super) struct CertificateUpdate {
    acknowledge: bool,
}
fn fingerprint(pem: &str) -> Result<Vec<u8>> {
    openssl::x509::X509::from_pem(pem.as_bytes())
        .and_then(|c| c.to_der())
        .map_err(anyhow::Error::from)
        .map_err(Error::from)
}
fn host_trust_updates(a: &App, endpoint: &str) -> Result<Vec<(String, String)>> {
    let mut updates = Vec::new();
    for mut host in hosts::list(a)? {
        if !host.draft.allowed_groups.is_empty()
            && host
                .draft
                .endpoints
                .iter()
                .any(|e| same_endpoint(e, endpoint))
        {
            host.revision += 1;
            host.updated_at = now();
            updates.push((
                host.id.clone(),
                serde_json::to_string(&host).map_err(anyhow::Error::from)?,
            ));
        }
    }
    Ok(updates)
}
pub(super) async fn stage_certificate(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<CertificateUpdate>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    if !p.acknowledge {
        return Err(bad(
            "Acknowledge redeploying client trust before activating the staged certificate",
        ));
    }
    let _guard = a.gate.lock().await;
    let server = load(&a, &id)?;
    if server.state != "enrolled"
        || server.next_certificate.is_some()
        || server.pending_epoch.is_some()
    {
        return Err(bad(
            "Use an enrolled server without an existing certificate transition",
        ));
    }
    let generated = node_request(&a, &server, "/v1/certificate/stage", json!({"id":id})).await?;
    let certificate = generated["certificate"]
        .as_str()
        .ok_or(bad("Replica did not return a public certificate"))?
        .to_owned();
    validate_certificate(&certificate, &hosts::endpoint_hostname(&server.endpoint)?)?;
    if fingerprint(&certificate)? == fingerprint(server.certificate.as_deref().unwrap_or(""))? {
        return Err(bad("Certificate is already active"));
    }
    let updates = host_trust_updates(&a, &server.endpoint)?;
    let mut db = a.db.lock().unwrap();
    let tx = db.transaction().map_err(anyhow::Error::from)?;
    tx.execute(
        "UPDATE directory_servers SET next_certificate=?,certificate_staged_at=? WHERE id=?",
        params![certificate, now(), id],
    )
    .map_err(anyhow::Error::from)?;
    for (host, data) in &updates {
        tx.execute("UPDATE hosts SET data=? WHERE id=?", params![data, host])
            .map_err(anyhow::Error::from)?;
    }
    tx.execute(
        "INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)",
        params![now(), who, "stage replica certificate", id],
    )
    .map_err(anyhow::Error::from)?;
    tx.commit().map_err(anyhow::Error::from)?;
    Ok(Json(
        json!({"staged":true,"hosts_requiring_export":updates.len()}),
    ))
}
pub(super) async fn finalize_certificate(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<operations::Acknowledgment>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    if !p.acknowledge {
        return Err(bad(
            "Acknowledge client trust deployment and retiring the old pin",
        ));
    }
    let _guard = a.gate.lock().await;
    let server = load(&a, &id)?;
    if server.pending_epoch.is_some() {
        return Err(bad("Finish the pending credential update first"));
    }
    let next = server
        .next_certificate
        .as_deref()
        .ok_or(bad("No staged certificate"))?;
    node_request(
        &a,
        &server,
        "/v1/certificate/activate",
        json!({"id":id,"fingerprint":hex::encode(Sha256::digest(fingerprint(next)?))}),
    )
    .await?;
    let mut l = connection(&a, &server).await?;
    let presented = l
        .get_peer_certificate()
        .await?
        .ok_or(bad("No TLS peer certificate"))?;
    if presented != fingerprint(next)? {
        return Err(Error(StatusCode::CONFLICT,"Replica still presents a different certificate; activate the staged certificate and restart it first".into()));
    }
    node_request(&a, &server, "/v1/certificate/retire", json!({"id":id})).await?;
    let updates = host_trust_updates(&a, &server.endpoint)?;
    let mut db = a.db.lock().unwrap();
    let tx = db.transaction().map_err(anyhow::Error::from)?;
    tx.execute("UPDATE directory_servers SET certificate=next_certificate,next_certificate=NULL,certificate_staged_at=NULL WHERE id=?",[&id]).map_err(anyhow::Error::from)?;
    for (host, data) in &updates {
        tx.execute("UPDATE hosts SET data=? WHERE id=?", params![data, host])
            .map_err(anyhow::Error::from)?;
    }
    tx.execute(
        "INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)",
        params![now(), who, "finalize replica certificate", id],
    )
    .map_err(anyhow::Error::from)?;
    tx.commit().map_err(anyhow::Error::from)?;
    Ok(Json(
        json!({"finalized":true,"hosts_requiring_export":updates.len()}),
    ))
}
pub(super) async fn rotate_credential(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<operations::Acknowledgment>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    if !p.acknowledge {
        return Err(bad(
            "Acknowledge rotating and applying this replica's credentials",
        ));
    }
    let _guard = a.gate.lock().await;
    let mut server = load(&a, &id)?;
    if server.state != "enrolled" {
        return Err(bad("Enroll this server first"));
    }
    let epoch = server.pending_epoch.unwrap_or(server.credential_epoch + 1);
    a.db.lock()
        .unwrap()
        .execute(
            "UPDATE directory_servers SET pending_epoch=? WHERE id=?",
            params![epoch, id],
        )
        .map_err(anyhow::Error::from)?;
    server.pending_epoch = Some(epoch);
    audit(&a, &who, "attempt rotate replica credentials", &id)?;
    let mut ldap = service(&a).await?;
    password(
        &mut ldap,
        &format!("cn=replica-{id},{}", base(&a)?),
        &node_secret(&id, epoch, "replication"),
    )
    .await?;
    node_request(&a,&server,"/v1/credential",json!({"id":id,"base":base(&a)?,"provider":server.provider,"credential_epoch":epoch,"credential":node_secret(&id,epoch,"replication"),"control_token":node_secret(&id,epoch,"control")})).await?;
    a.db.lock().unwrap().execute("UPDATE directory_servers SET pending_epoch=NULL,credential_epoch=?,credential_rotated_at=? WHERE id=?",params![epoch,now(),id]).map_err(anyhow::Error::from)?;
    audit(&a, &who, "apply replica credential update", &id)?;
    Ok(Json(json!({"applied":true,"epoch":epoch})))
}
pub(super) async fn reconnect(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<operations::Acknowledgment>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    if !p.acknowledge {
        return Err(bad("Acknowledge reconnecting to the configured primary"));
    }
    let _guard = a.gate.lock().await;
    let server = load(&a, &id)?;
    let provider = config(&a)
        .and_then(|v| v["network"]["endpoint"].as_str().map(str::to_owned))
        .ok_or(bad("Primary configuration missing"))?;
    node_request(
        &a,
        &server,
        "/v1/provider",
        json!({"id":id,"provider":provider}),
    )
    .await?;
    a.db.lock()
        .unwrap()
        .execute(
            "UPDATE directory_servers SET provider=? WHERE id=?",
            params![provider, id],
        )
        .map_err(anyhow::Error::from)?;
    audit(&a, &who, "reconnect replica provider", &id)?;
    Ok(Json(json!({"applied":true})))
}
pub(super) async fn restart(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<operations::Acknowledgment>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    if !p.acknowledge {
        return Err(bad("Acknowledge restarting the replica"));
    }
    let _guard = a.gate.lock().await;
    let server = load(&a, &id)?;
    node_request(&a, &server, "/v1/restart", json!({"id":id})).await?;
    audit(&a, &who, "restart replica directory", &id)?;
    Ok(Json(json!({"restarted":true})))
}
fn node_secret(id: &str, epoch: i64, purpose: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(secret("node-control-key").as_bytes())
        .expect("HMAC accepts the installation key");
    mac.update(format!("forklift/node/v1/{purpose}/{id}/{epoch}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
async fn node_request(_a: &App, server: &Server, path: &str, body: Value) -> Result<Value> {
    if server.state != "enrolled" {
        return Err(bad("The replica must be enrolled before remote management"));
    }
    let mut builder = reqwest::Client::builder()
        .use_native_tls()
        .tls_built_in_root_certs(false)
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none());
    for certificate in [
        server.certificate.as_ref(),
        server.next_certificate.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(certificate.as_bytes()).map_err(anyhow::Error::from)?,
        );
    }
    let client = builder.build().map_err(anyhow::Error::from)?;
    let hostname = hosts::endpoint_hostname(&server.endpoint)?;
    let url = format!("https://{hostname}:{}{path}", server.control_port);
    for epoch in [Some(server.credential_epoch), server.pending_epoch]
        .into_iter()
        .flatten()
    {
        let mut response = {
            let mut received = None;
            for attempt in 0..4 {
                match client
                    .post(&url)
                    .bearer_auth(node_secret(&server.id, epoch, "control"))
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(response) => {
                        received = Some(response);
                        break;
                    }
                    Err(_) if attempt < 3 => {
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await
                    }
                    Err(_) => {}
                }
            }
            received.ok_or(Error(StatusCode::SERVICE_UNAVAILABLE,"Cannot reach the replica control service. Check its private control port and pinned TLS certificate, then retry in Forklift.".into()))?
        };
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            continue;
        }
        if !response.status().is_success() {
            return Err(bad(
                "Replica refused the requested transition; retry its current credential or certificate operation",
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(anyhow::Error::from)? {
            if bytes.len() + chunk.len() > 32768 {
                return Err(bad("Replica control response exceeded its limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        return serde_json::from_slice(&bytes)
            .map_err(anyhow::Error::from)
            .map_err(Error::from);
    }
    Err(Error(StatusCode::FORBIDDEN,"Replica control authorization failed; finish any pending credential update or reenroll a fenced server".into()))
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
