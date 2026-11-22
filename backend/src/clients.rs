//! Optional native-client enrollment. Never supplies authentication-service configuration.
use super::*;
pub(super) mod monitoring;
use axum::{extract::Request, middleware::Next};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Serialize;

const PREFIX: &str = "/api/client/v1";
const LIFETIME: i64 = 600;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub hostname: String,
    pub fqdn: Option<String>,
    pub os: String,
    pub os_version: String,
    pub kernel: String,
    pub architecture: String,
    pub client_version: String,
    pub addresses: Vec<Address>,
    pub capabilities: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Address {
    pub interface: String,
    pub address: std::net::IpAddr,
}
#[derive(Clone, Deserialize, Serialize)]
struct Enrollment {
    id: String,
    request_hash: String,
    device_hash: String,
    code_hash: String,
    jwk: Value,
    thumbprint: String,
    identity: Identity,
    state: String,
    host_id: Option<String>,
    created_at: i64,
    expires_at: i64,
    last_poll: i64,
    enrolled_at: Option<i64>,
    last_contact: Option<i64>,
    generation: i64,
}
pub(super) fn migrate(db: &Connection) -> anyhow::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS client_enrollments(id TEXT PRIMARY KEY,request_hash TEXT UNIQUE NOT NULL,device_hash TEXT UNIQUE NOT NULL,code_hash TEXT UNIQUE NOT NULL,host_id TEXT,data TEXT NOT NULL); CREATE INDEX IF NOT EXISTS client_host_index ON client_enrollments(host_id); CREATE TABLE IF NOT EXISTS client_replays(thumb TEXT NOT NULL,jti TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(thumb,jti)); CREATE TABLE IF NOT EXISTS client_limits(scope TEXT PRIMARY KEY,at INTEGER NOT NULL,count INTEGER NOT NULL);")?;
    db.execute(
        "INSERT OR IGNORE INTO settings(key,value) VALUES('client_instance_id',?)",
        [json!(token()[..32]).to_string()],
    )?;
    monitoring::migrate(db)?;
    Ok(())
}
fn fail(code: StatusCode, message: &str) -> Error {
    Error(code, message.into())
}
fn secure(a: &App) -> Result<()> {
    if !public_url(a).starts_with("https://") || config(a).is_none() {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Configure Forklift HTTPS and finish setup before enrolling clients",
        ));
    }
    Ok(())
}
fn derive(purpose: &str, id: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret("node-control-key").as_bytes())
        .expect("Installation key");
    mac.update(format!("forklift/client/v1/{purpose}/{id}").as_bytes());
    B64.encode(mac.finalize().into_bytes())
}
fn equal(a: &str, b: &str) -> bool {
    openssl::memcmp::eq(
        Sha256::digest(a.as_bytes()).as_slice(),
        Sha256::digest(b.as_bytes()).as_slice(),
    )
}
fn nonce() -> String {
    let bucket = now() / 60;
    format!("{bucket}.{}", derive("nonce", &bucket.to_string()))
}
fn valid_nonce(value: &str) -> bool {
    (0..=1).any(|offset| {
        let bucket = now() / 60 - offset;
        equal(
            value,
            &format!("{bucket}.{}", derive("nonce", &bucket.to_string())),
        )
    })
}
pub(super) async fn headers(State(a): State<App>, req: Request, next: Next) -> Response {
    if let Err(e) = secure(&a) {
        return e.into_response();
    }
    let mut response = next.run(req).await;
    if matches!(response.status().as_u16(), 413 | 415 | 422) {
        response = (response.status(), Json(json!({"error":"invalid_request"}))).into_response();
    }
    response
        .headers_mut()
        .insert("DPoP-Nonce", nonce().parse().expect("ASCII nonce"));
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, "5".parse().unwrap());
    }
    response
}
fn rate(a: &App, scope: &str, max: i64) -> Result<()> {
    let db = a.db.lock().unwrap();
    db.execute("DELETE FROM client_limits WHERE at<?", [now() - 120])
        .map_err(anyhow::Error::from)?;
    db.execute("INSERT INTO client_limits(scope,at,count) VALUES(?,?,1) ON CONFLICT(scope) DO UPDATE SET count=CASE WHEN at<? THEN 1 ELSE count+1 END,at=CASE WHEN at<? THEN excluded.at ELSE at END",params![scope,now(),now()-60,now()-60]).map_err(anyhow::Error::from)?;
    let count: i64 = db
        .query_row(
            "SELECT count FROM client_limits WHERE scope=?",
            [scope],
            |r| r.get(0),
        )
        .map_err(anyhow::Error::from)?;
    if count > max {
        return Err(fail(
            StatusCode::TOO_MANY_REQUESTS,
            "Client request limit reached; retry later",
        ));
    }
    Ok(())
}
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Claims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    nonce: String,
    ath: Option<String>,
}
fn proof(
    a: &App,
    h: &HeaderMap,
    method: &str,
    path: &str,
    access: Option<&str>,
    expected_thumb: Option<&str>,
) -> Result<(Value, String)> {
    let invalid = || fail(StatusCode::UNAUTHORIZED, "invalid_dpop_proof");
    let raw = h
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 2048)
        .ok_or_else(invalid)?;
    let first = raw.split('.').next().ok_or_else(invalid)?;
    let header: Value = serde_json::from_slice(&B64.decode(first).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let obj = header.as_object().ok_or_else(invalid)?;
    if obj
        .keys()
        .any(|k| !["typ", "alg", "jwk"].contains(&k.as_str()))
        || header["typ"] != "dpop+jwt"
        || header["alg"] != "ES256"
    {
        return Err(invalid());
    }
    let jwk = &header["jwk"];
    let members = jwk.as_object().ok_or_else(invalid)?;
    if members.len() != 4
        || members
            .keys()
            .any(|k| !["kty", "crv", "x", "y"].contains(&k.as_str()))
        || jwk["kty"] != "EC"
        || jwk["crv"] != "P-256"
    {
        return Err(invalid());
    }
    for k in ["x", "y"] {
        if !jwk[k]
            .as_str()
            .is_some_and(|s| s.len() == 43 && B64.decode(s).is_ok_and(|b| b.len() == 32))
        {
            return Err(invalid());
        }
    }
    let typed = serde_json::from_value(jwk.clone()).map_err(|_| invalid())?;
    let key = DecodingKey::from_jwk(&typed).map_err(|_| invalid())?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<Claims>(raw, &key, &validation)
        .map_err(|_| invalid())?
        .claims;
    if !valid_nonce(&claims.nonce) {
        return Err(fail(StatusCode::UNAUTHORIZED, "use_dpop_nonce"));
    }
    if claims.htm != method
        || claims.htu != format!("{}{path}", public_url(a))
        || claims.iat.abs_diff(now()) > 60
        || claims.jti.len() < 22
        || claims.jti.len() > 128
        || !claims
            .jti
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(invalid());
    }
    if claims.ath != access.map(|s| B64.encode(Sha256::digest(s.as_bytes()))) {
        return Err(invalid());
    }
    // RFC 7638: precisely the required public members, in lexicographic order.
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap()
    );
    let thumb = B64.encode(Sha256::digest(canonical.as_bytes()));
    if expected_thumb.is_some_and(|expected| !equal(expected, &thumb)) {
        return Err(invalid());
    }
    let db = a.db.lock().unwrap();
    db.execute("DELETE FROM client_replays WHERE expires<?", [now()])
        .map_err(anyhow::Error::from)?;
    if db
        .query_row("SELECT count(*) FROM client_replays", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(anyhow::Error::from)?
        > 10000
    {
        return Err(fail(
            StatusCode::TOO_MANY_REQUESTS,
            "Proof replay cache is full; retry later",
        ));
    }
    db.execute(
        "INSERT INTO client_replays(thumb,jti,expires) VALUES(?,?,?)",
        params![thumb, claims.jti, now() + 120],
    )
    .map_err(|_| invalid())?;
    Ok((jwk.clone(), thumb))
}
fn store(a: &App, n: &Enrollment) -> Result<()> {
    a.db.lock().unwrap().execute("INSERT INTO client_enrollments(id,request_hash,device_hash,code_hash,host_id,data) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET host_id=excluded.host_id,data=excluded.data",params![n.id,n.request_hash,n.device_hash,n.code_hash,n.host_id,serde_json::to_string(n).map_err(anyhow::Error::from)?]).map_err(anyhow::Error::from)?;
    Ok(())
}
fn rows(a: &App) -> Result<Vec<Enrollment>> {
    let db = a.db.lock().unwrap();
    let mut q = db
        .prepare("SELECT data FROM client_enrollments ORDER BY rowid DESC")
        .map_err(anyhow::Error::from)?;
    let values = q
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(anyhow::Error::from)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?;
    values
        .into_iter()
        .map(|s| {
            serde_json::from_str(&s)
                .map_err(anyhow::Error::from)
                .map_err(Error::from)
        })
        .collect()
}
fn code(n: &Enrollment) -> String {
    let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let bytes = Sha256::digest(derive("pairing", &n.id).as_bytes());
    let mut result = String::new();
    for (i, b) in bytes[..8].iter().enumerate() {
        if i == 4 {
            result.push('-');
        }
        result.push(alphabet[(b & 31) as usize] as char);
    }
    result
}
fn device(n: &Enrollment) -> String {
    derive("device", &n.id)
}
fn credential(n: &Enrollment) -> String {
    derive(
        "access",
        &format!("{}/{}/{}", n.id, n.thumbprint, n.generation),
    )
}
fn view(n: &Enrollment) -> Value {
    json!({"id":n.id,"identity":n.identity,"key_fingerprint":n.thumbprint,"state":if n.state=="pending"&&n.expires_at<=now(){"expired"}else{&n.state},"host_id":n.host_id,"created_at":n.created_at,"expires_at":n.expires_at,"enrolled_at":n.enrolled_at,"last_contact":n.last_contact})
}
fn validate_identity(i: &Identity) -> Result<()> {
    if !hosts::hostname(&i.hostname)
        || i.fqdn.as_ref().is_some_and(|s| !hosts::hostname(s))
        || i.addresses.len() > 32
        || i.capabilities.len() > 8
    {
        return Err(bad("Invalid machine identity"));
    }
    for s in [
        &i.os,
        &i.os_version,
        &i.kernel,
        &i.architecture,
        &i.client_version,
    ]
    .into_iter()
    .chain(i.capabilities.iter())
    {
        if s.len() > 100 || s.is_empty() || s.chars().any(char::is_control) {
            return Err(bad("Invalid bounded machine identity field"));
        }
    }
    for addr in &i.addresses {
        if addr.interface.is_empty()
            || addr.interface.len() > 32
            || !addr
                .interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || addr.address.is_unspecified()
            || addr.address.is_multicast()
            || addr.address.is_loopback()
        {
            return Err(bad("Invalid reported network address"));
        }
    }
    Ok(())
}
pub(super) async fn info(State(a): State<App>) -> Result<Json<Value>> {
    let instance: String =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key='client_instance_id'",
                [],
                |r| r.get(0),
            )
            .map_err(anyhow::Error::from)?;
    Ok(Json(
        json!({"api_version":1,"instance_id":serde_json::from_str::<String>(&instance).map_err(anyhow::Error::from)?,"name":config(&a).and_then(|d|d["name"].as_str().map(str::to_owned)),"url":public_url(&a),"pairing_lifetime":LIFETIME,"capabilities":["enrollment-v1","session-v1","inventory-v1"]}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Start {
    api_version: u8,
    request_id: String,
    identity: Identity,
}
fn grant(n: &Enrollment, a: &App) -> Value {
    json!({"api_version":1,"enrollment_id":n.id,"device_code":device(n),"user_code":code(n),"verification_uri":public_url(a),"expires_at":n.expires_at,"expires_in":(n.expires_at-now()).max(0),"interval":5,"key_fingerprint":n.thumbprint})
}
pub(super) async fn start(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Start>,
) -> Result<Json<Value>> {
    if operations::recovery(&a)? {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Complete recovery review before enrolling clients",
        ));
    }
    rate(&a, "start", 30)?;
    if p.api_version != 1
        || p.request_id.len() != 64
        || !p.request_id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(bad("Unsupported API version or invalid request ID"));
    }
    validate_identity(&p.identity)?;
    let (jwk, thumbprint) = proof(&a, &h, "POST", &format!("{PREFIX}/enrollments"), None, None)?;
    let _gate = a.gate.lock().await;
    let existing = rows(&a)?;
    if let Some(n) = existing
        .iter()
        .find(|n| n.request_hash == digest(&p.request_id))
    {
        if n.thumbprint != thumbprint {
            return Err(unauthorized());
        }
        if n.expires_at <= now() || !["pending", "approved", "active"].contains(&n.state.as_str()) {
            return Err(fail(StatusCode::GONE, "expired_token"));
        }
        return Ok(Json(grant(n, &a)));
    }
    if existing
        .iter()
        .filter(|n| n.state == "pending" && n.expires_at > now())
        .count()
        >= 64
    {
        return Err(fail(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many pending machines; wait for pending pairing requests to expire",
        ));
    }
    if existing
        .iter()
        .any(|n| n.thumbprint == thumbprint && ["active", "approved"].contains(&n.state.as_str()))
    {
        return Err(fail(
            StatusCode::CONFLICT,
            "This machine key is already enrolled",
        ));
    }
    rate(&a, &format!("key:{thumbprint}"), 3)?;
    a.db.lock().unwrap().execute("DELETE FROM client_enrollments WHERE host_id IS NULL AND json_extract(data,'$.expires_at')<?",[now()-86400]).map_err(anyhow::Error::from)?;
    let mut n = Enrollment {
        id: token()[..32].into(),
        request_hash: digest(&p.request_id),
        device_hash: String::new(),
        code_hash: String::new(),
        jwk,
        thumbprint,
        identity: p.identity,
        state: "pending".into(),
        host_id: None,
        created_at: now(),
        expires_at: now() + LIFETIME,
        last_poll: 0,
        enrolled_at: None,
        last_contact: None,
        generation: 1,
    };
    n.device_hash = digest(&device(&n));
    n.code_hash = digest(&code(&n));
    store(&a, &n)?;
    Ok(Json(grant(&n, &a)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Device {
    device_code: String,
}
fn pending(a: &App, h: &HeaderMap, id: &str, p: &Device, action: &str) -> Result<Enrollment> {
    if id.len() != 32 || p.device_code.len() != 43 {
        return Err(unauthorized());
    }
    let n = rows(a)?
        .into_iter()
        .find(|n| n.id == id && equal(&n.device_hash, &digest(&p.device_code)))
        .ok_or_else(unauthorized)?;
    if !["pending", "approved", "active", "cancelled"].contains(&n.state.as_str()) {
        return Err(fail(StatusCode::FORBIDDEN, "access_denied"));
    }
    proof(
        a,
        h,
        "POST",
        &format!("{PREFIX}/enrollments/{id}/{action}"),
        None,
        Some(&n.thumbprint),
    )?;
    if n.expires_at <= now() {
        return Err(fail(StatusCode::GONE, "expired_token"));
    }
    Ok(n)
}
pub(super) async fn poll(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Device>,
) -> Result<Json<Value>> {
    rate(&a, "poll", 1200)?;
    let _gate = a.gate.lock().await;
    let mut n = pending(&a, &h, &id, &p, "token")?;
    if !["pending", "approved", "active"].contains(&n.state.as_str()) {
        return Err(fail(StatusCode::FORBIDDEN, "access_denied"));
    }
    if n.last_poll > now() - 5 {
        return Err(fail(StatusCode::TOO_MANY_REQUESTS, "slow_down"));
    }
    n.last_poll = now();
    store(&a, &n)?;
    if n.state == "pending" {
        return Ok(Json(json!({"state":"authorization_pending"})));
    }
    Ok(Json(
        json!({"state":"approved","api_version":1,"host_id":n.host_id,"credential_id":n.id,"access_token":credential(&n),"token_type":"DPoP"}),
    ))
}
pub(super) async fn cancel(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Device>,
) -> Result<Json<Value>> {
    let _gate = a.gate.lock().await;
    rate(&a, "cancel", 60)?;
    let mut n = pending(&a, &h, &id, &p, "cancel")?;
    if n.state == "active" {
        return Err(bad("Use authenticated leave for an active machine"));
    }
    n.state = "cancelled".into();
    store(&a, &n)?;
    audit(&a, "machine", "client cancel pairing", &id)?;
    Ok(Json(json!({"cancelled":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Lookup {
    code: String,
}
pub(super) async fn lookup(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Lookup>,
) -> Result<Json<Value>> {
    admin(&a, &h, true).await?;
    rate(&a, "lookup", 20)?;
    if p.code.len() > 20 {
        return Err(bad("Invalid pairing code"));
    }
    let raw = p.code.trim().to_ascii_uppercase().replace('-', "");
    if raw.len() != 8
        || !raw
            .bytes()
            .all(|b| b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(&b))
    {
        return Err(bad("Enter the eight-character pairing code"));
    }
    let formatted = format!("{}-{}", &raw[..4], &raw[4..]);
    let n = rows(&a)?
        .into_iter()
        .find(|n| n.code_hash == digest(&formatted) && n.state == "pending" && n.expires_at > now())
        .ok_or(fail(
            StatusCode::NOT_FOUND,
            "Pairing code is invalid, expired or already used",
        ))?;
    Ok(Json(view(&n)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Approve {
    name: String,
    host_id: Option<String>,
    host_revision: Option<i64>,
    acknowledge: bool,
}
pub(super) async fn approve(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Approve>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    let _gate = a.gate.lock().await;
    let mut n = rows(&a)?
        .into_iter()
        .find(|n| n.id == id)
        .ok_or(fail(StatusCode::NOT_FOUND, "Pairing request not found"))?;
    if n.state != "pending" || n.expires_at <= now() {
        return Err(fail(
            StatusCode::CONFLICT,
            "Pairing code is expired or already used",
        ));
    }
    if !p.acknowledge {
        return Err(bad("Confirm the machine identity before approval"));
    }
    let hosts = hosts::list(&a)?;
    let host = if let Some(host_id) = p.host_id {
        let host = hosts
            .iter()
            .find(|h| h.id == host_id)
            .cloned()
            .ok_or(bad("Existing host not found"))?;
        if p.host_revision != Some(host.revision) {
            return Err(fail(
                StatusCode::CONFLICT,
                "Host changed; refresh before linking",
            ));
        }
        if rows(&a)?.iter().any(|n| {
            n.host_id.as_ref() == Some(&host_id)
                && ["active", "approved"].contains(&n.state.as_str())
        }) {
            return Err(bad(
                "Revoke the host's existing client identity before linking another",
            ));
        }
        host
    } else {
        if p.name.trim().is_empty() || p.name.len() > 100 || p.name.chars().any(char::is_control) {
            return Err(bad("Provide a friendly host name"));
        }
        if hosts
            .iter()
            .any(|h| h.draft.hostname == n.identity.hostname)
        {
            return Err(fail(
                StatusCode::CONFLICT,
                "A host with this hostname exists. Explicitly link that inventory record instead.",
            ));
        }
        let endpoints = hosts
            .iter()
            .find(|h| h.directory_id.as_deref() == Some("primary"))
            .map(|h| h.draft.endpoints.clone())
            .ok_or(bad("Primary directory inventory is unavailable"))?;
        hosts::Host {
            id: token()[..32].into(),
            directory_id: None,
            directory_role: None,
            draft: hosts::HostDraft {
                name: p.name,
                hostname: n.identity.hostname.clone(),
                endpoints,
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
        }
    };
    n.host_id = Some(host.id.clone());
    n.state = "approved".into();
    n.enrolled_at = Some(now());
    // Inventory and approval commit together; no LDAP/DNS write or permission grant.
    {
        let mut db = a.db.lock().unwrap();
        let tx = db.transaction().map_err(anyhow::Error::from)?;
        tx.execute(
            "INSERT OR IGNORE INTO hosts(id,hostname,data) VALUES(?,?,?)",
            params![
                host.id,
                host.draft.hostname,
                serde_json::to_string(&host).map_err(anyhow::Error::from)?
            ],
        )
        .map_err(anyhow::Error::from)?;
        tx.execute(
            "UPDATE client_enrollments SET host_id=?,data=? WHERE id=?",
            params![
                n.host_id,
                serde_json::to_string(&n).map_err(anyhow::Error::from)?,
                n.id
            ],
        )
        .map_err(anyhow::Error::from)?;
        tx.commit().map_err(anyhow::Error::from)?;
    }
    audit(&a, &who, "client approve enrollment", &host.id)?;
    Ok(Json(view(&n)))
}
fn by_host(a: &App, id: &str) -> Result<Vec<Enrollment>> {
    let db = a.db.lock().unwrap();
    let mut query = db
        .prepare("SELECT data FROM client_enrollments WHERE host_id=? ORDER BY rowid DESC")
        .map_err(anyhow::Error::from)?;
    let values = query
        .query_map([id], |r| r.get::<_, String>(0))
        .map_err(anyhow::Error::from)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?;
    values
        .into_iter()
        .map(|value| {
            serde_json::from_str(&value)
                .map_err(anyhow::Error::from)
                .map_err(Error::from)
        })
        .collect()
}
fn authenticate(a: &App, h: &HeaderMap, id: &str, action: &str) -> Result<Enrollment> {
    rate(a, "machine-auth", 1200)?;
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(unauthorized());
    }
    let access = h
        .get(header::AUTHORIZATION)
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.strip_prefix("DPoP "))
        .filter(|s| s.len() == 43)
        .ok_or_else(unauthorized)?;
    let n = by_host(a, id)?
        .into_iter()
        .find(|n| {
            ["approved", "active"].contains(&n.state.as_str()) && equal(&credential(n), access)
        })
        .ok_or_else(unauthorized)?;
    proof(
        a,
        h,
        "POST",
        &format!("{PREFIX}/hosts/{id}/{action}"),
        Some(access),
        Some(&n.thumbprint),
    )?;
    Ok(n)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Empty {}
pub(super) async fn session(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(_): Json<Empty>,
) -> Result<Json<Value>> {
    let _gate = a.gate.lock().await;
    let mut n = authenticate(&a, &h, &id, "session")?;
    rate(&a, &format!("session:{}", n.id), 30)?;
    hosts::load(&a, &id)?;
    if n.state == "approved" {
        audit(&a, "machine", "client confirm enrollment", &id)?;
    }
    n.state = "active".into();
    n.last_contact = Some(now());
    store(&a, &n)?;
    Ok(Json(
        json!({"api_version":1,"host_id":id,"server_time":now(),"enrollment":"active"}),
    ))
}
pub(super) async fn leave(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(_): Json<Empty>,
) -> Result<Json<Value>> {
    let _gate = a.gate.lock().await;
    let mut n = authenticate(&a, &h, &id, "leave")?;
    n.state = "revoked".into();
    store(&a, &n)?;
    audit(&a, "machine", "client leave", &id)?;
    Ok(Json(json!({"revoked":true,"host_retained":true})))
}
pub(super) async fn index(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    Ok(Json(
        json!({"enrollments":rows(&a)?.iter().filter(|n|n.host_id.is_some()||n.expires_at>now()).take(128).map(view).collect::<Vec<_>>()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Revoke {
    acknowledge: bool,
}
pub(super) async fn revoke(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Revoke>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    if !p.acknowledge {
        return Err(bad("Confirm revoking this client identity"));
    }
    let _gate = a.gate.lock().await;
    let mut n = rows(&a)?
        .into_iter()
        .find(|n| n.id == id)
        .ok_or(fail(StatusCode::NOT_FOUND, "Client identity not found"))?;
    n.state = "revoked".into();
    store(&a, &n)?;
    audit(
        &a,
        &who,
        "client revoke",
        n.host_id.as_deref().unwrap_or(&n.id),
    )?;
    Ok(Json(json!({"revoked":true,"host_retained":true})))
}
pub(super) fn summary(a: &App, id: &str) -> Result<Option<Value>> {
    by_host(a, id)?
        .into_iter()
        .filter(|n| n.host_id.as_deref() == Some(id))
        .max_by_key(|n| {
            (
                ["approved", "active"].contains(&n.state.as_str()),
                n.enrolled_at.unwrap_or(0),
                n.created_at,
            )
        })
        .map(|n| {
            let mut v = view(&n);
            v["monitoring"] = monitoring::summary(a, &n)?;
            Ok::<Value, Error>(v)
        })
        .transpose()
}
pub(super) fn revoke_host(a: &App, id: &str) -> Result<()> {
    for mut n in by_host(a, id)?
        .into_iter()
        .filter(|n| n.host_id.as_deref() == Some(id))
    {
        n.state = "revoked".into();
        store(a, &n)?;
    }
    Ok(())
}
