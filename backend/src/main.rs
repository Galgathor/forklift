mod clients;
mod discovery;
mod dns;
mod hosts;
mod maintenance;
mod network;
mod operations;
mod port_checks;
mod replica_setup;
mod replicas;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use ldap3::{Ldap, LdapConnAsync, Mod, Scope, SearchEntry};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::services::{ServeDir, ServeFile};
#[derive(Clone)]
struct App {
    db: Arc<Mutex<maintenance::Database>>,
    url: Arc<std::sync::RwLock<String>>,
    jobs: Arc<maintenance::Jobs>,
    configured: Arc<std::sync::atomic::AtomicBool>,
    gate: Arc<tokio::sync::Mutex<()>>,
    directory_restart: Arc<tokio::sync::RwLock<()>>,
}
type Result<T> = std::result::Result<T, Error>;
struct Error(StatusCode, String);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<ldap3::LdapError> for Error {
    fn from(e: ldap3::LdapError) -> Self {
        anyhow::Error::from(e).into()
    }
}
fn bad(s: &str) -> Error {
    Error(StatusCode::BAD_REQUEST, s.into())
}
fn unauthorized() -> Error {
    Error(StatusCode::UNAUTHORIZED, "Authentication required".into())
}
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        eprintln!("operation failed: {}", e);
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Directory or storage operation failed. Check server logs and TLS connectivity.".into(),
        )
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}
fn digest(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}
fn secret(s: &str) -> String {
    std::fs::read_to_string(format!("/run/secrets/{s}"))
        .expect("missing installation secret")
        .trim()
        .into()
}
fn valid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
fn base_valid(s: &str) -> bool {
    if s.len() > 255 {
        return false;
    }
    let v: Vec<_> = s.split(',').collect();
    v.len() >= 2
        && v.iter().all(|s| {
            s.strip_prefix("dc=").is_some_and(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        })
}
fn config(a: &App) -> Option<Value> {
    a.db.lock()
        .unwrap()
        .0
        .as_ref()?
        .query_row(
            "SELECT value FROM settings WHERE key='directory'",
            [],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}
fn base(a: &App) -> Result<String> {
    config(a)
        .and_then(|v| v["base"].as_str().map(str::to_owned))
        .ok_or(bad("Setup required"))
}
async fn connect() -> anyhow::Result<Ldap> {
    let (conn, ldap) = LdapConnAsync::with_settings(
        ldap3::LdapConnSettings::new().set_conn_timeout(std::time::Duration::from_secs(5)),
        "ldapi://%2Frun%2Fldap-socket%2Fldap.sock",
    )
    .await?;
    ldap3::drive!(conn);
    let mut ldap = ldap;
    ldap.with_timeout(std::time::Duration::from_secs(5));
    Ok(ldap)
}
async fn service(a: &App) -> anyhow::Result<Ldap> {
    let mut l = connect().await?;
    let b = base(a).map_err(|_| anyhow::anyhow!("setup required"))?;
    if dns::peer::directory::local_sid(a)
        .map_err(|e| anyhow::anyhow!(e.1))?
        .is_some_and(|sid| sid > 1)
    {
        l.sasl_external_bind().await?.success()?;
    } else {
        l.simple_bind(&format!("cn=manager,{b}"), &secret("service"))
            .await?
            .success()?;
    }
    Ok(l)
}
async fn read_service(a: &App) -> anyhow::Result<(Ldap, bool)> {
    match service(a).await {
        Ok(l) => Ok((l, true)),
        Err(_) => Ok((replicas::fallback(a).await?, false)),
    }
}
async fn search(l: &mut Ldap, b: &str, f: &str) -> anyhow::Result<Vec<Value>> {
    l.with_timeout(std::time::Duration::from_secs(5));
    let (rs, _) = l
        .search(
            b,
            Scope::OneLevel,
            f,
            vec![
                "uid",
                "cn",
                "sn",
                "mail",
                "description",
                "uidNumber",
                "gidNumber",
                "homeDirectory",
                "loginShell",
                "shadowExpire",
                "memberUid",
                "createTimestamp",
                "modifyTimestamp",
            ],
        )
        .await?
        .success()?;
    Ok(rs
        .into_iter()
        .map(|r| {
            let e = SearchEntry::construct(r);
            json!({"dn":e.dn,"attrs":e.attrs})
        })
        .collect())
}
fn attrs(v: &Value, k: &str) -> String {
    v["attrs"][k][0].as_str().unwrap_or("").into()
}
fn public_url(a: &App) -> String {
    a.url.read().unwrap().clone()
}
fn valid_public_url(raw: &str) -> bool {
    if raw.len() > 2048 {
        return false;
    }
    reqwest::Url::parse(raw).is_ok_and(|url| {
        ["http", "https"].contains(&url.scheme())
            && url.host_str().is_some()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && raw.trim_end_matches('/') == url.origin().ascii_serialization()
    })
}
fn request_origin(h: &HeaderMap) -> Result<String> {
    let value = h
        .get("origin")
        .and_then(|s| s.to_str().ok())
        .ok_or(bad("A browser origin is required"))?;
    if !valid_public_url(value) {
        return Err(bad("Use an HTTP(S) origin without a path or credentials"));
    }
    Ok(value.into())
}
fn bootstrap(a: &App, h: &HeaderMap, raw: &str) -> Result<()> {
    if config(a).is_some() {
        return Err(bad("Already configured"));
    }
    if digest(raw) != digest(&secret("bootstrap")) {
        return Err(unauthorized());
    }
    request_origin(h)?;
    Ok(())
}
#[derive(Deserialize)]
struct Inspect {
    token: String,
}
async fn inspect_setup(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Inspect>,
) -> Result<Json<Value>> {
    bootstrap(&a, &h, &p.token)?;
    Ok(Json(
        maintenance::local("/inspect", Some(&json!({}))).await?,
    ))
}
fn origin(a: &App, h: &HeaderMap) -> Result<()> {
    if h.get("origin").and_then(|s| s.to_str().ok()) != Some(public_url(a).as_str()) {
        return Err(Error(StatusCode::FORBIDDEN, "Origin rejected".into()));
    }
    Ok(())
}
async fn admin(a: &App, h: &HeaderMap, write: bool) -> Result<String> {
    let raw = h
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .find_map(|s| s.trim().strip_prefix("forklift_session="))
        .ok_or(unauthorized())?;
    let session =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT username,csrf FROM sessions WHERE id=? AND expires>?",
                params![digest(raw), now()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .map_err(|_| unauthorized())?;
    if write {
        origin(a, h)?;
        if h.get("x-csrf-token").and_then(|v| v.to_str().ok()) != Some(&session.1) {
            return Err(Error(StatusCode::FORBIDDEN, "CSRF token rejected".into()));
        }
    }
    if write && operations::recovery(a)? {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Recovery review is required before administrative writes".into(),
        ));
    }
    let mut l = if write {
        service(a).await?
    } else {
        read_service(a).await?.0
    };
    let b = base(a)?;
    let groups = search(
        &mut l,
        &format!("ou=groups,{b}"),
        &format!("(&(cn=administrators)(memberUid={}))", session.0),
    )
    .await?;
    let users = search(
        &mut l,
        &format!("ou=people,{b}"),
        &format!("(uid={})", session.0),
    )
    .await?;
    if groups.is_empty() || users.is_empty() || attrs(&users[0], "shadowExpire") == "1" {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Administrator access required".into(),
        ));
    }
    Ok(session.0)
}
fn audit(a: &App, who: &str, action: &str, target: &str) -> Result<()> {
    a.db.lock()
        .unwrap()
        .execute(
            "INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)",
            params![now(), who, action, target],
        )
        .map_err(anyhow::Error::from)?;
    Ok(())
}
async fn health() -> Json<Value> {
    Json(json!({"status":"ok"}))
}
async fn ready(State(a): State<App>) -> Result<Json<Value>> {
    if a.jobs.active.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Directory maintenance is active".into(),
        ));
    }
    let _lease = a.jobs.lease.read().await;
    let _directory = a.directory_restart.read().await;
    if a.jobs.active.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Directory maintenance is active".into(),
        ));
    }
    if config(&a).is_some() {
        let mut l = service(&a).await?;
        l.search(&base(&a)?, Scope::Base, "(objectClass=*)", vec!["dc"])
            .await?
            .success()?;
    }
    a.db.lock()
        .unwrap()
        .execute_batch("SELECT 1")
        .map_err(anyhow::Error::from)?;
    Ok(Json(
        json!({"ready": true, "configured": config(&a).is_some()}),
    ))
}
async fn status(State(a): State<App>) -> Json<Value> {
    Json(
        json!({"configured":a.configured.load(std::sync::atomic::Ordering::SeqCst),"maintenance":a.jobs.active.load(std::sync::atomic::Ordering::SeqCst),"maintenance_bootstrap":a.jobs.ticket.read().unwrap().as_ref().is_some_and(|t|t.bootstrap),"public_url":public_url(&a),"version":env!("CARGO_PKG_VERSION")}),
    )
}
#[derive(Deserialize)]
struct Setup {
    network: Value,
    public_url: String,
    token: String,
    name: String,
    base: String,
    username: String,
    password: String,
}
async fn setup(State(a): State<App>, h: HeaderMap, Json(p): Json<Setup>) -> Result<Json<Value>> {
    bootstrap(&a, &h, &p.token)?;
    if !valid_public_url(&p.public_url) || request_origin(&h)? != p.public_url {
        return Err(bad("Use the current browser origin as the public URL"));
    }
    let _guard = a.gate.lock().await;
    if config(&a).is_some() {
        return Err(bad("Already configured"));
    }
    if digest(&p.token) != digest(&secret("bootstrap")) {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Invalid bootstrap token".into(),
        ));
    }
    if !valid(&p.username)
        || !base_valid(&p.base)
        || p.password.len() < 14
        || p.password.len() > 1024
        || p.name.trim().is_empty()
        || p.name.len() > 100
    {
        return Err(bad(
            "Use a valid username, dc-based base DN, directory name and password of at least 14 characters",
        ));
    }
    let readiness = maintenance::local("/inspect", Some(&json!({}))).await?;
    let joining: bool =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM settings WHERE key='directory_join_pending')",
                [],
                |r| r.get(0),
            )
            .map_err(anyhow::Error::from)?;
    if joining {
        return Err(bad("Resume the existing directory pairing"));
    }
    let pending =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key='setup_pending'",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok();
    if readiness["initialized"] == true && pending.is_none() {
        return Err(bad(
            "Directory data exists without matching metadata. Restore a complete backup instead of resetting ID allocation.",
        ));
    }
    if let Some(pending) = pending {
        let previous: Value = serde_json::from_str(&pending).map_err(anyhow::Error::from)?;
        if previous["base"] != p.base || previous["username"] != p.username {
            return Err(bad(
                "Retry interrupted setup with its original base DN and administrator identity",
            ));
        }
    }
    dns::check_setup().await?;
    a.db.lock()
        .unwrap()
        .execute(
            "INSERT INTO settings VALUES('setup_pending',?) ON CONFLICT(key) DO NOTHING",
            [json!({"base":p.base,"username":p.username}).to_string()],
        )
        .map_err(anyhow::Error::from)?;
    let network = maintenance::local("/configure", Some(&p.network)).await?;
    maintenance::directory(
        "/initialize",
        &json!({"base":p.base,"username":p.username,"password":p.password}),
    )
    .await?;
    let mut l = connect().await?;
    l.simple_bind(
        &format!("uid={},ou=people,{}", p.username, p.base),
        &p.password,
    )
    .await?
    .success()?;
    if search(
        &mut l,
        &format!("ou=groups,{}", p.base),
        &format!("(&(cn=administrators)(memberUid={}))", p.username),
    )
    .await?
    .is_empty()
    {
        return Err(bad(
            "Use the original directory administrator to complete setup",
        ));
    }
    dns::check_setup().await?;
    let value = json!({"name":p.name,"base":p.base,"network":network});
    {
        let mut db = a.db.lock().unwrap();
        let tx = db.transaction().map_err(anyhow::Error::from)?;
        tx.execute(
            "INSERT INTO settings(key,value) VALUES('directory',?)",
            [value.to_string()],
        )
        .map_err(anyhow::Error::from)?;
        tx.execute(
            "INSERT INTO settings VALUES('public_url',?)",
            [json!(p.public_url).to_string()],
        )
        .map_err(anyhow::Error::from)?;
        tx.execute("DELETE FROM settings WHERE key='setup_pending'", [])
            .map_err(anyhow::Error::from)?;
        tx.commit().map_err(anyhow::Error::from)?;
    }
    *a.url.write().unwrap() = p.public_url;
    hosts::sync_directory(
        &a,
        "primary",
        "Primary directory",
        network["hostname"].as_str().unwrap_or(""),
        "primary",
    )?;
    a.configured
        .store(true, std::sync::atomic::Ordering::SeqCst);
    audit(&a, &p.username, "setup", "directory")?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}
async fn login(State(a): State<App>, h: HeaderMap, Json(p): Json<Login>) -> Result<Response> {
    origin(&a, &h)?;
    if !valid(&p.username) || p.password.is_empty() || p.password.len() > 1024 {
        return Err(unauthorized());
    }
    {
        let db = a.db.lock().unwrap();
        let n: i64 = db
            .query_row(
                "SELECT count(*) FROM attempts WHERE at>?",
                [now() - 300],
                |r| r.get(0),
            )
            .map_err(anyhow::Error::from)?;
        if n >= 20 {
            return Err(Error(
                StatusCode::TOO_MANY_REQUESTS,
                "Login rate limit reached; wait five minutes".into(),
            ));
        }
        let account: i64 = db
            .query_row(
                "SELECT count(*) FROM attempts WHERE at>? AND username=?",
                params![now() - 300, p.username],
                |r| r.get(0),
            )
            .map_err(anyhow::Error::from)?;
        if account >= 10 {
            return Err(Error(
                StatusCode::TOO_MANY_REQUESTS,
                "Account login rate limit reached; wait five minutes".into(),
            ));
        }
        db.execute(
            "INSERT INTO attempts(at,username) VALUES(?,?)",
            params![now(), p.username],
        )
        .map_err(anyhow::Error::from)?;
        db.execute("DELETE FROM attempts WHERE at<?", [now() - 300])
            .map_err(anyhow::Error::from)?;
    }
    let b = base(&a)?;
    let (mut l, primary_available) = read_service(&a).await?;
    l.with_timeout(std::time::Duration::from_secs(5));
    if l.simple_bind(&format!("uid={},ou=people,{b}", p.username), &p.password)
        .await?
        .success()
        .is_err()
    {
        audit(&a, &p.username, "failed login", "credentials")?;
        return Err(unauthorized());
    }
    let u = search(
        &mut l,
        &format!("ou=people,{b}"),
        &format!("(uid={})", p.username),
    )
    .await?;
    let g = search(
        &mut l,
        &format!("ou=groups,{b}"),
        &format!("(&(cn=administrators)(memberUid={}))", p.username),
    )
    .await?;
    if u.is_empty() || g.is_empty() || attrs(&u[0], "shadowExpire") == "1" {
        audit(&a, &p.username, "failed login", "authorization")?;
        return Err(unauthorized());
    }
    let raw = token();
    let csrf = token();
    {
        let db = a.db.lock().unwrap();
        db.execute("DELETE FROM sessions WHERE expires<?", [now()])
            .map_err(anyhow::Error::from)?;
        db.execute(
            "INSERT INTO sessions VALUES(?,?,?,?)",
            params![digest(&raw), p.username, csrf, now() + 28800],
        )
        .map_err(anyhow::Error::from)?;
    }
    audit(&a, &p.username, "login", "session")?;
    let cookie = format!(
        "forklift_session={raw}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800{}",
        if public_url(&a).starts_with("https://") {
            "; Secure"
        } else {
            ""
        }
    );
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(json!({"csrf":csrf,"username":p.username,"read_only":!primary_available})),
    )
        .into_response())
}
async fn me(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let u = admin(&a, &h, false).await?;
    let db = a.db.lock().unwrap();
    let csrf: String = db
        .query_row(
            "SELECT csrf FROM sessions WHERE username=? AND id=?",
            params![
                u,
                digest(
                    h.get(header::COOKIE)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .split(';')
                        .find_map(|v| v.trim().strip_prefix("forklift_session="))
                        .unwrap()
                )
            ],
            |r| r.get(0),
        )
        .map_err(anyhow::Error::from)?;
    Ok(Json(json!({"username":u,"csrf":csrf})))
}
async fn logout(State(a): State<App>, h: HeaderMap) -> Result<Response> {
    origin(&a, &h)?;
    let raw_session = h
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';')
                .find_map(|s| s.trim().strip_prefix("forklift_session="))
        })
        .ok_or(unauthorized())?;
    let csrf =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT csrf FROM sessions WHERE id=? AND expires>?",
                params![digest(raw_session), now()],
                |r| r.get::<_, String>(0),
            )
            .map_err(|_| unauthorized())?;
    if h.get("x-csrf-token").and_then(|v| v.to_str().ok()) != Some(csrf.as_str()) {
        return Err(Error(StatusCode::FORBIDDEN, "CSRF token rejected".into()));
    }
    if let Some(raw) = h
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';')
                .find_map(|s| s.trim().strip_prefix("forklift_session="))
        })
    {
        a.db.lock()
            .unwrap()
            .execute("DELETE FROM sessions WHERE id=?", [digest(raw)])
            .map_err(anyhow::Error::from)?;
    }
    Ok((
        [(
            header::SET_COOKIE,
            "forklift_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
        Json(json!({"ok":true})),
    )
        .into_response())
}
async fn overview(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    let (mut l, primary_available) = read_service(&a).await?;
    let b = base(&a)?;
    let users = search(
        &mut l,
        &format!("ou=people,{b}"),
        "(objectClass=posixAccount)",
    )
    .await?;
    let groups = search(
        &mut l,
        &format!("ou=groups,{b}"),
        "(objectClass=posixGroup)",
    )
    .await?;
    let events = {
        let db = a.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT at,actor,action,target FROM audit ORDER BY id DESC LIMIT 30")
            .map_err(anyhow::Error::from)?;
        stmt.query_map([],|r|Ok(json!({"at":r.get::<_,i64>(0)?,"actor":r.get::<_,String>(1)?,"action":r.get::<_,String>(2)?,"target":r.get::<_,String>(3)?}))).map_err(anyhow::Error::from)?.collect::<std::result::Result<Vec<_>,_>>().map_err(anyhow::Error::from)?
    };
    Ok(Json(
        json!({"directory":config(&a),"users":users,"groups":groups,"events":events,"ldap":"connected","read_only":!primary_available||operations::recovery(&a)?,"read_only_reason":if operations::recovery(&a)?{Some("recovery_review")}else if !primary_available{Some("primary_unavailable")}else{None},"directory_source":if primary_available{"primary"}else{"replica"},"directory_servers":replicas::health(&a).await?,"hosts":hosts::list(&a)?}),
    ))
}
#[derive(Deserialize)]
struct User {
    username: String,
    display_name: String,
    email: String,
    description: String,
    shell: String,
    home: String,
    gid: i64,
    password: Option<String>,
    disabled: bool,
}
fn user_check(p: &User) -> Result<()> {
    if !valid(&p.username)
        || p.display_name.trim().is_empty()
        || p.display_name.len() > 128
        || p.email.len() > 254
        || p.description.len() > 1024
        || !["/bin/bash", "/bin/sh", "/usr/sbin/nologin"].contains(&p.shell.as_str())
        || !p.home.starts_with('/')
        || p.home.len() > 256
        || p.gid < 10000
    {
        return Err(bad("Invalid account attributes"));
    }
    if p.password
        .as_ref()
        .is_some_and(|v| v.len() < 14 || v.len() > 1024)
    {
        return Err(bad("Password must contain 14–1024 characters"));
    }
    Ok(())
}
async fn password(l: &mut Ldap, dn: &str, p: &str) -> anyhow::Result<()> {
    l.extended(ldap3::exop::PasswordModify {
        user_id: Some(dn),
        old_pass: None,
        new_pass: Some(p),
    })
    .await?
    .success()?;
    Ok(())
}
fn next_id(a: &App) -> Result<i64> {
    let db = a.db.lock().unwrap();
    let bound: Option<i64> = db
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM settings WHERE key='directory_allocator_max'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(anyhow::Error::from)?;
    if db
        .execute(
            "UPDATE allocator SET value=value+1 WHERE value < coalesce(?,2147483647)",
            [bound],
        )
        .map_err(anyhow::Error::from)?
        != 1
    {
        return Err(bad("This directory node has used all its Unix IDs"));
    }
    Ok(db
        .query_row("SELECT value FROM allocator", [], |r| r.get(0))
        .map_err(anyhow::Error::from)?)
}
async fn save_user(State(a): State<App>, h: HeaderMap, Json(p): Json<User>) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    user_check(&p)?;
    let _guard = a.gate.lock().await;
    let mut l = service(&a).await?;
    let b = base(&a)?;
    let dn = format!("uid={},ou=people,{b}", p.username);
    let existing = search(
        &mut l,
        &format!("ou=people,{b}"),
        &format!("(uid={})", p.username),
    )
    .await?;
    if existing
        .first()
        .is_some_and(|u| attrs(u, "shadowExpire") == "1")
        && !p.disabled
        && p.password.is_none()
    {
        return Err(bad("Set a new password when enabling a disabled account"));
    }
    if p.username == who && p.disabled {
        return Err(bad("Cannot disable your current administrator"));
    }
    let groups = search(
        &mut l,
        &format!("ou=groups,{b}"),
        &format!("(gidNumber={})", p.gid),
    )
    .await?;
    if groups.is_empty() {
        return Err(bad("Select an existing primary group"));
    }
    let fields = vec![
        ("cn", p.display_name.clone()),
        ("sn", p.display_name.clone()),
        ("mail", p.email.clone()),
        ("description", p.description.clone()),
        ("homeDirectory", p.home.clone()),
        ("loginShell", p.shell.clone()),
        ("gidNumber", p.gid.to_string()),
        ("shadowExpire", if p.disabled { "1" } else { "-1" }.into()),
    ];
    audit(&a, &who, "attempt save user", &p.username)?;
    if existing.is_empty() {
        if p.password.is_none() {
            return Err(bad("Password required"));
        }
        let uid = next_id(&a)?;
        let mut add: Vec<(String, HashSet<String>)> = fields
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k.to_string(), HashSet::from([v.clone()])))
            .collect();
        add.extend([
            (
                "objectClass".to_string(),
                HashSet::from([
                    "inetOrgPerson".into(),
                    "posixAccount".into(),
                    "shadowAccount".into(),
                ]),
            ),
            ("uid".to_string(), HashSet::from([p.username.clone()])),
            ("uidNumber".to_string(), HashSet::from([uid.to_string()])),
        ]);
        l.add(&dn, add).await?.success()?;
    } else {
        let mods = fields
            .into_iter()
            .map(|(k, v)| {
                Mod::Replace(
                    k.to_string(),
                    if v.is_empty() {
                        HashSet::new()
                    } else {
                        HashSet::from([v])
                    },
                )
            })
            .collect();
        l.modify(&dn, mods).await?.success()?;
    }
    let revoke_sessions = p.password.is_some() || p.disabled;
    if let Some(pw) = p.password {
        password(&mut l, &dn, &pw).await?;
    }
    // shadowExpire is consumed by SSSD; removing userPassword also prevents direct LDAP binds.
    if p.disabled {
        l.modify(
            &dn,
            vec![Mod::Replace(
                "userPassword".to_string(),
                HashSet::<String>::new(),
            )],
        )
        .await?
        .success()?;
    }
    if revoke_sessions {
        a.db.lock()
            .unwrap()
            .execute("DELETE FROM sessions WHERE username=?", [&p.username])
            .map_err(anyhow::Error::from)?;
    }
    audit(&a, &who, "save user", &p.username)?;
    Ok(Json(json!({"ok":true})))
}
async fn delete_user(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    if !valid(&id) || id == who {
        return Err(bad("Cannot delete this account"));
    }
    let _guard = a.gate.lock().await;
    let mut l = service(&a).await?;
    let b = base(&a)?;
    let groups = search(
        &mut l,
        &format!("ou=groups,{b}"),
        &format!("(memberUid={id})"),
    )
    .await?;
    audit(&a, &who, "attempt delete user", &id)?;
    for g in groups {
        l.modify(
            g["dn"].as_str().unwrap(),
            vec![Mod::Delete(
                "memberUid".to_string(),
                HashSet::from([id.clone()]),
            )],
        )
        .await?
        .success()?;
    }
    l.delete(&format!("uid={id},ou=people,{b}"))
        .await?
        .success()?;
    a.db.lock()
        .unwrap()
        .execute("DELETE FROM sessions WHERE username=?", [&id])
        .map_err(anyhow::Error::from)?;
    audit(&a, &who, "delete user", &id)?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
struct Group {
    name: String,
    members: Vec<String>,
}
async fn save_group(
    State(a): State<App>,
    h: HeaderMap,
    Path(old): Path<String>,
    Json(p): Json<Group>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    if !valid(&old)
        || !valid(&p.name)
        || p.members.iter().any(|u| !valid(u))
        || p.members.len() > 10000
    {
        return Err(bad("Invalid group or members"));
    }
    let _guard = a.gate.lock().await;
    let mut l = service(&a).await?;
    let b = base(&a)?;
    if old == "administrators" && (p.name != old || !p.members.contains(&who)) {
        return Err(bad("Keep the administrator group and your own membership"));
    }
    for u in &p.members {
        if search(&mut l, &format!("ou=people,{b}"), &format!("(uid={u})"))
            .await?
            .is_empty()
        {
            return Err(bad("Unknown group member"));
        }
    }
    if old != p.name && hosts::group_in_use(&a, &old)? {
        return Err(bad(
            "Group is referenced by host access rules; update the hosts before renaming it",
        ));
    }
    let dn = format!("cn={old},ou=groups,{b}");
    let exists = search(&mut l, &format!("ou=groups,{b}"), &format!("(cn={old})")).await?;
    audit(&a, &who, "attempt save group", &p.name)?;
    if exists.is_empty() {
        let gid = next_id(&a)?;
        let mut fields = vec![
            (
                "objectClass".to_string(),
                HashSet::from(["posixGroup".to_string()]),
            ),
            ("cn".to_string(), HashSet::from([p.name.clone()])),
            ("gidNumber".to_string(), HashSet::from([gid.to_string()])),
        ];
        if !p.members.is_empty() {
            fields.push(("memberUid".to_string(), p.members.into_iter().collect()));
        }
        l.add(&format!("cn={},ou=groups,{b}", p.name), fields)
            .await?
            .success()?;
    } else {
        if old != p.name {
            l.modifydn(&dn, &format!("cn={}", p.name), true, None)
                .await?
                .success()?;
        }
        l.modify(
            &format!("cn={},ou=groups,{b}", p.name),
            vec![Mod::Replace(
                "memberUid".to_string(),
                p.members.into_iter().collect(),
            )],
        )
        .await?
        .success()?;
    }
    audit(&a, &who, "save group", &p.name)?;
    Ok(Json(json!({"ok":true})))
}
async fn delete_group(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    if !valid(&id) || id == "administrators" {
        return Err(bad("Cannot delete this group"));
    }
    let _guard = a.gate.lock().await;
    let mut l = service(&a).await?;
    let b = base(&a)?;
    let g = search(&mut l, &format!("ou=groups,{b}"), &format!("(cn={id})")).await?;
    if g.is_empty() {
        return Err(bad("Group not found"));
    }
    if !search(
        &mut l,
        &format!("ou=people,{b}"),
        &format!("(gidNumber={})", attrs(&g[0], "gidNumber")),
    )
    .await?
    .is_empty()
    {
        return Err(bad("Group is a primary group for existing users"));
    }
    if hosts::group_in_use(&a, &id)? {
        return Err(bad("Group is referenced by host access rules"));
    }
    audit(&a, &who, "attempt delete group", &id)?;
    l.delete(&format!("cn={id},ou=groups,{b}"))
        .await?
        .success()?;
    audit(&a, &who, "delete group", &id)?;
    Ok(Json(json!({"ok":true})))
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("publish-discovery") {
        return discovery::publish().await;
    }
    let initial_url = std::env::var("FORKLIFT_PUBLIC_URL")
        .unwrap_or("http://localhost:8080".into())
        .trim_end_matches('/')
        .to_owned();
    anyhow::ensure!(
        valid_public_url(&initial_url),
        "Invalid FORKLIFT_PUBLIC_URL"
    );
    let state = maintenance::local("/status", None)
        .await
        .map_err(|e| anyhow::anyhow!(e.1))?;
    let active = ["running", "needs_resume", "awaiting_ack"]
        .contains(&state["job"]["status"].as_str().unwrap_or(""));
    let mut db = maintenance::Database(None);
    if !active {
        let connection = Connection::open("/data/forklift.db")?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        anyhow::ensure!(
            version == 0 || version == 5,
            "Forklift 0.5 requires fresh storage; preserve old volumes and use the previous release for old backups"
        );
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,username TEXT NOT NULL,csrf TEXT NOT NULL,expires INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS attempts(at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL); CREATE TABLE IF NOT EXISTS allocator(value INTEGER NOT NULL); INSERT INTO allocator SELECT 10000 WHERE NOT EXISTS(SELECT 1 FROM allocator);")?;
        clients::migrate(&connection)?;
        hosts::migrate(&connection)?;
        replicas::migrate(&connection)?;
        operations::migrate(&connection)?;
        db = maintenance::Database(Some(connection));
    }
    let jobs = maintenance::Jobs::new(active);
    let url = if active {
        jobs.ticket
            .read()
            .unwrap()
            .as_ref()
            .map(|t| t.public_url.clone())
            .unwrap_or(initial_url)
    } else {
        db.query_row(
            "SELECT value FROM settings WHERE key='public_url'",
            [],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(initial_url)
    };
    let configured = if active {
        jobs.ticket
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|t| !t.bootstrap)
    } else {
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM settings WHERE key='directory')",
            [],
            |r| r.get::<_, bool>(0),
        )?
    };
    let a = App {
        db: Arc::new(Mutex::new(db)),
        url: Arc::new(std::sync::RwLock::new(url)),
        gate: Arc::new(tokio::sync::Mutex::new(())),
        directory_restart: Arc::new(tokio::sync::RwLock::new(())),
        jobs: Arc::new(jobs),
        configured: Arc::new(std::sync::atomic::AtomicBool::new(configured)),
    };
    if !active && let Some(directory) = config(&a) {
        hosts::sync_directory(
            &a,
            "primary",
            "Primary directory",
            directory["network"]["hostname"].as_str().unwrap_or(""),
            "primary",
        )
        .map_err(|e| anyhow::anyhow!(e.1))?;
        for node in replicas::records(&a).map_err(|e| anyhow::anyhow!(e.1))? {
            hosts::sync_directory(
                &a,
                &node.id,
                &node.name,
                &hosts::endpoint_hostname(&node.endpoint).map_err(|e| anyhow::anyhow!(e.1))?,
                "replica",
            )
            .map_err(|e| anyhow::anyhow!(e.1))?;
        }
    }
    maintenance::watch(a.clone());
    dns::replication::watch_forwarding(a.clone());
    clients::monitoring::watch(a.clone());
    let machine = Router::new()
        .route("/api/client/v1/info", get(clients::info))
        .route("/api/client/v1/enrollments", post(clients::start))
        .route("/api/client/v1/enrollments/{id}/token", post(clients::poll))
        .route(
            "/api/client/v1/enrollments/{id}/cancel",
            post(clients::cancel),
        )
        .route("/api/client/v1/hosts/{id}/session", post(clients::session))
        .route(
            "/api/client/v1/hosts/{id}/rotation/prepare",
            post(clients::rotation::prepare),
        )
        .route(
            "/api/client/v1/hosts/{id}/rotation/confirm",
            post(clients::rotation::confirm),
        )
        .route(
            "/api/client/v1/hosts/{id}/diagnostic-profile",
            post(clients::diagnostics::profile),
        )
        .route(
            "/api/client/v1/hosts/{id}/diagnostics",
            post(clients::diagnostics::report).layer(axum::extract::DefaultBodyLimit::max(65536)),
        )
        .route(
            "/api/client/v1/hosts/{id}/heartbeat",
            post(clients::monitoring::heartbeat),
        )
        .route(
            "/api/client/v1/hosts/{id}/deployments/poll",
            post(clients::deployments::poll),
        )
        .route(
            "/api/client/v1/hosts/{id}/deployments/grant",
            post(clients::deployments::grant),
        )
        .route(
            "/api/client/v1/hosts/{id}/deployments/progress",
            post(clients::deployments::progress),
        )
        .route("/api/client/v1/hosts/{id}/leave", post(clients::leave))
        .layer(axum::extract::DefaultBodyLimit::max(16384))
        .layer(axum::middleware::from_fn_with_state(
            a.clone(),
            clients::headers,
        ));
    tokio::spawn(dns::peer::watch(a.clone()));
    let app = Router::new()
        .merge(machine)
        .route("/api/hosts/{id}/replica-deployment",get(clients::deployments::details).post(clients::deployments::create))
        .route("/api/hosts/{id}/replica-deployment/action",post(clients::deployments::action))
        .route("/api/clients", get(clients::index))
        .route("/api/clients/{id}/rotate",post(clients::rotation::request))
        .route("/api/hosts/{id}/diagnostics",get(clients::diagnostics::details))
        .route("/api/hosts/{id}/issues/{issue}",post(clients::diagnostics::acknowledge_issue))
        .route("/api/notifications",get(clients::diagnostics::notifications))
        .route("/api/notifications/{id}",post(clients::diagnostics::acknowledge_notification))
        .route("/api/hosts/{id}/monitoring", get(clients::monitoring::details).put(clients::monitoring::policy))
        .route("/api/clients/lookup", post(clients::lookup))
        .route("/api/clients/{id}/approve", post(clients::approve))
        .route("/api/clients/{id}/revoke", post(clients::revoke))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/{*path}", axum::routing::any(|| async { (StatusCode::NOT_FOUND, Json(json!({"error":"API endpoint not found"}))) }))
        .route("/api/status", get(status))
        .route("/api/setup", post(setup))
        .route("/api/setup/join", post(dns::peer::directory::join_setup))
        .route("/api/directory/peer/register", post(dns::peer::directory::register))
        .route("/api/directory/peer/membership", get(dns::peer::directory::current))
        .route("/api/directory/peers/invite", post(dns::peer::invite_directory))
        .route("/api/setup/inspect", post(inspect_setup))
        .route("/api/login", post(login))
        .route("/api/me", get(me))
        .route("/api/logout", post(logout))
        .route("/api/overview", get(overview))
        .route("/api/network/checks", post(network::checks))
        .route("/api/hosts/{id}/network-checks", post(network::host_checks))
        .route("/api/dns", get(dns::index))
        .route("/api/dns/peers", get(dns::peer::invitations).post(dns::peer::invite))
        .route("/api/dns/peers/{id}", axum::routing::delete(dns::peer::revoke))
        .route("/api/dns/peer/join", post(dns::peer::join))
        .route("/api/dns/peer/redeem", post(dns::peer::redeem))
        .route("/api/dns/peer/snapshot", get(dns::peer::snapshot))
        .route("/api/dns/zones", post(dns::create))
        .route("/api/dns/zones/{zone}", get(dns::get_zone).delete(dns::delete).put(dns::settings))
        .route("/api/dns/zones/{zone}/records", post(dns::records).layer(axum::extract::DefaultBodyLimit::max(262144)))
        .route("/api/dns/zones/{zone}/export-json", get(dns::imports::export))
        .route("/api/dns/zones/{zone}/import/preview", post(dns::imports::preview).layer(axum::extract::DefaultBodyLimit::max(262144)))
        .route("/api/dns/zones/{zone}/import", post(dns::imports::commit).layer(axum::extract::DefaultBodyLimit::max(262144)))
        .route("/api/dns/zones/{zone}/export", get(dns::export))
        .route("/api/dns/changes/{id}/retry", post(dns::retry))
        .route("/api/dns/changes/{id}/abandon", post(dns::abandon))
        .route("/api/dns/hosts/{id}/reconcile", post(dns::host_records::reconcile))
        .route("/api/dns/hosts/{id}/retain", post(dns::host_records::retain))
        .route("/api/dns/servers", get(dns::replication::index).post(dns::replication::create))
        .route("/api/dns/servers/from-host", post(dns::replication::create_for_host))
        .route("/api/dns/primary", put(dns::replication::set_primary))
        .route("/api/dns/servers/{id}/deployment", post(dns::replication::deployment))
        .route("/api/dns/servers/{id}/enroll", post(dns::replication::enroll))
        .route("/api/dns/servers/{id}/assignments", put(dns::replication::assignments))
        .route("/api/dns/servers/{id}/reconcile", post(dns::replication::reconcile))
        .route("/api/dns/servers/{id}/credentials", post(dns::replication::credentials))
        .route("/api/dns/servers/{id}/certificate", post(dns::replication::certificate))
        .route("/api/dns/servers/{id}/certificate/finalize", post(dns::replication::finalize_certificate))
        .route("/api/dns/servers/{id}/check", post(dns::replication::check))
        .route("/api/dns/servers/{id}", axum::routing::delete(dns::replication::remove))
        .route("/api/dns/forwarding", get(dns::forwarding::get).put(dns::forwarding::put))
        .route("/api/dns/rotate", post(dns::rotate))
        .route("/api/maintenance", get(maintenance::index))
        .route("/api/maintenance/inspect", get(maintenance::inspect))
        .route("/api/maintenance/current", get(maintenance::current))
        .route("/api/maintenance/jobs", post(maintenance::launch))
        .route("/api/maintenance/recover", post(maintenance::resume))
        .route("/api/maintenance/keys", post(maintenance::keygen))
        .route("/api/maintenance/uploads", post(maintenance::upload).layer(axum::extract::DefaultBodyLimit::max(8*1024*1024*1024usize)))
        .route("/api/maintenance/backups/{id}", get(maintenance::download).delete(maintenance::remove))
        .route("/api/operations", get(operations::status))
        .route("/api/settings/public-url", post(operations::set_public_url))
        .route("/api/audit", get(operations::audit_page))
        .route("/api/audit/export", get(operations::audit_export))
        .route("/api/sessions/revoke", post(operations::revoke_sessions))
        .route("/api/recovery/complete", post(operations::complete_recovery))
        .route("/api/replication/setup", get(replica_setup::status))
        .route("/api/directory-servers", get(replicas::index).post(replicas::create))
        .route("/api/replicas/{id}/bundle", post(replicas::bundle))
        .route("/api/replicas/{id}/deployment", post(replicas::deployment))
        .route("/api/replicas/{id}/enroll", post(replicas::enroll))
        .route("/api/replicas/{id}/certificate", post(replicas::stage_certificate))
        .route("/api/replicas/{id}/certificate/finalize", post(replicas::finalize_certificate))
        .route("/api/replicas/{id}/credential", post(replicas::rotate_credential))
        .route("/api/replicas/{id}/reconnect", post(replicas::reconnect))
        .route("/api/replicas/{id}/restart", post(replicas::restart))
        .route("/api/replicas/{id}", axum::routing::delete(replicas::delete))
        .route("/api/hosts", get(hosts::index).post(hosts::create))
        .route("/api/hosts/{id}", put(hosts::update).delete(hosts::delete))
        .route("/api/hosts/{id}/bundle", post(hosts::bundle))
        .route("/api/users", post(save_user))
        .route("/api/users/{id}", axum::routing::delete(delete_user))
        .route("/api/groups/{id}", put(save_group).delete(delete_group))
        .fallback_service(
            ServeDir::new("/app/web").not_found_service(ServeFile::new("/app/web/index.html")),
        )
        .layer(axum::extract::DefaultBodyLimit::max(32768))
        .layer(axum::middleware::from_fn_with_state(a.clone(),dns::peer::forward))
        .layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                header::X_CONTENT_TYPE_OPTIONS,
                axum::http::HeaderValue::from_static("nosniff"),
            ),
        )
        .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(header::CONTENT_SECURITY_POLICY, axum::http::HeaderValue::from_static("default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")))
        .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store")))
        .layer(axum::middleware::from_fn_with_state(a.clone(),maintenance::fence))
        .with_state(a);
    let listener = tokio::net::TcpListener::bind(
        std::env::var("FORKLIFT_LISTEN").unwrap_or("0.0.0.0:8080".into()),
    )
    .await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        })
        .await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn injection_inputs_are_rejected() {
        for s in ["a*)(uid=*)", "a,b", "a\\00", "Admin", "", "a b"] {
            assert!(!valid(s));
        }
        assert!(valid("server-admins"));
    }
    #[test]
    fn constrained_suffix() {
        assert!(base_valid("dc=example,dc=com"));
        assert!(!base_valid("dc=example,dc=com\nrootdn evil"));
        assert!(!base_valid("dc=example"));
    }
}
