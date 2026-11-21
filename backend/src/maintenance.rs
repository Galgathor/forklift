//! Authenticated, durable fixed-operation jobs. Ordinary API requests drain before SQLite closes.
use super::*;
use axum::{
    body::Body,
    extract::{Multipart, Request},
    middleware::Next,
};
use std::{
    ops::{Deref, DerefMut},
    sync::{
        RwLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{io::AsyncWriteExt, sync::RwLock as AsyncRwLock};

pub(super) struct Database(pub Option<Connection>);
impl Deref for Database {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.0.as_ref().expect("database lease required")
    }
}
impl DerefMut for Database {
    fn deref_mut(&mut self) -> &mut Connection {
        self.0.as_mut().expect("database lease required")
    }
}
impl Database {
    pub fn open(&mut self) -> anyhow::Result<()> {
        if self.0.is_some() {
            return Ok(());
        }
        let db = Connection::open("/data/forklift.db")?;
        anyhow::ensure!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? == 5,
            "Unsupported metadata schema"
        );
        anyhow::ensure!(
            db.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))? == "ok",
            "Metadata integrity check failed"
        );
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        self.0 = Some(db);
        Ok(())
    }
    fn close(&mut self) -> anyhow::Result<()> {
        if let Some(db) = self.0.take() {
            db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            match db.close() {
                Ok(()) => {}
                Err((db, error)) => {
                    self.0 = Some(db);
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, serde::Serialize, Deserialize)]
pub(super) struct Ticket {
    id: String,
    actor: String,
    auth_hash: String,
    csrf: String,
    expires: i64,
    pub(super) bootstrap: bool,
    pub(super) public_url: String,
}
pub(super) struct Jobs {
    pub active: AtomicBool,
    pub recovering: AtomicBool,
    pub lease: Arc<AsyncRwLock<()>>,
    pub ticket: RwLock<Option<Ticket>>,
    pub failure: RwLock<Option<Value>>,
}
impl Jobs {
    pub fn new(active: bool) -> Self {
        let ticket = std::fs::read("/run/maintenance-control/ticket.json")
            .ok()
            .and_then(|v| serde_json::from_slice(&v).ok());
        Self {
            active: AtomicBool::new(active),
            recovering: AtomicBool::new(false),
            lease: Arc::new(AsyncRwLock::new(())),
            ticket: RwLock::new(ticket),
            failure: RwLock::new(None),
        }
    }
}
pub(super) async fn local(path: &str, payload: Option<&Value>) -> Result<Value> {
    let client = reqwest::Client::builder()
        .unix_socket("/run/maintenance-control/maintenance.sock")
        .timeout(std::time::Duration::from_secs(1800))
        .build()
        .map_err(anyhow::Error::from)?;
    let builder = if let Some(value) = payload {
        client.post(format!("http://maintenance{path}")).json(value)
    } else {
        client.get(format!("http://maintenance{path}"))
    };
    let response = builder
        .bearer_auth(secret("maintenance"))
        .send()
        .await
        .map_err(anyhow::Error::from)?;
    let status = response.status();
    let value: Value = response.json().await.map_err(anyhow::Error::from)?;
    if !status.is_success() {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            value["error"]
                .as_str()
                .unwrap_or("Maintenance service unavailable")
                .into(),
        ));
    }
    Ok(value)
}
pub(super) async fn directory(path: &str, payload: &Value) -> Result<Value> {
    let response = reqwest::Client::builder()
        .unix_socket("/run/ldap-control/primary.sock")
        .timeout(std::time::Duration::from_secs(40))
        .build()
        .map_err(anyhow::Error::from)?
        .post(format!("http://directory{path}"))
        .bearer_auth(secret("provision"))
        .json(payload)
        .send()
        .await
        .map_err(anyhow::Error::from)?;
    let status = response.status();
    let value: Value = response.json().await.map_err(anyhow::Error::from)?;
    if !status.is_success() {
        return Err(bad(value["error"]
            .as_str()
            .unwrap_or("Directory supervision failed")));
    }
    Ok(value)
}
pub(super) async fn fence(State(a): State<App>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if !path.starts_with("/api/")
        || path == "/api/status"
        || path.starts_with("/api/maintenance/")
        || path == "/api/maintenance"
    {
        return next.run(request).await;
    }
    if a.jobs.active.load(Ordering::SeqCst) {
        return Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "A maintenance job is active. Open its progress or recovery view.".into(),
        )
        .into_response();
    }
    let _lease = a.jobs.lease.read().await;
    if a.jobs.active.load(Ordering::SeqCst) {
        return Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Maintenance is in progress".into(),
        )
        .into_response();
    }
    next.run(request).await
}
fn raw_session(h: &HeaderMap) -> Option<&str> {
    h.get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';')
                .find_map(|s| s.trim().strip_prefix("forklift_session="))
        })
}
fn bootstrap_header(h: &HeaderMap) -> Option<&str> {
    h.get("x-bootstrap-token").and_then(|v| v.to_str().ok())
}
fn cached(a: &App, h: &HeaderMap, write: bool) -> Result<Ticket> {
    let ticket = a
        .jobs
        .ticket
        .read()
        .unwrap()
        .clone()
        .ok_or(unauthorized())?;
    let supplied = if ticket.bootstrap {
        bootstrap_header(h)
    } else {
        raw_session(h)
    }
    .ok_or(unauthorized())?;
    if digest(supplied) != ticket.auth_hash || ticket.expires <= now() {
        return Err(unauthorized());
    }
    if write
        && (h.get("origin").and_then(|v| v.to_str().ok()) != Some(ticket.public_url.as_str())
            || h.get("x-csrf-token").and_then(|v| v.to_str().ok()) != Some(ticket.csrf.as_str()))
    {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Maintenance CSRF token rejected".into(),
        ));
    }
    Ok(ticket)
}
async fn authorize(
    a: &App,
    h: &HeaderMap,
    write: bool,
) -> Result<(Ticket, tokio::sync::OwnedRwLockReadGuard<()>)> {
    if a.jobs.active.load(Ordering::SeqCst) {
        return Err(Error(
            StatusCode::CONFLICT,
            "Finish the existing maintenance job first".into(),
        ));
    }
    let lease = a.jobs.lease.clone().read_owned().await;
    if a.jobs.active.load(Ordering::SeqCst) {
        return Err(Error(
            StatusCode::CONFLICT,
            "Finish the existing maintenance job first".into(),
        ));
    }
    if config(a).is_none() {
        let raw = bootstrap_header(h).ok_or(unauthorized())?;
        if digest(raw) != digest(&secret("bootstrap")) {
            return Err(unauthorized());
        }
        if write {
            bootstrap(a, h, raw)?;
        }
        return Ok((
            Ticket {
                id: String::new(),
                actor: "bootstrap".into(),
                auth_hash: digest(raw),
                csrf: token(),
                expires: now() + 3600,
                bootstrap: true,
                public_url: if write {
                    request_origin(h)?
                } else {
                    public_url(a)
                },
            },
            lease,
        ));
    }
    let actor = admin(a, h, false).await?;
    if write {
        operations::csrf(a, h)?;
    }
    let raw = raw_session(h).ok_or(unauthorized())?;
    let (csrf, expires) =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT csrf,expires FROM sessions WHERE id=?",
                [digest(raw)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(anyhow::Error::from)?;
    Ok((
        Ticket {
            id: String::new(),
            actor,
            auth_hash: digest(raw),
            csrf,
            expires,
            bootstrap: false,
            public_url: public_url(a),
        },
        lease,
    ))
}
fn persist(ticket: &Ticket) -> Result<()> {
    use std::io::Write;
    let path = "/run/maintenance-control/ticket.json.new";
    let mut file = std::fs::File::create(path).map_err(anyhow::Error::from)?;
    file.write_all(&serde_json::to_vec(ticket).map_err(anyhow::Error::from)?)
        .map_err(anyhow::Error::from)?;
    file.sync_all().map_err(anyhow::Error::from)?;
    std::fs::rename(path, "/run/maintenance-control/ticket.json").map_err(anyhow::Error::from)?;
    std::fs::File::open("/run/maintenance-control")
        .and_then(|f| f.sync_all())
        .map_err(anyhow::Error::from)?;
    Ok(())
}
pub(super) async fn settle(a: &App, value: Value) -> Result<Value> {
    let mut value = value;
    if value["status"] == "awaiting_ack"
        || value["status"] == "completed"
        || value["status"] == "failed"
    {
        a.db.lock().unwrap().open()?;
        a.configured.store(config(a).is_some(), Ordering::SeqCst);
        if let Some(network) = value["result"].get("network").filter(|n| n.is_object())
            && let Some(mut config) = config(a)
        {
            let previous = value["result"]["previous_endpoint"].as_str().unwrap_or("");
            config["network"] = network.clone();
            let mut hosts = hosts::list(a)?;
            for host in &mut hosts {
                let mut changed = false;
                for endpoint in &mut host.draft.endpoints {
                    if endpoint == previous
                        && previous != network["endpoint"].as_str().unwrap_or("")
                    {
                        *endpoint = network["endpoint"].as_str().unwrap_or("").into();
                        changed = true;
                    }
                }
                if host.directory_id.as_deref() == Some("primary") {
                    host.draft.hostname = network["hostname"].as_str().unwrap_or("").into();
                }
                if changed {
                    host.revision += 1;
                }
            }
            let mut db = a.db.lock().unwrap();
            let tx = db.transaction().map_err(anyhow::Error::from)?;
            tx.execute(
                "UPDATE settings SET value=? WHERE key='directory'",
                [config.to_string()],
            )
            .map_err(anyhow::Error::from)?;
            for host in hosts {
                tx.execute(
                    "UPDATE hosts SET hostname=?,data=? WHERE id=?",
                    params![
                        host.draft.hostname,
                        serde_json::to_string(&host).map_err(anyhow::Error::from)?,
                        host.id
                    ],
                )
                .map_err(anyhow::Error::from)?;
            }
            tx.commit().map_err(anyhow::Error::from)?;
        }
        if value["status"] == "awaiting_ack" {
            for retry in 0..4 {
                match local("/ack", Some(&json!({"id":value["id"]}))).await {
                    Ok(v) => {
                        value = v;
                        break;
                    }
                    Err(error) => {
                        if retry == 3 {
                            return Err(error);
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        a.jobs.active.store(false, Ordering::SeqCst);
    }
    Ok(value)
}
pub(super) async fn current(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let ticket = cached(&a, &h, false)?;
    let state = local("/status", None).await?;
    if state["job"]["id"] != ticket.id {
        if let Some(failure) = a.jobs.failure.read().unwrap().clone() {
            return Ok(Json(json!({"job":failure,"csrf":ticket.csrf})));
        }
        if a.jobs.active.load(Ordering::SeqCst) {
            return Ok(Json(
                json!({"job":{"id":ticket.id,"status":"starting"},"csrf":ticket.csrf}),
            ));
        }
        return Err(bad("This maintenance ticket is no longer current"));
    }
    if a.jobs.recovering.load(Ordering::SeqCst) && state["job"]["status"] == "needs_resume" {
        return Ok(Json(
            json!({"job":{"id":ticket.id,"action":state["job"]["action"],"status":"starting"},"csrf":ticket.csrf}),
        ));
    }
    let still_current = a
        .jobs
        .ticket
        .read()
        .unwrap()
        .as_ref()
        .is_some_and(|t| t.id == ticket.id);
    let job = if still_current
        && a.jobs.active.load(Ordering::SeqCst)
        && state["job"]["status"] != "running"
    {
        settle(&a, state["job"].clone()).await?
    } else {
        state["job"].clone()
    };
    Ok(Json(json!({"job":job,"csrf":ticket.csrf})))
}
pub(super) async fn index(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let (_authorization, _lease) = authorize(&a, &h, false).await?;
    let mut value = local("/status", None).await?;
    value["backup_recipient"] =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key='backup_recipient'",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(json!(""));
    Ok(Json(value))
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JobRequest {
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_gib: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uid_floor: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_fenced: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acknowledge: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<Value>,
}
pub(super) async fn launch(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<JobRequest>,
) -> Result<Json<Value>> {
    let _launch = a.gate.lock().await;
    if ![
        "backup",
        "verify",
        "restore",
        "rotate-service",
        "renew-primary",
        "configure-primary",
    ]
    .contains(&p.action.as_str())
    {
        return Err(bad("Unknown maintenance action"));
    }
    if [
        "restore",
        "rotate-service",
        "renew-primary",
        "configure-primary",
    ]
    .contains(&p.action.as_str())
        && p.acknowledge != Some(true)
    {
        return Err(bad("Acknowledge the requested maintenance operation"));
    }
    if ["verify", "restore"].contains(&p.action.as_str()) {
        secure_transport(&a, &h)?;
    }
    let (mut ticket, lease) = authorize(&a, &h, true).await?;
    if ticket.bootstrap && p.action != "restore" && p.action != "verify" {
        return Err(bad(
            "Initial setup only permits backup verification or restoration",
        ));
    }
    if p.max_gib.is_some_and(|v| !(1..=64).contains(&v)) {
        return Err(bad("Use a snapshot limit from 1 to 64 GiB"));
    }
    if ["verify", "restore"].contains(&p.action.as_str())
        && (!p
            .sha256
            .as_ref()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            || !p
                .upload_id
                .as_ref()
                .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            || !p
                .identity
                .as_ref()
                .is_some_and(|s| s.len() <= 8192 && s.contains("AGE-SECRET-KEY-")))
    {
        return Err(bad(
            "Supply an uploaded archive, its trusted creation-time checksum and a native age recovery key",
        ));
    }
    ticket.id = token()[..32].into();
    persist(&ticket)?;
    let mut value = serde_json::to_value(p).map_err(anyhow::Error::from)?;
    value["id"] = json!(ticket.id);
    value["actor"] = json!(ticket.actor);
    value["public_url"] = json!(ticket.public_url);
    *a.jobs.ticket.write().unwrap() = Some(ticket.clone());
    *a.jobs.failure.write().unwrap() = None;
    a.jobs.active.store(true, Ordering::SeqCst);
    drop(lease);
    start_task(a.clone(), h, value, false);
    Ok(Json(
        json!({"id":ticket.id,"csrf":ticket.csrf,"started":true}),
    ))
}
fn start_task(a: App, h: HeaderMap, payload: Value, recovery: bool) {
    tokio::spawn(async move {
        let _exclusive = a.jobs.lease.write().await;
        let result = async {
            if !recovery {
                let ticket = a
                    .jobs
                    .ticket
                    .read()
                    .unwrap()
                    .clone()
                    .ok_or(unauthorized())?;
                if ticket.bootstrap {
                    bootstrap(&a, &h, bootstrap_header(&h).ok_or(unauthorized())?)?;
                } else {
                    admin(&a, &h, false).await?;
                    operations::csrf(&a, &h)?;
                }
            }
            a.db.lock().unwrap().close()?;
            let result = local("/run", Some(&payload)).await?;
            settle(&a, result).await?;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(error) = result {
            // The ticket remains usable for recovery; never print request bodies or key material.
            eprintln!("maintenance needs attention: {}", error.1);
            let state = local("/status", None).await.ok();
            if state.as_ref().is_some_and(|s| {
                !s["busy"].as_bool().unwrap_or(true)
                    && !s["offline"].as_bool().unwrap_or(true)
                    && !["running", "needs_resume", "awaiting_ack"]
                        .contains(&s["job"]["status"].as_str().unwrap_or(""))
            }) {
                let id = a
                    .jobs
                    .ticket
                    .read()
                    .unwrap()
                    .as_ref()
                    .map(|t| t.id.clone())
                    .unwrap_or_default();
                *a.jobs.failure.write().unwrap() =
                    Some(json!({"id":id,"status":"failed","error":error.1}));
                let opened = a.db.lock().unwrap().open().is_ok();
                if opened {
                    a.jobs.active.store(false, Ordering::SeqCst);
                }
            }
        }
        if a.jobs
            .ticket
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|t| Some(t.id.as_str()) == payload["id"].as_str())
        {
            a.jobs.recovering.store(false, Ordering::SeqCst);
        }
    });
}
#[derive(Deserialize)]
pub(super) struct Recovery {
    action: String,
}
pub(super) async fn resume(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Recovery>,
) -> Result<Json<Value>> {
    if !["resume", "rollback"].contains(&p.action.as_str()) {
        return Err(bad("Choose resume or rollback"));
    }
    let _launch = a.gate.lock().await;
    let ticket = cached(&a, &h, true)?;
    if a.jobs.recovering.load(Ordering::SeqCst) {
        return Err(bad("A recovery request is already starting"));
    }
    let state = local("/status", None).await?;
    if state["busy"] == true {
        return Err(bad("A maintenance worker is still active"));
    }
    if state["job"]["id"] != ticket.id
        || !["needs_resume", "awaiting_ack"]
            .contains(&state["job"]["status"].as_str().unwrap_or(""))
    {
        return Err(bad("This operation does not require recovery"));
    }
    a.jobs.active.store(true, Ordering::SeqCst);
    a.jobs.recovering.store(true, Ordering::SeqCst);
    start_task(
        a.clone(),
        h,
        json!({"id":ticket.id,"action":p.action}),
        true,
    );
    Ok(Json(json!({"id":ticket.id,"started":true})))
}
fn secure_transport(a: &App, h: &HeaderMap) -> Result<()> {
    let raw = if !a.configured.load(Ordering::SeqCst) {
        request_origin(h)?
    } else {
        public_url(a)
    };
    let url = reqwest::Url::parse(&raw).map_err(|_| bad("Invalid public URL"))?;
    if url.scheme() != "https"
        && !["localhost", "127.0.0.1", "[::1]"].contains(&url.host_str().unwrap_or(""))
    {
        return Err(bad(
            "Use HTTPS or a localhost connection when handling backup recovery keys",
        ));
    }
    Ok(())
}
pub(super) async fn keygen(State(a): State<App>, h: HeaderMap) -> Result<Response> {
    let (authorization, _lease) = authorize(&a, &h, true).await?;
    if authorization.bootstrap {
        return Err(bad("Complete setup before generating backup keys"));
    }
    secure_transport(&a, &h)?;
    let value = local("/keygen", Some(&json!({}))).await?;
    let recipient = value["recipient"]
        .as_str()
        .ok_or(bad("Key generation failed"))?;
    a.db.lock().unwrap().execute("INSERT INTO settings VALUES('backup_recipient',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[json!(recipient).to_string()]).map_err(anyhow::Error::from)?;
    audit(
        &a,
        &authorization.actor,
        "generate backup recovery key",
        "download",
    )?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/plain".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"forklift-recovery.txt\"".into(),
            ),
            (
                header::HeaderName::from_static("x-age-recipient"),
                recipient.to_owned(),
            ),
        ],
        value["identity"].as_str().unwrap_or("").to_owned(),
    )
        .into_response())
}
pub(super) async fn upload(
    State(a): State<App>,
    h: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<Value>> {
    let (_authorization, _lease) = authorize(&a, &h, true).await?;
    let id = token()[..32].to_owned();
    let path = format!("/transfers/{id}.age");
    let mut file = tokio::fs::File::create(&path)
        .await
        .map_err(anyhow::Error::from)?;
    let result = async {
        let mut field = multipart
            .next_field()
            .await
            .map_err(anyhow::Error::from)?
            .ok_or(bad("Select an encrypted backup"))?;
        if field.name() != Some("archive") {
            return Err(bad("Expected an archive upload"));
        }
        let mut bytes = 0u64;
        let mut hash = Sha256::new();
        while let Some(chunk) = field.chunk().await.map_err(anyhow::Error::from)? {
            bytes += chunk.len() as u64;
            if bytes > 8 * 1024 * 1024 * 1024 {
                return Err(bad("Encrypted upload exceeds 8 GiB"));
            }
            hash.update(&chunk);
            file.write_all(&chunk).await.map_err(anyhow::Error::from)?;
        }
        file.sync_all().await.map_err(anyhow::Error::from)?;
        Ok(Json(
            json!({"id":id,"sha256":hex::encode(hash.finalize()),"bytes":bytes}),
        ))
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(path).await;
    }
    result
}
pub(super) async fn download(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response> {
    let (_authorization, _lease) = authorize(&a, &h, false).await?;
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad("Invalid backup identifier"));
    }
    let path = format!("/backups/{id}.tar.gz.age");
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(anyhow::Error::from)?;
    let stream = tokio_util::io::ReaderStream::new(file);
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"forklift-backup.tar.gz.age\"",
            ),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}
pub(super) async fn remove(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let (authorization, _lease) = authorize(&a, &h, true).await?;
    if authorization.bootstrap {
        return Err(unauthorized());
    }
    let result = local("/delete", Some(&json!({"id":id}))).await?;
    audit(&a, &authorization.actor, "delete backup", &id)?;
    Ok(Json(result))
}

pub(super) async fn inspect(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let (_authorization, _lease) = authorize(&a, &h, false).await?;
    Ok(Json(local("/inspect", Some(&json!({}))).await?))
}
pub(super) fn watch(a: App) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if !a.jobs.active.load(Ordering::SeqCst) {
                continue;
            }
            let Ok(state) = local("/status", None).await else {
                continue;
            };
            if !["awaiting_ack", "completed", "failed"]
                .contains(&state["job"]["status"].as_str().unwrap_or(""))
            {
                continue;
            }
            let _exclusive = a.jobs.lease.write().await;
            let id = a.jobs.ticket.read().unwrap().as_ref().map(|t| t.id.clone());
            if a.jobs.active.load(Ordering::SeqCst) && id.as_deref() == state["job"]["id"].as_str()
            {
                let _ = settle(&a, state["job"].clone()).await;
            }
        }
    });
}
