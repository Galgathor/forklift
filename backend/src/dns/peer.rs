//! Manager-to-manager DNS authorization and transport.
use super::*;
pub(crate) mod directory;
use axum::body::Bytes;
use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::middleware::Next;
use rusqlite::OptionalExtension;

const LIMIT: usize = 8 * 1024 * 1024;
const INVITE_LIFETIME: i64 = 600;

#[derive(Deserialize, Serialize)]
pub(crate) struct Upstream {
    url: String,
    key: String,
}

fn schema(a: &App) -> Result<()> {
    a.db.lock()
        .unwrap()
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS dns_peer_keys(
            id TEXT PRIMARY KEY, secret_hash TEXT UNIQUE NOT NULL,
            expires INTEGER NOT NULL, access_hash TEXT UNIQUE, directory INTEGER NOT NULL DEFAULT 0
        );",
        )
        .map_err(anyhow::Error::from)?;
    Ok(())
}

fn upstream(a: &App) -> Result<Option<Upstream>> {
    let raw: Option<String> =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key='dns_coordinator'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
    raw.map(|v| {
        serde_json::from_str(&v)
            .map_err(anyhow::Error::from)
            .map_err(Error::from)
    })
    .transpose()
}

fn secure_origin(url: &str) -> bool {
    url.starts_with("https://") && !url.ends_with('/') && valid_public_url(url)
}

fn key_valid(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit())
}

fn peer_key(h: &HeaderMap) -> Result<&str> {
    let raw = h
        .get("x-forklift-dns-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(unauthorized())?;
    if !key_valid(raw) {
        return Err(unauthorized());
    }
    Ok(raw)
}

fn principal(a: &App, h: &HeaderMap) -> Result<String> {
    let raw = peer_key(h)?;
    schema(a)?;
    let id: String =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT id FROM dns_peer_keys WHERE access_hash=?",
                [digest(raw)],
                |r| r.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?
            .ok_or(unauthorized())?;
    Ok(format!("dns-peer/{id}"))
}

pub(super) async fn editor(a: &App, h: &HeaderMap, write: bool) -> Result<String> {
    if !h.contains_key("x-forklift-dns-key") {
        return authorize(a, h, write).await;
    }
    let who = principal(a, h)?;
    if write && operations::recovery(a)? {
        return Err(unavailable(
            "Complete the recovery review before DNS changes",
        ));
    }
    meta(a)?;
    Ok(who)
}

pub(crate) async fn invitations(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    authorize(&a, &h, false).await?;
    schema(&a)?;
    directory::schema(&a)?;
    let peers = {
        let db = a.db.lock().unwrap();
        let mut q = db.prepare("SELECT k.id,k.access_hash IS NOT NULL,k.expires,k.directory,p.sid FROM dns_peer_keys k LEFT JOIN ldap_peers p ON p.peer_id=k.id AND p.revoked=0 WHERE k.access_hash IS NOT NULL OR k.expires>? ORDER BY k.expires DESC")
            .map_err(anyhow::Error::from)?;
        q.query_map([now()], |r| Ok(json!({"id":r.get::<_,String>(0)?,"active":r.get::<_,bool>(1)?,"expires":r.get::<_,i64>(2)?,"directory":r.get::<_,bool>(3)?,"server_id":r.get::<_,Option<i64>>(4)?.map(|sid| format!("provider-{sid}"))})))
            .map_err(anyhow::Error::from)?
            .collect::<std::result::Result<Vec<_>,_>>().map_err(anyhow::Error::from)?
    };
    let coordinator = upstream(&a)?.map(|v| v.url);
    let applied: Option<String> =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key='dns_coordinator_revision'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
    let error: Option<String> =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key='dns_coordinator_error'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
    Ok(Json(
        json!({"peers":peers,"coordinator":coordinator,"applied_revision":applied,"error":error}),
    ))
}

pub(crate) async fn invite(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    issue(&a, &h, false).await
}

pub(crate) async fn invite_directory(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    issue(&a, &h, true).await
}

async fn issue(a: &App, h: &HeaderMap, directory: bool) -> Result<Json<Value>> {
    let who = authorize(a, h, true).await?;
    let _guard = a.gate.lock().await;
    let url = public_url(a);
    if !secure_origin(&url) || upstream(a)?.is_some() {
        return Err(bad(
            "Create the pairing key on the DNS coordinator using its HTTPS WebUI",
        ));
    }
    schema(a)?;
    let key = token();
    let id = token()[..32].to_owned();
    let expires = now() + INVITE_LIFETIME;
    {
        let db = a.db.lock().unwrap();
        db.execute(
            "DELETE FROM dns_peer_keys WHERE access_hash IS NULL AND expires<=?",
            [now()],
        )
        .map_err(anyhow::Error::from)?;
        let count: usize = db
            .query_row("SELECT count(*) FROM dns_peer_keys", [], |r| r.get(0))
            .map_err(anyhow::Error::from)?;
        if count >= 8 {
            return Err(bad("Remove an unused DNS peer before adding another"));
        }
        db.execute(
            "INSERT INTO dns_peer_keys(id,secret_hash,expires,directory) VALUES(?,?,?,?)",
            params![id, digest(&key), expires, directory],
        )
        .map_err(anyhow::Error::from)?;
    }
    audit(a, &who, "approve DNS peer pairing", &id)?;
    Ok(Json(json!({"id":id,"url":url,"key":key,"expires":expires})))
}

pub(crate) async fn revoke(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    schema(&a)?;
    directory::revoke(&a, &id).await?;
    a.db.lock()
        .unwrap()
        .execute("DELETE FROM dns_peer_keys WHERE id=?", [&id])
        .map_err(anyhow::Error::from)?;
    audit(&a, &who, "revoke DNS peer", &id)?;
    Ok(Json(json!({"ok":true})))
}

#[derive(Deserialize)]
pub(crate) struct Redemption {
    access_key: String,
}

pub(crate) async fn redeem(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Redemption>,
) -> Result<Json<Value>> {
    let raw = peer_key(&h)?;
    if !key_valid(&p.access_key) || p.access_key == raw {
        return Err(unauthorized());
    }
    let access_hash = digest(&p.access_key);
    let _guard = a.gate.lock().await;
    if operations::recovery(&a)? || upstream(&a)?.is_some() || config(&a).is_none() {
        return Err(unavailable("DNS coordinator is unavailable"));
    }
    schema(&a)?;
    let affected =
        a.db.lock()
            .unwrap()
            .execute(
                "UPDATE dns_peer_keys SET access_hash=? WHERE secret_hash=? AND ((access_hash IS NULL AND expires>?) OR access_hash=?)",
                params![access_hash, digest(raw), now(), access_hash],
            )
            .map_err(anyhow::Error::from)?;
    if affected != 1 {
        return Err(unauthorized());
    }
    Ok(Json(json!({"ok":true})))
}

async fn remote(
    up: &Upstream,
    method: Method,
    path: &str,
    body: Bytes,
) -> Result<(StatusCode, Option<String>, Vec<u8>)> {
    let client = reqwest::Client::builder()
        .use_native_tls()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(anyhow::Error::from)?;
    let mut response = client
        .request(method, format!("{}{path}", up.url))
        .header("x-forklift-dns-key", &up.key)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| unavailable("Could not reach the DNS coordinator over verified HTTPS"))?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| unavailable("DNS coordinator response was interrupted"))?
    {
        if data.len() + chunk.len() > LIMIT {
            return Err(unavailable(
                "DNS coordinator response exceeds the supported size",
            ));
        }
        data.extend_from_slice(&chunk);
    }
    Ok((status, content_type, data))
}

pub(crate) async fn join(
    State(a): State<App>,
    h: HeaderMap,
    Json(up): Json<Upstream>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    if !secure_origin(&up.url) || up.url == public_url(&a) {
        return Err(bad("Use the HTTPS address of a different Forklift manager"));
    }
    if !key_valid(&up.key) {
        return Err(bad("Enter the DNS pairing key from the coordinator"));
    }
    let _guard = a.gate.lock().await;
    if directory::local_sid(&a)?.is_some_and(|sid| sid > 1) {
        return Err(bad(
            "This manager joined with both LDAP and DNS. Its membership uses the directory pairing.",
        ));
    }
    let current = upstream(&a)?;
    if current.as_ref().is_some_and(|v| v.url != up.url) {
        return Err(bad(
            "Use the current DNS coordinator address to replace the pairing",
        ));
    }
    schema(&a)?;
    let has_peers: bool = a
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM dns_peer_keys WHERE access_hash IS NOT NULL OR expires>?)",
            [now()],
            |r| r.get(0),
        )
        .map_err(anyhow::Error::from)?;
    if has_peers || (current.is_none() && !zones().await?.is_empty()) {
        return Err(bad(
            "Join from a manager with an empty local DNS server and no DNS peers",
        ));
    }
    let activated = activate(&a, up).await?;
    let url = activated.url.clone();
    store_upstream(&a, &activated)?;
    audit(&a, &who, "join DNS coordinator", &url)?;
    Ok(Json(json!({"ok":true})))
}

async fn activate(a: &App, up: Upstream) -> Result<Upstream> {
    // Preserve the generated credential across a lost remote acknowledgement.
    let fingerprint = digest(&json!([up.url, up.key]).to_string());
    let access_key = {
        let db = a.db.lock().unwrap();
        let pending: Option<String> = db
            .query_row(
                "SELECT value FROM settings WHERE key='dns_coordinator_pending'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
        let key = pending
            .as_deref()
            .and_then(|v| v.strip_prefix(&fingerprint))
            .filter(|v| key_valid(v))
            .map(str::to_owned)
            .unwrap_or_else(token);
        db.execute("INSERT INTO settings VALUES('dns_coordinator_pending',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [format!("{fingerprint}{key}")]).map_err(anyhow::Error::from)?;
        key
    };
    let (status, _, _) = remote(
        &up,
        Method::POST,
        "/api/dns/peer/redeem",
        Bytes::from(json!({"access_key":access_key}).to_string()),
    )
    .await?;
    if !status.is_success() {
        return Err(bad(
            "The DNS coordinator rejected the pairing key. Check the address and generate a new key if it expired.",
        ));
    }
    Ok(Upstream {
        url: up.url,
        key: access_key,
    })
}

fn store_upstream(a: &App, active: &Upstream) -> Result<()> {
    let mut db = a.db.lock().unwrap();
    let tx = db.transaction().map_err(anyhow::Error::from)?;
    persist_upstream(&tx, active)?;
    tx.commit().map_err(anyhow::Error::from)?;
    Ok(())
}

fn persist_upstream(tx: &rusqlite::Transaction<'_>, active: &Upstream) -> Result<()> {
    tx.execute(
        "INSERT INTO settings VALUES('dns_coordinator',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        [serde_json::to_string(active).map_err(anyhow::Error::from)?],
    ).map_err(anyhow::Error::from)?;
    tx.execute(
        "DELETE FROM settings WHERE key='dns_coordinator_pending'",
        [],
    )
    .map_err(anyhow::Error::from)?;
    Ok(())
}

fn forwardable(method: &Method, path: &str) -> bool {
    if path == "/api/dns" {
        return method == Method::GET;
    }
    if path == "/api/dns/forwarding" {
        return matches!(*method, Method::GET | Method::PUT);
    }
    if path == "/api/dns/zones" {
        return method == Method::POST;
    }
    if let Some(rest) = path.strip_prefix("/api/dns/zones/") {
        let parts = rest.split('/').collect::<Vec<_>>();
        if parts[0].is_empty() {
            return false;
        }
        return match parts.as_slice() {
            [_] => matches!(*method, Method::GET | Method::PUT | Method::DELETE),
            [_, "records" | "import"] | [_, "import", "preview"] => method == Method::POST,
            [_, "export" | "export-json"] => method == Method::GET,
            _ => false,
        };
    }
    if let Some(rest) = path.strip_prefix("/api/dns/changes/") {
        return matches!(
            rest.split('/').collect::<Vec<_>>().as_slice(),
            [_, "retry" | "abandon"]
        ) && method == Method::POST;
    }
    false
}

pub(crate) async fn forward(State(a): State<App>, req: Request, next: Next) -> Response {
    if !forwardable(req.method(), req.uri().path()) {
        return next.run(req).await;
    }
    let up = match upstream(&a) {
        Ok(Some(up)) => up,
        Ok(None) => return next.run(req).await,
        Err(e) => return e.into_response(),
    };
    forward_request(&a, req, &up)
        .await
        .unwrap_or_else(Error::into_response)
}

async fn forward_request(a: &App, req: Request, up: &Upstream) -> Result<Response> {
    let (parts, body) = req.into_parts();
    authorize(a, &parts.headers, parts.method != Method::GET).await?;
    let body = to_bytes(body, 262144).await.map_err(|_| {
        Error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "DNS request too large".into(),
        )
    })?;
    let path = parts.uri.path();
    let (status, content_type, data) = remote(up, parts.method, path, body).await?;
    if status == StatusCode::UNAUTHORIZED {
        return Err(unavailable(
            "The DNS coordinator revoked or rejected this manager's pairing key",
        ));
    }
    let mut response = Response::new(Body::from(data));
    *response.status_mut() = status;
    match content_type.as_deref().and_then(|v| v.split(';').next()) {
        Some("application/json") => {
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        }
        Some("text/plain") if path.ends_with("/export") => {
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
        }
        _ => {
            return Err(unavailable(
                "The DNS coordinator returned an unexpected response",
            ));
        }
    }
    if status.is_success() && (path.ends_with("/export") || path.ends_with("/export-json")) {
        let filename = if path.ends_with("/export") {
            "forklift-zone.txt"
        } else {
            "forklift-zone.json"
        };
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename={filename}")
                .parse()
                .map_err(anyhow::Error::from)?,
        );
    }
    Ok(response)
}

const COPY_OWNER: &str = "forklift-peer";

#[derive(Serialize, Deserialize)]
struct Snapshot {
    revision: String,
    zones: BTreeMap<String, Vec<Value>>,
    #[serde(default)]
    forwarding: Option<forwarding::Settings>,
}

fn published_sets(z: &Value) -> Vec<Value> {
    let mut result = sets(z).iter().map(canonical).collect::<Vec<_>>();
    result.sort_by_key(|r| (r["name"].to_string(), r["type"].to_string()));
    result
}

pub(crate) async fn snapshot(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let _guard = a.gate.lock().await;
    principal(&a, &h)?;
    meta(&a)?;
    no_pending(&a)?;
    let mut records = BTreeMap::new();
    for entry in zones().await? {
        if managed(&entry).is_ok() {
            let n = name(
                entry["name"].as_str().ok_or(bad("Invalid DNS zone"))?,
                false,
            )?;
            records.insert(n.clone(), published_sets(&zone(&n).await?));
        }
    }
    let revision = digest(&serde_json::to_string(&records).map_err(anyhow::Error::from)?);
    let document = json!(Snapshot {
        revision,
        zones: records,
        forwarding: Some(forwarding::current().await?)
    });
    if document.to_string().len() > LIMIT {
        return Err(unavailable(
            "Managed DNS exceeds the supported synchronization size",
        ));
    }
    Ok(Json(document))
}

async fn apply_snapshot(snapshot: &Snapshot) -> Result<()> {
    if snapshot.zones.len() > 128 {
        return Err(unavailable("DNS snapshot contains more than 128 zones"));
    }
    let revision = digest(&serde_json::to_string(&snapshot.zones).map_err(anyhow::Error::from)?);
    if revision != snapshot.revision {
        return Err(unavailable(
            "DNS snapshot revision did not match its contents",
        ));
    }
    let mut existing = BTreeMap::new();
    for entry in zones().await? {
        let n = name(
            entry["name"].as_str().ok_or(bad("Invalid DNS zone"))?,
            false,
        )?;
        if entry["account"] != COPY_OWNER && snapshot.zones.contains_key(&n) {
            return Err(unavailable(
                "A local DNS zone already uses a name managed by the coordinator",
            ));
        }
        if entry["account"] == COPY_OWNER {
            existing.insert(n, entry);
        }
    }
    for (n, desired) in &snapshot.zones {
        if name(n, false)? != *n {
            return Err(bad("Invalid zone in DNS snapshot"));
        }
        if existing.remove(n).is_none() {
            request(
                Method::POST,
                "/zones",
                Some(&json!({
                    "name":n,"kind":"Native","account":COPY_OWNER,"nameservers":[],
                    "rrsets":desired,"soa_edit_api":""
                })),
            )
            .await?;
        } else {
            let current = published_sets(&zone(n).await?);
            let key = |r: &Value| (r["name"].to_string(), r["type"].to_string());
            let desired_by_key = desired
                .iter()
                .map(|r| (key(r), r))
                .collect::<BTreeMap<_, _>>();
            let current_by_key = current
                .iter()
                .map(|r| (key(r), r))
                .collect::<BTreeMap<_, _>>();
            let mut patch = Vec::new();
            for (k, r) in &current_by_key {
                if !desired_by_key.contains_key(k) {
                    patch.push(json!({"name":r["name"],"type":r["type"],"changetype":"DELETE"}));
                }
            }
            for (k, r) in desired_by_key {
                if current_by_key.get(&k).copied() != Some(r) {
                    let mut replacement = r.clone();
                    replacement["changetype"] = json!("REPLACE");
                    patch.push(replacement);
                }
            }
            if !patch.is_empty() {
                request(Method::PATCH, &zone_path(n), Some(&json!({"rrsets":patch}))).await?;
            }
        }
        if published_sets(&zone(n).await?) != *desired {
            return Err(unavailable(
                "PowerDNS records or SOA serial differ from the DNS coordinator",
            ));
        }
    }
    for n in existing.keys() {
        request(Method::DELETE, &zone_path(n), None).await?;
    }
    Ok(())
}

async fn sync(a: &App) -> Result<()> {
    let Some(up) = upstream(a)? else {
        return Ok(());
    };
    let (status, _, data) =
        remote(&up, Method::GET, "/api/dns/peer/snapshot", Bytes::new()).await?;
    if !status.is_success() {
        return Err(unavailable(
            "The DNS coordinator did not provide a complete snapshot",
        ));
    }
    let snapshot: Snapshot = serde_json::from_slice(&data).map_err(anyhow::Error::from)?;
    let _guard = a.gate.lock().await;
    apply_snapshot(&snapshot).await?;
    if let Some(policy) = &snapshot.forwarding {
        forwarding::apply(policy, replication::primary(a)?.as_ref()).await?;
    }
    let db = a.db.lock().unwrap();
    db.execute("INSERT INTO settings VALUES('dns_coordinator_revision',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[snapshot.revision])
        .map_err(anyhow::Error::from)?;
    Ok(())
}

pub(crate) async fn watch(a: App) {
    loop {
        {
            let _lease = a.jobs.lease.read().await;
            if !a.jobs.active.load(std::sync::atomic::Ordering::SeqCst) {
                let error = sync(&a).await.err().map(|e| e.1);
                let directory_error = directory::refresh(&a).await.err().map(|e| e.1);
                if let Some(error) = directory_error {
                    let _ = a.db.lock().unwrap().execute("INSERT INTO settings VALUES('directory_peer_error',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[error]);
                } else {
                    let _ =
                        a.db.lock()
                            .unwrap()
                            .execute("DELETE FROM settings WHERE key='directory_peer_error'", []);
                }
                if let Some(error) = error {
                    let _ = a.db.lock().unwrap().execute("INSERT INTO settings VALUES('dns_coordinator_error',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[error]);
                } else {
                    let _ =
                        a.db.lock()
                            .unwrap()
                            .execute("DELETE FROM settings WHERE key='dns_coordinator_error'", []);
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_allows_record_edits_and_excludes_pairing_and_credential_operations() {
        assert!(forwardable(
            &Method::POST,
            "/api/dns/zones/example.test./records"
        ));
        assert!(forwardable(&Method::DELETE, "/api/dns/zones/example.test."));
        for path in [
            "/api/dns/peers",
            "/api/dns/peer/redeem",
            "/api/dns/rotate",
            "/api/dns/servers",
            "/api/hosts",
        ] {
            assert!(!forwardable(&Method::POST, path));
            assert!(!forwardable(&Method::GET, path));
        }
    }
}
