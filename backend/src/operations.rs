use super::*;
use axum::extract::Query;
use rusqlite::OptionalExtension;

pub(super) fn migrate(db: &Connection) -> anyhow::Result<()> {
    db.execute_batch("BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS maintenance_events(operation_id TEXT PRIMARY KEY,at INTEGER NOT NULL,kind TEXT NOT NULL,status TEXT NOT NULL,artifact TEXT NOT NULL DEFAULT '',sha256 TEXT NOT NULL DEFAULT '',detail TEXT NOT NULL DEFAULT '');")?;
    let columns = db
        .prepare("PRAGMA table_info(attempts)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if !columns.iter().any(|s| s == "username") {
        db.execute(
            "ALTER TABLE attempts ADD COLUMN username TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    let columns = db
        .prepare("PRAGMA table_info(directory_servers)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (name, kind) in [
        ("next_certificate", "TEXT"),
        ("certificate_staged_at", "INTEGER"),
        ("credential_rotated_at", "INTEGER"),
        ("credential_epoch", "INTEGER NOT NULL DEFAULT 0"),
    ] {
        if !columns.iter().any(|s| s == name) {
            db.execute(
                &format!("ALTER TABLE directory_servers ADD COLUMN {name} {kind}"),
                [],
            )?;
        }
    }
    db.execute_batch("PRAGMA user_version=4; COMMIT;")?;
    Ok(())
}
pub(super) fn recovery(a: &App) -> Result<bool> {
    let value =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key='recovery_required'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
    value
        .map(|v| {
            serde_json::from_str::<bool>(&v)
                .map_err(anyhow::Error::from)
                .map_err(Error::from)
        })
        .unwrap_or(Ok(false))
}
pub(super) fn csrf(a: &App, h: &HeaderMap) -> Result<()> {
    origin(a, h)?;
    let raw = h
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';')
                .find_map(|s| s.trim().strip_prefix("forklift_session="))
        })
        .ok_or(unauthorized())?;
    let expected =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT csrf FROM sessions WHERE id=? AND expires>?",
                params![digest(raw), now()],
                |r| r.get::<_, String>(0),
            )
            .map_err(|_| unauthorized())?;
    if h.get("x-csrf-token").and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return Err(Error(StatusCode::FORBIDDEN, "CSRF token rejected".into()));
    }
    Ok(())
}
pub(super) fn certificate(label: &str, pem: &str) -> Value {
    let parsed = openssl::x509::X509::from_pem(pem.as_bytes())
        .ok()
        .and_then(|c| c.to_der().ok());
    if let Some(der) = parsed
        && let Ok((_, cert)) = x509_parser::parse_x509_certificate(&der)
    {
        let expires = cert.validity().not_after.timestamp();
        return json!({"label":label,"not_after":expires,"days_remaining":(expires-now())/86400,"fingerprint":hex::encode(Sha256::digest(&der)),"status":if expires<=now(){"expired"}else if expires-now()<30*86400{"renew_soon"}else{"valid"}});
    }
    json!({"label":label,"status":"unavailable"})
}
pub(super) async fn status(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    let mut certificates = Vec::new();
    for (label, file) in [
        ("Primary configured certificate", "ldap.crt"),
        ("Installation CA", "ca.crt"),
    ] {
        let pem = std::fs::read_to_string(format!("/run/secrets/{file}")).unwrap_or_default();
        certificates.push(certificate(label, &pem));
    }
    for s in replicas::records(&a)? {
        if let Some(pem) = s.certificate {
            certificates.push(certificate(&s.name, &pem));
        }
        if let Some(pem) = s.next_certificate {
            certificates.push(certificate(&format!("{} (staged)", s.name), &pem));
        }
    }
    let (maintenance, sessions, schema) = {
        let db = a.db.lock().unwrap();
        let mut q=db.prepare("SELECT operation_id,at,kind,status,artifact,sha256,detail FROM maintenance_events ORDER BY at DESC LIMIT 30").map_err(anyhow::Error::from)?;
        let rows=q.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"at":r.get::<_,i64>(1)?,"kind":r.get::<_,String>(2)?,"status":r.get::<_,String>(3)?,"artifact":r.get::<_,String>(4)?,"sha256":r.get::<_,String>(5)?,"detail":r.get::<_,String>(6)?}))).map_err(anyhow::Error::from)?.collect::<std::result::Result<Vec<_>,_>>().map_err(anyhow::Error::from)?;
        let sessions: i64 = db
            .query_row(
                "SELECT count(*) FROM sessions WHERE expires>?",
                [now()],
                |r| r.get(0),
            )
            .map_err(anyhow::Error::from)?;
        let schema: i64 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(anyhow::Error::from)?;
        (rows, sessions, schema)
    };
    Ok(Json(
        json!({"version":env!("CARGO_PKG_VERSION"),"schema":schema,"recovery_required":recovery(&a)?,"certificates":certificates,"maintenance":maintenance,"active_sessions":sessions,"checked_at":now()}),
    ))
}
#[derive(Deserialize)]
pub(super) struct Page {
    before: Option<i64>,
    limit: Option<usize>,
    q: Option<String>,
}
fn audit_rows(a: &App, p: &Page, max: usize) -> Result<(Vec<Value>, Option<i64>)> {
    let limit = p.limit.unwrap_or(50);
    let query = p.q.as_deref().unwrap_or("");
    if limit == 0 || limit > max || p.before.is_some_and(|n| n <= 0) || query.len() > 128 {
        return Err(bad("Invalid audit page size, cursor or search"));
    }
    let db = a.db.lock().unwrap();
    let mut q=db.prepare("SELECT id,at,actor,action,target FROM audit WHERE id<? AND instr(lower(actor||' '||action||' '||target),lower(?))>0 ORDER BY id DESC LIMIT ?").map_err(anyhow::Error::from)?;
    let mut rows=q.query_map(params![p.before.unwrap_or(i64::MAX),query,(limit+1) as i64],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"at":r.get::<_,i64>(1)?,"actor":r.get::<_,String>(2)?,"action":r.get::<_,String>(3)?,"target":r.get::<_,String>(4)?}))).map_err(anyhow::Error::from)?.collect::<std::result::Result<Vec<_>,_>>().map_err(anyhow::Error::from)?;
    let more = rows.len() > limit;
    rows.truncate(limit);
    let cursor = if more {
        rows.last().and_then(|r| r["id"].as_i64())
    } else {
        None
    };
    Ok((rows, cursor))
}
pub(super) async fn audit_page(
    State(a): State<App>,
    h: HeaderMap,
    Query(p): Query<Page>,
) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    let (rows, next) = audit_rows(&a, &p, 200)?;
    Ok(Json(json!({"events":rows,"next_cursor":next})))
}
pub(super) async fn audit_export(
    State(a): State<App>,
    h: HeaderMap,
    Query(mut p): Query<Page>,
) -> Result<Response> {
    admin(&a, &h, false).await?;
    if p.limit.is_none() {
        p.limit = Some(5000);
    }
    let (rows, next) = audit_rows(&a, &p, 5000)?;
    let mut text = String::new();
    for row in rows {
        text.push_str(&row.to_string());
        text.push('\n');
    }
    let mut response = (
        [
            (header::CONTENT_TYPE, "application/x-ndjson"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"forklift-audit.ndjson\"",
            ),
        ],
        text,
    )
        .into_response();
    if let Some(next) = next {
        response.headers_mut().insert(
            "x-next-cursor",
            next.to_string().parse().map_err(anyhow::Error::from)?,
        );
    }
    Ok(response)
}
#[derive(Deserialize)]
pub(super) struct Acknowledgment {
    pub acknowledge: bool,
}
pub(super) async fn revoke_sessions(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Acknowledgment>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    if !p.acknowledge {
        return Err(bad("Acknowledge revoking all administrative sessions"));
    }
    let mut db = a.db.lock().unwrap();
    let tx = db.transaction().map_err(anyhow::Error::from)?;
    tx.execute(
        "INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)",
        params![now(), who, "revoke all sessions", "administration"],
    )
    .map_err(anyhow::Error::from)?;
    tx.execute("DELETE FROM sessions", [])
        .map_err(anyhow::Error::from)?;
    tx.commit().map_err(anyhow::Error::from)?;
    Ok(Json(json!({"revoked":true})))
}
pub(super) async fn complete_recovery(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Acknowledgment>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, false).await?;
    csrf(&a, &h)?;
    if !p.acknowledge {
        return Err(bad(
            "Review original-node fencing, ID allocation and replica quarantine before enabling writes",
        ));
    }
    let _guard = a.gate.lock().await;
    service(&a).await?; // Never complete recovery using a replica alone.
    let mut db = a.db.lock().unwrap();
    let tx = db.transaction().map_err(anyhow::Error::from)?;
    tx.execute("INSERT INTO settings(key,value) VALUES('recovery_required','false') ON CONFLICT(key) DO UPDATE SET value='false'",[]).map_err(anyhow::Error::from)?;
    tx.execute(
        "INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)",
        params![now(), who, "complete recovery review", "installation"],
    )
    .map_err(anyhow::Error::from)?;
    tx.commit().map_err(anyhow::Error::from)?;
    Ok(Json(json!({"recovery_required":false})))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn earlier_migrations_cannot_lower_the_downgrade_guard() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("PRAGMA user_version=4;").unwrap();
        // A crash after either committed migration must still advertise schema 4.
        hosts::migrate(&db).unwrap();
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            4
        );
        replicas::migrate(&db).unwrap();
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            4
        );
    }
    #[test]
    fn upgrade_is_idempotent_and_preserves_existing_state() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE attempts(at INTEGER); CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT); INSERT INTO settings VALUES('preserve','true');").unwrap();
        hosts::migrate(&db).unwrap();
        replicas::migrate(&db).unwrap();
        migrate(&db).unwrap();
        migrate(&db).unwrap();
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            4
        );
        assert_eq!(
            db.query_row("SELECT value FROM settings WHERE key='preserve'", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "true"
        );
    }
}
