//! Fixed LDAP replica jobs, bound to one enrolled identity. No scripts or deployment manifests cross this API.
use super::*;
use rusqlite::OptionalExtension;
#[derive(Clone, Deserialize, Serialize)]
struct Job {
    id: String,
    host_id: String,
    credential_id: String,
    directory_id: String,
    address: String,
    port: u16,
    control_port: u16,
    component: String,
    stage: String,
    error: Option<String>,
    attempt: i64,
    created_at: i64,
    updated_at: i64,
}
pub(super) fn migrate(db: &Connection) -> anyhow::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS client_deployments(host_id TEXT PRIMARY KEY,data TEXT NOT NULL);")?;
    Ok(())
}
fn load(a: &App, id: &str) -> Result<Option<Job>> {
    let raw: Option<String> =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT data FROM client_deployments WHERE host_id=?",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
    raw.map(|s| {
        serde_json::from_str(&s)
            .map_err(anyhow::Error::from)
            .map_err(Error::from)
    })
    .transpose()
}
fn save(a: &App, j: &Job) -> Result<()> {
    a.db.lock().unwrap().execute("INSERT INTO client_deployments(host_id,data) VALUES(?,?) ON CONFLICT(host_id) DO UPDATE SET data=excluded.data",params![j.host_id,serde_json::to_string(j).map_err(anyhow::Error::from)?]).map_err(anyhow::Error::from)?;
    Ok(())
}
pub(super) fn component() -> String {
    let docker = include_str!("../../assets/replica.Dockerfile").to_owned();
    let mut h = Sha256::new();
    h.update(docker.as_bytes());
    h.update([0]);
    h.update(include_bytes!("../../assets/replica.py"));
    hex::encode(h.finalize())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Create {
    address: String,
    port: u16,
    control_port: u16,
    acknowledge: bool,
}
pub(crate) async fn create(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Create>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    replicas::https_required(&a)?;
    if !p.acknowledge || p.port < 1024 || p.control_port < 1024 || p.port == p.control_port {
        return Err(bad(
            "Confirm deployment and choose distinct ports from 1024 to 65535",
        ));
    }
    replica_setup::private_ipv4(&p.address)?;
    let host = hosts::list(&a)?
        .into_iter()
        .find(|v| v.id == id)
        .ok_or(fail(StatusCode::NOT_FOUND, "Host not found"))?;
    let n = by_host(&a, &id)?
        .into_iter()
        .find(|n| n.state == "active")
        .ok_or(bad("Enroll this host first"))?;
    let inventory = monitoring::deployment_inventory(&a, &id, &n.id)?;
    if !inventory
        .capabilities
        .iter()
        .any(|v| v == "replica-deploy-v1")
        || !inventory
            .addresses
            .iter()
            .any(|v| v.address.to_string() == p.address)
    {
        return Err(bad(
            "Wait for a deployment-capable client's inventory and choose one of its current private addresses",
        ));
    }
    if load(&a, &id)?.is_some() {
        return Err(fail(
            StatusCode::CONFLICT,
            "This host already has a deployment; use its retry/cancel controls",
        ));
    }
    let Json(node) = replicas::create(
        State(a.clone()),
        h,
        Json(replicas::Draft {
            name: host.draft.name.clone(),
            address: p.address.clone(),
            hostname: Some(p.address.clone()),
            port: p.port,
            control_port: p.control_port,
            inventory_host_id: Some(id.clone()),
        }),
    )
    .await?;
    let _gate = a.gate.lock().await;
    let j = Job {
        id: token()[..32].into(),
        host_id: id.clone(),
        credential_id: n.id,
        directory_id: node["id"]
            .as_str()
            .ok_or(bad("Directory registration failed"))?
            .into(),
        address: p.address,
        port: p.port,
        control_port: p.control_port,
        component: component(),
        stage: "queued".into(),
        error: None,
        attempt: 1,
        created_at: now(),
        updated_at: now(),
    };
    save(&a, &j)?;
    audit(&a, &who, "queue client LDAP replica deployment", &id)?;
    Ok(Json(json!({"deployment":j})))
}
pub(crate) async fn details(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    let j = load(&a, &id)?;
    let replica = if let Some(j) = &j {
        let health = replicas::health(&a).await?;
        health["servers"]
            .as_array()
            .and_then(|v| v.iter().find(|v| v["id"] == j.directory_id))
            .cloned()
    } else {
        None
    };
    Ok(Json(json!({"deployment":j,"replica":replica})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Action {
    action: String,
    acknowledge: bool,
}
pub(crate) async fn action(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Action>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    let _gate = a.gate.lock().await;
    let mut j = load(&a, &id)?.ok_or(bad("Deployment not found"))?;
    if !p.acknowledge {
        return Err(bad("Confirm deployment operation"));
    }
    match p.action.as_str() {
        "retry" if ["failed", "cancelled"].contains(&j.stage.as_str()) => {
            let n = by_host(&a, &id)?
                .into_iter()
                .find(|n| n.id == j.credential_id && n.state == "active")
                .ok_or(bad("The original client identity must still be active"))?;
            let _ = n;
            j.component = component();
            j.attempt += 1;
            j.stage = "queued".into();
            j.error = None;
        }
        "cancel" if ["queued", "preparing", "failed"].contains(&j.stage.as_str()) => {
            j.stage = "cancelled".into();
            a.db.lock().unwrap().execute("UPDATE directory_servers SET enrollment_hash=NULL,enrollment_expires=0 WHERE id=? AND state='pending'",[&j.directory_id]).map_err(anyhow::Error::from)?;
        }
        _ => {
            return Err(bad(
                "Retry a failed deployment or cancel before service startup; persistent replica data is never removed",
            ));
        }
    }
    j.updated_at = now();
    save(&a, &j)?;
    audit(
        &a,
        &who,
        &format!("client replica deployment {}", p.action),
        &id,
    )?;
    Ok(Json(json!({"deployment":j})))
}
fn authorized(a: &App, h: &HeaderMap, id: &str, route: &str) -> Result<(Enrollment, Option<Job>)> {
    let n = authenticate(a, h, id, route)?;
    rate(a, &format!("deploy:{id}"), 30)?;
    if operations::recovery(a)? {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Complete recovery review before deployment",
        ));
    }
    let j = load(a, id)?.filter(|j| j.credential_id == n.id);
    Ok((n, j))
}
pub(crate) async fn poll(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(_): Json<Empty>,
) -> Result<Json<Value>> {
    let _gate = a.gate.lock().await;
    let (_, j) = authorized(&a, &h, &id, "deployments/poll")?;
    Ok(Json(
        json!({"deployment":j.filter(|j|!["cancelled", "failed", "awaiting_sync"].contains(&j.stage.as_str()))}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Progress {
    job_id: String,
    attempt: i64,
    stage: String,
    error: Option<String>,
}
pub(crate) async fn progress(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Progress>,
) -> Result<Json<Value>> {
    let _gate = a.gate.lock().await;
    let (_, j) = authorized(&a, &h, &id, "deployments/progress")?;
    let mut j = j.ok_or_else(unauthorized)?;
    if j.id != p.job_id || j.attempt != p.attempt || j.stage == "cancelled" {
        return Err(fail(
            StatusCode::CONFLICT,
            "Deployment authorization changed",
        ));
    }
    if !["preparing", "starting", "awaiting_sync", "failed"].contains(&p.stage.as_str())
        || p.error
            .as_ref()
            .is_some_and(|e| e.len() > 300 || e.chars().any(char::is_control))
    {
        return Err(bad("Invalid bounded deployment progress"));
    }
    // Progress can never create synchronization health; only existing LDAP probes can confirm it.
    j.stage = p.stage;
    j.error = p.error;
    j.updated_at = now();
    save(&a, &j)?;
    Ok(Json(json!({"accepted":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Grant {
    job_id: String,
    attempt: i64,
}
pub(crate) async fn grant(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Grant>,
) -> Result<Json<Value>> {
    let _gate = a.gate.lock().await;
    let (_, j) = authorized(&a, &h, &id, "deployments/grant")?;
    let mut j = j.ok_or_else(unauthorized)?;
    if j.id != p.job_id
        || j.attempt != p.attempt
        || ["cancelled", "failed"].contains(&j.stage.as_str())
    {
        return Err(fail(
            StatusCode::CONFLICT,
            "Deployment authorization changed",
        ));
    }
    let node = replicas::records(&a)?
        .into_iter()
        .find(|n| n.id == j.directory_id)
        .ok_or(bad("Replica was removed; deployment cannot continue"))?;
    if node.state == "enrolled" {
        return Ok(Json(json!({"configured":true})));
    }
    if node.state == "redeeming" {
        return Err(fail(
            StatusCode::CONFLICT,
            "Replica enrollment is in progress; retry after checking its state",
        ));
    }
    let (_, enrollment, ca, expiry) = replicas::issue_enrollment(&a, &j.directory_id, "machine")?;
    j.stage = "starting".into();
    j.updated_at = now();
    save(&a, &j)?;
    Ok(Json(
        json!({"configured":false,"enrollment":enrollment,"provider_ca":String::from_utf8(ca).map_err(anyhow::Error::from)?,"expires_at":expiry}),
    ))
}
