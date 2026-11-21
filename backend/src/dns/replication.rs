//! Native PowerDNS primary/secondary provisioning; secrets stay behind the Rust API.
use super::*;
use hmac::{Hmac, Mac};
use rusqlite::OptionalExtension;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Primary {
    address: Ipv4Addr,
    dns_port: u16,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Draft {
    name: String,
    address: Ipv4Addr,
    dns_port: u16,
    control_port: u16,
    zones: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Node {
    id: String,
    draft: Draft,
    revision: i64,
    generation: i64,
    state: String,
    certificate: Option<String>,
    join_hash: Option<String>,
    expires_at: i64,
    last_error: Option<String>,
    checked_at: Option<i64>,
    last_sync_at: Option<i64>,
    report: Value,
    #[serde(default)]
    revoked: bool,
    #[serde(default)]
    pending_generation: Option<i64>,
    #[serde(default)]
    rotation: Option<String>,
    #[serde(default)]
    next_certificate: Option<String>,
    #[serde(default)]
    certificate_staged_at: Option<i64>,
    #[serde(default)]
    certificate_retirement_pending: bool,
}
fn schema(a: &App) -> Result<()> {
    meta(a)?;
    a.db.lock()
        .unwrap()
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS dns_servers(id TEXT PRIMARY KEY,data TEXT NOT NULL);",
        )
        .map_err(anyhow::Error::from)?;
    Ok(())
}
fn nodes(a: &App) -> Result<Vec<Node>> {
    schema(a)?;
    let db = a.db.lock().unwrap();
    let mut q = db
        .prepare("SELECT data FROM dns_servers ORDER BY id")
        .map_err(anyhow::Error::from)?;
    let rows = q
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(anyhow::Error::from)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?;
    rows.into_iter()
        .map(|s| {
            serde_json::from_str(&s)
                .map_err(anyhow::Error::from)
                .map_err(Error::from)
        })
        .collect()
}
fn load(a: &App, id: &str) -> Result<Node> {
    nodes(a)?
        .into_iter()
        .find(|n| n.id == id)
        .ok_or(bad("DNS server not found"))
}
fn store(a: &App, n: &Node) -> Result<()> {
    a.db.lock().unwrap().execute("INSERT INTO dns_servers(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",params![n.id,serde_json::to_string(n).map_err(anyhow::Error::from)?]).map_err(anyhow::Error::from)?;
    Ok(())
}
fn public(n: &Node) -> Value {
    json!({"id":n.id,"name":n.draft.name,"address":n.draft.address,"dns_port":n.draft.dns_port,"control_port":n.draft.control_port,"zones":n.draft.zones,"revision":n.revision,"state":n.state,"expires_at":n.expires_at,"checked_at":n.checked_at,"last_sync_at":n.last_sync_at,"report":n.report,"error":n.last_error,"transfers_revoked":n.revoked,"credential_epoch":n.generation,"pending_epoch":n.pending_generation,"rotation":n.rotation,"certificate_rotation_pending":n.next_certificate.is_some()||n.certificate_retirement_pending,"certificate_staged_at":n.certificate_staged_at,"certificate_expires_at":n.certificate.as_ref().and_then(|c|openssl::x509::X509::from_pem(c.as_bytes()).ok()).map(|c|c.not_after().to_string())})
}
fn primary(a: &App) -> Result<Option<Primary>> {
    let raw =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key='dns_primary'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
    raw.map(|v| serde_json::from_str(&v))
        .transpose()
        .map_err(anyhow::Error::from)
        .map_err(Error::from)
}
fn private(address: Ipv4Addr, port: u16) -> Result<()> {
    if !address.is_private() || port == 0 {
        return Err(bad("Use a private IPv4 address and a port from 1 to 65535"));
    }
    Ok(())
}
async fn validate_draft(p: &mut Draft) -> Result<()> {
    private(p.address, p.dns_port)?;
    if p.name.trim().is_empty()
        || p.name.len() > 100
        || p.name.chars().any(char::is_control)
        || p.control_port == 0
        || p.control_port == p.dns_port
    {
        return Err(bad(
            "Choose a name and distinct DNS/private management ports",
        ));
    }
    if p.zones.len() > 32 {
        return Err(bad("Assign at most 32 zones per DNS secondary"));
    }
    for z in &mut p.zones {
        *z = name(z, false)?;
        managed(&zone(z).await?)?;
    }
    p.zones.sort();
    p.zones.dedup();
    Ok(())
}
fn derived(n: &Node, purpose: &str) -> Vec<u8> {
    derived_at(n, purpose, n.generation)
}
fn derived_at(n: &Node, purpose: &str, generation: i64) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret("node-control-key").as_bytes())
        .expect("Installation key");
    mac.update(format!("forklift/dns/v1/{purpose}/{}/{}", n.id, generation).as_bytes());
    mac.finalize().into_bytes().to_vec()
}
fn key_name(n: &Node) -> String {
    key_at(n, n.generation)
}
fn key_at(n: &Node, generation: i64) -> String {
    format!("forklift-dns-{}-{}.", n.id, generation)
}
fn generations(n: &Node) -> Vec<i64> {
    std::iter::once(n.generation)
        .chain(n.pending_generation)
        .collect()
}
fn transition(n: &Node) -> bool {
    n.rotation.is_some() || n.next_certificate.is_some() || n.certificate_retirement_pending
}
fn configuration(a: &App, n: &Node) -> Result<Value> {
    let primary = primary(a)?.ok_or(bad("Configure the reachable primary DNS endpoint first"))?;
    Ok(
        json!({"id":n.id,"revision":n.revision,"credential_epoch":n.generation,"address":n.draft.address,"dns_port":n.draft.dns_port,"control_port":n.draft.control_port,"primary":primary,"zones":n.draft.zones,"tsig_name":key_name(n),"tsig_key":openssl::base64::encode_block(&derived(n,"transfer")),"control_token":hex::encode(derived(n,"control"))}),
    )
}
async fn remote(n: &Node, path: &str, body: Value) -> Result<Value> {
    remote_as(n, path, body, None).await
}
async fn current_software(n: &Node) -> Result<()> {
    let health = remote(n, "/health", json!({"id":n.id})).await?;
    if health["protocol"] != 2 {
        return Err(bad(
            "Update the DNS secondary from the current Forklift repository and recreate its container with the same volume before rotating its credentials or certificate.",
        ));
    }
    Ok(())
}
async fn remote_as(n: &Node, path: &str, body: Value, epoch: Option<i64>) -> Result<Value> {
    let cert = n
        .certificate
        .as_ref()
        .ok_or(bad("Enroll the DNS server first"))?;
    let mut builder = reqwest::Client::builder()
        .use_native_tls()
        .tls_built_in_root_certs(false)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(45));
    for cert in std::iter::once(cert).chain(n.next_certificate.as_ref()) {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(cert.as_bytes()).map_err(anyhow::Error::from)?,
        );
    }
    let client = builder.build().map_err(anyhow::Error::from)?;
    for generation in epoch.map(|g| vec![g]).unwrap_or_else(|| generations(n)) {
        let mut response=client.post(format!("https://{}:{}{path}",n.draft.address,n.draft.control_port)).bearer_auth(hex::encode(derived_at(n,"control",generation))).json(&body).send().await.map_err(|_|unavailable("Cannot reach the DNS secondary's pinned HTTPS management listener. Check its private interface, port, certificate and firewall."))?;
        if response.status() == StatusCode::UNAUTHORIZED {
            continue;
        }
        if !response.status().is_success() {
            return Err(unavailable(
                "DNS secondary refused provisioning; review its pending transition and retry with its current credentials",
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(anyhow::Error::from)? {
            if bytes.len() + chunk.len() > 131072 {
                return Err(bad("DNS secondary diagnostics exceed their limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        return serde_json::from_slice(&bytes)
            .map_err(anyhow::Error::from)
            .map_err(Error::from);
    }
    Err(unavailable(
        "DNS secondary rejected its recorded credentials; resume its pending credential rotation",
    ))
}
async fn metadata(z: &str, kind: &str, values: Value) -> Result<()> {
    request(
        Method::PUT,
        &format!("{}/metadata/{kind}", zone_path(z)),
        Some(&json!({"kind":kind,"metadata":values})),
    )
    .await?;
    Ok(())
}
async fn provision_primary(a: &App) -> Result<()> {
    let enrolled = nodes(a)?
        .into_iter()
        .filter(|n| n.state == "enrolled")
        .collect::<Vec<_>>();
    let keys = request(Method::GET, "/tsigkeys", None)
        .await?
        .as_array()
        .cloned()
        .ok_or(unavailable("Invalid native DNS transfer-key response"))?;
    for n in &enrolled {
        for generation in generations(n) {
            let key = key_at(n, generation);
            let payload = json!({"name":key,"algorithm":"hmac-sha256","key":openssl::base64::encode_block(&derived_at(n,"transfer",generation))});
            request(
                if keys.iter().any(|k| k["id"] == key) {
                    Method::PUT
                } else {
                    Method::POST
                },
                &if keys.iter().any(|k| k["id"] == key) {
                    format!("/tsigkeys/{key}")
                } else {
                    "/tsigkeys".into()
                },
                Some(&payload),
            )
            .await?;
        }
    }
    for z in zones().await? {
        if managed(&z).is_err() {
            continue;
        }
        let name = z["name"].as_str().ok_or(bad("Invalid zone name"))?;
        let peers = enrolled
            .iter()
            .filter(|n| n.draft.zones.iter().any(|v| v == name))
            .collect::<Vec<_>>();
        // Forklift-owned zones have no IP-based transfer exception: a valid assigned TSIG is required.
        metadata(name, "ALLOW-AXFR-FROM", json!([])).await?;
        request(Method::PUT,&zone_path(name),Some(&json!({"kind":if peers.is_empty(){"Native"}else{"Primary"},"master_tsig_key_ids":peers.iter().flat_map(|n|generations(n).into_iter().map(|g|key_at(n,g))).collect::<Vec<_>>()}))).await?;
        metadata(
            name,
            "ALSO-NOTIFY",
            json!(
                peers
                    .iter()
                    .map(|n| format!("{}:{}", n.draft.address, n.draft.dns_port))
                    .collect::<Vec<_>>()
            ),
        )
        .await?;
    }
    for key in keys {
        if key["name"]
            .as_str()
            .is_some_and(|k| k.starts_with("forklift-dns-"))
            && !enrolled
                .iter()
                .any(|n| generations(n).iter().any(|g| key["id"] == key_at(n, *g)))
        {
            let id = key["id"].as_str().ok_or(bad("Invalid transfer key ID"))?;
            request(Method::DELETE, &format!("/tsigkeys/{id}"), None).await?;
        }
    }
    Ok(())
}
async fn apply_node(a: &App, n: &mut Node) -> Result<()> {
    let existing = zones()
        .await?
        .into_iter()
        .filter_map(|z| z["name"].as_str().map(str::to_owned))
        .collect::<HashSet<_>>();
    let before = n.draft.zones.len();
    n.draft.zones.retain(|name| existing.contains(name));
    if before != n.draft.zones.len() {
        n.revision += 1;
        store(a, n)?;
    }
    provision_primary(a).await?;
    remote(
        n,
        "/configure",
        json!({"id":n.id,"configuration":configuration(a,n)?}),
    )
    .await?;
    n.last_error = None;
    n.report = json!({"state":"awaiting_verification"});
    store(a, n)
}
pub(crate) async fn after_zone_change(a: &App, who: &str) {
    let outcome = async {
        let names = zones()
            .await?
            .iter()
            .filter_map(|z| z["name"].as_str().map(str::to_owned))
            .collect::<HashSet<_>>();
        for mut n in nodes(a)?.into_iter().filter(|n| n.state == "enrolled") {
            let old = n.draft.zones.len();
            n.draft.zones.retain(|z| names.contains(z));
            if old != n.draft.zones.len() {
                n.revision += 1;
                store(a, &n)?;
                if let Err(e) = apply_node(a, &mut n).await {
                    n.last_error = Some(e.1);
                    n.report = json!({"state":"needs_reconcile"});
                    store(a, &n)?;
                    audit(a, who, "DNS failed secondary assignment", &n.id)?;
                }
            }
        }
        Ok::<_, Error>(())
    }
    .await;
    if outcome.is_err() {
        let _ = audit(
            a,
            who,
            "DNS failed replication reconciliation",
            "Review DNS Servers and retry reconciliation",
        );
    }
}
pub(crate) async fn index(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    authorize(&a, &h, false).await?;
    Ok(Json(
        json!({"primary":primary(&a)?,"servers":nodes(&a)?.iter().map(public).collect::<Vec<_>>()}),
    ))
}
#[derive(Deserialize)]
pub(crate) struct PrimaryInput {
    address: Ipv4Addr,
    dns_port: u16,
    acknowledge: bool,
}
pub(crate) async fn set_primary(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<PrimaryInput>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    private(p.address, p.dns_port)?;
    if !p.acknowledge {
        return Err(bad(
            "Confirm that the primary DNS endpoint is reachable over both TCP and UDP from the new machine",
        ));
    }
    let _guard = a.gate.lock().await;
    if nodes(&a)?.iter().any(transition) {
        return Err(bad(
            "Finish DNS credential/certificate transitions before changing the primary endpoint",
        ));
    }
    let value = Primary {
        address: p.address,
        dns_port: p.dns_port,
    };
    if nodes(&a)?
        .iter()
        .any(|n| n.draft.address == p.address && n.draft.dns_port == p.dns_port)
    {
        return Err(bad(
            "The primary DNS endpoint cannot be a registered secondary endpoint",
        ));
    }
    a.db.lock().unwrap().execute("INSERT INTO settings(key,value) VALUES('dns_primary',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[json!(value).to_string()]).map_err(anyhow::Error::from)?;
    for mut n in nodes(&a)?.into_iter().filter(|n| n.state == "enrolled") {
        n.revision += 1;
        n.last_error = Some("Primary endpoint changed; reconcile this DNS secondary".into());
        n.report = json!({"state":"needs_reconcile"});
        store(&a, &n)?;
    }
    audit(
        &a,
        &who,
        "DNS configure primary endpoint",
        &format!("{}:{}", p.address, p.dns_port),
    )?;
    Ok(Json(json!({"saved":true})))
}
pub(crate) async fn create(
    State(a): State<App>,
    h: HeaderMap,
    Json(mut p): Json<Draft>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    if primary(&a)?.is_none() {
        return Err(bad("Configure a reachable primary DNS address first"));
    }
    validate_draft(&mut p).await?;
    let all = nodes(&a)?;
    if all.len() >= 8 {
        return Err(bad("This release supports up to eight DNS secondaries"));
    }
    if all.iter().any(|n| {
        n.draft.address == p.address
            && (n.draft.dns_port == p.dns_port
                || n.draft.control_port == p.control_port
                || n.draft.dns_port == p.control_port
                || n.draft.control_port == p.dns_port)
    }) {
        return Err(bad(
            "A DNS node already uses one of these private listener ports",
        ));
    }
    if primary(&a)?.is_some_and(|v| {
        v.address == p.address && (v.dns_port == p.dns_port || v.dns_port == p.control_port)
    }) {
        return Err(bad(
            "The secondary needs its own DNS and management listener ports",
        ));
    }
    let n = Node {
        id: token()[..32].into(),
        draft: p,
        revision: 1,
        generation: 0,
        state: "pending".into(),
        certificate: None,
        join_hash: None,
        expires_at: 0,
        last_error: None,
        checked_at: None,
        last_sync_at: None,
        report: json!({"state":"not_enrolled"}),
        revoked: false,
        pending_generation: None,
        rotation: None,
        next_certificate: None,
        certificate_staged_at: None,
        certificate_retirement_pending: false,
    };
    store(&a, &n)?;
    audit(&a, &who, "DNS register secondary", &n.id)?;
    Ok(Json(public(&n)))
}
#[derive(Deserialize)]
pub(crate) struct Join {
    acknowledge: bool,
    manager_ca: Option<String>,
}
pub(crate) async fn deployment(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Join>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    if !public_url(&a).starts_with("https://") {
        return Err(bad(
            "Configure the Forklift public HTTPS URL before DNS enrollment",
        ));
    }
    if !p.acknowledge {
        return Err(bad(
            "Acknowledge protecting the short-lived join credential",
        ));
    }
    if let Some(ca) = &p.manager_ca
        && (ca.len() > 65536
            || ca.contains("PRIVATE KEY")
            || ca
                .replace("-----BEGIN CERTIFICATE-----", "")
                .contains("-----BEGIN")
            || openssl::x509::X509::stack_from_pem(ca.as_bytes())
                .ok()
                .is_none_or(|v| v.is_empty()))
    {
        return Err(bad(
            "Provide public HTTPS CA certificates only, or leave the field empty for system trust",
        ));
    }
    let _guard = a.gate.lock().await;
    let mut n = load(&a, &id)?;
    if !["pending", "failed"].contains(&n.state.as_str()) {
        return Err(bad(
            "This node already enrolled; use reconciliation or remove it before enrolling a replacement",
        ));
    }
    n.generation += 1;
    n.state = "pending".into();
    n.expires_at = now() + 900;
    let raw = token();
    n.join_hash = Some(digest(&raw));
    n.last_error = None;
    store(&a, &n)?;
    let envelope = json!({"version":1,"enrollment":{"id":n.id,"address":n.draft.address,"dns_port":n.draft.dns_port,"control_port":n.draft.control_port,"manager_url":public_url(&a),"token":raw,"expires_at":n.expires_at},"manager_ca":p.manager_ca});
    audit(&a, &who, "DNS issue secondary enrollment", &id)?;
    Ok(Json(
        json!({"join_config":format!("FORKLIFT_DNS_JOIN={}",openssl::base64::encode_block(&serde_json::to_vec(&envelope).map_err(anyhow::Error::from)?)),"expires_at":n.expires_at}),
    ))
}
#[derive(Deserialize)]
pub(crate) struct Enrollment {
    token: String,
    certificate: String,
}
pub(crate) async fn enroll(
    State(a): State<App>,
    Path(id): Path<String>,
    Json(p): Json<Enrollment>,
) -> Result<Json<Value>> {
    if !public_url(&a).starts_with("https://") {
        return Err(bad("DNS enrollment requires HTTPS"));
    }
    let _guard = a.gate.lock().await;
    let mut n = load(&a, &id)?;
    if n.state != "pending"
        || n.expires_at <= now()
        || p.token.len() != 64
        || n.join_hash.as_deref() != Some(digest(&p.token).as_str())
    {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Invalid or expired DNS enrollment".into(),
        ));
    }
    if operations::recovery(&a)? {
        return Err(unavailable(
            "Complete recovery review before DNS enrollment",
        ));
    }
    replicas::validate_certificate(&p.certificate, &n.draft.address.to_string())?;
    n.join_hash = None;
    n.state = "enrolled".into();
    n.certificate = Some(p.certificate);
    store(&a, &n)?;
    if let Err(e) = provision_primary(&a).await {
        n.state = "failed".into();
        n.last_error = Some(e.1.clone());
        store(&a, &n)?;
        audit(&a, "enrollment", "DNS failed secondary enrollment", &id)?;
        return Err(e);
    }
    audit(&a, "enrollment", "DNS enroll secondary", &id)?;
    Ok(Json(configuration(&a, &n)?))
}
#[derive(Deserialize)]
pub(crate) struct Assign {
    zones: Vec<String>,
    revision: i64,
}
pub(crate) async fn assignments(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Assign>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    let mut n = load(&a, &id)?;
    if transition(&n) {
        return Err(bad(
            "Finish the pending DNS identity rotation before editing assignments",
        ));
    }
    if n.revision != p.revision || n.state != "enrolled" {
        return Err(Error(
            StatusCode::CONFLICT,
            "Refresh this enrolled DNS node before changing its assignments".into(),
        ));
    }
    n.draft.zones = p.zones;
    validate_draft(&mut n.draft).await?;
    n.revision += 1;
    n.last_error = Some("Zone assignments changed; reconcile this node to apply them".into());
    n.report = json!({"state":"needs_reconcile"});
    store(&a, &n)?;
    audit(&a, &who, "DNS change secondary assignments", &id)?;
    Ok(Json(public(&n)))
}
pub(crate) async fn reconcile(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    let mut n = load(&a, &id)?;
    if n.state != "enrolled" {
        return Err(bad("Enroll the DNS node before reconciling it"));
    }
    if transition(&n) {
        return Err(bad(
            "Resume the pending DNS credential/certificate operation before reconciliation",
        ));
    }
    match apply_node(&a, &mut n).await {
        Ok(()) => audit(&a, &who, "DNS reconcile secondary", &id)?,
        Err(e) => {
            n.last_error = Some(e.1);
            n.report = json!({"state":"needs_reconcile"});
            store(&a, &n)?;
            audit(&a, &who, "DNS failed secondary reconciliation", &id)?;
        }
    }
    Ok(Json(public(&n)))
}
pub(crate) async fn check(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    let mut n = load(&a, &id)?;
    if n.state != "enrolled" {
        return Err(bad("Enroll the DNS node before checking synchronization"));
    }
    let primary_zones = zones().await.ok();
    match remote(&n, "/inspect", json!({"id":id})).await {
        Ok(mut report) => {
            let mut synchronized = !n.draft.zones.is_empty() && report["revision"] == n.revision;
            for item in report["zones"]
                .as_array_mut()
                .ok_or(bad("Invalid secondary diagnostics"))?
            {
                let current = primary_zones
                    .as_ref()
                    .and_then(|zs| zs.iter().find(|z| z["name"] == item["name"]))
                    .and_then(|z| z["serial"].as_u64());
                let good = current.is_some()
                    && item["kind"] == "Secondary"
                    && item["udp"]["authoritative"] == true
                    && item["tcp"]["authoritative"] == true
                    && item["primary"]["authoritative"] == true
                    && item["udp"]["serial"].as_u64() == current
                    && item["tcp"]["serial"].as_u64() == current
                    && item["primary"]["serial"].as_u64() == current;
                item["synchronized"] = json!(good);
                item["expected_serial"] = json!(current);
                synchronized &= good;
            }
            synchronized &= report["zones"].as_array().is_some_and(|zs| {
                zs.len() == n.draft.zones.len()
                    && n.draft
                        .zones
                        .iter()
                        .all(|name| zs.iter().any(|z| z["name"] == *name))
            });
            let state = if transition(&n) {
                "rotation_pending"
            } else if report["revision"] != n.revision {
                "needs_reconcile"
            } else if synchronized {
                "synchronized"
            } else if n.draft.zones.is_empty() {
                "no_zones"
            } else if primary_zones.is_none() {
                "primary_unavailable"
            } else {
                "not_synchronized"
            };
            report["state"] = json!(state);
            n.checked_at = Some(now());
            if synchronized {
                n.last_sync_at = Some(now());
            }
            n.last_error = if synchronized || state == "no_zones" {
                None
            } else {
                Some("Synchronization is not confirmed. Review per-zone serials/reachability and reconcile if configuration changed.".into())
            };
            n.report = report;
        }
        Err(e) => {
            n.checked_at = Some(now());
            n.last_error = Some(e.1);
            n.report = json!({"state":"management_unavailable","api_available":null});
        }
    }
    store(&a, &n)?;
    audit(&a, &who, "DNS check secondary", &id)?;
    Ok(Json(public(&n)))
}
#[derive(Deserialize)]
pub(crate) struct Remove {
    acknowledge: bool,
    #[serde(default)]
    retain_data: bool,
}
pub(crate) async fn remove(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Remove>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    if !p.acknowledge {
        return Err(bad(
            "Confirm revoking this DNS node's transfers and removing its assignments",
        ));
    }
    let _guard = a.gate.lock().await;
    let mut n = load(&a, &id)?;
    let restored = n.state == "restore_required" || n.report["state"] == "restore_required";
    n.state = "removing".into();
    n.join_hash = None;
    n.revision += 1;
    store(&a, &n)?;
    let result = async {
        provision_primary(&a).await?;
        n.revoked = true;
        store(&a, &n)?;
        if !restored && !p.retain_data && n.certificate.is_some() {
            n.draft.zones.clear();
            let mut active = n.clone();
            active.generation = n.pending_generation.unwrap_or(n.generation);
            remote(
                &n,
                "/configure",
                json!({"id":id,"configuration":configuration(&a,&active)?}),
            )
            .await?;
        }
        Ok::<_, Error>(())
    }
    .await;
    if let Err(e) = result {
        n.last_error = Some(e.1);
        store(&a, &n)?;
        audit(&a, &who, "DNS failed secondary removal", &id)?;
        return Ok(Json(json!({"removed":false,"server":public(&n)})));
    }
    a.db.lock()
        .unwrap()
        .execute("DELETE FROM dns_servers WHERE id=?", [&id])
        .map_err(anyhow::Error::from)?;
    audit(&a, &who, "DNS remove secondary", &id)?;
    Ok(Json(json!({"removed":true})))
}

fn fingerprint(pem: &str) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        openssl::x509::X509::from_pem(pem.as_bytes())
            .map_err(anyhow::Error::from)?
            .to_der()
            .map_err(anyhow::Error::from)?,
    )))
}
#[derive(Deserialize)]
pub(crate) struct Acknowledge {
    acknowledge: bool,
}
pub(crate) async fn credentials(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Acknowledge>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    if !p.acknowledge {
        return Err(bad(
            "Confirm rotating DNS transfer and management credentials",
        ));
    }
    let _guard = a.gate.lock().await;
    let mut n = load(&a, &id)?;
    if n.state != "enrolled" || n.next_certificate.is_some() || n.certificate_retirement_pending {
        return Err(bad(
            "Use an enrolled node without a pending certificate operation",
        ));
    }
    let result=async {
        if n.rotation.as_deref()!=Some("retire_old") {
            current_software(&n).await?;
            if n.pending_generation.is_none(){n.pending_generation=Some(n.generation+1);n.rotation=Some("prepare".into());n.revision+=1;store(&a,&n)?;audit(&a,&who,"DNS attempt credential rotation",&id)?;}
            provision_primary(&a).await?;
            let epoch=n.pending_generation.ok_or(bad("Missing DNS rotation journal"))?;
            let mut next=n.clone();next.generation=epoch;
            remote(&n,"/credentials",json!({"id":id,"configuration":configuration(&a,&next)?})).await?;
            n.rotation=Some("verify_new".into());store(&a,&n)?;
            let proof=remote_as(&n,"/credentials/verify",json!({"id":id,"credential_epoch":epoch}),Some(epoch)).await?;
            if proof["credential_epoch"]!=epoch||!proof["transfers"].as_array().is_some_and(|rows|rows.len()==n.draft.zones.len()&&n.draft.zones.iter().all(|z|rows.iter().any(|r|r["name"]==*z&&r["verified"]==true))) {return Err(unavailable("The new DNS transfer credential is not confirmed. Keep overlap and retry after the primary is reachable."));}
            n.generation=epoch;n.pending_generation=None;n.rotation=Some("retire_old".into());store(&a,&n)?;
        }
        provision_primary(&a).await?;
        n.rotation=None;n.last_error=None;n.report=json!({"state":"awaiting_verification"});store(&a,&n)?;audit(&a,&who,"DNS rotate secondary credentials",&id)?;Ok::<_,Error>(())
    }.await;
    if let Err(error) = result {
        n.last_error = Some(error.1);
        store(&a, &n)?;
        audit(&a, &who, "DNS failed credential rotation", &id)?;
    }
    Ok(Json(public(&n)))
}
pub(crate) async fn certificate(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Acknowledge>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    if !p.acknowledge {
        return Err(bad(
            "Confirm staging a new pinned DNS management certificate",
        ));
    }
    let _guard = a.gate.lock().await;
    let mut n = load(&a, &id)?;
    if n.state != "enrolled" || n.rotation.is_some() || n.certificate_retirement_pending {
        return Err(bad("Finish the pending DNS identity transition first"));
    }
    if n.next_certificate.is_none() {
        current_software(&n).await?;
        audit(&a, &who, "DNS attempt certificate staging", &id)?;
        let generated = remote(&n, "/certificate/stage", json!({"id":id})).await?;
        let pem = generated["certificate"]
            .as_str()
            .ok_or(bad("DNS node did not return a public certificate"))?;
        replicas::validate_certificate(pem, &n.draft.address.to_string())?;
        if fingerprint(pem)? == fingerprint(n.certificate.as_deref().unwrap_or(""))? {
            return Err(bad(
                "DNS node returned its current certificate instead of a new identity",
            ));
        }
        n.next_certificate = Some(pem.into());
        n.certificate_staged_at = Some(now());
        store(&a, &n)?;
        audit(&a, &who, "DNS stage secondary certificate", &id)?;
    }
    Ok(Json(public(&n)))
}
pub(crate) async fn finalize_certificate(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Acknowledge>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    if !p.acknowledge {
        return Err(bad(
            "Confirm activating the staged DNS certificate and retiring old trust",
        ));
    }
    let _guard = a.gate.lock().await;
    let mut n = load(&a, &id)?;
    if n.state != "enrolled"
        || n.rotation.is_some()
        || n.next_certificate.is_none() && !n.certificate_retirement_pending
    {
        return Err(bad("Stage a DNS certificate before activation"));
    }
    let result=async {
        if let Some(next)=n.next_certificate.clone(){
            remote(&n,"/certificate/activate",json!({"id":id,"fingerprint":fingerprint(&next)?})).await?;
            let mut pinned=n.clone();pinned.certificate=Some(next.clone());pinned.next_certificate=None;
            let healthy=remote(&pinned,"/health",json!({"id":id})).await?;
            if healthy["api_available"]!=true{return Err(unavailable("The new DNS TLS identity did not confirm a healthy service; keep staged trust and retry"));}
            n.certificate=Some(next);n.next_certificate=None;n.certificate_retirement_pending=true;store(&a,&n)?;
        }
        remote(&n,"/certificate/retire",json!({"id":id,"fingerprint":fingerprint(n.certificate.as_deref().unwrap_or(""))?})).await?;
        n.certificate_retirement_pending=false;n.certificate_staged_at=None;n.last_error=None;store(&a,&n)?;audit(&a,&who,"DNS activate secondary certificate",&id)?;Ok::<_,Error>(())
    }.await;
    if let Err(error) = result {
        n.last_error = Some(error.1);
        store(&a, &n)?;
        audit(&a, &who, "DNS failed certificate activation", &id)?;
    }
    Ok(Json(public(&n)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_peer_endpoints_stay_on_private_unicast_networks() {
        assert!(private(Ipv4Addr::new(192, 168, 1, 2), 53).is_ok());
        for address in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(private(address, 53).is_err());
        }
        assert!(private(Ipv4Addr::new(192, 168, 1, 2), 0).is_err());
    }
}
