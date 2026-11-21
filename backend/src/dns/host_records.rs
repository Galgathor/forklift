//! Host lifecycle intents and per-value ownership. LDAP/host saves are never DNS transactions.
use super::*;
use rusqlite::{OptionalExtension, Transaction};

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub zone: String,
    pub fqdn: String,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    #[serde(default)]
    pub reverse: bool,
}
impl Config {
    pub fn normalize(mut self) -> Result<Self> {
        self.zone = name(&self.zone, false)?;
        self.fqdn = name(&owner(&self.fqdn, &self.zone)?, false)?;
        if self.zone.ends_with(".arpa.") {
            return Err(bad("Select a forward zone for host registration"));
        }
        if self.ipv4.is_unspecified()
            || self.ipv4.is_multicast()
            || self.ipv4 == Ipv4Addr::BROADCAST
            || self
                .ipv6
                .is_some_and(|v| v.is_unspecified() || v.is_multicast())
        {
            return Err(bad(
                "Use unicast host addresses; unspecified, multicast and broadcast addresses are not valid host registrations",
            ));
        }
        Ok(self)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Status {
    pub state: String,
    pub error: Option<String>,
    pub warnings: Vec<String>,
    pub operation_id: Option<String>,
    pub managed_values: usize,
    pub checked_at: Option<i64>,
}
impl Status {
    pub fn failed(message: &str) -> Self {
        Self {
            state: "needs_retry".into(),
            error: Some(message.into()),
            warnings: vec![],
            operation_id: None,
            managed_values: 0,
            checked_at: None,
        }
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct Binding {
    zone: String,
    name: String,
    rr_type: String,
    value: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct State {
    id: String,
    label: String,
    desired: Option<Config>,
    revision: i64,
    bindings: Vec<Binding>,
    deleted: bool,
    status: Status,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Completion {
    host_id: String,
    revision: i64,
    desired: Option<Config>,
    deleted: bool,
    bindings: Vec<Binding>,
    warnings: Vec<String>,
}
fn ensure(a: &App) -> Result<()> {
    meta(a)?;
    a.db.lock()
        .unwrap()
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS host_dns(id TEXT PRIMARY KEY,data TEXT NOT NULL);",
        )
        .map_err(anyhow::Error::from)?;
    Ok(())
}
fn all(a: &App) -> Result<Vec<State>> {
    ensure(a)?;
    let db = a.db.lock().unwrap();
    let mut query = db
        .prepare("SELECT data FROM host_dns")
        .map_err(anyhow::Error::from)?;
    let data = query
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(anyhow::Error::from)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?;
    data.into_iter()
        .map(|v| {
            serde_json::from_str(&v)
                .map_err(anyhow::Error::from)
                .map_err(Error::from)
        })
        .collect()
}
fn get(a: &App, id: &str) -> Result<Option<State>> {
    Ok(all(a)?.into_iter().find(|v| v.id == id))
}
fn store_tx(tx: &Transaction<'_>, state: &State) -> Result<()> {
    tx.execute("INSERT INTO host_dns(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",params![state.id,serde_json::to_string(state).map_err(anyhow::Error::from)?]).map_err(anyhow::Error::from)?;
    Ok(())
}
fn store(a: &App, state: &State) -> Result<()> {
    let mut db = a.db.lock().unwrap();
    let tx = db.transaction().map_err(anyhow::Error::from)?;
    store_tx(&tx, state)?;
    tx.commit().map_err(anyhow::Error::from)?;
    Ok(())
}
fn pending_status(values: usize) -> Status {
    Status {
        state: "needs_apply".into(),
        error: None,
        warnings: vec![],
        operation_id: None,
        managed_values: values,
        checked_at: None,
    }
}
pub(crate) fn validate_unique(a: &App, id: &str, config: Option<&Config>) -> Result<()> {
    if let Some(config) = config {
        if all(a)?.iter().any(|s| {
            s.id != id && !s.deleted && s.desired.as_ref().is_some_and(|c| c.fqdn == config.fqdn)
        }) {
            return Err(bad("This DNS name is already assigned to another host"));
        }
        // The host row remains authoritative if a prior save stopped before recording its DNS intent.
        let db = a.db.lock().unwrap();
        let mut q = db
            .prepare("SELECT id,data FROM hosts")
            .map_err(anyhow::Error::from)?;
        for row in q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(anyhow::Error::from)?
        {
            let (other, data) = row.map_err(anyhow::Error::from)?;
            if other != id
                && serde_json::from_str::<Value>(&data)
                    .ok()
                    .is_some_and(|h| h["dns"]["fqdn"] == config.fqdn)
            {
                return Err(bad("This DNS name is already assigned to another host"));
            }
        }
    }
    Ok(())
}
pub(crate) fn status(
    a: &App,
    id: &str,
    config: Option<&Config>,
    revision: i64,
) -> Result<Option<Status>> {
    // Read-only inventory queries must not require a DNS schema or a working DNS daemon.
    let db = a.db.lock().unwrap();
    let exists = db
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='host_dns'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map_err(anyhow::Error::from)?;
    if exists == 0 {
        return Ok(config.map(|_| pending_status(0)));
    }
    let state = db
        .query_row("SELECT data FROM host_dns WHERE id=?", [id], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .map_err(anyhow::Error::from)?
        .map(|v| serde_json::from_str::<State>(&v))
        .transpose()
        .map_err(anyhow::Error::from)?;
    Ok(match state {
        Some(state) if state.revision == revision && state.desired.as_ref() == config => {
            Some(state.status)
        }
        Some(state) => Some(pending_status(state.bindings.len())),
        None => config.map(|_| pending_status(0)),
    })
}
fn cancel(tx: &Transaction<'_>, state: &State) -> Result<()> {
    if let Some(operation) = &state.status.operation_id {
        tx.execute("UPDATE dns_changes SET status='completed',error='Superseded host intent; applied values retained for ownership-checked reconciliation' WHERE id=? AND status!='completed'",[operation]).map_err(anyhow::Error::from)?;
    }
    Ok(())
}
pub(crate) fn intent(a: &App, host: &hosts::Host) -> Result<()> {
    ensure(a)?;
    let old = get(a, &host.id)?;
    let bindings = old.as_ref().map(|s| s.bindings.clone()).unwrap_or_default();
    let state = State {
        id: host.id.clone(),
        label: host.draft.name.clone(),
        desired: host.dns.clone(),
        revision: host.revision,
        bindings: bindings.clone(),
        deleted: false,
        status: pending_status(bindings.len()),
    };
    let mut db = a.db.lock().unwrap();
    let tx = db.transaction().map_err(anyhow::Error::from)?;
    if let Some(old) = old {
        cancel(&tx, &old)?;
    }
    store_tx(&tx, &state)?;
    tx.commit().map_err(anyhow::Error::from)?;
    Ok(())
}
pub(crate) fn retire(a: &App, host: &hosts::Host, remove: bool) -> Result<()> {
    ensure(a)?;
    let mut state = get(a, &host.id)?.unwrap_or(State {
        id: host.id.clone(),
        label: host.draft.name.clone(),
        desired: host.dns.clone(),
        revision: host.revision,
        bindings: vec![],
        deleted: false,
        status: pending_status(0),
    });
    let mut db = a.db.lock().unwrap();
    let tx = db.transaction().map_err(anyhow::Error::from)?;
    cancel(&tx, &state)?;
    state.desired = None;
    state.deleted = true;
    state.revision = host.revision;
    state.status = pending_status(state.bindings.len());
    if !remove {
        state.bindings.clear();
        state.status.state = "retained".into();
        state.status.managed_values = 0;
    }
    store_tx(&tx, &state)?;
    tx.execute("DELETE FROM hosts WHERE id=?", [&host.id])
        .map_err(anyhow::Error::from)?;
    tx.commit().map_err(anyhow::Error::from)?;
    Ok(())
}
pub(crate) fn detach(a: &App, host: &hosts::Host) -> Result<()> {
    intent(a, host)?;
    let mut state = get(a, &host.id)?.unwrap();
    state.bindings.clear();
    state.status = pending_status(0);
    state.status.state = "retained".into();
    store(a, &state)
}
fn marker(id: &str) -> String {
    format!("forklift-host:{id}")
}
fn marker_value(binding: &Binding) -> String {
    format!("{} {}", binding.rr_type, binding.value)
}
fn owns(record: &Value, id: &str, binding: &Binding) -> bool {
    record["records"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|r| r["content"] == binding.value && r["disabled"] == false)
        && record["comments"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|c| c["account"] == marker(id) && c["content"] == marker_value(binding))
}
pub(super) fn has_markers(record: &Value) -> bool {
    record["comments"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|c| {
            c["account"]
                .as_str()
                .is_some_and(|v| v.starts_with("forklift-host:"))
        })
}
pub(super) fn strip_markers(record: &mut Value) {
    if let Some(comments) = record["comments"].as_array_mut() {
        comments.retain(|c| {
            !c["account"]
                .as_str()
                .is_some_and(|v| v.starts_with("forklift-host:"))
        });
    }
}
pub(super) fn record_revision(record: &Value) -> String {
    let mut comments = record["comments"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| json!({"account":c["account"],"content":c["content"]}))
        .collect::<Vec<_>>();
    comments.sort_by_key(Value::to_string);
    digest(&json!({"record":canonical(record),"comments":comments}).to_string())
}
pub(super) fn check_current(a: &App, operation: &str, completion: &Completion) -> Result<()> {
    let state = get(a, &completion.host_id)?.ok_or(bad("Host DNS intent no longer exists"))?;
    if state.status.operation_id.as_deref() != Some(operation)
        || state.revision != completion.revision
        || state.desired != completion.desired
        || state.deleted != completion.deleted
    {
        return Err(Error(StatusCode::CONFLICT,"The host DNS intent changed; reconcile its current settings instead of retrying an old plan".into()));
    }
    let host = hosts::load(a, &completion.host_id).ok();
    if completion.deleted {
        if host.is_some() {
            return Err(bad(
                "The host has not been removed; DNS cleanup is not authorized",
            ));
        }
    } else if !host
        .is_some_and(|h| h.revision == completion.revision && h.dns == completion.desired)
    {
        return Err(Error(
            StatusCode::CONFLICT,
            "Host settings changed; review and reconcile the current host".into(),
        ));
    }
    Ok(())
}
pub(super) fn failed(
    a: &App,
    operation: &str,
    completion: &Completion,
    message: &str,
) -> Result<()> {
    if let Some(mut state) = get(a, &completion.host_id)?
        && state.status.operation_id.as_deref() == Some(operation)
    {
        state.status.state = "needs_retry".into();
        state.status.error = Some(message.into());
        store(a, &state)?;
    }
    Ok(())
}
pub(super) fn complete(
    tx: &Transaction<'_>,
    operation: &str,
    completion: &Completion,
) -> Result<()> {
    let data = tx
        .query_row(
            "SELECT data FROM host_dns WHERE id=?",
            [&completion.host_id],
            |r| r.get::<_, String>(0),
        )
        .map_err(anyhow::Error::from)?;
    let mut state: State = serde_json::from_str(&data).map_err(anyhow::Error::from)?;
    if state.status.operation_id.as_deref() != Some(operation) {
        return Err(bad("Host DNS operation was superseded"));
    }
    state.bindings = completion.bindings.clone();
    state.status = Status {
        state: if state.deleted || state.desired.is_none() {
            "removed"
        } else {
            "applied"
        }
        .into(),
        error: None,
        warnings: completion.warnings.clone(),
        operation_id: None,
        managed_values: state.bindings.len(),
        checked_at: Some(now()),
    };
    store_tx(tx, &state)
}
pub(super) fn manual_override(tx: &Transaction<'_>, change: &Change) -> Result<()> {
    let mut q = tx.prepare("SELECT data FROM host_dns");
    // Phase-1 installations need no host-DNS table until this module is used.
    let Ok(ref mut q) = q else { return Ok(()) };
    let rows = q
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(anyhow::Error::from)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?;
    for data in rows {
        let mut state: State = serde_json::from_str(&data).map_err(anyhow::Error::from)?;
        let before = state.bindings.len();
        state.bindings.retain(|b| {
            !change
                .steps
                .iter()
                .any(|step| b.zone == step.zone && b.name == step.name && b.rr_type == step.rr_type)
        });
        if before != state.bindings.len() {
            state.status.state = "needs_review".into();
            state.status.managed_values = state.bindings.len();
            state.status.warnings.push(
                "Managed record values were manually edited; their host ownership was relinquished"
                    .into(),
            );
            store_tx(tx, &state)?;
        }
    }
    Ok(())
}
fn key(binding: &Binding) -> (String, String, String) {
    (
        binding.zone.clone(),
        binding.name.clone(),
        binding.rr_type.clone(),
    )
}
async fn plan(a: &App, state: &State) -> Result<(Change, Vec<Binding>)> {
    no_pending(a)?;
    let list = zones().await?;
    let mut desired = Vec::new();
    if let Some(config) = &state.desired {
        let forward = zone(&config.zone).await?;
        managed(&forward)?;
        if list.iter().any(|z| {
            z["name"]
                .as_str()
                .is_some_and(|n| n.len() > config.zone.len() && within(&config.fqdn, n))
        }) {
            return Err(bad("The host name belongs to a more specific DNS zone"));
        }
        for (typ, value) in [
            ("A", Some(config.ipv4.to_string())),
            ("AAAA", config.ipv6.map(|v| v.to_string())),
        ] {
            if let Some(value) = value {
                desired.push(Binding {
                    zone: config.zone.clone(),
                    name: config.fqdn.clone(),
                    rr_type: typ.into(),
                    value: value.clone(),
                });
                if config.reverse {
                    let ptr = reverse(value.parse().map_err(|_| bad("Invalid host address"))?);
                    let z=list.iter().filter(|z|z["account"]=="forklift"&&matches!(z["kind"].as_str(),Some("Native"|"Primary"))).filter_map(|z|z["name"].as_str()).filter(|z|within(&ptr,z)).max_by_key(|z|z.len()).ok_or(bad("No managed reverse zone covers the host address. Create it or disable reverse registration."))?;
                    desired.push(Binding {
                        zone: z.into(),
                        name: ptr,
                        rr_type: "PTR".into(),
                        value: config.fqdn.clone(),
                    });
                }
            }
        }
    }
    let mut grouped: BTreeMap<(String, String, String), (Option<Value>, Value)> = BTreeMap::new();
    let mut warnings = Vec::new();
    for binding in state.bindings.iter().chain(&desired) {
        let k = key(binding);
        if grouped.contains_key(&k) {
            continue;
        }
        let z = match zone(&binding.zone).await {
            Ok(z) => z,
            Err(e) if e.0 == StatusCode::NOT_FOUND && !desired.iter().any(|d| key(d) == k) => {
                warnings.push(format!(
                    "Zone {} was removed; no cleanup was needed",
                    binding.zone
                ));
                continue;
            }
            Err(e) => return Err(e),
        };
        if managed(&z).is_err() && !desired.iter().any(|d| key(d) == k) {
            warnings.push(format!(
                "Zone {} is no longer managed; its records were retained",
                binding.zone
            ));
            continue;
        }
        managed(&z)?;
        if desired.iter().any(|d| key(d) == k) && find(&z, &binding.name, "CNAME").is_some() {
            return Err(bad(
                "A desired host DNS owner is a CNAME; resolve that conflict first",
            ));
        }
        let existing = find(&z, &binding.name, &binding.rr_type);
        let mut working = existing
            .clone()
            .unwrap_or_else(|| rrset(&binding.name, &binding.rr_type, 300, &[], None));
        if !working["comments"].is_array() {
            working["comments"] = json!([]);
        }
        grouped.insert(k, (existing, working));
    }
    for binding in &state.bindings {
        if let Some((Some(before), working)) = grouped.get_mut(&key(binding)) {
            if owns(before, &state.id, binding) {
                working["records"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|r| r["content"] != binding.value);
                working["comments"].as_array_mut().unwrap().retain(|c| {
                    c["account"] != marker(&state.id) || c["content"] != marker_value(binding)
                });
            } else if values(before).contains(&binding.value) {
                warnings.push(format!(
                    "{} {} was changed outside host management and was preserved",
                    binding.name, binding.rr_type
                ));
            }
        }
    }
    let mut owned = Vec::new();
    for binding in desired {
        let (_, working) = grouped
            .get_mut(&key(&binding))
            .ok_or(bad("Desired DNS record is unavailable"))?;
        if values(working).contains(&binding.value) {
            if working["records"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|r| r["content"] == binding.value && r["disabled"] == true)
            {
                return Err(bad(
                    "An existing host DNS value is disabled. Review it in DNS before registering this address; the disabled value was preserved.",
                ));
            }
            warnings.push(format!(
                "Existing {} value at {} was retained without taking ownership",
                binding.rr_type, binding.name
            ));
            continue;
        }
        working["records"]
            .as_array_mut()
            .unwrap()
            .push(json!({"content":binding.value,"disabled":false}));
        working["comments"].as_array_mut().unwrap().push(json!({"account":marker(&state.id),"content":marker_value(&binding),"modified_at":now()}));
        owned.push(binding);
    }
    let mut steps = Vec::new();
    for ((z, n, t), (before, working)) in grouped {
        if working["records"].as_array().is_some_and(|r| r.len() > 100) {
            return Err(bad(
                "Host registration would exceed 100 values in a DNS record set; review the existing records first",
            ));
        }
        let after = if working["records"].as_array().is_none_or(Vec::is_empty) {
            None
        } else {
            Some(working)
        };
        if before.as_ref().map(record_revision) == after.as_ref().map(record_revision) {
            continue;
        }
        steps.push(Step {
            zone: z,
            name: n,
            rr_type: t,
            before: before.as_ref().map(record_revision),
            after,
            protect_comments: true,
        });
    }
    // Union candidates survive interruption/supersession; marker checks authorize every cleanup.
    let mut candidates = state.bindings.clone();
    candidates.extend(owned.clone());
    candidates.sort();
    candidates.dedup();
    if candidates.len() > 128 {
        return Err(bad(
            "Too many unfinished host DNS ownership candidates; reconcile before making more changes",
        ));
    }
    Ok((
        Change {
            id: token()[..32].into(),
            key: format!("host:{}", state.id),
            steps,
            links: vec![],
            warnings: warnings.clone(),
            clear_ptr: None,
            host: Some(Completion {
                host_id: state.id.clone(),
                revision: state.revision,
                desired: state.desired.clone(),
                deleted: state.deleted,
                bindings: owned,
                warnings,
            }),
        },
        candidates,
    ))
}
pub(crate) async fn reconcile_locked(a: &App, who: &str, id: &str) -> Result<Status> {
    ensure(a)?;
    let host = hosts::load(a, id).ok();
    if let Some(host) = &host {
        let current = get(a, id)?;
        if current
            .as_ref()
            .is_none_or(|s| s.revision != host.revision || s.desired != host.dns || s.deleted)
        {
            intent(a, host)?;
        }
    }
    let mut state = get(a, id)?.ok_or(bad("No host DNS intent exists"))?;
    if state.deleted && ["retained", "removed"].contains(&state.status.state.as_str()) {
        return Err(bad("This deleted host's DNS cleanup is already resolved"));
    }
    if let Some(id) = state.status.operation_id.clone() {
        let data =
            a.db.lock()
                .unwrap()
                .query_row(
                    "SELECT data FROM dns_changes WHERE id=? AND status!='completed'",
                    [&id],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .map_err(anyhow::Error::from)?;
        if let Some(data) = data {
            let c: Change = serde_json::from_str(&data).map_err(anyhow::Error::from)?;
            apply(a, who, &c).await?;
            return Ok(get(a, &state.id)?.unwrap().status);
        }
    }
    match plan(a, &state).await {
        Ok((change, candidates)) => {
            state.bindings = candidates;
            state.status.state = "pending".into();
            state.status.error = None;
            state.status.operation_id = Some(change.id.clone());
            {
                let mut db = a.db.lock().unwrap();
                let tx = db.transaction().map_err(anyhow::Error::from)?;
                store_tx(&tx, &state)?;
                tx.execute(
                    "INSERT INTO dns_changes(id,at,data,status,error) VALUES(?,?,?,'pending',NULL)",
                    params![
                        change.id,
                        now(),
                        serde_json::to_string(&change).map_err(anyhow::Error::from)?
                    ],
                )
                .map_err(anyhow::Error::from)?;
                tx.commit().map_err(anyhow::Error::from)?;
            }
            audit(a, who, "DNS attempt host reconciliation", id)?;
            apply(a, who, &change).await?;
            Ok(get(a, id)?.unwrap().status)
        }
        Err(error) => {
            state.status.state = "needs_retry".into();
            state.status.error = Some(error.1);
            state.status.operation_id = None;
            store(a, &state)?;
            audit(a, who, "DNS failed host reconciliation", id)?;
            Ok(state.status)
        }
    }
}
pub(crate) async fn reconcile(
    axum::extract::State(a): axum::extract::State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    Ok(Json(json!(reconcile_locked(&a, &who, &id).await?)))
}
pub(crate) async fn retain(
    axum::extract::State(a): axum::extract::State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<operations::Acknowledgment>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    if !p.acknowledge {
        return Err(bad("Confirm retaining already applied DNS values"));
    }
    let mut state = get(&a, &id)?.ok_or(bad("No host DNS task exists"))?;
    if !state.deleted {
        return Err(bad("Change a live host's DNS settings through Hosts"));
    }
    let mut db = a.db.lock().unwrap();
    let tx = db.transaction().map_err(anyhow::Error::from)?;
    cancel(&tx, &state)?;
    state.bindings.clear();
    state.desired = None;
    state.status = pending_status(0);
    state.status.state = "retained".into();
    store_tx(&tx, &state)?;
    tx.commit().map_err(anyhow::Error::from)?;
    drop(db);
    audit(&a, &who, "DNS retain deleted-host records", &id)?;
    Ok(Json(json!({"retained":true})))
}
pub(crate) fn tasks(a: &App) -> Result<Vec<Value>> {
    Ok(all(a)?.into_iter().filter(|s|!["applied","retained","removed"].contains(&s.status.state.as_str())).map(|s|json!({"id":s.id,"name":s.label,"deleted":s.deleted,"desired":s.desired,"status":s.status})).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_names_and_comment_preconditions_are_validated() {
        let config = Config {
            zone: "Example.Test".into(),
            fqdn: "SERVER".into(),
            ipv4: Ipv4Addr::new(192, 168, 1, 50),
            ipv6: None,
            reverse: true,
        }
        .normalize()
        .ok()
        .unwrap();
        assert_eq!(config.fqdn, "server.example.test.");
        for invalid in [
            "outside.invalid.",
            "*.example.test.",
            "_service",
            "bad\nname",
        ] {
            assert!(
                Config {
                    fqdn: invalid.into(),
                    ..config.clone()
                }
                .normalize()
                .is_err()
            );
        }
        let mut rr = rrset(&config.fqdn, "A", 300, &[config.ipv4.to_string()], None);
        let before = record_revision(&rr);
        rr["comments"] =
            json!([{"account":"forklift-host:example","content":"A 192.168.1.50","modified_at":1}]);
        assert_ne!(before, record_revision(&rr));
        let marked = record_revision(&rr);
        rr["comments"][0]["modified_at"] = json!(2);
        assert_eq!(marked, record_revision(&rr));
    }
}
