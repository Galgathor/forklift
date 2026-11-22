//! Key-bound inventory, server-clock freshness and explicitly authorized DNS reconciliation.
use super::*;
use crate::dns::host_records as dns_hosts;
use rusqlite::OptionalExtension;
use std::net::IpAddr;

#[derive(Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Selector {
    interface: String,
    address: Option<IpAddr>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Policy {
    offline_after: i64,
    dns_updates: bool,
    ipv4: Option<Selector>,
    ipv6: Option<Selector>,
    diagnostics: diagnostics::Config,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            offline_after: 900,
            dns_updates: false,
            ipv4: None,
            ipv6: None,
            diagnostics: diagnostics::Config::default(),
        }
    }
}
#[derive(Clone, Default, Deserialize, Serialize)]
struct Observation {
    sequence: i64,
    hash: String,
    received_at: i64,
    interval: i64,
    identity: Option<Identity>,
    #[serde(default)]
    interfaces: Vec<String>,
    offline: bool,
    dns: Option<Value>,
}
#[derive(Default, Deserialize, Serialize)]
struct Monitor {
    #[serde(default)]
    policy: Policy,
    #[serde(default)]
    credential_id: String,
    #[serde(default)]
    observation: Observation,
    #[serde(default)]
    history: Vec<Value>,
    #[serde(default)]
    revision: i64,
}
pub(super) fn migrate(db: &Connection) -> anyhow::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS client_monitoring(host_id TEXT PRIMARY KEY,data TEXT NOT NULL);")?;
    Ok(())
}
fn load(a: &App, id: &str) -> Result<Monitor> {
    let data: Option<String> =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT data FROM client_monitoring WHERE host_id=?",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
    data.map(|s| {
        serde_json::from_str(&s)
            .map_err(anyhow::Error::from)
            .map_err(Error::from)
    })
    .transpose()
    .map(Option::unwrap_or_default)
}
fn save(a: &App, id: &str, m: &Monitor) -> Result<()> {
    a.db.lock().unwrap().execute("INSERT INTO client_monitoring(host_id,data) VALUES(?,?) ON CONFLICT(host_id) DO UPDATE SET data=excluded.data",params![id,serde_json::to_string(m).map_err(anyhow::Error::from)?]).map_err(anyhow::Error::from)?;
    Ok(())
}
fn event(m: &mut Monitor, kind: &str, detail: Value) {
    m.history
        .push(json!({"id":token()[..32],"at":now(),"kind":kind,"detail":detail}));
    let excess = m.history.len().saturating_sub(100);
    m.history.drain(..excess);
}
fn threshold(m: &Monitor) -> i64 {
    m.policy.offline_after.max(3 * m.observation.interval)
}
fn connectivity(m: &Monitor, n: &Enrollment, at: i64) -> &'static str {
    if !["active", "approved"].contains(&n.state.as_str()) {
        return "unenrolled";
    }
    if m.credential_id != n.id || m.observation.received_at == 0 {
        return "not_reporting";
    }
    if at.saturating_sub(m.observation.received_at) >= threshold(m) {
        "offline"
    } else {
        "online"
    }
}
pub(super) fn summary(a: &App, n: &Enrollment) -> Result<Value> {
    let m = load(a, n.host_id.as_deref().unwrap_or_default())?;
    let current = m.credential_id == n.id;
    let diagnostic = diagnostics::summary(
        a,
        n.host_id.as_deref().unwrap_or_default(),
        ["active", "approved"].contains(&n.state.as_str()),
        connectivity(&m, n, now()) == "online",
    )?;
    Ok(
        json!({"diagnostics":diagnostic,"connectivity":connectivity(&m,n,now()),"received_at":if current {Some(m.observation.received_at).filter(|v|*v>0)}else{None},"interfaces":if current {m.observation.interfaces.clone()}else{vec![]},"interval":if current {Some(m.observation.interval).filter(|v|*v>0)}else{None},"offline_after":threshold(&m),"inventory":if current {m.observation.identity.as_ref()}else{None},"dns":if current {m.observation.dns.as_ref()}else{None}}),
    )
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Report {
    api_version: u8,
    sequence: i64,
    interval: i64,
    identity: Identity,
    interfaces: Vec<String>,
}
fn validate(p: &Report) -> Result<()> {
    if p.api_version != 1
        || p.sequence <= 0
        || p.sequence == i64::MAX
        || !(30..=3600).contains(&p.interval)
    {
        return Err(bad("Unsupported inventory version, sequence or interval"));
    }
    validate_identity(&p.identity)?;
    if p.interfaces.len() > 32
        || p.interfaces.iter().any(|v| {
            v.is_empty()
                || v.len() > 32
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        return Err(bad("Invalid inventory interfaces"));
    }
    let mut addresses = std::collections::HashSet::new();
    for a in &p.identity.addresses {
        if !usable(a.address) || !addresses.insert((a.interface.clone(), a.address)) {
            return Err(bad("Inventory contains invalid or duplicate addresses"));
        }
    }
    Ok(())
}
fn usable(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(v) => !v.is_link_local() && v != std::net::Ipv4Addr::BROADCAST,
            IpAddr::V6(v) => !v.is_unicast_link_local() && v.to_ipv4_mapped().is_none(),
        }
}
fn select(identity: &Identity, selector: &Selector, ipv4: bool) -> Result<IpAddr> {
    let mut found = identity
        .addresses
        .iter()
        .filter(|a| {
            a.interface == selector.interface
                && a.address.is_ipv4() == ipv4
                && selector.address.is_none_or(|v| v == a.address)
        })
        .map(|a| a.address);
    let address = found.next().ok_or(bad(
        "The selected DNS interface/address is not present in the latest inventory",
    ))?;
    if found.next().is_some() {
        return Err(bad(
            "The selected interface has multiple addresses; pin an address or choose a dedicated interface",
        ));
    }
    Ok(address)
}
async fn update_dns(a: &App, id: &str, policy: &Policy, identity: &Identity) -> Result<Value> {
    if !policy.dns_updates {
        return Ok(json!({"state":"disabled"}));
    }
    let mut host = hosts::load(a, id)?;
    if host.directory_id.is_some() {
        return Err(bad(
            "Directory server DNS addresses are managed through their server configuration",
        ));
    }
    let old = host.dns.clone().ok_or(bad(
        "Configure this host's managed DNS records before enabling automatic updates",
    ))?;
    let mut desired = old.clone();
    desired.ipv4 = match select(
        identity,
        policy
            .ipv4
            .as_ref()
            .ok_or(bad("Select an IPv4 interface"))?,
        true,
    )? {
        IpAddr::V4(v) => v,
        _ => unreachable!(),
    };
    if let Some(selector) = &policy.ipv6 {
        desired.ipv6 = match select(identity, selector, false)? {
            IpAddr::V6(v) => Some(v),
            _ => unreachable!(),
        };
    }
    let desired = desired.normalize()?;
    if desired != old {
        // Validate native markers before changing intent. Never adopt or remove another writer's values.
        dns_hosts::authorize_client_update(a, &host).await?;
        dns_hosts::validate_unique(a, id, Some(&desired))?;
        host.dns = Some(desired);
        host.revision += 1;
        host.updated_at = now();
        hosts::store(a, &host)?;
        audit(a, "machine", "client DNS address intent", id)?;
        // The host row is durable before DNS. A crash here is reconciled from current intent on retry.
        dns_hosts::client_intent(a, &host)?;
    }
    dns_hosts::client_retry_allowed(a, &host).await?;
    let result = dns_hosts::reconcile_locked(a, "machine", id).await?;
    Ok(json!(result))
}
fn response(a: &App, id: &str, m: &Monitor) -> Result<Value> {
    Ok(
        json!({"api_version":1,"host_id":id,"sequence":m.observation.sequence,"received_at":m.observation.received_at,"inventory":"accepted","dns":m.observation.dns,"credentials":rotation::host_control(a,id)?}),
    )
}
pub(crate) async fn heartbeat(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Report>,
) -> Result<Json<Value>> {
    validate(&p)?;
    let _gate = a.gate.lock().await;
    let mut n = authenticate(&a, &h, &id, "heartbeat")?;
    rate(&a, &format!("heartbeat:{}", n.id), 6)?;
    if operations::recovery(&a)? {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Complete recovery review before receiving inventory",
        ));
    }
    hosts::load(&a, &id)?;
    let mut m = load(&a, &id)?;
    if m.credential_id != n.id {
        diagnostics::retire(&a, &id)?;
        m.credential_id = n.id.clone();
        m.observation = Observation::default();
        // A replacement identity never inherits automatic DNS authorization.
        m.policy.dns_updates = false;
        m.revision += 1;
        event(&mut m, "monitoring_started", json!({"credential_id":n.id}));
    }
    let hash = digest(&serde_json::to_string(&p).map_err(anyhow::Error::from)?);
    if p.sequence <= m.observation.sequence {
        if p.sequence == m.observation.sequence && hash == m.observation.hash {
            return Ok(Json(response(&a, &id, &m)?));
        }
        return Err(fail(
            StatusCode::CONFLICT,
            "Inventory sequence is stale or has different contents",
        ));
    }
    if connectivity(&m, &n, now()) == "offline" && !m.observation.offline {
        let detail = json!({"last_heartbeat":m.observation.received_at});
        event(&mut m, "offline", detail);
        m.observation.offline = true;
    }
    diagnostics::system(
        &a,
        &id,
        "client.offline",
        false,
        "Client heartbeat recovered",
        1,
    )?;
    if m.observation.offline {
        event(&mut m, "connection_recovered", json!({}));
    }
    if let Some(previous) = m.observation.identity.clone() {
        let before = json!(previous);
        let after = json!(p.identity);
        if before != after || m.observation.interfaces != p.interfaces {
            let detail = json!({"previous":previous,"current":p.identity,"previous_interfaces":m.observation.interfaces,"current_interfaces":p.interfaces});
            event(&mut m, "inventory_changed", detail);
        }
    } else {
        event(
            &mut m,
            "inventory_received",
            json!({"hostname":p.identity.hostname}),
        );
    }
    let previous_dns = m.observation.dns.clone();
    m.observation = Observation {
        sequence: p.sequence,
        hash,
        received_at: now(),
        interval: p.interval,
        identity: Some(p.identity.clone()),
        interfaces: p.interfaces.clone(),
        offline: false,
        dns: Some(json!({"state":if m.policy.dns_updates {"pending"}else{"disabled"}})),
    };
    n.state = "active".into();
    n.last_contact = Some(now());
    store(&a, &n)?;
    // Inventory acknowledgement is durable before any independent DNS request.
    save(&a, &id, &m)?;
    let outcome = match tokio::time::timeout(
        std::time::Duration::from_secs(8),
        update_dns(&a, &id, &m.policy, &p.identity),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => json!({"state":"needs_retry","error":e.1}),
        Err(_) => {
            json!({"state":"needs_retry","error":"DNS reconciliation timed out; the next heartbeat retries current intent"})
        }
    };
    if previous_dns.as_ref().map(|v| (&v["state"], &v["error"]))
        != Some((&outcome["state"], &outcome["error"]))
    {
        event(&mut m, "dns_update", outcome.clone());
    }
    if outcome["state"] == "applied" || outcome["state"] == "needs_retry" {
        diagnostics::system(
            &a,
            &id,
            "dns.update",
            outcome["state"] == "needs_retry",
            "Managed DNS address reconciliation failed",
            m.policy.diagnostics.failure_threshold,
        )?;
    } else if outcome["state"] == "disabled" {
        diagnostics::retire_check(&a, &id, "dns.update", "disabled")?;
    }
    m.observation.dns = Some(outcome);
    save(&a, &id, &m)?;
    Ok(Json(response(&a, &id, &m)?))
}
fn history_view(a: &App, id: &str, m: &Monitor) -> Result<Vec<Value>> {
    let mut events = m.history.clone();
    events.extend(diagnostics::history(a, id)?);
    events.sort_by_key(|v| v["at"].as_i64().unwrap_or(0));
    let excess = events.len().saturating_sub(100);
    events.drain(..excess);
    Ok(events)
}
pub(crate) async fn details(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    hosts::load(&a, &id)?;
    let m = load(&a, &id)?;
    Ok(Json(
        json!({"policy":m.policy,"revision":m.revision,"history":history_view(&a,&id,&m)?}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyEdit {
    revision: i64,
    policy: Policy,
}
pub(crate) async fn policy(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<PolicyEdit>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    let _gate = a.gate.lock().await;
    let host = hosts::load(&a, &id)?;
    let mut m = load(&a, &id)?;
    if m.revision != p.revision {
        return Err(fail(
            StatusCode::CONFLICT,
            "Monitoring settings changed; refresh before saving",
        ));
    }
    diagnostics::validate_config(&p.policy.diagnostics)?;
    if !(90..=10800).contains(&p.policy.offline_after) {
        return Err(bad(
            "Offline threshold must be between 90 and 10800 seconds",
        ));
    }
    for (selector, ipv4) in [(&p.policy.ipv4, true), (&p.policy.ipv6, false)] {
        if let Some(selector) = selector
            && (selector.interface.is_empty()
                || selector.interface.len() > 32
                || !selector
                    .interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || selector
                    .address
                    .is_some_and(|v| !usable(v) || v.is_ipv4() != ipv4))
        {
            return Err(bad("Invalid DNS interface or address selector"));
        }
    }
    if p.policy.dns_updates {
        if host.directory_id.is_some() || host.dns.is_none() || p.policy.ipv4.is_none() {
            return Err(bad(
                "Configure managed host DNS and select an IPv4 interface first",
            ));
        }
        let active = by_host(&a, &id)?
            .iter()
            .any(|n| n.id == m.credential_id && n.state == "active");
        if !active {
            return Err(bad(
                "Wait for a current enrolled client's first inventory report",
            ));
        }
        let identity = m
            .observation
            .identity
            .as_ref()
            .ok_or(bad("No current inventory available"))?;
        select(identity, p.policy.ipv4.as_ref().unwrap(), true)?;
        if let Some(selector) = &p.policy.ipv6 {
            select(identity, selector, false)?;
        }
        // Do not require the DNS API just to retain an existing policy during an outage.
        if !m.policy.dns_updates || m.policy.ipv4 != p.policy.ipv4 || m.policy.ipv6 != p.policy.ipv6
        {
            dns_hosts::authorize_client_update(&a, &host).await?;
        }
    }
    if m.policy != p.policy {
        let detail = json!({"previous":m.policy,"current":p.policy});
        event(&mut m, "policy_changed", detail);
        m.policy = p.policy;
        m.revision += 1;
        save(&a, &id, &m)?;
        audit(&a, &who, "client monitoring policy", &id)?;
    }
    Ok(Json(
        json!({"policy":m.policy,"revision":m.revision,"history":history_view(&a,&id,&m)?}),
    ))
}
pub(crate) fn watch(a: App) {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            timer.tick().await;
            let _gate = a.gate.lock().await;
            if let Err(e) = offline(&a) {
                eprintln!("Client freshness check unavailable: {}", e.1);
            }
        }
    });
}
fn offline(a: &App) -> Result<()> {
    for n in rows(a)?.iter().filter(|n| n.state == "active") {
        let Some(id) = &n.host_id else {
            continue;
        };
        let mut m = load(a, id)?;
        if !m.observation.offline && connectivity(&m, n, now()) == "offline" {
            let detail = json!({"last_heartbeat":m.observation.received_at});
            event(&mut m, "offline", detail);
            m.observation.offline = true;
            diagnostics::system(
                a,
                id,
                "client.offline",
                true,
                "Client missed its heartbeat threshold",
                1,
            )?;
            save(a, id, &m)?;
        }
    }
    for n in rows(a)?
        .iter()
        .filter(|n| !["active", "approved"].contains(&n.state.as_str()))
    {
        if let Some(id) = &n.host_id
            && !by_host(a, id)?
                .iter()
                .any(|v| ["active", "approved"].contains(&v.state.as_str()))
        {
            diagnostics::retire(a, id)?;
        }
    }
    Ok(())
}
pub(crate) fn diagnostic_config(a: &App, id: &str) -> Result<diagnostics::Config> {
    Ok(load(a, id)?.policy.diagnostics)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_discards_old_events_without_losing_current_state() {
        let mut m = Monitor::default();
        for index in 0..125 {
            event(&mut m, "change", json!({"index":index}));
        }
        assert_eq!(m.history.len(), 100);
        assert_eq!(m.history[0]["detail"]["index"], 25);
        assert_eq!(m.history[99]["detail"]["index"], 124);
        assert_eq!(m.observation.sequence, 0);
    }
    #[test]
    fn selectors_never_pick_the_first_multihomed_address() {
        let identity:Identity=serde_json::from_value(json!({"hostname":"server","fqdn":null,"os":"ubuntu","os_version":"24.04","kernel":"test","architecture":"x86_64","client_version":"0.2.0","capabilities":[],"addresses":[{"interface":"eth0","address":"192.168.1.40"},{"interface":"eth0","address":"192.168.1.41"}]})).unwrap();
        assert!(
            select(
                &identity,
                &Selector {
                    interface: "eth0".into(),
                    address: None
                },
                true
            )
            .is_err()
        );
        assert_eq!(
            select(
                &identity,
                &Selector {
                    interface: "eth0".into(),
                    address: Some("192.168.1.41".parse().unwrap())
                },
                true
            )
            .ok()
            .unwrap()
            .to_string(),
            "192.168.1.41"
        );
        assert!(
            select(
                &identity,
                &Selector {
                    interface: "eth1".into(),
                    address: None
                },
                true
            )
            .is_err()
        );
        assert!(!usable("::ffff:192.168.1.40".parse().unwrap()));
        let m = Monitor::default();
        assert_eq!(threshold(&m), 900);
        let mut m = m;
        m.observation.interval = 3600;
        assert_eq!(threshold(&m), 10800);
    }
}

pub(super) fn rotation_capable(a: &App, id: &str, credential: &str) -> Result<bool> {
    let m = load(a, id)?;
    Ok(m.credential_id == credential
        && m.observation
            .identity
            .as_ref()
            .is_some_and(|i| i.capabilities.iter().any(|v| v == "rotation-v1")))
}

pub(super) fn record_event(a: &App, id: &str, kind: &str, detail: Value) -> Result<()> {
    let mut m = load(a, id)?;
    event(&mut m, kind, detail);
    save(a, id, &m)
}

pub(super) fn network_capable(a: &App, id: &str) -> Result<bool> {
    let m = load(a, id)?;
    Ok(m.observation
        .identity
        .as_ref()
        .is_some_and(|i| i.capabilities.iter().any(|c| c == "network-v1")))
}
