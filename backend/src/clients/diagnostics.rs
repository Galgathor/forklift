//! Diagnostic observations, authoritative issue state, and administrator notifications.
use super::*;
use rusqlite::OptionalExtension;

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Config {
    pub authentication: bool,
    pub ssh: bool,
    pub domain: String,
    pub test_user: Option<String>,
    pub test_group: Option<String>,
    pub ssh_source: Option<std::net::IpAddr>,
    pub ssh_source_name: Option<String>,
    pub ssh_local: Option<std::net::IpAddr>,
    pub ssh_port: u16,
    pub failure_threshold: u8,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            authentication: false,
            ssh: false,
            domain: "forklift".into(),
            test_user: None,
            test_group: None,
            ssh_source: None,
            ssh_source_name: None,
            ssh_local: None,
            ssh_port: 22,
            failure_threshold: 2,
        }
    }
}
pub(crate) fn validate_config(c: &Config) -> Result<()> {
    if !(1..=5).contains(&c.failure_threshold)
        || c.ssh_port == 0
        || !identifier(&c.domain)
        || c.test_user.as_ref().is_some_and(|v| !identifier(v))
        || c.test_group.as_ref().is_some_and(|v| !identifier(v))
        || c.ssh_source_name
            .as_ref()
            .is_some_and(|v| !hosts::hostname(v))
    {
        return Err(bad(
            "Invalid diagnostic domain, test identity, SSH context, port or failure threshold",
        ));
    }
    Ok(())
}
fn identifier(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && !v.starts_with('-')
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Check {
    id: String,
    status: String,
    severity: String,
    summary: String,
    details: String,
    remediation: String,
    at: i64,
}
#[derive(Clone, Deserialize, Serialize)]
struct Issue {
    id: String,
    check_id: String,
    state: String,
    severity: String,
    summary: String,
    details: String,
    remediation: String,
    first_detected: i64,
    last_detected: i64,
    last_checked: i64,
    resolved_at: Option<i64>,
    verification: String,
    acknowledged: bool,
}
#[derive(Default, Deserialize, Serialize)]
struct Candidate {
    count: u8,
    first: i64,
}
#[derive(Default, Deserialize, Serialize)]
struct Record {
    credential_id: String,
    sequence: i64,
    hash: String,
    profile: String,
    received_at: i64,
    interval: i64,
    checks: Vec<Check>,
    issues: Vec<Issue>,
    candidates: std::collections::BTreeMap<String, Candidate>,
    #[serde(default)]
    contexts: std::collections::BTreeMap<String, String>,
    #[serde(skip)]
    pending: Vec<Value>,
}
pub(crate) fn migrate(db: &Connection) -> anyhow::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS client_diagnostics(host_id TEXT PRIMARY KEY,data TEXT NOT NULL); CREATE TABLE IF NOT EXISTS client_notifications(id INTEGER PRIMARY KEY,host_id TEXT NOT NULL,data TEXT NOT NULL);")?;
    Ok(())
}
fn load(a: &App, id: &str) -> Result<Record> {
    let raw: Option<String> =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT data FROM client_diagnostics WHERE host_id=?",
                [id],
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
    .map(Option::unwrap_or_default)
}
fn save(a: &App, id: &str, r: &mut Record) -> Result<()> {
    let mut db = a.db.lock().unwrap();
    let tx = db.transaction().map_err(anyhow::Error::from)?;
    tx.execute("INSERT INTO client_diagnostics(host_id,data) VALUES(?,?) ON CONFLICT(host_id) DO UPDATE SET data=excluded.data",params![id,serde_json::to_string(r).map_err(anyhow::Error::from)?]).map_err(anyhow::Error::from)?;
    for event in &r.pending {
        let mut event = event.clone();
        event["host_id"] = json!(id);
        tx.execute(
            "INSERT INTO client_notifications(host_id,data) VALUES(?,?)",
            params![id, event.to_string()],
        )
        .map_err(anyhow::Error::from)?;
    }
    tx.execute("DELETE FROM client_notifications WHERE id NOT IN (SELECT id FROM client_notifications ORDER BY id DESC LIMIT 500)",[]).map_err(anyhow::Error::from)?;
    tx.commit().map_err(anyhow::Error::from)?;
    r.pending.clear();
    Ok(())
}
fn notification(issue: &Issue, kind: &str) -> Value {
    json!({"issue_id":issue.id,"check_id":issue.check_id,"kind":kind,"severity":issue.severity,"summary":issue.summary,"at":now(),"acknowledged":false,"dismissed":false})
}
fn known(id: &str) -> bool {
    if id == "network.management" {
        return true;
    }
    if ["network.ldap.", "network.dns_tcp.", "network.dns_udp."]
        .iter()
        .any(|p| {
            id.strip_prefix(p)
                .is_some_and(|s| s.len() == 1 && s.bytes().all(|b| b.is_ascii_digit() && b < b'4'))
        })
    {
        return true;
    }
    [
        "client.enrollment",
        "dns.resolver",
        "dns.forward",
        "dns.zone",
        "sssd.installed",
        "sssd.service",
        "sssd.syntax",
        "sssd.directory",
        "sssd.online",
        "nss.configuration",
        "nss.user",
        "nss.group",
        "pam.integration",
        "pam.access",
        "ssh.installed",
        "ssh.service",
        "ssh.syntax",
        "ssh.authentication",
        "ssh.listener",
    ]
    .contains(&id)
        || ["dns.reverse.", "dns.authority.", "ldap.endpoint."]
            .iter()
            .any(|p| {
                id.strip_prefix(p).is_some_and(|s| {
                    s.len() == 1 && s.bytes().all(|b| b.is_ascii_digit() && b < b'4')
                })
            })
}
fn validate_checks(checks: &[Check]) -> Result<()> {
    let mut ids = std::collections::HashSet::new();
    if checks.is_empty() || checks.len() > 48 {
        return Err(bad("Submit between 1 and 48 diagnostic checks"));
    }
    for c in checks {
        if !known(&c.id)
            || !ids.insert(&c.id)
            || !["pass", "warning", "failure", "unsupported", "unknown"]
                .contains(&c.status.as_str())
            || !["info", "warning", "critical"].contains(&c.severity.as_str())
            || c.at < 0
        {
            return Err(bad("Invalid or duplicate diagnostic check"));
        }
        for (v, max) in [(&c.summary, 200), (&c.details, 512), (&c.remediation, 400)] {
            if v.len() > max || v.chars().any(char::is_control) {
                return Err(bad("Invalid bounded diagnostic text"));
            }
        }
    }
    Ok(())
}
fn severity(c: &Check) -> String {
    if c.status == "failure"
        && [
            "sssd.service",
            "sssd.syntax",
            "pam.access",
            "ssh.syntax",
            "ssh.authentication",
        ]
        .contains(&c.id.as_str())
    {
        "critical"
    } else {
        "warning"
    }
    .into()
}
fn observe(r: &mut Record, c: &Check, threshold: u8) {
    let at = now();
    if let Some(i) = r
        .issues
        .iter_mut()
        .find(|i| i.check_id == c.id && i.state == "active")
    {
        i.last_checked = at;
        i.verification = c.status.clone();
        if c.status == "pass" {
            i.state = "resolved".into();
            i.resolved_at = Some(at);
            r.pending.push(notification(i, "recovered"));
            r.candidates.remove(&c.id);
        } else if ["warning", "failure"].contains(&c.status.as_str()) {
            i.last_detected = at;
            i.summary = c.summary.clone();
            i.details = c.details.clone();
            i.remediation = c.remediation.clone();
            let next = severity(c);
            if next != i.severity {
                i.severity = next;
                r.pending.push(notification(i, "severity_changed"));
            }
        }
        return;
    }
    if !["warning", "failure"].contains(&c.status.as_str()) {
        r.candidates.remove(&c.id);
        return;
    }
    let candidate = r.candidates.entry(c.id.clone()).or_insert(Candidate {
        count: 0,
        first: at,
    });
    candidate.count = candidate.count.saturating_add(1);
    if candidate.count >= threshold {
        let issue = Issue {
            id: token()[..32].into(),
            check_id: c.id.clone(),
            state: "active".into(),
            severity: severity(c),
            summary: c.summary.clone(),
            details: c.details.clone(),
            remediation: c.remediation.clone(),
            first_detected: candidate.first,
            last_detected: at,
            last_checked: at,
            resolved_at: None,
            verification: c.status.clone(),
            acknowledged: false,
        };
        r.pending.push(notification(&issue, "opened"));
        r.issues.push(issue);
        r.candidates.remove(&c.id);
    }
    // At most 32 current checks plus bounded historical episodes.
    while r.issues.len() > 232 {
        if let Some(index) = r.issues.iter().position(|i| i.state != "active") {
            r.issues.remove(index);
        } else {
            break;
        }
    }
}

fn profile_value(a: &App, id: &str) -> Result<Value> {
    let raw: String =
        a.db.lock()
            .unwrap()
            .query_row("SELECT data FROM hosts WHERE id=?", [id], |r| r.get(0))
            .map_err(anyhow::Error::from)?;
    let host: hosts::Host = serde_json::from_str(&raw).map_err(anyhow::Error::from)?;
    let config = monitoring::diagnostic_config(a, id)?;
    let ca = if config.authentication {
        String::from_utf8(replicas::client_trust(a, &host.draft.endpoints)?)
            .map_err(anyhow::Error::from)?
    } else {
        String::new()
    };
    let mut authorities = Vec::<Value>::new();
    if let Some(p) = dns::replication::primary(a)? {
        authorities.push(json!({"address":p.address,"port":p.dns_port}));
    }
    let db = a.db.lock().unwrap();
    // Read only public serving addresses, never management API/control credentials.
    let exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='dns_servers')",
            [],
            |r| r.get(0),
        )
        .map_err(anyhow::Error::from)?;
    if exists {
        let mut q = db
            .prepare("SELECT data FROM dns_servers ORDER BY id LIMIT 8")
            .map_err(anyhow::Error::from)?;
        for row in q
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(anyhow::Error::from)?
        {
            let v: Value = serde_json::from_str(&row.map_err(anyhow::Error::from)?)
                .map_err(anyhow::Error::from)?;
            if v["state"] == "active"
                && v["revoked"] != true
                && host.dns.as_ref().is_some_and(|d| {
                    v["draft"]["zones"]
                        .as_array()
                        .is_some_and(|zs| zs.contains(&json!(d.zone)))
                })
            {
                authorities
                    .push(json!({"address":v["draft"]["address"],"port":v["draft"]["dns_port"]}));
            }
        }
    }
    drop(db);
    authorities.truncate(4);
    let mut value = json!({"api_version":1,"settings":config,"dns":host.dns,"authorities":authorities,"endpoints":host.draft.endpoints.iter().take(4).collect::<Vec<_>>(),"base":base(a)?,"ldap_ca":ca,"allowed_groups":host.draft.allowed_groups});
    if monitoring::network_capable(a, id)? {
        value["network"] = json!(true);
    }
    value["revision"] = json!(digest(&value.to_string()));
    Ok(value)
}
pub(crate) async fn profile(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(_): Json<Empty>,
) -> Result<Json<Value>> {
    let _gate = a.gate.lock().await;
    authenticate(&a, &h, &id, "diagnostic-profile")?;
    rate(&a, &format!("profile:{id}"), 12)?;
    Ok(Json(profile_value(&a, &id)?))
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Report {
    api_version: u8,
    sequence: i64,
    profile_revision: String,
    interval: i64,
    checks: Vec<Check>,
}
pub(crate) async fn report(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Report>,
) -> Result<Json<Value>> {
    validate_checks(&p.checks)?;
    if p.api_version != 1
        || p.sequence <= 0
        || p.sequence == i64::MAX
        || !(30..=3600).contains(&p.interval)
    {
        return Err(bad("Invalid diagnostic version, sequence or interval"));
    }
    let _gate = a.gate.lock().await;
    let n = authenticate(&a, &h, &id, "diagnostics")?;
    rate(&a, &format!("diagnostics:{id}"), 6)?;
    if operations::recovery(&a)? {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Complete recovery review before diagnostic reports",
        ));
    }
    let profile = profile_value(&a, &id)?;
    if profile["revision"] != p.profile_revision {
        return Err(fail(
            StatusCode::CONFLICT,
            "Diagnostic expectations changed; retrieve the current profile",
        ));
    }
    let mut r = load(&a, &id)?;
    if r.credential_id == n.id && p.sequence < r.sequence {
        return Err(fail(StatusCode::CONFLICT, "Stale diagnostic sequence"));
    }
    let next_contexts = contexts(&profile);
    if r.credential_id != n.id || r.profile != p.profile_revision {
        for issue in r.issues.iter_mut().filter(|i| {
            i.state == "active" && !i.check_id.starts_with("client.") && i.check_id != "dns.update"
        }) {
            if r.contexts.get(&issue.check_id) != next_contexts.get(&issue.check_id) {
                issue.state = "retired".into();
                issue.verification = "expectations_changed".into();
            }
        }
        if r.credential_id != n.id {
            r.sequence = 0;
            r.hash.clear();
        }
        r.credential_id = n.id;
        r.checks.clear();
        r.candidates.retain(|key, _| {
            key == "client.offline"
                || key == "dns.update"
                || r.contexts.get(key) == next_contexts.get(key)
        });
        r.contexts = next_contexts;
        r.profile = p.profile_revision.clone();
    }
    let hash = digest(&serde_json::to_string(&p).map_err(anyhow::Error::from)?);
    if p.sequence <= r.sequence {
        if p.sequence == r.sequence && r.hash == hash {
            return Ok(Json(
                json!({"accepted":true,"sequence":r.sequence,"received_at":r.received_at}),
            ));
        }
        return Err(fail(
            StatusCode::CONFLICT,
            "Stale or conflicting diagnostic sequence",
        ));
    }
    let threshold = profile["settings"]["failure_threshold"]
        .as_u64()
        .unwrap_or(2) as u8;
    // Missing checks are unverified, never positive recoveries or consecutive failure evidence.
    let submitted = p
        .checks
        .iter()
        .map(|c| c.id.as_str())
        .collect::<std::collections::HashSet<_>>();
    r.candidates.retain(|key, _| {
        submitted.contains(key.as_str()) || key == "dns.update" || key == "client.offline"
    });
    for i in r.issues.iter_mut().filter(|i| {
        i.state == "active"
            && !submitted.contains(i.check_id.as_str())
            && !i.check_id.starts_with("client.")
            && i.check_id != "dns.update"
    }) {
        i.verification = "not_reported".into();
    }
    let enabled = required(&profile);
    for c in &p.checks {
        if enabled.contains(&c.id) {
            observe(&mut r, c, threshold);
        }
    }

    r.sequence = p.sequence;
    r.hash = hash;
    r.checks = p.checks;
    r.received_at = now();
    r.interval = p.interval;
    save(&a, &id, &mut r)?;
    Ok(Json(
        json!({"accepted":true,"sequence":r.sequence,"received_at":r.received_at}),
    ))
}
pub(crate) fn system(
    a: &App,
    id: &str,
    check: &str,
    failed: bool,
    summary: &str,
    threshold: u8,
) -> Result<()> {
    let mut r = load(a, id)?;
    observe(
        &mut r,
        &Check {
            id: check.into(),
            status: if failed { "failure" } else { "pass" }.into(),
            severity: "warning".into(),
            summary: summary.into(),
            details: String::new(),
            remediation: if check == "client.offline" {
                "Check the client service and management-network connectivity"
            } else {
                "Review the host DNS outcome and reconcile its current settings"
            }
            .into(),
            at: now(),
        },
        threshold,
    );
    save(a, id, &mut r)
}
pub(crate) fn retire_check(a: &App, id: &str, check: &str, reason: &str) -> Result<()> {
    let mut r = load(a, id)?;
    for issue in r
        .issues
        .iter_mut()
        .filter(|i| i.check_id == check && i.state == "active")
    {
        issue.state = "retired".into();
        issue.verification = reason.into();
    }
    r.candidates.remove(check);
    save(a, id, &mut r)
}
pub(crate) fn retire(a: &App, id: &str) -> Result<()> {
    let mut r = load(a, id)?;
    for i in r.issues.iter_mut().filter(|i| i.state == "active") {
        i.state = "retired".into();
        i.verification = "monitoring_ended".into();
    }
    r.candidates.clear();
    save(a, id, &mut r)
}
fn contexts(p: &Value) -> std::collections::BTreeMap<String, String> {
    let mut values = std::collections::BTreeMap::new();
    for id in required(p)
        .into_iter()
        .chain(["sssd.installed".into(), "ssh.installed".into()])
    {
        let c = if id.starts_with("network.dns_") {
            let i = id
                .rsplit('.')
                .next()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            json!({"server":p["authorities"][i]})
        } else if id.starts_with("network.ldap.") {
            let i = id
                .rsplit('.')
                .next()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            json!({"endpoint":p["endpoints"][i]})
        } else if id == "network.management" {
            json!({"network":p["network"]})
        } else if id == "client.enrollment" || id == "dns.resolver" {
            json!({"check":id})
        } else if id == "dns.zone" {
            json!({"zone":p["dns"]["zone"]})
        } else if id.starts_with("dns.authority.") {
            let i = id
                .rsplit('.')
                .next()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            json!({"zone":p["dns"]["zone"],"server":p["authorities"][i]})
        } else if id.starts_with("dns.") {
            json!({"dns":p["dns"]})
        } else if id.starts_with("ldap.endpoint.") {
            let i = id
                .rsplit('.')
                .next()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            json!({"endpoint":p["endpoints"][i],"ca":p["ldap_ca"]})
        } else if id == "nss.user" {
            json!({"user":p["settings"]["test_user"]})
        } else if id == "nss.group" {
            json!({"group":p["settings"]["test_group"]})
        } else if id == "sssd.directory" {
            json!({"domain":p["settings"]["domain"],"base":p["base"],"endpoints":p["endpoints"]})
        } else if id == "sssd.online" {
            json!({"domain":p["settings"]["domain"]})
        } else if id == "pam.access" {
            json!({"groups":p["allowed_groups"]})
        } else if id == "ssh.authentication" {
            json!({"user":p["settings"]["test_user"],"source":p["settings"]["ssh_source"],"name":p["settings"]["ssh_source_name"],"local":p["settings"]["ssh_local"],"port":p["settings"]["ssh_port"]})
        } else if id == "ssh.listener" {
            json!({"local":p["settings"]["ssh_local"],"port":p["settings"]["ssh_port"]})
        } else {
            json!({"enabled":if id.starts_with("ssh."){p["settings"]["ssh"].clone()}else{p["settings"]["authentication"].clone()}})
        };
        values.insert(id, digest(&c.to_string()));
    }
    values
}
fn required(p: &Value) -> Vec<String> {
    let mut ids = vec!["client.enrollment".into(), "dns.resolver".into()];
    if p["network"] == true {
        ids.push("network.management".into());
        for i in 0..p["endpoints"].as_array().map(Vec::len).unwrap_or(0) {
            ids.push(format!("network.ldap.{i}"));
        }
        for i in 0..p["authorities"].as_array().map(Vec::len).unwrap_or(0) {
            ids.push(format!("network.dns_tcp.{i}"));
            ids.push(format!("network.dns_udp.{i}"));
        }
    }
    if p["dns"].is_object() {
        ids.extend(["dns.forward".into(), "dns.zone".into()]);
        if p["dns"]["reverse"] == true {
            ids.push("dns.reverse.0".into());
            if p["dns"]["ipv6"].is_string() {
                ids.push("dns.reverse.1".into());
            }
        }
        for i in 0..p["authorities"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0)
            .max(1)
        {
            ids.push(format!("dns.authority.{i}"));
        }
    }
    if p["settings"]["authentication"] == true {
        ids.extend(
            [
                "sssd.installed",
                "sssd.service",
                "sssd.syntax",
                "sssd.directory",
                "sssd.online",
                "nss.configuration",
                "nss.user",
                "nss.group",
                "pam.integration",
                "pam.access",
            ]
            .map(str::to_owned),
        );
        for i in 0..p["endpoints"].as_array().map(Vec::len).unwrap_or(0) {
            ids.push(format!("ldap.endpoint.{i}"));
        }
    }
    if p["settings"]["ssh"] == true {
        ids.extend(
            [
                "ssh.installed",
                "ssh.service",
                "ssh.syntax",
                "ssh.authentication",
                "ssh.listener",
            ]
            .map(str::to_owned),
        );
    }
    ids
}
pub(crate) fn summary(a: &App, id: &str, current: bool, online: bool) -> Result<Value> {
    let r = load(a, id)?;
    let active = r
        .issues
        .iter()
        .filter(|i| i.state == "active" && current)
        .collect::<Vec<_>>();
    let profile_current = current
        && !r.profile.is_empty()
        && profile_value(a, id).is_ok_and(|v| v["revision"] == r.profile);
    let fresh =
        profile_current && r.received_at > 0 && now() - r.received_at < 900.max(3 * r.interval);
    let expected = if profile_current {
        required(&profile_value(a, id)?)
    } else {
        vec![]
    };
    let complete = !expected.is_empty()
        && expected
            .iter()
            .all(|id| r.checks.iter().any(|c| &c.id == id && c.status == "pass"));
    let health = if !current {
        "unmonitored"
    } else if !online || !fresh {
        "unknown"
    } else if active.iter().any(|i| i.severity == "critical") {
        "critical"
    } else if !active.is_empty() {
        "warning"
    } else if !complete
        || r.checks.is_empty()
        || r.checks
            .iter()
            .any(|c| !["pass", "unsupported"].contains(&c.status.as_str()))
    {
        "unknown"
    } else {
        "healthy"
    };
    Ok(
        json!({"health":health,"active_issues":active.len(),"received_at":if r.received_at>0{Some(r.received_at)}else{None},"fresh":fresh&&current}),
    )
}
pub(crate) async fn details(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    let host = hosts::load(&a, &id)?;
    let r = load(&a, &id)?;
    Ok(Json(
        json!({"checks":r.checks,"issues":r.issues,"received_at":r.received_at,"profile_revision":r.profile,"status":host.client.and_then(|v|v["monitoring"]["diagnostics"].as_object().cloned())}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Acknowledge {
    action: String,
}
pub(crate) async fn acknowledge_issue(
    State(a): State<App>,
    h: HeaderMap,
    Path((id, issue)): Path<(String, String)>,
    Json(p): Json<Acknowledge>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    let _gate = a.gate.lock().await;
    hosts::load(&a, &id)?;
    if p.action != "acknowledge" {
        return Err(bad(
            "Issues may be acknowledged; only a positive check resolves an active issue",
        ));
    }
    let mut r = load(&a, &id)?;
    let i = r
        .issues
        .iter_mut()
        .find(|i| i.id == issue)
        .ok_or(fail(StatusCode::NOT_FOUND, "Issue not found"))?;
    i.acknowledged = true;
    save(&a, &id, &mut r)?;
    audit(&a, &who, "client acknowledge issue", &issue)?;
    Ok(Json(json!({"acknowledged":true})))
}
pub(super) fn history(a: &App, id: &str) -> Result<Vec<Value>> {
    let db = a.db.lock().unwrap();
    let mut q = db
        .prepare(
            "SELECT id,data FROM client_notifications WHERE host_id=? ORDER BY id DESC LIMIT 100",
        )
        .map_err(anyhow::Error::from)?;
    let values = q
        .query_map([id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .map_err(anyhow::Error::from)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?;
    values.into_iter().map(|(id,s)|{let v:Value=serde_json::from_str(&s).map_err(anyhow::Error::from)?;Ok(json!({"id":format!("issue-event-{id}"),"at":v["at"],"kind":format!("issue_{}",v["kind"].as_str().unwrap_or("changed")),"detail":{"issue_id":v["issue_id"],"check_id":v["check_id"],"summary":v["summary"],"severity":v["severity"]}}))}).collect()
}
pub(crate) async fn notifications(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    let db = a.db.lock().unwrap();
    let mut q = db
        .prepare("SELECT id,data FROM client_notifications ORDER BY id DESC LIMIT 200")
        .map_err(anyhow::Error::from)?;
    let values = q
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .map_err(anyhow::Error::from)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?;
    drop(q);
    drop(db);
    let mut values = values
        .into_iter()
        .map(|(id, s)| {
            serde_json::from_str::<Value>(&s)
                .map(|mut v| {
                    v["id"] = json!(id);
                    v
                })
                .map_err(anyhow::Error::from)
                .map_err(Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    for v in &mut values {
        v["host_name"] = json!(
            hosts::load(&a, v["host_id"].as_str().unwrap_or_default())
                .map(|h| h.draft.name)
                .unwrap_or_else(|_| "Removed host".into())
        );
        let r = load(&a, v["host_id"].as_str().unwrap_or_default())?;
        v["issue_state"] = json!(
            r.issues
                .iter()
                .find(|i| i.id == v["issue_id"])
                .map(|i| i.state.as_str())
                .unwrap_or("archived")
        );
    }
    Ok(Json(json!({"notifications":values})))
}
pub(crate) async fn acknowledge_notification(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(p): Json<Acknowledge>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    let _gate = a.gate.lock().await;
    if !["acknowledge", "dismiss"].contains(&p.action.as_str()) {
        return Err(bad("Choose acknowledge or dismiss"));
    }
    let db = a.db.lock().unwrap();
    let raw: String = db
        .query_row(
            "SELECT data FROM client_notifications WHERE id=?",
            [id],
            |r| r.get(0),
        )
        .optional()
        .map_err(anyhow::Error::from)?
        .ok_or(fail(StatusCode::NOT_FOUND, "Notification not found"))?;
    let mut v: Value = serde_json::from_str(&raw).map_err(anyhow::Error::from)?;
    v[if p.action == "dismiss" {
        "dismissed"
    } else {
        "acknowledged"
    }] = json!(true);
    v["updated_by"] = json!(who);
    db.execute(
        "UPDATE client_notifications SET data=? WHERE id=?",
        params![v.to_string(), id],
    )
    .map_err(anyhow::Error::from)?;
    drop(db);
    audit(&a, &who, "client notification action", &id.to_string())?;
    Ok(Json(json!({"updated":true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn result(status: &str) -> Check {
        Check {
            id: "sssd.service".into(),
            status: status.into(),
            severity: "info".into(),
            summary: "Service observation".into(),
            details: String::new(),
            remediation: String::new(),
            at: 1,
        }
    }
    #[test]
    fn issues_require_distinct_failures_preserve_unknown_and_resolve_only_on_pass() {
        let mut r = Record::default();
        observe(&mut r, &result("failure"), 2);
        assert!(r.issues.is_empty());
        observe(&mut r, &result("unknown"), 2);
        observe(&mut r, &result("failure"), 2);
        assert!(r.issues.is_empty());
        observe(&mut r, &result("failure"), 2);
        assert_eq!(r.issues.len(), 1);
        let id = r.issues[0].id.clone();
        assert_eq!(r.issues[0].severity, "critical");
        observe(&mut r, &result("failure"), 2);
        assert_eq!(r.issues.len(), 1);
        assert_eq!(r.pending.len(), 1);
        r.issues[0].acknowledged = true;
        observe(&mut r, &result("unknown"), 2);
        assert_eq!(r.issues[0].state, "active");
        assert_eq!(r.issues[0].id, id);
        observe(&mut r, &result("pass"), 2);
        assert_eq!(r.issues[0].state, "resolved");
        assert_eq!(r.pending.len(), 2);
        observe(&mut r, &result("failure"), 2);
        observe(&mut r, &result("failure"), 2);
        assert_eq!(r.issues.len(), 2);
        assert_ne!(r.issues[1].id, id);
    }
    #[test]
    fn reports_cannot_invent_checks_or_inject_context_arguments() {
        assert!(!identifier("--help"));
        assert!(!identifier("user,addr=host"));
        let mut check = result("failure");
        assert!(validate_checks(&[check.clone(), check.clone()]).is_err());
        check.id = "shell.command".into();
        assert!(validate_checks(&[check]).is_err());
        assert!(
            required(
                &json!({"settings":{"authentication":true,"ssh":true},"endpoints":[],"dns":null})
            )
            .contains(&"ssh.syntax".into())
        );
    }
}

pub(crate) fn network_observations(a: &App) -> Result<Vec<Value>> {
    let ids: Vec<(String, String)> = {
        let db = a.db.lock().unwrap();
        let mut q = db
            .prepare("SELECT id,data FROM hosts ORDER BY id LIMIT 128")
            .map_err(anyhow::Error::from)?;
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(anyhow::Error::from)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(anyhow::Error::from)?
    };
    let mut out = Vec::new();
    for (id, raw) in ids {
        let host: hosts::Host = serde_json::from_str(&raw).map_err(anyhow::Error::from)?;
        let r = load(a, &id)?;
        if r.received_at == 0 {
            continue;
        }
        let active = by_host(a, &id)?
            .iter()
            .any(|n| n.id == r.credential_id && n.state == "active");
        let fresh = active
            && now() - r.received_at < 900.max(3 * r.interval)
            && profile_value(a, &id).is_ok_and(|p| p["revision"] == r.profile);
        for c in r.checks.iter().filter(|c| c.id.starts_with("network.")) {
            out.push(json!({"host_id":id,"host":host.draft.name,"check":c,"received_at":r.received_at,"fresh":fresh}));
        }
    }
    Ok(out)
}
