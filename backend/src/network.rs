//! Probe configured services only. Never edits a firewall or accepts an arbitrary scan target.
use super::*;
use rusqlite::OptionalExtension;
#[derive(Clone)]
struct Target {
    label: String,
    host: String,
    port: u16,
    transport: &'static str,
}
async fn execute(targets: Vec<Target>) -> Vec<Value> {
    let mut tasks = tokio::task::JoinSet::new();
    for t in targets.into_iter().take(64) {
        tasks.spawn(async move {
            let (status,details)=if t.transport=="TCP" {port_checks::tcp(&t.host,t.port).await} else {
                match t.host.parse() {Ok(ip)=>port_checks::dns(ip,t.port,t.transport=="DNS/TCP").await,Err(_)=>("unknown","DNS listener address is not an IP literal".into())}
            };
            json!({"label":t.label,"address":t.host,"port":t.port,"transport":t.transport,"status":status,"details":details,"checked_at":now(),"source":"Forklift manager network namespace"})
        });
    }
    let mut rows = Vec::new();
    while let Some(Ok(row)) = tasks.join_next().await {
        rows.push(row);
    }
    rows.sort_by_key(|r| format!("{}{}", r["label"], r["transport"]));
    rows
}
fn endpoint(targets: &mut Vec<Target>, label: &str, url: &str) {
    if let Ok(u) = reqwest::Url::parse(url)
        && let Some(host) = u.host_str()
    {
        targets.push(Target {
            label: label.into(),
            host: host.trim_matches(['[', ']']).into(),
            port: u
                .port()
                .unwrap_or(if u.scheme() == "ldaps" { 636 } else { 443 }),
            transport: "TCP",
        });
    }
}
pub(crate) async fn checks(
    State(a): State<App>,
    h: HeaderMap,
    Json(_): Json<clients::Empty>,
) -> Result<Json<Value>> {
    admin(&a, &h, true).await?;
    clients::network_rate(&a)?;
    let mut targets = Vec::new();
    endpoint(
        &mut targets,
        "WebUI HTTPS (manager self-path)",
        &public_url(&a),
    );
    if let Some(c) = config(&a) {
        endpoint(
            &mut targets,
            "Primary LDAP",
            c["network"]["endpoint"].as_str().unwrap_or(""),
        );
    }
    for r in replicas::records(&a)?.into_iter().take(12) {
        endpoint(&mut targets, &format!("{} LDAP", r.name), &r.endpoint);
        targets.push(Target {
            label: format!("{} replica control", r.name),
            host: r.address,
            port: r.control_port,
            transport: "TCP",
        });
    }
    {
        let db = a.db.lock().unwrap();
        let primary = db
            .query_row(
                "SELECT value FROM settings WHERE key='dns_primary'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
        let mut servers = Vec::new();
        if let Some(p) = primary {
            servers.push(serde_json::from_str::<Value>(&p).map_err(anyhow::Error::from)?);
        }
        let exists:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='dns_servers' AND type='table')",[],|r|r.get(0)).map_err(anyhow::Error::from)?;
        let mut q = db
            .prepare(if exists {
                "SELECT data FROM dns_servers ORDER BY id LIMIT 8"
            } else {
                "SELECT '{}' WHERE 0"
            })
            .map_err(anyhow::Error::from)?;
        for row in q
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(anyhow::Error::from)?
        {
            let v: Value = serde_json::from_str(&row.map_err(anyhow::Error::from)?)
                .map_err(anyhow::Error::from)?;
            if v["state"] == "active" && v["revoked"] != true {
                let mut draft = v["draft"].clone();
                draft["secondary"] = json!(true);
                servers.push(draft);
            }
        }
        for (i, v) in servers.iter().enumerate() {
            if let (Some(host), Some(port)) = (
                v["address"].as_str(),
                v["dns_port"].as_u64().filter(|p| *p > 0 && *p <= 65535),
            ) {
                for transport in ["DNS/TCP", "DNS/UDP"] {
                    targets.push(Target {
                        label: format!("DNS server {}", i + 1),
                        host: host.into(),
                        port: port as u16,
                        transport,
                    });
                }
                if v["secondary"] == true
                    && let Some(port) = v["control_port"].as_u64().filter(|p| *p > 0 && *p <= 65535)
                {
                    targets.push(Target {
                        label: format!("DNS server {} control", i + 1),
                        host: host.into(),
                        port: port as u16,
                        transport: "TCP",
                    });
                }
            }
        }
    }
    let observations = clients::diagnostics::network_observations(&a)?;
    Ok(Json(
        json!({"checks":execute(targets).await,"observations":observations,"checked_at":now()}),
    ))
}
pub(crate) async fn host_checks(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(_): Json<clients::Empty>,
) -> Result<Json<Value>> {
    admin(&a, &h, true).await?;
    clients::network_rate(&a)?;
    let exists: bool =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM hosts WHERE id=?)",
                [&id],
                |r| r.get(0),
            )
            .map_err(anyhow::Error::from)?;
    if !exists {
        return Err(Error(StatusCode::NOT_FOUND, "Host not found".into()));
    }
    let policy = clients::monitoring::diagnostic_config(&a, &id)?;
    if policy.ssh
        && policy
            .ssh_local
            .is_some_and(|ip| ip.is_loopback() || ip.is_unspecified() || ip.is_multicast())
    {
        return Err(bad(
            "Select a non-loopback unicast host address for the inbound network probe; the manager cannot test a remote host through its own loopback",
        ));
    }
    let targets = if policy.ssh {
        policy
            .ssh_local
            .map(|ip| {
                vec![Target {
                    label: "Host SSH (manager → selected address)".into(),
                    host: ip.to_string(),
                    port: policy.ssh_port,
                    transport: "TCP",
                }]
            })
            .unwrap_or_default()
    } else {
        vec![]
    };
    Ok(Json(
        json!({"checks":execute(targets).await,"observations":[],"checked_at":now()}),
    ))
}
