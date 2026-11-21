//! PowerDNS REST management. No DNS database writes or dependency in the LDAP login path.
pub(crate) mod host_records;
pub(crate) mod replication;
use super::*;
use axum::http::Method;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

fn unavailable(message: &str) -> Error {
    Error(StatusCode::SERVICE_UNAVAILABLE, message.into())
}
fn meta(a: &App) -> Result<()> {
    a.db.lock().unwrap().execute_batch("CREATE TABLE IF NOT EXISTS dns_changes(id TEXT PRIMARY KEY,at INTEGER NOT NULL,data TEXT NOT NULL,status TEXT NOT NULL,error TEXT); CREATE TABLE IF NOT EXISTS dns_links(id TEXT PRIMARY KEY,data TEXT NOT NULL);").map_err(anyhow::Error::from)?;
    Ok(())
}
async fn authorize(a: &App, h: &HeaderMap, write: bool) -> Result<String> {
    let who = admin(a, h, false).await?;
    if write {
        operations::csrf(a, h)?;
        if operations::recovery(a)? {
            return Err(unavailable(
                "Complete the restored-directory recovery review before DNS changes",
            ));
        }
    }
    meta(a)?;
    Ok(who)
}
fn credential(name: &str) -> Result<String> {
    std::fs::read_to_string(format!("/run/dns-secrets/{name}"))
        .map(|v| v.trim().to_owned())
        .map_err(|_| unavailable("DNS credentials are not ready; check the DNS container"))
}
async fn transport(
    method: Method,
    path: &str,
    body: Option<&Value>,
    control: bool,
) -> Result<(StatusCode, Vec<u8>)> {
    let client = reqwest::Client::builder()
        .unix_socket("/run/dns-control/dns.sock")
        .timeout(std::time::Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(anyhow::Error::from)?;
    let mut request = client.request(method, format!("http://localhost{path}"));
    request = if control {
        request.bearer_auth(credential("control")?)
    } else {
        request.header("X-API-Key", credential("api-key")?)
    };
    if let Some(value) = body {
        request = request.json(value);
    }
    let mut response = request.send().await.map_err(|_| {
        unavailable("PowerDNS is unreachable; LDAP remains available independently")
    })?;
    let status = response.status();
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| unavailable("PowerDNS response was interrupted"))?
    {
        if data.len() + chunk.len() > 8 * 1024 * 1024 {
            return Err(unavailable("DNS response exceeds the supported size"));
        }
        data.extend_from_slice(&chunk);
    }
    Ok((status, data))
}
async fn request(method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
    let (status, data) = transport(
        method,
        &format!("/api/v1/servers/localhost{path}"),
        body,
        false,
    )
    .await?;
    if !status.is_success() {
        return Err(if status == StatusCode::NOT_FOUND {
            Error(
                StatusCode::NOT_FOUND,
                "DNS zone no longer exists; refresh its list".into(),
            )
        } else if status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::BAD_REQUEST {
            bad(
                "PowerDNS rejected the change. Check zone ownership, record syntax and CNAME/NS conflicts, then refresh before retrying",
            )
        } else {
            unavailable("PowerDNS API failed; check DNS health and API credentials")
        });
    }
    if data.is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_slice(&data)
            .map(normalize_kind)
            .map_err(|_| unavailable("PowerDNS returned an invalid response"))
    }
}
fn normalize_kind(mut value: Value) -> Value {
    match &mut value {
        Value::Array(values) => {
            for v in values {
                *v = normalize_kind(v.take());
            }
        }
        Value::Object(object) => {
            if let Some(kind) = object.get_mut("kind") {
                match kind.as_str() {
                    Some("Master") => *kind = json!("Primary"),
                    Some("Slave") => *kind = json!("Secondary"),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    value
}
fn name(raw: &str, owner: bool) -> Result<String> {
    let s = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if raw.trim().ends_with("..")
        || s.is_empty()
        || s.len() > 253
        || s.split('.').enumerate().any(|(i, label)| {
            label.is_empty()
                || label.len() > 63
                || !(owner && i == 0 && label == "*")
                    && (label.starts_with('-')
                        || label.ends_with('-')
                        || !label.bytes().all(|c| {
                            c.is_ascii_lowercase()
                                || c.is_ascii_digit()
                                || c == b'-'
                                || owner && c == b'_'
                        }))
        })
    {
        return Err(bad(
            "Use a DNS name with labels up to 63 characters; wildcards are allowed only as the first owner label",
        ));
    }
    Ok(s + ".")
}
fn within(owner: &str, zone: &str) -> bool {
    owner == zone || owner.ends_with(&format!(".{zone}"))
}
fn owner(raw: &str, zone: &str) -> Result<String> {
    let raw = raw.trim();
    let normalized = if raw.is_empty() || raw == "@" {
        zone.into()
    } else if raw.ends_with('.') || within(&(raw.to_ascii_lowercase() + "."), zone) {
        name(raw, true)?
    } else {
        name(&format!("{raw}.{zone}"), true)?
    };
    if !within(&normalized, zone) {
        return Err(bad("The record owner must belong to the selected zone"));
    }
    Ok(normalized)
}
fn zone_path(zone: &str) -> String {
    format!("/zones/{zone}")
}
async fn zone(zone: &str) -> Result<Value> {
    request(Method::GET, &zone_path(zone), None).await
}
async fn zones() -> Result<Vec<Value>> {
    request(Method::GET, "/zones", None)
        .await?
        .as_array()
        .cloned()
        .ok_or(unavailable("Invalid PowerDNS zone list"))
}
fn managed(z: &Value) -> Result<()> {
    if z["account"] != "forklift" || !matches!(z["kind"].as_str(), Some("Native" | "Primary")) {
        return Err(bad("This zone is not a Forklift-managed writable zone"));
    }
    Ok(())
}
fn sets(z: &Value) -> Vec<Value> {
    z["rrsets"].as_array().cloned().unwrap_or_default()
}
fn find(z: &Value, n: &str, t: &str) -> Option<Value> {
    sets(z)
        .into_iter()
        .find(|r| r["name"] == n && r["type"] == t)
}
fn canonical(r: &Value) -> Value {
    let mut records = r["records"].as_array().cloned().unwrap_or_default();
    records.sort_by_key(Value::to_string);
    json!({"name":r["name"],"type":r["type"],"ttl":r["ttl"],"records":records})
}
fn revision(r: &Value) -> String {
    digest(&canonical(r).to_string())
}
fn zone_revision(z: &Value) -> String {
    let mut records = sets(z).iter().map(canonical).collect::<Vec<_>>();
    records.sort_by_key(Value::to_string);
    digest(
        &json!({"name":z["name"],"account":z["account"],"kind":z["kind"],"rrsets":records})
            .to_string(),
    )
}
fn summary(z: &Value) -> Value {
    json!({"name":z["name"],"kind":z["kind"],"serial":z["serial"],"managed":z["account"]=="forklift","record_count":sets(z).iter().map(|r|r["records"].as_array().map_or(0,Vec::len)).sum::<usize>(),"revision":zone_revision(z)})
}
fn decorated(z: Value) -> Value {
    let mut info = summary(&z);
    info["rrsets"] = json!(
        sets(&z)
            .into_iter()
            .map(|mut r| {
                r["revision"] = json!(revision(&r));
                r
            })
            .collect::<Vec<_>>()
    );
    info
}
fn no_pending(a: &App) -> Result<()> {
    let count =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM dns_changes WHERE status!='completed'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(anyhow::Error::from)?;
    if count > 0 {
        return Err(bad(
            "Resolve or review pending DNS changes before starting another record operation",
        ));
    }
    Ok(())
}
fn applied(current: Option<&Value>, desired: Option<&Value>) -> bool {
    if current.map(revision) == desired.map(revision) {
        return true;
    }
    if let (Some(current), Some(desired)) = (current, desired)
        && current["type"] == "SOA"
        && current["ttl"] == desired["ttl"]
    {
        let normalize = |r: &Value| {
            values(r)
                .iter()
                .map(|v| {
                    v.split_whitespace()
                        .enumerate()
                        .filter(|(i, _)| *i != 2)
                        .map(|(_, v)| v)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .collect::<Vec<_>>()
        };
        return normalize(current) == normalize(desired);
    }
    false
}
fn ttl(v: u32) -> Result<()> {
    if v > 2147483647 {
        Err(bad("TTL must be between 0 and 2147483647 seconds"))
    } else {
        Ok(())
    }
}
fn rrset(n: &str, t: &str, time: u32, values: &[String], current: Option<&Value>) -> Value {
    let records = values
        .iter()
        .map(|value| {
            let disabled = current
                .and_then(|r| r["records"].as_array())
                .and_then(|rs| rs.iter().find(|r| r["content"] == *value))
                .and_then(|r| r["disabled"].as_bool())
                .unwrap_or(false);
            json!({"content":value,"disabled":disabled})
        })
        .collect::<Vec<_>>();
    json!({"name":n,"type":t,"ttl":time,"records":records,"comments":current.map(|r|r["comments"].clone()).unwrap_or(json!([]))})
}
fn values(r: &Value) -> Vec<String> {
    r["records"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["content"].as_str().map(str::to_owned))
        .collect()
}
fn txt(v: &str) -> Result<String> {
    let bytes = v.as_bytes();
    let mut i = 0;
    let mut chunks = Vec::new();
    while i < bytes.len() {
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        if i == bytes.len() {
            break;
        }
        if bytes[i] != b'"' {
            return Err(bad(
                "TXT values must be quoted, for example \"v=spf1 -all\"",
            ));
        }
        i += 1;
        let mut decoded = Vec::new();
        loop {
            if i >= bytes.len() {
                return Err(bad("TXT has an unclosed quote"));
            }
            if bytes[i] == b'"' {
                i += 1;
                break;
            }
            if bytes[i] == b'\\' {
                i += 1;
                if i >= bytes.len() {
                    return Err(bad("Invalid TXT escape"));
                }
                if bytes[i].is_ascii_digit() {
                    if i + 3 > bytes.len() || !bytes[i..i + 3].iter().all(u8::is_ascii_digit) {
                        return Err(bad(
                            "TXT numeric escapes require three digits from 000 to 255",
                        ));
                    }
                    let number = v[i..i + 3].parse::<u16>().unwrap_or(999);
                    if number > 255 {
                        return Err(bad(
                            "TXT numeric escapes require three digits from 000 to 255",
                        ));
                    }
                    decoded.push(number as u8);
                    i += 3;
                    continue;
                }
            }
            decoded.push(bytes[i]);
            i += 1;
        }
        if decoded.len() > 255 {
            return Err(bad("Each quoted TXT segment may contain at most 255 bytes"));
        }
        let mut encoded = String::from("\"");
        for byte in decoded {
            match byte {
                b'"' => encoded.push_str("\\\""),
                b'\\' => encoded.push_str("\\\\"),
                32..=126 => encoded.push(char::from(byte)),
                _ => encoded.push_str(&format!("\\{byte:03}")),
            }
        }
        encoded.push('"');
        chunks.push(encoded);
        if i < bytes.len() && bytes[i] != b' ' {
            return Err(bad("Separate TXT quoted segments with spaces"));
        }
    }
    if chunks.is_empty() {
        return Err(bad("Supply a quoted TXT value"));
    }
    Ok(chunks.join(" "))
}
fn content(t: &str, v: &str) -> Result<String> {
    let v = v.trim();
    if v.is_empty() || v.len() > 2048 || v.chars().any(char::is_control) {
        return Err(bad(
            "DNS values must be nonempty, at most 2048 bytes and contain no control characters",
        ));
    }
    match t {
        "A" => v
            .parse::<Ipv4Addr>()
            .map(|ip| ip.to_string())
            .map_err(|_| bad("Invalid IPv4 address")),
        "AAAA" => v
            .parse::<Ipv6Addr>()
            .map(|ip| ip.to_string())
            .map_err(|_| bad("Invalid IPv6 address")),
        "CNAME" | "PTR" | "NS" => name(v, false),
        "TXT" => txt(v),
        "MX" | "SRV" => {
            let parts = v.split_whitespace().collect::<Vec<_>>();
            let count = if t == "MX" { 2 } else { 4 };
            if parts.len() != count || parts[..count - 1].iter().any(|n| n.parse::<u16>().is_err())
            {
                return Err(bad(
                    "MX requires priority target; SRV requires priority weight port target (numbers 0–65535)",
                ));
            }
            let target = if parts[count - 1] == "." {
                ".".into()
            } else {
                name(parts[count - 1], false)?
            };
            let mut output = parts[..count - 1]
                .iter()
                .map(|n| n.parse::<u16>().unwrap().to_string())
                .collect::<Vec<_>>();
            output.push(target);
            Ok(output.join(" "))
        }
        _ => Err(bad(
            "Supported record types: A, AAAA, CNAME, PTR, TXT, MX, SRV and NS; edit SOA through zone settings",
        )),
    }
}
fn reverse(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v) => {
            let hex = format!("{:032x}", u128::from(v));
            format!(
                "{}.ip6.arpa.",
                hex.chars()
                    .rev()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(".")
            )
        }
    }
}
fn reverse4(cidr: &str) -> Result<String> {
    let (ip, prefix) = cidr.split_once('/').ok_or(bad(
        "Enter an aligned private IPv4 network with /8, /16 or /24",
    ))?;
    let ip = ip
        .parse::<Ipv4Addr>()
        .map_err(|_| bad("Invalid reverse IPv4 network"))?;
    let prefix = prefix.parse::<u32>().unwrap_or(0);
    if ![8, 16, 24].contains(&prefix) {
        return Err(bad(
            "IPv4 reverse zones support /8, /16 and /24; classless delegation is not supported",
        ));
    }
    let mask = u32::MAX << (32 - prefix);
    if !ip.is_private() || u32::from(ip) & mask != u32::from(ip) {
        return Err(bad(
            "Use an aligned RFC1918 private network with no host bits",
        ));
    }
    let o = ip.octets();
    Ok(format!(
        "{}.in-addr.arpa.",
        o[..(prefix / 8) as usize]
            .iter()
            .rev()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".")
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ZoneDraft {
    name: String,
    kind: String,
    nameserver: String,
    nameserver_address: Option<IpAddr>,
    ttl: u32,
}
pub(super) async fn create(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<ZoneDraft>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    ttl(p.ttl)?;
    let z = match p.kind.as_str() {
        "forward" => {
            let n = name(&p.name, false)?;
            if n.ends_with(".arpa.") {
                return Err(bad("Choose the reverse zone type for .arpa names"));
            }
            n
        }
        "reverse4" => reverse4(&p.name)?,
        "reverse6" => {
            let n = name(&p.name, false)?;
            let prefix = n.strip_suffix(".ip6.arpa.").ok_or(bad(
                "Enter a nibble-form ULA IPv6 reverse zone ending .c.f.ip6.arpa. or .d.f.ip6.arpa.",
            ))?;
            let parts = prefix.split('.').collect::<Vec<_>>();
            if parts.len() < 2
                || parts.len() > 32
                || parts
                    .iter()
                    .any(|v| v.len() != 1 || !v.as_bytes()[0].is_ascii_hexdigit())
                || !within(&n, "c.f.ip6.arpa.") && !within(&n, "d.f.ip6.arpa.")
            {
                return Err(bad("Use a ULA IPv6 nibble reverse zone"));
            }
            n
        }
        _ => return Err(bad("Choose forward, reverse4 or reverse6")),
    };
    let ns = name(&p.nameserver, false)?;
    if within(&ns, &z) && p.nameserver_address.is_none() {
        return Err(bad(
            "Supply the address of the in-zone nameserver so its name can resolve",
        ));
    }
    let list = zones().await?;
    if list.len() >= 128 {
        return Err(bad("This release supports up to 128 zones"));
    }
    if list.iter().any(|v| v["name"] == z) {
        return Err(bad("Zone already exists"));
    }
    let mut records = vec![
        rrset(
            &z,
            "SOA",
            p.ttl,
            &[format!("{ns} hostmaster.{z} 1 10800 3600 604800 300")],
            None,
        ),
        rrset(&z, "NS", p.ttl, std::slice::from_ref(&ns), None),
    ];
    if let Some(ip) = p.nameserver_address {
        records.push(rrset(
            &ns,
            if ip.is_ipv4() { "A" } else { "AAAA" },
            p.ttl,
            &[ip.to_string()],
            None,
        ));
        if !within(&ns, &z) {
            records.pop();
        }
    }
    audit(&a, &who, "DNS attempt create zone", &z)?;
    match request(Method::POST,"/zones",Some(&json!({"name":z,"kind":"Native","account":"forklift","nameservers":[],"rrsets":records,"soa_edit_api":"INCREASE"}))).await {
        Ok(_)=>{audit(&a,&who,"DNS create zone",&z)?;replication::after_zone_change(&a,&who).await;Ok(Json(decorated(zone(&z).await?)))},Err(e)=>{audit(&a,&who,"DNS failed create zone",&z)?;Err(e)}
    }
}
#[derive(Serialize, Deserialize, Clone)]
struct Link {
    zone: String,
    name: String,
    address: String,
    target: String,
    revision: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct Step {
    zone: String,
    name: String,
    rr_type: String,
    before: Option<String>,
    after: Option<Value>,
    #[serde(default)]
    protect_comments: bool,
}
#[derive(Serialize, Deserialize, Clone)]
struct Change {
    id: String,
    key: String,
    steps: Vec<Step>,
    links: Vec<Link>,
    warnings: Vec<String>,
    clear_ptr: Option<(String, String)>,
    #[serde(default)]
    host: Option<host_records::Completion>,
}
fn change_target(c: &Change) -> String {
    c.steps
        .first()
        .map(|step| format!("{} {} {} [{}]", step.zone, step.name, step.rr_type, c.id))
        .unwrap_or(c.id.clone())
}
fn save(a: &App, c: &Change, status: &str, error: Option<&str>) -> Result<()> {
    a.db.lock().unwrap().execute("INSERT INTO dns_changes(id,at,data,status,error) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,status=excluded.status,error=excluded.error",params![c.id,now(),serde_json::to_string(c).map_err(anyhow::Error::from)?,status,error]).map_err(anyhow::Error::from)?;
    Ok(())
}
async fn apply(a: &App, who: &str, c: &Change) -> Result<Value> {
    if let Some(completion) = &c.host {
        host_records::check_current(a, &c.id, completion)?;
    }
    for step in &c.steps {
        let result=async {
            let current_zone=zone(&step.zone).await?;managed(&current_zone)?;
            let current=find(&current_zone,&step.name,&step.rr_type);
            let signature=|r:&Value|if step.protect_comments {host_records::record_revision(r)} else {revision(r)};
            let actual=current.as_ref().map(&signature);
            if if step.protect_comments {actual==step.after.as_ref().map(&signature)} else {applied(current.as_ref(),step.after.as_ref())} {return Ok(());}
            if actual!=step.before {return Err(Error(StatusCode::CONFLICT,"A record set changed since this operation was planned. Inspect the current values before editing again; the conflicting step was preserved.".into()));}
            let payload=if let Some(r)=&step.after {let mut r=r.clone();r["changetype"]=json!("REPLACE");r} else {json!({"name":step.name,"type":step.rr_type,"changetype":"DELETE"})};
            request(Method::PATCH,&zone_path(&step.zone),Some(&json!({"rrsets":[payload]}))).await?;Ok::<_,Error>(())
        }.await;
        if let Err(error) = result {
            save(a, c, "needs_retry", Some(&error.1))?;
            if let Some(completion) = &c.host {
                host_records::failed(a, &c.id, completion, &error.1)?;
            }
            audit(a, who, "DNS failed record change", &change_target(c))?;
            return Ok(
                json!({"id":c.id,"status":"needs_retry","error":error.1,"warnings":c.warnings}),
            );
        }
    }
    {
        let mut db = a.db.lock().unwrap();
        let tx = db.transaction().map_err(anyhow::Error::from)?;
        if let Some((z, n)) = &c.clear_ptr {
            let mut q = tx
                .prepare("SELECT id,data FROM dns_links")
                .map_err(anyhow::Error::from)?;
            let rows = q
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(anyhow::Error::from)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(anyhow::Error::from)?;
            drop(q);
            for (id, data) in rows {
                let mut links: Vec<Link> =
                    serde_json::from_str(&data).map_err(anyhow::Error::from)?;
                links.retain(|v| v.zone != *z || v.name != *n);
                tx.execute(
                    "UPDATE dns_links SET data=? WHERE id=?",
                    params![json!(links).to_string(), id],
                )
                .map_err(anyhow::Error::from)?;
            }
        }
        if let Some(completion) = &c.host {
            host_records::complete(&tx, &c.id, completion)?;
        } else {
            tx.execute("INSERT INTO dns_links(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",params![c.key,serde_json::to_string(&c.links).map_err(anyhow::Error::from)?]).map_err(anyhow::Error::from)?;
            host_records::manual_override(&tx, c)?;
        }
        tx.execute(
            "UPDATE dns_changes SET status='completed',error=NULL WHERE id=?",
            [&c.id],
        )
        .map_err(anyhow::Error::from)?;
        tx.commit().map_err(anyhow::Error::from)?;
    }
    save(a, c, "completed", None)?;
    for z in c.steps.iter().map(|s| &s.zone).collect::<HashSet<_>>() {
        // Native notifications are best-effort; SOA refresh remains independent of Forklift.
        let _ = request(Method::PUT, &format!("{}/notify", zone_path(z)), None).await;
    }
    audit(a, who, "DNS complete record change", &change_target(c))?;
    Ok(json!({"id":c.id,"status":"completed","warnings":c.warnings}))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordDraft {
    name: String,
    #[serde(rename = "type")]
    rr_type: String,
    ttl: u32,
    values: Vec<String>,
    expected_revision: Option<String>,
    #[serde(default)]
    delete: bool,
    #[serde(default)]
    auto_ptr: bool,
    #[serde(default)]
    acknowledge: bool,
}
pub(super) async fn records(
    State(a): State<App>,
    h: HeaderMap,
    Path(z): Path<String>,
    Json(p): Json<RecordDraft>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    no_pending(&a)?;
    let z = name(&z, false)?;
    let n = owner(&p.name, &z)?;
    ttl(p.ttl)?;
    let t = p.rr_type.to_ascii_uppercase();
    if !["A", "AAAA", "CNAME", "PTR", "TXT", "MX", "SRV", "NS"].contains(&t.as_str()) {
        return Err(bad(
            "Unsupported record type; SOA has separate zone settings",
        ));
    }
    if p.delete && !p.acknowledge {
        return Err(bad("Confirm record-set deletion"));
    }
    if p.values.len() > 100 || !p.delete && p.values.is_empty() {
        return Err(bad("Supply 1–100 record values"));
    }
    let data = zone(&z).await?;
    managed(&data)?;
    let current = find(&data, &n, &t);
    if current.as_ref().map(revision) != p.expected_revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Record set changed. Refresh before editing to avoid losing another change.".into(),
        ));
    }
    let list = zones().await?;
    if list.iter().any(|v| {
        v["name"]
            .as_str()
            .is_some_and(|other| other.len() > z.len() && within(&n, other))
    }) {
        return Err(bad(
            "This owner belongs to a more specific zone; select that zone",
        ));
    }
    let mut next = if p.delete {
        vec![]
    } else {
        p.values
            .iter()
            .map(|v| content(&t, v))
            .collect::<Result<Vec<_>>>()?
    };
    next.sort();
    if next.windows(2).any(|v| v[0] == v[1]) {
        return Err(bad("Duplicate record values are not allowed"));
    }
    if t == "NS" && n == z && p.delete {
        return Err(bad("A zone must retain at least one apex nameserver"));
    }
    if !p.delete
        && (t == "CNAME"
            && (n == z
                || next.len() != 1
                || next[0] == n
                || sets(&data)
                    .iter()
                    .any(|r| r["name"] == n && r["type"] != "CNAME"))
            || t != "CNAME" && find(&data, &n, "CNAME").is_some())
    {
        return Err(bad(
            "CNAME requires one non-self target, cannot be the zone apex and cannot coexist with other record types",
        ));
    }
    if p.auto_ptr && !["A", "AAAA"].contains(&t.as_str()) {
        return Err(bad("Automatic PTR applies only to A or AAAA records"));
    }
    let key = format!("{z}/{n}/{t}");
    let old =
        a.db.lock()
            .unwrap()
            .query_row("SELECT data FROM dns_links WHERE id=?", [&key], |r| {
                r.get::<_, String>(0)
            })
            .ok()
            .map(|v| serde_json::from_str::<Vec<Link>>(&v))
            .transpose()
            .map_err(anyhow::Error::from)?
            .unwrap_or_default();
    let mut links = Vec::new();
    let mut warnings = Vec::new();
    let mut reverse_sets: BTreeMap<(String, String), (Option<Value>, Option<Value>)> =
        BTreeMap::new();
    for link in old {
        if next.contains(&link.address) {
            links.push(link);
            continue;
        }
        let rz = match zone(&link.zone).await {
            Ok(value) => value,
            Err(e) if e.0 == StatusCode::NOT_FOUND => {
                warnings.push(format!(
                    "Reverse zone {} was removed; no PTR cleanup was needed",
                    link.zone
                ));
                continue;
            }
            Err(e) => return Err(e),
        };
        managed(&rz)?;
        let existing = find(&rz, &link.name, "PTR");
        if existing.as_ref().map(revision) != Some(link.revision.clone()) {
            warnings.push(format!(
                "PTR {} changed outside its automatic mapping and was preserved",
                link.name
            ));
            continue;
        }
        let mut remaining = existing.as_ref().map(values).unwrap_or_default();
        remaining.retain(|v| v != &link.target);
        let after = if remaining.is_empty() {
            None
        } else {
            Some(rrset(
                &link.name,
                "PTR",
                existing
                    .as_ref()
                    .and_then(|r| r["ttl"].as_u64())
                    .unwrap_or(300) as u32,
                &remaining,
                existing.as_ref(),
            ))
        };
        reverse_sets.insert((link.zone, link.name), (existing, after));
    }
    if p.auto_ptr && !p.delete {
        for address in &next {
            let ip = address
                .parse::<IpAddr>()
                .map_err(|_| bad("Invalid address"))?;
            let ptr = reverse(ip);
            let rz=list.iter().filter(|v|v["account"]=="forklift"&&matches!(v["kind"].as_str(),Some("Native"|"Primary"))).filter_map(|v|v["name"].as_str()).filter(|z|within(&ptr,z)).max_by_key(|z|z.len()).ok_or(bad("No managed reverse zone covers this address. Create the reverse zone first or disable automatic PTR."))?.to_owned();
            let reverse_zone = zone(&rz).await?;
            if find(&reverse_zone, &ptr, "CNAME").is_some() {
                return Err(bad(
                    "The reverse owner is a CNAME; resolve that conflict before creating an automatic PTR",
                ));
            }
            let existing = find(&reverse_zone, &ptr, "PTR");
            let mut entries = existing.as_ref().map(values).unwrap_or_default();
            if !entries.contains(&n) {
                entries.push(n.clone());
                entries.sort();
                let after = rrset(&ptr, "PTR", p.ttl, &entries, existing.as_ref());
                links.retain(|l| l.address != *address);
                links.push(Link {
                    zone: rz.clone(),
                    name: ptr.clone(),
                    address: address.clone(),
                    target: n.clone(),
                    revision: revision(&after),
                });
                reverse_sets.insert((rz, ptr), (existing, Some(after)));
            }
        }
    }
    let mut steps = vec![Step {
        zone: z,
        name: n.clone(),
        rr_type: t.clone(),
        before: current.as_ref().map(revision),
        protect_comments: false,
        after: if p.delete {
            None
        } else {
            Some(rrset(&n, &t, p.ttl, &next, current.as_ref()))
        },
    }];
    for ((zone, name), (before, after)) in reverse_sets {
        steps.push(Step {
            zone,
            name,
            rr_type: "PTR".into(),
            before: before.as_ref().map(revision),
            protect_comments: false,
            after,
        });
    }
    for step in &mut steps {
        let z = zone(&step.zone).await?;
        let before = find(&z, &step.name, &step.rr_type);
        if before.as_ref().is_some_and(host_records::has_markers) {
            // Recheck the original plan before changing its ownership precondition.
            if before.as_ref().map(revision) != step.before {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "DNS records changed while planning; refresh and try again".into(),
                ));
            }
            step.protect_comments = true;
            step.before = before.as_ref().map(host_records::record_revision);
            if let Some(after) = step.after.as_mut() {
                host_records::strip_markers(after);
            }
        }
    }
    let c = Change {
        id: token()[..32].into(),
        key,
        steps,
        links,
        warnings,
        host: None,
        clear_ptr: if t == "PTR" {
            Some((data["name"].as_str().unwrap().into(), n))
        } else {
            None
        },
    };
    save(&a, &c, "pending", None)?;
    audit(&a, &who, "DNS attempt record change", &change_target(&c))?;
    Ok(Json(apply(&a, &who, &c).await?))
}
#[derive(Deserialize)]
pub(super) struct DeleteZone {
    acknowledge: bool,
    confirm_name: String,
    expected_revision: String,
}
pub(super) async fn delete(
    State(a): State<App>,
    h: HeaderMap,
    Path(z): Path<String>,
    Json(p): Json<DeleteZone>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    let z = name(&z, false)?;
    if !p.acknowledge || p.confirm_name != z {
        return Err(bad(
            "Confirm deletion by entering the exact zone name including its final dot",
        ));
    }
    let data = zone(&z).await?;
    managed(&data)?;
    if zone_revision(&data) != p.expected_revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Zone changed since it was displayed. Refresh before deleting.".into(),
        ));
    }
    let pending =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM dns_changes WHERE status!='completed'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(anyhow::Error::from)?;
    if pending > 0 {
        return Err(bad("Resolve pending DNS changes before deleting a zone"));
    }
    audit(&a, &who, "DNS attempt delete zone", &z)?;
    if let Err(e) = request(Method::DELETE, &zone_path(&z), None).await {
        audit(&a, &who, "DNS failed delete zone", &z)?;
        return Err(e);
    }
    {
        let mut db = a.db.lock().unwrap();
        let tx = db.transaction().map_err(anyhow::Error::from)?;
        let mut query = tx
            .prepare("SELECT id,data FROM dns_links")
            .map_err(anyhow::Error::from)?;
        let rows = query
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(anyhow::Error::from)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(anyhow::Error::from)?;
        drop(query);
        for (id, data) in rows {
            if id.starts_with(&format!("{z}/")) {
                tx.execute("DELETE FROM dns_links WHERE id=?", [id])
                    .map_err(anyhow::Error::from)?;
            } else {
                let mut links: Vec<Link> =
                    serde_json::from_str(&data).map_err(anyhow::Error::from)?;
                links.retain(|link| link.zone != z);
                tx.execute(
                    "UPDATE dns_links SET data=? WHERE id=?",
                    params![json!(links).to_string(), id],
                )
                .map_err(anyhow::Error::from)?;
            }
        }
        tx.commit().map_err(anyhow::Error::from)?;
    }
    audit(&a, &who, "DNS delete zone", &z)?;
    replication::after_zone_change(&a, &who).await;
    Ok(Json(json!({"deleted":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Soa {
    primary: String,
    contact: String,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
    ttl: u32,
    expected_revision: String,
}
pub(super) async fn settings(
    State(a): State<App>,
    h: HeaderMap,
    Path(z): Path<String>,
    Json(p): Json<Soa>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    no_pending(&a)?;
    let z = name(&z, false)?;
    ttl(p.ttl)?;
    let data = zone(&z).await?;
    managed(&data)?;
    let old = find(&data, &z, "SOA").ok_or(bad("Zone SOA is missing"))?;
    if revision(&old) != p.expected_revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "SOA changed; refresh before editing".into(),
        ));
    }
    if p.refresh == 0 || p.retry == 0 || p.expire < p.refresh || p.expire < p.retry {
        return Err(bad(
            "SOA refresh/retry must be positive and expiry must be at least both values",
        ));
    }
    let serial = values(&old)
        .first()
        .and_then(|v| v.split_whitespace().nth(2))
        .unwrap_or("1")
        .to_owned();
    let after = rrset(
        &z,
        "SOA",
        p.ttl,
        &[format!(
            "{} {} {serial} {} {} {} {}",
            name(&p.primary, false)?,
            name(&p.contact, false)?,
            p.refresh,
            p.retry,
            p.expire,
            p.minimum
        )],
        Some(&old),
    );
    let c = Change {
        id: token()[..32].into(),
        key: format!("{z}/{z}/SOA"),
        steps: vec![Step {
            zone: z.clone(),
            name: z,
            rr_type: "SOA".into(),
            before: Some(revision(&old)),
            protect_comments: false,
            after: Some(after),
        }],
        links: vec![],
        warnings: vec![],
        clear_ptr: None,
        host: None,
    };
    save(&a, &c, "pending", None)?;
    audit(&a, &who, "DNS attempt SOA change", &change_target(&c))?;
    Ok(Json(apply(&a, &who, &c).await?))
}
pub(super) async fn get_zone(
    State(a): State<App>,
    h: HeaderMap,
    Path(z): Path<String>,
) -> Result<Json<Value>> {
    authorize(&a, &h, false).await?;
    let z = name(&z, false)?;
    let mut value = decorated(zone(&z).await?);
    if let Some(sets) = value["rrsets"].as_array_mut() {
        let db = a.db.lock().unwrap();
        for r in sets {
            let key = format!(
                "{z}/{}/{}",
                r["name"].as_str().unwrap_or(""),
                r["type"].as_str().unwrap_or("")
            );
            let links = db
                .query_row("SELECT data FROM dns_links WHERE id=?", [key], |row| {
                    row.get::<_, String>(0)
                })
                .ok()
                .and_then(|v| serde_json::from_str::<Vec<Link>>(&v).ok())
                .unwrap_or_default();
            r["auto_ptr"] = json!(!links.is_empty());
        }
    }
    Ok(Json(value))
}
pub(super) async fn retry(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    let (data, status) =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT data,status FROM dns_changes WHERE id=?",
                [&id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .map_err(|_| bad("DNS change not found"))?;
    if status == "completed" {
        return Err(bad("This DNS change already completed"));
    }
    let c = serde_json::from_str(&data).map_err(anyhow::Error::from)?;
    Ok(Json(apply(&a, &who, &c).await?))
}
pub(super) async fn abandon(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<operations::Acknowledgment>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    if !p.acknowledge {
        return Err(bad(
            "Confirm you reviewed and will retain any already applied DNS steps",
        ));
    }
    let data =
        a.db.lock()
            .unwrap()
            .query_row("SELECT data FROM dns_changes WHERE id=?", [&id], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| bad("DNS change not found"))?;
    let change: Change = serde_json::from_str(&data).map_err(anyhow::Error::from)?;
    if change.host.is_some() {
        return Err(bad(
            "Review this host's DNS settings, then reconcile or detach them from Hosts; deleted-host cleanup has its own retain option",
        ));
    }
    a.db.lock().unwrap().execute("UPDATE dns_changes SET status='completed',error='Abandoned after review; already-applied records retained' WHERE id=? AND status!='completed'",[&id]).map_err(anyhow::Error::from)?;
    audit(&a, &who, "DNS abandon partial change", &id)?;
    Ok(Json(json!({"abandoned":true})))
}
pub(super) async fn export(
    State(a): State<App>,
    h: HeaderMap,
    Path(z): Path<String>,
) -> Result<Response> {
    let who = authorize(&a, &h, false).await?;
    let z = name(&z, false)?;
    let (status, body) = transport(
        Method::GET,
        &format!("/api/v1/servers/localhost/zones/{z}/export"),
        None,
        false,
    )
    .await?;
    if !status.is_success() {
        return Err(unavailable("DNS zone export failed"));
    }
    let value: Value = serde_json::from_slice(&body).map_err(anyhow::Error::from)?;
    let text = value["zone"]
        .as_str()
        .ok_or(unavailable("Invalid DNS zone export"))?
        .to_owned();
    audit(&a, &who, "DNS export zone", &z)?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/plain"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"forklift-zone.txt\"",
            ),
        ],
        text,
    )
        .into_response())
}
pub(super) async fn rotate(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<operations::Acknowledgment>,
) -> Result<Json<Value>> {
    let who = authorize(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    if !p.acknowledge {
        return Err(bad(
            "Confirm rotating the DNS API credential and briefly restarting DNS",
        ));
    }
    audit(&a, &who, "DNS attempt API credential rotation", "local")?;
    let (status, _) = match transport(Method::POST, "/rotate", Some(&json!({})), true).await {
        Ok(value) => value,
        Err(e) => {
            audit(&a, &who, "DNS failed API credential rotation", "local")?;
            return Err(e);
        }
    };
    if !status.is_success() {
        audit(&a, &who, "DNS failed API credential rotation", "local")?;
        return Err(unavailable(
            "DNS credential rotation needs attention; restart the DNS container and inspect its health",
        ));
    }
    audit(&a, &who, "DNS rotate API credential", "local")?;
    Ok(Json(json!({"rotated":true})))
}
pub(super) async fn index(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    authorize(&a, &h, false).await?;
    let changes = {
        let db = a.db.lock().unwrap();
        let mut q=db.prepare("SELECT id,at,status,error FROM dns_changes WHERE status!='completed' ORDER BY at DESC LIMIT 30").map_err(anyhow::Error::from)?;
        q.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"at":r.get::<_,i64>(1)?,"status":r.get::<_,String>(2)?,"error":r.get::<_,Option<String>>(3)?}))).map_err(anyhow::Error::from)?.collect::<std::result::Result<Vec<_>,_>>().map_err(anyhow::Error::from)?
    };
    let errors = {
        let db = a.db.lock().unwrap();
        let mut q=db.prepare("SELECT at,action,target FROM audit WHERE action LIKE 'DNS failed%' ORDER BY id DESC LIMIT 10").map_err(anyhow::Error::from)?;
        q.query_map([],|r|Ok(json!({"at":r.get::<_,i64>(0)?,"action":r.get::<_,String>(1)?,"target":r.get::<_,String>(2)?}))).map_err(anyhow::Error::from)?.collect::<std::result::Result<Vec<_>,_>>().map_err(anyhow::Error::from)?
    };
    let host_tasks = host_records::tasks(&a)?;
    let data = async {
        let (status, raw) = transport(Method::GET, "/inspect", None, true).await?;
        if !status.is_success() {
            return Err(unavailable(
                "PowerDNS is unavailable; check DNS container health",
            ));
        }
        let mut health: Value = serde_json::from_slice(&raw).map_err(anyhow::Error::from)?;
        health["address"] = json!(std::env::var("FORKLIFT_DNS_BIND").unwrap_or("127.0.0.1".into()));
        health["port"] = json!(
            std::env::var("FORKLIFT_DNS_PORT")
                .ok()
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(53)
        );
        let list = zones().await?;
        if list.len() > 128 {
            return Err(unavailable(
                "More than 128 DNS zones; this release is intended for homelab directories",
            ));
        }
        let mut all = Vec::new();
        for z in list {
            let n = z["name"].as_str().ok_or(unavailable("Invalid DNS zone"))?;
            all.push(summary(&zone(n).await?));
        }
        Ok::<_, Error>((health, all))
    }
    .await;
    match data {
        Ok((health, list)) => Ok(Json(
            json!({"available":true,"server":health,"zones":list,"changes":changes,"host_tasks":host_tasks,"errors":errors}),
        )),
        Err(e) => Ok(Json(
            json!({"available":false,"error":e.1,"zones":[],"changes":changes,"host_tasks":host_tasks,"errors":errors,"server":{"api_available":false,"service_available":null,"role":"standalone","replication":"not_configured","address":std::env::var("FORKLIFT_DNS_BIND").unwrap_or("127.0.0.1".into()),"port":std::env::var("FORKLIFT_DNS_PORT").ok().and_then(|v|v.parse::<u16>().ok()).unwrap_or(53)}}),
        )),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_role_aliases_remain_writable_and_canonical() {
        let zones = normalize_kind(
            json!([{"kind":"Master","account":"forklift"},{"kind":"Slave","account":"forklift"}]),
        );
        assert_eq!(zones[0]["kind"], "Primary");
        assert_eq!(zones[1]["kind"], "Secondary");
        assert!(managed(&zones[0]).is_ok());
        assert!(managed(&zones[1]).is_err());
    }
    #[test]
    fn reverse_boundaries_and_owners() {
        assert_eq!(
            reverse4("192.168.1.0/24").ok().unwrap(),
            "1.168.192.in-addr.arpa."
        );
        assert!(reverse4("192.168.1.1/24").is_err());
        assert!(reverse4("8.8.8.0/24").is_err());
        assert_eq!(
            reverse("192.168.1.50".parse().unwrap()),
            "50.1.168.192.in-addr.arpa."
        );
        assert_eq!(
            owner("monolith", "example.test.").ok().unwrap(),
            "monolith.example.test."
        );
        assert!(owner("other.example.", "example.test.").is_err());
    }
    #[test]
    fn dns_values_and_injection() {
        assert!(name("bad/../../zones", false).is_err());
        assert!(content("MX", "10 mail.example.").is_ok());
        assert!(content("SRV", "0 5 389 ldap.example.").is_ok());
        assert!(content("TXT", "\"hello\" \"world\"").is_ok());
        assert!(content("TXT", "not quoted").is_err());
        assert!(content("A", "127.0.0.1\napi-key=bad").is_err());
        assert!(content("LUA", "os.execute()").is_err());
    }
}
