//! Native LDAP provider membership approved by the installation's manager.
use super::*;
use hmac::{Hmac, Mac};

const FIRST_ID: &str = "00000000000000000000000000000001";

#[derive(Deserialize, Serialize, Clone, PartialEq)]
pub(crate) struct Endpoint {
    address: Ipv4Addr,
    port: u16,
    ca: String,
}

#[derive(Deserialize, Serialize, Clone)]
struct Provider {
    sid: i64,
    #[serde(flatten)]
    endpoint: Endpoint,
}

#[derive(Deserialize, Serialize)]
struct Membership {
    base: String,
    name: String,
    id: String,
    sid: i64,
    credential: String,
    allocation_start: i64,
    #[serde(default)]
    watermark: Vec<String>,
    providers: Vec<Provider>,
}

fn own_endpoint(network: &Value) -> Result<Endpoint> {
    Ok(Endpoint {
        address: network["address"]
            .as_str()
            .and_then(|v| v.parse().ok())
            .ok_or(bad("Set the local directory address"))?,
        port: network["port"]
            .as_u64()
            .and_then(|v| v.try_into().ok())
            .ok_or(bad("Set the local directory port"))?,
        ca: std::fs::read_to_string("/run/secrets/ca.crt").map_err(anyhow::Error::from)?,
    })
}

pub(super) fn schema(a: &App) -> Result<()> {
    a.db.lock()
        .unwrap()
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS ldap_peers(
            sid INTEGER PRIMARY KEY, peer_id TEXT UNIQUE NOT NULL,
            endpoint TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
        );",
        )
        .map_err(anyhow::Error::from)?;
    Ok(())
}

fn validated_endpoint(p: &Endpoint) -> Result<()> {
    replica_setup::private_ipv4(&p.address.to_string())?;
    if p.port == 0 || p.ca.len() > 6000 {
        return Err(bad("Invalid directory endpoint or certificate"));
    }
    let certs = openssl::x509::X509::stack_from_pem(p.ca.as_bytes())
        .map_err(|_| bad("Invalid directory CA"))?;
    if certs.len() != 1
        || certs[0].to_pem().map_err(anyhow::Error::from)?.as_slice() != p.ca.as_bytes()
    {
        return Err(bad("Use the single directory CA issued by Forklift"));
    }
    Ok(())
}

fn credential(id: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret("node-control-key").as_bytes())
        .expect("installation key");
    mac.update(format!("forklift/ldap/provider/v1/{id}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn peer_id(a: &App, h: &HeaderMap) -> Result<String> {
    let raw = peer_key(h)?;
    super::schema(a)?;
    let id =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT id FROM dns_peer_keys WHERE access_hash=? AND directory=1",
                [digest(raw)],
                |r| r.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?
            .ok_or(unauthorized())?;
    Ok(id)
}

fn providers(a: &App) -> Result<Vec<Provider>> {
    schema(a)?;
    let db = a.db.lock().unwrap();
    let mut q = db
        .prepare("SELECT sid,endpoint FROM ldap_peers WHERE revoked=0 ORDER BY sid")
        .map_err(anyhow::Error::from)?;
    let rows = q
        .query_map([], |r| Ok((r.get(0)?, r.get::<_, String>(1)?)))
        .map_err(anyhow::Error::from)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?;
    rows.into_iter()
        .map(|(sid, s)| {
            let endpoint = serde_json::from_str(&s).map_err(anyhow::Error::from)?;
            Ok(Provider { sid, endpoint })
        })
        .collect()
}

fn membership(a: &App, id: &str, sid: i64) -> Result<Membership> {
    let config = config(a).ok_or(bad(
        "Configure the installation before adding directory nodes",
    ))?;
    let mut providers = providers(a)?
        .into_iter()
        .filter(|p| p.sid != sid)
        .collect::<Vec<_>>();
    if sid != 1 {
        providers.insert(
            0,
            Provider {
                sid: 1,
                endpoint: own_endpoint(&config["network"])?,
            },
        );
    }
    Ok(Membership {
        base: base(a)?,
        name: config["name"].as_str().unwrap_or("Forklift").into(),
        id: id.into(),
        sid,
        credential: credential(id),
        allocation_start: allocation_base(a)? + (sid - 2) * 1_000_000,
        watermark: Vec::new(),
        providers,
    })
}

fn allocation_base(a: &App) -> Result<i64> {
    a.db.lock()
        .unwrap()
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM settings WHERE key='ldap_allocation_base'",
            [],
            |r| r.get(0),
        )
        .map_err(anyhow::Error::from)
        .map_err(Error::from)
}

fn reserve_allocation(a: &App) -> Result<()> {
    let mut db = a.db.lock().unwrap();
    let tx = db.transaction().map_err(anyhow::Error::from)?;
    let last: i64 = tx
        .query_row("SELECT value FROM allocator", [], |r| r.get(0))
        .map_err(anyhow::Error::from)?;
    let start = (last / 1_000_000 + 1) * 1_000_000;
    if start + 8_000_000 > i32::MAX as i64 {
        return Err(bad("Insufficient Unix ID space to add directory nodes"));
    }
    tx.execute(
        "INSERT INTO settings VALUES('ldap_allocation_base',?) ON CONFLICT(key) DO NOTHING",
        [start.to_string()],
    )
    .map_err(anyhow::Error::from)?;
    tx.execute(
        "INSERT INTO settings VALUES('directory_allocator_max',?) ON CONFLICT(key) DO NOTHING",
        [(start - 1).to_string()],
    )
    .map_err(anyhow::Error::from)?;
    tx.commit().map_err(anyhow::Error::from)?;
    Ok(())
}

async fn identity(a: &App, id: &str) -> Result<()> {
    let base = base(a)?;
    let name = format!("replica-{id}");
    let dn = format!("cn={name},{base}");
    let mut l = service(a).await?;
    if !search(&mut l, &base, &format!("(cn={name})"))
        .await?
        .is_empty()
    {
        return Ok(());
    }
    let salt = rand::random::<[u8; 16]>();
    let mut salted = credential(id).into_bytes();
    salted.extend_from_slice(&salt);
    let mut hash = openssl::sha::sha1(&salted).to_vec();
    hash.extend_from_slice(&salt);
    let password_hash = format!("{{SSHA}}{}", openssl::base64::encode_block(&hash));
    l.add(
        &dn,
        vec![
            (
                "objectClass".to_owned(),
                HashSet::from([
                    "organizationalRole".to_owned(),
                    "simpleSecurityObject".to_owned(),
                ]),
            ),
            ("cn".to_owned(), HashSet::from([name])),
            ("userPassword".to_owned(), HashSet::from([password_hash])),
        ],
    )
    .await?
    .success()?;
    Ok(())
}

async fn configure(p: &Membership) -> Result<()> {
    maintenance::directory(
        "/peers",
        &serde_json::to_value(p).map_err(anyhow::Error::from)?,
    )
    .await?;
    Ok(())
}

pub(crate) async fn register(
    State(a): State<App>,
    h: HeaderMap,
    Json(endpoint): Json<Endpoint>,
) -> Result<Json<Value>> {
    let _guard = a.gate.lock().await;
    let id = peer_id(&a, &h)?;
    if operations::recovery(&a)? {
        return Err(unavailable(
            "Complete recovery review before adding directory nodes",
        ));
    }
    validated_endpoint(&endpoint)?;
    let local = own_endpoint(&config(&a).ok_or(bad("Installation setup is required"))?["network"])?;
    if local.address == endpoint.address && local.port == endpoint.port {
        return Err(bad("Use a different directory listener for each node"));
    }
    schema(&a)?;
    let old =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT sid,endpoint,revoked FROM ldap_peers WHERE peer_id=?",
                [&id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, bool>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(anyhow::Error::from)?;
    if let Some((sid, previous, revoked)) = old {
        let previous: Endpoint = serde_json::from_str(&previous).map_err(anyhow::Error::from)?;
        if revoked || previous != endpoint {
            return Err(bad(
                "Retry with the same directory endpoint and node identity",
            ));
        }
        identity(&a, &id).await?;
        configure(&membership(&a, FIRST_ID, 1)?).await?;
        return seeded_membership(&a, &id, sid).await;
    }
    if providers(&a)?
        .iter()
        .any(|p| p.endpoint.address == endpoint.address && p.endpoint.port == endpoint.port)
    {
        return Err(bad("That directory listener already belongs to a node"));
    }
    let sid: i64 =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT max(coalesce((SELECT max(sid) FROM ldap_peers),1),1)+1",
                [],
                |r| r.get(0),
            )
            .map_err(anyhow::Error::from)?;
    if sid > 9 {
        return Err(bad("This installation has used all directory node numbers"));
    }
    reserve_allocation(&a)?;
    identity(&a, FIRST_ID).await?;
    identity(&a, &id).await?;
    a.db.lock()
        .unwrap()
        .execute(
            "INSERT INTO ldap_peers(sid,peer_id,endpoint) VALUES(?,?,?)",
            params![
                sid,
                id,
                serde_json::to_string(&endpoint).map_err(anyhow::Error::from)?
            ],
        )
        .map_err(anyhow::Error::from)?;
    install_local(&a, &membership(&a, FIRST_ID, 1)?).await?;
    audit(&a, "directory pairing", "add directory node", &id)?;
    seeded_membership(&a, &id, sid).await
}

async fn seeded_membership(a: &App, id: &str, sid: i64) -> Result<Json<Value>> {
    let mut m = membership(a, id, sid)?;
    m.watermark = replicas::context(&mut service(a).await?, &m.base).await?;
    if m.watermark.is_empty() {
        return Err(unavailable(
            "The existing directory has no synchronization checkpoint yet",
        ));
    }
    Ok(Json(json!(m)))
}

async fn install_local(a: &App, m: &Membership) -> Result<()> {
    a.db.lock()
        .unwrap()
        .execute(
            "INSERT INTO settings VALUES('directory_local_sid',?) ON CONFLICT(key) DO NOTHING",
            [m.sid.to_string()],
        )
        .map_err(anyhow::Error::from)?;
    configure(m).await
}

pub(crate) async fn current(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let _guard = a.gate.lock().await;
    let id = peer_id(&a, &h)?;
    schema(&a)?;
    let sid: i64 =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT sid FROM ldap_peers WHERE peer_id=? AND revoked=0",
                [&id],
                |r| r.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?
            .ok_or(unauthorized())?;
    Ok(Json(json!(membership(&a, &id, sid)?)))
}

pub(crate) async fn revoke(a: &App, id: &str) -> Result<()> {
    schema(a)?;
    let found =
        a.db.lock()
            .unwrap()
            .execute("UPDATE ldap_peers SET revoked=1 WHERE peer_id=?", [id])
            .map_err(anyhow::Error::from)?;
    if found > 0 {
        let b = base(a)?;
        let mut l = service(a).await?;
        let result = l.delete(&format!("cn=replica-{id},{b}")).await?;
        if result.rc != 32 {
            result.success()?;
        }
        configure(&membership(a, FIRST_ID, 1)?).await?;
    }
    Ok(())
}

pub(crate) fn local_sid(a: &App) -> Result<Option<i64>> {
    a.db.lock()
        .unwrap()
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM settings WHERE key='directory_local_sid'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(anyhow::Error::from)
        .map_err(Error::from)
}

pub(crate) async fn refresh(a: &App) -> Result<()> {
    if local_sid(a)?.is_none_or(|sid| sid <= 1) || config(a).is_none() {
        return Ok(());
    }
    let up = upstream(a)?.ok_or(bad("Directory peer enrollment is missing"))?;
    let (status, _, body) = remote(
        &up,
        Method::GET,
        "/api/directory/peer/membership",
        Bytes::new(),
    )
    .await?;
    if !status.is_success() {
        return Err(unavailable("Could not refresh directory peer membership"));
    }
    let m: Membership = serde_json::from_slice(&body).map_err(anyhow::Error::from)?;
    let _directory = a.directory_restart.write().await;
    let _guard = a.gate.lock().await;
    configure(&m).await?;
    save_topology(a, &m)
}

#[derive(Deserialize)]
pub(crate) struct Join {
    token: String,
    public_url: String,
    network: Value,
    coordinator: String,
    key: String,
}

pub(crate) async fn join_setup(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Join>,
) -> Result<Json<Value>> {
    bootstrap(&a, &h, &p.token)?;
    if !valid_public_url(&p.public_url) || request_origin(&h)? != p.public_url {
        return Err(bad("Use the current WebUI address"));
    }
    if !secure_origin(&p.coordinator) || p.coordinator == p.public_url || !key_valid(&p.key) {
        return Err(bad(
            "Enter a different Forklift HTTPS address and the directory pairing key",
        ));
    }
    let _guard = a.gate.lock().await;
    bootstrap(&a, &h, &p.token)?;
    let pending: Option<String> =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key='directory_join_pending'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
    let existing_setup: bool =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM settings WHERE key='setup_pending')",
                [],
                |r| r.get(0),
            )
            .map_err(anyhow::Error::from)?;
    let readiness = maintenance::local("/inspect", Some(&json!({}))).await?;
    if existing_setup || (pending.is_none() && readiness["initialized"] == true) {
        return Err(bad(
            "Directory data already exists. Complete the original setup or restore the matching backup.",
        ));
    }
    let fingerprint = digest(&json!([p.coordinator, p.key, p.network]).to_string());
    if pending.is_some_and(|v| v != fingerprint) {
        return Err(bad(
            "Resume with the original pairing key and directory address",
        ));
    }
    check_setup().await?;
    if !zones()
        .await?
        .iter()
        .all(|zone| zone["account"] == COPY_OWNER)
    {
        return Err(bad(
            "Local DNS zones already exist. Preserve them before joining.",
        ));
    }
    let activated = activate(
        &a,
        Upstream {
            url: p.coordinator,
            key: p.key,
        },
    )
    .await?;
    let network = if readiness["initialized"] == true {
        let address = p.network["address"]
            .as_str()
            .ok_or(bad("Local directory address is required"))?;
        let hostname = p.network["hostname"]
            .as_str()
            .ok_or(bad("Local directory name is required"))?;
        let port = p.network["port"]
            .as_u64()
            .ok_or(bad("Local directory port is required"))?;
        json!({"address":address,"hostname":hostname,"port":port,"endpoint":format!("ldaps://{hostname}:{port}")})
    } else {
        maintenance::local("/configure", Some(&p.network)).await?
    };
    let endpoint = own_endpoint(&network)?;
    let (status, _, body) = remote(
        &activated,
        Method::POST,
        "/api/directory/peer/register",
        Bytes::from(serde_json::to_vec(&endpoint).map_err(anyhow::Error::from)?),
    )
    .await?;
    if !status.is_success() {
        let error = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_owned));
        return Err(bad(error.as_deref().unwrap_or(
            "The existing installation rejected directory enrollment",
        )));
    }
    let m: Membership = serde_json::from_slice(&body).map_err(anyhow::Error::from)?;
    if !base_valid(&m.base)
        || !(2..=9).contains(&m.sid)
        || m.providers.is_empty()
        || !(1_000_000..=i32::MAX as i64 - 999_999).contains(&m.allocation_start)
    {
        return Err(bad(
            "The installation returned invalid directory membership",
        ));
    }
    a.db.lock()
        .unwrap()
        .execute(
            "INSERT INTO settings VALUES('directory_join_pending',?) ON CONFLICT(key) DO NOTHING",
            [fingerprint],
        )
        .map_err(anyhow::Error::from)?;
    configure(&m).await?;
    let mut directory = connect().await?;
    directory.sasl_external_bind().await?.success()?;
    // Wait for a complete synchronization cookie, not just an open socket or a seed entry.
    let mut seeded = false;
    for _ in 0..30 {
        if let Ok((rows, _)) = directory
            .search(&m.base, Scope::Base, "(objectClass=*)", vec!["contextCSN"])
            .await?
            .success()
            && rows.into_iter().map(SearchEntry::construct).any(|entry| {
                entry
                    .attrs
                    .get("contextCSN")
                    .is_some_and(|v| covers(v, &m.watermark))
            })
            && !search(
                &mut directory,
                &format!("ou=groups,{}", m.base),
                "(cn=administrators)",
            )
            .await?
            .is_empty()
        {
            seeded = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if !seeded {
        return Err(unavailable(
            "The directory has not synchronized. Check the private directory connection and retry pairing.",
        ));
    }
    let (status, _, body) = remote(
        &activated,
        Method::GET,
        "/api/dns/peer/snapshot",
        Bytes::new(),
    )
    .await?;
    if !status.is_success() {
        return Err(unavailable(
            "DNS has not synchronized. Check the existing manager and retry pairing.",
        ));
    }
    let snapshot: Snapshot = serde_json::from_slice(&body).map_err(anyhow::Error::from)?;
    apply_snapshot(&snapshot).await?;
    let config = json!({"name":m.name,"base":m.base,"network":network});
    {
        let mut db = a.db.lock().unwrap();
        let tx = db.transaction().map_err(anyhow::Error::from)?;
        persist_upstream(&tx, &activated)?;
        for (key, value) in [
            ("directory", config.to_string()),
            ("public_url", json!(p.public_url).to_string()),
            ("directory_local_sid", m.sid.to_string()),
            (
                "directory_allocator_max",
                (m.allocation_start + 999_999).to_string(),
            ),
            ("dns_coordinator_revision", snapshot.revision),
            (
                "directory_peer_topology",
                serde_json::to_string(&m).map_err(anyhow::Error::from)?,
            ),
        ] {
            tx.execute(
                "INSERT INTO settings(key,value) VALUES(?,?)",
                params![key, value],
            )
            .map_err(anyhow::Error::from)?;
        }
        tx.execute("UPDATE allocator SET value=?", [m.allocation_start - 1])
            .map_err(anyhow::Error::from)?;
        tx.execute(
            "DELETE FROM settings WHERE key='directory_join_pending'",
            [],
        )
        .map_err(anyhow::Error::from)?;
        tx.commit().map_err(anyhow::Error::from)?;
    }
    *a.url.write().unwrap() = p.public_url;
    a.configured
        .store(true, std::sync::atomic::Ordering::SeqCst);
    hosts::sync_directory(
        &a,
        "primary",
        "Local directory",
        network["hostname"].as_str().unwrap_or(""),
        "primary",
    )?;
    audit(&a, "directory pairing", "join installation", &m.id)?;
    Ok(Json(json!({"ok":true})))
}

fn covers(actual: &[String], expected: &[String]) -> bool {
    !expected.is_empty()
        && expected.iter().all(|baseline| {
            let server = baseline.split('#').nth(2);
            server.is_some()
                && actual
                    .iter()
                    .any(|current| current.split('#').nth(2) == server && current >= baseline)
        })
}

fn save_topology(a: &App, m: &Membership) -> Result<()> {
    a.db.lock().unwrap().execute(
        "INSERT INTO settings VALUES('directory_peer_topology',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        [serde_json::to_string(m).map_err(anyhow::Error::from)?],
    ).map_err(anyhow::Error::from)?;
    Ok(())
}

async fn probe_provider(
    b: &str,
    id: &str,
    credential: &str,
    endpoint: &Endpoint,
) -> anyhow::Result<Vec<String>> {
    let mut tls = native_tls::TlsConnector::builder();
    tls.disable_built_in_roots(true);
    tls.add_root_certificate(native_tls::Certificate::from_pem(endpoint.ca.as_bytes())?);
    let settings = ldap3::LdapConnSettings::new()
        .set_conn_timeout(std::time::Duration::from_secs(2))
        .set_connector(tls.build()?);
    let (conn, mut l) = LdapConnAsync::with_settings(
        settings,
        &format!("ldaps://{}:{}", endpoint.address, endpoint.port),
    )
    .await?;
    ldap3::drive!(conn);
    l.with_timeout(std::time::Duration::from_secs(2));
    l.simple_bind(&format!("cn=replica-{id},{b}"), credential)
        .await?
        .success()?;
    let context = replicas::context(&mut l, b).await;
    let _ = l.unbind().await;
    context
}

pub(crate) async fn health(a: &App, local: Option<&[String]>) -> Result<Vec<Value>> {
    let Some(sid) = local_sid(a)? else {
        return Ok(Vec::new());
    };
    let m = if sid == 1 {
        membership(a, FIRST_ID, 1)?
    } else {
        let Some(raw): Option<String> =
            a.db.lock()
                .unwrap()
                .query_row(
                    "SELECT value FROM settings WHERE key='directory_peer_topology'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .map_err(anyhow::Error::from)?
        else {
            return Ok(Vec::new());
        };
        serde_json::from_str(&raw).map_err(anyhow::Error::from)?
    };
    let mut probes = tokio::task::JoinSet::new();
    for provider in m.providers {
        let (base, id, key) = (m.base.clone(), m.id.clone(), m.credential.clone());
        let local = local.map(<[String]>::to_vec);
        probes.spawn(async move {
            let remote = probe_provider(&base,&id,&key,&provider.endpoint).await.ok();
            let confirmed = remote.as_ref().zip(local.as_ref())
                .is_some_and(|(remote,local)|covers(local,remote) && covers(remote,local));
            let state = if confirmed {"synchronized"} else if remote.is_some() {"catching_up"} else {"unreachable"};
            let endpoint = format!("ldaps://{}:{}",provider.endpoint.address,provider.endpoint.port);
            json!({"id":format!("provider-{}",provider.sid),"name":format!("Directory node {}",provider.sid),
                "role":"provider","endpoint":endpoint,"reachable":remote.is_some(),"state":state,
                "context_csn":remote,"checked_at":now(),"last_sync_at":confirmed.then(now),
                "error":if remote.is_some(){None}else{Some("Could not check this node over verified directory TLS")}})
        });
    }
    let mut result = Vec::new();
    while let Some(node) = probes.join_next().await {
        result.push(node.map_err(anyhow::Error::from)?);
    }
    result.sort_by_cached_key(|v| v["name"].as_str().unwrap_or_default().to_owned());
    Ok(result)
}
