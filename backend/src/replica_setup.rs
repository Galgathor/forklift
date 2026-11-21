//! Guided deployment preparation. No credentials are sent to user-supplied endpoints.
use super::*;
use rusqlite::OptionalExtension;

pub(super) async fn status(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    let endpoint: Option<String> =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key='replication_primary_endpoint'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
    Ok(Json(
        json!({"manager_url":a.url,"https_ready":a.url.starts_with("https://"),"primary_endpoint":endpoint}),
    ))
}
#[derive(Deserialize)]
pub(super) struct Primary {
    hostname: String,
    port: u16,
}
pub(super) async fn check(
    State(a): State<App>,
    h: HeaderMap,
    Json(p): Json<Primary>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    if p.port == 0 || p.hostname.parse::<std::net::IpAddr>().is_ok() {
        return Err(bad(
            "Use the primary server's DNS name and a port from 1 to 65535",
        ));
    }
    let endpoint = format!("ldaps://{}:{}", p.hostname, p.port);
    if hosts::endpoint_hostname(&endpoint)? != p.hostname {
        return Err(bad("Use a lowercase DNS hostname without a scheme or port"));
    }
    let ca = std::fs::read("/run/secrets/ca.crt").map_err(anyhow::Error::from)?;
    let expected = std::fs::read("/run/secrets/ldap.crt").map_err(|_| bad("Update the primary Compose stack first; its public directory certificate must be mounted in the manager"))?;
    let expected = openssl::x509::X509::from_pem(&expected)
        .and_then(|c| c.to_der())
        .map_err(anyhow::Error::from)?;
    let mut tls = native_tls::TlsConnector::builder();
    tls.disable_built_in_roots(true);
    tls.add_root_certificate(native_tls::Certificate::from_pem(&ca).map_err(anyhow::Error::from)?);
    let settings = ldap3::LdapConnSettings::new()
        .set_conn_timeout(std::time::Duration::from_secs(5))
        .set_connector(tls.build().map_err(anyhow::Error::from)?);
    let result = async {
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &endpoint).await?;
        ldap3::drive!(conn);
        // Check the exact configured primary leaf, not merely any certificate signed by its CA.
        // Do not bind: a mistyped endpoint never receives administrative/service credentials.
        anyhow::ensure!(
            ldap.get_peer_certificate().await? == Some(expected),
            "Different primary certificate"
        );
        ldap.unbind().await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        return Err(Error(StatusCode::BAD_REQUEST, "Cannot verify this primary address. Run the preparation command on the existing Forklift Docker host, check the DNS record and private port/firewall, then retry. The certificate must include this hostname. No credentials were sent.".into()));
    }
    a.db.lock().unwrap().execute("INSERT INTO settings(key,value) VALUES('replication_primary_endpoint',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [&endpoint]).map_err(anyhow::Error::from)?;
    audit(&a, &who, "verify replication primary address", &endpoint)?;
    Ok(Json(
        json!({"verified":true,"endpoint":endpoint,"checked_at":now()}),
    ))
}
pub(super) fn private_ipv4(raw: &str) -> Result<std::net::Ipv4Addr> {
    let ip: std::net::Ipv4Addr = raw
        .parse()
        .map_err(|_| bad("Enter the new server's private IPv4 address"))?;
    if !ip.is_private() {
        return Err(bad(
            "Use a private LAN IPv4 address, not a public address or all interfaces",
        ));
    }
    Ok(ip)
}
