//! The primary is configured during first-run setup, never during replica enrollment.
use super::*;
pub(super) async fn status(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    admin(&a, &h, false).await?;
    let network = config(&a)
        .and_then(|v| v.get("network").cloned())
        .ok_or(bad("Complete initial setup before adding replicas"))?;
    Ok(Json(
        json!({"manager_url":public_url(&a),"https_ready":public_url(&a).starts_with("https://"),"primary":network}),
    ))
}
pub(super) fn private_ipv4(raw: &str) -> Result<std::net::Ipv4Addr> {
    let ip: std::net::Ipv4Addr = raw
        .parse()
        .map_err(|_| bad("Enter a private IPv4 address"))?;
    if !ip.is_private() {
        return Err(bad("Choose a private LAN IPv4 address"));
    }
    Ok(ip)
}
