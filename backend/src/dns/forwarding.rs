//! Fixed upstream forwarding settings; the DNS supervisor owns persistent runtime state.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Upstream {
    address: IpAddr,
    port: u16,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    enabled: bool,
    upstreams: Vec<Upstream>,
    allowed_clients: Vec<String>,
}
fn client_network(raw: &str) -> bool {
    let Some((address, prefix)) = raw.split_once('/') else {
        return false;
    };
    let (Ok(address), Ok(prefix)) = (address.parse::<IpAddr>(), prefix.parse::<u32>()) else {
        return false;
    };
    match address {
        IpAddr::V4(ip) if (1..=32).contains(&prefix) => {
            let mask = u32::MAX << (32 - prefix);
            let first = u32::from(ip) & mask;
            let last = Ipv4Addr::from(first | !mask);
            first == u32::from(ip)
                && ((ip.is_private() && last.is_private())
                    || (ip.is_loopback() && last.is_loopback()))
        }
        IpAddr::V6(ip) if (7..=128).contains(&prefix) => {
            let mask = u128::MAX << (128 - prefix);
            (u128::from(ip) & mask) == u128::from(ip)
                && (ip.is_unique_local() || (ip.is_loopback() && prefix == 128))
        }
        _ => false,
    }
}
fn validate(value: &Settings, own: Option<&replication::Primary>) -> Result<()> {
    if value.upstreams.len() > 4 || (value.enabled && value.upstreams.is_empty()) {
        return Err(bad(
            "Choose one to four upstream DNS servers before enabling forwarding",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for peer in &value.upstreams {
        let address = peer.address.to_canonical();
        if peer.port == 0
            || address.is_loopback()
            || address.is_unspecified()
            || address.is_multicast()
            || address == IpAddr::V4(Ipv4Addr::BROADCAST)
            || own.is_some_and(|p| address == IpAddr::V4(p.address) && peer.port == p.dns_port)
            || !seen.insert((address, peer.port))
        {
            return Err(bad(
                "Use distinct upstream DNS servers. Do not enter Forklift’s own DNS address or localhost.",
            ));
        }
    }
    if !(1..=16).contains(&value.allowed_clients.len())
        || value.allowed_clients.iter().any(|n| !client_network(n))
    {
        return Err(bad(
            "Enter private client networks with their network size, such as 192.168.1.0/24. Public or all-network ranges are not allowed.",
        ));
    }
    Ok(())
}
pub(crate) async fn get(State(a): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    peer::editor(&a, &h, false).await?;
    control(Method::GET, None).await
}
pub(super) async fn control(method: Method, value: Option<&Value>) -> Result<Json<Value>> {
    let (status, body) = transport(method, "/forwarding", value, true).await?;
    if !status.is_success() {
        return Err(unavailable(
            "DNS forwarding settings are unavailable. Check DNS container health and update its image if needed, then refresh this page before retrying.",
        ));
    }
    Ok(Json(
        serde_json::from_slice(&body).map_err(anyhow::Error::from)?,
    ))
}
pub(super) async fn current() -> Result<Settings> {
    let Json(value) = control(Method::GET, None).await?;
    serde_json::from_value(value["settings"].clone())
        .map_err(anyhow::Error::from)
        .map_err(Error::from)
}

pub(super) async fn apply(value: &Settings, own: Option<&replication::Primary>) -> Result<()> {
    validate(value, own)?;
    let desired = serde_json::to_value(value).map_err(anyhow::Error::from)?;
    let Json(local) = control(Method::GET, None).await?;
    if local["settings"] != desired {
        let _ = control(Method::PUT, Some(&desired)).await?;
    }
    Ok(())
}

pub(crate) async fn put(
    State(a): State<App>,
    h: HeaderMap,
    Json(value): Json<Settings>,
) -> Result<Json<Value>> {
    let who = peer::editor(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    validate(&value, replication::primary(&a)?.as_ref())?;
    for endpoint in replication::peer_endpoints(&a)? {
        validate(&value, Some(&endpoint))?;
    }
    audit(&a, &who, "DNS update forwarding", "primary")?;
    let body = serde_json::to_value(value).map_err(anyhow::Error::from)?;
    match control(Method::PUT, Some(&body)).await {
        Ok(v) => {
            audit(&a, &who, "DNS forwarding saved", "primary")?;
            Ok(v)
        }
        Err(e) => {
            audit(&a, &who, "DNS failed forwarding", "primary")?;
            Err(e)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_client_networks_only() {
        for value in ["192.168.1.0/24", "127.0.0.1/32", "fd00::/8", "::1/128"] {
            assert!(client_network(value), "{value}");
        }
        for value in [
            "0.0.0.0/0",
            "::/0",
            "8.8.8.0/24",
            "192.168.1.1/24",
            "192.168.1.0/33",
            "fd00::1/8",
            "bad",
        ] {
            assert!(!client_network(value), "{value}");
        }
    }
    #[test]
    fn forwarding_rejects_missing_duplicate_and_self_upstreams() {
        let own = replication::Primary {
            address: Ipv4Addr::new(192, 168, 1, 2),
            dns_port: 53,
        };
        let mut value = Settings {
            enabled: true,
            upstreams: vec![],
            allowed_clients: vec!["192.168.1.0/24".into()],
        };
        assert!(validate(&value, Some(&own)).is_err());
        value.upstreams.push(Upstream {
            address: IpAddr::V4(own.address),
            port: 53,
        });
        assert!(validate(&value, Some(&own)).is_err());
        value.upstreams[0].address = "::ffff:127.0.0.1".parse().unwrap();
        assert!(validate(&value, Some(&own)).is_err());
        value.upstreams[0].address = "192.168.1.1".parse().unwrap();
        assert!(validate(&value, Some(&own)).is_ok());
        value.upstreams.push(value.upstreams[0].clone());
        assert!(validate(&value, Some(&own)).is_err());
    }
}
