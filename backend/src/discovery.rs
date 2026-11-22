//! Optional LAN publisher. No storage, signing secrets or privileged control sockets.
use anyhow::{Context, Result, ensure};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use serde::Deserialize;
use std::time::Duration;
#[derive(Deserialize)]
struct Descriptor {
    api_version: u8,
    instance_id: String,
    name: String,
    url: String,
}
pub(crate) async fn publish() -> Result<()> {
    let origin = std::env::var("FORKLIFT_PUBLIC_URL")
        .context("Set FORKLIFT_PUBLIC_URL to the verified HTTPS origin")?;
    let url = reqwest::Url::parse(&origin)?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "Discovery needs an HTTPS origin"
    );
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10));
    if let Ok(file) = std::env::var("FORKLIFT_DISCOVERY_CA_FILE") {
        let pem = std::fs::read(file)?;
        ensure!(pem.len() <= 1024 * 1024, "CA bundle exceeds limit");
        for certificate in reqwest::Certificate::from_pem_bundle(&pem)? {
            builder = builder.add_root_certificate(certificate);
        }
    }
    let http = builder.build()?;
    let daemon = ServiceDaemon::new()?;
    let mut advertised: Option<String> = None;
    let mut fingerprint = String::new();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        let fetched = async {
            let mut response = http
                .get(format!(
                    "{}/api/client/v1/info",
                    origin.trim_end_matches('/')
                ))
                .send()
                .await?
                .error_for_status()?;
            ensure!(
                response.content_length().unwrap_or(0) <= 16384,
                "Discovery descriptor exceeds limit"
            );
            let mut data = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    data.len() + chunk.len() <= 16384,
                    "Discovery descriptor exceeds limit"
                );
                data.extend_from_slice(&chunk);
            }
            let d: Descriptor = serde_json::from_slice(&data)?;
            ensure!(
                d.api_version == 1
                    && d.instance_id.len() == 32
                    && d.instance_id.bytes().all(|b| b.is_ascii_hexdigit())
                    && d.name.len() <= 100
                    && !d.name.chars().any(char::is_control)
                    && d.url == origin.trim_end_matches('/'),
                "Invalid discovery descriptor"
            );
            Ok::<_, anyhow::Error>(d)
        }
        .await;
        match fetched {
            Ok(d) => {
                let addresses = tokio::net::lookup_host((
                    url.host_str().context("Missing endpoint host")?,
                    url.port_or_known_default().unwrap_or(443),
                ))
                .await?
                .map(|a| a.ip())
                .collect::<std::collections::BTreeSet<_>>();
                let address_list = addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let next = format!("{}:{}:{}:{address_list}", d.instance_id, d.url, d.name);
                if next != fingerprint {
                    if let Some(name) = advertised.take() {
                        daemon.unregister(&name)?;
                    }
                    let properties = [
                        ("url", d.url.as_str()),
                        ("api", "1"),
                        ("instance", d.instance_id.as_str()),
                        ("name", d.name.as_str()),
                    ];
                    let name = format!("Forklift-{}", &d.instance_id[..12]);
                    // Publish resolved endpoint addresses, not the publisher machine addresses.
                    // The client verifies the HTTPS origin from TXT rather than trusting this alias.
                    let service = ServiceInfo::new(
                        "_forklift._tcp.local.",
                        &name,
                        &format!("forklift-{}.local.", d.instance_id),
                        address_list.as_str(),
                        url.port_or_known_default().unwrap_or(443),
                        &properties[..],
                    )?;
                    advertised = Some(service.get_fullname().to_string());
                    daemon.register(service)?;
                    fingerprint = next;
                    eprintln!("Forklift discovery advertisement registered");
                }
            }
            Err(_) => {
                if let Some(name) = advertised.take() {
                    daemon.unregister(&name)?;
                    fingerprint.clear();
                    eprintln!("Discovery unavailable: verify the manager HTTPS origin and trust");
                }
            }
        }
        tokio::select! {_ = tokio::time::sleep(Duration::from_secs(30))=>{},_ = async {tokio::select!{_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}}=>{if let Some(name)=advertised.take(){daemon.unregister(&name)?;}daemon.shutdown()?;return Ok(());}}
    }
}
