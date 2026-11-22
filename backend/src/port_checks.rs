//! Bounded transport probes. A failed connection cannot identify which firewall/router/service caused it.
use anyhow::{Result, ensure};
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{Name, RecordType},
};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn tcp(host: &str, port: u16) -> (&'static str, String) {
    match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => ("pass", "TCP connection accepted from this probe source; this does not verify TLS, authentication or other network paths".into()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => ("failure", "TCP connection refused; check the listener, published port and reject rules".into()),
        Ok(Err(_)) => ("failure", "TCP connection failed; check address resolution, listener, routing, host/network firewall and published ports".into()),
        Err(_) => ("failure", "TCP connection timed out; a firewall, routing problem or unavailable service may be responsible".into()),
    }
}
async fn dns_exchange(address: SocketAddr, tcp: bool) -> Result<()> {
    let mut query = Message::query();
    query.metadata.recursion_desired = false;
    query.add_query(Query::query(Name::root(), RecordType::SOA));
    let bytes = query.to_vec()?;
    let data = if tcp {
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        stream.write_u16(bytes.len() as u16).await?;
        stream.write_all(&bytes).await?;
        let len = stream.read_u16().await? as usize;
        ensure!(len >= 12, "Short DNS response");
        let mut data = vec![0; len];
        stream.read_exact(&mut data).await?;
        data
    } else {
        let socket = tokio::net::UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        socket.connect(address).await?;
        socket.send(&bytes).await?;
        let mut data = vec![0; 65535];
        let len = socket.recv(&mut data).await?;
        data.truncate(len);
        data
    };
    let response = Message::from_vec(&data)?;
    ensure!(
        response.id == query.id
            && response.message_type == MessageType::Response
            && response.queries == query.queries
            && response.op_code == query.op_code,
        "Mismatched DNS response"
    );
    // REFUSED/NXDOMAIN still prove this transport carried a DNS response. Zone health is checked separately.
    Ok(())
}
pub async fn dns(address: IpAddr, port: u16, tcp: bool) -> (&'static str, String) {
    match tokio::time::timeout(Duration::from_secs(2), dns_exchange(SocketAddr::new(address,port), tcp)).await {
        Ok(Ok(())) => ("pass", "Matching DNS response received over this transport from this probe source; zone contents and replication are checked separately".into()),
        _ => ("failure", "No valid DNS response on this transport; check the listener, published TCP/UDP ports, routing and host/network firewall".into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn probes_require_a_live_listener_and_matching_dns_reply() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        assert_eq!(tcp("127.0.0.1", address.port()).await.0, "pass");
        drop(listener);
        assert_eq!(tcp("127.0.0.1", address.port()).await.0, "failure");
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        let worker = tokio::spawn(async move {
            for valid in [true, false] {
                let mut bytes = [0u8; 512];
                let (len, peer) = udp.recv_from(&mut bytes).await.unwrap();
                let mut response = Message::from_vec(&bytes[..len]).unwrap();
                response.metadata.message_type = MessageType::Response;
                if !valid {
                    response.metadata.id = response.id.wrapping_add(1);
                }
                udp.send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        assert_eq!(dns(address.ip(), address.port(), false).await.0, "pass");
        assert_eq!(dns(address.ip(), address.port(), false).await.0, "failure");
        worker.await.unwrap();
    }
}
