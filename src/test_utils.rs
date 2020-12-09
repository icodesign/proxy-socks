use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::stream::StreamExt;
use crate::server::SocksServer;
use tokio::runtime::Handle;

pub async fn start_no_auth_socks_server() -> io::Result<SocketAddr> {
    let proxy =
        SocksServer::start_no_auth(("127.0.0.1", 0), Handle::current()).await?;
    Ok(proxy.local_addr())
}

pub async fn start_auth_socks_server(user: &str, pass: &str) -> io::Result<SocketAddr> {
    let proxy =
        SocksServer::start_auth(("127.0.0.1", 0), user, pass, Handle::current()).await?;
    Ok(proxy.local_addr())
}

pub async fn start_test_upstream_server(copyback: bool) -> io::Result<SocketAddr> {
    let mut listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Some(socket_res) = listener.incoming().next().await {
            let mut socket: TcpStream = match socket_res {
                Err(e) => {
                    warn!("error accepting tcp socket: {:?}", e);
                    continue;
                }
                Ok(socket) => socket,
            };
            debug!(
                "Test server accepted connection from {:?}",
                socket.peer_addr()
            );
            tokio::spawn(async move {
                if copyback {
                    let (mut reader, mut writer) = socket.split();
                    tokio::io::copy(&mut reader, &mut writer).await
                } else {
                    let mut buf = [0u8; 8192];
                    loop {
                        let _ = socket.read(&mut buf[..8192]).await;
                    }
                }
            });
        }
    });
    Ok(addr)
}
