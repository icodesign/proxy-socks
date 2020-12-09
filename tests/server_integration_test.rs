use log::debug;
use proxy_socks::server::SocksServer;
use proxy_socks::test_utils;
use std::net::{IpAddr, Ipv4Addr, Shutdown};
use tokio::prelude::*;
use tokio::runtime::Handle;
use tokio::net::TcpStream;

#[tokio::test]
async fn socks_server_integration() {
    // let _ = env_logger::try_init();
    let server_addr = test_utils::start_test_upstream_server(true).await.unwrap();
    let proxy_addr = test_utils::start_no_auth_socks_server()
        .await
        .unwrap();
    assert_ne!(proxy_addr.port(), 0);
    assert_eq!(proxy_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let _ = client.write_all(&[0x05, 0x01, 0x00]).await;
    let mut buffer = [0; 10];
    let n1 = client.read(&mut buffer[..]).await;
    debug!("The bytes: {:?}", &buffer[..n1.unwrap()]);
    let port = server_addr.port();
    let _ = client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01])
        .await;
    let _ = client.write_u16(port).await;
    let n2 = client.read(&mut buffer[..]).await;
    debug!("The bytes: {:?}", &buffer[..n2.unwrap()]);
    let _ = client.write(b"hello world!").await;
    let _ = client.shutdown(Shutdown::Write);
    let mut buffer = String::new();
    let _ = client.read_to_string(&mut buffer).await;
    debug!("The response: {:?}", &buffer);
}
