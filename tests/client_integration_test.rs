use log::debug;
use proxy_relay::TargetAddr;
use proxy_socks::client::{SocksClient, SocksProxyConfig};
use proxy_socks::test_utils;
use std::net::Shutdown;
use tokio::prelude::*;
use trust_dns_resolver::TokioAsyncResolver;

#[tokio::test]
async fn socks_client_auth_integration() {
    // let _ = env_logger::try_init();
    let upstream_addr = test_utils::start_test_upstream_server(true).await.unwrap();
    let proxy_addr = test_utils::start_auth_socks_server("user", "pass").await.unwrap();
    let resolver = TokioAsyncResolver::tokio_from_system_conf().await.unwrap();
    let proxy = TargetAddr::Addr(proxy_addr);
    let server = SocksProxyConfig::new_auth(proxy, "user", "pass");
    let mut connection = SocksClient::connect(TargetAddr::Addr(upstream_addr), &server, &resolver)
        .await
        .unwrap();
    let _ = connection.write(b"hello world!").await;
    let _ = connection.shutdown(Shutdown::Write);
    let mut buffer = String::new();
    let _ = connection.read_to_string(&mut buffer).await;
    debug!("The response: {:?}", &buffer);
}

#[tokio::test]
async fn socks_client_no_auth_integration() {
    // let _ = env_logger::try_init();
    let upstream_addr = test_utils::start_test_upstream_server(true).await.unwrap();
    let proxy_addr = test_utils::start_no_auth_socks_server().await.unwrap();
    let resolver = TokioAsyncResolver::tokio_from_system_conf().await.unwrap();
    let proxy = TargetAddr::Addr(proxy_addr);
    let server = SocksProxyConfig::new(proxy);
    let mut connection = SocksClient::connect(TargetAddr::Addr(upstream_addr), &server, &resolver)
        .await
        .unwrap();
    let _ = connection.write(b"hello world!").await;
    let _ = connection.shutdown(Shutdown::Write);
    let mut buffer = String::new();
    let _ = connection.read_to_string(&mut buffer).await;
    debug!("The response: {:?}", &buffer);
}
