#![feature(test)]

extern crate test;
extern crate rand;

#[cfg(test)]
mod tests {
    use test::Bencher;
    use proxy_socks::test_utils;
    use trust_dns_resolver::TokioAsyncResolver;
    use proxy_relay::TargetAddr;
    use proxy_socks::client::{SocksProxyConfig, SocksClient};
    use tokio::prelude::*;
    use rand::rngs::SmallRng;
    use rand::{RngCore, SeedableRng};
    use tokio::runtime::Runtime;
    use std::sync::{Arc, Mutex};

    #[bench]
    fn client_write_bench(b: &mut Bencher) {
        // let _ = env_logger::try_init();
        let mut rt = Runtime::new().unwrap();
        let total: u32 = 10;
        let mut buf = [0u8; 4096];
        let mut small_rng = SmallRng::from_entropy();
        small_rng.fill_bytes(&mut buf);
        let connection = rt.block_on(async {
            let upstream_addr = test_utils::start_test_upstream_server(false).await.unwrap();
            let proxy_addr = test_utils::start_auth_socks_server("user", "pass").await.unwrap();
            let resolver = TokioAsyncResolver::tokio_from_system_conf().await.unwrap();
            let proxy = TargetAddr::Addr(proxy_addr);
            let server = SocksProxyConfig::new_auth(proxy, "user", "pass");
            let connection = SocksClient::connect(TargetAddr::Addr(upstream_addr), &server, &resolver)
                .await
                .unwrap();
            return Arc::new(Mutex::new(connection));
        });
        for _ in 0..total {
            b.iter(|| {
                let inner = connection.clone();
                rt.block_on(async move {
                    let _ = inner.lock().unwrap().write(&buf).await;
                })
            });
        }
        b.bytes = (total * 4096) as u64;
    }
}