use crate::auth::{
    PlainSocksClientAuthProvider, ProtectedSocksClientAuthProvider, SocksClientAuthProvider,
};
use crate::common::*;
use proxy_relay::TargetAddr;
use tokio::net::TcpStream;
use trust_dns_resolver::proto::DnsHandle;
use trust_dns_resolver::{AsyncResolver, ConnectionProvider};

#[derive(Clone, Debug)]
pub struct SocksProxyConfig {
    addr: TargetAddr,
    auth: Option<SocksProxyAuthConfig>,
}

impl SocksProxyConfig {
    pub fn new(addr: TargetAddr) -> SocksProxyConfig {
        SocksProxyConfig { addr, auth: None }
    }

    pub fn new_auth(addr: TargetAddr, username: &str, password: &str) -> SocksProxyConfig {
        let auth = SocksProxyAuthConfig::new(username, password);
        SocksProxyConfig {
            addr,
            auth: Some(auth),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SocksProxyAuthConfig {
    username: String,
    password: String,
}

impl SocksProxyAuthConfig {
    fn new(username: &str, password: &str) -> SocksProxyAuthConfig {
        SocksProxyAuthConfig {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }

    fn username(&self) -> &str {
        &self.username
    }

    fn password(&self) -> &str {
        &self.password
    }
}

pub struct SocksClient;

impl SocksClient {
    pub async fn connect<C: DnsHandle, P: ConnectionProvider<Conn = C>>(
        target: TargetAddr,
        proxy: &SocksProxyConfig,
        resolver: &AsyncResolver<C, P>,
    ) -> Result<TcpStream> {
        let target_addr = SocksAddr::new(target);
        match &proxy.auth {
            Some(auth) => {
                SocksClient::connect_auth(target_addr, proxy.addr.clone(), auth.clone(), resolver)
                    .await
            }
            None => SocksClient::connect_no_auth(target_addr, proxy.addr.clone(), resolver).await,
        }
    }

    async fn connect_no_auth<C: DnsHandle, P: ConnectionProvider<Conn = C>>(
        target_addr: SocksAddr,
        proxy_addr: TargetAddr,
        resolver: &AsyncResolver<C, P>,
    ) -> Result<TcpStream> {
        let auth_provider = PlainSocksClientAuthProvider::new();
        SocksClient::connect_inner(target_addr, proxy_addr, auth_provider, resolver).await
    }

    async fn connect_auth<C: DnsHandle, P: ConnectionProvider<Conn = C>>(
        target_addr: SocksAddr,
        proxy_addr: TargetAddr,
        proxy_auth: SocksProxyAuthConfig,
        resolver: &AsyncResolver<C, P>,
    ) -> Result<TcpStream> {
        let auth_provider =
            ProtectedSocksClientAuthProvider::new(proxy_auth.username(), proxy_auth.password());
        SocksClient::connect_inner(target_addr, proxy_addr, auth_provider, resolver).await
    }

    async fn connect_inner<
        T: SocksClientAuthProvider + Send + Sync,
        C: DnsHandle,
        P: ConnectionProvider<Conn = C>,
    >(
        target_addr: SocksAddr,
        proxy_addr: TargetAddr,
        proxy_auth_provider: T,
        resolver: &AsyncResolver<C, P>,
    ) -> Result<TcpStream> {
        debug!("Connecting to proxy...");
        let mut connection = proxy_addr.connect(resolver).await?;
        debug!("Connected to proxy");
        SocksClient::handshake(
            target_addr,
            &mut connection,
            SocksVersion::V5,
            proxy_auth_provider,
        )
        .await?;
        debug!("Successfully handshake with proxy");
        Ok(connection)
    }

    async fn handshake<T: SocksClientAuthProvider + Send + Sync>(
        target_addr: SocksAddr,
        connection: &mut TcpStream,
        version: SocksVersion,
        auth_provider: T,
    ) -> Result<()> {
        let (mut inbound, mut outbound) = connection.split();
        let methods = auth_provider.methods().await;
        debug!(
            "Writing auth methods: {:?}, version: {:?}",
            methods, version
        );
        let auth_methods_request = SocksAuthMethodsRequest::new(version, methods);
        auth_methods_request.write_to(&mut outbound).await?;
        let auth_methods_response = SocksAuthMethodsResponse::read_from(&mut inbound).await?;
        let method_res = auth_methods_response.method;
        if method_res.is_none() {
            return Err(SocksError::NoAuthMethodSupported);
        }
        let method = method_res.unwrap();
        debug!("Received server selected auth method: {:?}", method);
        auth_provider
            .authenticate(version, method, &mut inbound, &mut outbound)
            .await?;
        let request = SocksRequest::new(version, SocksCommand::Connect, target_addr);
        debug!("Writing request: {:?}", request);
        request.write_to(&mut outbound).await?;
        let response = SocksResponse::read_from(&mut inbound).await?;
        if response.code != SocksResponseCode::Success {
            return Err(SocksError::ConnectionFailed(response.code));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::client::{SocksClient, SocksProxyConfig};
    use crate::server::SocksServer;
    use proxy_relay::TargetAddr;
    use std::net::{Shutdown, SocketAddr};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::prelude::*;
    use tokio::runtime::Handle;
    use tokio::stream::StreamExt;
    use trust_dns_resolver::TokioAsyncResolver;

    #[tokio::test]
    async fn socks_client_integration() {
        let upstream_addr = start_test_upstream_server().await.unwrap();
        let proxy_addr = start_socks_server().await.unwrap();
        let resolver = TokioAsyncResolver::tokio_from_system_conf().await.unwrap();
        let proxy = TargetAddr::Addr(proxy_addr);
        let server = SocksProxyConfig::new_auth(proxy, "user", "pass");
        let mut connection =
            SocksClient::connect(TargetAddr::Addr(upstream_addr), &server, &resolver)
                .await
                .unwrap();
        let _ = connection.write(b"hello world!").await;
        let _ = connection.shutdown(Shutdown::Write);
        let mut buffer = String::new();
        let _ = connection.read_to_string(&mut buffer).await;
        debug!("The response: {:?}", &buffer);
    }

    async fn start_socks_server() -> io::Result<SocketAddr> {
        let proxy =
            SocksServer::start_auth(("127.0.0.1", 0), "user", "pass", Handle::current()).await?;
        Ok(proxy.local_addr())
    }

    async fn start_test_upstream_server() -> io::Result<SocketAddr> {
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
                    let (mut reader, mut writer) = socket.split();
                    tokio::io::copy(&mut reader, &mut writer).await
                });
            }
        });
        Ok(addr)
    }
}
