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
        let nodelay = connection.nodelay();
        if let Err(e) = connection.set_nodelay(true) {
            warn!("Couldn't enable tcp_nodelay: {:?}", e);
        }
        let (mut inbound, mut outbound) = connection.split();
        let methods = auth_provider.methods().await;
        debug!(
            "Writing auth methods: {:?}, version: {:?}",
            methods, version
        );
        let auth_methods_request = SocksAuthMethodsRequest::new(version, methods);
        debug!("Sending auth method request: {:?}", auth_methods_request);
        auth_methods_request.write_to(&mut outbound).await?;
        let auth_methods_response = SocksAuthMethodsResponse::read_from(&mut inbound).await?;
        debug!("Received server auth method response: {:?}", auth_methods_response);
        let method_res = auth_methods_response.method;
        if method_res.is_none() {
            return Err(SocksError::NoAuthMethodSupported);
        }
        let method = method_res.unwrap();
        debug!("Selected auth method: {:?}", method);
        auth_provider
            .authenticate(version, method, &mut inbound, &mut outbound)
            .await?;
        let request = SocksRequest::new(version, SocksCommand::Connect, target_addr);
        debug!("Sending request: {:?}", request);
        request.write_to(&mut outbound).await?;
        let response = SocksResponse::read_from(&mut inbound).await?;
        debug!("Received server response: {:?}", response);
        if response.code != SocksResponseCode::Success {
            debug!("Received server response code: {:?}", response.code);
            return Err(SocksError::ConnectionFailed(response.code));
        }
        match nodelay {
            Ok(nodelay) => {
                if let Err(e) = connection.set_nodelay(nodelay) {
                    warn!("Couldn't disable tcp_nodelay: {:?}", e);
                }
            },
            Err(e) => {
                warn!("Couldn't fetch tcp_nodelay status: {:?}", e);
            }
        }
        Ok(())
    }
}
