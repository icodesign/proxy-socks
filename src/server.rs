use crate::auth::{
    PlainSocksServerAuthProvider, ProtectedSocksServerAuthProvider, SocksServerAuthProvider,
};
use crate::common::*;
use proxy_relay::{relay, TargetAddr};
use std::net::{Shutdown, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::prelude::*;
use tokio::runtime::Handle;
use tokio::stream::StreamExt;

pub struct SocksServer {
    local_addr: SocketAddr,
}

impl SocksServer {
    pub async fn start_no_auth<T: ToSocketAddrs>(
        addr: T,
        handle: Handle,
    ) -> io::Result<SocksServer> {
        info!("Starting Socks server with no authentication...");
        SocksServer::start(addr, PlainSocksServerAuthProvider::new(), handle).await
    }

    pub async fn start_auth<T: ToSocketAddrs>(
        addr: T,
        username: &str,
        password: &str,
        handle: Handle,
    ) -> io::Result<SocksServer> {
        info!("Starting Socks server with authentication...");
        SocksServer::start(
            addr,
            ProtectedSocksServerAuthProvider::new(username, password),
            handle,
        )
        .await
    }

    pub async fn start<T: ToSocketAddrs, U: SocksServerAuthProvider + Send + Sync + 'static>(
        addr: T,
        auth_provider: U,
        handle: Handle,
    ) -> io::Result<SocksServer> {
        info!("Starting Socks server...");
        let listener = TcpListener::bind(addr).await?;
        SocksServer::start_with_listener(listener, auth_provider, handle).await
    }

    pub async fn start_with_listener<U: SocksServerAuthProvider + Send + Sync + 'static>(
        mut listener: TcpListener,
        auth_provider: U,
        handle: Handle,
    ) -> io::Result<SocksServer> {
        let local_addr = listener.local_addr()?;
        info!("Socks server listening at {:?}", &local_addr);
        let server_auth_provider = Arc::new(auth_provider);
        handle.spawn(async move {
            while let Some(socket_res) = listener.incoming().next().await {
                let socket: TcpStream = match socket_res {
                    Err(e) => {
                        warn!("Couldn't accept TCP socket: {:?}", e);
                        continue;
                    }
                    Ok(socket) => socket,
                };
                let auth_provider = server_auth_provider.clone();
                Handle::current().spawn(async move {
                    handle_raw_request(socket, auth_provider).await;
                });
            }
        });
        Ok(SocksServer { local_addr })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

struct SocksConnection<T: SocksServerAuthProvider> {
    identifier: String,
    socket: TcpStream,
    auth_provider: Arc<T>,
}

async fn handle_raw_request<T: SocksServerAuthProvider>(socket: TcpStream, auth_provider: Arc<T>) {
    debug!("Accepted connection from {:?}", socket.peer_addr());
    let mut connection = SocksConnection::new(socket, auth_provider);
    let res = connection.handshake().await;
    match res {
        Ok(outbound) => {
            let _ = connection.relay(outbound).await;
        }
        Err(err) => {
            warn!(
                "{}: Socks connection handshake failed: {:?}",
                &connection.identifier, err
            );
            let _ = connection.shutdown();
            return;
        }
    }
}

impl<T: SocksServerAuthProvider> SocksConnection<T> {
    fn new(socket: TcpStream, auth_provider: Arc<T>) -> SocksConnection<T> {
        let identifier = format!("[{:?} -> {:?}]", socket.peer_addr(), socket.local_addr());
        SocksConnection {
            identifier,
            socket,
            auth_provider,
        }
    }

    fn shutdown(&self) -> io::Result<()> {
        self.socket.shutdown(Shutdown::Both)
    }

    async fn handshake(&mut self) -> Result<TcpStream> {
        let nodelay = self.socket.nodelay();
        if let Err(e) = self.socket.set_nodelay(true) {
            warn!("{}: Couldn't enable tcp_nodelay: {:?}", &self.identifier, e);
        }
        let (mut inbound, mut outbound) = self.socket.split();
        debug!("{}: Reading auth methods request...", &self.identifier);
        let auth_method_request = SocksAuthMethodsRequest::read_from(&mut inbound).await?;
        debug!(
            "{}: Received auth methods request: {:?}",
            &self.identifier, auth_method_request
        );
        let version = auth_method_request.version;
        if version != SocksVersion::V5 {
            return Err(SocksError::VersionNotSupported(
                auth_method_request.version.into(),
            ));
        }
        let methods = auth_method_request.methods;
        debug!(
            "{}: {:?} socks auth methods",
            &self.identifier,
            methods.len()
        );
        let auth_provider = self.auth_provider.clone();
        let method = auth_provider.select(&methods[..]).await;
        if method.is_err() {
            let response = SocksAuthMethodsResponse::new(version, None);
            response.write_to(&mut outbound).await?;
            return Err(method.unwrap_err());
        }
        let method = method.unwrap();
        debug!(
            "{}: Select socks auth method: {:?}",
            &self.identifier, method
        );
        let response = SocksAuthMethodsResponse::new(version, Some(method));
        response.write_to(&mut outbound).await?;
        auth_provider
            .validate(version, method, &mut inbound, &mut outbound)
            .await?;
        debug!("{}: Reading socks request...", &self.identifier);
        let request = SocksRequest::read_from(&mut inbound).await?;
        debug!(
            "{}: Received socks request: {:?}",
            &self.identifier, request
        );
        debug!(
            "{}: Making request to upstream: {:?}...",
            &self.identifier, request.addr
        );
        let remote_conn_res = match request.addr.inner() {
            TargetAddr::Addr(addr) => TcpStream::connect(addr).await,
            TargetAddr::Host(domain, port) => {
                TcpStream::connect((domain.as_str(), port.to_owned())).await
            }
        };
        let addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let conn = match remote_conn_res {
            Ok(remote_conn) => {
                debug!("{}: Connected to upstream", &self.identifier);
                let response = SocksResponse::new(
                    version,
                    SocksResponseCode::Success,
                    SocksAddr::new(TargetAddr::Addr(addr)),
                );
                debug!("{}: Send socks response: {:?}", &self.identifier, response);
                response.write_to(&mut outbound).await?;
                Ok(remote_conn)
            }
            Err(e) => {
                debug!("{}: Could not connect to upstream", &self.identifier);
                let response = SocksResponse::new(
                    version,
                    SocksResponseCode::NetworkUnreachable,
                    SocksAddr::new(TargetAddr::Addr(addr)),
                );
                response.write_to(&mut outbound).await?;
                Err(SocksError::IoError(e))
            }
        }?;
        match nodelay {
            Ok(nodelay) => {
                if let Err(e) = self.socket.set_nodelay(nodelay) {
                    warn!("Couldn't disable tcp_nodelay: {:?}", e);
                }
            }
            Err(e) => {
                warn!("Couldn't fetch tcp_nodelay status: {:?}", e);
            }
        }
        Ok(conn)
    }

    async fn relay(&mut self, mut outbound: TcpStream) -> io::Result<()> {
        warn!("{}: Starting relay...", &self.identifier);
        let (written, received) = relay(&mut self.socket, &mut outbound).await?;
        debug!(
            "{}: Client wrote {} bytes and received {} bytes",
            &self.identifier, written, received
        );
        Ok(())
    }
}
