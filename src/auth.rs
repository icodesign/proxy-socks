use super::common::*;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[async_trait]
pub trait SocksServerAuthProvider {
    async fn select(&self, methods: &[SocksAuthMethod]) -> Result<SocksAuthMethod>;
    async fn validate<R, W>(
        &self,
        version: SocksVersion,
        method: SocksAuthMethod,
        inbound: &mut R,
        outbound: &mut W,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send;
}

#[derive(Debug)]
pub struct PlainSocksServerAuthProvider;

impl PlainSocksServerAuthProvider {
    #[allow(dead_code)]
    pub fn new() -> PlainSocksServerAuthProvider {
        PlainSocksServerAuthProvider {}
    }
}

#[async_trait]
impl SocksServerAuthProvider for PlainSocksServerAuthProvider {
    async fn select(&self, methods: &[SocksAuthMethod]) -> Result<SocksAuthMethod> {
        let res = methods.iter().find(|&&x| x == SocksAuthMethod::None);
        if res.is_some() {
            Ok(SocksAuthMethod::None)
        } else {
            Err(SocksError::AuthMethodNotSupported(0xff))
        }
    }

    async fn validate<R, W>(
        &self,
        version: SocksVersion,
        method: SocksAuthMethod,
        _inbound: &mut R,
        outbound: &mut W,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        if version != SocksVersion::V5 {
            auth_respond(version, false, outbound).await?;
            return Err(SocksError::VersionNotSupported(version.into()));
        }
        match method {
            SocksAuthMethod::None => {
                auth_respond(version, true, outbound).await?;
                Ok(())
            }
            _ => {
                auth_respond(version, false, outbound).await?;
                Err(SocksError::AuthMethodNotSupported(method.into()))
            }
        }
    }
}

#[derive(Debug)]
pub struct ProtectedSocksServerAuthProvider {
    username: String,
    password: String,
}

impl ProtectedSocksServerAuthProvider {
    #[allow(dead_code)]
    pub fn new(username: &str, password: &str) -> ProtectedSocksServerAuthProvider {
        ProtectedSocksServerAuthProvider {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }
}

#[async_trait]
impl SocksServerAuthProvider for ProtectedSocksServerAuthProvider {
    async fn select(&self, methods: &[SocksAuthMethod]) -> Result<SocksAuthMethod> {
        let res = methods
            .iter()
            .find(|&&x| x == SocksAuthMethod::UsernamePassword);
        if res.is_some() {
            return Ok(SocksAuthMethod::UsernamePassword);
        }
        Err(SocksError::AuthMethodNotSupported(0xff))
    }

    async fn validate<R, W>(
        &self,
        version: SocksVersion,
        method: SocksAuthMethod,
        inbound: &mut R,
        outbound: &mut W,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        if version != SocksVersion::V5 {
            auth_respond(version, false, outbound).await?;
            return Err(SocksError::VersionNotSupported(version.into()));
        }
        match method {
            SocksAuthMethod::UsernamePassword => {
                UserPassSocksAuthHandler::validate(
                    version,
                    &self.username,
                    &self.password,
                    inbound,
                    outbound,
                )
                .await
            }
            _ => {
                auth_respond(version, false, outbound).await?;
                Err(SocksError::AuthMethodNotSupported(method.into()))
            }
        }
    }
}

#[async_trait]
pub trait SocksClientAuthProvider {
    async fn methods(&self) -> Vec<SocksAuthMethod>;
    async fn authenticate<R, W>(
        &self,
        version: SocksVersion,
        method: SocksAuthMethod,
        inbound: &mut R,
        outbound: &mut W,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send;
}

#[derive(Debug)]
pub struct PlainSocksClientAuthProvider;

impl PlainSocksClientAuthProvider {
    #[allow(dead_code)]
    pub fn new() -> PlainSocksClientAuthProvider {
        PlainSocksClientAuthProvider {}
    }
}

#[async_trait]
impl SocksClientAuthProvider for PlainSocksClientAuthProvider {
    async fn methods(&self) -> Vec<SocksAuthMethod> {
        vec![SocksAuthMethod::None]
    }

    async fn authenticate<R, W>(
        &self,
        version: SocksVersion,
        method: SocksAuthMethod,
        _inbound: &mut R,
        _outbound: &mut W,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        if version != SocksVersion::V5 {
            return Err(SocksError::VersionNotSupported(version.into()));
        }
        match method {
            SocksAuthMethod::None => Ok(()),
            _ => Err(SocksError::AuthMethodNotSupported(method.into())),
        }
    }
}

#[derive(Debug)]
pub struct ProtectedSocksClientAuthProvider {
    username: String,
    password: String,
}

impl ProtectedSocksClientAuthProvider {
    #[allow(dead_code)]
    pub fn new(username: &str, password: &str) -> ProtectedSocksClientAuthProvider {
        ProtectedSocksClientAuthProvider {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }
}

#[async_trait]
impl SocksClientAuthProvider for ProtectedSocksClientAuthProvider {
    async fn methods(&self) -> Vec<SocksAuthMethod> {
        vec![SocksAuthMethod::None, SocksAuthMethod::UsernamePassword]
    }

    async fn authenticate<R, W>(
        &self,
        version: SocksVersion,
        method: SocksAuthMethod,
        inbound: &mut R,
        outbound: &mut W,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        if version != SocksVersion::V5 {
            return Err(SocksError::VersionNotSupported(version.into()));
        }
        match method {
            SocksAuthMethod::None => Ok(()),
            SocksAuthMethod::UsernamePassword => {
                UserPassSocksAuthHandler::authenticate(
                    &self.username,
                    &self.password,
                    inbound,
                    outbound,
                )
                .await
            }
            _ => Err(SocksError::AuthMethodNotSupported(method.into())),
        }
    }
}

#[derive(Debug)]
pub struct UserPassSocksAuthHandler;

impl UserPassSocksAuthHandler {
    async fn validate<R, W>(
        version: SocksVersion,
        username: &str,
        password: &str,
        inbound: &mut R,
        outbound: &mut W,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let auth_version_raw = inbound.read_u8().await?;
        if auth_version_raw != 0x01 {
            return Err(SocksError::VersionNotSupported(auth_version_raw));
        }
        let ulen = inbound.read_u8().await?;
        let mut ubuff = BytesMut::with_capacity(ulen as usize);
        inbound.read_buf(&mut ubuff).await?;
        let plen = inbound.read_u8().await?;
        let mut pbuff = BytesMut::with_capacity(plen as usize);
        inbound.read_buf(&mut pbuff).await?;
        if username.as_bytes() == &ubuff[..] && password.as_bytes() == &pbuff[..] {
            auth_respond(version, true, outbound).await
        } else {
            auth_respond(version, false, outbound).await?;
            Err(SocksError::AuthFailed("incorrect credentials".to_owned()))
        }
    }

    async fn authenticate<R, W>(
        username: &str,
        password: &str,
        inbound: &mut R,
        outbound: &mut W,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let username_bytes = username.as_bytes();
        let ulen = username_bytes.len();
        let password_bytes = password.as_bytes();
        let plen = password_bytes.len();
        if ulen > 255 {
            return Err(SocksError::AuthFailed("username is too long".to_owned()));
        }
        if plen > 255 {
            return Err(SocksError::AuthFailed("password is too long".to_owned()));
        }
        let mut buf = BytesMut::with_capacity(1 + 1 + ulen + 1 + plen);
        buf.put_u8(0x01);
        buf.put_u8(ulen as u8);
        buf.put_slice(username_bytes);
        buf.put_u8(plen as u8);
        buf.put_slice(password_bytes);
        debug!("auth: {:?}", &buf);
        outbound.write_all(&buf).await?;
        // version
        let _ = inbound.read_u8().await?;
        let res = inbound.read_u8().await?;
        if res == 0x00 {
            Ok(())
        } else {
            return Err(SocksError::AuthFailed("incorrect credential".to_owned()));
        }
    }
}

async fn auth_respond<T>(version: SocksVersion, success: bool, outbound: &mut T) -> Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    let res = if success { 0x00 } else { 0x01 };
    outbound.write_all(&[version.into(), res]).await?;
    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::sync::Arc;
//     use tokio::net::{TcpListener, TcpStream};
//     use tokio::sync::oneshot;
//     use tokio::sync::Mutex;
//
//     #[tokio::test]
//     async fn socks_none_auth() {
//         let server_provider = PlainSocksServerAuthProvider::new();
//         let client_provider = PlainSocksClientAuthProvider::new();
//         let res = socks_auth(
//             SocksVersion::V5,
//             SocksAuthMethod::None,
//             server_provider,
//             client_provider,
//         )
//             .await;
//         assert!(res.is_ok());
//     }
//
//     #[tokio::test]
//     async fn socks_protected_auth() {
//         let username = "testusername";
//         let password = "pass&%&*%^1244";
//         let server_provider = ProtectedSocksServerAuthProvider::new(username, password);
//         let client_provider = ProtectedSocksClientAuthProvider::new(username, password);
//         let res = socks_auth(
//             SocksVersion::V5,
//             SocksAuthMethod::UsernamePassword,
//             server_provider,
//             client_provider,
//         )
//             .await;
//         assert!(res.is_ok());
//     }
//
//     #[tokio::test]
//     async fn socks_protected_auth_wrong_credential() {
//         let username = "testusername";
//         let password = "pass&%&*%^1244";
//         let server_provider = ProtectedSocksServerAuthProvider::new(username, password);
//         let client_provider = ProtectedSocksClientAuthProvider::new(username, "wrongpass");
//         let res = socks_auth(
//             SocksVersion::V5,
//             SocksAuthMethod::UsernamePassword,
//             server_provider,
//             client_provider,
//         )
//             .await;
//         assert!(res.is_err());
//     }
//
//     async fn socks_auth<S, C>(
//         version: SocksVersion,
//         method: SocksAuthMethod,
//         server_provider: S,
//         client_provider: C,
//     ) -> Result<()>
//         where
//             S: SocksServerAuthProvider + Send + Sync + 'static,
//             C: SocksClientAuthProvider + Send + 'static,
//     {
//         let (tx, rx) = oneshot::channel();
//         let inner = Arc::new(Mutex::new(server_provider));
//         tokio::spawn(async move {
//             let mut server = TcpListener::bind("127.0.0.1:0").await.unwrap();
//             let server_addr = server.local_addr().unwrap();
//             assert!(tx.send(server_addr).is_ok());
//             let (mut socket, _) = server.accept().await.unwrap();
//             let (mut inbound, mut outbound) = socket.split();
//             let provider = inner.lock().await;
//             let _ = provider
//                 .validate(version, method, &mut inbound, &mut outbound)
//                 .await;
//         });
//         let server_addr = rx.await.unwrap();
//         let mut client = TcpStream::connect(&server_addr).await.unwrap();
//         let (mut inbound, mut outbound) = client.split();
//         client_provider
//             .authenticate(version, method, &mut inbound, &mut outbound)
//             .await
//     }
// }
