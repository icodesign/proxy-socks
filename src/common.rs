use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use proxy_relay::TargetAddr;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::string::FromUtf8Error;
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum SocksError {
    #[error("io error: {0}")]
    IoError(#[from] io::Error),
    #[error("version is not supported: {0}")]
    VersionNotSupported(u8),
    #[error("auth method is not supported: {0}")]
    AuthMethodNotSupported(u8),
    #[error("too many methods")]
    TooManyMethods,
    #[error("command is not supported: {0}")]
    CommandNotSupported(u8),
    #[error("addr type is not supported: {0}")]
    AddrTypeNotSupported(u8),
    #[error("domain name is too long")]
    DomainTooLong,
    #[error("invalid domain: {0}")]
    InvalidDomain(FromUtf8Error),
    #[error("response code is not supported: {0}")]
    ResponseCodeNotSupported(u8),
    #[error("no auth method is supported")]
    NoAuthMethodSupported,
    #[error("auth failed: {0}")]
    AuthFailed(String),
    #[error("connection failed with response code: {0:?}")]
    ConnectionFailed(SocksResponseCode),
}

pub type Result<T, E = SocksError> = std::result::Result<T, E>;

#[async_trait]
pub trait SocksProtocol: Sized {
    async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin + Send;

    async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send;
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum SocksVersion {
    V4,
    V5,
}

impl Into<u8> for SocksVersion {
    fn into(self) -> u8 {
        match self {
            SocksVersion::V4 => 0x04,
            SocksVersion::V5 => 0x05,
        }
    }
}

impl TryFrom<u8> for SocksVersion {
    type Error = SocksError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x04 => Ok(SocksVersion::V4),
            0x05 => Ok(SocksVersion::V5),
            _ => Err(SocksError::VersionNotSupported(value)),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum SocksAuthMethod {
    /// No authentication required.
    None,
    /// GSS API.
    GssApi,
    /// A username + password authentication.
    UsernamePassword,
    /// IANA reserved.
    IanaReserved(u8),
    /// A private authentication method.
    Private(u8),
}

impl Into<u8> for SocksAuthMethod {
    fn into(self) -> u8 {
        match self {
            SocksAuthMethod::None => 0x00,
            SocksAuthMethod::GssApi => 0x01,
            SocksAuthMethod::UsernamePassword => 0x02,
            SocksAuthMethod::IanaReserved(v) => v.to_owned(),
            SocksAuthMethod::Private(v) => v.to_owned(),
        }
    }
}

impl TryFrom<u8> for SocksAuthMethod {
    type Error = SocksError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(SocksAuthMethod::None),
            0x01 => Ok(SocksAuthMethod::GssApi),
            0x02 => Ok(SocksAuthMethod::UsernamePassword),
            0x03..=0x7f => Ok(SocksAuthMethod::IanaReserved(value)),
            0x80..=0xfe => Ok(SocksAuthMethod::Private(value)),
            _ => Err(SocksError::AuthMethodNotSupported(value)),
        }
    }
}

#[derive(Debug)]
pub struct SocksAuthMethodsRequest {
    pub version: SocksVersion,
    pub methods: Vec<SocksAuthMethod>,
}

impl SocksAuthMethodsRequest {
    pub fn new(version: SocksVersion, methods: Vec<SocksAuthMethod>) -> SocksAuthMethodsRequest {
        SocksAuthMethodsRequest { version, methods }
    }
}

#[async_trait]
impl SocksProtocol for SocksAuthMethodsRequest {
    async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let method_len = self.methods.len();
        if method_len > 255 {
            return Err(SocksError::TooManyMethods);
        }
        let mut buf = BytesMut::with_capacity(1 + 1 + method_len);
        buf.put_u8(self.version.into());
        buf.put_u8(method_len as u8);
        for method in self.methods.iter() {
            buf.put_u8((*method).into());
        }
        writer.write_all(&buf).await?;
        Ok(())
    }

    async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let verison_raw = reader.read_u8().await?;
        let version = SocksVersion::try_from(verison_raw)?;
        let method_len = reader.read_u8().await?;
        let mut methods = Vec::<SocksAuthMethod>::new();
        for _ in 0..method_len {
            let method_raw = reader.read_u8().await?;
            let method = SocksAuthMethod::try_from(method_raw)?;
            methods.push(method);
        }
        Ok(SocksAuthMethodsRequest { version, methods })
    }
}

#[derive(Debug)]
pub struct SocksAuthMethodsResponse {
    pub version: SocksVersion,
    pub method: Option<SocksAuthMethod>,
}

impl SocksAuthMethodsResponse {
    pub fn new(version: SocksVersion, method: Option<SocksAuthMethod>) -> SocksAuthMethodsResponse {
        SocksAuthMethodsResponse { version, method }
    }
}

#[async_trait]
impl SocksProtocol for SocksAuthMethodsResponse {
    async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let mut buf = BytesMut::with_capacity(1 + 1);
        buf.put_u8(self.version.into());
        match self.method {
            Some(method) => {
                buf.put_u8(method.into());
            }
            None => {
                buf.put_u8(0xff);
            }
        }
        writer.write_all(&buf).await?;
        Ok(())
    }

    async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let version_raw = reader.read_u8().await?;
        let version = SocksVersion::try_from(version_raw)?;
        let method_raw = reader.read_u8().await?;
        let method = SocksAuthMethod::try_from(method_raw)?;
        Ok(SocksAuthMethodsResponse::new(version, Some(method)))
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum SocksCommand {
    Connect,
    Bind,
    UdpAssociate,
}

impl Into<u8> for SocksCommand {
    fn into(self) -> u8 {
        match self {
            SocksCommand::Connect => 0x01,
            SocksCommand::Bind => 0x02,
            SocksCommand::UdpAssociate => 0x03,
        }
    }
}

impl TryFrom<u8> for SocksCommand {
    type Error = SocksError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(SocksCommand::Connect),
            0x02 => Ok(SocksCommand::Bind),
            0x03 => Ok(SocksCommand::UdpAssociate),
            _ => Err(SocksError::CommandNotSupported(value)),
        }
    }
}

#[derive(Debug)]
pub enum SocksAddrType {
    Ipv4,
    Domain,
    Ipv6,
}

impl Into<u8> for SocksAddrType {
    fn into(self) -> u8 {
        match self {
            SocksAddrType::Ipv4 => 0x01,
            SocksAddrType::Domain => 0x03,
            SocksAddrType::Ipv6 => 0x04,
        }
    }
}

impl TryFrom<u8> for SocksAddrType {
    type Error = SocksError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(SocksAddrType::Ipv4),
            0x03 => Ok(SocksAddrType::Domain),
            0x04 => Ok(SocksAddrType::Ipv6),
            _ => Err(SocksError::AddrTypeNotSupported(value)),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct SocksAddr(TargetAddr);

impl SocksAddr {
    pub fn new(dest: TargetAddr) -> SocksAddr {
        SocksAddr(dest)
    }

    pub fn inner(&self) -> &TargetAddr {
        &self.0
    }

    pub fn serialize_len(&self) -> usize {
        match &self.0 {
            TargetAddr::Addr(SocketAddr::V4(_)) => 1 + 4 + 2,
            TargetAddr::Addr(SocketAddr::V6(_)) => 1 + 16 + 2,
            TargetAddr::Host(domain, _) => 1 + 1 + domain.as_bytes().len() + 2,
        }
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        match &self.0 {
            TargetAddr::Addr(SocketAddr::V4(addr)) => {
                buf.put_u8(SocksAddrType::Ipv4.into());
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            TargetAddr::Addr(SocketAddr::V6(addr)) => {
                buf.put_u8(SocksAddrType::Ipv6.into());
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            TargetAddr::Host(domain, port) => {
                buf.put_u8(SocksAddrType::Domain.into());
                let bytes = domain.as_bytes();
                if bytes.len() > 255 {
                    return Err(SocksError::DomainTooLong);
                }
                buf.put_u8(bytes.len() as u8);
                buf.put_slice(bytes);
                buf.put_u16(*port);
            }
        }
        Ok(())
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let addr_type_raw = reader.read_u8().await?;
        let addr_type = SocksAddrType::try_from(addr_type_raw)?;
        let addr = match addr_type {
            SocksAddrType::Ipv4 => {
                let mut ip = [0; 4];
                reader.read_exact(&mut ip).await?;
                let port = reader.read_u16().await?;
                TargetAddr::Addr(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            SocksAddrType::Ipv6 => {
                let mut ip = [0; 16];
                reader.read_exact(&mut ip).await?;
                let port = reader.read_u16().await?;
                TargetAddr::Addr(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                )))
            }
            SocksAddrType::Domain => {
                let len = reader.read_u8().await?;
                let mut str = Vec::with_capacity(len as usize);
                reader.read_exact(&mut str).await?;
                let domain = String::from_utf8(str).map_err(|e| SocksError::InvalidDomain(e))?;
                let port = reader.read_u16().await?;
                TargetAddr::Host(domain, port)
            }
        };
        Ok(SocksAddr(addr))
    }
}

#[derive(Debug)]
pub struct SocksRequest {
    pub version: SocksVersion,
    pub command: SocksCommand,
    pub addr: SocksAddr,
}

impl SocksRequest {
    pub fn new(version: SocksVersion, command: SocksCommand, addr: SocksAddr) -> SocksRequest {
        SocksRequest {
            version,
            command,
            addr,
        }
    }
}

#[async_trait]
impl SocksProtocol for SocksRequest {
    async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let mut buf = BytesMut::with_capacity(1 + 1 + self.addr.serialize_len());
        buf.put_u8(self.version.into());
        buf.put_u8(self.command.into());
        buf.put_u8(0x00);
        self.addr.write_to_buf(&mut buf)?;
        writer.write_all(&buf).await?;
        Ok(())
    }

    async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let venison_raw = reader.read_u8().await?;
        let version = SocksVersion::try_from(venison_raw)?;
        let command_raw = reader.read_u8().await?;
        let command = SocksCommand::try_from(command_raw)?;
        // Reserved
        let _ = reader.read_u8().await?;
        let addr = SocksAddr::read_from(reader).await?;
        Ok(SocksRequest {
            version,
            command,
            addr,
        })
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(dead_code)]
pub enum SocksResponseCode {
    Success,
    GeneralSocksServerFailure,
    ConnectionNotAllowedByRuleset,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddrTypeNotSupported,
}

impl Into<u8> for SocksResponseCode {
    fn into(self) -> u8 {
        match self {
            SocksResponseCode::Success => 0x00,
            SocksResponseCode::GeneralSocksServerFailure => 0x01,
            SocksResponseCode::ConnectionNotAllowedByRuleset => 0x02,
            SocksResponseCode::NetworkUnreachable => 0x03,
            SocksResponseCode::HostUnreachable => 0x04,
            SocksResponseCode::ConnectionRefused => 0x05,
            SocksResponseCode::TtlExpired => 0x06,
            SocksResponseCode::CommandNotSupported => 0x07,
            SocksResponseCode::AddrTypeNotSupported => 0x08,
        }
    }
}

impl TryFrom<u8> for SocksResponseCode {
    type Error = SocksError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(SocksResponseCode::Success),
            0x01 => Ok(SocksResponseCode::NetworkUnreachable),
            0x02 => Ok(SocksResponseCode::ConnectionNotAllowedByRuleset),
            0x03 => Ok(SocksResponseCode::NetworkUnreachable),
            0x04 => Ok(SocksResponseCode::HostUnreachable),
            0x05 => Ok(SocksResponseCode::ConnectionRefused),
            0x06 => Ok(SocksResponseCode::TtlExpired),
            0x07 => Ok(SocksResponseCode::CommandNotSupported),
            0x08 => Ok(SocksResponseCode::AddrTypeNotSupported),
            _ => Err(SocksError::ResponseCodeNotSupported(value)),
        }
    }
}

#[derive(Debug)]
pub struct SocksResponse {
    pub version: SocksVersion,
    pub code: SocksResponseCode,
    pub addr: SocksAddr,
}

impl SocksResponse {
    pub fn new(version: SocksVersion, code: SocksResponseCode, addr: SocksAddr) -> SocksResponse {
        SocksResponse {
            version,
            code,
            addr,
        }
    }
}

#[async_trait]
impl SocksProtocol for SocksResponse {
    async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let mut buf = BytesMut::with_capacity(1 + 1 + self.addr.serialize_len());
        buf.put_u8(self.version.into());
        buf.put_u8(self.code.into());
        buf.put_u8(0x00);
        self.addr.write_to_buf(&mut buf)?;
        writer.write_all(&buf).await?;
        Ok(())
    }

    async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send,
    {
        let version_raw = reader.read_u8().await?;
        let version = SocksVersion::try_from(version_raw)?;
        let code_raw = reader.read_u8().await?;
        let code = SocksResponseCode::try_from(code_raw)?;
        // Reserved
        let _ = reader.read_u8().await?;
        let addr = SocksAddr::read_from(reader).await?;
        Ok(SocksResponse {
            version,
            code,
            addr,
        })
    }
}
