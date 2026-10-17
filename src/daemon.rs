//! The client as a long-running process, set up from a TOML file.
//!
//! Local programs reach the network through a SOCKS5 proxy or an HTTP
//! proxy. Names under `.onion` go to onion services through a rendezvous;
//! other hosts are reached through exit relays.

use std::{fmt, fs, io, net::SocketAddr, path::Path, time::Duration};

use axon_runtime::{
    http::{self, Rewrite},
    socks::{self, Host, Reply},
};
use serde::Deserialize;
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream},
    time::sleep,
};

use crate::client::{TorClient, TorError};

/// Headers the HTTP proxy drops because they tell sites where a visitor
/// comes from.
const DROPPED_HEADERS: [&str; 5] = [
    "via",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-server",
];
/// How long a connection may wait for its circuit and stream.
const CONNECT_WAIT: Duration = Duration::from_secs(120);
/// A new consensus is fetched this often.
const DIRECTORY_REFRESH: Duration = Duration::from_secs(3600);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// A SOCKS5 proxy for local programs.
    pub socks: Option<SocketAddr>,
    /// An HTTP proxy for browsers; CONNECT carries HTTPS.
    pub http_proxy: Option<SocketAddr>,
}

#[derive(Debug)]
pub enum DaemonError {
    Config(String),
    Io(io::Error),
    Tor(TorError),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(formatter, "configuration: {message}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Tor(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<io::Error> for DaemonError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<TorError> for DaemonError {
    fn from(error: TorError) -> Self {
        Self::Tor(error)
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, DaemonError> {
        let text = fs::read_to_string(path)?;
        let config: Self =
            toml::from_str(&text).map_err(|error| DaemonError::Config(error.to_string()))?;
        if config.socks.is_none() && config.http_proxy.is_none() {
            return Err(DaemonError::Config(
                "set socks, http_proxy or both".to_owned(),
            ));
        }
        Ok(config)
    }
}

async fn connect(client: &TorClient, host: &str, port: u16) -> Result<DuplexStream, TorError> {
    if host.to_ascii_lowercase().ends_with(".onion") {
        client.connect_onion(host, port, CONNECT_WAIT).await
    } else {
        client.connect(host, port, CONNECT_WAIT).await
    }
}

async fn serve_socks(client: TorClient, mut stream: TcpStream) -> io::Result<()> {
    let target = socks::accept(&mut stream).await?;
    let host = match &target.host {
        Host::Name(name) => name.clone(),
        Host::Ip(address) => address.to_string(),
    };
    match connect(&client, &host, target.port).await {
        Ok(mut remote) => {
            socks::reply(&mut stream, Reply::Succeeded).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
            Ok(())
        }
        Err(_) => socks::reply(&mut stream, Reply::HostUnreachable).await,
    }
}

async fn serve_http(client: TorClient, mut stream: TcpStream) -> io::Result<()> {
    let rewrite = Rewrite {
        user_agent: None,
        drop: &DROPPED_HEADERS,
    };
    let request = match http::accept_proxy_request(&mut stream, &rewrite).await {
        Ok(request) => request,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            let page = http::status_page(400, "Bad Request", &error.to_string());
            return stream.write_all(&page).await;
        }
        Err(error) => return Err(error),
    };
    let host = request.target.host.to_string();
    let mut remote = match connect(&client, &host, request.target.port).await {
        Ok(remote) => remote,
        Err(error) => {
            let page = http::status_page(504, "Gateway Timeout", &format!("{host}: {error}"));
            return stream.write_all(&page).await;
        }
    };
    if request.tunnel {
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
    }
    remote.write_all(&request.forward).await?;
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

async fn listen<F, Fut>(address: SocketAddr, client: TorClient, serve: F) -> io::Result<()>
where
    F: Fn(TorClient, TcpStream) -> Fut + Send + Copy + 'static,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let listener = TcpListener::bind(address).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let client = client.clone();
        tokio::spawn(async move {
            let _ = serve(client, stream).await;
        });
    }
}

/// Fetches a fresh consensus now and then.
async fn refresh_directory(client: TorClient) {
    loop {
        sleep(DIRECTORY_REFRESH).await;
        match client.bootstrap().await {
            Ok(directory) => {
                eprintln!("new consensus: {} relays", directory.consensus.relays.len())
            }
            Err(error) => eprintln!("could not refresh the directory: {error}"),
        }
    }
}

/// Runs the client until interrupted.
pub async fn run(config: Config) -> Result<(), DaemonError> {
    let client = TorClient::start()?;
    eprintln!("fetching the consensus and microdescriptors");
    let directory = client.bootstrap().await?;
    eprintln!(
        "{} relays, {} microdescriptors",
        directory.consensus.relays.len(),
        directory.microdescriptors.len()
    );
    if let Some(address) = config.socks {
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(error) = listen(address, client, serve_socks).await {
                eprintln!("SOCKS proxy on {address}: {error}");
            }
        });
        eprintln!("SOCKS5 proxy on {address}");
    }
    if let Some(address) = config.http_proxy {
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(error) = listen(address, client, serve_http).await {
                eprintln!("HTTP proxy on {address}: {error}");
            }
        });
        eprintln!("HTTP proxy on {address}");
    }
    tokio::spawn(refresh_directory(client));
    tokio::signal::ctrl_c().await?;
    Ok(())
}
