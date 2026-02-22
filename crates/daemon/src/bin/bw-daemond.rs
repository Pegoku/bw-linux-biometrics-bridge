use anyhow::Result;
use clap::Parser;
use protocol::default_socket_path;
use tracing_subscriber::EnvFilter;

use bw_daemon::Daemon;

#[derive(Parser, Debug)]
#[command(name = "bw-daemond")]
struct Args {
    #[arg(long)]
    socket: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let args = Args::parse();
    let socket = args
        .socket
        .unwrap_or_else(|| default_socket_path().to_string_lossy().to_string());

    let daemon = Daemon::new(socket, env!("CARGO_PKG_VERSION").to_string());
    daemon.run().await
}
