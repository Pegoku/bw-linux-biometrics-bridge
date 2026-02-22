use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use protocol::{default_socket_path, HostRequest, HostResponse};

use bw_daemon::request;

#[derive(Parser, Debug)]
#[command(name = "bwctl")]
struct Args {
    #[arg(long)]
    socket: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Health,
    Status,
    Enroll { user_id: String, user_key_b64: String },
    Unenroll { user_id: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let socket = args
        .socket
        .unwrap_or_else(|| default_socket_path().to_string_lossy().to_string());

    let req = match args.command {
        Command::Health => HostRequest::Health,
        Command::Status => HostRequest::Status,
        Command::Enroll {
            user_id,
            user_key_b64,
        } => HostRequest::EnrollUserKey {
            user_id,
            user_key_b64,
        },
        Command::Unenroll { user_id } => HostRequest::DeleteUserKey { user_id },
    };

    let response = request(&socket, req).await?;
    match response {
        HostResponse::Ok => {
            println!("ok");
            Ok(())
        }
        HostResponse::Health { alive, version } => {
            println!("alive={alive} version={version}");
            Ok(())
        }
        HostResponse::Status {
            version,
            socket_path,
            enrolled_users,
        } => {
            println!("version={version}");
            println!("socket={socket_path}");
            println!("enrolled_users={enrolled_users}");
            Ok(())
        }
        HostResponse::Error { message } => Err(anyhow!(message)),
        HostResponse::NativeMessage { .. } => Err(anyhow!("unexpected native response")),
    }
}
