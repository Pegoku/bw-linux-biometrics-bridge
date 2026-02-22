use std::io::{Read, Write};

use anyhow::{anyhow, Context, Result};
use protocol::{default_socket_path, HostRequest, HostResponse};
use serde_json::{json, Value};
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LinesCodec};
use tracing_subscriber::EnvFilter;

fn read_native_frame(input: &mut impl Read) -> Result<Option<Value>> {
    let mut len_buf = [0u8; 4];
    match input.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    input.read_exact(&mut payload)?;
    let value: Value = serde_json::from_slice(&payload)?;
    Ok(Some(value))
}

fn write_native_frame(output: &mut impl Write, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    let len = u32::try_from(bytes.len()).context("native message too large")?;
    output.write_all(&len.to_le_bytes())?;
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}

async fn send_request(
    framed: &mut Framed<UnixStream, LinesCodec>,
    request: HostRequest,
) -> Result<HostResponse> {
    use futures::{SinkExt, StreamExt};

    let line = serde_json::to_string(&request)?;
    framed.send(line).await?;

    let response_line = framed
        .next()
        .await
        .ok_or_else(|| anyhow!("daemon closed connection"))??;

    let response = serde_json::from_str::<HostResponse>(&response_line)?;
    Ok(response)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let socket = default_socket_path();
    let stream = UnixStream::connect(&socket)
        .await
        .with_context(|| format!("failed to connect daemon at {}", socket.display()))?;
    let mut framed = Framed::new(stream, LinesCodec::new());

    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    write_native_frame(&mut stdout, &json!({ "command": "connected" }))?;

    while let Some(message) = read_native_frame(&mut stdin)? {
        let response = send_request(&mut framed, HostRequest::NativeMessage { payload: message }).await?;

        match response {
            HostResponse::NativeMessage { payload } => write_native_frame(&mut stdout, &payload)?,
            HostResponse::Error { message } => {
                write_native_frame(&mut stdout, &json!({ "command": "disconnected" }))?;
                return Err(anyhow!("daemon error: {}", message));
            }
            _ => return Err(anyhow!("unexpected daemon response")),
        }
    }

    write_native_frame(&mut stdout, &json!({ "command": "disconnected" }))?;
    Ok(())
}
