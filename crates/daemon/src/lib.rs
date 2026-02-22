use std::collections::HashMap;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;

use aes::Aes256;
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use protocol::{BiometricsStatus, HostRequest, HostResponse, POLICY_ACTION};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio_util::codec::{Framed, LinesCodec};
use tracing::{error, info, warn};

#[derive(Clone, Debug)]
struct Session {
    key64: [u8; 64],
}

#[derive(Default)]
struct DaemonState {
    sessions: HashMap<String, Session>,
    user_keys: HashMap<String, Vec<u8>>,
}

#[derive(Clone)]
pub struct Daemon {
    state: Arc<Mutex<DaemonState>>,
    socket_path: String,
    version: String,
}

impl Daemon {
    pub fn new(socket_path: String, version: String) -> Self {
        Self {
            state: Arc::new(Mutex::new(DaemonState::default())),
            socket_path,
            version,
        }
    }

    pub async fn run(self) -> Result<()> {
        let socket_path = std::path::Path::new(&self.socket_path);
        if socket_path.exists() {
            std::fs::remove_file(socket_path)
                .with_context(|| format!("failed to remove stale socket {}", self.socket_path))?;
        }

        let listener = UnixListener::bind(socket_path)
            .with_context(|| format!("failed to bind socket {}", self.socket_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(socket_path, perms)
                .with_context(|| format!("failed to set socket permissions on {}", self.socket_path))?;
        }

        info!(socket = %self.socket_path, "daemon listening");

        loop {
            let (stream, _) = listener.accept().await?;
            let daemon = self.clone();
            tokio::spawn(async move {
                if let Err(err) = daemon.handle_client(stream).await {
                    error!(error = %err, "client handling failed");
                }
            });
        }
    }

    async fn handle_client(&self, stream: UnixStream) -> Result<()> {
        self.handle_framed(Framed::new(stream, LinesCodec::new())).await
    }

    pub async fn handle_framed<T>(&self, mut framed: Framed<T, LinesCodec>) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        use futures::{SinkExt, StreamExt};

        while let Some(line) = framed.next().await {
            let line = line?;
            let request: HostRequest = serde_json::from_str(&line).context("invalid request json")?;
            let response = self.handle_request(request).await;
            let response_line = serde_json::to_string(&response)?;
            framed.send(response_line).await?;
        }

        Ok(())
    }

    async fn handle_request(&self, request: HostRequest) -> HostResponse {
        match request {
            HostRequest::Health => HostResponse::Health {
                alive: true,
                version: self.version.clone(),
            },
            HostRequest::Status => {
                let guard = self.state.lock().await;
                HostResponse::Status {
                    version: self.version.clone(),
                    socket_path: self.socket_path.clone(),
                    enrolled_users: guard.user_keys.len(),
                }
            }
            HostRequest::EnrollUserKey {
                user_id,
                user_key_b64,
            } => match STANDARD.decode(user_key_b64.as_bytes()) {
                Ok(bytes) => {
                    self.state.lock().await.user_keys.insert(user_id, bytes);
                    HostResponse::Ok
                }
                Err(_) => HostResponse::Error {
                    message: "invalid base64 user key".to_string(),
                },
            },
            HostRequest::DeleteUserKey { user_id } => {
                self.state.lock().await.user_keys.remove(&user_id);
                HostResponse::Ok
            }
            HostRequest::NativeMessage { payload } => match self.handle_native_message(payload).await {
                Ok(response) => HostResponse::NativeMessage { payload: response },
                Err(err) => {
                    warn!(error = %err, "native message handling error");
                    HostResponse::Error {
                        message: err.to_string(),
                    }
                }
            },
        }
    }

    async fn handle_native_message(&self, payload: Value) -> Result<Value> {
        let subject_pid = payload
            .get("hostPid")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or_else(std::process::id);

        let app_id = payload
            .get("appId")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing appId"))?
            .to_string();

        let message = payload
            .get("message")
            .ok_or_else(|| anyhow!("missing message"))?
            .clone();

        if let Some(command) = message.get("command").and_then(Value::as_str) {
            if command == "setupEncryption" {
                let public_key_b64 = message
                    .get("publicKey")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("setupEncryption missing publicKey"))?;

                let public_key_der = STANDARD
                    .decode(public_key_b64.as_bytes())
                    .context("invalid setupEncryption public key")?;

                let public_key = parse_rsa_public_key(&public_key_der)
                    .context("unsupported public key encoding")?;

                let mut key64 = [0u8; 64];
                OsRng.fill_bytes(&mut key64);

                let encrypted_secret = public_key
                    .encrypt(&mut OsRng, Oaep::new::<Sha1>(), &key64)
                    .context("failed to encrypt shared secret")?;

                self.state
                    .lock()
                    .await
                    .sessions
                    .insert(app_id.clone(), Session { key64 });

                return Ok(json!({
                    "appId": app_id,
                    "command": "setupEncryption",
                    "messageId": -1,
                    "sharedSecret": STANDARD.encode(encrypted_secret),
                }));
            }
        }

        let session = {
            let guard = self.state.lock().await;
            guard.sessions.get(&app_id).cloned()
        };

        let Some(session) = session else {
            return Ok(json!({ "appId": app_id, "command": "invalidateEncryption" }));
        };

        let decrypted = decrypt_message_object(&message, &session.key64)?;
        let msg_id = decrypted
            .get("messageId")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        let command = decrypted
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let user_id = decrypted
            .get("userId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let inner_response = match command {
            "authenticateWithBiometrics" => json!({
                "command": command,
                "messageId": msg_id,
                "response": polkit_authenticate(subject_pid),
                "timestamp": now_ms(),
            }),
            "getBiometricsStatus" => json!({
                "command": command,
                "messageId": msg_id,
                "response": get_platform_status() as i32,
                "timestamp": now_ms(),
            }),
            "getBiometricsStatusForUser" => {
                let user_has_key = self.state.lock().await.user_keys.contains_key(&user_id);
                let status = if !user_has_key {
                    BiometricsStatus::UnlockNeeded
                } else {
                    get_platform_status()
                };

                json!({
                    "command": command,
                    "messageId": msg_id,
                    "response": status as i32,
                    "timestamp": now_ms(),
                })
            }
            "setupBiometricsForUser" => {
                let user_key_b64 = decrypted
                    .get("userKeyB64")
                    .and_then(Value::as_str)
                    .unwrap_or_default();

                let enrolled = match STANDARD.decode(user_key_b64.as_bytes()) {
                    Ok(user_key) if !user_key.is_empty() => {
                        self.state.lock().await.user_keys.insert(user_id.clone(), user_key);
                        true
                    }
                    _ => false,
                };

                json!({
                    "command": command,
                    "messageId": msg_id,
                    "response": enrolled,
                    "timestamp": now_ms(),
                })
            }
            "unlockWithBiometricsForUser" => {
                let user_key = self.state.lock().await.user_keys.get(&user_id).cloned();
                let Some(user_key) = user_key else {
                    let payload = json!({
                        "command": command,
                        "messageId": msg_id,
                        "response": false,
                        "timestamp": now_ms(),
                    });
                    return wrap_native_response(&app_id, msg_id, payload, &session.key64);
                };

                let granted = polkit_authenticate(subject_pid);
                if granted {
                    json!({
                        "command": command,
                        "messageId": msg_id,
                        "response": true,
                        "userKeyB64": STANDARD.encode(user_key),
                        "timestamp": now_ms(),
                    })
                } else {
                    json!({
                        "command": command,
                        "messageId": msg_id,
                        "response": false,
                        "timestamp": now_ms(),
                    })
                }
            }
            _ => json!({
                "command": command,
                "messageId": msg_id,
                "response": false,
                "timestamp": now_ms(),
            }),
        };

        wrap_native_response(&app_id, msg_id, inner_response, &session.key64)
    }
}

fn now_ms() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(now.as_millis()).unwrap_or(i64::MAX)
}

fn parse_rsa_public_key(der: &[u8]) -> Result<RsaPublicKey> {
    if let Ok(key) = RsaPublicKey::from_public_key_der(der) {
        return Ok(key);
    }

    if let Ok(key) = RsaPublicKey::from_pkcs1_der(der) {
        return Ok(key);
    }

    Err(anyhow!("could not parse RSA public key"))
}

fn wrap_native_response(app_id: &str, msg_id: i64, inner: Value, key64: &[u8; 64]) -> Result<Value> {
    let encrypted = encrypt_message_object(&inner, key64)?;
    Ok(json!({
        "appId": app_id,
        "messageId": msg_id,
        "message": encrypted,
    }))
}

fn decrypt_message_object(enc_object: &Value, key64: &[u8; 64]) -> Result<Value> {
    let encrypted_string = enc_object
        .get("encryptedString")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing encryptedString"))?;

    let (enc_type, rest) = encrypted_string
        .split_once('.')
        .ok_or_else(|| anyhow!("invalid encryptedString format"))?;

    if enc_type != "2" {
        return Err(anyhow!("unsupported encryption type {}", enc_type));
    }

    let parts: Vec<&str> = rest.split('|').collect();
    if parts.len() != 3 {
        return Err(anyhow!("invalid enc string part count"));
    }

    let iv = STANDARD.decode(parts[0].as_bytes())?;
    let data = STANDARD.decode(parts[1].as_bytes())?;
    let mac = STANDARD.decode(parts[2].as_bytes())?;

    let enc_key = &key64[0..32];
    let mac_key = &key64[32..64];

    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key)?;
    hmac.update(&iv);
    hmac.update(&data);
    hmac.verify_slice(&mac)
        .map_err(|_| anyhow!("message mac validation failed"))?;

    type Aes256CbcDec = cbc::Decryptor<Aes256>;
    let mut data_mut = data.clone();
    let plaintext = Aes256CbcDec::new_from_slices(enc_key, &iv)
        .map_err(|_| anyhow!("invalid key/iv for decrypt"))?
        .decrypt_padded_mut::<Pkcs7>(&mut data_mut)
        .map_err(|_| anyhow!("decrypt failed"))?
        .to_vec();

    let value: Value = serde_json::from_slice(&plaintext)?;
    Ok(value)
}

fn encrypt_message_object(plain: &Value, key64: &[u8; 64]) -> Result<Value> {
    let enc_key = &key64[0..32];
    let mac_key = &key64[32..64];

    let plaintext = serde_json::to_vec(plain)?;

    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;
    let mut buf = plaintext.clone();
    let pos = buf.len();
    let block_size = 16;
    let pad_len = block_size - (pos % block_size);
    buf.resize(pos + pad_len, 0u8);

    let cipher = Aes256CbcEnc::new_from_slices(enc_key, &iv)
        .map_err(|_| anyhow!("invalid key/iv for encrypt"))?
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pos)
        .map_err(|_| anyhow!("encrypt failed"))?
        .to_vec();

    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key)?;
    hmac.update(&iv);
    hmac.update(&cipher);
    let mac = hmac.finalize().into_bytes();

    let iv_b64 = STANDARD.encode(iv);
    let data_b64 = STANDARD.encode(cipher);
    let mac_b64 = STANDARD.encode(mac);
    let encrypted_string = format!("2.{}|{}|{}", iv_b64, data_b64, mac_b64);

    Ok(json!({
        "encryptedString": encrypted_string,
        "encryptionType": 2,
        "iv": iv_b64,
        "data": data_b64,
        "mac": mac_b64,
    }))
}

fn get_platform_status() -> BiometricsStatus {
    if !command_exists("pkcheck") {
        return BiometricsStatus::ManualSetupNeeded;
    }

    if !polkit_action_exists() {
        return BiometricsStatus::ManualSetupNeeded;
    }

    BiometricsStatus::Available
}

fn polkit_action_exists() -> bool {
    if !command_exists("pkaction") {
        return false;
    }

    Command::new("pkaction")
        .args(["--action-id", POLICY_ACTION])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn polkit_authenticate(subject_pid: u32) -> bool {
    if !command_exists("pkcheck") {
        return false;
    }

    let pid = subject_pid.to_string();
    Command::new("pkcheck")
        .args([
            "--action-id",
            POLICY_ACTION,
            "--process",
            &pid,
            "--allow-user-interaction",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn command_exists(command: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {} >/dev/null 2>&1", command)])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub async fn request(socket_path: &str, request: HostRequest) -> Result<HostResponse> {
    use futures::{SinkExt, StreamExt};

    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("failed to connect to {}", socket_path))?;

    let mut framed = Framed::new(stream, LinesCodec::new());
    framed.send(serde_json::to_string(&request)?).await?;

    let line = framed
        .next()
        .await
        .ok_or_else(|| anyhow!("daemon closed connection"))??;

    let response: HostResponse = serde_json::from_str(&line)?;
    Ok(response)
}
