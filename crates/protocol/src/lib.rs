use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const NATIVE_HOST_NAME: &str = "com.8bit.bitwarden";
pub const POLICY_ACTION: &str = "com.bitwarden.Bitwarden.unlock";

pub fn default_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("bw-daemon.sock");
    }

    PathBuf::from("/tmp/bw-daemon.sock")
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostRequest {
    Health,
    Status,
    NativeMessage { payload: serde_json::Value },
    EnrollUserKey { user_id: String, user_key_b64: String },
    DeleteUserKey { user_id: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostResponse {
    Ok,
    Health {
        alive: bool,
        version: String,
    },
    Status {
        version: String,
        socket_path: String,
        enrolled_users: usize,
    },
    NativeMessage {
        payload: serde_json::Value,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Copy)]
#[repr(i32)]
pub enum BiometricsStatus {
    Available = 0,
    UnlockNeeded = 1,
    HardwareUnavailable = 2,
    AutoSetupNeeded = 3,
    ManualSetupNeeded = 4,
    PlatformUnsupported = 5,
    DesktopDisconnected = 6,
    NotEnabledLocally = 7,
    NotEnabledInConnectedDesktopApp = 8,
    NativeMessagingPermissionMissing = 9,
}
