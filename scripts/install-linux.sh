#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${HOME}/.local/bin"
SOCKET_PATH="${XDG_RUNTIME_DIR:-/tmp}/bw-daemon.sock"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
POLKIT_DEST="/usr/share/polkit-1/actions/com.bitwarden.Bitwarden.unlock.policy"

usage() {
  cat <<'EOF'
Usage: scripts/install-linux.sh [--no-build] [--bin-dir PATH] [--no-polkit]

Installs:
- bw-daemond, bw-native-host, bwctl into ~/.local/bin (or --bin-dir)
- Native messaging manifests for Chrome/Chromium/Edge/Firefox
- systemd user service and enables it
- Polkit policy (unless --no-polkit)
EOF
}

DO_BUILD=1
DO_POLKIT=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)
      DO_BUILD=0
      shift
      ;;
    --bin-dir)
      BIN_DIR="$2"
      shift 2
      ;;
    --no-polkit)
      DO_POLKIT=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

mkdir -p "${BIN_DIR}"

if [[ "${DO_BUILD}" -eq 1 ]]; then
  echo "[1/6] Building release binaries..."
  cargo build --release --manifest-path "${ROOT_DIR}/Cargo.toml"
else
  echo "[1/6] Skipping build (--no-build)"
fi

echo "[2/6] Installing binaries to ${BIN_DIR}..."
install -m 0755 "${ROOT_DIR}/target/release/bw-daemond" "${BIN_DIR}/bw-daemond"
install -m 0755 "${ROOT_DIR}/target/release/bw-native-host" "${BIN_DIR}/bw-native-host"
install -m 0755 "${ROOT_DIR}/target/release/bwctl" "${BIN_DIR}/bwctl"

echo "[3/6] Installing native messaging manifests..."
CHROME_TEMPLATE="${ROOT_DIR}/packaging/native-messaging/com.8bit.bitwarden.chrome.json.template"
FIREFOX_TEMPLATE="${ROOT_DIR}/packaging/native-messaging/com.8bit.bitwarden.firefox.json.template"
NATIVE_HOST_PATH="${BIN_DIR}/bw-native-host"

CHROME_TARGETS=(
  "${HOME}/.config/google-chrome/NativeMessagingHosts/com.8bit.bitwarden.json"
  "${HOME}/.config/chromium/NativeMessagingHosts/com.8bit.bitwarden.json"
  "${HOME}/.config/microsoft-edge/NativeMessagingHosts/com.8bit.bitwarden.json"
)

for target in "${CHROME_TARGETS[@]}"; do
  mkdir -p "$(dirname "${target}")"
  sed "s|__NATIVE_HOST_PATH__|${NATIVE_HOST_PATH}|g" "${CHROME_TEMPLATE}" > "${target}"
done

FIREFOX_TARGET="${HOME}/.mozilla/native-messaging-hosts/com.8bit.bitwarden.json"
mkdir -p "$(dirname "${FIREFOX_TARGET}")"
sed "s|__NATIVE_HOST_PATH__|${NATIVE_HOST_PATH}|g" "${FIREFOX_TEMPLATE}" > "${FIREFOX_TARGET}"

echo "[4/6] Installing systemd user service..."
mkdir -p "${SYSTEMD_USER_DIR}"
SERVICE_PATH="${SYSTEMD_USER_DIR}/bw-daemond.service"
cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=Bitwarden Linux biometric daemon
After=graphical-session.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/bw-daemond --socket ${SOCKET_PATH}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now bw-daemond.service

echo "[5/6] Installing polkit policy..."
if [[ "${DO_POLKIT}" -eq 1 ]]; then
  POLKIT_SRC="${ROOT_DIR}/packaging/polkit/com.bitwarden.Bitwarden.unlock.policy"
  if [[ -w "$(dirname "${POLKIT_DEST}")" ]]; then
    install -m 0644 "${POLKIT_SRC}" "${POLKIT_DEST}"
  else
    sudo install -m 0644 "${POLKIT_SRC}" "${POLKIT_DEST}"
  fi
else
  echo "Skipping polkit install (--no-polkit)"
fi

echo "[6/6] Verifying daemon health..."
"${BIN_DIR}/bwctl" --socket "${SOCKET_PATH}" health

echo
echo "Done."
echo "- Binaries installed in: ${BIN_DIR}"
echo "- Native host path: ${NATIVE_HOST_PATH}"
echo "- Socket path: ${SOCKET_PATH}"
echo "- Service: bw-daemond.service (enabled + started)"
