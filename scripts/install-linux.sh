#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="/usr/bin"
SOCKET_PATH="${XDG_RUNTIME_DIR:-/tmp}/bw-daemon.sock"
SYSTEMD_USER_DIR="/usr/lib/systemd/user"
POLKIT_DEST="/usr/share/polkit-1/actions/com.bitwarden.Bitwarden.unlock.policy"
FIREFOX_MANIFEST_DEST="/usr/lib/mozilla/native-messaging-hosts/com.8bit.bitwarden.json"
CHROMIUM_MANIFEST_DEST="/etc/chromium/native-messaging-hosts/com.8bit.bitwarden.json"
CHROME_MANIFEST_DEST="/etc/opt/chrome/native-messaging-hosts/com.8bit.bitwarden.json"
EDGE_MANIFEST_DEST="/etc/opt/edge/native-messaging-hosts/com.8bit.bitwarden.json"

usage() {
  cat <<'EOF'
Usage: scripts/install-linux.sh [--no-build] [--bin-dir PATH] [--no-polkit] [--browsers LIST] [--firefox-extension-id ID]

Installs:
- bw-daemond, bw-native-host, bwctl into /usr/bin (or --bin-dir)
- Native messaging manifests (asks which browsers; default firefox)
- systemd user service and enables it
- Polkit policy (unless --no-polkit)

Browser list format:
- --browsers firefox
- --browsers firefox,chromium,chrome,edge

Firefox example:
- --firefox-extension-id bitwarden-d-fork@pegoku.local
EOF
}

DO_BUILD=1
DO_POLKIT=1
BROWSER_LIST=""
FIREFOX_EXTENSION_ID="{5d11d186-9b66-4f59-9b5a-670d320f920e}"

install_file() {
  local src="$1"
  local dest="$2"
  local mode="$3"

  if [[ -w "$(dirname "${dest}")" ]]; then
    install -m "${mode}" "${src}" "${dest}"
  else
    sudo install -m "${mode}" "${src}" "${dest}"
  fi
}

write_file_with_sudo_if_needed() {
  local dest="$1"
  local content="$2"

  if [[ -w "$(dirname "${dest}")" ]]; then
    printf "%s" "${content}" > "${dest}"
  else
    printf "%s" "${content}" | sudo tee "${dest}" > /dev/null
  fi
}

resolve_browsers() {
  local raw="$1"
  local normalized

  if [[ -z "${raw}" ]]; then
    echo "Select browsers for native-messaging manifest install"
    echo "Press Enter for default: firefox"
    echo "Options: firefox, chromium, chrome, edge"
    read -r -p "Browsers (comma-separated): " raw
  fi

  if [[ -z "${raw}" ]]; then
    raw="firefox"
  fi

  normalized="${raw// /}"
  IFS=',' read -r -a BROWSERS <<< "${normalized}"

  if [[ "${#BROWSERS[@]}" -eq 0 ]]; then
    echo "No browsers selected" >&2
    exit 1
  fi

  for browser in "${BROWSERS[@]}"; do
    case "${browser}" in
      firefox|chromium|chrome|edge) ;;
      *)
        echo "Unsupported browser: ${browser}" >&2
        echo "Supported: firefox, chromium, chrome, edge" >&2
        exit 1
        ;;
    esac
  done
}

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
    --browsers)
      BROWSER_LIST="$2"
      shift 2
      ;;
    --firefox-extension-id)
      FIREFOX_EXTENSION_ID="$2"
      shift 2
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

resolve_browsers "${BROWSER_LIST}"

if [[ -w "$(dirname "${BIN_DIR}")" ]]; then
  mkdir -p "${BIN_DIR}"
else
  sudo mkdir -p "${BIN_DIR}"
fi

if [[ "${DO_BUILD}" -eq 1 ]]; then
  echo "[1/6] Building release binaries..."
  cargo build --release --manifest-path "${ROOT_DIR}/Cargo.toml"
else
  echo "[1/6] Skipping build (--no-build)"
fi

echo "[2/6] Installing binaries to ${BIN_DIR}..."
install_file "${ROOT_DIR}/target/release/bw-daemond" "${BIN_DIR}/bw-daemond" 0755
install_file "${ROOT_DIR}/target/release/bw-native-host" "${BIN_DIR}/bw-native-host" 0755
install_file "${ROOT_DIR}/target/release/bwctl" "${BIN_DIR}/bwctl" 0755

echo "[3/6] Installing native messaging manifests..."
CHROME_TEMPLATE="${ROOT_DIR}/packaging/native-messaging/com.8bit.bitwarden.chrome.json.template"
FIREFOX_TEMPLATE="${ROOT_DIR}/packaging/native-messaging/com.8bit.bitwarden.firefox.json.template"
NATIVE_HOST_PATH="${BIN_DIR}/bw-native-host"

for browser in "${BROWSERS[@]}"; do
  case "${browser}" in
    firefox)
      content="$(sed \
        -e "s|__NATIVE_HOST_PATH__|${NATIVE_HOST_PATH}|g" \
        -e "s|__FIREFOX_EXTENSION_ID__|${FIREFOX_EXTENSION_ID}|g" \
        "${FIREFOX_TEMPLATE}")"
      if [[ -w "$(dirname "${FIREFOX_MANIFEST_DEST}")" ]]; then
        mkdir -p "$(dirname "${FIREFOX_MANIFEST_DEST}")"
      else
        sudo mkdir -p "$(dirname "${FIREFOX_MANIFEST_DEST}")"
      fi
      write_file_with_sudo_if_needed "${FIREFOX_MANIFEST_DEST}" "${content}"
      ;;
    chromium)
      content="$(sed "s|__NATIVE_HOST_PATH__|${NATIVE_HOST_PATH}|g" "${CHROME_TEMPLATE}")"
      if [[ -w "$(dirname "${CHROMIUM_MANIFEST_DEST}")" ]]; then
        mkdir -p "$(dirname "${CHROMIUM_MANIFEST_DEST}")"
      else
        sudo mkdir -p "$(dirname "${CHROMIUM_MANIFEST_DEST}")"
      fi
      write_file_with_sudo_if_needed "${CHROMIUM_MANIFEST_DEST}" "${content}"
      ;;
    chrome)
      content="$(sed "s|__NATIVE_HOST_PATH__|${NATIVE_HOST_PATH}|g" "${CHROME_TEMPLATE}")"
      if [[ -w "$(dirname "${CHROME_MANIFEST_DEST}")" ]]; then
        mkdir -p "$(dirname "${CHROME_MANIFEST_DEST}")"
      else
        sudo mkdir -p "$(dirname "${CHROME_MANIFEST_DEST}")"
      fi
      write_file_with_sudo_if_needed "${CHROME_MANIFEST_DEST}" "${content}"
      ;;
    edge)
      content="$(sed "s|__NATIVE_HOST_PATH__|${NATIVE_HOST_PATH}|g" "${CHROME_TEMPLATE}")"
      if [[ -w "$(dirname "${EDGE_MANIFEST_DEST}")" ]]; then
        mkdir -p "$(dirname "${EDGE_MANIFEST_DEST}")"
      else
        sudo mkdir -p "$(dirname "${EDGE_MANIFEST_DEST}")"
      fi
      write_file_with_sudo_if_needed "${EDGE_MANIFEST_DEST}" "${content}"
      ;;
  esac
done

echo "[4/6] Installing systemd user service..."
if [[ -w "$(dirname "${SYSTEMD_USER_DIR}")" ]]; then
  mkdir -p "${SYSTEMD_USER_DIR}"
else
  sudo mkdir -p "${SYSTEMD_USER_DIR}"
fi
SERVICE_PATH="${SYSTEMD_USER_DIR}/bw-daemond.service"
SERVICE_CONTENT=$(cat <<EOF
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
)
write_file_with_sudo_if_needed "${SERVICE_PATH}" "${SERVICE_CONTENT}"

systemctl --user daemon-reload
systemctl --user enable --now bw-daemond.service

echo "[5/6] Installing polkit policy..."
if [[ "${DO_POLKIT}" -eq 1 ]]; then
  POLKIT_SRC="${ROOT_DIR}/packaging/polkit/com.bitwarden.Bitwarden.unlock.policy"
  install_file "${POLKIT_SRC}" "${POLKIT_DEST}" 0644
else
  echo "Skipping polkit install (--no-polkit)"
fi

echo "[6/6] Verifying daemon health..."
for _ in {1..20}; do
  if [[ -S "${SOCKET_PATH}" ]]; then
    if "${BIN_DIR}/bwctl" --socket "${SOCKET_PATH}" health >/dev/null 2>&1; then
      break
    fi
  fi
  sleep 0.25
done

"${BIN_DIR}/bwctl" --socket "${SOCKET_PATH}" health

echo
echo "Done."
echo "- Binaries installed in: ${BIN_DIR}"
echo "- Native host path: ${NATIVE_HOST_PATH}"
echo "- Socket path: ${SOCKET_PATH}"
echo "- Service: bw-daemond.service (enabled + started)"
echo "- Browsers: ${BROWSERS[*]}"
echo "- Firefox extension id: ${FIREFOX_EXTENSION_ID}"
