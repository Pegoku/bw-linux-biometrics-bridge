# bw-daemon (Linux biometrics bridge)

This folder contains a Linux-first daemon + CLI + browser native host that can bridge browser extension native messaging requests to local system authentication.

## Binaries

- `bw-daemond`: long-running Unix-socket daemon
- `bw-native-host`: browser Native Messaging host process (`com.8bit.bitwarden`)
- `bwctl`: CLI for health checks and key enrollment/unenrollment

## Current scope

- Native Messaging framing and host bridge
- Session handshake (`setupEncryption`) and encrypted message transport
- Linux system auth via `pkcheck` and a Polkit action (`com.bitwarden.Bitwarden.unlock`)
- In-memory per-user unlock key cache (daemon lifetime)

## Setup behavior

When used with the browser extension code in this repository, enabling biometrics performs an enrollment step automatically via native messaging (`setupBiometricsForUser`) using the modified browser extension in [my fork](https://github.com/Pegoku/clients).

`bwctl enroll` remains available for manual troubleshooting.

## Quick start

1. Build:

```bash
cargo build --release
```

Or run the installer script (build + install + systemd + manifests + polkit):

```bash
./scripts/install-linux.sh
```

2. Start daemon:

```bash
./target/release/bw-daemond
```

3. Check health:

```bash
./target/release/bwctl status
```

4. Install native messaging manifests from templates in `packaging/native-messaging/`.

## Packaging assets

- `packaging/systemd/user/bw-daemond.service`
- `packaging/native-messaging/com.8bit.bitwarden.chrome.json.template`
- `packaging/native-messaging/com.8bit.bitwarden.firefox.json.template`
- `packaging/polkit/com.bitwarden.Bitwarden.unlock.policy`
